#include <linux/device.h>
#include <linux/errno.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/suspend.h>
#include <linux/string.h>

#include "export_fun.h"
#include "touch.h"
#include "nbg_log.h"

#define VTOUCH_DEFAULT_SLOTS 1
#define VTOUCH_MAX_SLOTS     16
#define VTOUCH_PREFERRED_REAL_SLOTS 4
#define VTOUCH_MIN_REAL_SLOTS 1
#define VTOUCH_TRACKING_BASE 40000
#define VTOUCH_TRACKING_FALLBACK_MAX 65535
#define VTOUCH_PRESSURE      60
#define VTOUCH_TOUCH_MAJOR   10
#define VTOUCH_WIDTH_MAJOR   10

typedef void (*input_handle_event_fn_t)(struct input_dev *dev,
                                        unsigned int type,
                                        unsigned int code,
                                        int value);

struct vtouch_slot_state {
    bool active;
    int tracking_id;
};

static struct {
    struct input_dev *dev;
    struct vtouch_slot_state slots[VTOUCH_MAX_SLOTS];
        int configured_slots;
        int reserved_slots;
        int active_count;
        int original_slots;
        int physical_slots;
        int virtual_slot_base;
        int next_tracking_id;
        unsigned int original_mt_flags;
    int phys_width;
    int phys_height;
    int user_width;
    int user_height;
    bool has_touch_major;
    bool has_width_major;
    bool has_pressure;
        bool had_btn_touch;
        bool had_btn_finger;
        bool had_btn_doubletap;
        bool had_btn_tripletap;
        bool had_btn_quadtap;
        bool had_btn_quinttap;
        bool global_keys_locked;
        bool initialized;
    bool pm_notifier_registered;
    unsigned long input_handle_event_addr;
    struct mutex state_lock;
    } vt = {
        .configured_slots = VTOUCH_DEFAULT_SLOTS,
        .next_tracking_id = VTOUCH_TRACKING_BASE,
        .state_lock = __MUTEX_INITIALIZER(vt.state_lock),
    };

static int touch_pm_event(struct notifier_block *notifier,
                          unsigned long event, void *unused)
{
    if (event == PM_SUSPEND_PREPARE ||
        event == PM_HIBERNATION_PREPARE ||
        event == PM_RESTORE_PREPARE)
        touch_up_all();
    return NOTIFY_DONE;
}

static struct notifier_block touch_pm_notifier = {
    .notifier_call = touch_pm_event,
};

NBG_NO_CFI
static inline void call_input_handle_event(unsigned long addr,
                                           struct input_dev *dev,
                                           unsigned int type,
                                           unsigned int code,
                                           int value)
{
    input_handle_event_fn_t fn = (input_handle_event_fn_t)addr;

    fn(dev, type, code, value);
}

static int ensure_input_handle_event(void)
{
    unsigned long addr = READ_ONCE(vt.input_handle_event_addr);

    if (addr)
        return 0;
    addr = generic_kallsyms_lookup_name("input_handle_event");
    if (addr)
        WRITE_ONCE(vt.input_handle_event_addr, addr);
    return 0;
}

/* Caller holds dev->event_lock. */
static inline void emit_event_locked(struct input_dev *dev,
                                     unsigned int type,
                                     unsigned int code,
                                     int value)
{
    call_input_handle_event(READ_ONCE(vt.input_handle_event_addr),
                            dev, type, code, value);
}

static void clear_slot_states_locked(void)
{
    int i;

    for (i = 0; i < VTOUCH_MAX_SLOTS; i++) {
        vt.slots[i].active = false;
        vt.slots[i].tracking_id = -1;
    }
        vt.active_count = 0;
}

static int vtouch_slot_limit_locked(void)
{
    return vt.reserved_slots > 0 ? vt.reserved_slots : vt.configured_slots;
}

static int vtouch_reserved_from_total_locked(int original_slots)
{
    int spare;

    if (original_slots <= VTOUCH_MIN_REAL_SLOTS)
        return 0;

    /*
     * Prefer to leave four real MT slots visible for fire/scope/move gestures.
     * Small panels which expose only 2~4 slots still get one virtual slot, so
     * diagnostics and single-slot aim injection work instead of reporting no
     * touchscreen.  Multi-slot injection is then capped by the real spare slots.
     */
    spare = original_slots - VTOUCH_PREFERRED_REAL_SLOTS;
    if (spare <= 0)
        spare = 1;
    return min(vt.configured_slots, spare);
}

static int clamp_abs_value_locked(unsigned int code, int value)
{
    struct input_dev *dev = vt.dev;
    int minv;
    int maxv;

    if (!dev || !dev->absinfo || !test_bit(code, dev->absbit))
        return value;

    minv = dev->absinfo[code].minimum;
    maxv = dev->absinfo[code].maximum;
    if (maxv <= minv)
        return value;
    return clamp(value, minv, maxv);
}

static int next_tracking_id_locked(void)
{
    struct input_dev *dev = vt.dev;
    int minv = 0;
    int maxv = VTOUCH_TRACKING_FALLBACK_MAX;
    int id;

    if (dev && dev->absinfo && test_bit(ABS_MT_TRACKING_ID, dev->absbit)) {
        int dev_min = dev->absinfo[ABS_MT_TRACKING_ID].minimum;
        int dev_max = dev->absinfo[ABS_MT_TRACKING_ID].maximum;

        if (dev_max > dev_min) {
            minv = max(dev_min, 0);
            maxv = dev_max;
        }
    }

    if (maxv < minv)
        maxv = minv;
    if (vt.next_tracking_id < minv || vt.next_tracking_id > maxv)
        vt.next_tracking_id =
            min_t(int, max_t(int, VTOUCH_TRACKING_BASE, minv), maxv);

    id = vt.next_tracking_id++;
    if (vt.next_tracking_id > maxv)
        vt.next_tracking_id = minv;
    return id;
}

static void convert_coords_locked(int x, int y, int *out_x, int *out_y)
{
    if (vt.user_width > vt.user_height) {
        *out_x = (int)((long long)y * vt.phys_width /
                       (vt.user_height - 1));
        *out_y = (int)((long long)x * vt.phys_height /
                       (vt.user_width - 1));
    } else {
        *out_x = (int)((long long)x * vt.phys_width /
                       (vt.user_width - 1));
        *out_y = (int)((long long)y * vt.phys_height /
                       (vt.user_height - 1));
    }

    *out_x = clamp(*out_x, 0, vt.phys_width);
    *out_y = clamp(*out_y, 0, vt.phys_height);
}

struct touch_match {
    struct input_dev *dev;
    const struct device_type *input_type;
    unsigned long long score;
};

static int match_touchscreen(struct device *dev, void *data)
{
    struct input_dev *input;
    struct touch_match *match = data;
    unsigned long long score;
    int max_x;
    int max_y;

    /* input_class also contains evdev/mousedev child nodes, which are NOT
     * embedded in struct input_dev. Validate the kernel's device type before
     * container_of; otherwise a diagnostic-only query can read outside the
     * child object's allocation (observed by KASAN on android14-6.1). */
    if (!match->input_type || dev->type != match->input_type)
        return 0;
    input = to_input_dev(dev);

        if (!input || input->going_away || !input->mt || !input->absinfo)
            return 0;
    if (input->id.bustype == BUS_VIRTUAL)
        return 0;
    if (!test_bit(EV_ABS, input->evbit) ||
            !test_bit(ABS_MT_SLOT, input->absbit) ||
            !test_bit(ABS_MT_TRACKING_ID, input->absbit) ||
            !test_bit(ABS_MT_POSITION_X, input->absbit) ||
            !test_bit(ABS_MT_POSITION_Y, input->absbit))
            return 0;
        if (input->mt->num_slots <= VTOUCH_MIN_REAL_SLOTS)
            return 0;

    max_x = input->absinfo[ABS_MT_POSITION_X].maximum;
    max_y = input->absinfo[ABS_MT_POSITION_Y].maximum;
    if (max_x <= 0 || max_y <= 0)
        return 0;

    score = (unsigned long long)max_x * (unsigned long long)max_y;
    score += (unsigned long long)input->mt->num_slots << 48;
    if (test_bit(INPUT_PROP_DIRECT, input->propbit))
        score += 1ULL << 62;
    if (score <= match->score)
        return 0;

    get_device(dev);
    if (match->dev)
        put_device(&match->dev->dev);
    match->dev = input;
    match->score = score;
    return 0;
}

static void set_global_key_bits_locked(bool enable)
{
    struct input_dev *dev = vt.dev;

    if (!dev)
        return;

    if (vt.had_btn_touch) {
        if (enable)
            set_bit(BTN_TOUCH, dev->keybit);
        else
            clear_bit(BTN_TOUCH, dev->keybit);
    }
    if (vt.had_btn_finger) {
        if (enable)
            set_bit(BTN_TOOL_FINGER, dev->keybit);
        else
            clear_bit(BTN_TOOL_FINGER, dev->keybit);
    }
        if (vt.had_btn_doubletap) {
            if (enable)
                set_bit(BTN_TOOL_DOUBLETAP, dev->keybit);
            else
                clear_bit(BTN_TOOL_DOUBLETAP, dev->keybit);
        }
        if (vt.had_btn_tripletap) {
            if (enable)
                set_bit(BTN_TOOL_TRIPLETAP, dev->keybit);
            else
                clear_bit(BTN_TOOL_TRIPLETAP, dev->keybit);
        }
        if (vt.had_btn_quadtap) {
            if (enable)
                set_bit(BTN_TOOL_QUADTAP, dev->keybit);
            else
                clear_bit(BTN_TOOL_QUADTAP, dev->keybit);
        }
        if (vt.had_btn_quinttap) {
            if (enable)
                set_bit(BTN_TOOL_QUINTTAP, dev->keybit);
            else
                clear_bit(BTN_TOOL_QUINTTAP, dev->keybit);
        }
}

static int virtual_active_count_locked(void)
{
    int i;
    int count = 0;

        for (i = 0; i < VTOUCH_MAX_SLOTS; i++)
            if (vt.slots[i].active)
                count++;
    return count;
}

static int physical_active_count_locked(void)
{
    struct input_mt *mt = vt.dev ? vt.dev->mt : NULL;
    int i;
    int count = 0;

    if (!mt)
        return 0;
    for (i = 0; i < vt.physical_slots; i++)
        if (input_mt_get_value(&mt->slots[i], ABS_MT_TRACKING_ID) != -1)
            count++;
    return count;
}

static void update_global_keys_locked(void)
{
    struct input_dev *dev = vt.dev;
    bool relock;
    int count;

    if (!dev)
        return;

    count = physical_active_count_locked() + virtual_active_count_locked();
    relock = vt.global_keys_locked;
    if (relock)
        set_global_key_bits_locked(true);

    if (vt.had_btn_touch)
        emit_event_locked(dev, EV_KEY, BTN_TOUCH, count > 0);
    if (vt.had_btn_finger)
        emit_event_locked(dev, EV_KEY, BTN_TOOL_FINGER, count > 0);
    if (vt.had_btn_doubletap)
        emit_event_locked(dev, EV_KEY, BTN_TOOL_DOUBLETAP, count >= 2);
    if (vt.had_btn_tripletap)
        emit_event_locked(dev, EV_KEY, BTN_TOOL_TRIPLETAP, count == 3);
    if (vt.had_btn_quadtap)
        emit_event_locked(dev, EV_KEY, BTN_TOOL_QUADTAP, count == 4);
    if (vt.had_btn_quinttap)
        emit_event_locked(dev, EV_KEY, BTN_TOOL_QUINTTAP, count >= 5);

    if (relock)
        set_global_key_bits_locked(false);
}

static void set_global_key_bits_unlocked(bool enable)
{
    struct input_dev *dev = vt.dev;
    unsigned long irq_flags;

    if (!dev)
        return;
    spin_lock_irqsave(&dev->event_lock, irq_flags);
    set_global_key_bits_locked(enable);
    spin_unlock_irqrestore(&dev->event_lock, irq_flags);
}

static int physical_active_count_unlocked(void)
{
    struct input_dev *dev = vt.dev;
    unsigned long irq_flags;
    int count;

    if (!dev)
        return 0;
    spin_lock_irqsave(&dev->event_lock, irq_flags);
    count = physical_active_count_locked();
    spin_unlock_irqrestore(&dev->event_lock, irq_flags);
    return count;
}

static void update_global_keys_unlocked(void)
{
    struct input_dev *dev = vt.dev;
    bool relock;
    int count;

    if (!dev)
        return;

    count = physical_active_count_unlocked() + virtual_active_count_locked();
    relock = vt.global_keys_locked;
    if (relock)
        set_global_key_bits_unlocked(true);

    if (vt.had_btn_touch)
        input_event(dev, EV_KEY, BTN_TOUCH, count > 0);
    if (vt.had_btn_finger)
        input_event(dev, EV_KEY, BTN_TOOL_FINGER, count > 0);
    if (vt.had_btn_doubletap)
        input_event(dev, EV_KEY, BTN_TOOL_DOUBLETAP, count >= 2);
    if (vt.had_btn_tripletap)
        input_event(dev, EV_KEY, BTN_TOOL_TRIPLETAP, count == 3);
    if (vt.had_btn_quadtap)
        input_event(dev, EV_KEY, BTN_TOOL_QUADTAP, count == 4);
    if (vt.had_btn_quinttap)
        input_event(dev, EV_KEY, BTN_TOOL_QUINTTAP, count >= 5);

    if (relock)
        set_global_key_bits_unlocked(false);
}

static int report_contact_fallback_locked(int slot, int x, int y, bool active)
{
    struct input_dev *dev = vt.dev;
    struct input_mt *mt;
    unsigned long irq_flags;
    int hw_slot;
    int old_slot;
    int phys_x = 0;
    int phys_y = 0;

    if (!dev || !dev->mt)
        return -ENODEV;
    if (slot < 0 || slot >= vtouch_slot_limit_locked())
        return -EINVAL;
    if (active)
        convert_coords_locked(x, y, &phys_x, &phys_y);

    spin_lock_irqsave(&dev->event_lock, irq_flags);
    mt = dev->mt;
    if (!mt || vt.original_slots <= 0 || vt.physical_slots <= 0 ||
        vt.virtual_slot_base < 0 || vt.reserved_slots <= 0) {
        spin_unlock_irqrestore(&dev->event_lock, irq_flags);
        return -ENODEV;
    }
    hw_slot = vt.virtual_slot_base + slot;
    if (hw_slot < 0 || hw_slot >= vt.original_slots) {
        spin_unlock_irqrestore(&dev->event_lock, irq_flags);
        return -ENOSPC;
    }
    old_slot = READ_ONCE(mt->slot);
    if (old_slot < 0 || old_slot >= vt.physical_slots)
        old_slot = 0;
    WRITE_ONCE(mt->num_slots, vt.original_slots);
    spin_unlock_irqrestore(&dev->event_lock, irq_flags);

    /*
     * Fallback path for devices whose kallsyms table does not expose the
     * internal input_handle_event symbol. It uses exported input_event(), so
     * each event takes event_lock separately; the private-symbol path below is
     * still preferred when available because it keeps the whole MT transaction
     * atomic.
     */
    input_event(dev, EV_ABS, ABS_MT_SLOT, hw_slot);
    input_event(dev, EV_ABS, ABS_MT_TRACKING_ID,
                active ? vt.slots[slot].tracking_id : -1);

    if (active) {
        input_event(dev, EV_ABS, ABS_MT_POSITION_X, phys_x);
        input_event(dev, EV_ABS, ABS_MT_POSITION_Y, phys_y);
        if (vt.has_touch_major)
            input_event(dev, EV_ABS, ABS_MT_TOUCH_MAJOR,
                        clamp_abs_value_locked(ABS_MT_TOUCH_MAJOR,
                                               VTOUCH_TOUCH_MAJOR));
        if (vt.has_width_major)
            input_event(dev, EV_ABS, ABS_MT_WIDTH_MAJOR,
                        clamp_abs_value_locked(ABS_MT_WIDTH_MAJOR,
                                               VTOUCH_WIDTH_MAJOR));
        if (vt.has_pressure)
            input_event(dev, EV_ABS, ABS_MT_PRESSURE,
                        clamp_abs_value_locked(ABS_MT_PRESSURE,
                                               VTOUCH_PRESSURE));
    }

    input_event(dev, EV_ABS, ABS_MT_SLOT, old_slot);

    spin_lock_irqsave(&dev->event_lock, irq_flags);
    if (dev->mt)
        WRITE_ONCE(dev->mt->num_slots, vt.physical_slots);
    spin_unlock_irqrestore(&dev->event_lock, irq_flags);

    update_global_keys_unlocked();
    input_event(dev, EV_SYN, SYN_REPORT, 0);
    return 0;
}

/*
 * Update one reserved slot on the physical touchscreen. Do not call
 * input_mt_sync_frame(): it applies DROP_UNUSED semantics to a partial frame
 * and can release real fingers which the physical driver did not re-report in
 * this injected transaction.
 */
static int report_contact_locked(int slot, int x, int y, bool active)
{
    struct input_dev *dev = vt.dev;
    struct input_mt *mt;
    unsigned long irq_flags;
    int hw_slot;
    int old_slot;
    int phys_x = 0;
    int phys_y = 0;

	    if (!dev || !dev->mt)
	        return -ENODEV;
	    if (slot < 0 || slot >= vtouch_slot_limit_locked())
	        return -EINVAL;
	    if (!READ_ONCE(vt.input_handle_event_addr))
	        return report_contact_fallback_locked(slot, x, y, active);

    if (active)
        convert_coords_locked(x, y, &phys_x, &phys_y);

        spin_lock_irqsave(&dev->event_lock, irq_flags);
        mt = dev->mt;
        if (!mt || vt.original_slots <= 0 || vt.physical_slots <= 0 ||
            vt.virtual_slot_base < 0 || vt.reserved_slots <= 0) {
            spin_unlock_irqrestore(&dev->event_lock, irq_flags);
            return -ENODEV;
        }
        hw_slot = vt.virtual_slot_base + slot;
        if (hw_slot < 0 || hw_slot >= vt.original_slots) {
            spin_unlock_irqrestore(&dev->event_lock, irq_flags);
            return -ENOSPC;
        }
        old_slot = READ_ONCE(mt->slot);
    if (old_slot < 0 || old_slot >= vt.physical_slots)
        old_slot = 0;

    /* Let input core accept the reserved slot only for this atomic report. */
    WRITE_ONCE(mt->num_slots, vt.original_slots);
    emit_event_locked(dev, EV_ABS, ABS_MT_SLOT, hw_slot);
    emit_event_locked(dev, EV_ABS, ABS_MT_TRACKING_ID,
                      active ? vt.slots[slot].tracking_id : -1);

        if (active) {
            emit_event_locked(dev, EV_ABS, ABS_MT_POSITION_X, phys_x);
            emit_event_locked(dev, EV_ABS, ABS_MT_POSITION_Y, phys_y);
            if (vt.has_touch_major)
                emit_event_locked(dev, EV_ABS, ABS_MT_TOUCH_MAJOR,
                                  clamp_abs_value_locked(ABS_MT_TOUCH_MAJOR,
                                                         VTOUCH_TOUCH_MAJOR));
            if (vt.has_width_major)
                emit_event_locked(dev, EV_ABS, ABS_MT_WIDTH_MAJOR,
                                  clamp_abs_value_locked(ABS_MT_WIDTH_MAJOR,
                                                         VTOUCH_WIDTH_MAJOR));
            if (vt.has_pressure)
                emit_event_locked(dev, EV_ABS, ABS_MT_PRESSURE,
                                  clamp_abs_value_locked(ABS_MT_PRESSURE,
                                                         VTOUCH_PRESSURE));
        }

    /* Return the stream cursor before the physical IRQ reports more data. */
    emit_event_locked(dev, EV_ABS, ABS_MT_SLOT, old_slot);
    WRITE_ONCE(mt->num_slots, vt.physical_slots);

    update_global_keys_locked();
    emit_event_locked(dev, EV_SYN, SYN_REPORT, 0);
    spin_unlock_irqrestore(&dev->event_lock, irq_flags);
    return 0;
}

static void restore_physical_device_locked(void)
{
    struct input_dev *dev = vt.dev;
    unsigned long irq_flags;

    if (dev) {
        spin_lock_irqsave(&dev->event_lock, irq_flags);
        set_global_key_bits_locked(true);
        if (dev->mt) {
            WRITE_ONCE(dev->mt->num_slots, vt.original_slots);
            dev->mt->flags = vt.original_mt_flags;
        }
        spin_unlock_irqrestore(&dev->event_lock, irq_flags);
        put_device(&dev->dev);
    }

    vt.dev = NULL;
        vt.original_slots = 0;
        vt.physical_slots = 0;
        vt.virtual_slot_base = 0;
        vt.reserved_slots = 0;
        vt.global_keys_locked = false;
        vt.initialized = false;
}

static int ensure_device_locked(void)
{
    struct class *input_class;
    struct touch_match match = { 0 };
    struct input_dev *dev;
    unsigned long irq_flags;
    unsigned int original_mt_flags;
        int original_slots;
        int physical_slots;
    int reserved_slots;
    int i;
    int ret;

    if (vt.dev)
        return 0;
    if (vt.configured_slots <= 0 ||
        vt.configured_slots > VTOUCH_MAX_SLOTS)
        return -EINVAL;
    ret = ensure_input_handle_event();
    if (ret)
        return ret;

    input_class = (struct class *)generic_kallsyms_lookup_name("input_class");
    if (!input_class)
        return -ENOENT;

    match.input_type = (const struct device_type *)
        generic_kallsyms_lookup_name("input_dev_type");
    if (!match.input_type)
        return -EOPNOTSUPP;

    ret = class_for_each_device(input_class, NULL, &match, match_touchscreen);
    if (ret < 0) {
        if (match.dev)
            put_device(&match.dev->dev);
        return ret;
    }
    if (!match.dev)
        return -ENODEV;

    dev = match.dev;
    spin_lock_irqsave(&dev->event_lock, irq_flags);
    if (!dev->mt || dev->going_away) {
        spin_unlock_irqrestore(&dev->event_lock, irq_flags);
        put_device(&dev->dev);
        return -ENODEV;
    }
        original_slots = dev->mt->num_slots;
        if (original_slots <= VTOUCH_MIN_REAL_SLOTS) {
            spin_unlock_irqrestore(&dev->event_lock, irq_flags);
            put_device(&dev->dev);
            return -ENOSPC;
        }
        reserved_slots = vtouch_reserved_from_total_locked(original_slots);
        if (reserved_slots <= 0) {
            spin_unlock_irqrestore(&dev->event_lock, irq_flags);
            put_device(&dev->dev);
            return -ENOSPC;
        }
        physical_slots = original_slots - reserved_slots;
        for (i = physical_slots; i < original_slots; i++) {
            if (input_mt_get_value(&dev->mt->slots[i],
                               ABS_MT_TRACKING_ID) != -1) {
            spin_unlock_irqrestore(&dev->event_lock, irq_flags);
            put_device(&dev->dev);
            return -EBUSY;
        }
    }
    original_mt_flags = dev->mt->flags;
    dev->mt->flags &= ~INPUT_MT_DROP_UNUSED;
    dev->mt->flags |= INPUT_MT_DIRECT;
    dev->mt->flags &= ~INPUT_MT_POINTER;
    WRITE_ONCE(dev->mt->num_slots, physical_slots);
    spin_unlock_irqrestore(&dev->event_lock, irq_flags);

    vt.dev = dev;
        vt.original_slots = original_slots;
        vt.physical_slots = physical_slots;
        vt.reserved_slots = reserved_slots;
        vt.virtual_slot_base = physical_slots;
    vt.original_mt_flags = original_mt_flags;
    vt.phys_width = dev->absinfo[ABS_MT_POSITION_X].maximum;
    vt.phys_height = dev->absinfo[ABS_MT_POSITION_Y].maximum;
    vt.has_touch_major = test_bit(ABS_MT_TOUCH_MAJOR, dev->absbit) &&
        dev->absinfo[ABS_MT_TOUCH_MAJOR].maximum >
        dev->absinfo[ABS_MT_TOUCH_MAJOR].minimum;
    vt.has_width_major = test_bit(ABS_MT_WIDTH_MAJOR, dev->absbit) &&
        dev->absinfo[ABS_MT_WIDTH_MAJOR].maximum >
        dev->absinfo[ABS_MT_WIDTH_MAJOR].minimum;
    vt.has_pressure = test_bit(ABS_MT_PRESSURE, dev->absbit) &&
        dev->absinfo[ABS_MT_PRESSURE].maximum >
        dev->absinfo[ABS_MT_PRESSURE].minimum;
    vt.had_btn_touch = test_bit(BTN_TOUCH, dev->keybit);
        vt.had_btn_finger = test_bit(BTN_TOOL_FINGER, dev->keybit);
        vt.had_btn_doubletap = test_bit(BTN_TOOL_DOUBLETAP, dev->keybit);
        vt.had_btn_tripletap = test_bit(BTN_TOOL_TRIPLETAP, dev->keybit);
        vt.had_btn_quadtap = test_bit(BTN_TOOL_QUADTAP, dev->keybit);
        vt.had_btn_quinttap = test_bit(BTN_TOOL_QUINTTAP, dev->keybit);
        if (vt.user_width <= 1)
            vt.user_width = vt.phys_width + 1;
        if (vt.user_height <= 1)
            vt.user_height = vt.phys_height + 1;

        clear_slot_states_locked();
    vt.initialized = true;
    return 0;
}

static int probe_touchscreen_diag_locked(struct touch_diag *out)
{
    struct class *input_class;
    struct touch_match match = { 0 };
    struct input_dev *dev;
    unsigned long irq_flags;
    int original_slots;
    int reserve;
    int phys_width;
    int phys_height;
    bool has_touch_major;
    bool has_width_major;
    bool has_pressure;
    int ret;

    if (!out)
        return -EINVAL;

    input_class = (struct class *)generic_kallsyms_lookup_name("input_class");
    if (!input_class)
        return -ENOENT;

    match.input_type = (const struct device_type *)
        generic_kallsyms_lookup_name("input_dev_type");
    if (!match.input_type)
        return -EOPNOTSUPP;

    ret = class_for_each_device(input_class, NULL, &match, match_touchscreen);
    if (ret < 0) {
        if (match.dev)
            put_device(&match.dev->dev);
        return ret;
    }
    if (!match.dev)
        return -ENODEV;

    dev = match.dev;
    original_slots = 0;
    reserve = 0;
    phys_width = 0;
    phys_height = 0;
    has_touch_major = false;
    has_width_major = false;
    has_pressure = false;

    spin_lock_irqsave(&dev->event_lock, irq_flags);
    if (dev->mt)
        original_slots = dev->mt->num_slots;
    if (dev->absinfo) {
        phys_width = dev->absinfo[ABS_MT_POSITION_X].maximum;
        phys_height = dev->absinfo[ABS_MT_POSITION_Y].maximum;
        has_touch_major = test_bit(ABS_MT_TOUCH_MAJOR, dev->absbit) &&
            dev->absinfo[ABS_MT_TOUCH_MAJOR].maximum >
            dev->absinfo[ABS_MT_TOUCH_MAJOR].minimum;
        has_width_major = test_bit(ABS_MT_WIDTH_MAJOR, dev->absbit) &&
            dev->absinfo[ABS_MT_WIDTH_MAJOR].maximum >
            dev->absinfo[ABS_MT_WIDTH_MAJOR].minimum;
        has_pressure = test_bit(ABS_MT_PRESSURE, dev->absbit) &&
            dev->absinfo[ABS_MT_PRESSURE].maximum >
            dev->absinfo[ABS_MT_PRESSURE].minimum;
    }
    spin_unlock_irqrestore(&dev->event_lock, irq_flags);

    if (original_slots > VTOUCH_MIN_REAL_SLOTS)
        reserve = vtouch_reserved_from_total_locked(original_slots);

    out->initialized = reserve > 0 ? 1 : 0;
    out->has_dev = 1;
    out->phys_width = phys_width;
    out->phys_height = phys_height;
    out->user_width = vt.user_width > 1 ? vt.user_width : phys_width + 1;
    out->user_height = vt.user_height > 1 ? vt.user_height : phys_height + 1;
    out->is_touching = 0;
    out->has_touch_major = has_touch_major ? 1 : 0;
    out->has_width_major = has_width_major ? 1 : 0;
    out->has_pressure = has_pressure ? 1 : 0;
    out->tracking_id = -1;
    out->reserved = reserve;
    if (dev->name) {
        strncpy(out->dev_name, dev->name, sizeof(out->dev_name) - 1);
        out->dev_name[sizeof(out->dev_name) - 1] = '\0';
    }

    put_device(&dev->dev);
    return reserve > 0 ? 0 : -ENOSPC;
}

static void release_all_slots_locked(void)
{
    int i;

    if (!vt.dev) {
        clear_slot_states_locked();
        return;
    }

        for (i = 0; i < vtouch_slot_limit_locked(); i++) {
            vt.slots[i].active = false;
        vt.slots[i].tracking_id = -1;
        /* Reset every reserved hardware slot, including states which may have
         * diverged after a failed userspace/client lifecycle. */
        report_contact_locked(i, 0, 0, false);
    }

    vt.active_count = 0;
}

int touch_init(void)
{
    int ret = 0;

    mutex_lock(&vt.state_lock);
    clear_slot_states_locked();
    if (!vt.pm_notifier_registered) {
        ret = register_pm_notifier(&touch_pm_notifier);
        if (!ret)
            vt.pm_notifier_registered = true;
    }
    mutex_unlock(&vt.state_lock);
    return ret;
}

void touch_exit(void)
{
    if (vt.pm_notifier_registered) {
        unregister_pm_notifier(&touch_pm_notifier);
        vt.pm_notifier_registered = false;
    }
    mutex_lock(&vt.state_lock);
    release_all_slots_locked();
    restore_physical_device_locked();
    clear_slot_states_locked();
    mutex_unlock(&vt.state_lock);
}

int touch_set_slots(int slots)
{
    if (slots <= 0 || slots > VTOUCH_MAX_SLOTS)
        return -EINVAL;

    mutex_lock(&vt.state_lock);
    if (vt.active_count != 0) {
        mutex_unlock(&vt.state_lock);
        return -EBUSY;
    }

    if (slots != vt.configured_slots) {
        restore_physical_device_locked();
        vt.configured_slots = slots;
        clear_slot_states_locked();
    }
    mutex_unlock(&vt.state_lock);
    return 0;
}

int touch_slot_down(int slot, int x, int y)
{
    int ret;

    mutex_lock(&vt.state_lock);
        if (slot < 0 || slot >= vt.configured_slots) {
            ret = -EINVAL;
            goto out;
        }
    if (vt.slots[slot].active) {
        ret = -EALREADY;
        goto out;
    }

        ret = ensure_device_locked();
        if (ret)
            goto out;
        if (slot >= vt.reserved_slots) {
            ret = -ENOSPC;
            goto out;
        }

        vt.slots[slot].active = true;
        vt.slots[slot].tracking_id = next_tracking_id_locked();
    vt.active_count++;
    ret = report_contact_locked(slot, x, y, true);
    if (ret) {
        vt.slots[slot].active = false;
        vt.slots[slot].tracking_id = -1;
        vt.active_count--;
        if (vt.active_count == 0)
            restore_physical_device_locked();
        goto out;
    }

    /*
     * Keep the touchscreen key capabilities visible while a virtual contact is
     * held.  On devices with a small MT slot count (Ace5Pro class hardware),
     * hiding BTN_TOUCH/BTN_TOOL_* during the aim drag can make newly pressed
     * fire/scope fingers arrive without their companion key state and the game
     * may miss that press.  The per-frame global-key report above already
     * publishes physical+virtual contact count, so the capability-bit lock is
     * skipped for the aim slot path.
     */
    if (vt.active_count == 1) {
        unsigned long irq_flags;

        spin_lock_irqsave(&vt.dev->event_lock, irq_flags);
        set_global_key_bits_locked(true);
        vt.global_keys_locked = false;
        spin_unlock_irqrestore(&vt.dev->event_lock, irq_flags);
    }
out:
    mutex_unlock(&vt.state_lock);
    return ret;
}

int touch_slot_move(int slot, int x, int y)
{
    int ret = 0;

    mutex_lock(&vt.state_lock);
        if (slot < 0 || slot >= vtouch_slot_limit_locked()) {
            ret = -EINVAL;
            goto out;
        }
    if (!vt.dev || !vt.initialized) {
        ret = -ENODEV;
        goto out;
    }
    if (!vt.slots[slot].active) {
        ret = -ENOENT;
        goto out;
    }

    ret = report_contact_locked(slot, x, y, true);
    if (ret) {
        release_all_slots_locked();
        restore_physical_device_locked();
    }
out:
    mutex_unlock(&vt.state_lock);
    return ret;
}

int touch_slot_up(int slot)
{
    int ret = 0;
    bool last_virtual;

    mutex_lock(&vt.state_lock);
        if (slot < 0 || slot >= vtouch_slot_limit_locked()) {
            ret = -EINVAL;
            goto out;
        }
    if (!vt.dev || !vt.initialized) {
        ret = -ENODEV;
        goto out;
    }
    if (!vt.slots[slot].active) {
        ret = -ENOENT;
        goto out;
    }

    vt.slots[slot].active = false;
    vt.slots[slot].tracking_id = -1;
    if (vt.active_count > 0)
        vt.active_count--;
    last_virtual = vt.active_count == 0;
    ret = report_contact_locked(slot, 0, 0, false);

    if (ret) {
        release_all_slots_locked();
        restore_physical_device_locked();
    } else if (last_virtual) {
        /* Keep PM/FOD/screen-off paths on the untouched physical MT state. */
        restore_physical_device_locked();
    }
out:
    mutex_unlock(&vt.state_lock);
    return ret;
}

void touch_up_all(void)
{
    mutex_lock(&vt.state_lock);
    release_all_slots_locked();
    restore_physical_device_locked();
    clear_slot_states_locked();
    mutex_unlock(&vt.state_lock);
}

void touch_release_slots(unsigned long slot_mask)
{
    int i;
    int ret = 0;

    mutex_lock(&vt.state_lock);
        for (i = 0; i < vtouch_slot_limit_locked(); i++) {
            if (!(slot_mask & BIT(i)) || !vt.slots[i].active)
            continue;
        vt.slots[i].active = false;
        vt.slots[i].tracking_id = -1;
        if (vt.active_count > 0)
            vt.active_count--;
        if (vt.dev && report_contact_locked(i, 0, 0, false))
            ret = -EIO;
    }
    if (ret) {
        release_all_slots_locked();
        restore_physical_device_locked();
    } else if (vt.active_count == 0) {
        restore_physical_device_locked();
    }
    mutex_unlock(&vt.state_lock);
}

int touch_down(int x, int y)
{
    return touch_slot_down(0, x, y);
}

int touch_move(int x, int y)
{
    return touch_slot_move(0, x, y);
}

int touch_up(void)
{
    return touch_slot_up(0);
}

int touch_set_resolution(int width, int height)
{
    if (width <= 1 || height <= 1) {
        NBG_FAIL_CODE(3031, -EINVAL);
        return -EINVAL;
    }

    mutex_lock(&vt.state_lock);
    if (vt.active_count != 0 &&
        (width != vt.user_width || height != vt.user_height)) {
        mutex_unlock(&vt.state_lock);
        NBG_FAIL_CODE(3032, -EBUSY);
        return -EBUSY;
    }
    vt.user_width = width;
    vt.user_height = height;
    mutex_unlock(&vt.state_lock);
    return 0;
}

void touch_query_state(struct touch_diag *out)
{
    if (!out)
        return;

    mutex_lock(&vt.state_lock);
    memset(out, 0, sizeof(*out));
    out->tracking_id = -1;
    if (!vt.dev) {
        probe_touchscreen_diag_locked(out);
    } else {
        out->initialized = vt.initialized ? 1 : 0;
        out->has_dev = 1;
        out->phys_width = vt.phys_width;
        out->phys_height = vt.phys_height;
        out->user_width = vt.user_width;
        out->user_height = vt.user_height;
        out->is_touching = vt.active_count > 0 ? 1 : 0;
        out->has_touch_major = vt.has_touch_major ? 1 : 0;
        out->has_width_major = vt.has_width_major ? 1 : 0;
        out->has_pressure = vt.has_pressure ? 1 : 0;
        out->tracking_id = vt.slots[0].tracking_id;
        out->reserved = vtouch_slot_limit_locked();
        if (vt.dev->name) {
            strncpy(out->dev_name, vt.dev->name, sizeof(out->dev_name) - 1);
            out->dev_name[sizeof(out->dev_name) - 1] = '\0';
        }
    }
    mutex_unlock(&vt.state_lock);
}
