/* Opt-in, short-lease SensorService gyro test overlay. */
#include <linux/errno.h>
#include <linux/atomic.h>
#include <linux/jiffies.h>
#include <linux/kprobes.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "comm.h"
#include "export_fun.h"
#include "gyro.h"
#include "gyro_math.h"
#include "nbg_log.h"

#define NBG_SENSOR_MAX_BATCH 1000U

struct nbg_gyro_state {
    bool enabled;
    u32 type_mask;
    s64 delta_x_q32;
    s64 delta_y_q32;
    unsigned long expires;
};

static DEFINE_SPINLOCK(gyro_state_lock);
static struct nbg_gyro_state gyro_state;
static atomic64_t gyro_modified_events = ATOMIC64_INIT(0);
static struct kprobe gyro_sendto_kprobe;
static bool gyro_probe_registered;
static bool gyro_syscall_wrapper;

static bool gyro_caller_is_system_server(void)
{
    const struct task_struct *leader = current->group_leader;

    return leader && strncmp(leader->comm, "system_server", TASK_COMM_LEN) == 0;
}

static void gyro_update_event(unsigned long event,
                              const struct nbg_gyro_state *state)
{
    s32 type;
    u32 xy[2];
    u32 result_x, result_y;
    bool selected = false;

    if (copy_from_user_nofault(&type,
            (const void __user *)(event + NBG_GYRO_EVENT_TYPE_OFFSET), sizeof(type)))
        return;
    selected = nbg_gyro_type_selected(type, state->type_mask);
    if (!selected || (!state->delta_x_q32 && !state->delta_y_q32))
        return;
    if (copy_from_user_nofault(xy,
            (const void __user *)(event + NBG_GYRO_EVENT_DATA_OFFSET), sizeof(xy)))
        return;
    if (nbg_gyro_add_xy(xy[0], xy[1], state->delta_x_q32,
                        state->delta_y_q32, &result_x, &result_y) != 0)
        return;
    xy[0] = result_x;
    xy[1] = result_y;
    if (!copy_to_user_nofault((void __user *)(event + NBG_GYRO_EVENT_DATA_OFFSET),
                              xy, sizeof(xy)))
        atomic64_inc(&gyro_modified_events);
}

static int gyro_sendto_pre(struct kprobe *probe, struct pt_regs *regs)
{
    struct nbg_gyro_state state;
    unsigned long buffer, length;
    unsigned long flags;
    unsigned int count, index;

    (void)probe;
    if (!READ_ONCE(gyro_state.enabled) ||
        !time_before(jiffies, READ_ONCE(gyro_state.expires)))
        return 0;
    if (!gyro_caller_is_system_server())
        return 0;

    spin_lock_irqsave(&gyro_state_lock, flags);
    state = gyro_state;
    spin_unlock_irqrestore(&gyro_state_lock, flags);
    if (!state.enabled || !time_before(jiffies, state.expires))
        return 0;

    if (gyro_syscall_wrapper) {
        struct pt_regs *user_regs = (struct pt_regs *)(unsigned long)regs->regs[0];
        if (!user_regs)
            return 0;
        buffer = user_regs->regs[1];
        length = user_regs->regs[2];
    } else {
        buffer = regs->regs[1];
        length = regs->regs[2];
    }

    if (!buffer || !length ||
        length > NBG_GYRO_EVENT_SIZE * NBG_SENSOR_MAX_BATCH ||
        length % NBG_GYRO_EVENT_SIZE ||
        buffer > ULONG_MAX - length)
        return 0;

    count = (unsigned int)(length / NBG_GYRO_EVENT_SIZE);
    for (index = 0; index < count; ++index)
        gyro_update_event(buffer + (unsigned long)index * NBG_GYRO_EVENT_SIZE,
                          &state);
    return 0;
}

int nbg_gyro_init(void)
{
    static const char * const candidates[] = {
        "__arm64_sys_sendto",
        "__se_sys_sendto",
        "sys_sendto",
        NULL,
    };
    int index, ret = -ENOENT;

    if (gyro_probe_registered)
        return 0;
    for (index = 0; candidates[index]; ++index) {
        memset(&gyro_sendto_kprobe, 0, sizeof(gyro_sendto_kprobe));
        gyro_sendto_kprobe.pre_handler = gyro_sendto_pre;
        ret = nbg_register_kprobe_named(&gyro_sendto_kprobe,
                                        &candidates[index], NULL);
        if (!ret) {
            gyro_probe_registered = true;
            gyro_syscall_wrapper = index == 0;
            NBG_INFO("gyro test hook installed at %s\n", candidates[index]);
            return 0;
        }
    }
    NBG_WARN("gyro test hook unavailable: %d\n", ret);
    return ret;
}

int nbg_gyro_configure(NBG_GYRO_CONFIG *config)
{
    struct nbg_gyro_state next = {};
    unsigned long flags;

    if (!config || config->abi_version != NBG_GYRO_ABI_VERSION ||
        config->reserved || config->enabled > 1U ||
        (config->type_mask & ~(NBG_GYRO_TYPE_GYROSCOPE |
                               NBG_GYRO_TYPE_UNCALIBRATED)) ||
        (config->enabled && (!config->type_mask || !config->lease_ms ||
         config->lease_ms > NBG_GYRO_MAX_LEASE_MS)))
        return -EINVAL;
    if (!gyro_probe_registered)
        return -EOPNOTSUPP;

    if (nbg_gyro_bits_to_q32(config->delta_x_bits, &next.delta_x_q32) ||
        nbg_gyro_bits_to_q32(config->delta_y_bits, &next.delta_y_q32) ||
        next.delta_x_q32 > (1LL << 32) || next.delta_x_q32 < -(1LL << 32) ||
        next.delta_y_q32 > (1LL << 32) || next.delta_y_q32 < -(1LL << 32))
        return -ERANGE;

    next.enabled = config->enabled != 0;
    next.type_mask = config->type_mask;
    next.expires = next.enabled
        ? jiffies + msecs_to_jiffies(config->lease_ms) : jiffies;
    spin_lock_irqsave(&gyro_state_lock, flags);
    gyro_state = next;
    spin_unlock_irqrestore(&gyro_state_lock, flags);

    config->enabled = next.enabled;
    config->type_mask = next.type_mask;
    config->modified_events = atomic64_read(&gyro_modified_events);
    config->hook_available = 1;
    return 0;
}

void nbg_gyro_exit(void)
{
    unsigned long flags;

    spin_lock_irqsave(&gyro_state_lock, flags);
    memset(&gyro_state, 0, sizeof(gyro_state));
    spin_unlock_irqrestore(&gyro_state_lock, flags);
    if (gyro_probe_registered) {
        nbg_unregister_kprobe(&gyro_sendto_kprobe);
        gyro_probe_registered = false;
    }
}
