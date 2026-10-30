/* Passive input subscriptions. Registered only while an authenticated client
 * subscribes; no grabs, injections, persisted events or visibility changes. */
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/input.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include "nbg_alloc.h"
#include "nbg_readonly.h"
#define RO_RING_SIZE 512U
struct ro_input {
    struct input_handle handle;
    struct list_head list;
    struct NbgRoInputDevice description;
    struct NbgRoInputEvent ring[RO_RING_SIZE];
    u64 sequence;
};
static LIST_HEAD(ro_inputs);
static DEFINE_SPINLOCK(ro_input_lock);
static DEFINE_MUTEX(ro_subscription_lock);
static unsigned int ro_subscribers, ro_device_count, ro_next_id = 1;
static struct input_handler ro_handler;
static void ro_input_event(struct input_handle *handle, unsigned int type,
                           unsigned int code, int value)
{
    struct ro_input *input = handle->private;
    unsigned long flags;
    struct NbgRoInputEvent *event;
    if (type != EV_SYN && type != EV_ABS && type != EV_KEY) return;
    spin_lock_irqsave(&ro_input_lock, flags);
    event = &input->ring[input->sequence % RO_RING_SIZE];
    event->type = type; event->code = code; event->value = value;
    ++input->sequence;
    spin_unlock_irqrestore(&ro_input_lock, flags);
}
static int ro_input_connect(struct input_handler *handler, struct input_dev *dev,
                            const struct input_device_id *id)
{
    struct ro_input *input;
    unsigned int capabilities = 0, code, letters = 0;
    unsigned long flags;
    int result;
    if (test_bit(EV_ABS, dev->evbit) && test_bit(ABS_MT_SLOT, dev->absbit) &&
        test_bit(ABS_MT_TRACKING_ID, dev->absbit) &&
        test_bit(ABS_MT_POSITION_X, dev->absbit) && test_bit(ABS_MT_POSITION_Y, dev->absbit))
        capabilities |= NBG_RO_INPUT_TOUCH;
    for (code = KEY_A; code <= KEY_Z; ++code) if (test_bit(code, dev->keybit)) ++letters;
    if (letters >= 20 || test_bit(KEY_VOLUMEUP, dev->keybit) || test_bit(KEY_VOLUMEDOWN, dev->keybit))
        capabilities |= NBG_RO_INPUT_KEYS;
    if (!capabilities) return -ENODEV;
    input = nbg_kzalloc(sizeof(*input), GFP_KERNEL); if (!input) return -ENOMEM;
    input->description.capabilities = capabilities;
    if (capabilities & NBG_RO_INPUT_TOUCH) {
        input->description.x_min = input_abs_get_min(dev, ABS_MT_POSITION_X);
        input->description.x_max = input_abs_get_max(dev, ABS_MT_POSITION_X);
        input->description.y_min = input_abs_get_min(dev, ABS_MT_POSITION_Y);
        input->description.y_max = input_abs_get_max(dev, ABS_MT_POSITION_Y);
        input->description.slot_min = input_abs_get_min(dev, ABS_MT_SLOT);
        input->description.slot_max = input_abs_get_max(dev, ABS_MT_SLOT);
    }
    for (code = 0; code <= KEY_MAX && code < sizeof(input->description.key_bits) * 8; ++code)
        if (test_bit(code, dev->keybit)) input->description.key_bits[code / 8] |= 1U << (code % 8);
    input->handle.dev = dev; input->handle.handler = handler;
    input->handle.name = "nbg-readonly-input"; input->handle.private = input;
    result = input_register_handle(&input->handle); if (result) goto free_input;
    result = input_open_device(&input->handle); if (result) goto unregister;
    spin_lock_irqsave(&ro_input_lock, flags);
    if (ro_device_count >= NBG_RO_INPUT_MAX_DEVICES || !ro_next_id) {
        spin_unlock_irqrestore(&ro_input_lock, flags);
        result = -ENOSPC; input_close_device(&input->handle); goto unregister;
    }
    input->description.id = ro_next_id++; ++ro_device_count;
    list_add_tail(&input->list, &ro_inputs);
    spin_unlock_irqrestore(&ro_input_lock, flags);
    return 0;
unregister:
    input_unregister_handle(&input->handle);
free_input:
    kfree(input); return result;
}
static void ro_input_disconnect(struct input_handle *handle)
{
    struct ro_input *input = handle->private;
    unsigned long flags;
    spin_lock_irqsave(&ro_input_lock, flags);
    list_del(&input->list); --ro_device_count;
    spin_unlock_irqrestore(&ro_input_lock, flags);
    input_close_device(handle); input_unregister_handle(handle); kfree(input);
}
static const struct input_device_id ro_input_ids[] = { { .driver_info = 1 }, {} };
static struct input_handler ro_handler = {
    .event = ro_input_event, .connect = ro_input_connect, .disconnect = ro_input_disconnect,
    .name = "nbg-readonly-input", .id_table = ro_input_ids,
};
static int ro_subscribe(bool *subscribed, bool enabled)
{
    int result = 0;
    mutex_lock(&ro_subscription_lock);
    if (*subscribed == enabled) goto out;
    if (enabled) {
        if (!ro_subscribers) {
            result = input_register_handler(&ro_handler); if (result) goto out;
        }
        ++ro_subscribers; *subscribed = true;
    } else {
        *subscribed = false;
        if (ro_subscribers && --ro_subscribers == 0) input_unregister_handler(&ro_handler);
    }
out:
    mutex_unlock(&ro_subscription_lock); return result;
}
void nbg_input_snapshot_release(bool *subscribed) { if (subscribed) ro_subscribe(subscribed, false); }
long nbg_input_snapshot_ioctl(unsigned int command, unsigned long argument, bool *subscribed)
{
    unsigned long flags;
    struct ro_input *input;
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;
    if (!subscribed) return -ENOTCONN;
    if (command == NBG_RO_INPUT_SUBSCRIBE) {
        struct NbgRoInputSubscription req;
        if (copy_from_user(&req, (void __user *)argument, sizeof(req))) return -EFAULT;
        if (req.abi != NBG_RO_ABI || req.enabled > 1) return -EINVAL;
        return ro_subscribe(subscribed, req.enabled != 0);
    }
    /* Serializes same-socket unsubscribe against list/read requests. */
    mutex_lock(&ro_subscription_lock);
    if (!*subscribed) { mutex_unlock(&ro_subscription_lock); return -ENOTCONN; }
    if (command == NBG_RO_INPUT_LIST) {
        struct NbgRoInputList *req = nbg_kzalloc(sizeof(*req), GFP_KERNEL);
        int result = 0;
        if (!req) { mutex_unlock(&ro_subscription_lock); return -ENOMEM; }
        if (copy_from_user(req, (void __user *)argument, sizeof(*req))) { result = -EFAULT; goto list_out; }
        if (req->abi != NBG_RO_ABI) { result = -EPROTO; goto list_out; }
        memset(req, 0, sizeof(*req)); req->abi = NBG_RO_ABI;
        spin_lock_irqsave(&ro_input_lock, flags);
        list_for_each_entry(input, &ro_inputs, list) {
            req->devices[req->count] = input->description;
            req->devices[req->count++].cursor = input->sequence;
        }
        spin_unlock_irqrestore(&ro_input_lock, flags);
        if (copy_to_user((void __user *)argument, req, sizeof(*req))) result = -EFAULT;
list_out:
        kfree(req); mutex_unlock(&ro_subscription_lock); return result;
    }
    if (command == NBG_RO_INPUT_READ) {
        struct NbgRoInputRead req;
        int result = -ENODEV;
        if (copy_from_user(&req, (void __user *)argument, sizeof(req))) { result = -EFAULT; goto read_out; }
        if (req.abi != NBG_RO_ABI) { result = -EPROTO; goto read_out; }
        req.count = req.flags = 0; memset(req.events, 0, sizeof(req.events));
        spin_lock_irqsave(&ro_input_lock, flags);
        list_for_each_entry(input, &ro_inputs, list) {
            if (input->description.id != req.device) continue;
            if (req.cursor > input->sequence) { result = -ESTALE; break; }
            if (input->sequence - req.cursor > RO_RING_SIZE) {
                req.flags = NBG_RO_INPUT_DROPPED; req.cursor = input->sequence;
            }
            while (req.cursor < input->sequence && req.count < NBG_RO_INPUT_MAX_EVENTS)
                req.events[req.count++] = input->ring[req.cursor++ % RO_RING_SIZE];
            result = 0; break;
        }
        spin_unlock_irqrestore(&ro_input_lock, flags);
        if (!result && copy_to_user((void __user *)argument, &req, sizeof(req))) result = -EFAULT;
read_out:
        mutex_unlock(&ro_subscription_lock); return result;
    }
    mutex_unlock(&ro_subscription_lock); return -ENOTTY;
}
