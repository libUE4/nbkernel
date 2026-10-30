/* hwbp_regset_filter.c - exact raw BP/WP PTRACE_GETREGSET filtering.
 *
 * This component only filters raw hardware-debug records after the kernel
 * copies a matching GETREGSET result to userspace.  It does not inspect or
 * rewrite PID arguments for syscall entry points.
 */
#include "hwbp_regset_filter.h"
#include "hide_internal.h"
#include "nbg_compat.h"
#include "nbg_ksyms.h"
#include "hwbp_raw.h"

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/ptrace.h>
#include <linux/sched/task.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif
#include <asm/ptrace.h>

/*
 * ptrace GETREGSET returns an eight-byte resource header followed by
 * (address, control, padding) records. Keep the header and the kernel's
 * iov_len update intact, and clear only the record payload that matches an
 * active raw slot. Ordinary hardware-debug records remain unchanged.
 */
#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#endif
#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x402
#endif
#ifndef NT_ARM_HW_WATCH
#define NT_ARM_HW_WATCH 0x403
#endif

#define NBG_HWDEBUG_INFO_SIZE    8U
#define NBG_HWDEBUG_RECORD_SIZE  16U
#define NBG_HWDEBUG_MAX_RECORDS  16U
#define NBG_HWDEBUG_MAX_BYTES    (NBG_HWDEBUG_INFO_SIZE + \
                                  NBG_HWDEBUG_RECORD_SIZE * \
                                  NBG_HWDEBUG_MAX_RECORDS)
#define NBG_HWDEBUG_MAX_RAW_ADDRESSES \
    ((MAX_RAW_BP > MAX_RAW_WP) ? MAX_RAW_BP : MAX_RAW_WP)

struct nbg_hwdebug_record {
    u64 addr;
    u32 ctrl;
    u32 pad;
};

struct nbg_ptrace_regset_data {
    bool filter;
    bool is_break;
    u8 raw_count;
    void __user *iov_base;
    size_t iov_len;
    u64 raw_addresses[NBG_HWDEBUG_MAX_RAW_ADDRESSES];
};

static DEFINE_MUTEX(regset_filter_lock);

static bool nbg_capture_ptrace_regset(struct pt_regs *regs, bool compat,
                                      struct nbg_ptrace_regset_data *d)
{
    struct task_struct *child;
    unsigned long iov_addr;
    unsigned long request;
    unsigned long note;
    pid_t tgid;
    u64 base;
    u64 len;
#ifdef CONFIG_COMPAT
    u32 compat_base;
    u32 compat_len;
#else
    (void)compat;
#endif

    if (!regs || !d)
        return false;
    memset(d, 0, sizeof(*d));

    child = (struct task_struct *)(uintptr_t)READ_ONCE(regs->regs[0]);
    request = READ_ONCE(regs->regs[1]);
    note = READ_ONCE(regs->regs[2]);
    iov_addr = READ_ONCE(regs->regs[3]);
    if (!child || request != (unsigned long)PTRACE_GETREGSET)
        return false;

    tgid = task_tgid_nr(child);
    if (note == (unsigned long)NT_ARM_HW_BREAK) {
        d->is_break = true;
        d->raw_count = (u8)raw_hwbp_snapshot(
            tgid, d->raw_addresses, NBG_HWDEBUG_MAX_RAW_ADDRESSES);
    } else if (note == (unsigned long)NT_ARM_HW_WATCH) {
        d->is_break = false;
        d->raw_count = (u8)raw_hwwp_snapshot(
            tgid, d->raw_addresses, NBG_HWDEBUG_MAX_RAW_ADDRESSES);
    } else {
        return false;
    }
    if (!d->raw_count || !iov_addr)
        return false;

#ifdef CONFIG_COMPAT
    if (compat) {
        if (iov_addr > ULONG_MAX - 8UL ||
            !access_ok((void __user *)iov_addr, 8U))
            return false;
        if (__get_user(compat_base, (u32 __user *)iov_addr) ||
            __get_user(compat_len,
                       (u32 __user *)(iov_addr + sizeof(compat_base))))
            return false;
        d->iov_base = compat_ptr(compat_base);
        d->iov_len = (size_t)compat_len;
        d->filter = d->iov_base != NULL &&
            d->iov_len > NBG_HWDEBUG_INFO_SIZE;
        return d->filter;
    }
#endif

    if (iov_addr > ULONG_MAX - 16UL ||
        !access_ok((void __user *)iov_addr, 16U))
        return false;
    if (__get_user(base, (u64 __user *)iov_addr) ||
        __get_user(len, (u64 __user *)(iov_addr + sizeof(base))))
        return false;
    d->iov_base = (void __user *)(uintptr_t)base;
    d->iov_len = (size_t)len;
    d->filter = d->iov_base != NULL &&
        d->iov_len > NBG_HWDEBUG_INFO_SIZE;
    return d->filter;
}

static bool nbg_raw_record_matches(const struct nbg_ptrace_regset_data *d,
                                   u64 address)
{
    u8 i;

    if (!d || !address)
        return false;
    for (i = 0; i < d->raw_count; i++) {
        if (d->is_break) {
            if (address == d->raw_addresses[i])
                return true;
        } else if ((address & ~0x7ULL) == d->raw_addresses[i]) {
            return true;
        }
    }
    return false;
}

static void nbg_filter_ptrace_regset_records(
    const struct nbg_ptrace_regset_data *d)
{
    unsigned long dst;
    size_t bytes;
    size_t records;
    size_t i;

    if (!d || !d->filter || !d->iov_base ||
        d->iov_len <= NBG_HWDEBUG_INFO_SIZE)
        return;

    bytes = d->iov_len;
    if (bytes > NBG_HWDEBUG_MAX_BYTES)
        bytes = NBG_HWDEBUG_MAX_BYTES;
    if (bytes <= NBG_HWDEBUG_INFO_SIZE)
        return;

    dst = (unsigned long)d->iov_base;
    if (dst > ULONG_MAX - NBG_HWDEBUG_INFO_SIZE)
        return;
    dst += NBG_HWDEBUG_INFO_SIZE;
    bytes -= NBG_HWDEBUG_INFO_SIZE;
    records = bytes / NBG_HWDEBUG_RECORD_SIZE;
    if (!records || !access_ok((void __user *)dst,
                               records * NBG_HWDEBUG_RECORD_SIZE))
        return;

    /* The kernel has just copied this regset to userspace. Use no-fault
     * accesses because the kretprobe return handler must not sleep. */
    pagefault_disable();
    for (i = 0; i < records; i++, dst += NBG_HWDEBUG_RECORD_SIZE) {
        struct nbg_hwdebug_record record;

        if (__get_user(record.addr, (u64 __user *)dst) ||
            __get_user(record.ctrl,
                       (u32 __user *)(dst + offsetof(
                           struct nbg_hwdebug_record, ctrl))))
            break;
        if (!(record.ctrl & 1U) ||
            !nbg_raw_record_matches(d, record.addr))
            continue;
        if (__put_user(0ULL, (u64 __user *)dst) ||
            __put_user(0U, (u32 __user *)(dst + offsetof(
                struct nbg_hwdebug_record, ctrl))) ||
            __put_user(0U, (u32 __user *)(dst + offsetof(
                struct nbg_hwdebug_record, pad))))
            break;
    }
    pagefault_enable();
}

NBG_NO_CFI
static int nbg_ptrace_regset_entry(struct kretprobe_instance *ri,
                                   struct pt_regs *regs)
{
    struct nbg_ptrace_regset_data *d;

    if (!ri || !regs)
        return 1;
    d = (struct nbg_ptrace_regset_data *)ri->data;
    if (!nbg_capture_ptrace_regset(regs, false, d))
        return 1;
    return 0;
}

NBG_NO_CFI
static int nbg_ptrace_regset_ret(struct kretprobe_instance *ri,
                                 struct pt_regs *regs)
{
    struct nbg_ptrace_regset_data *d;

    if (!ri || !regs)
        return 0;
    d = (struct nbg_ptrace_regset_data *)ri->data;
    if (d && d->filter && regs_return_value(regs) == 0)
        nbg_filter_ptrace_regset_records(d);
    return 0;
}

#ifdef CONFIG_COMPAT
NBG_NO_CFI
static int nbg_compat_ptrace_regset_entry(struct kretprobe_instance *ri,
                                          struct pt_regs *regs)
{
    struct nbg_ptrace_regset_data *d;

    if (!ri || !regs)
        return 1;
    d = (struct nbg_ptrace_regset_data *)ri->data;
    if (!nbg_capture_ptrace_regset(regs, true, d))
        return 1;
    return 0;
}
#endif

static struct kretprobe nbg_ptrace_regset_krp;
static bool nbg_ptrace_regset_hooked;
static const char * const nbg_ptrace_request_names[] = {
    "ptrace_request",
    "ptrace_request.constprop.0",
    "ptrace_request.isra.0",
    NULL,
};

#ifdef CONFIG_COMPAT
static struct kretprobe nbg_compat_ptrace_regset_krp;
static bool nbg_compat_ptrace_regset_hooked;
static const char * const nbg_compat_ptrace_request_names[] = {
    "compat_ptrace_request",
    "compat_ptrace_request.constprop.0",
    "compat_ptrace_request.isra.0",
    NULL,
};
#endif

int hwbp_regset_filter_install(void)
{
    int ret = -ENOENT;
    int installed = 0;

    mutex_lock(&regset_filter_lock);
    if (nbg_ptrace_regset_hooked) {
        installed++;
    } else {
        memset(&nbg_ptrace_regset_krp, 0,
               sizeof(nbg_ptrace_regset_krp));
        nbg_ptrace_regset_krp.entry_handler = nbg_ptrace_regset_entry;
        nbg_ptrace_regset_krp.handler = nbg_ptrace_regset_ret;
        nbg_ptrace_regset_krp.data_size =
            sizeof(struct nbg_ptrace_regset_data);
        nbg_ptrace_regset_krp.maxactive = max(num_possible_cpus() * 4, 64U);
        ret = nbg_register_kretprobe_named(&nbg_ptrace_regset_krp,
                                           nbg_ptrace_request_names, NULL);
        if (!ret) {
            track_hidden_kprobe(&nbg_ptrace_regset_krp);
            nbg_ptrace_regset_hooked = true;
            installed++;
        }
    }

#ifdef CONFIG_COMPAT
    if (nbg_compat_ptrace_regset_hooked) {
        installed++;
    } else {
        memset(&nbg_compat_ptrace_regset_krp, 0,
               sizeof(nbg_compat_ptrace_regset_krp));
        nbg_compat_ptrace_regset_krp.entry_handler =
            nbg_compat_ptrace_regset_entry;
        nbg_compat_ptrace_regset_krp.handler = nbg_ptrace_regset_ret;
        nbg_compat_ptrace_regset_krp.data_size =
            sizeof(struct nbg_ptrace_regset_data);
        nbg_compat_ptrace_regset_krp.maxactive =
            max(num_possible_cpus() * 4, 64U);
        ret = nbg_register_kretprobe_named(
            &nbg_compat_ptrace_regset_krp,
            nbg_compat_ptrace_request_names, NULL);
        if (!ret) {
            track_hidden_kprobe(&nbg_compat_ptrace_regset_krp);
            nbg_compat_ptrace_regset_hooked = true;
            installed++;
        }
    }
#endif

    mutex_unlock(&regset_filter_lock);
    return installed ? 0 : ret;
}

void hwbp_regset_filter_cleanup(void)
{
    mutex_lock(&regset_filter_lock);
#ifdef CONFIG_COMPAT
    if (nbg_compat_ptrace_regset_hooked) {
        untrack_hidden_kprobe(&nbg_compat_ptrace_regset_krp);
        unregister_kretprobe(&nbg_compat_ptrace_regset_krp);
        nbg_compat_ptrace_regset_hooked = false;
    }
#endif
    if (nbg_ptrace_regset_hooked) {
        untrack_hidden_kprobe(&nbg_ptrace_regset_krp);
        unregister_kretprobe(&nbg_ptrace_regset_krp);
        nbg_ptrace_regset_hooked = false;
    }
    mutex_unlock(&regset_filter_lock);
}
