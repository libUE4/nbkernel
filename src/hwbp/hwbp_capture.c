/* Diagnostic-only one-shot BR X8 capture for offline segment emulation. */
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <asm/ptrace.h>

#include "hwbp_capture.h"
#include "hwbp_raw.h"
#include "memory.h"

#define HWBP_CAPTURE_DEFAULT_TIMEOUT_MS 300U
#define HWBP_CAPTURE_MAX_TIMEOUT_MS     1000U

struct hwbp_capture_context {
    struct mutex lock;
    struct work_struct retire_work;
    struct delayed_work timeout_work;
    atomic_t state;
    bool active;
    pid_t tgid;
    pid_t tid;
    uint64_t target;
    int result;
    uint32_t hits;
    pid_t hit_tid;
    uint32_t flags;
    uint64_t hit_pc;
    uint64_t hit_branch_target;
    uint64_t hit_time_ns;
    uint64_t registers[31];
    uint64_t sp;
    uint64_t pstate;
    bool capture_pointees;
    uint32_t match_enabled;
    uint32_t match_register;
    uint64_t match_value;
    uint32_t pointee_valid_mask;
    uint64_t pointee_address[NBG_HWBP_CAPTURE_POINTEE_COUNT];
    uint8_t pointee_data[NBG_HWBP_CAPTURE_POINTEE_COUNT][NBG_HWBP_CAPTURE_POINTEE_SIZE];
    uint64_t stack_address;
    uint8_t stack_data[NBG_HWBP_CAPTURE_STACK_SIZE];
};

static struct hwbp_capture_context capture;

static bool hwbp_capture_tid_matches(pid_t tgid, pid_t tid)
{
    struct task_struct *task;
    bool matches = false;

    rcu_read_lock();
    task = pid_task(find_vpid(tid), PIDTYPE_PID);
    if (task && task->tgid == tgid)
        matches = true;
    rcu_read_unlock();
    return matches;
}

static pid_t hwbp_capture_normalize_tgid(pid_t pid)
{
    struct task_struct *task;
    pid_t tgid = 0;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        tgid = task->tgid;
    rcu_read_unlock();
    return tgid;
}

/* Runs in the trapped task. Never faults pages in, sleeps, allocates, or
 * writes target memory. Clear a partial copy so invalid data cannot resemble
 * a successful sample. Other threads can still change shared data. */
static bool hwbp_capture_read_user_words(unsigned long address, uint8_t *out,
                                         size_t size)
{
    size_t offset;
    int ret = -EFAULT;

    if (address >= 0x10000UL && size && !(size % sizeof(uint64_t)) &&
        access_ok((const void __user *)address, size)) {
        /* Match watch_get_user_u64: inline exception-table reads avoid the
         * device's protected copy_from_user_nofault module import. */
        pagefault_disable();
        for (offset = 0; offset < size; offset += sizeof(uint64_t)) {
            uint64_t word = 0;

            ret = __get_user(word, (const uint64_t __user *)(address + offset));
            if (ret)
                break;
            memcpy(out + offset, &word, sizeof(word));
        }
        pagefault_enable();
    }
    if (ret)
        memset(out, 0, size);
    return !ret;
}

static void hwbp_capture_pointees(struct pt_regs *regs)
{
    static const unsigned int indexes[NBG_HWBP_CAPTURE_POINTEE_COUNT] = {
        0, 1, 19, 20
    };
    const unsigned long stack_address = untagged_addr(regs->sp);
    unsigned int i;

    for (i = 0; i < NBG_HWBP_CAPTURE_POINTEE_COUNT; ++i) {
        const unsigned long address = untagged_addr(regs->regs[indexes[i]]);
        capture.pointee_address[i] = address;
        if (hwbp_capture_read_user_words(address, capture.pointee_data[i],
                                         NBG_HWBP_CAPTURE_POINTEE_SIZE))
            capture.pointee_valid_mask |= 1U << i;
    }
    capture.stack_address = stack_address;
    if (hwbp_capture_read_user_words(stack_address, capture.stack_data,
                                     NBG_HWBP_CAPTURE_STACK_SIZE))
        capture.pointee_valid_mask |= NBG_HWBP_CAPTURE_STACK_VALID;
}

/* raw HWBP advances PC by four after callbacks. Storing X8 - 4 means that
 * advance lands at the exact BR X8 destination, including unmatched hits. */
static void hwbp_capture_callback(struct pt_regs *regs, void *private)
{
    const uint64_t branch_target = regs->regs[8];

    (void)private;
    if (READ_ONCE(capture.active) && current &&
        current->tgid == READ_ONCE(capture.tgid) &&
        (!READ_ONCE(capture.tid) ||
         current->pid == READ_ONCE(capture.tid)) &&
        (!READ_ONCE(capture.match_enabled) ||
         regs->regs[READ_ONCE(capture.match_register)] ==
             READ_ONCE(capture.match_value)) &&
        atomic_cmpxchg(&capture.state, NBG_HWBP_CAPTURE_ARMED,
                       NBG_HWBP_CAPTURE_CAPTURING) ==
            NBG_HWBP_CAPTURE_ARMED) {
        memcpy(capture.registers, regs->regs, sizeof(capture.registers));
        capture.sp = regs->sp;
        capture.pstate = regs->pstate;
        capture.hit_pc = regs->pc;
        capture.hit_branch_target = branch_target;
        capture.hit_time_ns = ktime_get_ns();
        capture.hit_tid = current->pid;
        capture.hits = 1;
        capture.flags = NBG_HWBP_CAPTURE_FLAG_BRANCH_EMULATED;
        if (capture.capture_pointees)
            hwbp_capture_pointees(regs);
        smp_store_release(&capture.state.counter, NBG_HWBP_CAPTURE_HIT);
        schedule_work(&capture.retire_work);
    }
    regs->pc = branch_target - 4U;
}

static void hwbp_capture_retire(struct work_struct *work)
{
    pid_t tgid;
    uint64_t target;
    int ret;

    (void)work;
    mutex_lock(&capture.lock);
    if (!capture.active) {
        mutex_unlock(&capture.lock);
        return;
    }
    tgid = capture.tgid;
    target = capture.target;
    ret = raw_hwbp_del_pid(tgid, target);
    if (ret && ret != -ENOENT) {
        capture.result = ret;
    } else {
        capture.result = 0;
        WRITE_ONCE(capture.active, false);
    }
    mutex_unlock(&capture.lock);
}

static void hwbp_capture_timeout(struct work_struct *work)
{
    (void)work;
    if (atomic_cmpxchg(&capture.state, NBG_HWBP_CAPTURE_ARMED,
                       NBG_HWBP_CAPTURE_TIMED_OUT) ==
        NBG_HWBP_CAPTURE_ARMED)
        schedule_work(&capture.retire_work);
}

static void hwbp_capture_fill(HwbpCaptureReq *request)
{
    const int state = smp_load_acquire(&capture.state.counter);

    request->pid = capture.tgid;
    request->tid = capture.tid;
    request->target_vaddr = capture.target;
    request->expected_instruction = NBG_HWBP_CAPTURE_BR_X8;
    request->state = state;
    request->result = capture.result;
    request->hit_count = 0;
    request->hit_tid = 0;
    request->flags = 0;
    request->hit_pc = 0;
    request->hit_branch_target = 0;
    request->hit_time_ns = 0;
    memset(request->registers, 0, sizeof(request->registers));
    request->sp = 0;
    request->pstate = 0;
    request->match_enabled = capture.match_enabled;
    request->match_register = capture.match_register;
    request->match_value = capture.match_value;
    request->pointee_valid_mask = 0;
    request->reserved_v2 = 0;
    memset(request->pointee_address, 0, sizeof(request->pointee_address));
    memset(request->pointee_data, 0, sizeof(request->pointee_data));
    request->stack_address = 0;
    memset(request->stack_data, 0, sizeof(request->stack_data));
    if (state == NBG_HWBP_CAPTURE_HIT) {
        request->hit_count = capture.hits;
        request->hit_tid = capture.hit_tid;
        request->flags = capture.flags;
        request->hit_pc = capture.hit_pc;
        request->hit_branch_target = capture.hit_branch_target;
        request->hit_time_ns = capture.hit_time_ns;
        memcpy(request->registers, capture.registers,
               sizeof(request->registers));
        request->sp = capture.sp;
        request->pstate = capture.pstate;
        request->pointee_valid_mask = capture.pointee_valid_mask;
        memcpy(request->pointee_address, capture.pointee_address,
               sizeof(request->pointee_address));
        memcpy(request->pointee_data, capture.pointee_data,
               sizeof(request->pointee_data));
        request->stack_address = capture.stack_address;
        memcpy(request->stack_data, capture.stack_data, sizeof(request->stack_data));
    }
}

static void hwbp_capture_reset_locked(void)
{
    capture.tgid = 0;
    capture.tid = 0;
    capture.target = 0;
    capture.result = 0;
    capture.hits = 0;
    capture.hit_tid = 0;
    capture.flags = 0;
    capture.hit_pc = 0;
    capture.hit_branch_target = 0;
    capture.hit_time_ns = 0;
    memset(capture.registers, 0, sizeof(capture.registers));
    capture.sp = 0;
    capture.pstate = 0;
    capture.capture_pointees = false;
    capture.match_enabled = 0;
    capture.match_register = 0;
    capture.match_value = 0;
    capture.pointee_valid_mask = 0;
    memset(capture.pointee_address, 0, sizeof(capture.pointee_address));
    memset(capture.pointee_data, 0, sizeof(capture.pointee_data));
    capture.stack_address = 0;
    memset(capture.stack_data, 0, sizeof(capture.stack_data));
    atomic_set(&capture.state, NBG_HWBP_CAPTURE_IDLE);
}

static int hwbp_capture_arm(HwbpCaptureReq *request)
{
    struct raw_bp_req raw = { 0 };
    uint32_t instruction = 0;
    pid_t tgid;
    uint32_t timeout;
    int ret;

    if (!request->pid || request->tid < 0 ||
        request->target_vaddr < 0x10000U ||
        (request->target_vaddr & 3U) ||
        request->expected_instruction != NBG_HWBP_CAPTURE_BR_X8)
        return -EINVAL;
    if (request->abi_version == NBG_HWBP_CAPTURE_ABI_VERSION &&
        (request->match_enabled > 1U ||
         (request->match_enabled && request->match_register >= 31U) ||
         request->reserved_v2))
        return -EINVAL;
    timeout = request->timeout_ms ? request->timeout_ms :
        HWBP_CAPTURE_DEFAULT_TIMEOUT_MS;
    if (timeout > HWBP_CAPTURE_MAX_TIMEOUT_MS)
        return -EINVAL;
    tgid = hwbp_capture_normalize_tgid(request->pid);
    if (!tgid || (request->tid > 0 &&
                  !hwbp_capture_tid_matches(tgid, request->tid)))
        return -ESRCH;
    if (!read_process_memory_kernel(tgid, request->target_vaddr,
                                    &instruction, sizeof(instruction)) ||
        instruction != NBG_HWBP_CAPTURE_BR_X8)
        return -EINVAL;

    mutex_lock(&capture.lock);
    if (capture.active) {
        hwbp_capture_fill(request);
        mutex_unlock(&capture.lock);
        return -EBUSY;
    }
    mutex_unlock(&capture.lock);
    /* A prior successful capture leaves its harmless timeout queued. Drain it
     * before publishing a new ARMED state so it cannot time out this request. */
    cancel_delayed_work_sync(&capture.timeout_work);
    mutex_lock(&capture.lock);
    if (capture.active) {
        hwbp_capture_fill(request);
        mutex_unlock(&capture.lock);
        return -EBUSY;
    }
    hwbp_capture_reset_locked();
    capture.tgid = tgid;
    capture.tid = request->tid;
    capture.target = request->target_vaddr;
    capture.capture_pointees = request->abi_version == NBG_HWBP_CAPTURE_ABI_VERSION;
    if (capture.capture_pointees && request->match_enabled) {
        capture.match_enabled = 1;
        capture.match_register = request->match_register;
        capture.match_value = request->match_value;
    }
    WRITE_ONCE(capture.active, true);
    atomic_set(&capture.state, NBG_HWBP_CAPTURE_ARMED);
    raw.pid = tgid;
    raw.target_vaddr = request->target_vaddr;
    raw.callback = hwbp_capture_callback;
    raw.priv = &capture;
    ret = raw_hwbp_add_exclusive(&raw);
    if (ret) {
        capture.result = ret;
        WRITE_ONCE(capture.active, false);
        atomic_set(&capture.state, NBG_HWBP_CAPTURE_IDLE);
    } else {
        schedule_delayed_work(&capture.timeout_work,
                              msecs_to_jiffies(timeout));
    }
    hwbp_capture_fill(request);
    mutex_unlock(&capture.lock);
    return ret;
}

static int hwbp_capture_cancel(HwbpCaptureReq *request)
{
    pid_t tgid;
    uint64_t target;
    int ret = 0;

    mutex_lock(&capture.lock);
    if (capture.active && request->pid > 0 &&
        hwbp_capture_normalize_tgid(request->pid) != capture.tgid) {
        mutex_unlock(&capture.lock);
        return -EPERM;
    }
    if (capture.active) {
        tgid = capture.tgid;
        target = capture.target;
        WRITE_ONCE(capture.active, false);
        atomic_set(&capture.state, NBG_HWBP_CAPTURE_CANCELED);
        ret = raw_hwbp_del_pid(tgid, target);
        if (ret == -ENOENT)
            ret = 0;
        capture.result = ret;
    }
    hwbp_capture_fill(request);
    mutex_unlock(&capture.lock);
    cancel_delayed_work_sync(&capture.timeout_work);
    return ret;
}

int hwbp_capture_control(HwbpCaptureReq *request)
{
    int ret;

    if (!request ||
        (request->abi_version != NBG_HWBP_CAPTURE_ABI_VERSION_1 &&
         request->abi_version != NBG_HWBP_CAPTURE_ABI_VERSION))
        return -EPROTO;
    switch (request->action) {
    case NBG_HWBP_CAPTURE_ARM:
        ret = hwbp_capture_arm(request);
        break;
    case NBG_HWBP_CAPTURE_READ:
        mutex_lock(&capture.lock);
        hwbp_capture_fill(request);
        mutex_unlock(&capture.lock);
        ret = request->result;
        break;
    case NBG_HWBP_CAPTURE_CANCEL:
        ret = hwbp_capture_cancel(request);
        break;
    default:
        ret = -EINVAL;
        break;
    }
    request->result = ret;
    return ret;
}

int hwbp_capture_init(void)
{
    memset(&capture, 0, sizeof(capture));
    mutex_init(&capture.lock);
    INIT_WORK(&capture.retire_work, hwbp_capture_retire);
    INIT_DELAYED_WORK(&capture.timeout_work, hwbp_capture_timeout);
    atomic_set(&capture.state, NBG_HWBP_CAPTURE_IDLE);
    return 0;
}

void hwbp_capture_exit(void)
{
    pid_t tgid = 0;
    uint64_t target = 0;

    cancel_delayed_work_sync(&capture.timeout_work);
    mutex_lock(&capture.lock);
    if (capture.active) {
        tgid = capture.tgid;
        target = capture.target;
        WRITE_ONCE(capture.active, false);
    }
    mutex_unlock(&capture.lock);
    if (tgid && target)
        raw_hwbp_del_pid(tgid, target);
    flush_work(&capture.retire_work);
}
