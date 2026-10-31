/* socket_ioctl.c - custom socket family + ioctl dispatch */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/pid.h>
#include <linux/sched/task.h>
#include "nbg_alloc.h"
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/version.h>
#include <linux/mutex.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/refcount.h>
#include <linux/task_work.h>
#include <linux/vmalloc.h>
#include <linux/idr.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#include <asm/processor.h>
#include <asm/ptrace.h>

#include "comm.h"
#include "nbg_readonly.h"
#include "memory.h"
#include "process.h"
#include "query.h"
#include "touch.h"
#include "hwbp_raw.h"
#include "hwbp_capture.h"
#include "hwbp_shadow.h"
#include "hide_core.h"
#include "devpts_filter.h"
#include "hide_file.h"
#include "hide_kgsl.h"
#include "hide_module.h"
#include "hide_proc.h"
#include "nbg_ksyms.h"
#include "nbg_log.h"
#include "nbg_compat.h"

struct nbg_sock_ctx {
    bool authed;
    bool readonly_input_subscribed;
    unsigned long touch_slots;
};

static int registered_family = -1;
static atomic_t authed_clients = ATOMIC_INIT(0);
static DEFINE_MUTEX(nbg_session_cleanup_lock);
static DEFINE_MUTEX(nbg_touch_owner_lock);

int nbg_comm_registered_family(void)
{
    return registered_family;
}

int nbg_comm_authed_clients(void)
{
    return atomic_read(&authed_clients);
}

static struct nbg_sock_ctx *nbg_ctx(struct socket *sock)
{
    return sock && sock->sk ? (struct nbg_sock_ctx *)sock->sk->sk_user_data : NULL;
}

static bool comm_cmd_public(unsigned int cmd)
{
    return cmd == OP_INIT_KEY;
}

static int comm_ioctl_init_key(struct socket *sock, unsigned long arg)
{
    struct nbg_sock_ctx *ctx = nbg_ctx(sock);
    INIT_KEY req;

    if (!ctx)
        return -EINVAL;
    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;

    req.accepted = 0;
    req.family = registered_family;
    req.authed_clients = atomic_read(&authed_clients);
    if (req.abi_version != NBG_ABI_VERSION || req.token != NBG_AUTH_TOKEN) {
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return -EACCES;
    }

    mutex_lock(&nbg_session_cleanup_lock);
    if (!ctx->authed) {
        ctx->authed = true;
        atomic_inc(&authed_clients);
    }
    req.authed_clients = atomic_read(&authed_clients);
    mutex_unlock(&nbg_session_cleanup_lock);

    req.accepted = 1;
    if (copy_to_user((void __user *)arg, &req, sizeof(req)))
        return -EFAULT;
    return 0;
}

static void comm_copy_touch_diag(TOUCH_DIAG *dst, const struct touch_diag *src)
{
    memset(dst, 0, sizeof(*dst));
    dst->initialized = src->initialized;
    dst->has_dev = src->has_dev;
    dst->phys_width = src->phys_width;
    dst->phys_height = src->phys_height;
    dst->user_width = src->user_width;
    dst->user_height = src->user_height;
    dst->is_touching = src->is_touching;
    dst->has_touch_major = src->has_touch_major;
    dst->has_width_major = src->has_width_major;
    dst->has_pressure = src->has_pressure;
    dst->tracking_id = src->tracking_id;
    dst->reserved = src->reserved;
    memcpy(dst->dev_name, src->dev_name, sizeof(dst->dev_name));
}

static void comm_copy_watch_read(WatchReadReq *dst, const WATCH_READ_REQ *src)
{
    uint32_t i, count;

    memset(dst, 0, sizeof(*dst));
    count = src->count;
    if (count > WATCH_BATCH_MAX)
        count = WATCH_BATCH_MAX;
    dst->count = count;
    for (i = 0; i < count; i++) {
        dst->events[i].watch_addr = src->events[i].watch_addr;
        dst->events[i].pc = src->events[i].pc;
        dst->events[i].tid = src->events[i].tid;
        dst->events[i].pid = src->events[i].pid;
        dst->events[i].bp_type = src->events[i].bp_type;
        dst->events[i].hit_count = src->events[i].hit_count;
    }
}

static long comm_ioctl_watch_read(unsigned long arg)
{
    WatchReadReq *req;
    WATCH_READ_REQ *rd;
    int ret;

    req = nbg_kzalloc(sizeof(*req), GFP_KERNEL);
    if (!req)
        return -ENOMEM;

    rd = nbg_kzalloc(sizeof(*rd), GFP_KERNEL);
    if (!rd) {
        kfree(req);
        return -ENOMEM;
    }

    ret = watch_read_kernel(rd);
    if (!ret) {
        comm_copy_watch_read(req, rd);
        if (copy_to_user((void __user *)arg, req, sizeof(*req)))
            ret = -EFAULT;
    }

    kfree(rd);
    kfree(req);
    return ret;
}

static long comm_ioctl_hide_file(unsigned int cmd, unsigned long arg)
{
    HideFileReq req;
    int ret;

    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;

    req.path[NBG_PATH_LEN - 1] = '\0';
    ret = cmd == OP_HIDE_FILE ? hide_file(req.path) : unhide_file(req.path);
    return ret;
}

static long comm_ioctl_devpts_filter(unsigned long arg)
{
    DevptsFilterReq req;
    int ret;

    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;

    ret = devpts_filter_configure(&req);
    if (copy_to_user((void __user *)arg, &req, sizeof(req)))
        return -EFAULT;
    return ret;
}

typedef struct file *(*nbg_fget_task_t)(struct task_struct *task,
                                        unsigned int fd);

static DEFINE_MUTEX(nbg_fget_task_lock);
static nbg_fget_task_t nbg_fget_task_fn;

static nbg_fget_task_t comm_resolve_fget_task(void)
{
    nbg_fget_task_t fn = READ_ONCE(nbg_fget_task_fn);

    if (fn)
        return fn;

    mutex_lock(&nbg_fget_task_lock);
    fn = nbg_fget_task_fn;
    if (!fn) {
        fn = (nbg_fget_task_t)generic_kallsyms_lookup_name("fget_task");
        if (fn)
            WRITE_ONCE(nbg_fget_task_fn, fn);
    }
    mutex_unlock(&nbg_fget_task_lock);
    return fn;
}

typedef void *(*nbg_kgsl_process_find_t)(pid_t pid);
typedef void (*nbg_kgsl_process_put_t)(void *process);

typedef long (*nbg_kgsl_gpuobj_info_t)(void *device_private,
                                      unsigned int command, void *data);

NBG_NO_CFI
static long comm_ioctl_kgsl_gpuobj_info(unsigned long arg)
{
    KgslGpuObjectInfoReq req;
    nbg_fget_task_t fget_task_fn;
    nbg_kgsl_gpuobj_info_t query;
    struct pid *pid;
    struct task_struct *task;
    struct file *file;
    const u32 *query_code;
    void *kgsl_ioctl_address;
    long ret;

    BUILD_BUG_ON(sizeof(KgslGpuObjectInfo) != 48);
    BUILD_BUG_ON(sizeof(KgslGpuObjectInfoReq) != 80);
    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;
    if (req.abi_version != NBG_KGSL_GPUOBJ_INFO_ABI_VERSION)
        return -EPROTO;
    if (req.pid <= 0 || req.target_fd < 0 || !req.object_id)
        return -EINVAL;

    fget_task_fn = comm_resolve_fget_task();
    if (!fget_task_fn)
        return -ENOSYS;
    pid = find_get_pid(req.pid);
    if (!pid)
        return -ESRCH;
    task = get_pid_task(pid, PIDTYPE_PID);
    put_pid(pid);
    if (!task)
        return -ESRCH;
    if (!pid_alive(task) || (READ_ONCE(task->flags) & PF_EXITING) ||
        READ_ONCE(task->tgid) != req.pid) {
        put_task_struct(task);
        return -ESRCH;
    }
    file = fget_task_fn(task, req.target_fd);
    put_task_struct(task);
    if (!file)
        return -EBADF;

    /* The pinned file also pins the vendor driver. Use only its bounded
     * metadata reader with a kernel-owned output buffer. Never run task_work
     * in the game or pass a target address to the vendor ioctl dispatcher. */
    ret = -ENOTTY;
    kgsl_ioctl_address = (void *)generic_kallsyms_lookup_name("kgsl_ioctl");
    if (!file->f_op || !file->private_data ||
        !S_ISCHR(file_inode(file)->i_mode) || !kgsl_ioctl_address ||
        (void *)file->f_op->unlocked_ioctl != kgsl_ioctl_address)
        goto out;

    query = (nbg_kgsl_gpuobj_info_t)
        generic_kallsyms_lookup_name("kgsl_ioctl_gpuobj_info");
    if (!query) {
        ret = -ENOENT;
        goto out;
    }
    query_code = (const u32 *)query;
    /* Verified against this device's msm_kgsl module: X2 points to the
     * 48-byte kernel structure, ID is at +0x28, process_private at +0x8. */
    if (READ_ONCE(query_code[0]) != 0xd503233fU ||
        READ_ONCE(query_code[4]) != 0xb9402841U ||
        READ_ONCE(query_code[6]) != 0xf9400400U) {
        ret = -EPROTO;
        goto out;
    }
    memset(&req.info, 0, sizeof(req.info));
    req.info.id = req.object_id;
    req.result = query(file->private_data, 0xc0300947U, &req.info);
    req.sample_ns = ktime_get_mono_fast_ns();
    ret = copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : 0;
out:
    fput(file);
    return ret;
}

struct nbg_kgsl_syncsource_symbols {
    nbg_kgsl_process_find_t find;
    nbg_kgsl_process_put_t put;
    const u32 *destroy;
    u32 idr_offset;
    u32 lock_offset;
};

static DEFINE_MUTEX(nbg_kgsl_syncsource_resolve_lock);
static struct nbg_kgsl_syncsource_symbols nbg_kgsl_syncsource_symbols;

static bool comm_decode_add_imm(const u32 instruction, u32 source_register,
                                u32 destination_register, u32 *immediate)
{
    u32 value;

    if ((instruction & 0xff000000U) != 0x91000000U ||
        ((instruction >> 5) & 31U) != source_register ||
        (instruction & 31U) != destination_register)
        return false;

    value = (instruction >> 10) & 0xfffU;
    if (instruction & (1U << 22))
        value <<= 12;
    *immediate = value;
    return true;
}

static int comm_resolve_kgsl_syncsource_symbols(
    struct nbg_kgsl_syncsource_symbols *out)
{
    struct nbg_kgsl_syncsource_symbols resolved;
    u32 idr_offset;
    u32 lock_offset;

    mutex_lock(&nbg_kgsl_syncsource_resolve_lock);
    if (nbg_kgsl_syncsource_symbols.find) {
        *out = nbg_kgsl_syncsource_symbols;
        mutex_unlock(&nbg_kgsl_syncsource_resolve_lock);
        return 0;
    }

    memset(&resolved, 0, sizeof(resolved));
    resolved.find = (nbg_kgsl_process_find_t)
        generic_kallsyms_lookup_name("kgsl_process_private_find");
    resolved.put = (nbg_kgsl_process_put_t)
        generic_kallsyms_lookup_name("kgsl_process_private_put");
    resolved.destroy = (const u32 *)
        generic_kallsyms_lookup_name("kgsl_ioctl_syncsource_destroy");
    if (!resolved.find || !resolved.put || !resolved.destroy) {
        mutex_unlock(&nbg_kgsl_syncsource_resolve_lock);
        return -ENOENT;
    }

    /* Current KGSL loads process_private into x21. Extract the two member
     * offsets from its syncsource destroy routine instead of trusting an
     * unchecked vendor-structure constant. */
    if (READ_ONCE(resolved.destroy[5]) != 0xf9400415U ||
        !comm_decode_add_imm(READ_ONCE(resolved.destroy[7]), 21U, 19U,
                             &lock_offset) ||
        !comm_decode_add_imm(READ_ONCE(resolved.destroy[11]), 21U, 21U,
                             &idr_offset) ||
        idr_offset < 0x40U || idr_offset > 0x1000U ||
        lock_offset != idr_offset + sizeof(struct idr)) {
        mutex_unlock(&nbg_kgsl_syncsource_resolve_lock);
        return -EPROTO;
    }

    resolved.idr_offset = idr_offset;
    resolved.lock_offset = lock_offset;
    nbg_kgsl_syncsource_symbols = resolved;
    *out = resolved;
    mutex_unlock(&nbg_kgsl_syncsource_resolve_lock);
    return 0;
}

NBG_NO_CFI
static void *comm_call_kgsl_process_find(nbg_kgsl_process_find_t find,
                                         pid_t pid)
{
    return find(pid);
}

NBG_NO_CFI
static void comm_call_kgsl_process_put(nbg_kgsl_process_put_t put,
                                       void *process)
{
    put(process);
}

static long comm_ioctl_kgsl_syncsource_snapshot(unsigned long arg)
{
    struct nbg_kgsl_syncsource_symbols symbols;
    KgslSyncsourceSnapshotReq req;
    spinlock_t *lock;
    struct idr *idr;
    void *process;
    unsigned int id;
    int ret;

    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;
    if (req.abi_version != NBG_KGSL_SYNCSOURCE_ABI_VERSION)
        return -EPROTO;
    if (req.pid <= 0 || req.max_id == 0 ||
        req.max_id > NBG_KGSL_SYNCSOURCE_MAX_ID)
        return -EINVAL;

    ret = comm_resolve_kgsl_syncsource_symbols(&symbols);
    if (ret)
        return ret;

    process = comm_call_kgsl_process_find(symbols.find, req.pid);
    if (!process)
        return -ESRCH;

    req.flags = 0;
    req.occupied_count = 0;
    req.first_free = 0;
    req.idr_offset = symbols.idr_offset;
    req.lock_offset = symbols.lock_offset;
    req.sample_ns = 0;
    memset(req.occupied, 0, sizeof(req.occupied));

    idr = (struct idr *)((u8 *)process + symbols.idr_offset);
    lock = (spinlock_t *)((u8 *)process + symbols.lock_offset);
    spin_lock(lock);
    for (id = 1; id <= req.max_id; id++) {
        if (idr_find(idr, id)) {
            req.occupied[(id - 1U) >> 6] |=
                1ULL << ((id - 1U) & 63U);
            req.occupied_count++;
        } else if (!req.first_free) {
            req.first_free = id;
        }
    }
    req.sample_ns = ktime_get_mono_fast_ns();
    spin_unlock(lock);
    comm_call_kgsl_process_put(symbols.put, process);

    req.flags = NBG_KGSL_SYNCSOURCE_LAYOUT_VERIFIED;
    if (copy_to_user((void __user *)arg, &req, sizeof(req)))
        return -EFAULT;
    return 0;
}

typedef int (*nbg_task_work_add_t)(struct task_struct *task,
                                   struct callback_head *work,
                                   enum task_work_notify_mode mode);

static DEFINE_MUTEX(nbg_task_work_add_lock);
static nbg_task_work_add_t nbg_task_work_add_fn;

static nbg_task_work_add_t comm_resolve_task_work_add(void)
{
    nbg_task_work_add_t fn = READ_ONCE(nbg_task_work_add_fn);

    if (fn)
        return fn;

    mutex_lock(&nbg_task_work_add_lock);
    fn = nbg_task_work_add_fn;
    if (!fn) {
        fn = (nbg_task_work_add_t)generic_kallsyms_lookup_name("task_work_add");
        if (fn)
            WRITE_ONCE(nbg_task_work_add_fn, fn);
    }
    mutex_unlock(&nbg_task_work_add_lock);
    return fn;
}

NBG_NO_CFI
static int comm_task_work_add(nbg_task_work_add_t fn,
                              struct task_struct *task,
                              struct callback_head *work)
{
    return fn(task, work, TWA_SIGNAL);
}

enum nbg_target_thread_session_state {
    NBG_SESSION_STARTING = 0,
    NBG_SESSION_WAITING = 1,
    NBG_SESSION_SUBMITTED = 2,
    NBG_SESSION_DONE = 3,
};

struct nbg_target_thread_session_work {
    struct callback_head callback;
    struct completion first_done;
    struct completion second_ready;
    struct completion second_done;
    refcount_t refs;
    atomic_t state;
    struct file *file;
    int32_t pid;
    int32_t tid;
    uint32_t target_fd;
    uint32_t command;
    uint32_t argument_size;
    uint32_t hold_timeout_ms;
    uint32_t stack_size;
    uint32_t stack_pointer_offset;
    uint32_t argument_offset;
    uint32_t syscall_number;
    uint32_t relocation_count;
    uint64_t session_id;
    uint64_t user_pc;
    uint64_t relative_mask;
    uint64_t registers[NBG_TARGET_THREAD_REGISTER_COUNT];
    uint64_t scratch;
    uint64_t context_sp;
    long result;
    int status;
    bool abort;
    bool module_ref;
    uint8_t data[];
};

static DEFINE_MUTEX(nbg_target_thread_session_lock);
static struct nbg_target_thread_session_work *nbg_target_thread_session;
static atomic64_t nbg_target_thread_session_sequence = ATOMIC64_INIT(0);

static uint8_t *comm_session_image(
    struct nbg_target_thread_session_work *work)
{
    return work->data;
}

static uint8_t *comm_session_saved_stack(
    struct nbg_target_thread_session_work *work)
{
    return work->data + work->stack_size;
}

static uint8_t *comm_session_response(
    struct nbg_target_thread_session_work *work)
{
    return work->data + (2U * work->stack_size);
}

static TargetThreadStackRelocation *comm_session_relocations(
    struct nbg_target_thread_session_work *work)
{
    return (TargetThreadStackRelocation *)(
        comm_session_response(work) + work->argument_size);
}

static void comm_session_work_put(
    struct nbg_target_thread_session_work *work)
{
    if (!refcount_dec_and_test(&work->refs))
        return;
    fput(work->file);
    vfree(work);
}

static void comm_session_remove_global(
    struct nbg_target_thread_session_work *work)
{
    bool release_global = false;

    mutex_lock(&nbg_target_thread_session_lock);
    if (nbg_target_thread_session == work) {
        nbg_target_thread_session = NULL;
        release_global = true;
    }
    mutex_unlock(&nbg_target_thread_session_lock);
    if (release_global)
        comm_session_work_put(work);
}

static int comm_session_validate_context(
    const TargetThreadIoctlSessionReq *req)
{
    uint32_t index;

    if (req->flags != 0 || req->reserved != 0 ||
        req->relocation_reserved != 0 || req->pid <= 0 ||
        req->tid <= 0 || req->command == 0 || req->argument == 0 ||
        req->stack_image == 0 || req->argument_size == 0 ||
        req->argument_size > NBG_TARGET_THREAD_SESSION_MAX_ARGUMENT_SIZE ||
        req->stack_size == 0 ||
        req->stack_size > NBG_TARGET_THREAD_SESSION_MAX_STACK ||
        req->stack_pointer_offset >= req->stack_size ||
        req->argument_offset > req->stack_size - req->argument_size ||
        req->timeout_ms == 0 ||
        req->timeout_ms > NBG_TARGET_THREAD_SESSION_MAX_TIMEOUT_MS ||
        req->hold_timeout_ms == 0 ||
        req->hold_timeout_ms > NBG_TARGET_THREAD_SESSION_MAX_HOLD_MS ||
        req->stack_relocation_count >
            NBG_TARGET_THREAD_SESSION_MAX_RELOCATIONS ||
        (req->stack_relocation_count != 0 &&
         req->stack_relocations == 0) ||
        req->syscall_number == 0 || req->user_pc == 0 ||
        (req->user_pc & 3ULL) != 0 ||
        (req->relative_mask >> NBG_TARGET_THREAD_REGISTER_COUNT) != 0)
        return -EINVAL;
    if (_IOC_SIZE(req->command) &&
        _IOC_SIZE(req->command) > req->argument_size)
        return -EMSGSIZE;
    if (!(req->relative_mask & BIT_ULL(2)) ||
        req->registers[0] != req->target_fd ||
        req->registers[1] != req->command ||
        req->registers[2] != req->argument_offset)
        return -EINVAL;
    for (index = 0; index < NBG_TARGET_THREAD_REGISTER_COUNT; ++index) {
        if ((req->relative_mask & BIT_ULL(index)) &&
            req->registers[index] >= req->stack_size)
            return -ERANGE;
    }
    return 0;
}

static int comm_session_validate_relocations(
    struct nbg_target_thread_session_work *work)
{
    TargetThreadStackRelocation *relocations =
        comm_session_relocations(work);
    uint32_t index;

    for (index = 0; index < work->relocation_count; ++index) {
        const TargetThreadStackRelocation *relocation = &relocations[index];

        if ((relocation->source_offset & (sizeof(uint64_t) - 1U)) != 0)
            return -EINVAL;
        if (relocation->source_offset >
            work->stack_size - sizeof(uint64_t))
            return -ERANGE;
        if (relocation->target_offset >= work->stack_size)
            return -ERANGE;
    }
    return 0;
}

static bool comm_session_commands_compatible(unsigned int first,
                                             unsigned int next)
{
    return _IOC_DIR(first) == _IOC_DIR(next) &&
           _IOC_TYPE(first) == _IOC_TYPE(next) &&
           _IOC_SIZE(first) == _IOC_SIZE(next);
}

static int comm_session_load_phase(
    struct nbg_target_thread_session_work *work,
    const TargetThreadIoctlSessionReq *req)
{
    if (req->stack_size != work->stack_size ||
        req->argument_size != work->argument_size ||
        req->argument_offset > work->stack_size - req->argument_size)
        return -EPROTO;
    if (copy_from_user(comm_session_image(work),
                       (void __user *)(uintptr_t)req->stack_image,
                       work->stack_size) ||
        copy_from_user(comm_session_image(work) + req->argument_offset,
                       (void __user *)(uintptr_t)req->argument,
                       work->argument_size))
        return -EFAULT;
    if (work->relocation_count != 0 &&
        copy_from_user(comm_session_relocations(work),
                       (void __user *)(uintptr_t)req->stack_relocations,
                       work->relocation_count *
                           sizeof(TargetThreadStackRelocation)))
        return -EFAULT;
    if (comm_session_validate_relocations(work) != 0)
        return -ERANGE;

    work->stack_pointer_offset = req->stack_pointer_offset;
    work->argument_offset = req->argument_offset;
    work->syscall_number = req->syscall_number;
    work->user_pc = req->user_pc;
    work->relative_mask = req->relative_mask;
    memcpy(work->registers, req->registers, sizeof(work->registers));
    return 0;
}

static bool comm_session_save_target_stack(
    struct nbg_target_thread_session_work *work, unsigned long scratch)
{
    if (!access_ok((void __user *)scratch, work->stack_size) ||
        copy_from_user(comm_session_saved_stack(work),
                       (void __user *)scratch, work->stack_size))
        return false;
    work->scratch = scratch;
    work->context_sp = scratch + work->stack_pointer_offset;
    return true;
}

NBG_NO_CFI
static void comm_session_execute_phase(
    struct nbg_target_thread_session_work *work, struct pt_regs *regs)
{
    struct pt_regs saved_regs;
    unsigned long argument;
    uint32_t index;

    work->result = -EINPROGRESS;
    work->status = -EINPROGRESS;
    if (copy_to_user((void __user *)(uintptr_t)work->scratch,
                     comm_session_image(work), work->stack_size)) {
        work->status = -EFAULT;
        return;
    }
    for (index = 0; index < work->relocation_count; ++index) {
        const TargetThreadStackRelocation *relocation =
            &comm_session_relocations(work)[index];
        const uint64_t relocated =
            work->scratch + relocation->target_offset;

        if (copy_to_user(
                (void __user *)(uintptr_t)(
                    work->scratch + relocation->source_offset),
                &relocated, sizeof(relocated))) {
            work->status = -EFAULT;
            return;
        }
    }

    saved_regs = *regs;
    for (index = 0; index < NBG_TARGET_THREAD_REGISTER_COUNT; ++index) {
        if (work->relative_mask & BIT_ULL(index))
            regs->regs[index] = work->scratch + work->registers[index];
        else
            regs->regs[index] = work->registers[index];
    }
    regs->sp = work->context_sp;
    regs->pc = work->user_pc;
    regs->orig_x0 = regs->regs[0];
    regs->syscallno = work->syscall_number;

    argument = work->scratch + work->argument_offset;
    work->result = work->file->f_op->unlocked_ioctl(
        work->file, work->command, argument);
    *regs = saved_regs;

    if (copy_from_user(comm_session_response(work),
                       (void __user *)argument, work->argument_size)) {
        work->status = -EFAULT;
        return;
    }
    work->status = 0;
}

static void comm_target_thread_session_callback(
    struct callback_head *callback)
{
    struct nbg_target_thread_session_work *work = container_of(
        callback, struct nbg_target_thread_session_work, callback);
    struct pt_regs *regs;
    unsigned long target_sp;
    unsigned long span;
    unsigned long scratch;
    unsigned long wait_result;
    bool restore_stack = false;
    bool module_ref = work->module_ref;

    work->status = -ESRCH;
    if (task_pid_nr(current) != work->tid ||
        task_tgid_nr(current) != work->pid)
        goto first_failed;
    if (!work->file->f_op || !work->file->f_op->unlocked_ioctl) {
        work->status = -ENOTTY;
        goto first_failed;
    }

    regs = task_pt_regs(current);
    target_sp = user_stack_pointer(regs);
    span = ALIGN(work->stack_size, 16UL);
    if (target_sp > span + 0x200UL) {
        scratch = ALIGN_DOWN(target_sp - span - 0x200UL, 16UL);
        restore_stack = comm_session_save_target_stack(work, scratch);
    }
    if (!restore_stack && target_sp <= ULONG_MAX - span - 0x200UL) {
        scratch = ALIGN(target_sp + 0x200UL, 16UL);
        restore_stack = comm_session_save_target_stack(work, scratch);
    }
    if (!restore_stack) {
        work->status = -EFAULT;
        goto first_failed;
    }

    comm_session_execute_phase(work, regs);
    if (work->status)
        goto first_failed;

    atomic_set(&work->state, NBG_SESSION_WAITING);
    complete(&work->first_done);
    wait_result = wait_for_completion_timeout(
        &work->second_ready, msecs_to_jiffies(work->hold_timeout_ms));
    if (!wait_result) {
        work->result = -ETIMEDOUT;
        work->status = -ETIMEDOUT;
    } else if (READ_ONCE(work->abort)) {
        work->result = -ECANCELED;
        work->status = -ECANCELED;
    } else {
        comm_session_execute_phase(work, regs);
    }
    atomic_set(&work->state, NBG_SESSION_DONE);
    if (restore_stack &&
        copy_to_user((void __user *)(uintptr_t)work->scratch,
                     comm_session_saved_stack(work), work->stack_size))
        work->status = -EIO;
    complete(&work->second_done);
    goto out;

first_failed:
    atomic_set(&work->state, NBG_SESSION_DONE);
    if (restore_stack &&
        copy_to_user((void __user *)(uintptr_t)work->scratch,
                     comm_session_saved_stack(work), work->stack_size))
        work->status = -EIO;
    complete(&work->first_done);
out:
    comm_session_remove_global(work);
    comm_session_work_put(work);
    if (module_ref)
        module_put(THIS_MODULE);
}

NBG_NO_CFI
static long comm_ioctl_target_thread_session_begin(
    TargetThreadIoctlSessionReq *req)
{
    struct nbg_target_thread_session_work *work;
    nbg_fget_task_t fget_task_fn;
    nbg_task_work_add_t task_work_add_fn;
    struct pid *thread_pid;
    struct task_struct *thread_task;
    struct file *target_file;
    unsigned long wait_result;
    size_t allocation_size;
    size_t relocation_size;
    bool release_global = false;
    int ret;

    ret = comm_session_validate_context(req);
    if (ret)
        return ret;
    fget_task_fn = comm_resolve_fget_task();
    task_work_add_fn = comm_resolve_task_work_add();
    if (!fget_task_fn || !task_work_add_fn)
        return -ENOSYS;

    thread_pid = find_get_pid(req->tid);
    if (!thread_pid)
        return -ESRCH;
    thread_task = get_pid_task(thread_pid, PIDTYPE_PID);
    put_pid(thread_pid);
    if (!thread_task)
        return -ESRCH;
    if (!pid_alive(thread_task) ||
        (READ_ONCE(thread_task->flags) & PF_EXITING) ||
        READ_ONCE(thread_task->tgid) != req->pid) {
        put_task_struct(thread_task);
        return -ESRCH;
    }

    target_file = fget_task_fn(thread_task, req->target_fd);
    if (!target_file) {
        put_task_struct(thread_task);
        return -EBADF;
    }
    if (!target_file->f_op || !target_file->f_op->unlocked_ioctl) {
        fput(target_file);
        put_task_struct(thread_task);
        return -ENOTTY;
    }

    relocation_size = req->stack_relocation_count *
                      sizeof(TargetThreadStackRelocation);
    if (req->stack_size >
        (SIZE_MAX - sizeof(*work) - req->argument_size -
         relocation_size) / 2U) {
        fput(target_file);
        put_task_struct(thread_task);
        return -EOVERFLOW;
    }
    allocation_size = sizeof(*work) + (2U * req->stack_size) +
                      req->argument_size + relocation_size;
    /* A typical captured stack makes this object about 40 KiB.  Requiring
     * physically contiguous pages here caused intermittent -ENOMEM despite
     * ample available memory, so use virtually contiguous storage. */
    work = vzalloc(allocation_size);
    if (!work) {
        fput(target_file);
        put_task_struct(thread_task);
        return -ENOMEM;
    }

    init_task_work(&work->callback, comm_target_thread_session_callback);
    init_completion(&work->first_done);
    init_completion(&work->second_ready);
    init_completion(&work->second_done);
    refcount_set(&work->refs, 1); /* begin ioctl */
    atomic_set(&work->state, NBG_SESSION_STARTING);
    work->file = target_file;
    work->pid = req->pid;
    work->tid = req->tid;
    work->target_fd = req->target_fd;
    work->command = req->command;
    work->argument_size = req->argument_size;
    work->hold_timeout_ms = req->hold_timeout_ms;
    work->stack_size = req->stack_size;
    work->stack_pointer_offset = req->stack_pointer_offset;
    work->argument_offset = req->argument_offset;
    work->relocation_count = req->stack_relocation_count;
    work->session_id = (uint64_t)atomic64_inc_return(
        &nbg_target_thread_session_sequence);
    if (!work->session_id)
        work->session_id = (uint64_t)atomic64_inc_return(
            &nbg_target_thread_session_sequence);
    ret = comm_session_load_phase(work, req);
    if (ret)
        goto out_put_local;

    work->module_ref = try_module_get(THIS_MODULE);
    if (!work->module_ref) {
        ret = -ENODEV;
        goto out_put_local;
    }

    mutex_lock(&nbg_target_thread_session_lock);
    if (nbg_target_thread_session) {
        mutex_unlock(&nbg_target_thread_session_lock);
        module_put(THIS_MODULE);
        work->module_ref = false;
        ret = -EBUSY;
        goto out_put_local;
    }
    nbg_target_thread_session = work;
    refcount_inc(&work->refs); /* global session */
    mutex_unlock(&nbg_target_thread_session_lock);

    refcount_inc(&work->refs); /* task_work callback */
    ret = comm_task_work_add(task_work_add_fn, thread_task, &work->callback);
    if (ret) {
        mutex_lock(&nbg_target_thread_session_lock);
        if (nbg_target_thread_session == work) {
            nbg_target_thread_session = NULL;
            release_global = true;
        }
        mutex_unlock(&nbg_target_thread_session_lock);
        if (release_global)
            comm_session_work_put(work);
        comm_session_work_put(work); /* callback */
        module_put(THIS_MODULE);
        work->module_ref = false;
        goto out_put_local;
    }
    wake_up_process(thread_task);
    put_task_struct(thread_task);
    thread_task = NULL;

    wait_result = wait_for_completion_timeout(
        &work->first_done, msecs_to_jiffies(req->timeout_ms));
    if (!wait_result) {
        req->result = -ETIMEDOUT;
        req->status = -ETIMEDOUT;
        req->session_id = work->session_id;
    } else {
        req->result = work->result;
        req->status = work->status;
        req->scratch = work->scratch;
        req->context_sp = work->context_sp;
        if (!req->status &&
            atomic_read(&work->state) == NBG_SESSION_WAITING) {
            req->session_id = work->session_id;
            if (copy_to_user((void __user *)(uintptr_t)req->argument,
                             comm_session_response(work),
                             work->argument_size))
                ret = -EFAULT;
        } else {
            req->session_id = 0;
        }
    }
    comm_session_work_put(work);
    return ret;

out_put_local:
    if (thread_task)
        put_task_struct(thread_task);
    comm_session_work_put(work);
    return ret;
}

static long comm_ioctl_target_thread_session_finish(
    TargetThreadIoctlSessionReq *req, bool abort_session)
{
    struct nbg_target_thread_session_work *work;
    unsigned long wait_result;
    int ret = 0;

    if (!req->session_id)
        return -EINVAL;
    if (!abort_session) {
        ret = comm_session_validate_context(req);
        if (ret)
            return ret;
    }

    mutex_lock(&nbg_target_thread_session_lock);
    work = nbg_target_thread_session;
    if (!work || work->session_id != req->session_id) {
        mutex_unlock(&nbg_target_thread_session_lock);
        return -ENOENT;
    }
    if (work->pid != req->pid || work->tid != req->tid ||
        work->target_fd != req->target_fd ||
        (!abort_session &&
         !comm_session_commands_compatible(work->command, req->command)) ||
        (!abort_session &&
         (work->stack_size != req->stack_size ||
          work->argument_size != req->argument_size ||
          work->relocation_count != req->stack_relocation_count))) {
        mutex_unlock(&nbg_target_thread_session_lock);
        return -EPROTO;
    }
    if (atomic_cmpxchg(&work->state, NBG_SESSION_WAITING,
                       NBG_SESSION_SUBMITTED) != NBG_SESSION_WAITING) {
        mutex_unlock(&nbg_target_thread_session_lock);
        return -EALREADY;
    }
    refcount_inc(&work->refs); /* finish ioctl */
    if (abort_session) {
        WRITE_ONCE(work->abort, true);
    } else {
        ret = comm_session_load_phase(work, req);
        if (ret) {
            atomic_set(&work->state, NBG_SESSION_WAITING);
            mutex_unlock(&nbg_target_thread_session_lock);
            comm_session_work_put(work);
            return ret;
        }
        work->command = req->command;
    }
    complete(&work->second_ready);
    mutex_unlock(&nbg_target_thread_session_lock);

    wait_result = wait_for_completion_timeout(
        &work->second_done, msecs_to_jiffies(req->timeout_ms));
    if (!wait_result) {
        req->result = -ETIMEDOUT;
        req->status = -ETIMEDOUT;
    } else {
        req->result = work->result;
        req->status = work->status;
        req->scratch = work->scratch;
        req->context_sp = work->context_sp;
        if (!abort_session && !req->status &&
            copy_to_user((void __user *)(uintptr_t)req->argument,
                         comm_session_response(work),
                         work->argument_size))
            ret = -EFAULT;
    }
    comm_session_work_put(work);
    return ret;
}

static long comm_ioctl_target_thread_session(unsigned long arg)
{
    TargetThreadIoctlSessionReq req;
    long ret;

    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;
    if (req.abi_version != NBG_TARGET_THREAD_SESSION_ABI_VERSION)
        return -EINVAL;

    switch (req.phase) {
    case NBG_TARGET_THREAD_SESSION_BEGIN:
        ret = comm_ioctl_target_thread_session_begin(&req);
        break;
    case NBG_TARGET_THREAD_SESSION_FINISH:
        ret = comm_ioctl_target_thread_session_finish(&req, false);
        break;
    case NBG_TARGET_THREAD_SESSION_ABORT:
        ret = comm_ioctl_target_thread_session_finish(&req, true);
        break;
    default:
        return -EINVAL;
    }
    if (ret)
        return ret;
    if (copy_to_user((void __user *)arg, &req, sizeof(req)))
        return -EFAULT;
    return 0;
}

static long comm_ioctl_thread_env(unsigned long arg)
{
    ThreadEnvReq req;
    struct pid *thread_pid;
    struct task_struct *thread_task;
    long ret = 0;

    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;
    if (req.abi_version != NBG_THREAD_ENV_ABI_VERSION ||
        req.pid <= 0 || req.tid <= 0)
        return -EINVAL;

    req.valid = 0;
    req.tls = 0;
    req.apga_lo = 0;
    req.apga_hi = 0;

    thread_pid = find_get_pid(req.tid);
    if (!thread_pid)
        return -ESRCH;
    thread_task = get_pid_task(thread_pid, PIDTYPE_PID);
    put_pid(thread_pid);
    if (!thread_task)
        return -ESRCH;

    if (!pid_alive(thread_task) ||
        (READ_ONCE(thread_task->flags) & PF_EXITING) ||
        READ_ONCE(thread_task->tgid) != req.pid) {
        ret = -ESRCH;
        goto out_put_task;
    }

    /* These are the kernel's saved EL0 values.  APGA is process-shared on
     * arm64, while TLS is retained per thread across context switches. */
    req.tls = READ_ONCE(thread_task->thread.uw.tp_value);
    if (req.tls)
        req.valid |= NBG_THREAD_ENV_TLS_VALID;

#ifdef CONFIG_ARM64_PTR_AUTH
    req.apga_lo = READ_ONCE(thread_task->thread.keys_user.apga.lo);
    req.apga_hi = READ_ONCE(thread_task->thread.keys_user.apga.hi);
    if (req.apga_lo || req.apga_hi)
        req.valid |= NBG_THREAD_ENV_APGA_VALID;
#endif

out_put_task:
    put_task_struct(thread_task);
    if (ret)
        return ret;
    if (copy_to_user((void __user *)arg, &req, sizeof(req)))
        return -EFAULT;
    return 0;
}

static long nbg_comm_ioctl_dispatch(struct socket *sock, unsigned int cmd,
                                    unsigned long arg)
{
    struct nbg_sock_ctx *ctx = nbg_ctx(sock);
    int ret;

    if (!comm_cmd_public(cmd) && (!ctx || !ctx->authed))
        return -EACCES;

    switch (cmd) {
    case OP_INIT_KEY:
        return comm_ioctl_init_key(sock, arg);
    case OP_READ_MEM: {
        COPY_MEMORY req;
        size_t nbytes = 0;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        ret = nbg_read_memory(req.pid, req.addr, (uintptr_t)req.buffer,
                              req.size, &nbytes);
        return ret;
    }
    case OP_READ_MEM_FAULT: {
        COPY_MEMORY req;
        size_t nbytes = 0;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        ret = nbg_read_memory_fault(req.pid, req.addr, (uintptr_t)req.buffer,
                                    req.size, &nbytes);
        return ret;
    }
    case OP_READ_MEM_CACHE: {
        COPY_MEMORY req;
        size_t nbytes = 0;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        ret = nbg_read_memory_cache(req.pid, req.addr, (uintptr_t)req.buffer,
                                    req.size, &nbytes);
        return ret;
    }
    case OP_WRITE_MEM: {
        COPY_MEMORY req;
        size_t nbytes = 0;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        ret = nbg_write_memory(req.pid, req.addr, (uintptr_t)req.buffer,
                               req.size, &nbytes);
        return ret;
    }
    case OP_FLUSH_ICACHE:
        return -ENOTTY;
    case OP_READV_MEM: {
        READV_MEMORY req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        return nbg_readv_memory(req.pid, (READV_ENTRY __user *)req.iovs,
                                req.count);
    }
    case OP_READV_MEM_FAULT: {
        READV_MEMORY req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        return nbg_readv_memory_fault(req.pid,
                                      (READV_ENTRY __user *)req.iovs,
                                      req.count);
    }

    /* 进程 / 线程 / 地址查询 */
    case OP_MODULE_BASE: {
        /* 旧命令名转新实现，直接走内核侧扫描，不经用户指针。 */
        MODULE_BASE req;
        char name[256];
        uint64_t base = 0;
        uint64_t size = 0;
        long copied;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        if (!req.name)
            return -EINVAL;
        copied = strncpy_from_user(name, (char __user *)req.name,
                                   sizeof(name) - 1);
        if (copied < 0)
            return -EFAULT;
        name[copied] = '\0';
        if (name[0] == '\0')
            return -EINVAL;

        if (nbg_scan_module_kernel(&base, &size, req.pid, name, 0, NULL, 0))
            return -ENOENT;

        req.base = (uintptr_t)base;
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return base ? 0 : -ENOENT;
    }
    case OP_FIND_PID: {
        /* 旧命令名转新实现，直接走内核侧查找，不经用户指针。 */
        FIND_PID_REQ req;
        char name[256];
        long copied;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        if (!req.name)
            return -EINVAL;
        copied = strncpy_from_user(name, (char __user *)req.name,
                                   sizeof(name) - 1);
        if (copied < 0)
            return -EFAULT;
        name[copied] = '\0';

        req.pid = nbg_lookup_pid_by_comm(name);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return req.pid > 0 ? 0 : -ESRCH;
    }
    case OP_GET_PID:
        return nbg_query_pid((void __user *)arg);
    case OP_GET_PIDS:
        return nbg_query_pids((void __user *)arg);
    case OP_MODULE_BASE_EX:
        return nbg_query_module_base((void __user *)arg);
    case OP_MODULE_BASE2_EX:
        return nbg_query_module_base2((void __user *)arg);
    case OP_MODULE_PATH_EX:
        return nbg_query_module_path((void __user *)arg);
    case OP_GET_TLS:
        return nbg_query_tls((void __user *)arg);
    case OP_GET_THREAD_TID:
        return nbg_query_thread_tid((void __user *)arg);
    case OP_GET_THREAD_TIDS:
        return nbg_query_thread_tids((void __user *)arg);
    case OP_GET_THREAD_STACK:
        return nbg_query_thread_stack((void __user *)arg);
    case OP_QUERY_MAPPING:
        return nbg_query_mapping((void __user *)arg);
    case OP_QUERY_ACCESS:
        return nbg_query_access((void __user *)arg);
    case OP_QUERY_SIGNAL:
        return nbg_query_signal((void __user *)arg);

    case OP_SET_RESOLUTION: {
        SCREEN_RES req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        return touch_set_resolution(req.width, req.height);
    }
    case OP_TOUCH_DOWN:
    case OP_TOUCH_MOVE: {
        TOUCH_POINT req;
        int touch_ret;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        mutex_lock(&nbg_touch_owner_lock);
        if (cmd == OP_TOUCH_DOWN) {
            if (ctx->touch_slots & BIT(0)) {
                touch_ret = -EALREADY;
            } else {
                touch_ret = touch_down(req.x, req.y);
                if (!touch_ret)
                    ctx->touch_slots |= BIT(0);
            }
        } else if (!(ctx->touch_slots & BIT(0))) {
            touch_ret = -EACCES;
        } else {
            touch_ret = touch_move(req.x, req.y);
        }
        mutex_unlock(&nbg_touch_owner_lock);
        return touch_ret;
    }
    case OP_TOUCH_UP: {
        int touch_ret;

        mutex_lock(&nbg_touch_owner_lock);
        if (!(ctx->touch_slots & BIT(0))) {
            touch_ret = -EACCES;
        } else {
            touch_ret = touch_up();
            ctx->touch_slots &= ~BIT(0);
        }
        mutex_unlock(&nbg_touch_owner_lock);
        return touch_ret;
    }
    case OP_TOUCH_SLOT_DOWN:
    case OP_TOUCH_SLOT_MOVE:
    case OP_TOUCH_SLOT_UP: {
        TOUCH_SLOT_POINT req;
        int touch_ret;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        if (req.slot < 0 || req.slot >= BITS_PER_LONG)
            return -EINVAL;
        mutex_lock(&nbg_touch_owner_lock);
        if (cmd == OP_TOUCH_SLOT_DOWN) {
            if (ctx->touch_slots & BIT(req.slot)) {
                touch_ret = -EALREADY;
            } else {
                touch_ret = touch_slot_down(req.slot, req.x, req.y);
                if (!touch_ret)
                    ctx->touch_slots |= BIT(req.slot);
            }
        } else if (!(ctx->touch_slots & BIT(req.slot))) {
            touch_ret = -EACCES;
        } else if (cmd == OP_TOUCH_SLOT_MOVE) {
            touch_ret = touch_slot_move(req.slot, req.x, req.y);
        } else {
            touch_ret = touch_slot_up(req.slot);
            ctx->touch_slots &= ~BIT(req.slot);
        }
        mutex_unlock(&nbg_touch_owner_lock);
        return touch_ret;
    }
    case OP_SET_TOUCH_SLOTS: {
        int slots;

        if (copy_from_user(&slots, (void __user *)arg, sizeof(slots)))
            return -EFAULT;
        return touch_set_slots(slots);
    }
    case OP_TOUCH_DIAG: {
        struct touch_diag td;
        TOUCH_DIAG req;

        touch_query_state(&td);
        comm_copy_touch_diag(&req, &td);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }
    case OP_SHADOW_ADD:
    case OP_SHADOW_UPDATE:
    case OP_SHADOW_DELETE: {
        ShadowHookReq req;
        struct shadow_req s;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        memset(&s, 0, sizeof(s));
        s.pid = req.pid;
        s.vaddr = req.vaddr;
        s.target_vaddr = req.target_vaddr;
        memcpy(s.custom_rot, req.custom_rot, sizeof(s.custom_rot));
        s.is_rot_hook = req.is_rot_hook;
        if (cmd == OP_SHADOW_ADD)
            return shadow_add_hook(&s);
        if (cmd == OP_SHADOW_UPDATE)
            return shadow_update_rot(&s);
        return shadow_del_hook(&s);
    }
    case OP_SHADOW_DIAG: {
        ShadowDiag req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        if (req.abi_version != NBG_SHADOW_DIAG_ABI_VERSION)
            return -EPROTO;
        shadow_query_diag(&req);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }
    case OP_WATCH_ADD:
    case OP_WATCH_DELETE: {
        WatchReq req;
        struct watch_req w;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        memset(&w, 0, sizeof(w));
        w.pid = req.pid;
        w.watch_addr = req.watch_addr;
        w.bp_type = req.bp_type;
        w.bp_len = req.bp_len;
        w.log_limit = req.log_limit;
        w.flags = req.pad;
        return cmd == OP_WATCH_ADD ? watch_add(&w) : watch_delete(&w);
    }
    case OP_WATCH_CLEAR:
        watch_clear_all();
        return 0;
    case OP_WATCH_READ:
        return comm_ioctl_watch_read(arg);
    case OP_HIDE_PID:
    case OP_UNHIDE_PID: {
        HidePidReq req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        ret = cmd == OP_HIDE_PID ? hide_process(req.pid) : unhide_process(req.pid);
        if (cmd == OP_HIDE_PID && ret == 0) {
            (void)hide_kgsl_install();
            hide_kgsl_remove_pid(req.pid);
        } else if (cmd == OP_UNHIDE_PID && ret == 0) {
            hide_kgsl_restore_pid(req.pid);
        }
        return ret;
    }
    case OP_SIGNAL_HIDDEN_PID: {
        HiddenProcessSignalReq req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        if (req.abi_version != NBG_HIDDEN_SIGNAL_ABI_VERSION)
            return -EPROTO;
        req.matched = 0;
        req.delivered = 0;
        ret = signal_hidden_processes(req.signal, &req.matched,
                                      &req.delivered);
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return ret;
    }
    case OP_HIDE_FILE:
    case OP_UNHIDE_FILE:
        return comm_ioctl_hide_file(cmd, arg);
    case OP_DEVPTS_FILTER:
        return comm_ioctl_devpts_filter(arg);
    case NBG_RO_CAPS:
    case NBG_RO_MAPS:
    case NBG_RO_THREAD:
    case NBG_RO_THREAD_FPSTATE:
    case NBG_RO_FD:
    case NBG_RO_FILE:
        return nbg_readonly_ioctl(cmd, arg);
    case NBG_RO_INPUT_SUBSCRIBE:
    case NBG_RO_INPUT_LIST:
    case NBG_RO_INPUT_READ:
        return nbg_input_snapshot_ioctl(cmd, arg, &ctx->readonly_input_subscribed);
    case OP_THREAD_ENV:
        return comm_ioctl_thread_env(arg);
    case OP_KGSL_SYNCSOURCE_SNAPSHOT:
        return comm_ioctl_kgsl_syncsource_snapshot(arg);
    case OP_KGSL_GPUOBJ_INFO:
        return comm_ioctl_kgsl_gpuobj_info(arg);
    case OP_TARGET_THREAD_IOCTL_SESSION:
        return comm_ioctl_target_thread_session(arg);
    case OP_UNHIDE_MODULE:
        module_list_unhide();
        return 0;
    case OP_HWBP_INFO: {
        HwbpInfo req;
        u64 dfr0;

        memset(&req, 0, sizeof(req));
        asm volatile("mrs %0, id_aa64dfr0_el1" : "=r"(dfr0));
        req.breakpoints = ((dfr0 >> 12) & 0xF) + 1;
        req.watchpoints = ((dfr0 >> 20) & 0xF) + 1;
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }
    case OP_HWBP_CAPS: {
        HwbpCaps req;
        u64 dfr0;
        u64 dfr1;
        u32 raw_breakpoints;
        u32 raw_watchpoints;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        if (req.abi_version != NBG_HWBP_CAPS_ABI_VERSION)
            return -EPROTO;

        asm volatile("mrs %0, id_aa64dfr0_el1" : "=r"(dfr0));
        asm volatile("mrs %0, id_aa64dfr1_el1" : "=r"(dfr1));

        req.dfr0 = dfr0;
        req.dfr1 = dfr1;
        req.flags = ((dfr1 >> 40) & 0xFU) != 0
            ? NBG_HWBP_CAPS_FLAG_ABLE : 0;
        req.physical_breakpoints = ((dfr0 >> 12) & 0xFU) + 1U;
        req.physical_watchpoints = ((dfr0 >> 20) & 0xFU) + 1U;

        raw_breakpoints = req.physical_breakpoints > RAW_BP_SLOT_BASE
            ? req.physical_breakpoints - RAW_BP_SLOT_BASE : 0;
        if (raw_breakpoints > MAX_RAW_BP)
            raw_breakpoints = MAX_RAW_BP;
        raw_watchpoints = req.physical_watchpoints;
        if (raw_watchpoints > MAX_RAW_WP)
            raw_watchpoints = MAX_RAW_WP;
        req.usable_breakpoints = raw_breakpoints;
        req.usable_watchpoints = raw_watchpoints;

        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }
    case OP_HWBP_CAPTURE: {
        HwbpCaptureReq req = { 0 };
        uint32_t abi_version;
        size_t request_size;

        static_assert(offsetof(HwbpCaptureReq, match_enabled) ==
                      NBG_HWBP_CAPTURE_V1_SIZE);
        static_assert(sizeof(HwbpCaptureReq) == NBG_HWBP_CAPTURE_V2_SIZE);
        if (copy_from_user(&abi_version, (void __user *)arg,
                           sizeof(abi_version)))
            return -EFAULT;
        switch (abi_version) {
        case NBG_HWBP_CAPTURE_ABI_VERSION_1:
            request_size = NBG_HWBP_CAPTURE_V1_SIZE;
            break;
        case NBG_HWBP_CAPTURE_ABI_VERSION:
            request_size = NBG_HWBP_CAPTURE_V2_SIZE;
            break;
        default:
            return -EPROTO;
        }
        if (copy_from_user(&req, (void __user *)arg, request_size))
            return -EFAULT;
        if (req.abi_version != abi_version)
            return -EPROTO;
        ret = hwbp_capture_control(&req);
        if (copy_to_user((void __user *)arg, &req, request_size))
            return -EFAULT;
        return ret;
    }
    case OP_SET_LOG_LEVEL: {
        IntValue req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        nbg_log_set_level(req.value);
        req.value = nbg_log_get_level();
        if (copy_to_user((void __user *)arg, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }
    case OP_HIDE_KGSL:
        return hide_kgsl_install();
    case OP_UNHIDE_KGSL:
        hide_kgsl_cleanup();
        return 0;
    default:
        return -ENOTTY;
    }
}

static void nbg_last_client_cleanup_now(void)
{
    struct shadow_req all = {0};

    /* 用户态被后台杀掉/崩溃时不会主动清 WATCH_CLEAR、TOUCH_UP、UNHIDE_PID。
     * 最后一个授权 socket 释放时兜底抬起全部虚拟槽并清理这些
     * 运行期状态，避免旧 pid 断点/隐藏 task/mm cache 残留，导致游戏
     * 下次启动黑屏或进程起不来。
     */
    touch_up_all();
    watch_clear_all();
    shadow_del_hook(&all);      /* target_vaddr=0 => 清全部执行断点/影子 hook */
    /* linearmap 是模块级资源，客户端断开不释放。 */
    hide_cleanup_runtime_state();
}

static void nbg_last_client_cleanup_worker(struct work_struct *work)
{
    (void)work;

    mutex_lock(&nbg_session_cleanup_lock);
    if (atomic_read(&authed_clients) == 0)
        nbg_last_client_cleanup_now();
    mutex_unlock(&nbg_session_cleanup_lock);
}

static DECLARE_WORK(nbg_last_client_cleanup_work,
                    nbg_last_client_cleanup_worker);

static int nbg_release(struct socket *sock)
{
    struct sock *sk = sock->sk;
    struct nbg_sock_ctx *ctx;
    int left;

    if (!sk)
        return 0;
    ctx = (struct nbg_sock_ctx *)sk->sk_user_data;
    if (ctx && ctx->authed) {
        nbg_input_snapshot_release(&ctx->readonly_input_subscribed);
        mutex_lock(&nbg_touch_owner_lock);
        touch_release_slots(ctx->touch_slots);
        ctx->touch_slots = 0;
        mutex_unlock(&nbg_touch_owner_lock);
        mutex_lock(&nbg_session_cleanup_lock);
        left = atomic_dec_return(&authed_clients);
        if (left <= 0) {
            atomic_set(&authed_clients, 0);
            schedule_work(&nbg_last_client_cleanup_work);
        }
        mutex_unlock(&nbg_session_cleanup_lock);
    }
    kfree(ctx);
    sk->sk_user_data = NULL;
    sock->sk = NULL;
    sock_orphan(sk);
    sock_put(sk);
    return 0;
}

static int nbg_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
    return -EOPNOTSUPP;
}

static int nbg_recvmsg(struct socket *sock, struct msghdr *msg, size_t len, int flags)
{
    return -EOPNOTSUPP;
}

static int nbg_no_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
    return -EOPNOTSUPP;
}

static int nbg_no_connect(struct socket *sock, struct sockaddr *addr,
                          int addr_len, int flags)
{
    return -EOPNOTSUPP;
}

static int nbg_no_socketpair(struct socket *sock1, struct socket *sock2)
{
    return -EOPNOTSUPP;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static int nbg_no_accept(struct socket *sock, struct socket *newsock,
                         struct proto_accept_arg *arg)
#else
static int nbg_no_accept(struct socket *sock, struct socket *newsock,
                         int flags, bool kern)
#endif
{
    return -EOPNOTSUPP;
}

static int nbg_no_getname(struct socket *sock, struct sockaddr *addr, int peer)
{
    return -EOPNOTSUPP;
}

static int nbg_no_shutdown(struct socket *sock, int flags)
{
    return -EOPNOTSUPP;
}

static int nbg_sock_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
    return nbg_comm_ioctl_dispatch(sock, cmd, arg);
}

static __poll_t nbg_poll(struct file *file, struct socket *sock, struct poll_table_struct *wait)
{
    return 0;
}

static int nbg_setsockopt(struct socket *sock, int level, int optname,
                          sockptr_t optval, unsigned int optlen)
{
    return -ENOPROTOOPT;
}

static int nbg_getsockopt(struct socket *sock, int level, int optname,
                          char __user *optval, int __user *optlen)
{
    return -EOPNOTSUPP;
}

static const struct proto_ops nbg_sock_ops = {
    .family = AF_UNSPEC,
    /* Keep the module text/data alive for the complete lifetime of every
     * userspace socket.  __sock_create() takes this reference after create()
     * succeeds and __sock_release() drops it after ->release() returns. */
    .owner = THIS_MODULE,
    .release = nbg_release,
    .bind = nbg_no_bind,
    .connect = nbg_no_connect,
    .socketpair = nbg_no_socketpair,
    .accept = nbg_no_accept,
    .getname = nbg_no_getname,
    .poll = nbg_poll,
    .ioctl = nbg_sock_ioctl,
    .shutdown = nbg_no_shutdown,
    .setsockopt = nbg_setsockopt,
    .getsockopt = nbg_getsockopt,
    .sendmsg = nbg_sendmsg,
    .recvmsg = nbg_recvmsg,
};

static struct proto nbg_sock_proto = {
    .name = "net_rawx",
    .owner = THIS_MODULE,
    .obj_size = sizeof(struct sock),
};

static int nbg_create(struct net *net, struct socket *sock, int protocol, int kern)
{
    struct sock *sk;
    struct nbg_sock_ctx *ctx;

    if (protocol != NBG_SOCKET_PROTOCOL)
        return -EPROTONOSUPPORT;
    if (__kuid_val(current_uid()) >= 10000)
        return -EPROTONOSUPPORT;
    if (sock->type == SOCK_SEQPACKET)
        return -ENOKEY;
    if (sock->type != SOCK_RAW)
        return -ESOCKTNOSUPPORT;

    ctx = nbg_kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;

    sk = sk_alloc(net, registered_family, GFP_KERNEL, &nbg_sock_proto, kern);
    if (!sk) {
        kfree(ctx);
        return -ENOMEM;
    }

    sock->ops = &nbg_sock_ops;
    sock_init_data(sock, sk);
    sk->sk_user_data = ctx;
    return 0;
}

static struct net_proto_family nbg_family = {
    .create = nbg_create,
    /* Serializes family create against module teardown. */
    .owner = THIS_MODULE,
};

static int register_nbg_family(void)
{
    int family;

    for (family = 1; family < 50; family++) {
        nbg_family.family = family;
        if (sock_register(&nbg_family) == 0) {
            registered_family = family;
            return 0;
        }
    }
    return -EAFNOSUPPORT;
}

int nbg_comm_init(void)
{
    int ret;

    ret = proto_register(&nbg_sock_proto, 1);
    if (ret)
        return ret;

    ret = register_nbg_family();
    if (ret) {
        proto_unregister(&nbg_sock_proto);
        return ret;
    }
    return 0;
}

void nbg_comm_exit(void)
{
    cancel_work_sync(&nbg_last_client_cleanup_work);
    if (registered_family >= 0) {
        sock_unregister(registered_family);
        registered_family = -1;
    }
    proto_unregister(&nbg_sock_proto);
}
