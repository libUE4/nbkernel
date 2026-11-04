/* Bounded, authenticated, read-only metadata queries. No remote execution,
 * target writes, procfs reads, input injection, or visibility hooks. */
#include <linux/capability.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/kdev_t.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <linux/random.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/swap.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/uidgid.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include "nbg_alloc.h"
#include "nbg_compat.h"
#include "export_fun.h"
#include "nbg_readonly.h"

/* Older GKI uio.h calls a destination iterator READ. */
#ifndef ITER_DEST
#define ITER_DEST READ
#endif

typedef bool (*ro_access_fn)(struct task_struct *, unsigned int);
typedef int (*ro_syscall_fn)(struct task_struct *, struct syscall_info *);
typedef struct file *(*ro_fget_fn)(struct task_struct *, unsigned int);
typedef int (*ro_getattr_fn)(const struct path *, struct kstat *, u32,
                             unsigned int);
typedef ssize_t (*ro_read_fn)(struct file *, void *, size_t, loff_t *);
typedef int (*ro_task_call_fn)(struct task_struct *, task_call_f, void *);
static DEFINE_MUTEX(ro_symbols_lock);
static ro_access_fn ro_access;
static ro_syscall_fn ro_syscall;
static ro_fget_fn ro_fget;
static ro_getattr_fn ro_getattr;
static ro_read_fn ro_read;
static ro_task_call_fn ro_task_call;
static int *ro_overflowgid;

static int ro_symbols(void)
{
    int result;
    mutex_lock(&ro_symbols_lock);
    if (!ro_access) ro_access = (ro_access_fn)generic_kallsyms_lookup_name("ptrace_may_access");
    if (!ro_syscall) ro_syscall = (ro_syscall_fn)generic_kallsyms_lookup_name("task_current_syscall");
    if (!ro_fget) ro_fget = (ro_fget_fn)generic_kallsyms_lookup_name("fget_task");
    /* These VFS entry points exist in older GKI kernels but are not always
     * exported to modules. Keep optional read-only queries from preventing
     * the entire module from loading. Call the real VFS APIs, preserving
     * their FMODE, rw_verify_area and LSM checks; never call file operations
     * directly as a substitute for a missing API. */
    if (!ro_getattr) ro_getattr = (ro_getattr_fn)generic_kallsyms_lookup_name("vfs_getattr");
    if (!ro_read) ro_read = (ro_read_fn)generic_kallsyms_lookup_name("kernel_read");
    if (!ro_overflowgid) ro_overflowgid = (int *)generic_kallsyms_lookup_name("overflowgid");
    if (!ro_task_call)
        ro_task_call = (ro_task_call_fn)generic_kallsyms_lookup_name(
            "task_call_func");
    result = ro_access && ro_syscall && ro_fget ? 0 : -EOPNOTSUPP;
    mutex_unlock(&ro_symbols_lock);
    return result;
}

/* Hold exec_update_lock through each query, including the access check.
 * References prevent numeric PID reuse from changing the queried object. */
NBG_NO_CFI
static struct task_struct *ro_task(pid_t tgid, pid_t tid)
{
    struct pid *id;
    struct task_struct *task;
    if (tgid <= 0 || tid <= 0) return ERR_PTR(-EINVAL);
    if (!capable(CAP_SYS_PTRACE)) return ERR_PTR(-EPERM);
    if (ro_symbols()) return ERR_PTR(-EOPNOTSUPP);
    id = find_get_pid(tid);
    if (!id) return ERR_PTR(-ESRCH);
    task = get_pid_task(id, PIDTYPE_PID); put_pid(id);
    if (!task) return ERR_PTR(-ESRCH);
    if (nbg_down_read_killable(&task->signal->exec_update_lock)) {
        put_task_struct(task); return ERR_PTR(-EINTR);
    }
    if (!pid_alive(task) || READ_ONCE(task->tgid) != tgid ||
        (READ_ONCE(task->flags) & PF_EXITING)) goto gone;
    /* Preserve the ordinary Linux credential/LSM read-access decision. */
    if (!ro_access(task, PTRACE_MODE_READ_FSCREDS)) {
        up_read(&task->signal->exec_update_lock); put_task_struct(task);
        return ERR_PTR(-EACCES);
    }
    return task;
gone:
    up_read(&task->signal->exec_update_lock); put_task_struct(task);
    return ERR_PTR(-ESRCH);
}
static void ro_put_task(struct task_struct *task)
{
    up_read(&task->signal->exec_update_lock); put_task_struct(task);
}

static int ro_thread_fpstate_sample(struct task_struct *task, void *output)
{
    struct NbgRoThreadFpState *sample = output;

    if (task == current)
        return -EAGAIN;
#ifdef CONFIG_SMP
    if (READ_ONCE(task->on_cpu))
        return -EAGAIN;
#endif
    if (!pid_alive(task) || (READ_ONCE(task->flags) & PF_EXITING))
        return -ESRCH;

    sample->tls = READ_ONCE(task->thread.uw.tp_value);
    sample->fpsr = READ_ONCE(task->thread.uw.fpsimd_state.fpsr);
    sample->fpcr = READ_ONCE(task->thread.uw.fpsimd_state.fpcr);
    sample->process_start_ns =
        READ_ONCE(task->group_leader->start_boottime);
    sample->thread_start_ns = READ_ONCE(task->start_boottime);
    sample->sample_ns = ktime_get_ns();
    sample->valid = NBG_RO_FPSTATE_VALID;
    return 0;
}

NBG_NO_CFI
static long ro_thread_fpstate_ioctl(unsigned long argument)
{
    struct NbgRoThreadFpState request;
    struct NbgRoThreadFpState sample = {};
    struct task_struct *task;
    int result;

    static_assert(sizeof(sample) == 56);
    static_assert(offsetof(struct NbgRoThreadFpState, fpsr) == 48);
    if (copy_from_user(&request, (void __user *)argument, sizeof(request)))
        return -EFAULT;
    if (request.abi != NBG_RO_ABI || request.valid != 0 ||
        request.pid <= 0 || request.tid <= 0)
        return -EINVAL;
    task = ro_task(request.pid, request.tid);
    if (IS_ERR(task))
        return PTR_ERR(task);
    if (!ro_task_call) {
        ro_put_task(task);
        return -EOPNOTSUPP;
    }
    sample.abi = NBG_RO_ABI;
    sample.pid = request.pid;
    sample.tid = request.tid;
    result = ro_task_call(task, ro_thread_fpstate_sample, &sample);
    ro_put_task(task);
    if (result)
        return result;
    return copy_to_user((void __user *)argument, &sample, sizeof(sample))
        ? -EFAULT : 0;
}

struct ro_maps_buffer { char *bytes, *path, *line; size_t capacity, used; };
/* The caller holds mmap_lock and has already passed ro_task's access checks.
 * Android 12's 5.10 tree keeps anonymous names in the target's userspace;
 * later GKI trees own a refcounted kernel string instead. */
static const char *ro_anon_name(struct vm_area_struct *vma, char *scratch)
{
#ifdef CONFIG_ANON_VMA_NAME
    struct anon_vma_name *anon;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0)
    /* Some 5.x and 6.1 GKI trees do not export anon_vma_name.  Match
     * mm/madvise.c: hold mmap_lock and never read a file VMA's union
     * member as an anonymous name.  Newer kernels keep their accessor. */
    mmap_assert_locked(vma->vm_mm);
    anon = vma->vm_file ? NULL : vma->anon_name;
#else
    anon = anon_vma_name(vma);
#endif
    return anon ? anon->name : NULL;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
    const char __user *remote = vma_get_anon_name(vma);
    unsigned long address = (unsigned long)remote;
    size_t used = 0;

    if (!remote) return NULL;
    while (used < NAME_MAX) {
        struct page *page;
        char *mapped;
        size_t offset = offset_in_page(address);
        size_t available = min_t(size_t, NAME_MAX - used, PAGE_SIZE - offset);
        size_t length;
        long pinned = get_user_pages_remote(vma->vm_mm, address & PAGE_MASK,
                                           1, 0, &page, NULL, NULL);

        if (pinned != 1) return ERR_PTR(pinned < 0 ? pinned : -EFAULT);
        mapped = compat_kmap_page(page);
        length = strnlen(mapped + offset, available);
        memcpy(scratch + used, mapped + offset, length);
        compat_kunmap_page(mapped);
        /* Release the ordinary GUP reference through a kernel entry point.
         * Inlining put_page here imports optional PAGE_PINNER internals from
         * the build headers, absent on several older device kernels. */
        release_pages(&page, 1);
        used += length;
        if (length < available) break;
        address += available;
    }
    scratch[used] = '\0';
    return scratch;
#else
    return NULL;
#endif
}

static int ro_map_line(struct ro_maps_buffer *buffer, struct vm_area_struct *vma)
{
    struct file *file = vma->vm_file;
    const char *anon = ro_anon_name(vma, buffer->path);
    struct inode *inode = file ? file_inode(file) : NULL;
    unsigned long long offset = file ? (unsigned long long)vma->vm_pgoff << PAGE_SHIFT : 0;
    dev_t device = inode ? inode->i_sb->s_dev : 0;
    const char *name = "", *prefix = "", *suffix = "";
    int count;
    if (IS_ERR(anon)) return PTR_ERR(anon);
    if (anon) { name = anon; prefix = file ? "[anon_shmem:" : "[anon:"; suffix = "]"; }
    else if (file) {
        name = d_path(&file->f_path, buffer->path, PATH_MAX);
        if (IS_ERR(name)) return PTR_ERR(name);
    } else if (vma->vm_start <= vma->vm_mm->brk &&
               vma->vm_end >= vma->vm_mm->start_brk) name = "[heap]";
    else if (vma->vm_start <= vma->vm_mm->start_stack &&
             vma->vm_end >= vma->vm_mm->start_stack) name = "[stack]";
    /* Newlines in a path must never create a second, forged mapping record. */
    if (strchr(name, '\n') || strchr(name, '\r')) return -EOPNOTSUPP;
    count = snprintf(buffer->line, PATH_MAX + 256,
        "%016lx-%016lx %c%c%c%c %08llx %02x:%02x %lu %s%s%s\n",
        vma->vm_start, vma->vm_end,
        vma->vm_flags & VM_READ ? 'r' : '-', vma->vm_flags & VM_WRITE ? 'w' : '-',
        vma->vm_flags & VM_EXEC ? 'x' : '-', vma->vm_flags & VM_MAYSHARE ? 's' : 'p',
        offset, MAJOR(device), MINOR(device), inode ? inode->i_ino : 0,
        prefix, name, suffix);
    if (count < 0 || count >= PATH_MAX + 256 || buffer->used + count > NBG_RO_MAPS_MAX)
        return -EOVERFLOW;
    if (buffer->used + count <= buffer->capacity)
        memcpy(buffer->bytes + buffer->used, buffer->line, count);
    buffer->used += count;
    return 0;
}
static long ro_maps_ioctl(unsigned long argument)
{
    struct NbgRoMaps req;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    struct ro_maps_buffer out = {};
    int result = 0;
    if (copy_from_user(&req, (void __user *)argument, sizeof(req))) return -EFAULT;
    if (req.abi != NBG_RO_ABI || req.pid <= 0 || !req.buffer ||
        !req.capacity || req.capacity > NBG_RO_MAPS_MAX) return -EINVAL;
    task = ro_task(req.pid, req.pid); if (IS_ERR(task)) return PTR_ERR(task);
    req.process_start_ns = READ_ONCE(task->start_boottime); req.length = 0;
    mm = get_task_mm(task); if (!mm) { result = -ESRCH; goto put_task; }
    out.bytes = kvmalloc(req.capacity, GFP_KERNEL); out.capacity = req.capacity;
    out.path = nbg_kmalloc(PATH_MAX, GFP_KERNEL);
    out.line = nbg_kmalloc(PATH_MAX + 256, GFP_KERNEL);
    if (!out.bytes || !out.path || !out.line) { result = -ENOMEM; goto free_output; }
    compat_mmap_read_lock(mm);
#if USE_VMA_ITERATOR
    {
        VMA_ITERATOR(iterator, mm, 0);
        for_each_vma(iterator, vma) { result = ro_map_line(&out, vma); if (result) break; }
    }
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        result = ro_map_line(&out, vma); if (result) break;
    }
#endif
    compat_mmap_read_unlock(mm);
    req.length = out.used;
    if (!result && out.used > out.capacity) result = -ENOSPC;
    if (!result && copy_to_user((void __user *)(unsigned long)req.buffer, out.bytes, out.used))
        result = -EFAULT;
    if ((!result || result == -ENOSPC) &&
        copy_to_user((void __user *)argument, &req, sizeof(req))) result = -EFAULT;
free_output:
    kvfree(out.bytes); kfree(out.path); kfree(out.line); mmput(mm);
put_task:
    ro_put_task(task); return result;
}

NBG_NO_CFI
static long ro_thread_ioctl(unsigned long argument)
{
    struct NbgRoThread req;
    struct task_struct *task, *leader, *candidate;
    struct syscall_info info;
    int result = 0;
    pid_t found = 0;
    char comm[TASK_COMM_LEN];
    if (copy_from_user(&req, (void __user *)argument, sizeof(req))) return -EFAULT;
    if (req.abi != NBG_RO_ABI || req.pid <= 0 ||
        req.operation < NBG_RO_THREAD_FIND || req.operation > NBG_RO_THREAD_SYSCALL)
        return -EINVAL;
    if (req.operation == NBG_RO_THREAD_FIND) {
        if (!req.comm[0] || !memchr(req.comm, 0, sizeof(req.comm))) return -EINVAL;
        leader = ro_task(req.pid, req.pid); if (IS_ERR(leader)) return PTR_ERR(leader);
        get_task_comm(comm, leader);
        if (!strcmp(comm, req.comm)) found = req.pid;
        rcu_read_lock();
        if (!found) for_each_thread(leader, candidate) {
            get_task_comm(comm, candidate);
            if (!strcmp(comm, req.comm) && pid_alive(candidate)) {
                found = candidate->pid; break;
            }
        }
        rcu_read_unlock(); ro_put_task(leader);
        if (!found) return -ESRCH;
        req.tid = found;
    }
    task = ro_task(req.pid, req.tid); if (IS_ERR(task)) return PTR_ERR(task);
    req.process_start_ns = READ_ONCE(task->group_leader->start_boottime);
    req.thread_start_ns = READ_ONCE(task->start_boottime);
    get_task_comm(req.comm, task);
    req.sp = req.pc = 0; req.syscall_number = -1;
    if (req.operation == NBG_RO_THREAD_SYSCALL) {
        memset(&info, 0, sizeof(info));
        result = ro_syscall(task, &info);
        if (!result) { req.sp = info.sp; req.pc = info.data.instruction_pointer; req.syscall_number = info.data.nr; }
    }
    ro_put_task(task);
    if (!result && copy_to_user((void __user *)argument, &req, sizeof(req))) result = -EFAULT;
    return result;
}

NBG_NO_CFI
static long ro_fd_ioctl(unsigned long argument)
{
    struct NbgRoFd req;
    struct task_struct *task;
    struct file *file;
    struct kstat value;
    gid_t gid;
    int result;
    if (copy_from_user(&req, (void __user *)argument, sizeof(req))) return -EFAULT;
    if (req.abi != NBG_RO_ABI || req.pid <= 0 || req.fd < 0) return -EINVAL;
    task = ro_task(req.pid, req.pid); if (IS_ERR(task)) return PTR_ERR(task);
    if (!ro_getattr) { ro_put_task(task); return -EOPNOTSUPP; }
    file = ro_fget(task, req.fd);
    req.process_start_ns = READ_ONCE(task->start_boottime);
    if (!file) { ro_put_task(task); return -EBADF; }
    result = ro_getattr(&file->f_path, &value, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
    fput(file); ro_put_task(task);
    if (result) return result;
    req.reserved = req.padding = req.padding2 = 0;
    req.device = huge_encode_dev(value.dev); req.inode = value.ino;
    req.rdev = huge_encode_dev(value.rdev); req.size = value.size; req.blocks = value.blocks;
    req.mode = value.mode; req.nlink = value.nlink;
    req.uid = from_kuid_munged(current_user_ns(), value.uid);
    /* Match from_kgid_munged without importing its private fallback variable.
     * Do not hard-code 65534: overflowgid is a runtime kernel setting. */
    gid = from_kgid(current_user_ns(), value.gid);
    if (gid == (gid_t)-1) {
        if (!ro_overflowgid) return -EOPNOTSUPP;
        gid = (gid_t)READ_ONCE(*ro_overflowgid);
    }
    req.gid = gid; req.blksize = value.blksize;
    req.atime_sec = value.atime.tv_sec; req.atime_ns = value.atime.tv_nsec;
    req.mtime_sec = value.mtime.tv_sec; req.mtime_ns = value.mtime.tv_nsec;
    req.ctime_sec = value.ctime.tv_sec; req.ctime_ns = value.ctime.tv_nsec;
    return copy_to_user((void __user *)argument, &req, sizeof(req)) ? -EFAULT : 0;
}
NBG_NO_CFI
/* 由内核随机池填充调用方缓冲区：最多 64 字节，不引入任何未导出符号。 */
static long ro_random_ioctl(unsigned long argument)
{
    struct NbgRoRandom req;
    u8 bytes[64];

    if (copy_from_user(&req, (void __user *)argument, sizeof(req)))
        return -EFAULT;
    if (req.abi != NBG_RO_ABI || !req.size || req.size > sizeof(bytes) ||
        !req.buffer)
        return -EINVAL;

    get_random_bytes(bytes, req.size);
    if (copy_to_user((void __user *)(unsigned long)req.buffer, bytes,
                     req.size))
        return -EFAULT;

    req.result = req.size;
    if (copy_to_user((void __user *)argument, &req, sizeof(req)))
        return -EFAULT;
    return 0;
}

static long ro_file_ioctl(unsigned long argument)
{
    struct NbgRoFile req;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    struct file *file = NULL;
    struct inode *inode;
    void *bytes;
    loff_t offset = 0;
    ssize_t count;
    int result = 0;
    if (copy_from_user(&req, (void __user *)argument, sizeof(req))) return -EFAULT;
    if (req.abi != NBG_RO_ABI || req.pid <= 0 || !req.address || !req.buffer ||
        !req.size || req.size > NBG_RO_FILE_MAX || !req.inode) return -EINVAL;
    task = ro_task(req.pid, req.pid); if (IS_ERR(task)) return PTR_ERR(task);
    if (!ro_read) { ro_put_task(task); return -EOPNOTSUPP; }
    mm = get_task_mm(task); if (!mm) { ro_put_task(task); return -ESRCH; }
    compat_mmap_read_lock(mm);
    vma = find_vma(mm, req.address);
    if (!vma || req.address < vma->vm_start || req.size > vma->vm_end - req.address || !vma->vm_file) {
        result = -EFAULT; goto unlock;
    }
    inode = file_inode(vma->vm_file);
    if (inode->i_ino != req.inode || MAJOR(inode->i_sb->s_dev) != req.device_major ||
        MINOR(inode->i_sb->s_dev) != req.device_minor || !S_ISREG(inode->i_mode)) {
        result = -ESTALE; goto unlock;
    }
    if (vma->vm_pgoff > ((u64)LLONG_MAX >> PAGE_SHIFT) ||
        req.address - vma->vm_start > LLONG_MAX - ((u64)vma->vm_pgoff << PAGE_SHIFT)) {
        result = -EOVERFLOW; goto unlock;
    }
    offset = ((u64)vma->vm_pgoff << PAGE_SHIFT) + req.address - vma->vm_start;
    file = get_file(vma->vm_file);
unlock:
    compat_mmap_read_unlock(mm); mmput(mm);
    if (result) { ro_put_task(task); return result; }
    bytes = nbg_kmalloc(req.size, GFP_KERNEL);
    if (!bytes) { fput(file); ro_put_task(task); return -ENOMEM; }
    req.copied = 0;
    while (req.copied < req.size) {
        count = ro_read(file, (char *)bytes + req.copied,
                        req.size - req.copied, &offset);
        if (count <= 0) { result = count < 0 ? count : -EIO; break; }
        req.copied += count;
    }
    fput(file); ro_put_task(task);
    if (!result && copy_to_user((void __user *)(unsigned long)req.buffer, bytes, req.size)) result = -EFAULT;
    kfree(bytes);
    if (!result && copy_to_user((void __user *)argument, &req, sizeof(req))) result = -EFAULT;
    return result;
}
long nbg_readonly_ioctl(unsigned int command, unsigned long argument)
{
    if (!capable(CAP_SYS_PTRACE)) return -EPERM;
    switch (command) {
    case NBG_RO_CAPS: {
        struct NbgRoCaps req;
        if (copy_from_user(&req, (void __user *)argument, sizeof(req))) return -EFAULT;
        if (req.abi != NBG_RO_ABI) return -EPROTO;
        if (ro_symbols()) return -EOPNOTSUPP;
        req.reserved = 0; req.features = NBG_RO_REQUIRED_FEATURES;
        if (!ro_getattr) req.features &= ~NBG_RO_FEATURE_FD;
        if (!ro_read) req.features &= ~NBG_RO_FEATURE_FILE;
        if (ro_task_call) req.features |= NBG_RO_FEATURE_FPSTATE;
        return copy_to_user((void __user *)argument, &req, sizeof(req)) ? -EFAULT : 0;
    }
    case NBG_RO_MAPS: return ro_maps_ioctl(argument);
    case NBG_RO_THREAD: return ro_thread_ioctl(argument);
    case NBG_RO_THREAD_FPSTATE: return ro_thread_fpstate_ioctl(argument);
    case NBG_RO_FD: return ro_fd_ioctl(argument);
    case NBG_RO_RANDOM: return ro_random_ioctl(argument);
    case NBG_RO_FILE: return ro_file_ioctl(argument);
    default: return -ENOTTY;
    }
}
