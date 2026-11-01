/* sensor_mem.c — system_server 受限写会话与 GOT 钩子布防
 *
 * 只允许写 system_server 里 /system/lib64/libsensorservice.so 的映射，
 * 单次 IO 上限 4KB。布防后写窗口收缩到 delta 与 GOT 两个 8 字节槽，
 * GOT 槽只接受 original <-> replacement 两值并用 cmpxchg 原子切换。
 *
 * fd 关闭时（含 SIGKILL）在 work 里把 delta 清零、GOT 恢复原值。
 */
#include "sensor_mem.h"
#include "nbg_user_ns.h"

#include <linux/anon_inodes.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/pid.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/user_namespace.h>
#include <linux/workqueue.h>

#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/processor.h>

#include "comm.h"
#include "nbg_compat.h"
#include "nbg_ksyms.h"
#include "query.h"

#define NBG_SENSOR_LIBRARY "/system/lib64/libsensorservice.so"
#define NBG_SENSOR_CAVE    64U
#define NBG_SENSOR_IO_MAX  4096U

struct nbg_sensor_session {
    struct task_struct *target;
    struct pid *owner;
    struct mm_struct *mm;          /* 只 mmgrab，不阻止地址空间销毁 */
    struct file *library;
    struct mutex lock;
    struct work_struct cleanup;
    NBG_SENSOR_ARM_REQ patch;
    bool armed;
};

static DEFINE_MUTEX(g_session_lock);
/* 全局只允许一个会话，防止两处同时改同一个 GOT 槽。 */
static struct nbg_sensor_session *g_active;

/* 这两个符号在部分 GKI 分支不导出，走 kallsyms 解析。 */
typedef struct file *(*nbg_get_task_exe_file_t)(struct task_struct *);
typedef void (*nbg_sync_icache_dcache_t)(pte_t);
/* 凭据与命名空间同样存在导出差异：不导出时直接引用会让模块加载失败。 */
typedef const struct cred *(*nbg_get_task_cred_t)(struct task_struct *);
typedef void (*nbg_put_cred_t)(struct cred *);

static nbg_get_task_exe_file_t nbg_get_task_exe_file;
static nbg_sync_icache_dcache_t nbg_sync_icache_dcache;
static nbg_get_task_cred_t nbg_get_task_cred_fn;
static nbg_put_cred_t nbg_put_cred_fn;

static void nbg_sensor_resolve_symbols(void)
{
    if (!nbg_get_task_exe_file)
        nbg_get_task_exe_file = (nbg_get_task_exe_file_t)
            generic_kallsyms_lookup_name("get_task_exe_file");
    if (!nbg_sync_icache_dcache)
        nbg_sync_icache_dcache = (nbg_sync_icache_dcache_t)
            generic_kallsyms_lookup_name("sync_icache_dcache");
    if (!nbg_get_task_cred_fn)
        nbg_get_task_cred_fn = (nbg_get_task_cred_t)
            generic_kallsyms_lookup_name("get_task_cred");
    if (!nbg_put_cred_fn)
        nbg_put_cred_fn = (nbg_put_cred_t)
            generic_kallsyms_lookup_name("__put_cred");
}

/* init_user_ns 取不到时退化为只看 uid：宁可放过命名空间判断，
 * 也不能因为符号缺失让整个准入流程失效。 */
static bool nbg_user_ns_is_init(const struct cred *cred)
{
    struct user_namespace *init_ns = nbg_init_user_ns_addr();

    if (!init_ns)
        return true;

    return cred->user_ns == init_ns;
}

/* 与内核 put_cred 等价，但不内联展开到未导出的 __put_cred。
 * cred->usage 在 6.2 才改成 atomic_long_t，旧内核仍是 atomic_t。 */
static void nbg_put_cred_safe(struct cred *cred)
{
    bool drop;

    if (!cred)
        return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
    drop = atomic_long_dec_and_test(&cred->usage);
#else
    drop = atomic_dec_and_test(&cred->usage);
#endif

    if (!drop)
        return;

    if (!nbg_put_cred_fn) {
        kfree(cred);
        return;
    }

    nbg_put_cred_fn(cred);
}

/* ---- 调用方身份 ---- */

static bool nbg_caller_is_root(void)
{
    const struct cred *cred = current_cred();

    return nbg_user_ns_is_init(cred) &&
           uid_eq(cred->uid, GLOBAL_ROOT_UID) &&
           uid_eq(cred->euid, GLOBAL_ROOT_UID);
}

static bool nbg_caller_is_surfaceflinger(void)
{
    static const char *const exe_path = "/system/bin/surfaceflinger";
    const struct cred *cred = current_cred();
    struct file *exe;
    char comm[TASK_COMM_LEN];
    char *buf;
    char *path;
    bool allowed = false;

    if (!nbg_user_ns_is_init(cred) ||
        !uid_eq(cred->uid, KUIDT_INIT(1000)) ||
        !uid_eq(cred->euid, KUIDT_INIT(1000)) ||
        !uid_eq(cred->suid, KUIDT_INIT(1000)) ||
        !uid_eq(cred->fsuid, KUIDT_INIT(1000)))
        return false;

    get_task_comm(comm, current->group_leader);
    if (strcmp(comm, "surfaceflinger") != 0)
        return false;

    nbg_sensor_resolve_symbols();
    exe = nbg_get_task_exe_file ? nbg_get_task_exe_file(current->group_leader)
                               : NULL;
    if (!exe)
        return false;

    buf = (char *)__get_free_page(GFP_KERNEL);
    if (!buf)
        goto out_file;

    path = d_path(&exe->f_path, buf, PAGE_SIZE);
    if (!IS_ERR(path) && strcmp(path, exe_path) == 0)
        allowed = true;
    free_page((unsigned long)buf);

out_file:
    fput(exe);
    return allowed;
}

static bool nbg_sensor_caller_allowed(void)
{
    return nbg_caller_is_root() || nbg_caller_is_surfaceflinger();
}

/* ---- 会话与范围校验 ---- */

static struct mm_struct *nbg_sensor_live_mm(struct nbg_sensor_session *session)
{
    struct mm_struct *mm;

    if (!pid_alive(session->target) ||
        READ_ONCE(session->target->exit_state))
        return ERR_PTR(-ESRCH);

    mm = get_task_mm(session->target);
    if (!mm)
        return ERR_PTR(-ESRCH);

    /* mm 被 exec 换掉后旧地址空间已无意义。 */
    if (mm != session->mm) {
        mmput(mm);
        return ERR_PTR(-ESTALE);
    }
    return mm;
}

static bool nbg_sensor_same_library(struct nbg_sensor_session *session,
                                    struct vm_area_struct *vma)
{
    return vma->vm_file &&
           file_inode(vma->vm_file) == file_inode(session->library) &&
           vma->vm_file->f_path.mnt == session->library->f_path.mnt;
}

static int nbg_sensor_allowed_range(struct nbg_sensor_session *session,
                                    struct mm_struct *mm, unsigned long addr,
                                    size_t size, bool writing)
{
    unsigned long end;

    if (!size || addr >= TASK_SIZE_64 || size > TASK_SIZE_64 - addr)
        return -EINVAL;

    end = addr + size;
    while (addr < end) {
        struct vm_area_struct *vma = find_vma(mm, addr);

        if (!vma || addr < vma->vm_start)
            return -EFAULT;
        if (!nbg_sensor_same_library(session, vma) ||
            (vma->vm_flags & (VM_IO | VM_PFNMAP | VM_MIXEDMAP |
                              VM_HUGETLB | VM_MAYSHARE)))
            return -EACCES;
        if (!(vma->vm_flags & VM_READ) ||
            (writing && !(vma->vm_flags & VM_MAYWRITE)))
            return -EACCES;
        addr = min(end, vma->vm_end);
    }
    return 0;
}

/* 调用方持 session->lock。GUP 与范围校验共用一把 mmap 读锁，
 * 避免校验后并发 unmap 换成别的映射。 */
static ssize_t nbg_sensor_transfer(struct nbg_sensor_session *session,
                                   struct mm_struct *mm, unsigned long addr,
                                   void *buffer, size_t size, bool writing)
{
    size_t done = 0;
    int ret;

    /* 布防后只允许改 delta 与 GOT 两个 8 字节槽。 */
    if (writing && session->armed &&
        !((addr == session->patch.delta_addr ||
           addr == session->patch.got_addr) && size == sizeof(u64)))
        return -EPERM;

    compat_mmap_read_lock(mm);
    ret = nbg_sensor_allowed_range(session, mm, addr, size, writing);
    if (ret)
        goto out;

    while (done < size) {
        struct vm_area_struct *vma = find_vma(mm, addr);
        struct page *page = NULL;
        unsigned int flags = writing ? FOLL_WRITE | FOLL_FORCE : 0;
        size_t bytes = min_t(size_t, size - done,
                             PAGE_SIZE - offset_in_page(addr));
        void *mapped;
        void *at;

        /* locked 传 NULL：GUP 不得丢 mmap 锁，否则 vma 会失效。 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
        ret = get_user_pages_remote(mm, addr, 1, flags, &page, NULL);
#else
        ret = get_user_pages_remote(mm, addr, 1, flags, &page, NULL, NULL);
#endif
        if (ret != 1) {
            if (ret >= 0)
                ret = -EFAULT;
            break;
        }

        mapped = kmap(page);
        at = (char *)mapped + offset_in_page(addr);

        if (writing) {
            if (bytes == sizeof(u64) && IS_ALIGNED(addr, sizeof(u64))) {
                u64 value;

                memcpy(&value, (char *)buffer + done, sizeof(value));
                if (session->armed && addr == session->patch.got_addr) {
                    u64 expected;
                    u64 previous;

                    /* 只接受 original 与 replacement 两个值。 */
                    if (value != session->patch.original &&
                        value != session->patch.replacement) {
                        ret = -EINVAL;
                        goto put;
                    }
                    expected = value == session->patch.original ?
                        session->patch.replacement : session->patch.original;
                    /* trampoline 必须先写完再发布 GOT 指针。 */
                    smp_wmb();
                    previous = cmpxchg((u64 *)at, expected, value);
                    if (previous != expected && previous != value) {
                        ret = -EAGAIN;
                        goto put;
                    }
                } else {
                    WRITE_ONCE(*(u64 *)at, value);
                }
            } else {
                memcpy(at, (char *)buffer + done, bytes);
            }

            flush_dcache_page(page);
            if ((vma->vm_flags & VM_EXEC) && nbg_sync_icache_dcache)
                nbg_sync_icache_dcache(mk_pte(page, vma->vm_page_prot));
            set_page_dirty_lock(page);
        } else {
            memcpy((char *)buffer + done, at, bytes);
        }

        ret = 0;
put:
        kunmap(page);
        put_page(page);
        if (ret)
            break;
        done += bytes;
        addr += bytes;
    }

out:
    compat_mmap_read_unlock(mm);
    return done ? (ssize_t)done : ret;
}

static ssize_t nbg_sensor_rw(struct file *file, char __user *buf,
                             size_t count, loff_t *pos, bool writing)
{
    struct nbg_sensor_session *session = file->private_data;
    struct mm_struct *mm;
    void *buffer;
    ssize_t ret;

    if (task_tgid(current) != session->owner)
        return -EACCES;
    if (!count)
        return 0;
    if (count > NBG_SENSOR_IO_MAX)
        return -E2BIG;
    if (*pos < 0 || (u64)*pos >= TASK_SIZE_64 ||
        count > TASK_SIZE_64 - (u64)*pos)
        return -EINVAL;

    buffer = writing ? memdup_user(buf, count) : kmalloc(count, GFP_KERNEL);
    if (IS_ERR(buffer))
        return PTR_ERR(buffer);
    if (!buffer)
        return -ENOMEM;

    mutex_lock(&session->lock);
    mm = nbg_sensor_live_mm(session);
    if (IS_ERR(mm)) {
        ret = PTR_ERR(mm);
    } else {
        ret = nbg_sensor_transfer(session, mm, (unsigned long)*pos, buffer,
                                  count, writing);
        mmput(mm);
        if (ret > 0 && !writing && copy_to_user(buf, buffer, ret))
            ret = -EFAULT;
        if (ret > 0)
            *pos += ret;
    }
    mutex_unlock(&session->lock);

    kfree(buffer);
    return ret;
}

static ssize_t nbg_sensor_read(struct file *file, char __user *buf,
                               size_t count, loff_t *pos)
{
    return nbg_sensor_rw(file, buf, count, pos, false);
}

static ssize_t nbg_sensor_write(struct file *file, const char __user *buf,
                                size_t count, loff_t *pos)
{
    return nbg_sensor_rw(file, (char __user *)buf, count, pos, true);
}

/* ---- GOT 钩子布防 ---- */

static int nbg_sensor_arm(struct nbg_sensor_session *session,
                          struct mm_struct *mm, void __user *arg)
{
    NBG_SENSOR_ARM_REQ req;
    struct vm_area_struct *vma;
    u64 got;
    u64 original;
    int ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    if (req.version != NBG_SENSOR_ARM_ABI_VERSION || req.reserved ||
        !IS_ALIGNED(req.got_addr, 8) || !IS_ALIGNED(req.delta_addr, 16) ||
        req.delta_addr >= TASK_SIZE_64 - NBG_SENSOR_CAVE ||
        req.replacement != req.delta_addr + 16 ||
        !req.original || req.original >= TASK_SIZE_64 ||
        !IS_ALIGNED(req.original, 4) ||
        (req.original >= req.delta_addr &&
         req.original < req.delta_addr + NBG_SENSOR_CAVE) ||
        (req.got_addr >= req.delta_addr &&
         req.got_addr < req.delta_addr + NBG_SENSOR_CAVE))
        return -EINVAL;

    if (session->armed)
        return -EBUSY;

    compat_mmap_read_lock(mm);

    ret = nbg_sensor_allowed_range(session, mm, req.delta_addr,
                                   NBG_SENSOR_CAVE, true);
    if (!ret) {
        vma = find_vma(mm, req.delta_addr);
        /* trampoline 空穴必须整体落在可执行页内。 */
        if (!(vma->vm_flags & VM_EXEC) ||
            req.delta_addr + NBG_SENSOR_CAVE > vma->vm_end)
            ret = -EINVAL;
    }

    if (!ret)
        ret = nbg_sensor_allowed_range(session, mm, req.got_addr,
                                       sizeof(u64), true);
    /* GOT 槽本身不能在可执行页上，否则等于允许改代码。 */
    if (!ret && (find_vma(mm, req.got_addr)->vm_flags & VM_EXEC))
        ret = -EINVAL;

    if (!ret) {
        vma = find_vma(mm, req.original);
        if (!vma || req.original < vma->vm_start ||
            !(vma->vm_flags & VM_EXEC))
            ret = -EINVAL;
    }

    compat_mmap_read_unlock(mm);
    if (ret)
        return ret;

    /* 现场必须一致：GOT 槽与 delta+8 都已指向 original。 */
    if (nbg_sensor_transfer(session, mm, req.got_addr, &got, sizeof(got),
                            false) != sizeof(got) ||
        nbg_sensor_transfer(session, mm, req.delta_addr + 8, &original,
                            sizeof(original), false) != sizeof(original))
        return -EFAULT;
    if (got != req.original || original != req.original)
        return -ESTALE;

    session->patch = req;
    session->armed = true;
    return 0;
}

static long nbg_sensor_ioctl(struct file *file, unsigned int cmd,
                             unsigned long arg)
{
    struct nbg_sensor_session *session = file->private_data;
    struct mm_struct *mm;
    long ret;

    if (task_tgid(current) != session->owner)
        return -EACCES;

    mutex_lock(&session->lock);
    mm = nbg_sensor_live_mm(session);
    if (IS_ERR(mm)) {
        ret = PTR_ERR(mm);
        goto out;
    }

    if (cmd == NBG_SENSOR_IOC_ARM) {
        ret = nbg_sensor_arm(session, mm, (void __user *)arg);
    } else if (cmd == NBG_SENSOR_IOC_QUERY_ACCESS) {
        NBG_QUERY_ACCESS_REQ req;

        if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
            ret = -EFAULT;
        } else if (req.flags || req.pid != task_pid_vnr(session->target)) {
            ret = -EINVAL;
        } else {
            ret = nbg_query_access_mm(mm,
                                      (unsigned long)untagged_addr(req.addr),
                                      &req);
            if (!ret && copy_to_user((void __user *)arg, &req, sizeof(req)))
                ret = -EFAULT;
        }
    } else {
        ret = -ENOTTY;
    }

    mmput(mm);
out:
    mutex_unlock(&session->lock);
    return ret;
}

/* ---- 清理与释放 ---- */

static void nbg_sensor_cleanup(struct work_struct *work)
{
    struct nbg_sensor_session *session =
        container_of(work, struct nbg_sensor_session, cleanup);
    struct mm_struct *mm;
    u64 zero = 0;
    ssize_t delta_ret;
    ssize_t got_ret;

    if (!session->armed)
        return;

    mm = nbg_sensor_live_mm(session);
    if (IS_ERR(mm))
        return;

    delta_ret = nbg_sensor_transfer(session, mm, session->patch.delta_addr,
                                    &zero, sizeof(zero), true);
    got_ret = nbg_sensor_transfer(session, mm, session->patch.got_addr,
                                  &session->patch.original, sizeof(u64),
                                  true);
    if (delta_ret != sizeof(u64) || got_ret != sizeof(u64))
        pr_warn("nbg: sensor cleanup failed delta=%zd got=%zd\n",
                delta_ret, got_ret);

    mmput(mm);
}

static int nbg_sensor_release(struct inode *inode, struct file *file)
{
    struct nbg_sensor_session *session = file->private_data;

    /* 进程可能带未决 SIGKILL，GUP 会拒绝，所以在无该信号的 worker 里清理。 */
    schedule_work(&session->cleanup);
    flush_work(&session->cleanup);

    mutex_lock(&g_session_lock);
    if (g_active == session)
        g_active = NULL;
    mutex_unlock(&g_session_lock);

    if (session->library)
        fput(session->library);
    if (session->mm)
        mmdrop(session->mm);
    if (session->target)
        put_task_struct(session->target);
    if (session->owner)
        put_pid(session->owner);
    kfree(session);
    return 0;
}

static const struct file_operations nbg_sensor_fops = {
    .owner          = THIS_MODULE,
    .read           = nbg_sensor_read,
    .write          = nbg_sensor_write,
    .llseek         = default_llseek,
    .unlocked_ioctl = nbg_sensor_ioctl,
    .compat_ioctl   = nbg_sensor_ioctl,
    .release        = nbg_sensor_release,
};

long nbg_sensor_open(void __user *arg)
{
    NBG_SENSOR_OPEN_REQ req;
    struct nbg_sensor_session *session;
    struct mm_struct *mm = NULL;
    struct vm_area_struct *vma;
    const struct cred *cred;
    struct file *file;
    char comm[TASK_COMM_LEN];
    char *path_buf;
    int fd;
    int ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.version != NBG_SENSOR_OPEN_ABI_VERSION || req.reserved ||
        req.pid <= 0)
        return -EINVAL;
    if (!nbg_sensor_caller_allowed())
        return -EACCES;

    session = kzalloc(sizeof(*session), GFP_KERNEL);
    path_buf = (char *)__get_free_page(GFP_KERNEL);
    if (!session || !path_buf) {
        kfree(session);
        if (path_buf)
            free_page((unsigned long)path_buf);
        return -ENOMEM;
    }

    mutex_init(&session->lock);
    INIT_WORK(&session->cleanup, nbg_sensor_cleanup);
    session->owner = get_task_pid(current->group_leader, PIDTYPE_PID);

    mutex_lock(&g_session_lock);
    ret = -EBUSY;
    if (g_active)
        goto fail;

    rcu_read_lock();
    session->target = pid_task(find_vpid(req.pid), PIDTYPE_PID);
    if (session->target)
        get_task_struct(session->target);
    rcu_read_unlock();

    ret = -ESRCH;
    if (!session->target)
        goto fail;

    /* 只接受 system_server 组长线程，uid/euid 均为 system(1000)。 */
    get_task_comm(comm, session->target);
    if (!nbg_get_task_cred_fn) {
        /* 取不到 get_task_cred 就无法做身份核验，宁可直接拒绝。 */
        ret = -EACCES;
        goto fail;
    }

    cred = nbg_get_task_cred_fn(session->target);
    if (!cred) {
        ret = -EACCES;
        goto fail;
    }

    ret = strcmp(comm, "system_server") ||
          !thread_group_leader(session->target) ||
          !nbg_user_ns_is_init(cred) ||
          !uid_eq(cred->uid, KUIDT_INIT(1000)) ||
          !uid_eq(cred->euid, KUIDT_INIT(1000)) ? -EACCES : 0;
    nbg_put_cred_safe((struct cred *)cred);
    if (ret)
        goto fail;

    mm = get_task_mm(session->target);
    ret = -ESRCH;
    if (!mm)
        goto fail;

    req.out_module_base = 0;
    req.out_module_size = 0;

    compat_mmap_read_lock(mm);
#if USE_VMA_ITERATOR
    {
        VMA_ITERATOR(vmi, mm, 0);
        for_each_vma(vmi, vma) {
#else
    {
        for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
            if (!vma->vm_file)
                continue;

            if (!session->library) {
                char *path;

                if (strcmp(vma->vm_file->f_path.dentry->d_name.name,
                           "libsensorservice.so"))
                    continue;
                path = d_path(&vma->vm_file->f_path, path_buf, PAGE_SIZE);
                if (IS_ERR(path) || strcmp(path, NBG_SENSOR_LIBRARY) ||
                    vma->vm_pgoff)
                    continue;
                session->library = get_file(vma->vm_file);
                req.out_module_base = vma->vm_start;
            }

            if (nbg_sensor_same_library(session, vma))
                req.out_module_size = vma->vm_end - req.out_module_base;
        }
    }
    compat_mmap_read_unlock(mm);

    ret = -ENOENT;
    if (!session->library)
        goto fail;

    session->mm = mm;
    mmgrab(mm);
    mmput(mm);
    mm = NULL;

    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0) {
        ret = fd;
        goto fail;
    }

    file = anon_inode_getfile("[nbg-sensor-mem]", &nbg_sensor_fops, session,
                              O_RDWR | O_CLOEXEC);
    if (IS_ERR(file)) {
        put_unused_fd(fd);
        ret = PTR_ERR(file);
        goto fail;
    }

    /* anon_inode fd 必须显式开启定位 IO。 */
    file->f_mode |= FMODE_PREAD | FMODE_PWRITE | FMODE_LSEEK;
    req.out_fd = fd;
    req.out_uid = 1000;
    g_active = session;

    mutex_unlock(&g_session_lock);
    free_page((unsigned long)path_buf);

    if (copy_to_user(arg, &req, sizeof(req))) {
        put_unused_fd(fd);
        fput(file);
        return -EFAULT;
    }

    fd_install(fd, file);
    return 0;

fail:
    mutex_unlock(&g_session_lock);
    if (mm)
        mmput(mm);
    if (session->mm)
        mmdrop(session->mm);
    if (session->library)
        fput(session->library);
    if (session->target)
        put_task_struct(session->target);
    if (session->owner)
        put_pid(session->owner);
    free_page((unsigned long)path_buf);
    kfree(session);
    return ret;
}
