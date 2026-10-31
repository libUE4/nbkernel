/* query.c — 进程 / 线程 / 地址查询
 *
 * 按 comm 查 pid、按 VMA 文件名查模块基址与完整路径、TLS、线程 TID
 * 择优与枚举、线程栈、单地址映射查询、可访问性与信号状态查询。
 */
#include "query.h"

#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <asm/pgtable.h>
#include <asm/processor.h>

#include "nbg_compat.h"
#include "memory.h"
#include "nbg_ksyms.h"

/* ---- 公共小工具 ---- */

static struct task_struct *nbg_find_task(pid_t pid)
{
    struct task_struct *task;

    if (pid <= 0)
        return NULL;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();

    return task;
}

/* 拿到 siglock 后必须复核 task->sighand 未被 __exit_signal 置空，
 * 否则用的是回收后的对象。 */
static struct sighand_struct *nbg_lock_sighand(struct task_struct *task,
                                               unsigned long *irqflags)
{
    struct sighand_struct *sh;

    rcu_read_lock();
    for (;;) {
        sh = rcu_dereference(task->sighand);
        if (!sh) {
            smp_acquire__after_ctrl_dep();
            rcu_read_unlock();
            return NULL;
        }

        spin_lock_irqsave(&sh->siglock, *irqflags);
        if (sh == rcu_access_pointer(task->sighand)) {
            rcu_read_unlock();
            return sh;
        }
        spin_unlock_irqrestore(&sh->siglock, *irqflags);
    }
}

/* ---- 进程枚举 ---- */

long nbg_query_pid(void __user *arg)
{
    NBG_GET_PID_REQ req;
    struct task_struct *task;
    bool found = false;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    req.name[sizeof(req.name) - 1] = '\0';
    req.out_pid = -1;
    if (req.name[0] == '\0')
        return -EINVAL;

    rcu_read_lock();
    for_each_process(task) {
        if (strncmp(task->comm, req.name, TASK_COMM_LEN) == 0) {
            req.out_pid = task->pid;
            found = true;
            break;
        }
    }
    rcu_read_unlock();

    if (!found)
        return -ESRCH;
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

long nbg_query_pids(void __user *arg)
{
    NBG_GET_PIDS_REQ req;
    struct task_struct *task;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    req.name[sizeof(req.name) - 1] = '\0';
    req.out_count = 0;
    req.out_total = 0;
    memset(req.out_pids, 0, sizeof(req.out_pids));
    if (req.name[0] == '\0')
        return -EINVAL;

    rcu_read_lock();
    for_each_process(task) {
        if (strncmp(task->comm, req.name, TASK_COMM_LEN) != 0)
            continue;

        if (req.out_count < NBG_GET_PIDS_MAX)
            req.out_pids[req.out_count++] = task->pid;
        req.out_total++;
    }
    rcu_read_unlock();

    if (req.out_total == 0)
        return -ESRCH;
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

/* ---- 模块 / VMA ---- */

static struct mm_struct *nbg_task_mm(struct task_struct *task)
{
    return get_task_mm(task);
}

/* 首个匹配 VMA 的起始地址作为 base，最后一个匹配 VMA 的结束作为 size 上界。
 * 匹配用 dentry d_name + strstr，不是完整路径。 */
static int nbg_scan_module(uint64_t *base, uint64_t *size, pid_t pid,
                           const char *name, uint64_t max_vma_size,
                           char *pathbuf, size_t pathbuf_len)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    bool found = false;

    task = nbg_find_task(pid);
    if (!task)
        return -ESRCH;

    mm = nbg_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

    compat_mmap_read_lock(mm);
#if USE_VMA_ITERATOR
    {
        VMA_ITERATOR(vmi, mm, 0);
        for_each_vma(vmi, vma) {
            const char *vname;
            uint64_t vma_size;

            if (!vma->vm_file)
                continue;
            vname = vma->vm_file->f_path.dentry->d_name.name;
            if (!strstr(vname, name))
                continue;

            vma_size = (uint64_t)(vma->vm_end - vma->vm_start);
            if (max_vma_size && vma_size > max_vma_size)
                continue;

            if (!found) {
                *base = vma->vm_start;
                found = true;
                if (pathbuf && pathbuf_len) {
                    char *p = d_path(&vma->vm_file->f_path, pathbuf,
                                     pathbuf_len);
                    if (!IS_ERR(p))
                        strscpy(pathbuf, p, pathbuf_len);
                }
            }
            *size = vma->vm_end - *base;
            if (pathbuf)
                break;
        }
    }
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        const char *vname;
        uint64_t vma_size;

        if (!vma->vm_file)
            continue;
        vname = vma->vm_file->f_path.dentry->d_name.name;
        if (!strstr(vname, name))
            continue;

        vma_size = (uint64_t)(vma->vm_end - vma->vm_start);
        if (max_vma_size && vma_size > max_vma_size)
            continue;

        if (!found) {
            *base = vma->vm_start;
            found = true;
            if (pathbuf && pathbuf_len) {
                char *p = d_path(&vma->vm_file->f_path, pathbuf, pathbuf_len);
                if (!IS_ERR(p))
                    strscpy(pathbuf, p, pathbuf_len);
            }
        }
        *size = vma->vm_end - *base;
        if (pathbuf)
            break;
    }
#endif
    compat_mmap_read_unlock(mm);

    mmput(mm);
    put_task_struct(task);

    return found ? 0 : -ENOENT;
}

long nbg_query_module_base(void __user *arg)
{
    NBG_MODULE_BASE_REQ req;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    req.name[sizeof(req.name) - 1] = '\0';
    req.out_base = 0;
    req.out_size = 0;
    if (req.name[0] == '\0')
        return -EINVAL;

    if (nbg_scan_module(&req.out_base, &req.out_size, req.pid, req.name, 0,
                        NULL, 0))
        return -ENOENT;

    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

long nbg_query_module_base2(void __user *arg)
{
    NBG_MODULE_BASE2_REQ req;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    req.name[sizeof(req.name) - 1] = '\0';
    req.out_base = 0;
    req.out_size = 0;
    if (req.name[0] == '\0')
        return -EINVAL;

    if (nbg_scan_module(&req.out_base, &req.out_size, req.pid, req.name,
                        req.max_vma_size, NULL, 0))
        return -ENOENT;

    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

long nbg_query_module_path(void __user *arg)
{
    NBG_MODULE_PATH_REQ req;
    char pathbuf[512];
    uint64_t base = 0;
    uint64_t size = 0;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    req.name[sizeof(req.name) - 1] = '\0';
    req.out_path[0] = '\0';
    if (req.name[0] == '\0')
        return -EINVAL;

    pathbuf[0] = '\0';
    if (nbg_scan_module(&base, &size, req.pid, req.name, 0, pathbuf,
                        sizeof(pathbuf)))
        return -ENOENT;

    strscpy(req.out_path, pathbuf, sizeof(req.out_path));
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

/* ---- TLS / 线程 ---- */

long nbg_query_tls(void __user *arg)
{
    NBG_GET_TLS_REQ req;
    struct task_struct *task;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.pid <= 0)
        return -EINVAL;

    req.out_tls = 0;

    task = nbg_find_task(req.pid);
    if (!task)
        return -ESRCH;

    req.out_tls = (uint64_t)*task_user_tls(task);
    put_task_struct(task);

    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

static u64 nbg_thread_exec_ns(const struct task_struct *thread)
{
    return thread->se.sum_exec_runtime;
}

static u32 nbg_thread_sched_flags(const struct task_struct *thread)
{
    u32 flags = 0;

#ifdef CONFIG_SMP
    if (READ_ONCE(thread->on_cpu))
        flags |= NBG_THREAD_TID_F_ON_CPU;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
    if (READ_ONCE(thread->__state) == TASK_RUNNING)
        flags |= NBG_THREAD_TID_F_RUNNING;
#else
    if (READ_ONCE(thread->state) == TASK_RUNNING)
        flags |= NBG_THREAD_TID_F_RUNNING;
#endif
    return flags;
}

/* 优先选正在 CPU 上跑的，其次累积 CFS 运行时间最长的。不能取最小 tid：
 * UE4 多个 worker 共用 "GameThread" 这类 comm，最小 tid 常是空闲同名线程。 */
static bool nbg_thread_better(int tid, u32 flags, u64 exec_ns,
                              int best_tid, u32 best_flags, u64 best_exec)
{
    bool on_cpu;
    bool best_on_cpu;

    if (best_tid < 0)
        return true;

    on_cpu = (flags & NBG_THREAD_TID_F_ON_CPU) != 0;
    best_on_cpu = (best_flags & NBG_THREAD_TID_F_ON_CPU) != 0;
    if (on_cpu != best_on_cpu)
        return on_cpu;
    if (exec_ns != best_exec)
        return exec_ns > best_exec;
    return tid > best_tid;
}

long nbg_query_thread_tid(void __user *arg)
{
    NBG_GET_THREAD_TID_REQ req;
    struct task_struct *task;
    struct task_struct *leader;
    struct task_struct *thread;
    int best_tid = -1;
    u32 best_flags = 0;
    u64 best_exec = 0;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.pid <= 0)
        return -EINVAL;

    req.comm[sizeof(req.comm) - 1] = '\0';
    if (req.comm[0] == '\0')
        return -EINVAL;
    req.out_tid = -1;

    task = nbg_find_task(req.pid);
    if (!task)
        return -ESRCH;

    rcu_read_lock();
    leader = task->group_leader;
    for_each_thread(leader, thread) {
        u32 flags;
        u64 exec_ns;

        if (thread == leader)
            continue;
        if (strncmp(thread->comm, req.comm, TASK_COMM_LEN) != 0)
            continue;

        flags = nbg_thread_sched_flags(thread);
        exec_ns = nbg_thread_exec_ns(thread);
        if (nbg_thread_better(thread->pid, flags, exec_ns, best_tid,
                              best_flags, best_exec)) {
            best_tid = thread->pid;
            best_flags = flags;
            best_exec = exec_ns;
        }
    }
    rcu_read_unlock();
    put_task_struct(task);

    if (best_tid < 0)
        return -ESRCH;

    req.out_tid = best_tid;
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

long nbg_query_thread_tids(void __user *arg)
{
    NBG_GET_THREAD_TIDS_REQ req;
    struct task_struct *task;
    struct task_struct *leader;
    struct task_struct *thread;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.pid <= 0)
        return -EINVAL;

    req.comm[sizeof(req.comm) - 1] = '\0';
    if (req.comm[0] == '\0')
        return -EINVAL;

    req.out_count = 0;
    req.out_total = 0;
    req.reserved = 0;
    memset(req.out_threads, 0, sizeof(req.out_threads));

    task = nbg_find_task(req.pid);
    if (!task)
        return -ESRCH;

    rcu_read_lock();
    leader = task->group_leader;
    for_each_thread(leader, thread) {
        if (thread == leader)
            continue;
        if (strncmp(thread->comm, req.comm, TASK_COMM_LEN) != 0)
            continue;

        if (req.out_count < NBG_GET_THREAD_TIDS_MAX) {
            NBG_THREAD_TID_INFO *info =
                &req.out_threads[req.out_count];

            info->tid = thread->pid;
            info->flags = nbg_thread_sched_flags(thread);
            info->exec_ns = nbg_thread_exec_ns(thread);
            req.out_count++;
        }
        req.out_total++;
    }
    rcu_read_unlock();
    put_task_struct(task);

    if (req.out_total == 0)
        return -ESRCH;
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

/* ---- 线程栈 ---- */

#ifdef CONFIG_ANON_VMA_NAME
static bool nbg_is_thread_stack_vma(struct vm_area_struct *vma,
                                    const char *expected)
{
    struct anon_vma_name *anon_name;

    if (vma->vm_file)
        return false;
    if ((vma->vm_flags & (VM_READ | VM_WRITE)) != (VM_READ | VM_WRITE))
        return false;

    /* 调用方持 mmap_lock，且上面已确认 vm_file 为空，可直接读 anon_name。 */
    anon_name = vma->anon_name;
    return anon_name && strcmp(anon_name->name, expected) == 0;
}
#endif

long nbg_query_thread_stack(void __user *arg)
{
    NBG_GET_THREAD_STACK_REQ req;
#ifndef CONFIG_ANON_VMA_NAME
    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.tid <= 0)
        return -EINVAL;
    return -EOPNOTSUPP;
#else
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned long tls;
    unsigned long low = 0;
    unsigned long high = 0;
    char expected[32];
    bool found = false;
    bool contains_tls = false;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.tid <= 0)
        return -EINVAL;

    req.out_named = 0;
    req.out_low = 0;
    req.out_high = 0;
    req.out_tls = 0;

    task = nbg_find_task(req.tid);
    if (!task)
        return -ESRCH;

    tls = untagged_addr((unsigned long)*task_user_tls(task));
    mm = nbg_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

    scnprintf(expected, sizeof(expected), "stack_and_tls:%d", req.tid);

    compat_mmap_read_lock(mm);
#if USE_VMA_ITERATOR
    {
        VMA_ITERATOR(vmi, mm, 0);
        for_each_vma(vmi, vma) {
            if (!nbg_is_thread_stack_vma(vma, expected))
                continue;
            if (!found) {
                low = vma->vm_start;
                high = vma->vm_end;
                found = true;
            } else if (vma->vm_start <= high) {
                if (vma->vm_end > high)
                    high = vma->vm_end;
            } else {
                found = false;
                break;
            }
            if (tls >= vma->vm_start && tls < vma->vm_end)
                contains_tls = true;
        }
    }
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (!nbg_is_thread_stack_vma(vma, expected))
            continue;
        if (!found) {
            low = vma->vm_start;
            high = vma->vm_end;
            found = true;
        } else if (vma->vm_start <= high) {
            if (vma->vm_end > high)
                high = vma->vm_end;
        } else {
            found = false;
            break;
        }
        if (tls >= vma->vm_start && tls < vma->vm_end)
            contains_tls = true;
    }
#endif
    compat_mmap_read_unlock(mm);

    mmput(mm);
    put_task_struct(task);

    if (!found || !contains_tls || low == 0 || high <= low)
        return -ENOENT;

    req.out_named = 1;
    req.out_low = (uint64_t)low;
    req.out_high = (uint64_t)high;
    req.out_tls = (uint64_t)tls;
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
#endif
}

/* ---- 单地址映射查询 ---- */

static int nbg_mapping_leaf(NBG_QUERY_MAPPING_REQ *req,
                            struct vm_area_struct *vma, pte_t entry,
                            uint64_t phys, uint64_t granule)
{
    uint64_t attr = pte_val(entry) & PTE_ATTRINDX_MASK;

    /* arm64 5.10/5.15 没有 pte_user()，直接用 PTE_USER 位判断。 */
    if (!pte_valid(entry) || !(pte_val(entry) & PTE_USER))
        return -ENODATA;
    if (attr != PTE_ATTRINDX(MT_NORMAL) &&
        attr != PTE_ATTRINDX(MT_NORMAL_NC)
#ifdef MT_NORMAL_TAGGED
        && attr != PTE_ATTRINDX(MT_NORMAL_TAGGED)
#endif
        )
        return -EOPNOTSUPP;

    req->out_phys_addr = phys;
    req->out_page_size = granule;
    req->out_flags = 0;
    if (vma->vm_flags & VM_READ)
        req->out_flags |= NBG_MAPPING_F_READ;
    if (vma->vm_flags & VM_WRITE)
        req->out_flags |= NBG_MAPPING_F_WRITE;
    if (vma->vm_flags & VM_EXEC)
        req->out_flags |= NBG_MAPPING_F_EXEC;
    /* 只读 MAP_SHARED 文件会清 VM_SHARED，但仍保留 MAYSHARE。 */
    if (vma->vm_flags & VM_MAYSHARE)
        req->out_flags |= NBG_MAPPING_F_SHARED;
    return 0;
}

static int nbg_mapping_locked(struct mm_struct *mm, unsigned long addr,
                              NBG_QUERY_MAPPING_REQ *req)
{
    struct vm_area_struct *vma;
    pgd_t *pgdp;
    p4d_t *p4dp;
    pud_t *pudp, pud;
    pmd_t *pmdp, pmd;
    pte_t *ptep, pte;
    spinlock_t *ptl;
    int ret;

    vma = find_vma(mm, addr);
    if (!vma || addr < vma->vm_start)
        return -ENOENT;
    /* hugetlb 的加锁协议不同；设备内存不是 RAM。 */
    if (vma->vm_flags & (VM_IO | VM_PFNMAP | VM_MIXEDMAP | VM_HUGETLB))
        return -EOPNOTSUPP;

    pgdp = pgd_offset(mm, addr);
    if (pgd_none(READ_ONCE(*pgdp)) || pgd_bad(READ_ONCE(*pgdp)))
        return -ENODATA;
    p4dp = p4d_offset(pgdp, addr);
    if (p4d_none(READ_ONCE(*p4dp)) || p4d_bad(READ_ONCE(*p4dp)))
        return -ENODATA;

    pudp = pud_offset(p4dp, addr);
    ptl = pud_lock(mm, pudp);
    pud = READ_ONCE(*pudp);
    if (pud_leaf(pud)) {
        ret = nbg_mapping_leaf(req, vma, __pte(pud_val(pud)),
                               ((uint64_t)pud_pfn(pud) << PAGE_SHIFT) +
                                   (addr & ~PUD_MASK),
                               PUD_SIZE);
        spin_unlock(ptl);
        return ret;
    }
    ret = pud_none(pud) || pud_bad(pud);
    spin_unlock(ptl);
    if (ret)
        return -ENODATA;

    /* arm64 页表在低端内存。从采样 PMD 之前持有 RCU 直到释放 PTE 锁，
     * 然后在锁内复核父级，等价于 pte_offset_map_lock 的低端内存协议。 */
    rcu_read_lock();
    pmdp = pmd_offset(pudp, addr);
    ptl = pmd_lock(mm, pmdp);
    pmd = READ_ONCE(*pmdp);
    if (pmd_leaf(pmd)) {
        ret = nbg_mapping_leaf(req, vma, __pte(pmd_val(pmd)),
                               ((uint64_t)pmd_pfn(pmd) << PAGE_SHIFT) +
                                   (addr & ~PMD_MASK),
                               PMD_SIZE);
        spin_unlock(ptl);
        rcu_read_unlock();
        return ret;
    }
    ret = pmd_none(pmd) || pmd_bad(pmd);
    spin_unlock(ptl);
    if (ret) {
        rcu_read_unlock();
        return -ENODATA;
    }

    ptep = pte_offset_kernel(&pmd, addr);
    ptl = pte_lockptr(mm, &pmd);
    spin_lock(ptl);
    if (!pmd_same(pmd, READ_ONCE(*pmdp))) {
        ret = -EAGAIN;
    } else {
        pte = READ_ONCE(*ptep);
        ret = nbg_mapping_leaf(req, vma, pte,
                               ((uint64_t)pte_pfn(pte) << PAGE_SHIFT) +
                                   (addr & ~PAGE_MASK),
                               PAGE_SIZE);
    }
    spin_unlock(ptl);
    rcu_read_unlock();
    return ret;
}

long nbg_query_mapping(void __user *arg)
{
    NBG_QUERY_MAPPING_REQ req;
    struct nbg_read_ctx ctx;
    unsigned long addr;
    int ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.pid <= 0 || req.flags || req.reserved)
        return -EINVAL;

    addr = (unsigned long)untagged_addr((unsigned long)req.addr);
    if (!addr || addr >= TASK_SIZE_64)
        return -EINVAL;

    req.out_phys_addr = 0;
    req.out_page_size = 0;
    req.out_flags = 0;

    ret = nbg_read_ctx_init_pid(&ctx, req.pid);
    if (ret)
        return ret;

    compat_mmap_read_lock(ctx.mm);
    ret = nbg_mapping_locked(ctx.mm, addr, &req);
    compat_mmap_read_unlock(ctx.mm);
    nbg_read_ctx_release(&ctx);

    if (ret)
        return ret;
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

int nbg_query_access_mm(struct mm_struct *mm, unsigned long addr,
                        NBG_QUERY_ACCESS_REQ *req)
{
    NBG_QUERY_MAPPING_REQ physical = {};
    struct vm_area_struct *vma;
    int ret = 0;

    req->out_start = 0;
    req->out_end = 0;
    req->out_permissions = 0;
    req->out_state = NBG_ACCESS_UNMAPPED;

    compat_mmap_read_lock(mm);
    vma = addr < TASK_SIZE_64 ? find_vma(mm, addr) : NULL;
    if (vma && addr >= vma->vm_start) {
        req->out_start = vma->vm_start;
        req->out_end = vma->vm_end;
        if (vma->vm_flags & VM_READ)
            req->out_permissions |= NBG_MAPPING_F_READ;
        if (vma->vm_flags & VM_WRITE)
            req->out_permissions |= NBG_MAPPING_F_WRITE;
        if (vma->vm_flags & VM_EXEC)
            req->out_permissions |= NBG_MAPPING_F_EXEC;
        if (vma->vm_flags & VM_MAYSHARE)
            req->out_permissions |= NBG_MAPPING_F_SHARED;

        ret = nbg_mapping_locked(mm, addr, &physical);
        if (!ret)
            req->out_state = NBG_ACCESS_RESIDENT;
        else if (ret == -ENODATA)
            req->out_state = NBG_ACCESS_NONRESIDENT;
        else if (ret == -EOPNOTSUPP)
            req->out_state = NBG_ACCESS_UNSUPPORTED;
        else
            goto out;
        ret = 0;
    }
out:
    compat_mmap_read_unlock(mm);
    return ret;
}

long nbg_query_access(void __user *arg)
{
    NBG_QUERY_ACCESS_REQ req;
    struct nbg_read_ctx ctx;
    int ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.pid <= 0 || req.flags)
        return -EINVAL;

    ret = nbg_read_ctx_init_pid(&ctx, req.pid);
    if (ret)
        return ret;

    ret = nbg_query_access_mm(ctx.mm,
                              (unsigned long)untagged_addr(req.addr), &req);
    nbg_read_ctx_release(&ctx);

    if (ret)
        return ret;
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

long nbg_query_signal(void __user *arg)
{
    NBG_QUERY_SIGNAL_REQ req;
    struct task_struct *task;
    struct sighand_struct *sighand;
    struct k_sigaction action;
    unsigned long irqflags;
    unsigned long alt_sp;
    unsigned long alt_size;
    unsigned int alt_flags;
    int ret = 0;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.tid <= 0 || !req.signo || req.signo > _NSIG)
        return -EINVAL;

    task = nbg_find_task(req.tid);
    if (!task)
        return -ESRCH;

    sighand = nbg_lock_sighand(task, &irqflags);
    if (!sighand) {
        put_task_struct(task);
        return -ESRCH;
    }

    action = sighand->action[req.signo - 1];
    req.out_handler = (uint64_t)(unsigned long)action.sa.sa_handler;
    req.out_flags = action.sa.sa_flags;
    req.out_restorer = 0;
#ifdef __ARCH_HAS_SA_RESTORER
    req.out_restorer = (uint64_t)(unsigned long)action.sa.sa_restorer;
#endif
    req.out_action_mask = action.sa.sa_mask.sig[0];
    req.out_blocked = task->blocked.sig[0];
    req.out_tgid = task_tgid_vnr(task);

    alt_sp = READ_ONCE(task->sas_ss_sp);
    alt_size = READ_ONCE(task->sas_ss_size);
    alt_flags = READ_ONCE(task->sas_ss_flags);
    req.out_alt_sp = alt_sp;
    req.out_alt_size = alt_size;
    req.out_alt_flags = alt_flags | (alt_size ? 0 : SS_DISABLE);

    /* sigaltstack 是线程本地更新，不受 siglock 串行化。 */
    smp_rmb();
    if (alt_sp != READ_ONCE(task->sas_ss_sp) ||
        alt_size != READ_ONCE(task->sas_ss_size) ||
        alt_flags != READ_ONCE(task->sas_ss_flags))
        ret = -EAGAIN;

    spin_unlock_irqrestore(&sighand->siglock, irqflags);
    put_task_struct(task);

    if (ret)
        return ret;
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}
