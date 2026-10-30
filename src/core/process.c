/* process.c — 进程辅助查询(get_module_base / find_pid_by_name)*/

#include "process.h"
#include "memory.h"
#include "nbg_compat.h"
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include "nbg_alloc.h"
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>

/*
 * 匹配规则：name 与路径的 basename 完全相等，或 name 是 "libfoo.so" 而路径
 * 包含 "libfoo.so."（带版本号后缀），避免 strstr 误匹配同前缀的库。
 * 只取 vm_pgoff == 0 的 VMA，确保返回的是文件映射起始地址（真正的 base）。
 */
static bool vma_name_match(const char *path, const char *name)
{
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if (strcmp(base, name) == 0)
        return true;
    /* 允许匹配带版本号后缀，如 name="libfoo.so" 匹配 "libfoo.so.6"。
     * 收紧规则：版本号后缀必须全部是数字或点，避免病态名 "libfoo.so.evil" 误匹配。 */
    if (strncmp(base, name, strlen(name)) == 0 && base[strlen(name)] == '.') {
        const char *p = base + strlen(name) + 1;
        for (; *p; p++) {
            if (!((*p >= '0' && *p <= '9') || *p == '.'))
                return false;
        }
        return true;
    }
    return false;
}

uintptr_t get_module_base(pid_t pid, const char *name)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uintptr_t base = 0;
    char *buf;

    if (!name || !name[0])
        return 0;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return 0;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return 0;

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return 0;

    /* d_path 需要 PATH_MAX 大小的缓冲区，kmalloc 避免大栈帧 */
    buf = nbg_kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf) {
        mmput(mm);
        return 0;
    }

    compat_mmap_read_lock(mm);

#if USE_VMA_ITERATOR
    {
        VMA_ITERATOR(vmi, mm, 0);
        for_each_vma(vmi, vma) {
            char *filename;
            if (!vma->vm_file || vma->vm_pgoff != 0)
                continue;
            filename = d_path(&vma->vm_file->f_path, buf, PATH_MAX);
            if (!IS_ERR(filename) && vma_name_match(filename, name)) {
                base = vma->vm_start;
                break;
            }
        }
    }
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        char *filename;
        if (!vma->vm_file || vma->vm_pgoff != 0)
            continue;
        filename = d_path(&vma->vm_file->f_path, buf, PATH_MAX);
        if (IS_ERR(filename))
            continue;
        if (vma_name_match(filename, name)) {
            base = vma->vm_start;
            break;
        }
    }
#endif

    compat_mmap_read_unlock(mm);
    mmput(mm);
    kfree(buf);

    return base;
}

/* ==================== 按名字查 pid (零 procfs 暴露) ====================
 *
 * 这里直接在内核态遍历全局 tasklist:
 *   - for_each_process 走 init_task.tasks 链表, 不开任何文件
 *   - 短名 (<=15 字符) 直接比 task->comm (TASK_COMM_LEN=16, 含 NUL)
 *   - 长名 (Android 包名常见 20-30 字符) task->comm 被截断, 改读 argv[0]:
 *     mm->arg_start..arg_end 是用户态栈上 argv[]/env[] 区, 用自家
 *     read_process_memory_mm (memory.c 里的直接 PTE 路径)读取,
 *     仍然不打开文件, 也不留 access_process_vm 这个 ksymtab 字符串。
 *
 * 用户态 OP_FIND_PID 把包名传给内核, 拿回 pid.
 */

#define ARGV0_MAX_BYTES       512
#define ARGV0_SCAN_MAX_TASKS  512

/*
 * 读目标进程 argv[0] 到内核 buffer. 返回写入字节数 (含 NUL), 0=失败.
 * 与 access_process_vm 相比, 自家实现:
 *   - 完全不留 "access_process_vm" 这个符号字符串
 *   - 不 fault-in 缺页;页不在内存就按读失败处理
 *   - 复用调用方已持有的 mm 引用, 避免 exec 竞态
 */
static int read_argv0(struct mm_struct *mm, char *buf, size_t cap)
{
    unsigned long arg_start, arg_end;
    size_t len;

    if (!mm || !buf || cap == 0)
        return 0;

    arg_start = READ_ONCE(mm->arg_start);
    arg_end   = READ_ONCE(mm->arg_end);
    if (arg_end <= arg_start)
        return 0;

    len = arg_end - arg_start;
    if (len > cap - 1)
        len = cap - 1;

    memset(buf, 0, cap);
    if (!read_process_memory_mm(mm, (uintptr_t)arg_start, buf, len))
        return 0;

    /* argv[0] 以 NUL 结束 */
    buf[len] = '\0';
    return (int)strnlen(buf, cap);
}

static bool argv0_name_matches(const char *argv0, const char *name)
{
    const char *base;

    if (!argv0 || !name)
        return false;
    if (strcmp(argv0, name) == 0)
        return true;

    base = strrchr(argv0, '/');
    base = base ? base + 1 : argv0;
    return strcmp(base, name) == 0;
}

pid_t find_pid_by_cmdline(const char *name)
{
    struct task_struct *t;
    struct task_struct **cand;
    char *argv0_buf;
    pid_t found = 0;
    size_t name_len;
    int cand_n = 0;
    int i;

    if (!name || !name[0])
        return 0;
    name_len = strnlen(name, ARGV0_MAX_BYTES);
    if (name_len == 0 || name_len >= ARGV0_MAX_BYTES)
        return 0;

    argv0_buf = nbg_kmalloc(ARGV0_MAX_BYTES, GFP_KERNEL);
    cand = nbg_kmalloc_array(ARGV0_SCAN_MAX_TASKS, sizeof(*cand), GFP_KERNEL);
    if (!argv0_buf || !cand) {
        kfree(argv0_buf);
        kfree(cand);
        return 0;
    }

    /* Reading argv[0] can take the target mmap lock, so retain group leaders
     * under RCU and inspect them after leaving the task list read-side. */
    rcu_read_lock();
    for_each_process(t) {
        if ((t->flags & PF_KTHREAD) || t != t->group_leader)
            continue;
        if (cand_n >= ARGV0_SCAN_MAX_TASKS)
            break;
        get_task_struct(t);
        cand[cand_n++] = t;
    }
    rcu_read_unlock();

    for (i = 0; i < cand_n && !found; i++) {
        struct mm_struct *mm = get_task_mm(cand[i]);
        int n;

        if (!mm)
            continue;
        n = read_argv0(mm, argv0_buf, ARGV0_MAX_BYTES);
        mmput(mm);
        if (n > 0 && argv0_name_matches(argv0_buf, name))
            found = cand[i]->tgid;
    }

    for (i = 0; i < cand_n; i++)
        put_task_struct(cand[i]);
    kfree(cand);
    kfree(argv0_buf);
    return found;
}

pid_t find_pid_by_cmdline_ranked(const char *name)
{
    struct task_struct *t;
    struct task_struct **cand;
    char *argv0_buf;
    pid_t found = 0;
    int best_threads = -1;
    long best_rss = -1;
    size_t name_len;
    int cand_n = 0;
    int i;

    if (!name || !name[0])
        return 0;
    name_len = strnlen(name, ARGV0_MAX_BYTES);
    if (name_len == 0 || name_len >= ARGV0_MAX_BYTES)
        return 0;

    argv0_buf = nbg_kmalloc(ARGV0_MAX_BYTES, GFP_KERNEL);
    cand = nbg_kmalloc_array(ARGV0_SCAN_MAX_TASKS, sizeof(*cand), GFP_KERNEL);
    if (!argv0_buf || !cand) {
        kfree(argv0_buf);
        kfree(cand);
        return 0;
    }

    /* Reading argv[0] can take the target mmap lock, so retain group leaders
     * under RCU and inspect them after leaving the task list read-side. */
    rcu_read_lock();
    for_each_process(t) {
        if ((t->flags & PF_KTHREAD) || t != t->group_leader)
            continue;
        if (cand_n >= ARGV0_SCAN_MAX_TASKS)
            break;
        get_task_struct(t);
        cand[cand_n++] = t;
    }
    rcu_read_unlock();

    for (i = 0; i < cand_n; i++) {
        struct mm_struct *mm = get_task_mm(cand[i]);
        int n;

        if (!mm)
            continue;
        n = read_argv0(mm, argv0_buf, ARGV0_MAX_BYTES);
        if (n > 0 && strcmp(argv0_buf, name) == 0) {
            const int threads = get_nr_threads(cand[i]);
            const long rss = get_mm_rss(mm);
            const pid_t pid = cand[i]->tgid;
            if (threads > best_threads || (threads == best_threads && rss > best_rss) ||
                (threads == best_threads && rss == best_rss && (!found || pid > found))) {
                found = pid; best_threads = threads; best_rss = rss;
            }
        }
        mmput(mm);
    }

    for (i = 0; i < cand_n; i++)
        put_task_struct(cand[i]);
    kfree(cand);
    kfree(argv0_buf);
    return found;
}

pid_t find_pid_by_name(const char *name)
{
    struct task_struct *t;
    pid_t found = 0;
    size_t name_len;
    bool need_argv0;
    char *argv0_buf = NULL;
    /* 长名路径需要在锁外读 argv[0], 先把候选 task pin 进数组 */
    struct task_struct **cand = NULL;
    int cand_cap = 64, cand_n = 0, i;

    if (!name || !name[0])
        return 0;

    name_len = strnlen(name, ARGV0_MAX_BYTES);
    if (name_len == 0 || name_len >= ARGV0_MAX_BYTES)
        return 0;

    /*
     * task->comm 容量 TASK_COMM_LEN=16 (含 NUL), 实际可见 15 字符.
     * 名字超过 15 必须读 argv[0]. <=15 优先比 comm, 比不上再 fallback
     * argv[0] (有时进程会 prctl(PR_SET_NAME) 改 comm 但 argv[0] 仍是
     * 原可执行名).
     */
    need_argv0 = (name_len > 15);

    if (need_argv0) {
        argv0_buf = nbg_kmalloc(ARGV0_MAX_BYTES, GFP_KERNEL);
        if (!argv0_buf)
            return 0;
        cand = nbg_kmalloc_array(cand_cap, sizeof(*cand), GFP_KERNEL);
        if (!cand) {
            kfree(argv0_buf);
            return 0;
        }
    }

    /*
     * Phase 1: 在 RCU 锁里走 tasklist. 短名直接比 comm 命中即返回.
     * 长名路径只 pin 候选 (前缀 comm 匹配的 thread group leader),
     * 不在锁里调 read,避免页表读取和 get_task_mm/mmput 扩大 RCU 临界区.
     */
    rcu_read_lock();
    for_each_process(t) {
        if (t->flags & PF_KTHREAD)
            continue;

        if (!need_argv0) {
            if (strncmp(t->comm, name, sizeof(t->comm)) == 0 &&
                t->comm[name_len] == '\0') {
                found = t->tgid;
                break;
            }
            continue;
        }

        /* 长名: 前 15 字符 comm 前缀粗筛 */
        if (strncmp(t->comm, name, 15) != 0)
            continue;

        if (cand_n >= cand_cap)
            break;
        get_task_struct(t);
        cand[cand_n++] = t;
    }
    rcu_read_unlock();

    /* Phase 2: 锁外读 argv[0] 精确比对 */
    if (need_argv0 && !found) {
        for (i = 0; i < cand_n && !found; i++) {
            struct mm_struct *mm = get_task_mm(cand[i]);
            int n;
            if (!mm)
                continue;
            n = read_argv0(mm, argv0_buf, ARGV0_MAX_BYTES);
            mmput(mm);
            if (n <= 0)
                continue;
            if (argv0_name_matches(argv0_buf, name)) {
                found = cand[i]->tgid;
                break;
            }
        }
    }

    if (need_argv0) {
        for (i = 0; i < cand_n; i++)
            put_task_struct(cand[i]);
        kfree(cand);
        kfree(argv0_buf);
    }
    return found;
}
