/* hide_core.c — hide 子系统公共状态 + 总开关
 *
 * 这里管:
 *   - 动态符号(kern_path / path_put / d_drop)的 lazy 初始化
 *   - hidden_pids 列表(proc_name_is_hidden_pid / tgid_is_hidden)
 *   - auto_unhide_all:模块卸载时按依赖反向逐项关闭
 *
 * 模块自身隐藏、VMA maps 行隐藏、kprobes/list 隐藏、
 * dmesg/kmsg 日志过滤均不在默认加载路径启用。
 */
#include "hide_core.h"
#include "hide_kgsl.h"
#include "hide_internal.h"
#include "nbg_ksyms.h"
#include "nbg_compat.h"

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

static inline u32 hpid_hash(pid_t pid);

static bool hidden_pid_lookup_direct(pid_t pid)
{
    struct hidden_process *hp;
    bool found = false;

    if (pid <= 0 || hidden_pids_empty())
        return false;

    rcu_read_lock();
    hlist_for_each_entry_rcu(hp, &hidden_pids_ht[hpid_hash(pid)], hnode) {
        if (hp->pid == pid) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();
    return found;
}

/* ===================== 动态符号查找(供 hide_*.c 共用)===================== */

/* 不引入对 path_get/path_put 的直接重定位：部分 GKI 6.1 小分支不导出
 * 这两个符号，直接调用会生成 undefined symbol，导致 insmod 阶段失败。
 * 统一走 kallsyms 动态地址，保持所有目标只依赖 module_layout ABI。 */
kern_path_t  my_kern_path     = NULL;
path_get_t   my_path_get      = NULL;
path_put_t   my_path_put      = NULL;
d_drop_t     my_d_drop        = NULL;
d_invalidate_t my_d_invalidate = NULL;
lookup_one_len_unlocked_t my_lookup_one_len_unlocked = NULL;
d_rehash_t my_d_rehash = NULL;

int hide_init_path_functions(void)
{
    if (my_kern_path && my_path_get && my_path_put)
        return 0;

    my_kern_path = (kern_path_t)generic_kallsyms_lookup_name("kern_path");
    my_path_get  = (path_get_t)generic_kallsyms_lookup_name("path_get");
    my_path_put  = (path_put_t)generic_kallsyms_lookup_name("path_put");

    /* d_drop 在 GKI 6.6 被放进 VFS internal namespace,链接器拒掉,
     * 走 kallsyms 拿地址绕开命名空间限制。 */
    if (!my_d_drop)
        my_d_drop = (d_drop_t)generic_kallsyms_lookup_name("d_drop");
    if (!my_d_invalidate)
        my_d_invalidate = (d_invalidate_t)
            generic_kallsyms_lookup_name("d_invalidate");
    if (!my_lookup_one_len_unlocked)
        my_lookup_one_len_unlocked = (lookup_one_len_unlocked_t)
            generic_kallsyms_lookup_name("lookup_one_len_unlocked");
    if (!my_d_rehash)
        my_d_rehash = (d_rehash_t)generic_kallsyms_lookup_name("d_rehash");

    if (!my_kern_path || !my_path_get || !my_path_put)
        return -ENOSYS;
    return 0;
}

NBG_NO_CFI
struct dentry *nbg_lookup_one_len_unlocked(const char *name,
                                            struct dentry *parent,
                                            int len)
{
    if (!my_lookup_one_len_unlocked)
        my_lookup_one_len_unlocked = (lookup_one_len_unlocked_t)
            generic_kallsyms_lookup_name("lookup_one_len_unlocked");
    if (!my_lookup_one_len_unlocked)
        return ERR_PTR(-ENOSYS);
    return my_lookup_one_len_unlocked(name, parent, len);
}

NBG_NO_CFI
void nbg_dcache_rehash(struct dentry *dentry)
{
    if (!dentry)
        return;
    if (!my_d_rehash)
        my_d_rehash = (d_rehash_t)generic_kallsyms_lookup_name("d_rehash");
    if (my_d_rehash)
        my_d_rehash(dentry);
}

NBG_NO_CFI
void nbg_dcache_invalidate(struct dentry *dentry)
{
    if (!dentry)
        return;
    if (!my_d_invalidate)
        my_d_invalidate = (d_invalidate_t)
            generic_kallsyms_lookup_name("d_invalidate");
    if (my_d_invalidate)
        my_d_invalidate(dentry);

    /* d_invalidate() leaves a busy positive dentry hashed.  That is useful
     * for ordinary cache maintenance, but it lets a pathname such as a live
     * /dev/pts/N skip the parent lookup hook.  d_drop() only removes the
     * dcache entry; open references remain valid, and the next pathname walk
     * must resolve through the directory filter again. */
    if (!my_d_drop)
        my_d_drop = (d_drop_t)generic_kallsyms_lookup_name("d_drop");
    if (my_d_drop)
        my_d_drop(dentry);
}

/* ===================== hidden pid 表(哈希 + RCU)=====================
 *
 * 64-bucket hash table (HIDDEN_PIDS_HBITS=6),哈希函数:pid & 0x3F。
 * Android 同时隐藏的 pid 通常 1-8 个,典型 bucket 链长 0-1。
 *
 * 读路径(proc_name_is_hidden_pid / tgid_is_hidden):
 *   1. atomic_read(hidden_pid_count) 短路 → 0 时直接 return false
 *   2. rcu_read_lock + hlist_for_each_entry_rcu 遍历 1 个 bucket
 *   无锁,无禁中断,在 pid_revalidate kretprobe 这种全机热路径上几乎零开销。
 *
 * 写路径(hide_proc.c 的 add/remove):持 hidden_pids_lock spinlock,
 *   同步更新哈希表 + list_head + count。释放走 kfree_rcu 保证读端安全。 */

LIST_HEAD(hidden_pids);
DEFINE_SPINLOCK(hidden_pids_lock);
atomic_t hidden_pid_count = ATOMIC_INIT(0);
struct hlist_head hidden_pids_ht[1 << HIDDEN_PIDS_HBITS];

static inline u32 hpid_hash(pid_t pid)
{
    return ((u32)pid) & ((1U << HIDDEN_PIDS_HBITS) - 1);
}

bool proc_name_is_hidden_pid(const char *name, int namlen)
{
    pid_t pid = 0;
    int i;

    /* 短路:0 个隐藏 pid 时立刻返回,避免后续无谓的字符串解析。 */
    if (hidden_pids_empty())
        return false;

    /* 只对纯数字目录名感兴趣 */
    for (i = 0; i < namlen; i++) {
        if (name[i] < '0' || name[i] > '9')
            return false;
        pid = pid * 10 + (name[i] - '0');
    }
    if (pid == 0)
        return false;

    return hidden_pid_lookup_direct(pid);
}

bool tgid_is_hidden(pid_t tgid)
{
    if (tgid <= 0 || hidden_pids_empty())
        return false;

    return hidden_pid_lookup_direct(tgid);
}

/* hidden_pids 表的 add/remove 由 hide_proc.c 的 hide_process / unhide_process
 * 操作；cleanup 时 hide_core 兜底把表清空。 */

static void cleanup_all_hidden_processes(void)
{
    struct hidden_process *hp, *tmp;
    LIST_HEAD(local_list);
    unsigned long flags;

    spin_lock_irqsave(&hidden_pids_lock, flags);
    /* 一次性从全局表里摘下所有节点(list + 哈希双向移除) */
    list_splice_init(&hidden_pids, &local_list);
    list_for_each_entry(hp, &local_list, list)
        hlist_del_rcu(&hp->hnode);
    atomic_set(&hidden_pid_count, 0);
    spin_unlock_irqrestore(&hidden_pids_lock, flags);

    /* 等所有 RCU reader 退出,才能安全 free */
    synchronize_rcu();

    list_for_each_entry_safe(hp, tmp, &local_list, list) {
        list_del(&hp->list);
        if (hp->proc_dentry) {
            if (d_is_positive(hp->proc_dentry))
                nbg_dcache_rehash(hp->proc_dentry);
            dput(hp->proc_dentry);
            hp->proc_dentry = NULL;
        }
        kfree(hp);
    }
}


/* ===================== kretprobe 探测地址跟踪 =====================
 * /sys/kernel/debug/kprobes/list 会打印 kprobe 地址。模块隐藏相关
 * kretprobe 装好后记录地址，hide_module.c 用这些地址过滤列表。
 */
#define MAX_HIDDEN_KPROBE_ADDRS 32
static unsigned long hidden_kprobe_addrs[MAX_HIDDEN_KPROBE_ADDRS];
static int           hidden_kprobe_addr_count = 0;
static DEFINE_SPINLOCK(hidden_kprobe_addr_lock);

void track_hidden_kprobe_addr(unsigned long addr)
{
    unsigned long flags;
    int i;

    if (!addr) return;

    spin_lock_irqsave(&hidden_kprobe_addr_lock, flags);
    for (i = 0; i < hidden_kprobe_addr_count; i++) {
        if (hidden_kprobe_addrs[i] == addr) {
            spin_unlock_irqrestore(&hidden_kprobe_addr_lock, flags);
            return;
        }
    }
    if (hidden_kprobe_addr_count < MAX_HIDDEN_KPROBE_ADDRS)
        hidden_kprobe_addrs[hidden_kprobe_addr_count++] = addr;
    spin_unlock_irqrestore(&hidden_kprobe_addr_lock, flags);
}

void untrack_hidden_kprobe_addr(unsigned long addr)
{
    unsigned long flags;
    int i;

    if (!addr) return;

    spin_lock_irqsave(&hidden_kprobe_addr_lock, flags);
    for (i = 0; i < hidden_kprobe_addr_count; i++) {
        if (hidden_kprobe_addrs[i] == addr) {
            hidden_kprobe_addrs[i] =
                hidden_kprobe_addrs[--hidden_kprobe_addr_count];
            hidden_kprobe_addrs[hidden_kprobe_addr_count] = 0;
            break;
        }
    }
    spin_unlock_irqrestore(&hidden_kprobe_addr_lock, flags);
}

void track_hidden_kprobe(struct kretprobe *krp)
{
    if (krp)
        track_hidden_kprobe_addr((unsigned long)krp->kp.addr);
}

void untrack_hidden_kprobe(struct kretprobe *krp)
{
    if (krp)
        untrack_hidden_kprobe_addr((unsigned long)krp->kp.addr);
}

int hide_kprobe_addr_count(void)
{
    int n;
    unsigned long flags;
    spin_lock_irqsave(&hidden_kprobe_addr_lock, flags);
    n = hidden_kprobe_addr_count;
    spin_unlock_irqrestore(&hidden_kprobe_addr_lock, flags);
    return n;
}

unsigned long hide_kprobe_addr_at(int i)
{
    unsigned long v = 0, flags;
    spin_lock_irqsave(&hidden_kprobe_addr_lock, flags);
    if (i >= 0 && i < hidden_kprobe_addr_count)
        v = hidden_kprobe_addrs[i];
    spin_unlock_irqrestore(&hidden_kprobe_addr_lock, flags);
    return v;
}

int ks_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ks_kretprobe_data *d = (struct ks_kretprobe_data *)ri->data;
    d->m      = (struct seq_file *)regs->regs[0];
    d->before = d->m ? d->m->count : 0;
    return 0;
}

/* ===================== 用户会话运行期清理 =====================
 *
 * 用户态辅助被后台杀掉时不会走正常 unhide/delete 流程。这里只清理
 * 每次会话临时产生的状态：隐藏 pid、隐藏文件、KGSL 过滤等。
 */
void hide_cleanup_runtime_state(void)
{
    hide_kgsl_cleanup();
    cleanup_all_hidden_processes();
    remove_proc_hook();
    synchronize_rcu();
}

/* ===================== 总卸载入口 ===================== */
void auto_unhide_all(pid_t pid)
{
    (void)pid;
    hide_kgsl_cleanup();
    remove_proc_hook();
    cleanup_all_hooks();
    cleanup_all_hidden_processes();
    synchronize_rcu();
}
