/* hide_module.c — 内核侧模块可见性隐藏
 *
 * 五件事,合一处方便维护:
 *
 *   1. /proc/kallsyms 过滤 — kallsyms_op->show kretprobe,行内含 "[modname]"
 *      就回滚 m->count 把这条丢掉
 *   2. /proc/modules 过滤 — modules_op->show kretprobe,行首是 modname 就丢
 *   3. struct module 链表脱链 — 把 THIS_MODULE 从全局 'modules' 链表
 *      list_del_rcu,/proc/modules、find_module 都看不到我们
 *   4. mod_tree 隐藏 — 仅过滤 __module_text_address。
 *      __module_address 必须保留，内核靠它查找模块 __ex_table。
 *      认不出我们的代码
 *   5. /sys/kernel/debug/kprobes/list 过滤 — show_kprobe_addr kretprobe,
 *      行内含我们任意已注册 kretprobe 的地址(hex)就丢
 *
 * 全部用 kretprobe 而非直接改 seq_operations:GKI 6.6 把 ops 放进 .rodata,
 * 直接 WRITE_ONCE 会 panic;走 kprobe 内部基础设施(可写内存)安全。
 *
 * 共享 helper:ks_entry / struct ks_kretprobe_data 在 hide_internal.h。
 */
#include "hide_module.h"
#include "hide_internal.h"
#include "nbg_ksyms.h"
#include "nbg_log.h"

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include "nbg_alloc.h"
#include <linux/mutex.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/string.h>
#include <asm/ptrace.h>

/* ===================== 模块名黑名单(kallsyms / proc_modules 共用) ===================== */

struct ks_mod_entry {
    char name[64];
    struct list_head list;
};

static LIST_HEAD(ks_hidden_mods);
static DEFINE_SPINLOCK(ks_lock);

static const char * const nbg_hidden_line_words[] = {
    "NBG",
    "nbg_",
    "qti_rawnet",
    "qti_syncd",
    "net_rawx",
    "rwProcMem",
    "rwProcMem33",
    "rwProcMem37",
    "perfMast",
    "KernelSU",
    "kernelsu",
    "magisk",
    "susfs",
    "chksum",
    "checksum",
    "cksum",
    NULL,
};

static bool nbg_hidden_line_has_word(const char *line, size_t len)
{
    int i;

    if (!line || !len)
        return false;
    for (i = 0; nbg_hidden_line_words[i]; i++) {
        if (strnstr(line, nbg_hidden_line_words[i], len))
            return true;
    }
    return false;
}

/* ===================== /proc/kallsyms 过滤 ===================== */

static struct kretprobe ks_krp;
static bool ks_hooked = false;
static DEFINE_MUTEX(ks_hook_lock);

static int ks_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ks_kretprobe_data *d = (struct ks_kretprobe_data *)ri->data;
    struct ks_mod_entry *entry;
    unsigned long flags;
    int ret;

    if (!d->m || d->m->count == d->before)
        return 0;
    ret = (int)regs->regs[0];
    if (ret != 0)
        return 0;

    spin_lock_irqsave(&ks_lock, flags);
    list_for_each_entry(entry, &ks_hidden_mods, list) {
        char bracket[66];
        snprintf(bracket, sizeof(bracket), "[%s]", entry->name);
        if (strnstr(d->m->buf + d->before, bracket, d->m->count - d->before)) {
            d->m->count = d->before;
            spin_unlock_irqrestore(&ks_lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&ks_lock, flags);
    if (nbg_hidden_line_has_word(d->m->buf + d->before,
                                 d->m->count - d->before))
        d->m->count = d->before;
    return 0;
}

static int kallsyms_install_hook(void)
{
    struct seq_operations *ops;
    unsigned long show_addr;
    int ret;

    mutex_lock(&ks_hook_lock);
    if (ks_hooked) {
        mutex_unlock(&ks_hook_lock);
        return 0;
    }

    {
        static const char * const ops_cands[] = {
            "kallsyms_op", "kallsyms_seq_ops", NULL
        };
        ops = (struct seq_operations *)resolve_first_symbol(ops_cands);
    }
    if (!ops) {
        NBG_FAIL_CODE(1201, -ENODEV);
        mutex_unlock(&ks_hook_lock);
        return -ENODEV;
    }

    /* 只读 ops->show 取地址,不写入 seq_operations(rodata 保护) */
    show_addr = (unsigned long)READ_ONCE(ops->show);
    if (!show_addr) {
        NBG_FAIL_CODE(1202, -ENODEV);
        mutex_unlock(&ks_hook_lock);
        return -ENODEV;
    }

    memset(&ks_krp, 0, sizeof(ks_krp));
    ks_krp.entry_handler  = ks_entry;
    ks_krp.handler        = ks_ret;
    ks_krp.data_size      = sizeof(struct ks_kretprobe_data);
    ks_krp.maxactive      = max(num_possible_cpus() * 4, 64U);

    ret = nbg_register_kretprobe_addr(&ks_krp, show_addr);
    if (ret) {
        NBG_FAIL_CODE(1203, ret);
        mutex_unlock(&ks_hook_lock);
        return ret;
    }
    track_hidden_kprobe(&ks_krp);
    ks_hooked = true;
    mutex_unlock(&ks_hook_lock);
    return 0;
}

void kallsyms_hide_cleanup(void)
{
    struct ks_mod_entry *e, *tmp;

    mutex_lock(&ks_hook_lock);
    if (ks_hooked) {
        untrack_hidden_kprobe(&ks_krp);
        unregister_kretprobe(&ks_krp);
        ks_hooked = false;
    }
    mutex_unlock(&ks_hook_lock);

    spin_lock(&ks_lock);
    list_for_each_entry_safe(e, tmp, &ks_hidden_mods, list) {
        list_del(&e->list);
        kfree(e);
    }
    spin_unlock(&ks_lock);
}

int kallsyms_hide_module(const char *modname)
{
    struct ks_mod_entry *e, *new_e;
    unsigned long flags;

    if (!modname || strlen(modname) == 0 || strlen(modname) >= 64)
    {
        NBG_FAIL_CODE(1204, -EINVAL);
        return -EINVAL;
    }

    new_e = nbg_kmalloc(sizeof(*new_e), GFP_KERNEL);
    if (!new_e) {
        NBG_FAIL_CODE(1205, -ENOMEM);
        return -ENOMEM;
    }
    strncpy(new_e->name, modname, 63);
    new_e->name[63] = '\0';

    spin_lock_irqsave(&ks_lock, flags);
    list_for_each_entry(e, &ks_hidden_mods, list) {
        if (strcmp(e->name, modname) == 0) {
            spin_unlock_irqrestore(&ks_lock, flags);
            kfree(new_e);
            return 0;
        }
    }
    list_add(&new_e->list, &ks_hidden_mods);
    spin_unlock_irqrestore(&ks_lock, flags);

    return kallsyms_install_hook();
}

/* ===================== /proc/modules 过滤 ===================== */

static struct kretprobe pm_krp;
static bool pm_hooked = false;
static DEFINE_MUTEX(pm_hook_lock);

static int pm_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ks_kretprobe_data *d = (struct ks_kretprobe_data *)ri->data;
    struct ks_mod_entry *entry;
    unsigned long flags;
    int ret;

    if (!d->m || d->m->count == d->before)
        return 0;
    ret = (int)regs->regs[0];
    if (ret != 0)
        return 0;

    spin_lock_irqsave(&ks_lock, flags);
    list_for_each_entry(entry, &ks_hidden_mods, list) {
        size_t nlen = strlen(entry->name);
        const char *line = d->m->buf + d->before;
        size_t llen = d->m->count - d->before;
        if (llen >= nlen &&
            strncmp(line, entry->name, nlen) == 0 &&
            (line[nlen] == ' ' || line[nlen] == '\n')) {
            d->m->count = d->before;
            spin_unlock_irqrestore(&ks_lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&ks_lock, flags);
    if (nbg_hidden_line_has_word(d->m->buf + d->before,
                                 d->m->count - d->before))
        d->m->count = d->before;
    return 0;
}

int proc_modules_hide_install(void)
{
    struct seq_operations *ops;
    unsigned long show_addr;
    int ret;

    mutex_lock(&pm_hook_lock);
    if (pm_hooked) {
        mutex_unlock(&pm_hook_lock);
        return 0;
    }

    {
        static const char * const ops_cands[] = {
            "modules_op", "modules_seq_ops", NULL
        };
        ops = (struct seq_operations *)resolve_first_symbol(ops_cands);
    }
    if (!ops) {
        NBG_FAIL_CODE(1211, -ENODEV);
        mutex_unlock(&pm_hook_lock);
        return -ENODEV;
    }

    show_addr = (unsigned long)READ_ONCE(ops->show);
    if (!show_addr) {
        NBG_FAIL_CODE(1212, -ENODEV);
        mutex_unlock(&pm_hook_lock);
        return -ENODEV;
    }

    memset(&pm_krp, 0, sizeof(pm_krp));
    pm_krp.entry_handler   = ks_entry;
    pm_krp.handler         = pm_ret;
    pm_krp.data_size       = sizeof(struct ks_kretprobe_data);
    pm_krp.maxactive       = max(num_possible_cpus() * 4, 64U);

    ret = nbg_register_kretprobe_addr(&pm_krp, show_addr);
    if (ret) {
        NBG_FAIL_CODE(1213, ret);
        mutex_unlock(&pm_hook_lock);
        return ret;
    }
    track_hidden_kprobe(&pm_krp);
    pm_hooked = true;
    mutex_unlock(&pm_hook_lock);
    return 0;
}

void proc_modules_hide_cleanup(void)
{
    mutex_lock(&pm_hook_lock);
    if (pm_hooked) {
        untrack_hidden_kprobe(&pm_krp);
        unregister_kretprobe(&pm_krp);
        pm_hooked = false;
    }
    mutex_unlock(&pm_hook_lock);
}

/* ===================== struct module 全局链表脱链 =====================
 *
 * /proc/modules、find_module、list_for_each_entry(&modules) 都靠这条
 * 链表。把 THIS_MODULE 从链表 list_del_rcu,但不动 mod_tree(动了会
 * 影响 oops 回溯 + 自家 kretprobe 的地址反查)。
 *
 * 卸载前必须把自己加回链表:free_module 内的 list_del_rcu 在 LIST_POISON
 * 头上会 panic。
 */

struct list_head *modules_list_head = NULL;
struct mutex     *module_mutex_ptr  = NULL;
static bool module_list_hidden = false;
static DEFINE_MUTEX(module_list_hide_lock);

static int init_module_list_symbols(void)
{
    if (modules_list_head && module_mutex_ptr)
        return 0;
    if (!modules_list_head)
        modules_list_head = (struct list_head *)
            generic_kallsyms_lookup_name("modules");
    if (!module_mutex_ptr)
        module_mutex_ptr = (struct mutex *)
            generic_kallsyms_lookup_name("module_mutex");
    if (!modules_list_head || !module_mutex_ptr)
        return -ENOSYS;
    return 0;
}

int module_list_hide(void)
{
    int ret;

    mutex_lock(&module_list_hide_lock);
    if (module_list_hidden) {
        mutex_unlock(&module_list_hide_lock);
        return 0;
    }

    ret = init_module_list_symbols();
    if (ret) {
        NBG_FAIL_CODE(1221, ret);
        mutex_unlock(&module_list_hide_lock);
        return ret;
    }

    mutex_lock(module_mutex_ptr);
    list_del_rcu(&THIS_MODULE->list);
    mutex_unlock(module_mutex_ptr);

    synchronize_rcu();      /* 等读者放手 */

    module_list_hidden = true;
    mutex_unlock(&module_list_hide_lock);
    return 0;
}

void module_list_unhide(void)
{
    mutex_lock(&module_list_hide_lock);
    if (!module_list_hidden) {
        mutex_unlock(&module_list_hide_lock);
        return;
    }

    if (modules_list_head && module_mutex_ptr) {
        mutex_lock(module_mutex_ptr);
        list_add_tail_rcu(&THIS_MODULE->list, modules_list_head);
        mutex_unlock(module_mutex_ptr);
    }

    module_list_hidden = false;
    mutex_unlock(&module_list_hide_lock);
}

/* ===================== mod_tree 隐藏(__module_address kretprobe)===================== */

static struct kretprobe mta_krp;
static bool mta_hooked = false;
static DEFINE_MUTEX(mod_tree_hide_lock);

/* 任何反查"地址 → 所属 module"的内核路径都过这里;命中我们就改写 x0=0 */
static int mod_addr_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct module *m = (struct module *)regs_return_value(regs);
    if (m == THIS_MODULE)
        regs_set_return_value(regs, 0);
    return 0;
}

int mod_tree_hide_install(void)
{
    int ret;

    mutex_lock(&mod_tree_hide_lock);

    if (!mta_hooked) {
        static const char * const cands[] = { "__module_text_address", NULL };
        memset(&mta_krp, 0, sizeof(mta_krp));
        mta_krp.handler        = mod_addr_ret;
        mta_krp.maxactive      = max(num_possible_cpus() * 4, 64U);
        ret = nbg_register_kretprobe_named(&mta_krp, cands, NULL);
        if (ret == 0) {
            mta_hooked = true;
            track_hidden_kprobe(&mta_krp);
        }
    }

    mutex_unlock(&mod_tree_hide_lock);
    ret = mta_hooked ? 0 : -ENODEV;
    NBG_FAIL_CODE(1231, ret);
    return ret;
}

void mod_tree_hide_cleanup(void)
{
    mutex_lock(&mod_tree_hide_lock);
    if (mta_hooked) {
        untrack_hidden_kprobe(&mta_krp);
        unregister_kretprobe(&mta_krp);
        mta_hooked = false;
    }
    mutex_unlock(&mod_tree_hide_lock);
}

/* ===================== /sys/kernel/debug/kprobes/list 过滤 =====================
 *
 * 命中条件:刚写入的行包含我们任意已注册 kretprobe 的探测地址(hex)。
 */

static struct kretprobe kp_list_krp;
static bool kp_list_hooked = false;
static DEFINE_MUTEX(kp_list_hook_lock);

static int kp_list_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ks_kretprobe_data *d = (struct ks_kretprobe_data *)ri->data;
    char *line;
    size_t len;
    int i, count;

    if (!d->m || d->m->count == d->before)
        return 0;

    line = d->m->buf + d->before;
    len  = d->m->count - d->before;

    count = hide_kprobe_addr_count();
    if (nbg_hidden_line_has_word(line, len)) {
        d->m->count = d->before;
        return 0;
    }
    for (i = 0; i < count; i++) {
        char hex[20];
        snprintf(hex, sizeof(hex), "%lx", hide_kprobe_addr_at(i));
        if (strnstr(line, hex, len)) {
            d->m->count = d->before;
            return 0;
        }
    }
    return 0;
}

int kprobes_list_hide_install(void)
{
    unsigned long show_addr;
    int ret;

    mutex_lock(&kp_list_hook_lock);
    if (kp_list_hooked) {
        mutex_unlock(&kp_list_hook_lock);
        return 0;
    }

    {
        static const char * const cands[] = { "show_kprobe_addr", NULL };
        show_addr = resolve_first_symbol(cands);
    }
    if (!show_addr) {
        NBG_FAIL_CODE(1241, -ENODEV);
        mutex_unlock(&kp_list_hook_lock);
        return -ENODEV;
    }

    memset(&kp_list_krp, 0, sizeof(kp_list_krp));
    kp_list_krp.entry_handler = ks_entry;       /* 复用:仅记录 m+count */
    kp_list_krp.handler       = kp_list_ret;
    kp_list_krp.data_size     = sizeof(struct ks_kretprobe_data);
    kp_list_krp.maxactive     = max(num_possible_cpus() * 4, 64U);

    ret = nbg_register_kretprobe_addr(&kp_list_krp, show_addr);
    if (ret) {
        NBG_FAIL_CODE(1242, ret);
        mutex_unlock(&kp_list_hook_lock);
        return ret;
    }
    /* 把 show_kprobe_addr 自己也加进隐藏地址表,防自爆 */
    track_hidden_kprobe(&kp_list_krp);
    kp_list_hooked = true;
    mutex_unlock(&kp_list_hook_lock);
    return 0;
}

/* ===================== /proc/net/protocols 过滤 ===================== */
static struct kretprobe proto_krp;
static bool proto_hooked = false;
static DEFINE_MUTEX(proto_hook_lock);

static int proto_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ks_kretprobe_data *d = (struct ks_kretprobe_data *)ri->data;
    const char *line;
    size_t len;
    int ret;

    if (!d->m || d->m->count == d->before)
        return 0;
    ret = (int)regs->regs[0];
    if (ret != 0)
        return 0;

    line = d->m->buf + d->before;
    len = d->m->count - d->before;
    if (strnstr(line, "net_rawx", len) ||
        strnstr(line, THIS_MODULE->name, len) ||
        nbg_hidden_line_has_word(line, len)) {
        d->m->count = d->before;
    }
    return 0;
}

int net_protocols_hide_install(void)
{
    int ret;
    static const char * const cands[] = { "proto_seq_show", NULL };

    mutex_lock(&proto_hook_lock);
    if (proto_hooked) {
        mutex_unlock(&proto_hook_lock);
        return 0;
    }

    memset(&proto_krp, 0, sizeof(proto_krp));
    proto_krp.entry_handler = ks_entry;
    proto_krp.handler = proto_ret;
    proto_krp.data_size = sizeof(struct ks_kretprobe_data);
    proto_krp.maxactive = max(num_possible_cpus() * 4, 64U);

    ret = nbg_register_kretprobe_named(&proto_krp, cands, NULL);
    if (ret == 0) {
        proto_hooked = true;
        track_hidden_kprobe(&proto_krp);
    }
    mutex_unlock(&proto_hook_lock);
    return ret;
}

void net_protocols_hide_cleanup(void)
{
    mutex_lock(&proto_hook_lock);
    if (proto_hooked) {
        untrack_hidden_kprobe(&proto_krp);
        unregister_kretprobe(&proto_krp);
        proto_hooked = false;
    }
    mutex_unlock(&proto_hook_lock);
}

void kprobes_list_hide_cleanup(void)
{
    mutex_lock(&kp_list_hook_lock);
    if (kp_list_hooked) {
        untrack_hidden_kprobe(&kp_list_krp);
        unregister_kretprobe(&kp_list_krp);
        kp_list_hooked = false;
    }
    mutex_unlock(&kp_list_hook_lock);
}
