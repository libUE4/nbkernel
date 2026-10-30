/* hide_kgsl.c - Qualcomm KGSL GPU sysfs/debugfs node hiding
 *
 * Qualcomm KGSL creates per-process nodes under paths such as:
 *   /sys/class/kgsl/kgsl-3d0/proc/<pid>/
 *   /sys/kernel/debug/kgsl/proc/<pid>/
 *
 * This module has two jobs:
 *   1. Intercept later node creation through kprobes.
 *   2. Remove already-created nodes for hidden pids through kernfs.
 */
#include "hide_kgsl.h"
#include "hide_file.h"
#include "hide_internal.h"
#include "nbg_ksyms.h"
#include "nbg_compat.h"

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernfs.h>
#include <linux/kobject.h>
#include <linux/kprobes.h>
#include <linux/magic.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <asm/ptrace.h>

static bool kobj_under_kgsl(struct kobject *kobj)
{
    struct kobject *p;
    int depth = 0;

    for (p = kobj; p && depth < 8; p = p->parent, depth++) {
        if (p->name && strstr(p->name, "kgsl"))
            return true;
    }
    return false;
}

static void skip_and_return_enomem(struct pt_regs *regs)
{
    regs_set_return_value(regs, (unsigned long)-ENOMEM);
    instruction_pointer_set(regs, procedure_link_pointer(regs));
}

typedef int (*kernfs_remove_by_name_ns_t)(struct kernfs_node *, const char *, const void *);
static kernfs_remove_by_name_ns_t my_kernfs_remove_by_name_ns;

NBG_NO_CFI
static void remove_existing_kgsl_node(pid_t pid)
{
    struct path parent_path;
    struct kernfs_node *parent_kn;
    char pid_str[16];
    char debug_path[64];
    int ret;

    if (pid <= 0)
        return;

    if (!my_kernfs_remove_by_name_ns)
        my_kernfs_remove_by_name_ns = (kernfs_remove_by_name_ns_t)
            generic_kallsyms_lookup_name("kernfs_remove_by_name_ns");
    if (!my_kernfs_remove_by_name_ns)
        return;

    if (!my_kern_path && hide_init_path_functions())
        return;
    if (!my_kern_path || !my_path_put)
        return;

    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    ret = my_kern_path("/sys/class/kgsl/kgsl-3d0/proc",
                       LOOKUP_DIRECTORY, &parent_path);
    if (ret == 0) {
        parent_kn = NULL;
        if (parent_path.dentry && parent_path.dentry->d_inode &&
            parent_path.dentry->d_inode->i_sb &&
            parent_path.dentry->d_inode->i_sb->s_magic == SYSFS_MAGIC)
            parent_kn = parent_path.dentry->d_inode->i_private;
        if (parent_kn)
            my_kernfs_remove_by_name_ns(parent_kn, pid_str, NULL);
        my_path_put(&parent_path);
    }

    /*
     * debugfs 不是 kernfs，inode->i_private 不是 struct kernfs_node。
     * 这里不把 debugfs 指针传给 kernfs_remove_by_name_ns；已有 debugfs
     * 节点走 VFS 隐藏，新建节点由 kprobe 拦截。
     */
    snprintf(debug_path, sizeof(debug_path),
             "/sys/kernel/debug/kgsl/proc/%d", pid);
    (void)hide_file(debug_path);
}

static int kgsl_sysfs_pre(struct kprobe *p, struct pt_regs *regs)
{
    if (tgid_is_hidden(current->tgid)) {
        skip_and_return_enomem(regs);
        return 1;
    }
    return 0;
}

static int kgsl_debugfs_pre(struct kprobe *p, struct pt_regs *regs)
{
    if (tgid_is_hidden(current->tgid)) {
        skip_and_return_enomem(regs);
        return 1;
    }
    return 0;
}

static int sysfs_create_group_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct kobject *kobj = (struct kobject *)regs->regs[0];

    if (!kobj || !kobj->name)
        return 0;
    if (!kobj_under_kgsl(kobj))
        return 0;
    if (tgid_is_hidden(current->tgid)) {
        skip_and_return_enomem(regs);
        return 1;
    }
    return 0;
}

static struct kprobe kp_sysfs;
static struct kprobe kp_debugfs;
static struct kprobe kp_sysfs_group;

static bool kp_sysfs_installed;
static bool kp_debugfs_installed;
static bool kp_sysfs_group_installed;
static DEFINE_MUTEX(kgsl_hide_lock);

static int install_kgsl_kprobe(struct kprobe *kp,
                               const char * const *names,
                               kprobe_pre_handler_t handler)
{
    memset(kp, 0, sizeof(*kp));
    kp->pre_handler = handler;
    return nbg_register_kprobe_named(kp, names, NULL);
}

bool hide_kgsl_available(void)
{
    static const char * const cands[] = {
        "kgsl_process_init_sysfs", NULL
    };

    return resolve_first_symbol(cands) != 0;
}

int hide_kgsl_install(void)
{
    int ret;

    mutex_lock(&kgsl_hide_lock);

    if (!kp_sysfs_installed) {
        static const char * const cands[] = {
            "kgsl_process_init_sysfs", NULL
        };

        ret = install_kgsl_kprobe(&kp_sysfs, cands, kgsl_sysfs_pre);
        if (ret == 0)
            kp_sysfs_installed = true;
    }

    if (!kp_debugfs_installed) {
        static const char * const cands[] = {
            "kgsl_process_init_debugfs", NULL
        };

        ret = install_kgsl_kprobe(&kp_debugfs, cands, kgsl_debugfs_pre);
        if (ret == 0)
            kp_debugfs_installed = true;
    }

    if (!kp_sysfs_group_installed) {
        static const char * const cands[] = {
            "sysfs_create_group", "sysfs_create_group_kn", NULL
        };

        ret = install_kgsl_kprobe(&kp_sysfs_group, cands,
                                  sysfs_create_group_pre);
        if (ret == 0)
            kp_sysfs_group_installed = true;
    }

    mutex_unlock(&kgsl_hide_lock);

    return (kp_sysfs_installed || kp_debugfs_installed) ? 0 : -ENODEV;
}

void hide_kgsl_remove_pid(pid_t pid)
{
    remove_existing_kgsl_node(pid);
}

void hide_kgsl_restore_pid(pid_t pid)
{
    char debug_path[64];

    if (pid <= 0)
        return;
    snprintf(debug_path, sizeof(debug_path),
             "/sys/kernel/debug/kgsl/proc/%d", pid);
    (void)unhide_file(debug_path);
}

void hide_kgsl_cleanup(void)
{
    mutex_lock(&kgsl_hide_lock);

    if (kp_sysfs_group_installed) {
        nbg_unregister_kprobe(&kp_sysfs_group);
        kp_sysfs_group_installed = false;
    }
    if (kp_debugfs_installed) {
        nbg_unregister_kprobe(&kp_debugfs);
        kp_debugfs_installed = false;
    }
    if (kp_sysfs_installed) {
        nbg_unregister_kprobe(&kp_sysfs);
        kp_sysfs_installed = false;
    }

    mutex_unlock(&kgsl_hide_lock);
}
