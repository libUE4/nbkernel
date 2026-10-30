/* devpts_filter.c - PID-scoped /dev/pts visibility policy
 *
 * The filter only changes probe-facing access(2) and newfstatat(2) results.
 * Normal open/read/write permission checks keep their kernel semantics so a
 * game render or IPC path cannot be turned into a synthetic missing device.
 *
 * The hooks are armed when the module loads. Before userspace supplies a
 * session PID, package identity scopes the view to the game; after cleanup
 * the filter returns to that automatic state.
 */
#include <linux/atomic.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/magic.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <asm/ptrace.h>

#include "devpts_filter.h"
#include "nbg_alloc.h"
#include "nbg_ksyms.h"
#include "nbg_target.h"

#define NBG_DEVPTS_PATH_PREFIX     "/dev/pts"
#define NBG_DEVPTS_PATH_PREFIX_LEN (sizeof(NBG_DEVPTS_PATH_PREFIX) - 1)
#define NBG_DEVPTS_SLAVE_MAJOR     136U

struct devpts_filter_state {
    pid_t tgid;
    u32 max_index;
};

static DEFINE_MUTEX(devpts_filter_lock);
static struct devpts_filter_state __rcu *devpts_filter_state;
static bool devpts_permission_hook_active;
static bool devpts_getattr_hook_active;
static atomic64_t devpts_permission_hits = ATOMIC64_INIT(0);
static atomic64_t devpts_getattr_hits = ATOMIC64_INIT(0);

static struct devpts_filter_state *devpts_filter_alloc_state(pid_t tgid,
                                                              u32 max_index)
{
    struct devpts_filter_state *state;

    state = nbg_kzalloc(sizeof(*state), GFP_KERNEL);
    if (!state)
        return NULL;
    state->tgid = tgid;
    state->max_index = max_index;
    return state;
}

static bool devpts_filter_current_max_index(u32 *max_index)
{
    const struct devpts_filter_state *state;
    bool match = false;
    u32 max = 0;

    if (!nbg_target_current_is_game())
        return false;

    rcu_read_lock();
    state = rcu_dereference(devpts_filter_state);
    if (state) {
        max = state->max_index;
        match = true;
    }
    rcu_read_unlock();

    if (match && max_index)
        *max_index = max;
    return match;
}

static bool devpts_filter_matches_inode(const struct inode *inode)
{
    u32 max_index;

    if (!inode || !inode->i_sb || !S_ISCHR(inode->i_mode) ||
        inode->i_sb->s_magic != DEVPTS_SUPER_MAGIC ||
        imajor(inode) != NBG_DEVPTS_SLAVE_MAJOR)
        return false;

    return devpts_filter_current_max_index(&max_index) &&
           iminor(inode) <= max_index;
}

static int devpts_filter_return_enoent(struct pt_regs *regs)
{
    regs_set_return_value(regs, (unsigned long)-ENOENT);
    instruction_pointer_set(regs, procedure_link_pointer(regs));
    return 1;
}

static int devpts_filter_permission_pre(struct kprobe *kp,
                                        struct pt_regs *regs)
{
    struct inode *inode;
    int mask;

    (void)kp;
    inode = (struct inode *)(unsigned long)regs->regs[0];
    mask = (int)regs->regs[1];
    if (!(mask & MAY_ACCESS) || !devpts_filter_matches_inode(inode))
        return 0;

    atomic64_inc(&devpts_permission_hits);
    return devpts_filter_return_enoent(regs);
}

static int devpts_filter_getattr_pre(struct kprobe *kp,
                                     struct pt_regs *regs)
{
    const struct path *path;
    struct inode *inode;

    (void)kp;
    path = (const struct path *)(unsigned long)regs->regs[0];
    if (!path || !path->dentry)
        return 0;

    inode = d_backing_inode(path->dentry);
    if (!devpts_filter_matches_inode(inode))
        return 0;

    atomic64_inc(&devpts_getattr_hits);
    return devpts_filter_return_enoent(regs);
}

static struct kprobe devpts_permission_kp;
static struct kprobe devpts_getattr_kp;

static const char * const devpts_permission_cands[] = {
    "security_inode_permission", NULL,
};

static const char * const devpts_getattr_cands[] = {
    "security_inode_getattr", NULL,
};

static void devpts_filter_unregister_hooks_locked(void)
{
    if (devpts_getattr_hook_active) {
        nbg_unregister_kprobe(&devpts_getattr_kp);
        devpts_getattr_hook_active = false;
    }
    if (devpts_permission_hook_active) {
        nbg_unregister_kprobe(&devpts_permission_kp);
        devpts_permission_hook_active = false;
    }
}

static int devpts_filter_register_hooks_locked(void)
{
    int ret;

    if (devpts_permission_hook_active && devpts_getattr_hook_active)
        return 0;

    devpts_filter_unregister_hooks_locked();

    memset(&devpts_permission_kp, 0, sizeof(devpts_permission_kp));
    devpts_permission_kp.pre_handler = devpts_filter_permission_pre;
    ret = nbg_register_kprobe_named(&devpts_permission_kp,
                                    devpts_permission_cands, NULL);
    if (ret)
        return ret;
    devpts_permission_hook_active = true;

    memset(&devpts_getattr_kp, 0, sizeof(devpts_getattr_kp));
    devpts_getattr_kp.pre_handler = devpts_filter_getattr_pre;
    ret = nbg_register_kprobe_named(&devpts_getattr_kp,
                                    devpts_getattr_cands, NULL);
    if (ret) {
        devpts_filter_unregister_hooks_locked();
        return ret;
    }
    devpts_getattr_hook_active = true;
    return 0;
}

static bool devpts_filter_path_matches_max(const char *path, u32 max_index)
{
    const char *p;
    u32 index = 0;

    if (!path || strncmp(path, NBG_DEVPTS_PATH_PREFIX,
                         NBG_DEVPTS_PATH_PREFIX_LEN) != 0)
        return false;

    p = path + NBG_DEVPTS_PATH_PREFIX_LEN;
    if (*p == '\0' || *p++ != '/' || *p == '\0')
        return false;

    for (; *p; p++) {
        u32 digit;

        if (*p < '0' || *p > '9')
            return false;
        digit = (u32)(*p - '0');
        if (index > max_index / 10 ||
            (index == max_index / 10 && digit > max_index % 10))
            return false;
        index = index * 10 + digit;
    }

    return true;
}

bool devpts_filter_current_is_active(void)
{
    return devpts_filter_current_max_index(NULL);
}

bool devpts_filter_path_hidden_for_current(const char *path)
{
    u32 max_index;
    bool hidden;

    hidden = devpts_filter_current_max_index(&max_index) &&
             devpts_filter_path_matches_max(path, max_index);
    if (hidden)
        devpts_filter_note_getattr_hit();
    return hidden;
}

void devpts_filter_note_permission_hit(void)
{
    atomic64_inc(&devpts_permission_hits);
}

void devpts_filter_note_getattr_hit(void)
{
    atomic64_inc(&devpts_getattr_hits);
}

static void devpts_filter_fill_status_locked(DevptsFilterReq *req)
{
    const struct devpts_filter_state *state;

    state = rcu_dereference_protected(devpts_filter_state,
                                      lockdep_is_held(&devpts_filter_lock));
    req->enabled = state && devpts_permission_hook_active &&
                   devpts_getattr_hook_active;
    /* Automatic discovery binds the target outside this state object; expose
     * that TGID through the existing query ABI until userspace supplies its
     * own explicit session binding. */
    req->pid = state ? (state->tgid ? state->tgid : nbg_target_bound_pid()) : 0;
    req->max_index = state ? state->max_index : 0;
    req->permission_hits = atomic64_read(&devpts_permission_hits);
    req->getattr_hits = atomic64_read(&devpts_getattr_hits);
}

int devpts_filter_install(void)
{
    struct devpts_filter_state *new_state;
    int ret;

    new_state = devpts_filter_alloc_state(0, NBG_DEVPTS_FILTER_MAX_INDEX);
    if (!new_state)
        return -ENOMEM;

    mutex_lock(&devpts_filter_lock);
    if (rcu_access_pointer(devpts_filter_state)) {
        mutex_unlock(&devpts_filter_lock);
        kfree(new_state);
        return 0;
    }

    ret = devpts_filter_register_hooks_locked();
    if (!ret)
        ret = nbg_target_auto_start();
    if (!ret) {
        rcu_assign_pointer(devpts_filter_state, new_state);
        new_state = NULL;
        atomic64_set(&devpts_permission_hits, 0);
        atomic64_set(&devpts_getattr_hits, 0);
    } else {
        nbg_target_auto_stop();
        devpts_filter_unregister_hooks_locked();
    }
    mutex_unlock(&devpts_filter_lock);

    kfree(new_state);
    return ret;
}

int devpts_filter_configure(DevptsFilterReq *req)
{
    struct devpts_filter_state *new_state = NULL;
    struct devpts_filter_state *old_state;
    const bool bind_target = req && req->enabled == NBG_DEVPTS_FILTER_ENABLE;
    int ret = 0;

    if (!req || req->abi_version != NBG_DEVPTS_FILTER_ABI_VERSION)
        return -EPROTO;
    if (req->enabled > NBG_DEVPTS_FILTER_QUERY)
        return -EINVAL;
    if (req->enabled == NBG_DEVPTS_FILTER_QUERY) {
        mutex_lock(&devpts_filter_lock);
        devpts_filter_fill_status_locked(req);
        mutex_unlock(&devpts_filter_lock);
        return 0;
    }
    if (req->enabled == NBG_DEVPTS_FILTER_ENABLE &&
        (req->pid <= 0 || req->max_index > NBG_DEVPTS_FILTER_MAX_INDEX))
        return -EINVAL;

    if (req->enabled == NBG_DEVPTS_FILTER_ENABLE) {
        new_state = devpts_filter_alloc_state(req->pid, req->max_index);
        if (!new_state)
            return -ENOMEM;
    } else {
        /* Client cleanup must not recreate the pre-launch detection window.
         * It drops the explicit PID and leaves the module-load automatic
         * package scope armed. */
        new_state = devpts_filter_alloc_state(0, NBG_DEVPTS_FILTER_MAX_INDEX);
        if (!new_state)
            return -ENOMEM;
    }

    mutex_lock(&devpts_filter_lock);
    old_state = rcu_dereference_protected(
        devpts_filter_state, lockdep_is_held(&devpts_filter_lock));
    ret = devpts_filter_register_hooks_locked();
    if (!ret && bind_target) {
            ret = nbg_target_bind_pid(new_state->tgid);
            if (!ret)
                new_state->tgid = nbg_target_bound_pid();
    }
    if (!ret) {
        rcu_assign_pointer(devpts_filter_state, new_state);
        new_state = NULL;
        atomic64_set(&devpts_permission_hits, 0);
        atomic64_set(&devpts_getattr_hits, 0);
    } else {
        /* Preserve a working automatic filter when a later explicit bind
         * fails.  Only roll back resources when no state existed yet. */
        if (!old_state) {
            devpts_filter_unregister_hooks_locked();
        }
        devpts_filter_fill_status_locked(req);
        mutex_unlock(&devpts_filter_lock);
        kfree(new_state);
        return ret;
    }

    devpts_filter_fill_status_locked(req);
    mutex_unlock(&devpts_filter_lock);

    if (old_state) {
        synchronize_rcu();
        kfree(old_state);
    }
    /* OP_DEVPTS_FILTER disable only drops the userspace session state.  Keep
     * the automatic package binding alive so closing the overlay cannot
     * reopen the game's devpts detection window. */
    kfree(new_state);
    return 0;
}

void devpts_filter_clear(void)
{
    struct devpts_filter_state *old_state;

    nbg_target_auto_stop();

    mutex_lock(&devpts_filter_lock);
    old_state = rcu_dereference_protected(
        devpts_filter_state, lockdep_is_held(&devpts_filter_lock));
    RCU_INIT_POINTER(devpts_filter_state, NULL);
    devpts_filter_unregister_hooks_locked();
    mutex_unlock(&devpts_filter_lock);

    if (old_state) {
        synchronize_rcu();
        kfree(old_state);
    }
    nbg_target_clear();
}
