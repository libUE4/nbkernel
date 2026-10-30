/* target.c - process-generation-safe target identity */
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/workqueue.h>

#include "nbg_target.h"
#include "nbg_ksyms.h"
#include "process.h"

/* 发现阶段按 cmdline 逐个匹配：本工程目标 rmcn，保留 DFM 以免其它分支回归。
 * Android 的 comm 上限 15 字节，com.tencent.rmcn（16 字节）会被截成
 * om.tencent.rmcn，因此 comm 判据同时接受这份截断前缀。 */
static const char * const nbg_target_cmdlines[] = {
    "com.tencent.rmcn",
    "com.tencent.tmgp.dfm",
};
#define NBG_TARGET_COMM_PREFIX       "com.tencent."
#define NBG_TARGET_COMM_PREFIX_SHORT "om.tencent."
#define NBG_TARGET_UE4_MAIN_COMM     "MainThread-UE4"
#define NBG_TARGET_DISCOVERY_RETRIES 8

/* Fork-inherited domain: once a task is in the game scope, every child it
 * forks stays in scope even after the child renames its comm or changes
 * credentials (anti-cheat helpers, privilege escalation paths).  Slots hold
 * struct pid references so pointer comparison is reuse-safe; a wrapped slot
 * drops the oldest reference. */
#define NBG_TARGET_INHERIT_MAX 64

static DEFINE_MUTEX(nbg_target_lock);
static struct pid __rcu *nbg_target_tgid;
static atomic_t nbg_target_uid = ATOMIC_INIT(-1);
static DEFINE_MUTEX(nbg_target_auto_lock);
static struct kprobe nbg_target_comm_kp;
static bool nbg_target_comm_hook_active;
static atomic_t nbg_target_pending_tgid = ATOMIC_INIT(0);
static atomic_t nbg_target_discovery_attempts = ATOMIC_INIT(0);

static DEFINE_SPINLOCK(nbg_target_inherit_lock);
static struct pid *nbg_target_inherit[NBG_TARGET_INHERIT_MAX];
static u32 nbg_target_inherit_head;
static struct kretprobe nbg_target_fork_krp;
static bool nbg_target_fork_hook_active;

static void nbg_target_discover_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(nbg_target_discover_work,
                            nbg_target_discover_workfn);

static bool nbg_target_comm_has_prefix(const char *comm, const char *prefix)
{
    return comm && strncmp(comm, prefix, strlen(prefix)) == 0;
}

static bool nbg_target_comm_matches(const struct task_struct *task)
{
    char comm[TASK_COMM_LEN];

    if (!task)
        return false;

    get_task_comm(comm, (struct task_struct *)task);
    return nbg_target_comm_has_prefix(comm, NBG_TARGET_COMM_PREFIX) ||
           nbg_target_comm_has_prefix(comm, NBG_TARGET_COMM_PREFIX_SHORT);
}

static bool nbg_target_comm_is_discovery_candidate(const char *comm)
{
    if (!comm)
        return false;
    return nbg_target_comm_has_prefix(comm, NBG_TARGET_COMM_PREFIX) ||
           nbg_target_comm_has_prefix(comm, NBG_TARGET_COMM_PREFIX_SHORT) ||
           nbg_target_comm_has_prefix(comm, NBG_TARGET_UE4_MAIN_COMM);
}

static bool nbg_target_inherited_locked(const struct task_struct *task)
{
    const struct pid *tgid;
    int i;

    tgid = task_tgid((struct task_struct *)task);
    if (!tgid)
        return false;
    for (i = 0; i < NBG_TARGET_INHERIT_MAX; i++) {
        if (READ_ONCE(nbg_target_inherit[i]) == tgid)
            return true;
    }
    return false;
}

bool nbg_target_task_is_game(const struct task_struct *task)
{
    const struct task_struct *leader;
    const struct pid *bound;
    int bound_uid;
    bool match = false;
    unsigned long flags;

    if (!task)
        return false;

    rcu_read_lock();
    bound = rcu_dereference(nbg_target_tgid);
    if (bound)
        match = task_tgid((struct task_struct *)task) == bound;
    rcu_read_unlock();
    if (match)
        return true;

    /* Children forked by an in-scope process stay in scope for their whole
     * lifetime (comm rename / credential changes do not escape). */
    spin_lock_irqsave(&nbg_target_inherit_lock, flags);
    match = nbg_target_inherited_locked(task);
    spin_unlock_irqrestore(&nbg_target_inherit_lock, flags);
    if (match)
        return true;

    /* A supplied TGID identifies the primary session, but the game's own
     * helper/service processes can perform the same probes.  Keep the
     * package-level match armed for those processes and for the early window
     * before userspace has connected. */

    /* Android package services share the app UID but can live in a separate
     * process with their own renamed leader.  Once cmdline discovery has
     * validated one process, cover the package's complete UID scope. */
    bound_uid = atomic_read(&nbg_target_uid);
    if (bound_uid >= 0 &&
        (int)__kuid_val(task_uid((struct task_struct *)task)) == bound_uid)
        return true;

    if (atomic_read(&nbg_target_pending_tgid) > 0 &&
        READ_ONCE(((struct task_struct *)task)->tgid) ==
        atomic_read(&nbg_target_pending_tgid))
        return true;

    if (nbg_target_comm_matches(task))
        return true;

    leader = READ_ONCE(task->group_leader);
    return leader && leader != task && nbg_target_comm_matches(leader);
}

bool nbg_target_current_is_game(void)
{
    return nbg_target_task_is_game(current);
}

static int nbg_target_fork_entry(struct kretprobe_instance *ri,
                                 struct pt_regs *regs)
{
    (void)ri;
    (void)regs;
    /* Only in-scope parents may consume an instance: copy_process runs for
     * every fork system-wide and a per-call instance would starve the pool. */
    if (!nbg_target_task_is_game(current))
        return 1;
    return 0;
}

static int nbg_target_fork_ret(struct kretprobe_instance *ri,
                               struct pt_regs *regs)
{
    struct task_struct *child =
        (struct task_struct *)regs_return_value(regs);
    struct pid *tgid;
    unsigned long flags;
    u32 slot;

    (void)ri;
    if (IS_ERR_OR_NULL(child))
        return 0;
    tgid = get_pid(task_tgid(child));
    if (!tgid)
        return 0;

    spin_lock_irqsave(&nbg_target_inherit_lock, flags);
    slot = nbg_target_inherit_head;
    nbg_target_inherit_head = (slot + 1) % NBG_TARGET_INHERIT_MAX;
    if (nbg_target_inherit[slot])
        put_pid(nbg_target_inherit[slot]);
    nbg_target_inherit[slot] = tgid;
    spin_unlock_irqrestore(&nbg_target_inherit_lock, flags);
    return 0;
}

static void nbg_target_inherit_clear(void)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&nbg_target_inherit_lock, flags);
    for (i = 0; i < NBG_TARGET_INHERIT_MAX; i++) {
        if (nbg_target_inherit[i]) {
            put_pid(nbg_target_inherit[i]);
            nbg_target_inherit[i] = NULL;
        }
    }
    nbg_target_inherit_head = 0;
    spin_unlock_irqrestore(&nbg_target_inherit_lock, flags);
}

static int nbg_target_comm_pre(struct kprobe *kp, struct pt_regs *regs)
{
    const struct task_struct *task;
    const char *comm;

    (void)kp;
    task = (const struct task_struct *)(unsigned long)regs->regs[0];
    comm = (const char *)(unsigned long)regs->regs[1];
    if (!task || (READ_ONCE(task->flags) & PF_KTHREAD) ||
        !nbg_target_comm_is_discovery_candidate(comm))
        return 0;

    /* This is intentionally provisional: it covers the small interval
     * between an engine renaming its main thread and workqueue cmdline
     * validation.  Validation clears non-target candidates promptly. */
    atomic_set(&nbg_target_pending_tgid, READ_ONCE(task->tgid));
    atomic_set(&nbg_target_discovery_attempts, 0);
    mod_delayed_work(system_wq, &nbg_target_discover_work, 0);
    return 0;
}

static void nbg_target_discover_workfn(struct work_struct *work)
{
    pid_t found = -1;
    int attempt;
    size_t i;

    (void)work;
    for (i = 0; i < ARRAY_SIZE(nbg_target_cmdlines) && found <= 0; ++i)
        found = find_pid_by_cmdline(nbg_target_cmdlines[i]);
    if (found > 0) {
        (void)nbg_target_bind_pid(found);
        atomic_cmpxchg(&nbg_target_pending_tgid, found, 0);
        atomic_set(&nbg_target_discovery_attempts, 0);
        return;
    }

    attempt = atomic_inc_return(&nbg_target_discovery_attempts);
    if (attempt < NBG_TARGET_DISCOVERY_RETRIES) {
        mod_delayed_work(system_wq, &nbg_target_discover_work, HZ / 2);
        return;
    }

    atomic_set(&nbg_target_pending_tgid, 0);
}

int nbg_target_auto_start(void)
{
    static const char * const comm_cands[] = {
        "__set_task_comm", NULL,
    };
    int ret;

    mutex_lock(&nbg_target_auto_lock);
    if (nbg_target_comm_hook_active) {
        mutex_unlock(&nbg_target_auto_lock);
        return 0;
    }

    memset(&nbg_target_comm_kp, 0, sizeof(nbg_target_comm_kp));
    nbg_target_comm_kp.pre_handler = nbg_target_comm_pre;
    ret = nbg_register_kprobe_named(&nbg_target_comm_kp, comm_cands, NULL);
    if (ret)
        goto out;
    nbg_target_comm_hook_active = true;

    /* Fork inheritance rides the same lifecycle as comm discovery; a failed
     * registration is non-fatal for the other probes. */
    if (!nbg_target_fork_hook_active) {
        static const char * const fork_cands[] = {
            "copy_process", "_copy_process", NULL,
        };

        memset(&nbg_target_fork_krp, 0, sizeof(nbg_target_fork_krp));
        nbg_target_fork_krp.entry_handler = nbg_target_fork_entry;
        nbg_target_fork_krp.handler = nbg_target_fork_ret;
        nbg_target_fork_krp.data_size = 0;
        nbg_target_fork_krp.maxactive =
            max_t(u32, num_possible_cpus() * 16, 256U);
        ret = nbg_register_kretprobe_named(&nbg_target_fork_krp,
                                           fork_cands, NULL);
        if (ret) {
            /* keep the comm probe; fork tracking is best-effort here */
            pr_warn("NBG target: fork kretprobe failed %d\n", ret);
            ret = 0;
        } else {
            nbg_target_fork_hook_active = true;
        }
    }

    atomic_set(&nbg_target_pending_tgid, 0);
    atomic_set(&nbg_target_discovery_attempts, 0);
    mod_delayed_work(system_wq, &nbg_target_discover_work, 0);
out:
    mutex_unlock(&nbg_target_auto_lock);
    return ret;
}

void nbg_target_auto_stop(void)
{
    mutex_lock(&nbg_target_auto_lock);
    if (nbg_target_comm_hook_active) {
        nbg_unregister_kprobe(&nbg_target_comm_kp);
        nbg_target_comm_hook_active = false;
    }
    if (nbg_target_fork_hook_active) {
        unregister_kretprobe(&nbg_target_fork_krp);
        nbg_target_fork_hook_active = false;
    }
    mutex_unlock(&nbg_target_auto_lock);

    cancel_delayed_work_sync(&nbg_target_discover_work);
    atomic_set(&nbg_target_pending_tgid, 0);
    atomic_set(&nbg_target_discovery_attempts, 0);
    nbg_target_inherit_clear();
}

int nbg_target_bind_pid(pid_t nr)
{
    struct task_struct *task;
    struct pid *lookup;
    struct pid *new_tgid;
    struct pid *old_tgid;
    int uid;

    if (nr <= 0)
        return -EINVAL;

    lookup = find_get_pid(nr);
    if (!lookup)
        return -ESRCH;

    task = get_pid_task(lookup, PIDTYPE_PID);
    put_pid(lookup);
    if (!task)
        return -ESRCH;
    if (!pid_alive(task) || (READ_ONCE(task->flags) & PF_EXITING)) {
        put_task_struct(task);
        return -ESRCH;
    }

    uid = (int)__kuid_val(task_uid(task));

    new_tgid = nbg_get_task_pid(task, PIDTYPE_TGID);
    put_task_struct(task);
    if (!new_tgid)
        return -ESRCH;

    mutex_lock(&nbg_target_lock);
    old_tgid = rcu_dereference_protected(
        nbg_target_tgid, lockdep_is_held(&nbg_target_lock));
    if (old_tgid == new_tgid) {
        atomic_set(&nbg_target_uid, uid);
        mutex_unlock(&nbg_target_lock);
        put_pid(new_tgid);
        return 0;
    }
    rcu_assign_pointer(nbg_target_tgid, new_tgid);
    atomic_set(&nbg_target_uid, uid);
    mutex_unlock(&nbg_target_lock);

    if (old_tgid) {
        synchronize_rcu();
        put_pid(old_tgid);
    }
    return 0;
}

void nbg_target_clear(void)
{
    struct pid *old_tgid;

    mutex_lock(&nbg_target_lock);
    old_tgid = rcu_dereference_protected(
        nbg_target_tgid, lockdep_is_held(&nbg_target_lock));
    RCU_INIT_POINTER(nbg_target_tgid, NULL);
    atomic_set(&nbg_target_uid, -1);
    mutex_unlock(&nbg_target_lock);

    if (old_tgid) {
        synchronize_rcu();
        put_pid(old_tgid);
    }
    nbg_target_inherit_clear();
}

pid_t nbg_target_bound_pid(void)
{
    struct pid *bound;
    pid_t nr = 0;

    rcu_read_lock();
    bound = rcu_dereference(nbg_target_tgid);
    if (bound)
        nr = pid_nr(bound);
    rcu_read_unlock();
    return nr;
}
