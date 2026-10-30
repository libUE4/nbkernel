/* Call the real 5.10 implementations when the vendor export list trims them.
 * Resolve once in module-init context, never from a callback/atomic section.
 * No replacement locks, no dropped references, and no force-load flags.
 */
#include "nbg_ksyms.h"
#include "nbg_gki_compat.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
static int (*gki_register_kprobe)(struct kprobe *);
static void (*gki_unregister_kprobe)(struct kprobe *);
static int (*gki_down_read_killable)(struct rw_semaphore *);
static struct pid *(*gki_get_task_pid)(struct task_struct *, enum pid_type);
static int (*gki_srcu_read_lock)(struct srcu_struct *);
static void (*gki_on_each_cpu)(smp_call_func_t, void *, int);

int nbg_gki_compat_init(void)
{
#define RESOLVE_REQUIRED(slot, symbol) do { \
    (slot) = (typeof(slot))generic_kallsyms_lookup_name(symbol); \
    if (!(slot)) \
        return -ENOENT; \
} while (0)
    RESOLVE_REQUIRED(gki_register_kprobe, "register_kprobe");
    RESOLVE_REQUIRED(gki_unregister_kprobe, "unregister_kprobe");
    RESOLVE_REQUIRED(gki_down_read_killable, "down_read_killable");
    RESOLVE_REQUIRED(gki_get_task_pid, "get_task_pid");
    RESOLVE_REQUIRED(gki_srcu_read_lock, "__srcu_read_lock");
    RESOLVE_REQUIRED(gki_on_each_cpu, "on_each_cpu");
#undef RESOLVE_REQUIRED
    return 0;
}

NBG_NO_CFI
int nbg_register_kprobe(struct kprobe *kp)
{
    return gki_register_kprobe(kp);
}

NBG_NO_CFI
void nbg_unregister_kprobe(struct kprobe *kp)
{
    gki_unregister_kprobe(kp);
}

NBG_NO_CFI
int nbg_down_read_killable(struct rw_semaphore *sem)
{
    /* Keep killability and exec_update_lock exclusion, including LSM checks. */
    return gki_down_read_killable(sem);
}

NBG_NO_CFI
struct pid *nbg_get_task_pid(struct task_struct *task, enum pid_type type)
{
    return gki_get_task_pid(task, type);
}

NBG_NO_CFI
int nbg_srcu_read_lock(struct srcu_struct *ssp) __acquires(ssp)
{
    int idx = gki_srcu_read_lock(ssp);

    /* Match include/linux/srcu.h, including lockdep's acquisition. The
     * existing srcu_read_unlock still performs the matching release. */
    rcu_lock_acquire(&ssp->dep_map);
    return idx;
}

NBG_NO_CFI
void nbg_on_each_cpu(smp_call_func_t func, void *info, int wait)
{
    /* Preserve local-CPU invocation, IRQ/preemption rules and wait semantics. */
    gki_on_each_cpu(func, info, wait);
}
#else
int nbg_gki_compat_init(void)
{
    return 0;
}
#endif
