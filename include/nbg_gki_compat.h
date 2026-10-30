/* GKI export trimming is independent of the kernel API/version. */
#ifndef _NBG_GKI_COMPAT_H_
#define _NBG_GKI_COMPAT_H_

#include <linux/kprobes.h>
#include <linux/pid.h>
#include <linux/rwsem.h>
#include <linux/smp.h>
#include <linux/srcu.h>
#include <linux/version.h>

/* Must succeed before installing any callback or exposing an ioctl. */
int nbg_gki_compat_init(void);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
int nbg_register_kprobe(struct kprobe *kp);
void nbg_unregister_kprobe(struct kprobe *kp);
int nbg_down_read_killable(struct rw_semaphore *sem);
struct pid *nbg_get_task_pid(struct task_struct *task, enum pid_type type);
int nbg_srcu_read_lock(struct srcu_struct *ssp) __acquires(ssp);
void nbg_on_each_cpu(smp_call_func_t func, void *info, int wait);
#else
#define nbg_register_kprobe register_kprobe
#define nbg_unregister_kprobe unregister_kprobe
#define nbg_down_read_killable down_read_killable
#define nbg_get_task_pid get_task_pid
#define nbg_srcu_read_lock srcu_read_lock
#define nbg_on_each_cpu on_each_cpu
#endif

#endif
