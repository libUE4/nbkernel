/* nbg_target.h - stable process scope used by app-only driver policies */
#ifndef _NBG_TARGET_H_
#define _NBG_TARGET_H_

#include <linux/types.h>

struct task_struct;

bool nbg_target_task_is_game(const struct task_struct *task);
bool nbg_target_current_is_game(void);

/* Lifecycle discovery binds a package cmdline to its whole thread group
 * before engines can rename their worker threads. */
int nbg_target_auto_start(void);
void nbg_target_auto_stop(void);

/* Bind by struct pid, rather than a numeric PID, so PID reuse cannot inherit
 * the app-only view. The comm fallback is used only before an explicit bind. */
int nbg_target_bind_pid(pid_t pid);
void nbg_target_clear(void);
pid_t nbg_target_bound_pid(void);

#endif /* _NBG_TARGET_H_ */
