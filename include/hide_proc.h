/* hide_proc.h — /proc/<pid> 与 tasklist 隐藏接口 */
#ifndef _HIDE_PROC_H_
#define _HIDE_PROC_H_

#include <linux/types.h>

int hide_process(pid_t pid_nr);
int unhide_process(pid_t pid_nr);
int signal_hidden_processes(int sig, u32 *matched, u32 *delivered);

#endif /* _HIDE_PROC_H_ */
