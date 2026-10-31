/* process.h — 进程辅助查询
 *
 * 不开 /proc 文件，完全在内核态走 tasklist / mm：
 *
 *   find_pid_by_name  按包名/可执行名查 pid。短名(<=15)比 task->comm，
 *                     长名先 comm 前缀粗筛，命中再读 argv[0] 精确比对。
 */
#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <linux/types.h>

pid_t     find_pid_by_name(const char *name);
/* Exact argv[0] lookup for low-frequency driver lifecycle work.  Unlike the
 * regular finder it does not depend on task->comm, which engines may rename
 * after Android has assigned the package cmdline. */
pid_t     find_pid_by_cmdline(const char *name);
pid_t     find_pid_by_cmdline_ranked(const char *name);

#endif /* _PROCESS_H_ */
