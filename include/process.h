/* process.h — 进程辅助查询
 *
 * 两个互补接口,都不开 /proc 文件,完全在内核态走 tasklist / mm:
 *
 *   get_module_base   按 (pid, "libxxx.so") 找模块基址(vm_pgoff==0 的
 *                     文件 VMA 起始)
 *
 *   find_pid_by_name  按包名/可执行名查 pid。短名(<=15)比 task->comm,
 *                     长名先 comm 前缀粗筛,命中再 access_process_vm
 *                     读 argv[0] 精确比对。
 */
#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <linux/types.h>

uintptr_t get_module_base(pid_t pid, const char *name);
pid_t     find_pid_by_name(const char *name);
/* Exact argv[0] lookup for low-frequency driver lifecycle work.  Unlike the
 * regular finder it does not depend on task->comm, which engines may rename
 * after Android has assigned the package cmdline. */
pid_t     find_pid_by_cmdline(const char *name);
pid_t     find_pid_by_cmdline_ranked(const char *name);

#endif /* _PROCESS_H_ */
