/* query.h — 进程 / 线程 / 地址查询接口
 *
 * ABI 定义集中在 comm.h。
 */
#ifndef _NBG_QUERY_H
#define _NBG_QUERY_H

#include <linux/types.h>

#include "comm.h"

struct mm_struct;

long nbg_query_pid(void __user *arg);
long nbg_query_pids(void __user *arg);
/* 内核侧模块扫描，供旧命令转发。 */
int nbg_scan_module_kernel(uint64_t *base, uint64_t *size, pid_t pid,
                           const char *name, uint64_t max_vma_size,
                           char *pathbuf, size_t pathbuf_len);
long nbg_query_module_base(void __user *arg);
long nbg_query_module_base2(void __user *arg);
long nbg_query_module_path(void __user *arg);
long nbg_query_tls(void __user *arg);
long nbg_query_thread_tid(void __user *arg);
long nbg_query_thread_tids(void __user *arg);
long nbg_query_thread_stack(void __user *arg);
long nbg_query_mapping(void __user *arg);
int nbg_query_access_mm(struct mm_struct *mm, unsigned long addr,
                        NBG_QUERY_ACCESS_REQ *req);
long nbg_query_access(void __user *arg);
long nbg_query_signal(void __user *arg);
long nbg_query_pacga(void __user *arg);

#endif /* _NBG_QUERY_H */
