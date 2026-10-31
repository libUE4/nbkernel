/* memory.h — 跨进程内存读取
 *
 * 页表遍历定位物理地址，再经 non-cacheable linearmap 读取目标内存。
 * linearmap 在 nbg_memory_init() 时按 memblock 区域一次性建立。
 */
#ifndef _NBG_MEMORY_H
#define _NBG_MEMORY_H

#include <linux/types.h>

#include "comm.h"

struct mm_struct;

int nbg_memory_init(void);
void nbg_memory_cache_cleanup(void);

/* 内核 buffer 直读，免 copy_to_user */
bool read_process_memory_kernel(pid_t pid, uintptr_t addr, void *buffer,
                                size_t size);
bool read_process_memory_mm(struct mm_struct *mm, uintptr_t addr,
                            void *buffer, size_t size);
bool write_process_memory_kernel(pid_t pid, uintptr_t addr,
                                 const void *buffer, size_t size);

/* ioctl 用户指针桥接接口：remote -> user buffer */
int nbg_read_memory(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                    size_t size, size_t *nbytes);
int nbg_read_memory_fault(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                          size_t size, size_t *nbytes);
int nbg_read_memory_cache(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                          size_t size, size_t *nbytes);
int nbg_write_memory(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                     size_t size, size_t *nbytes);
int nbg_write_memory_cache(pid_t pid, uintptr_t remote_addr,
                           uintptr_t user_addr, size_t size, size_t *nbytes);

#endif /* _NBG_MEMORY_H */
