/* memory.h — 跨进程内存读写
 *
 * 实现:带页表锁的直接 PTE -> page 读写。普通读取与写入只处理当前
 * present 页面;OP_READ_MEM_FAULT 会按需触发缺页后再走相同的 PTE 路径。
 *
 * 内核内部使用 kernel buffer 接口;ioctl 对接层使用 user buffer 接口。
 */
#ifndef _NBG_MEMORY_H
#define _NBG_MEMORY_H

#include <linux/types.h>

#include "comm.h"

struct mm_struct;

int nbg_memory_init(void);

/* 内核 buffer 直读,免 copy_to/from_user */
bool read_process_memory_kernel(pid_t pid, uintptr_t addr, void *buffer, size_t size);
bool read_process_memory_mm(struct mm_struct *mm, uintptr_t addr, void *buffer, size_t size);
bool write_process_memory_kernel(pid_t pid, uintptr_t addr,
                                 const void *buffer, size_t size);

/* 持有一个目标 mm 引用，供同一目标的多次读取复用。 */
struct nbg_read_ctx {
    pid_t pid;
    struct mm_struct *mm;
};

int nbg_read_ctx_init_pid(struct nbg_read_ctx *ctx, pid_t pid);
int nbg_read_ctx_init_current(struct nbg_read_ctx *ctx, pid_t expected_tgid);
long nbg_read_ctx_read(struct nbg_read_ctx *ctx, uint64_t addr, void *buf,
                       size_t size);
void nbg_read_ctx_release(struct nbg_read_ctx *ctx);
long nbg_read_kernel(pid_t pid, uint64_t addr, void *buf, size_t size);

/* ioctl 用户指针桥接接口: remote <-> user buffer */
int nbg_read_memory(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                    size_t size, size_t *nbytes);
int nbg_read_memory_fault(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                          size_t size, size_t *nbytes);
int nbg_write_memory(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                     size_t size, size_t *nbytes);
int nbg_flush_icache(pid_t pid, uintptr_t remote_addr, size_t size);
int nbg_readv_memory(pid_t pid, READV_ENTRY __user *iov, uint32_t count);
int nbg_readv_memory_fault(pid_t pid, READV_ENTRY __user *iov, uint32_t count);
void nbg_memory_cache_cleanup(void);

#endif /* _NBG_MEMORY_H */
