/* hwbp_raw.h — arm64 原始硬件断点 / 观察点底层接口 */
#ifndef _HWBP_RAW_H_
#define _HWBP_RAW_H_

#include <linux/types.h>
#include <linux/sched.h>

#define MAX_RAW_BP        4    /* 同时活跃的 BP 上限 */
#define RAW_BP_SLOT_BASE  2    /* dbgbvr2_el1 起;0/1 留给系统自身的 step/etc */

typedef void (*raw_bp_callback_t)(struct pt_regs *regs, void *priv);

struct raw_bp_req {
    pid_t              pid;
    uint64_t           target_vaddr;
    raw_bp_callback_t  callback;
    void              *priv;
};

int  raw_hwbp_add(struct raw_bp_req *req);
/* Refuse an existing (pid,address) owner instead of replacing its callback. */
int  raw_hwbp_add_exclusive(struct raw_bp_req *req);
int  raw_hwbp_del_pid(pid_t pid, uint64_t target_vaddr);
int  raw_hwbp_del(uint64_t target_vaddr);
void raw_hwbp_clear_all(void);
bool raw_hwbp_has_pid(pid_t pid);
/* Copy active raw execution-breakpoint addresses for a target.  The return
 * value is the number of entries copied (bounded by capacity). */
uint32_t raw_hwbp_snapshot(pid_t pid, uint64_t *addresses,
                           uint32_t capacity);
void raw_hwbp_rearm_all(void);
void raw_hwbp_clear_slots_this_cpu(void);
int  raw_hwbp_init(void);
void raw_hwbp_exit(void);

#define MAX_RAW_WP   4
#define RAW_WP_R     0x1
#define RAW_WP_W     0x2
#define RAW_WP_RW    0x3

#define WP_FLAG_NONE         0u
#define WP_FLAG_SKIP_STORE   (1u << 0)
#define WP_FLAG_TRACE_FRAMES (1u << 31)

typedef void (*raw_wp_callback_t)(struct pt_regs *regs, uint64_t hit_addr,
                                  void *priv);

struct raw_wp_req {
    pid_t              pid;
    uint64_t           watch_addr;
    uint32_t           bp_type;
    uint32_t           bp_len;
    uint32_t           flags;
    raw_wp_callback_t  callback;
    void              *priv;
};

int  raw_hwwp_add(struct raw_wp_req *req);
int  raw_hwwp_del_pid(pid_t pid, uint64_t watch_addr);
int  raw_hwwp_del(uint64_t watch_addr);
int  wp_validate_alignment(uint32_t bp_len, uint64_t watch_addr);
void raw_hwwp_clear_all(void);
bool raw_hwwp_has_pid(pid_t pid);
/* Copy active raw watchpoint granule addresses for a target. */
uint32_t raw_hwwp_snapshot(pid_t pid, uint64_t *addresses,
                           uint32_t capacity);
void raw_hwwp_rearm_all(void);
void raw_hwwp_clear_slots_this_cpu(void);
void wp_apply_this_cpu(void);
int  raw_hwwp_init(void);
void raw_hwwp_exit(void);

#endif /* _HWBP_RAW_H_ */
