/* hwbp_shadow.h — shadow hook 与 watch logger 协议接口 */
#ifndef _HWBP_SHADOW_H_
#define _HWBP_SHADOW_H_

#include <linux/types.h>
#include "comm.h"
#include "hwbp_raw.h"

#define MAX_SHADOW_HOOKS  MAX_RAW_BP
#ifndef WATCH_BATCH_MAX
#define WATCH_BATCH_MAX   32
#endif

struct shadow_req {
    int32_t  pid;
    uint64_t vaddr;             /* 目标 (被改写) 地址,留作扩展 */
    uint64_t target_vaddr;      /* 实际下断点的地址 */
    uint32_t custom_rot[3];     /* 业务 payload(各 hook 类型语义不同) */
    int32_t  is_rot_hook;       /* 支持 1/2/4/5/7/8/24/25/28/29/31/32/33/34/35/38/39/40 */
};

struct watch_req {
    int32_t  pid;
    uint64_t watch_addr;
    uint32_t bp_type;
    uint32_t bp_len;
    uint32_t log_limit;
    uint32_t flags;             /* WP_FLAG_*,与 raw_wp_req.flags 一致 */
};

typedef struct {
    uint64_t watch_addr;
    uint64_t pc;
    int32_t  tid;
    int32_t  pid;
    uint32_t bp_type;
    uint32_t hit_count;
} WATCH_EVENT;

typedef struct {
    WATCH_EVENT events[WATCH_BATCH_MAX];
    uint32_t    count;
} WATCH_READ_REQ;

int  shadow_add_hook(struct shadow_req *req);
int  shadow_update_rot(struct shadow_req *req);
int  shadow_del_hook(struct shadow_req *req);
void shadow_query_diag(ShadowDiag *diag);

int  watch_add(struct watch_req *req);
int  watch_delete(struct watch_req *req);
void watch_clear_all(void);
int  watch_read_kernel(void *buf);
void watch_push_custom_event(uint64_t a, uint64_t b, uint32_t type, uint32_t hit_count);

int  shadow_init_module(void);
void shadow_exit_module(void);

void watch_logger_init(void);
void watch_logger_exit(void);

#endif /* _HWBP_SHADOW_H_ */
