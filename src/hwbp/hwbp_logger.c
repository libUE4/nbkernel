/* hwbp_logger.c — 观察点命中事件环形缓冲
 *
 * 一句话:hwbp_watch 命中后,我们的 raw_watch_callback 把 (addr, pc, tid,
 * pid, type, hit_count) 推进 watch_ring,用户态 OP_WATCH_READ 通过
 * watch_read_kernel 一次取最多 WATCH_BATCH_MAX 条。
 *
 * 同步:raw_spin_lock 保 ring(callback 在原子段调用,不能 sleep);
 * watch_ctxs 按 raw WP 槽位数量保存每个观察点的 pid/type/log_limit,
 * 避免多槽并存时事件归属和限速计数互相串扰。
 */
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <asm/ptrace.h>
#include "hwbp_shadow.h"
#include "nbg_log.h"
#include "nbg_gki_compat.h"

#define WATCH_RING_SIZE  512
#define WATCH_RING_MASK  (WATCH_RING_SIZE - 1)
#define WATCH_FRAME_EVENT_BASE 0xF100U
#define WATCH_FRAME_MAX_DEPTH  8U
#define WATCH_USER_PTR_MASK    0x0000FFFFFFFFFFFFULL
#define WATCH_USER_MIN_ADDR    0x10000ULL
#define WATCH_FRAME_MAX_STEP   0x100000ULL

static WATCH_EVENT          watch_ring[WATCH_RING_SIZE];
static unsigned int         watch_ring_head;
static unsigned int         watch_ring_tail;
static DEFINE_RAW_SPINLOCK(watch_ring_lock);

struct watch_ctx {
    bool     active;
    pid_t    pid;
    uint64_t watch_addr;
    uint32_t bp_type;
    uint32_t log_limit;
    uint32_t flags;
    atomic_t hit_count;
};

static DEFINE_MUTEX(watch_param_mutex);
static struct watch_ctx watch_ctxs[MAX_RAW_WP];

/* 推一条事件;ring 满时丢最旧,保留最新命中 */
static void watch_ring_push(const WATCH_EVENT *ev)
{
    unsigned long flags;
    raw_spin_lock_irqsave(&watch_ring_lock, flags);
    if ((watch_ring_head - watch_ring_tail) >= WATCH_RING_SIZE)
        watch_ring_tail++;
    watch_ring[watch_ring_head & WATCH_RING_MASK] = *ev;
    watch_ring_head++;
    raw_spin_unlock_irqrestore(&watch_ring_lock, flags);
}

void watch_push_custom_event(uint64_t a, uint64_t b, uint32_t type, uint32_t hit_count)
{
    WATCH_EVENT ev;

    memset(&ev, 0, sizeof(ev));
    ev.watch_addr = a;
    ev.pc         = b;
    ev.tid        = current ? current->pid : 0;
    ev.pid        = current ? current->tgid : 0;
    ev.bp_type    = type;
    ev.hit_count  = hit_count;
    watch_ring_push(&ev);
}

static void watch_ring_reset(void)
{
    unsigned long flags;

    raw_spin_lock_irqsave(&watch_ring_lock, flags);
    watch_ring_head = 0;
    watch_ring_tail = 0;
    raw_spin_unlock_irqrestore(&watch_ring_lock, flags);
}

static void watch_noop_ipi(void *info) { (void)info; }

static void watch_sync_callbacks(void)
{
    nbg_on_each_cpu(watch_noop_ipi, NULL, 1);
}

static bool watch_get_user_u64(uint64_t addr, uint64_t *out)
{
    uint64_t value = 0;
    int ret;

    if (!out)
        return false;
    addr &= WATCH_USER_PTR_MASK;
    if (addr < WATCH_USER_MIN_ADDR || addr > WATCH_USER_PTR_MASK - sizeof(value))
        return false;

    pagefault_disable();
    ret = __get_user(value, (uint64_t __user *)addr);
    pagefault_enable();
    if (ret)
        return false;
    *out = value;
    return true;
}

static void watch_push_frame_events(const struct pt_regs *regs,
                                    const struct watch_ctx *ctx,
                                    uint32_t hit_count)
{
    uint64_t fp;
    uint32_t depth;

    if (!(READ_ONCE(ctx->flags) & WP_FLAG_TRACE_FRAMES))
        return;

    fp = regs->regs[29] & WATCH_USER_PTR_MASK;
    for (depth = 0; depth < WATCH_FRAME_MAX_DEPTH; depth++) {
        uint64_t next_fp = 0;
        uint64_t return_pc = 0;
        WATCH_EVENT ev;

        if (!watch_get_user_u64(fp, &next_fp) ||
            !watch_get_user_u64(fp + sizeof(uint64_t), &return_pc))
            break;
        next_fp &= WATCH_USER_PTR_MASK;
        return_pc &= WATCH_USER_PTR_MASK;
        if (return_pc < WATCH_USER_MIN_ADDR)
            break;

        memset(&ev, 0, sizeof(ev));
        ev.watch_addr = READ_ONCE(ctx->watch_addr);
        ev.pc = return_pc;
        ev.tid = current->pid;
        ev.pid = current->tgid;
        ev.bp_type = WATCH_FRAME_EVENT_BASE + depth;
        ev.hit_count = hit_count;
        watch_ring_push(&ev);

        if (next_fp <= fp || next_fp - fp > WATCH_FRAME_MAX_STEP)
            break;
        fp = next_fp;
    }
}

/* hwbp_watch 命中回调:在原子段被调用 */
static void raw_watch_callback(struct pt_regs *regs, uint64_t hit_addr,
                               void *priv)
{
    struct watch_ctx *ctx = (struct watch_ctx *)priv;
    int      hits;
    uint32_t log_limit;
    WATCH_EVENT ev;

    if (!ctx || !READ_ONCE(ctx->active))
        return;

    hits = atomic_inc_return(&ctx->hit_count);

    log_limit = READ_ONCE(ctx->log_limit);
    if (log_limit > 0 && (uint32_t)hits > log_limit)
        return;

    memset(&ev, 0, sizeof(ev));
    ev.watch_addr = hit_addr;
    ev.pc         = regs->pc;
    ev.tid        = current->pid;
    ev.pid        = current->tgid;
    ev.bp_type    = READ_ONCE(ctx->bp_type);
    ev.hit_count  = (uint32_t)hits;
    watch_ring_push(&ev);
    watch_push_frame_events(regs, ctx, (uint32_t)hits);
}

static struct watch_ctx *watch_find_ctx_locked(pid_t pid, uint64_t watch_addr)
{
    int i;

    for (i = 0; i < MAX_RAW_WP; i++) {
        if (watch_ctxs[i].active &&
            watch_ctxs[i].pid == pid &&
            watch_ctxs[i].watch_addr == watch_addr)
            return &watch_ctxs[i];
    }
    return NULL;
}

static struct watch_ctx *watch_alloc_ctx_locked(void)
{
    int i;

    for (i = 0; i < MAX_RAW_WP; i++) {
        if (!watch_ctxs[i].active)
            return &watch_ctxs[i];
    }
    return NULL;
}

/* ---- 公开接口 ---- */

int watch_add(struct watch_req *req)
{
    struct watch_ctx *ctx;
    struct raw_wp_req wreq;
    int ret;

    if (!req || !req->watch_addr)
    {
        NBG_FAIL_CODE(2401, -EINVAL);
        return -EINVAL;
    }
    if (req->bp_type != RAW_WP_R &&
        req->bp_type != RAW_WP_W &&
        req->bp_type != RAW_WP_RW) {
        NBG_FAIL_CODE(2402, -EINVAL);
        return -EINVAL;
    }

    ret = wp_validate_alignment(req->bp_len, req->watch_addr);
    if (ret) {
        NBG_FAIL_CODE(2403, ret);
        return ret;
    }

    mutex_lock(&watch_param_mutex);
    ctx = watch_find_ctx_locked(req->pid, req->watch_addr);
    if (!ctx)
        ctx = watch_alloc_ctx_locked();
    if (!ctx) {
        mutex_unlock(&watch_param_mutex);
        NBG_FAIL_CODE(2404, -ENOSPC);
        return -ENOSPC;
    }

    WRITE_ONCE(ctx->active, true);
    WRITE_ONCE(ctx->pid, req->pid);
    WRITE_ONCE(ctx->watch_addr, req->watch_addr);
    WRITE_ONCE(ctx->bp_type, req->bp_type);
    WRITE_ONCE(ctx->log_limit, req->log_limit);
    WRITE_ONCE(ctx->flags, req->flags);
    atomic_set(&ctx->hit_count, 0);

    memset(&wreq, 0, sizeof(wreq));
    wreq.pid        = req->pid;
    wreq.watch_addr = req->watch_addr;
    wreq.bp_type    = req->bp_type;
    wreq.bp_len     = req->bp_len;
    wreq.flags      = req->flags;
    wreq.callback   = raw_watch_callback;
    wreq.priv       = ctx;

    ret = raw_hwwp_add(&wreq);
    if (ret) {
        NBG_FAIL_CODE(2405, ret);
        WRITE_ONCE(ctx->active, false);
        WRITE_ONCE(ctx->watch_addr, 0);
        WRITE_ONCE(ctx->pid, 0);
        WRITE_ONCE(ctx->bp_type, 0);
        WRITE_ONCE(ctx->log_limit, 0);
        WRITE_ONCE(ctx->flags, 0);
    }
    mutex_unlock(&watch_param_mutex);
    return ret;
}

int watch_delete(struct watch_req *req)
{
    int ret;
    int i;

    if (!req || !req->watch_addr)
    {
        NBG_FAIL_CODE(2411, -EINVAL);
        return -EINVAL;
    }

    /* Serialize context ownership with watch_add.  raw_hwwp_del protects the
     * low-level slot, but without this mutex a concurrent add could reuse the
     * same watch_ctx before this function clears it. */
    mutex_lock(&watch_param_mutex);
    ret = raw_hwwp_del_pid(req->pid, req->watch_addr);
    if (ret)
        NBG_FAIL_CODE(2412, ret);
    if (ret == 0) {
        watch_sync_callbacks();
        /* HWBP-11:等所有 CPU 上 in-flight 的 raw_watch_callback 退出,
         * 再清 watch_ctx 防止回调读到 zeroed context。 */
        synchronize_rcu();
    }

    for (i = 0; i < MAX_RAW_WP; i++) {
        if (!watch_ctxs[i].active)
            continue;
        if (req->pid > 0 && watch_ctxs[i].pid != req->pid)
            continue;
        if (watch_ctxs[i].watch_addr != req->watch_addr)
            continue;
        WRITE_ONCE(watch_ctxs[i].active, false);
        WRITE_ONCE(watch_ctxs[i].watch_addr, 0);
        WRITE_ONCE(watch_ctxs[i].pid, 0);
        WRITE_ONCE(watch_ctxs[i].bp_type, 0);
        WRITE_ONCE(watch_ctxs[i].log_limit, 0);
        WRITE_ONCE(watch_ctxs[i].flags, 0);
        atomic_set(&watch_ctxs[i].hit_count, 0);
    }
    mutex_unlock(&watch_param_mutex);

    return ret;
}

void watch_clear_all(void)
{
    int i;

    mutex_lock(&watch_param_mutex);
    raw_hwwp_del(0);
    watch_sync_callbacks();
    synchronize_rcu();

    for (i = 0; i < MAX_RAW_WP; i++) {
        WRITE_ONCE(watch_ctxs[i].active, false);
        WRITE_ONCE(watch_ctxs[i].pid, 0);
        WRITE_ONCE(watch_ctxs[i].watch_addr, 0);
        WRITE_ONCE(watch_ctxs[i].bp_type, 0);
        WRITE_ONCE(watch_ctxs[i].log_limit, 0);
        WRITE_ONCE(watch_ctxs[i].flags, 0);
        atomic_set(&watch_ctxs[i].hit_count, 0);
    }
    mutex_unlock(&watch_param_mutex);

    watch_ring_reset();
}

int watch_read_kernel(void *buf)
{
    WATCH_READ_REQ *kreq = (WATCH_READ_REQ *)buf;
    unsigned int count = 0;
    unsigned long flags;

    memset(kreq, 0, sizeof(*kreq));

    raw_spin_lock_irqsave(&watch_ring_lock, flags);
    while (watch_ring_tail != watch_ring_head && count < WATCH_BATCH_MAX) {
        kreq->events[count++] = watch_ring[watch_ring_tail & WATCH_RING_MASK];
        watch_ring_tail++;
    }
    raw_spin_unlock_irqrestore(&watch_ring_lock, flags);

    kreq->count = count;
    return 0;
}

/* ---- 内部生命周期(由 hwbp_shadow.c 调)---- */

void watch_logger_init(void)
{
    memset(watch_ring, 0, sizeof(watch_ring));
    watch_ring_head = 0;
    watch_ring_tail = 0;
    memset(watch_ctxs, 0, sizeof(watch_ctxs));
}

void watch_logger_exit(void)
{
    int i;

    /* clear_all 由 shadow_exit_module 负责;这里只清本地状态 */
    watch_sync_callbacks();
    mutex_lock(&watch_param_mutex);
    for (i = 0; i < MAX_RAW_WP; i++)
        WRITE_ONCE(watch_ctxs[i].active, false);
    mutex_unlock(&watch_param_mutex);
    watch_ring_reset();
}
