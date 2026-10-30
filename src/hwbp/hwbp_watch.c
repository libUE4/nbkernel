/* hwbp_watch.c — arm64 观察点(WP)底层
 *
 * 一句话:把 dbgwvr0..3_el1 / dbgwcr0..3_el1 抢来按 (mm,addr,len,rw) 装载,
 * 命中走 watchpoint_handler 的同步异常路径(我们替它的 fault_info[i].fn)。
 *
 * 关键设计:
 *   - 命中后只 disarm 本 CPU 的对应槽,然后 schedule_delayed_work 在
 *     WP_REARM_DELAY_MS 后再 armed=true,避免同一 store 因 abort 重执行
 *     再次触发(ARM64 watchpoint 是 "before" 异常)
 *   - 不 +4 跳过 store:让原指令 ERET 后正常重执行,数据正确写入,AC
 *     "写已知值再读回"测不出来
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/smp.h>
#include <linux/ptrace.h>
#include <asm/ptrace.h>
#include <asm/debug-monitors.h>
#include "nbg_ksyms.h"
#include "hwbp_raw.h"
#include "nbg_log.h"
#include "nbg_compat.h"

/* rearm 延迟:命中后多久把硬件槽再装回来。
 *
 * 为什么不能 0:ARM64 watchpoint 是 "before" 异常,store 还没提交。
 * 我们 disarm 当前 CPU 让 ERET 后 store 重新执行,如果立即 rearm,
 * 重新执行的 store 又会触发 WP → 死循环。必须等 store 真正 commit
 * 后再 rearm。
 *
 * 为什么不能太大:游戏热路径上一关一段时间,游戏帧率会被打到 1/N
 * 倍(N = 1000ms / 延迟),50ms 就会让游戏从 60Hz 降到 ~15Hz 看着卡死。
 *
 * 5ms 是经验值:store commit 通常 < 1us,5ms 远超出;同时 5ms < 一帧
 * 16.6ms,游戏渲染基本无感。 */
#define WP_REARM_DELAY_MS  5

struct wp_slot {
    uint64_t          wvr;
    uint64_t          wcr;
    uint64_t          watch_addr;
    pid_t             pid;
    raw_wp_callback_t callback;
    void             *priv;
    bool              active;
    bool              retiring;
    bool              armed;
    bool              skip_store;     /* WP_FLAG_SKIP_STORE:命中后 PC+=4 跳过 */
    struct delayed_work rearm_work;
    int               slot_idx;
    /* HWBP-10:多核同地址命中合并。8 核同时写同地址会触发 8 次 WP 异常,
     * 旧实现每个 CPU 都 disarm + 排 1 个 delayed_work + 5ms 后广播 1 次
     * IPI re-arm,即 8×IPI 冗余。
     * cmpxchg 抢到 0->1 的那个 CPU 负责完整的 disarm + 排 work + 调 cb;
     * 输的 CPU 只 push event 进 ring。rearm work 跑完后清零。 */
    atomic_t          rearm_in_flight;
};

static struct wp_slot   wp_table[MAX_RAW_WP];
static DEFINE_SPINLOCK(wp_table_lock);
static DEFINE_MUTEX(wp_lifecycle_mutex);
static int wp_slot_count = MAX_RAW_WP;

/* 与 hwbp_core.c 的 bp_active_count 配对,用于 bm_switch_ret 快速短路。
 * 无活跃 wp 时调度切换路径不进锁,~1ns 开销。 */
atomic_t wp_active_count = ATOMIC_INIT(0);
extern atomic_t bp_active_count;

static pid_t raw_hwwp_pid_to_tgid(pid_t pid)
{
    struct task_struct *task;
    pid_t tgid = pid;

    if (pid <= 0)
        return pid;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        tgid = task->tgid;
    rcu_read_unlock();
    return tgid;
}

static int (*g_orig_wp_fn)(unsigned long, unsigned long, struct pt_regs *);
static int g_wp_idx = -1;
static struct fault_info *g_wp_fault_info;

struct fault_info {
    int  (*fn)(unsigned long, unsigned long, struct pt_regs *);
    int  sig;
    int  code;
    const char *name;
};

bool raw_hwwp_has_pid(pid_t pid)
{
    int i;
    unsigned long flags;
    bool found = false;
    pid_t tgid = raw_hwwp_pid_to_tgid(pid);

    spin_lock_irqsave(&wp_table_lock, flags);
    for (i = 0; i < wp_slot_count; i++) {
        if (wp_table[i].active && !wp_table[i].retiring &&
            (wp_table[i].pid == pid || wp_table[i].pid == tgid)) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&wp_table_lock, flags);
    return found;
}

uint32_t raw_hwwp_snapshot(pid_t pid, uint64_t *addresses,
                           uint32_t capacity)
{
    uint32_t copied = 0;
    int i;
    unsigned long flags;
    pid_t tgid;

    if (!addresses || !capacity)
        return 0;
    tgid = raw_hwwp_pid_to_tgid(pid);

    spin_lock_irqsave(&wp_table_lock, flags);
    for (i = 0; i < wp_slot_count && copied < capacity; i++) {
        if (!wp_table[i].active || wp_table[i].retiring)
            continue;
        if (wp_table[i].pid != pid && wp_table[i].pid != tgid)
            continue;
        /* WVR is the hardware's eight-byte granule base. */
        addresses[copied++] = wp_table[i].wvr;
    }
    spin_unlock_irqrestore(&wp_table_lock, flags);
    return copied;
}

static void wp_force_write_smp(void *info);   /* 前向声明 */

static void wp_rearm_work_fn(struct work_struct *work)
{
    struct wp_slot *slot = container_of(work, struct wp_slot, rearm_work.work);
    unsigned long flags;
    bool active;
    bool retry = false;

    spin_lock_irqsave(&wp_table_lock, flags);
    active = slot->active && !slot->retiring;
    if (active)
        slot->armed = true;
    spin_unlock_irqrestore(&wp_table_lock, flags);

    /* 关键:仅设软标记不够 — CPU-bound 热循环里没有任务调度,
     * finish_task_switch 钩子永远不被调,wp_apply_this_cpu 不会
     * 跑,硬件 dbg 寄存器永远 disarmed,WP 命中 1 次后失效。
     * 必须广播 IPI 到所有 CPU,直接重写硬件 dbg 寄存器。 */
    if (active)
        nbg_on_each_cpu(wp_force_write_smp, NULL, 1);

    /* A CPU can finish its IPI, return to user mode and hit this watchpoint
     * again while another CPU is still acknowledging the same broadcast.  In
     * that window the old owner flag is still one, so the new hit deliberately
     * does not queue work and clears armed instead.  Detect that loss here and
     * requeue this same work before releasing ownership. */
    spin_lock_irqsave(&wp_table_lock, flags);
    if (slot->active && !slot->retiring && !slot->armed)
        retry = true;
    else
        atomic_set(&slot->rearm_in_flight, 0);
    spin_unlock_irqrestore(&wp_table_lock, flags);

    if (retry)
        mod_delayed_work(system_wq, &slot->rearm_work,
                         msecs_to_jiffies(WP_REARM_DELAY_MS));
}

/* ARM64 watchpoint 的 WCR.BAS 字段只有 8 bit,描述同一个 8 字节单元内
 * 监控哪些字节。监控范围必须落在一个 8-byte 行内:
 *   bp_len=1  : 任意对齐 OK
 *   bp_len=2  : addr 必须 2-byte 对齐 且 (addr&7)+2 <= 8
 *   bp_len=4  : addr 必须 4-byte 对齐 且 (addr&7)+4 <= 8
 *   bp_len=8  : addr 必须 8-byte 对齐
 * 跨 8B 边界(如 bp_len=4 addr=...6)会让 BAS 溢出非法位,行为不可预测。
 * 调用方需自己保证对齐;wp_validate_alignment 提供给上层 raw_hwwp_add
 * 用,把"静默错位"提升为显式 -EINVAL。 */
int wp_validate_alignment(uint32_t bp_len, uint64_t addr)
{
    uint32_t offset;
    if (bp_len != 1 && bp_len != 2 && bp_len != 4 && bp_len != 8)
        return -EINVAL;
    offset = addr & 0x7;
    /* 必须 bp_len 对齐 */
    if (bp_len == 2 && (addr & 0x1)) return -EINVAL;
    if (bp_len == 4 && (addr & 0x3)) return -EINVAL;
    if (bp_len == 8 && (addr & 0x7)) return -EINVAL;
    /* 不能跨 8B 行 */
    if (offset + bp_len > 8) return -EINVAL;
    return 0;
}

static uint64_t wp_make_wcr(uint32_t bp_type, uint32_t bp_len, uint64_t addr)
{
    uint64_t wcr = 0;
    uint32_t bas_mask;
    uint32_t offset = addr & 0x7;

    /* 调用前 wp_validate_alignment 已保证 offset+bp_len <= 8,BAS 不会溢出。 */
    if (bp_len == 1)
        bas_mask = 0x1 << offset;
    else if (bp_len == 2)
        bas_mask = 0x3 << offset;
    else if (bp_len == 4)
        bas_mask = 0xF << offset;
    else
        bas_mask = 0xFF;            /* bp_len=8 必然 8B 对齐 offset=0 */
    bas_mask &= 0xFF;               /* 保险:截到合法 8 bit */

    wcr |= ((uint64_t)bas_mask << 5);
    wcr |= ((uint64_t)(bp_type & 0x3) << 3);
    wcr |= (2UL << 1);
    wcr |= 1UL;

    return wcr;
}

#define WRITE_WVRWCR(n, addr, ctrl) do {                      \
    asm volatile("dsb sy");                                   \
    asm volatile("msr dbgwvr" #n "_el1, %0" :: "r"(addr));   \
    asm volatile("msr dbgwcr" #n "_el1, %0" :: "r"(ctrl));   \
    asm volatile("isb");                                       \
} while (0)

#define CLEAR_WVRWCR(n) do {                                  \
    asm volatile("dsb sy");                                   \
    asm volatile("msr dbgwcr" #n "_el1, %0" :: "r"(0UL));    \
    asm volatile("msr dbgwvr" #n "_el1, %0" :: "r"(0UL));    \
    asm volatile("isb");                                       \
} while (0)

static void wp_write_slot_cpu(int idx, uint64_t wvr, uint64_t wcr)
{
    u64 mdscr;

    switch (idx) {
    case 0: WRITE_WVRWCR(0, wvr, wcr); break;
    case 1: WRITE_WVRWCR(1, wvr, wcr); break;
    case 2: WRITE_WVRWCR(2, wvr, wcr); break;
    case 3: WRITE_WVRWCR(3, wvr, wcr); break;
    default: return;
    }
    asm volatile("mrs %0, mdscr_el1" : "=r"(mdscr));
    if (!(mdscr & DBG_MDSCR_MDE)) {
        mdscr |= DBG_MDSCR_MDE;
        asm volatile("msr mdscr_el1, %0" :: "r"(mdscr));
        asm volatile("isb");
    }
}

static void wp_clear_slot_cpu(int idx)
{
    switch (idx) {
    case 0: CLEAR_WVRWCR(0); break;
    case 1: CLEAR_WVRWCR(1); break;
    case 2: CLEAR_WVRWCR(2); break;
    case 3: CLEAR_WVRWCR(3); break;
    }
}

static void wp_maybe_disable_mde_this_cpu(void)
{
    u64 mdscr;

    if (atomic_read(&wp_active_count) != 0 ||
        atomic_read(&bp_active_count) != 0)
        return;

    asm volatile("mrs %0, mdscr_el1" : "=r"(mdscr));
    if (mdscr & DBG_MDSCR_MDE) {
        mdscr &= ~DBG_MDSCR_MDE;
        asm volatile("msr mdscr_el1, %0" :: "r"(mdscr));
        asm volatile("isb");
    }
}

void raw_hwwp_clear_slots_this_cpu(void)
{
    int i;
    for (i = 0; i < wp_slot_count; i++)
        wp_clear_slot_cpu(i);
    wp_maybe_disable_mde_this_cpu();
}

void wp_apply_this_cpu(void)
{
    int i;
    pid_t tgid = current->tgid;
    unsigned long flags;

    spin_lock_irqsave(&wp_table_lock, flags);
    for (i = 0; i < wp_slot_count; i++) {
        if (wp_table[i].active && !wp_table[i].retiring &&
            wp_table[i].armed &&
            wp_table[i].pid == tgid)
            wp_write_slot_cpu(i, wp_table[i].wvr, wp_table[i].wcr);
        else
            wp_clear_slot_cpu(i);
    }
    spin_unlock_irqrestore(&wp_table_lock, flags);
    wp_maybe_disable_mde_this_cpu();
}

static void wp_force_write_smp(void *info)
{
    int i;
    unsigned long flags;

    spin_lock_irqsave(&wp_table_lock, flags);
    for (i = 0; i < wp_slot_count; i++) {
        if (wp_table[i].active && !wp_table[i].retiring &&
            wp_table[i].armed &&
            wp_table[i].pid == current->tgid)
            wp_write_slot_cpu(i, wp_table[i].wvr, wp_table[i].wcr);
        else
            wp_clear_slot_cpu(i);
    }
    spin_unlock_irqrestore(&wp_table_lock, flags);
    wp_maybe_disable_mde_this_cpu();
}

NBG_NO_CFI
static int bm_wp_entry(unsigned long addr, unsigned long esr, struct pt_regs *regs)
{
    uint64_t far = addr;
    int i;
    unsigned long flags;
    int (*orig_fn)(unsigned long, unsigned long, struct pt_regs *);

    spin_lock_irqsave(&wp_table_lock, flags);
    for (i = 0; i < wp_slot_count; i++) {
        if (!wp_table[i].active)
            continue;
        if (wp_table[i].pid != current->tgid)
            continue;
        if ((far & ~0x7ULL) != wp_table[i].wvr)
            continue;
        if (wp_table[i].callback) {
            raw_wp_callback_t cb = wp_table[i].callback;
            void *priv = wp_table[i].priv;
            bool skip = wp_table[i].skip_store;
            bool retiring = wp_table[i].retiring;

            if (skip) {
                /* SKIP_STORE:先解锁再调 cb,避免 cb 内部尝试操作 wp_table
                 * (例如自删自加) 造成同把锁递归 → 死锁。 */
                rcu_read_lock();
                spin_unlock_irqrestore(&wp_table_lock, flags);
                cb(regs, far, priv);
                rcu_read_unlock();
                regs->pc += 4;
                return 0;
            }

            /* 默认模式:让原 store 真执行。
             * HWBP-10 多核合并:用 cmpxchg 让"第一个命中的 CPU"独占
             * "排 delayed_work + 广播 IPI 让全核 re-arm" 这些昂贵动作;
             * 但**所有 CPU 都必须本地 disarm 自己的硬件 wp**,否则 ERET
             * 后该 CPU 上的 store 重新执行立刻又触发 → 输家在 5ms 窗口
             * 内无限循环触发,事件爆炸(测试 17 G 表现为期望 4-40 实际 512)。
             *
             * 简而言之:
             *   - disarm 本核硬件 wp     → 赢/输都做(防本核重触发死循环)
             *   - 调 cb 业务回调          → 赢/输都做(push event 进 ring)
             *   - 排 delayed_work + IPI   → 只赢家做(避免 N 个 CPU 排 N 次)
             *
             * 持 wp_table_lock 时本地 disarm 安全;cb 必须解锁后调。 */
            wp_table[i].armed = false;
            wp_clear_slot_cpu(i);   /* 本核 disarm,所有 CPU 都做 */

            /* A stale hardware hit during deletion must still find its
             * callback and disarm locally so the original store can retry.
             * Never queue another delayed re-arm for a retiring slot. */
            if (retiring) {
                rcu_read_lock();
                spin_unlock_irqrestore(&wp_table_lock, flags);
                cb(regs, far, priv);
                rcu_read_unlock();
                return 0;
            }

            if (atomic_cmpxchg(&wp_table[i].rearm_in_flight, 0, 1) == 0) {
                /* 赢家:负责排 rearm work + 调 cb */
                rcu_read_lock();
                spin_unlock_irqrestore(&wp_table_lock, flags);
                cb(regs, far, priv);
                mod_delayed_work(system_wq, &wp_table[i].rearm_work,
                                 msecs_to_jiffies(WP_REARM_DELAY_MS));
                rcu_read_unlock();
            } else {
                /* 输家:只调 cb push event,不重复排 work */
                rcu_read_lock();
                spin_unlock_irqrestore(&wp_table_lock, flags);
                cb(regs, far, priv);
                rcu_read_unlock();
            }
            return 0;
        }
        spin_unlock_irqrestore(&wp_table_lock, flags);
        /* 未命中 callback,但 slot 匹配 -> 透传原 handler。READ_ONCE 防
         * 模块卸载期间 g_orig_wp_fn 被清成 NULL 后还在解引用。 */
        orig_fn = READ_ONCE(g_orig_wp_fn);
        if (!orig_fn) return 0;
        return orig_fn(addr, esr, regs);
    }
    spin_unlock_irqrestore(&wp_table_lock, flags);
    orig_fn = READ_ONCE(g_orig_wp_fn);
    if (!orig_fn) return 0;
    return orig_fn(addr, esr, regs);
}

int raw_hwwp_add(struct raw_wp_req *req)
{
    int i, slot = -1;
    unsigned long flags;
    int align_ret;

    if (!req || !req->watch_addr || !req->callback)
    {
        NBG_FAIL_CODE(2101, -EINVAL);
        return -EINVAL;
    }
    if (g_wp_idx < 0)
    {
        NBG_FAIL_CODE(2102, -ENODEV);
        return -ENODEV;
    }

    /* 拒绝跨 8B 边界的请求,避免 BAS 溢出导致 wp 静默错位/不命中。
     * 上层 wp_validate_alignment 把这一类静默错误提升为 EINVAL,让
     * 用户态注入器立刻看到非法入参,而不是事后调试半天。 */
    align_ret = wp_validate_alignment(req->bp_len, req->watch_addr);
    if (align_ret) {
        NBG_FAIL_CODE(2103, align_ret);
        return align_ret;
    }

    mutex_lock(&wp_lifecycle_mutex);
    spin_lock_irqsave(&wp_table_lock, flags);
    for (i = 0; i < wp_slot_count; i++) {
        if (wp_table[i].active && wp_table[i].pid == req->pid &&
            wp_table[i].watch_addr == req->watch_addr) {
            wp_table[i].wcr        = wp_make_wcr(req->bp_type, req->bp_len, req->watch_addr);
            wp_table[i].callback   = req->callback;
            wp_table[i].priv       = req->priv;
            wp_table[i].skip_store = !!(req->flags & WP_FLAG_SKIP_STORE);
            spin_unlock_irqrestore(&wp_table_lock, flags);
            nbg_on_each_cpu(wp_force_write_smp, NULL, 1);
            mutex_unlock(&wp_lifecycle_mutex);
            return 0;
        }
    }
    for (i = 0; i < wp_slot_count; i++) {
        if (!wp_table[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        spin_unlock_irqrestore(&wp_table_lock, flags);
        NBG_FAIL_CODE(2104, -ENOSPC);
        mutex_unlock(&wp_lifecycle_mutex);
        return -ENOSPC;
    }
    wp_table[slot].armed      = true;
    wp_table[slot].retiring   = false;
    wp_table[slot].pid        = req->pid;
    wp_table[slot].watch_addr = req->watch_addr;
    wp_table[slot].wvr        = req->watch_addr & ~0x7ULL;
    wp_table[slot].wcr        = wp_make_wcr(req->bp_type, req->bp_len, req->watch_addr);
    wp_table[slot].callback   = req->callback;
    wp_table[slot].priv       = req->priv;
    wp_table[slot].skip_store = !!(req->flags & WP_FLAG_SKIP_STORE);
    wp_table[slot].slot_idx   = slot;
    atomic_set(&wp_table[slot].rearm_in_flight, 0);
    INIT_DELAYED_WORK(&wp_table[slot].rearm_work, wp_rearm_work_fn);
    WRITE_ONCE(wp_table[slot].active, true);
    spin_unlock_irqrestore(&wp_table_lock, flags);

    /* 更新短路计数器 (新建 slot 才 +1,update 路径不动) */
    atomic_inc(&wp_active_count);

    nbg_on_each_cpu(wp_force_write_smp, NULL, 1);
    mutex_unlock(&wp_lifecycle_mutex);
    return 0;
}

int raw_hwwp_del_pid(pid_t pid, uint64_t watch_addr)
{
    int i, found = 0;
    unsigned long flags;
    int to_cancel[MAX_RAW_WP];
    int pending_count = 0;

    /* Four-phase retirement:
     *   1) Keep active/callback visible, but set retiring and armed=false.
     *   2) Clear WCR on every CPU and wait for stale exception callbacks.
     *   3) Cancel delayed work after no callback can queue another re-arm.
     *   4) Clear business fields and make the slot reusable.
     *
     * 第 4 步不能用 memset 整块清零，那会破坏 delayed_work 内部状态。
     * timer_list / work_struct 状态清掉,下次 raw_hwwp_add 复用此 slot
     * 又调 INIT_DELAYED_WORK 重新初始化时,中间窗口若有别处尝试访问该
     * work(例如还在 workqueue 链表上的残留指针)就会跳到 NULL 函数。
     * 安全的清法是只清业务字段,delayed_work 本身保持 cancel 后的合法
     * idle 状态,下次 add 直接 INIT 覆盖即可。 */
    mutex_lock(&wp_lifecycle_mutex);
    spin_lock_irqsave(&wp_table_lock, flags);
    for (i = 0; i < wp_slot_count; i++) {
        if (!wp_table[i].active)
            continue;
        if (pid > 0 && wp_table[i].pid != pid)
            continue;
        if (watch_addr && wp_table[i].watch_addr != watch_addr)
            continue;
        if (wp_table[i].retiring)
            continue;
        wp_table[i].retiring = true;
        wp_table[i].armed = false;
        to_cancel[pending_count++] = i;
        found++;
    }
    spin_unlock_irqrestore(&wp_table_lock, flags);

    if (found) {
        atomic_sub(found, &wp_active_count);
        /* Retiring slots remain matchable by stale hardware hits so those
         * handlers can disarm locally and preserve the original instruction. */
        nbg_on_each_cpu(wp_force_write_smp, NULL, 1);
        synchronize_rcu();

        /* A winner that entered before retirement may queue this work at the
         * tail of its RCU section, so cancellation must happen after the grace
         * period rather than before it. */
        for (i = 0; i < pending_count; i++)
            cancel_delayed_work_sync(&wp_table[to_cancel[i]].rearm_work);
    }

    /* 只清业务字段,保留 delayed_work / slot_idx 不动。 */
    spin_lock_irqsave(&wp_table_lock, flags);
    for (i = 0; i < pending_count; i++) {
        int s = to_cancel[i];
        wp_table[s].armed       = false;
        wp_table[s].pid         = 0;
        wp_table[s].watch_addr  = 0;
        wp_table[s].wvr         = 0;
        wp_table[s].wcr         = 0;
        wp_table[s].callback    = NULL;
        wp_table[s].priv        = NULL;
        wp_table[s].skip_store  = false;
        atomic_set(&wp_table[s].rearm_in_flight, 0);
        WRITE_ONCE(wp_table[s].active, false);
        wp_table[s].retiring    = false;
        /* slot_idx/rearm_work remain valid and are initialized on next add. */
    }
    spin_unlock_irqrestore(&wp_table_lock, flags);

    mutex_unlock(&wp_lifecycle_mutex);
    return found > 0 ? 0 : -ENOENT;
}

int raw_hwwp_del(uint64_t watch_addr)
{
    return raw_hwwp_del_pid(0, watch_addr);
}

void raw_hwwp_clear_all(void)
{
    raw_hwwp_del(0);
}

void raw_hwwp_rearm_all(void)
{
    wp_apply_this_cpu();
}

int raw_hwwp_init(void)
{
    unsigned long fi_addr;
    unsigned long wp_handler_addr;
    struct fault_info *g_fault_info;
    uint64_t dfr0;
    int implemented;
    int i;

    memset(wp_table, 0, sizeof(wp_table));

    asm volatile("mrs %0, id_aa64dfr0_el1" : "=r"(dfr0));
    implemented = (int)((dfr0 >> 20) & 0xFU) + 1;
    wp_slot_count = implemented > MAX_RAW_WP ? MAX_RAW_WP : implemented;
    if (wp_slot_count <= 0) {
        NBG_FAIL_CODE(2113, -ENOSPC);
        return -ENOSPC;
    }

    fi_addr = generic_kallsyms_lookup_name("debug_fault_info");
    if (!fi_addr) {
        NBG_FAIL_CODE(2111, -ENOENT);
        return -ENOENT;
    }

    g_fault_info = (struct fault_info *)fi_addr;

    wp_handler_addr = generic_kallsyms_lookup_name("watchpoint_handler");
    if (!wp_handler_addr)
        wp_handler_addr = generic_kallsyms_lookup_name("hw_breakpoint_handler");

    if (wp_handler_addr) {
        for (i = 0; i < 16; i++) {
            if ((unsigned long)g_fault_info[i].fn == wp_handler_addr) {
                g_wp_idx = i;
                g_wp_fault_info = g_fault_info;
                g_orig_wp_fn = READ_ONCE(g_fault_info[i].fn);
                WRITE_ONCE(g_fault_info[i].fn, bm_wp_entry);

                break;
            }
        }
    }

    if (g_wp_idx < 0) {
        NBG_FAIL_CODE(2112, -ENOENT);
        return -ENOENT;
    }

    return 0;
}

static void do_nothing_ipi(void *info) { (void)info; }

void raw_hwwp_exit(void)
{
    /* 与 BP 退出同理:先撤业务状态并等待所有 CPU 清掉硬件 WP 槽,
     * 再恢复 fault handler。否则 module_exit 期间仍有 CPU 可能带着
     * 旧 watchpoint 重新进 bm_wp_entry。 */
    raw_hwwp_clear_all();
    nbg_on_each_cpu(wp_force_write_smp, NULL, 1);

    if (g_wp_idx >= 0 && g_orig_wp_fn && g_wp_fault_info) {
        WRITE_ONCE(g_wp_fault_info[g_wp_idx].fn, g_orig_wp_fn);
        nbg_on_each_cpu(do_nothing_ipi, NULL, 1);
    }

    g_wp_idx = -1;
    g_wp_fault_info = NULL;
    g_orig_wp_fn = NULL;
}
