/* hwbp_core.c — arm64 执行型硬件断点(BP)底层
 *
 * 一句话:把 dbgbvr2..5_el1 / dbgbcr2..5_el1 这四对寄存器抢过来给业务用,
 * 由 finish_task_switch kretprobe 在调度切换完成后按当前 task
 * 的 tgid 重装载,
 * 命中后 ARM64 的同步异常路径走 debug_fault_info[0].fn,我们改这个钩子
 * 让命中流向 raw_bp_callback。
 *
 * 同步:
 *   bp_table_lock      整张断点表(以及任何 bp_table[*] 的 active 检查)
 *   bm_cpuhp_state     CPUHP_AP_ONLINE_DYN 注册句柄,卸载时清理
 *
 * 配套子系统:hwbp_watch.c 用同一套 finish_task_switch / cpu_pm 钩子。
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/kprobes.h>
#include <linux/cpu_pm.h>
#include <linux/cpuhotplug.h>
#include <linux/smp.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <asm/ptrace.h>
#include <asm/debug-monitors.h>
#include "nbg_ksyms.h"
#include "hwbp_raw.h"
#include "nbg_log.h"
#include "nbg_compat.h"

struct fault_info {
    int  (*fn)(unsigned long, unsigned long, struct pt_regs *);
    int  sig;
    int  code;
    const char *name;
};

static struct fault_info *g_fault_info;
static int (*g_orig_bp_fn)(unsigned long, unsigned long, struct pt_regs *);

/* ==================== 执行断点表 ==================== */

struct bp_slot {
    uint64_t          target_vaddr;
    pid_t             pid;
    raw_bp_callback_t callback;
    void             *priv;
    bool              active;
    bool              retiring;
};

static struct bp_slot   bp_table[MAX_RAW_BP];
static DEFINE_SPINLOCK(bp_table_lock);
static DEFINE_MUTEX(bp_lifecycle_mutex);
static int bp_slot_count = MAX_RAW_BP;

struct bp_cpu_cache {
    unsigned long mask;
    uint64_t addr[MAX_RAW_BP];
};

static DEFINE_PER_CPU(struct bp_cpu_cache, bp_cpu_cache);

/* 调度切换热路径快速短路:
 * finish_task_switch 每秒几千次调用,即便无任何活跃断点,旧实现也要
 * 走两把 spin_lock_irqsave + 8 次 MSR。加一个 atomic 计数器,无活跃
 * 时退化为 1 个 atomic_read(~1ns),把"零开销"做实。
 *
 * 更新规则:raw_hwbp_add 创建新 slot 时 +1,raw_hwbp_del 删 slot 时 -1。
 * update 路径(同 pid+addr 改 callback)不改计数。wp 同理有 wp_active_count。
 *
 * 暴露给 hwbp_watch.c 的 wp_active_count 通过 extern 声明,这样
 * bm_switch_ret 一次读两个计数器决定是否进锁。 */
atomic_t bp_active_count = ATOMIC_INIT(0);   /* hwbp_watch.c 可读 */
extern atomic_t wp_active_count;             /* 定义在 hwbp_watch.c */
static atomic_t bm_bp_debug_samples = ATOMIC_INIT(0);
static atomic_t bm_bp_apply_debug_samples = ATOMIC_INIT(0);
static atomic_t bm_bp_write_debug_samples = ATOMIC_INIT(0);
static atomic_t bm_bp_switch_debug_samples = ATOMIC_INIT(0);

static pid_t raw_hwbp_pid_to_tgid(pid_t pid)
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

#define BP_BCR_VAL  0x1E5UL

#define WRITE_BVRBCR(n, addr, ctrl) do {                    \
    asm volatile("dsb sy");                                  \
    asm volatile("msr dbgbvr" #n "_el1, %0" :: "r"(addr)); \
    asm volatile("msr dbgbcr" #n "_el1, %0" :: "r"(ctrl)); \
    asm volatile("isb");                                     \
} while (0)

#define CLEAR_BVRBCR(n) do {                                \
    asm volatile("dsb sy");                                  \
    asm volatile("msr dbgbcr" #n "_el1, %0" :: "r"(0UL));  \
    asm volatile("msr dbgbvr" #n "_el1, %0" :: "r"(0UL));  \
    asm volatile("isb");                                     \
} while (0)

static void bp_write_slot_cpu(int slot_idx, uint64_t addr)
{
    u64 mdscr;
    int debug_sample;

    switch (RAW_BP_SLOT_BASE + slot_idx) {
    case 2: WRITE_BVRBCR(2, addr, BP_BCR_VAL); break;
    case 3: WRITE_BVRBCR(3, addr, BP_BCR_VAL); break;
    case 4: WRITE_BVRBCR(4, addr, BP_BCR_VAL); break;
    case 5: WRITE_BVRBCR(5, addr, BP_BCR_VAL); break;
    default: return;
    }
    asm volatile("mrs %0, mdscr_el1" : "=r"(mdscr));
    if (!(mdscr & DBG_MDSCR_MDE)) {
        mdscr |= DBG_MDSCR_MDE;
        asm volatile("msr mdscr_el1, %0" :: "r"(mdscr));
        asm volatile("isb");
    }

    debug_sample = atomic_inc_return(&bm_bp_write_debug_samples);
    if (debug_sample <= 32)
        NBG_INFO("bp write cpu=%d slot=%d addr=0x%llx mdscr=0x%llx sample=%d\n",
                 raw_smp_processor_id(), slot_idx,
                 (unsigned long long)addr, (unsigned long long)mdscr,
                 debug_sample);
}

static void bp_clear_slot_cpu(int slot_idx)
{
    switch (RAW_BP_SLOT_BASE + slot_idx) {
    case 2: CLEAR_BVRBCR(2); break;
    case 3: CLEAR_BVRBCR(3); break;
    case 4: CLEAR_BVRBCR(4); break;
    case 5: CLEAR_BVRBCR(5); break;
    default: break;
    }
}

static void bp_maybe_disable_mde_this_cpu(void)
{
    u64 mdscr;

    if (atomic_read(&bp_active_count) != 0 ||
        atomic_read(&wp_active_count) != 0)
        return;
    if (this_cpu_read(bp_cpu_cache.mask))
        return;

    asm volatile("mrs %0, mdscr_el1" : "=r"(mdscr));
    if (mdscr & DBG_MDSCR_MDE) {
        mdscr &= ~DBG_MDSCR_MDE;
        asm volatile("msr mdscr_el1, %0" :: "r"(mdscr));
        asm volatile("isb");
    }
}

void raw_hwbp_clear_slots_this_cpu(void)
{
    struct bp_cpu_cache *cache = this_cpu_ptr(&bp_cpu_cache);
    int i;

    for (i = 0; i < bp_slot_count; i++)
        bp_clear_slot_cpu(i);
    memset(cache, 0, sizeof(*cache));
    bp_maybe_disable_mde_this_cpu();
}

static bool bp_tgid_may_have_hook(pid_t tgid)
{
    int i;

    for (i = 0; i < bp_slot_count; i++) {
        if (READ_ONCE(bp_table[i].active) &&
            !READ_ONCE(bp_table[i].retiring) &&
            READ_ONCE(bp_table[i].pid) == tgid)
            return true;
    }
    return false;
}

static void bp_apply_this_cpu(bool force)
{
    struct bp_cpu_cache *cache = this_cpu_ptr(&bp_cpu_cache);
    uint64_t desired_addr[MAX_RAW_BP] = { 0 };
    unsigned long desired_mask = 0;
    unsigned long active_mask = 0;
    uint64_t first_target_addr = 0;
    pid_t first_target_pid = 0;
    pid_t tgid = current->tgid;
    int i;
    unsigned long irqflags;
    int debug_sample;

    /* Most context switches are between tasks that own no breakpoint.  Once
     * this CPU is already clear, avoid the global lock and all debug-register
     * barriers for that overwhelmingly common path. */
    if (!force && !cache->mask && !bp_tgid_may_have_hook(tgid))
        return;

    /* Keep the table snapshot, hardware writes and per-CPU cache update one
     * local atomic operation.  Otherwise a force-write IPI could interleave
     * after the snapshot and a retiring address could be reinstalled. */
    local_irq_save(irqflags);
    spin_lock(&bp_table_lock);
    for (i = 0; i < bp_slot_count; i++) {
        if (bp_table[i].active && !bp_table[i].retiring) {
            active_mask |= 1UL << i;
            if (first_target_pid == 0) {
                first_target_pid = bp_table[i].pid;
                first_target_addr = bp_table[i].target_vaddr;
            }
        }
        if (bp_table[i].active && !bp_table[i].retiring &&
            bp_table[i].pid == tgid) {
            desired_mask |= 1UL << i;
            desired_addr[i] = bp_table[i].target_vaddr;
        }
    }
    spin_unlock(&bp_table_lock);

    debug_sample = atomic_inc_return(&bm_bp_apply_debug_samples);
    if (active_mask && debug_sample <= 48)
        NBG_INFO("bp apply cpu=%d force=%d current_tgid=%d current_tid=%d active=0x%lx desired=0x%lx target_pid=%d target=0x%llx sample=%d\n",
                 raw_smp_processor_id(), force ? 1 : 0, tgid, current->pid,
                 active_mask, desired_mask, first_target_pid,
                 (unsigned long long)first_target_addr, debug_sample);

    for (i = 0; i < bp_slot_count; i++) {
        const bool want = !!(desired_mask & (1UL << i));
        const bool have = !!(cache->mask & (1UL << i));

        if (force || want != have || (want && cache->addr[i] != desired_addr[i])) {
            if (want)
                bp_write_slot_cpu(i, desired_addr[i]);
            else
                bp_clear_slot_cpu(i);
        }
        cache->addr[i] = desired_addr[i];
    }
    cache->mask = desired_mask;
    if (!desired_mask)
        bp_maybe_disable_mde_this_cpu();
    local_irq_restore(irqflags);
}

static void bp_reapply_this_cpu(void)
{
    /* hw_breakpoint_thread_switch() runs before finish_task_switch() and may
     * have restored a perf/ptrace breakpoint for the incoming thread.  The
     * per-CPU cache only describes our last write, so it cannot prove that the
     * physical DBGBVR/DBGBCR registers still contain that value.  This matters
     * especially when switching between two threads in the same tgid: the
     * desired table snapshot is unchanged and the old cached path skipped every
     * MSR, leaving the other owner's breakpoint installed.
     *
     * Force the write after each relevant task switch.  bm_switch_ret() still
     * takes the zero-active fast path, and non-target tasks are cleared here,
     * so the extra register writes are limited to periods with live raw hooks. */
    bp_apply_this_cpu(true);
}

static void bp_force_write_smp(void *info)
{
    (void)info;
    bp_apply_this_cpu(true);
}

NBG_NO_CFI
static int bm_bp_entry(unsigned long addr, unsigned long esr, struct pt_regs *regs)
{
    uint64_t pc = instruction_pointer(regs);
    int i;
    int debug_sample = 0;
    unsigned long flags;

    if (current && bp_tgid_may_have_hook(current->tgid))
        debug_sample = atomic_inc_return(&bm_bp_debug_samples);

    spin_lock_irqsave(&bp_table_lock, flags);
    for (i = 0; i < bp_slot_count; i++) {
        if (!bp_table[i].active)
            continue;
        if (bp_table[i].target_vaddr != pc)
            continue;
        if (bp_table[i].pid != current->tgid)
            continue;
        if (bp_table[i].callback) {
            raw_bp_callback_t cb = bp_table[i].callback;
            void *priv = bp_table[i].priv;

            if (debug_sample > 0 && debug_sample <= 16)
                NBG_INFO("bp dispatch pid=%d tid=%d pc=0x%llx addr=0x%lx sample=%d\n",
                         current->tgid, current->pid,
                         (unsigned long long)pc, addr, debug_sample);

            /* Publish the callback lifetime before dropping bp_table_lock.
             * shadow_del_hook() removes the raw slot and then waits for an RCU
             * grace period before the static context can be reset/reused. */
            rcu_read_lock();
            spin_unlock_irqrestore(&bp_table_lock, flags);
            cb(regs, priv);
            rcu_read_unlock();
            regs->pc += 4;
            return 0;
        }
        spin_unlock_irqrestore(&bp_table_lock, flags);
        regs->pc += 4;
        return 0;
    }
    spin_unlock_irqrestore(&bp_table_lock, flags);
    if (debug_sample > 0 && debug_sample <= 16)
        NBG_INFO("bp miss pid=%d tid=%d pc=0x%llx addr=0x%lx sample=%d\n",
                 current ? current->tgid : 0, current ? current->pid : 0,
                 (unsigned long long)pc, addr, debug_sample);
    {
        /* READ_ONCE 防 raw_hwbp_exit 中途把 fn 改回原值产生撕裂读 */
        int (*orig)(unsigned long, unsigned long, struct pt_regs *) =
            READ_ONCE(g_orig_bp_fn);
        return orig ? orig(addr, esr, regs) : 0;
    }
}

/* 前向声明 watchpoint 函数 — 已在 hwbp.h 声明,这里删掉重复 extern */

static int bm_switch_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int debug_sample;

    (void)ri;
    (void)regs;

    /* 快速短路:无任何活跃 BP/WP 时直接返回,避免每次调度切换都加锁
     * + 访问调试寄存器。这里必须是 finish_task_switch 的返回回调:
     * perf_event_task_sched_in() 会在该函数内部恢复目标线程的 perf
     * 硬件断点。kprobe post_handler 只在函数首条指令后运行,写得过早,
     * 会被后面的 perf 再次覆盖。 */
    if (atomic_read(&bp_active_count) == 0 &&
        atomic_read(&wp_active_count) == 0 &&
        !this_cpu_read(bp_cpu_cache.mask))
        return 0;

    debug_sample = atomic_inc_return(&bm_bp_switch_debug_samples);
    if (debug_sample <= 48)
        NBG_INFO("bp switch cpu=%d current_tgid=%d current_tid=%d active=%d cache=0x%lx sample=%d\n",
                 raw_smp_processor_id(), current->tgid, current->pid,
                 atomic_read(&bp_active_count),
                 this_cpu_read(bp_cpu_cache.mask), debug_sample);

    if (atomic_read(&bp_active_count) != 0 ||
        this_cpu_read(bp_cpu_cache.mask))
        bp_reapply_this_cpu();
    if (atomic_read(&wp_active_count) != 0)
        wp_apply_this_cpu();

    return 0;
}

static struct kretprobe bm_switch_krp = {
    .handler   = bm_switch_ret,
    .maxactive = 64,
};
/* finish_task_switch 在不同编译选项下经常被 constprop / isra,候选名比较长 */
static const char * const finish_task_switch_cands[] = {
    "finish_task_switch",
    "finish_task_switch.isra.0",
    "finish_task_switch.isra",
    "finish_task_switch.constprop.0",
    NULL
};

static int bm_cpu_pm_cb(struct notifier_block *nb, unsigned long cmd, void *v)
{
    if (cmd == CPU_PM_EXIT || cmd == CPU_CLUSTER_PM_EXIT) {
        raw_hwbp_rearm_all();
        raw_hwwp_rearm_all();
    }
    return NOTIFY_OK;
}

static struct notifier_block bm_cpu_pm_nb = {
    .notifier_call = bm_cpu_pm_cb,
};
static bool bm_cpu_pm_registered;

static int bm_cpuhp_online(unsigned int cpu)
{
    raw_hwbp_rearm_all();
    raw_hwwp_rearm_all();
    return 0;
}

/* CPU offline 前清掉本 CPU 的 dbg 寄存器,避免该 CPU 带着残留状态下线
 * 后被某些 SoC 的 PSCI 路径误判。online 时 bm_cpuhp_online 会重装载。 */
static int bm_cpuhp_offline(unsigned int cpu)
{
    raw_hwbp_clear_slots_this_cpu();
    raw_hwwp_clear_slots_this_cpu();
    return 0;
}

static enum cpuhp_state bm_cpuhp_state = CPUHP_INVALID;

/* ==================== 公开接口 ==================== */

static int raw_hwbp_add_mode(struct raw_bp_req *req, bool replace_existing)
{
    int i, slot = -1;
    unsigned long flags;

    if (!req || !req->target_vaddr || !req->callback)
    {
        NBG_FAIL_CODE(2001, -EINVAL);
        return -EINVAL;
    }

    mutex_lock(&bp_lifecycle_mutex);
    spin_lock_irqsave(&bp_table_lock, flags);
    for (i = 0; i < bp_slot_count; i++) {
        if (bp_table[i].active && bp_table[i].pid == req->pid &&
            bp_table[i].target_vaddr == req->target_vaddr) {
            if (!replace_existing) {
                spin_unlock_irqrestore(&bp_table_lock, flags);
                mutex_unlock(&bp_lifecycle_mutex);
                return -EEXIST;
            }
            bp_table[i].callback = req->callback;
            bp_table[i].priv     = req->priv;
            spin_unlock_irqrestore(&bp_table_lock, flags);
            nbg_on_each_cpu(bp_force_write_smp, NULL, 1);
            mutex_unlock(&bp_lifecycle_mutex);
            return 0;
        }
    }
    for (i = 0; i < bp_slot_count; i++) {
        if (!bp_table[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        spin_unlock_irqrestore(&bp_table_lock, flags);
        NBG_FAIL_CODE(2002, -ENOSPC);
        mutex_unlock(&bp_lifecycle_mutex);
        return -ENOSPC;
    }
    bp_table[slot].pid          = req->pid;
    bp_table[slot].target_vaddr = req->target_vaddr;
    bp_table[slot].callback     = req->callback;
    bp_table[slot].priv         = req->priv;
    bp_table[slot].retiring     = false;
    WRITE_ONCE(bp_table[slot].active, true);
    spin_unlock_irqrestore(&bp_table_lock, flags);

    /* 更新短路计数器 (无锁) */
    atomic_inc(&bp_active_count);

    nbg_on_each_cpu(bp_force_write_smp, NULL, 1);
    mutex_unlock(&bp_lifecycle_mutex);
    return 0;
}

int raw_hwbp_add(struct raw_bp_req *req)
{
    return raw_hwbp_add_mode(req, true);
}

int raw_hwbp_add_exclusive(struct raw_bp_req *req)
{
    return raw_hwbp_add_mode(req, false);
}

int raw_hwbp_add_pair_exclusive(struct raw_bp_req *first,
                                struct raw_bp_req *second)
{
    int i, slots[2] = { -1, -1 }, free_count = 0;
    unsigned long flags;

    if (!first || !second || first->pid <= 0 ||
        first->pid != second->pid || !first->target_vaddr ||
        !second->target_vaddr || first->target_vaddr == second->target_vaddr ||
        !first->callback || !second->callback)
        return -EINVAL;

    mutex_lock(&bp_lifecycle_mutex);
    spin_lock_irqsave(&bp_table_lock, flags);
    for (i = 0; i < bp_slot_count; i++) {
        if (bp_table[i].active && bp_table[i].pid == first->pid &&
            (bp_table[i].target_vaddr == first->target_vaddr ||
             bp_table[i].target_vaddr == second->target_vaddr)) {
            spin_unlock_irqrestore(&bp_table_lock, flags);
            mutex_unlock(&bp_lifecycle_mutex);
            return -EEXIST;
        }
        if (!bp_table[i].active && free_count < 2)
            slots[free_count++] = i;
    }
    if (free_count != 2) {
        spin_unlock_irqrestore(&bp_table_lock, flags);
        mutex_unlock(&bp_lifecycle_mutex);
        return -ENOSPC;
    }

    bp_table[slots[0]].pid = first->pid;
    bp_table[slots[0]].target_vaddr = first->target_vaddr;
    bp_table[slots[0]].callback = first->callback;
    bp_table[slots[0]].priv = first->priv;
    bp_table[slots[0]].retiring = false;
    bp_table[slots[1]].pid = second->pid;
    bp_table[slots[1]].target_vaddr = second->target_vaddr;
    bp_table[slots[1]].callback = second->callback;
    bp_table[slots[1]].priv = second->priv;
    bp_table[slots[1]].retiring = false;
    WRITE_ONCE(bp_table[slots[0]].active, true);
    WRITE_ONCE(bp_table[slots[1]].active, true);
    spin_unlock_irqrestore(&bp_table_lock, flags);

    atomic_add(2, &bp_active_count);
    nbg_on_each_cpu(bp_force_write_smp, NULL, 1);
    mutex_unlock(&bp_lifecycle_mutex);
    return 0;
}


int raw_hwbp_del_pid(pid_t pid, uint64_t target_vaddr)
{
    int i, found = 0;
    bool selected[MAX_RAW_BP] = { false };
    unsigned long flags;

    mutex_lock(&bp_lifecycle_mutex);
    spin_lock_irqsave(&bp_table_lock, flags);
    for (i = 0; i < bp_slot_count; i++) {
        if (!bp_table[i].active)
            continue;
        if (pid > 0 && bp_table[i].pid != pid)
            continue;
        if (target_vaddr && bp_table[i].target_vaddr != target_vaddr)
            continue;
        if (bp_table[i].retiring)
            continue;
        bp_table[i].retiring = true;
        selected[i] = true;
        found++;
    }
    spin_unlock_irqrestore(&bp_table_lock, flags);

    if (found) {
        /* 同步减少短路计数器 */
        atomic_sub(found, &bp_active_count);
        /* 删除执行断点必须等待所有 CPU 的 debug 寄存器都清完再返回。
         * worldTrace 是热点 LDR，如果这里异步清理，用户层已经认为断点关闭，
         * 目标线程却仍可能继续触发一小段时间，表现为周期性掉帧/卡顿。 */
        nbg_on_each_cpu(bp_force_write_smp, NULL, 1);
        /* A stale, already-taken debug exception still sees the retiring
         * entry and can emulate the skipped instruction.  Only clear its
         * callback/context after every such handler has returned. */
        synchronize_rcu();

        spin_lock_irqsave(&bp_table_lock, flags);
        for (i = 0; i < bp_slot_count; i++) {
            if (selected[i])
                memset(&bp_table[i], 0, sizeof(bp_table[i]));
        }
        spin_unlock_irqrestore(&bp_table_lock, flags);
    }

    mutex_unlock(&bp_lifecycle_mutex);
    return found > 0 ? 0 : -ENOENT;
}

int raw_hwbp_del_pair_pid(pid_t pid, uint64_t first_vaddr,
                          uint64_t second_vaddr)
{
    int i, found = 0;
    bool selected[MAX_RAW_BP] = { false };
    unsigned long flags;

    if (pid <= 0 || !first_vaddr || !second_vaddr ||
        first_vaddr == second_vaddr)
        return -EINVAL;

    mutex_lock(&bp_lifecycle_mutex);
    spin_lock_irqsave(&bp_table_lock, flags);
    for (i = 0; i < bp_slot_count; i++) {
        if (!bp_table[i].active || bp_table[i].pid != pid ||
            bp_table[i].retiring ||
            (bp_table[i].target_vaddr != first_vaddr &&
             bp_table[i].target_vaddr != second_vaddr))
            continue;
        bp_table[i].retiring = true;
        selected[i] = true;
        found++;
    }
    spin_unlock_irqrestore(&bp_table_lock, flags);

    if (found) {
        atomic_sub(found, &bp_active_count);
        nbg_on_each_cpu(bp_force_write_smp, NULL, 1);
        synchronize_rcu();
        spin_lock_irqsave(&bp_table_lock, flags);
        for (i = 0; i < bp_slot_count; i++) {
            if (selected[i])
                memset(&bp_table[i], 0, sizeof(bp_table[i]));
        }
        spin_unlock_irqrestore(&bp_table_lock, flags);
    }
    mutex_unlock(&bp_lifecycle_mutex);
    return found ? 0 : -ENOENT;
}

int raw_hwbp_del(uint64_t target_vaddr)
{
    return raw_hwbp_del_pid(0, target_vaddr);
}

void raw_hwbp_clear_all(void)
{
    raw_hwbp_del(0);
}

void raw_hwbp_rearm_all(void)
{
    bp_apply_this_cpu(true);
}

bool raw_hwbp_has_pid(pid_t pid)
{
    int i;
    unsigned long flags;
    bool found = false;
    pid_t tgid = raw_hwbp_pid_to_tgid(pid);

    spin_lock_irqsave(&bp_table_lock, flags);
    for (i = 0; i < bp_slot_count; i++) {
        if (bp_table[i].active && !bp_table[i].retiring &&
            (bp_table[i].pid == pid || bp_table[i].pid == tgid)) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&bp_table_lock, flags);
    return found;
}

uint32_t raw_hwbp_snapshot(pid_t pid, uint64_t *addresses,
                           uint32_t capacity)
{
    uint32_t copied = 0;
    int i;
    unsigned long flags;
    pid_t tgid;

    if (!addresses || !capacity)
        return 0;
    tgid = raw_hwbp_pid_to_tgid(pid);

    spin_lock_irqsave(&bp_table_lock, flags);
    for (i = 0; i < bp_slot_count && copied < capacity; i++) {
        if (!bp_table[i].active || bp_table[i].retiring)
            continue;
        if (bp_table[i].pid != pid && bp_table[i].pid != tgid)
            continue;
        addresses[copied++] = bp_table[i].target_vaddr;
    }
    spin_unlock_irqrestore(&bp_table_lock, flags);
    return copied;
}

/* ==================== 初始化/清理 ==================== */

int raw_hwbp_init(void)
{
    int ret;
    unsigned long fi_addr;
    uint64_t dfr0;
    int implemented;

    memset(bp_table, 0, sizeof(bp_table));

    asm volatile("mrs %0, id_aa64dfr0_el1" : "=r"(dfr0));
    implemented = (int)((dfr0 >> 12) & 0xFU) + 1;
    bp_slot_count = implemented > RAW_BP_SLOT_BASE
        ? implemented - RAW_BP_SLOT_BASE : 0;
    if (bp_slot_count > MAX_RAW_BP)
        bp_slot_count = MAX_RAW_BP;
    if (bp_slot_count <= 0) {
        NBG_FAIL_CODE(2014, -ENOSPC);
        return -ENOSPC;
    }

    {
        static const char * const fi_cands[] = {
            "debug_fault_info", "debug_fault_info_table", NULL
        };
        fi_addr = resolve_first_symbol(fi_cands);
    }
    if (!fi_addr)
    {
        NBG_FAIL_CODE(2011, -ENOENT);
        return -ENOENT;
    }
    g_fault_info  = (struct fault_info *)fi_addr;
    g_orig_bp_fn  = READ_ONCE(g_fault_info[0].fn);
    WRITE_ONCE(g_fault_info[0].fn, bm_bp_entry);

    /* 必须在 finish_task_switch 返回时重装。入口 kprobe 的
     * post_handler 早于函数内的 perf_event_task_sched_in(),会被目标
     * 线程已有的 perf 断点再次覆盖。 */
    ret = nbg_register_kretprobe_named(&bm_switch_krp,
                                       finish_task_switch_cands, NULL);
    if (ret) {
        g_fault_info[0].fn = g_orig_bp_fn;
        NBG_FAIL_CODE(2012, ret);
        return ret;
    }

    ret = cpu_pm_register_notifier(&bm_cpu_pm_nb);
    if (ret == 0)
        bm_cpu_pm_registered = true;
    else
        NBG_FAIL_CODE(2015, ret);

    /* 同时注册 online 和 offline 回调,保证 CPU hot-plug 时 dbg 寄存器
     * 状态一致(online 重装载,offline 清干净)。 */
    ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN, "cpu:pm",
                                     bm_cpuhp_online, bm_cpuhp_offline);
    if (ret > 0)
        bm_cpuhp_state = ret;
    else if (ret < 0)
        NBG_FAIL_CODE(2013, ret);

    return 0;
}

/* IPI 用的空函数:把所有 CPU"踢"出当前异常路径,保证它们走完 bm_bp_entry
 * 才能进入 idle/继续运行。nbg_on_each_cpu(..., wait=1) 会等所有 CPU ack。 */
static void do_nothing_ipi(void *info) { (void)info; }

void raw_hwbp_exit(void)
{
    /* 先撤业务状态并同步清掉所有 CPU 的硬件 BP 槽。
     * raw_hwbp_clear_all() 内部的 on_each_cpu wait=0 偏向运行期性能;
     * module_exit 这里必须 wait=1,否则某个 CPU 可能带着旧 BP 槽进入
     * 我们已经恢复/释放的 fault handler 路径。 */
    raw_hwbp_clear_all();
    nbg_on_each_cpu(bp_force_write_smp, NULL, 1);

    if (bm_cpuhp_state != CPUHP_INVALID) {
        cpuhp_remove_state_nocalls(bm_cpuhp_state);
        bm_cpuhp_state = CPUHP_INVALID;
    }

    if (bm_cpu_pm_registered) {
        cpu_pm_unregister_notifier(&bm_cpu_pm_nb);
        bm_cpu_pm_registered = false;
    }

    if (bm_switch_krp.kp.addr) {
        unregister_kretprobe(&bm_switch_krp);
        bm_switch_krp.kp.addr = NULL;
    }

    /* HWBP-3 修复:还原 debug_fault_info[0].fn 时必须等所有 CPU 走完
     * in-flight 的 bm_bp_entry,否则 module_exit 返回后内核会释放本
     * 模块 .text,正在 bm_bp_entry 末尾 ret 到调用方的 CPU 会跳到已
     * unmap 的代码段 → panic。
     *
     * 顺序:
     *   1) WRITE_ONCE 还原原 fn,新进入断点的 CPU 走原 handler。
     *   2) nbg_on_each_cpu(do_nothing, wait=1) 强制每个 CPU 跑一次空 IPI
     *      函数 — IPI 处理时 CPU 必须已离开异常上下文返回 user/idle,
     *      此后保证"再没有 CPU 持指针指向我们的代码段"。
     *
     * 注:不用 synchronize_rcu_expedited,该符号在部分魔改内核(KSU/
     * SukiSU)被拒导,而 nbg_on_each_cpu(wait=1) 在本场景下语义已经足够。 */
    if (g_fault_info && g_orig_bp_fn) {
        WRITE_ONCE(g_fault_info[0].fn, g_orig_bp_fn);
        nbg_on_each_cpu(do_nothing_ipi, NULL, 1);
    }
    g_fault_info = NULL;
    g_orig_bp_fn = NULL;
}
