/* hwbp_shadow.c — Shadow Hook(基于 hwbp_core 的指令仿真层)
 *
 * 思路:用户态拿到目标指令地址 → 我们在那儿放一个执行型断点。命中后
 * 对原指令做轻量解码,然后按 is_rot_hook 选业务逻辑。常见模式:
 *
 *   case 1  跳转改写        regs->pc = target_vaddr + offset
 *   case 2  浮点乘法仿真    SIMD/FP LDR + IEEE754 软浮点乘 → 写回 vregs[Rt]
 *   case 4  弹道补偿        按 SC 偏移连写三个 u32 + 设 v0/v1/v2
 *   case 5  弹道寄存器注入  直接把 custom_value[1] 写入 S/custom_value[0],
 *                           可用 custom_value[2] 按 X30 返回地址过滤调用者
 *   case 8  NZ 射线终点      命中 UInstantHitFireRaycastSubComponent::FireRaycast
 *                           主体,把 X23 指向的射线终点改为目标世界坐标
 *   case 30 RMCN 范围倍率    仿真 LDP S6,S5,[X1,#4]，同时把人物胶囊/盒体
 *                           的持久 geometry 尺寸放大，供后续窄相直接读取。
 *   case 31 DFM 人物高亮     仿真 LDR X8,[X20,#0x700]，对敌方角色
 *                           网格替换轮廓材质并同步渲染标志。
 *   case 32 RMCN 自由视角  仿真 MgrCamera.RenderUpdate 返回前的 LDP，
 *                           并在命中时调用游戏观察者模式接口。
 *   case 34 RMCN 第三人称    默认仿真 RenderUpdate 首指令并记录命中；
 *                           收到一次性状态命令时，尾跳到相机控制器
 *                           ChangeState(First/Third)。
 *   case 35 RMCN 视角同步    仿真 CorrectCmdViewPitchYaw 最终的 STP；
 *                           提交目标 ViewYaw/ViewPitch 到官方命令流。
 *   case 38 RMCN 扩散上下文  仿真 CalculateShootDir 的 FMOV S2,S10；
 *                           缓存官方公式/参数/武器，并在同一调用的
 *                           S0/S1 临时参数上按本发 seed 做逆补偿。
 *   case 40 RMCN 射击输入    仿真 CalculateShootDir 的 FMOV S8,S0，
 *                           在公式入口提交当前 yaw/pitch，并按 W3/W7
 *                           做本次 seed 的散布逆补偿。
 * 所有 case 都假定原指令被 ARM64 硬件断点的 +4 跳过,所以读取原本要
 * load 的值得手动从 [Rn+offset] 读;写入 fpsimd 状态后置
 * TIF_FOREIGN_FPSTATE 让调度路径帮我们 restore。
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/ptrace.h>
#include <linux/seqlock.h>
#include <linux/jiffies.h>
#include <asm/ptrace.h>
#include "nbg_ksyms.h"
#include "memory.h"
#include "hwbp_shadow.h"
#include "nbg_log.h"
#include "nbg_compat.h"

/* ---- shadow hook 槽 ---- */

#define RMCN_RANGE_PAIR_LOAD_INSN 0x2D409426U /* LDP S6,S5,[X1,#4] */
#define RMCN_RANGE_PAIR_LOAD_RVA  0x0176B74CULL
#define RMCN_RANGE_CACHE_SIZE     256U
#define RMCN_RANGE_CAPSULE_KIND   2U
#define RMCN_RANGE_BOX_KIND       3U
#define RMCN_RANGE_DIM_MIN        0x3CA3D70AU /* 0.02f */
#define RMCN_RANGE_RADIUS_MIN     0x3D4CCCCDU /* 0.05f */
#define RMCN_RANGE_DIM_MAX        0x3E4CCCCDU /* 0.20f */
#define RMCN_RANGE_FACTOR_MIN     0x40A00000U /* 5.0f, same as terminal */
#define RMCN_RANGE_FACTOR_MAX     0x40A00000U /* fixed 5.0f */
/* Opt-in test telemetry: custom_value[1] bit 0. Normal clients leave it zero. */
#define RMCN_RANGE_DIAG_FLAG      1U
#define RMCN_RANGE_EVENT_INPUT    0xD301U
#define RMCN_RANGE_EVENT_OUTPUT   0xD302U
#define RMCN_FREE_VIEW_EPILOGUE_INSN 0xA9434FF4U /* LDP X20,X19,[SP,#48] */
#define RMCN_FREE_VIEW_EPILOGUE_RVA  0x08AADEACULL
#define RMCN_FREE_VIEW_SET_OBSERVER_RVA 0x07FCF880ULL
#define RMCN_FREE_VIEW_SET_OBSERVER_INSN 0xF81D0FFEU
#define RMCN_FREE_VIEW_LOG_PERIOD    (2 * HZ)
#define RMCN_FREE_VIEW_ENABLE               6U
#define RMCN_FREE_VIEW_DISABLE              7U
struct rmcn_range_geometry_entry {
    uint64_t address;
    uint32_t kind;
    uint32_t value_count;
    uint32_t original[3];
    uint32_t applied[3];
};

struct rot_ctx {
    bool     active;
    pid_t    pid;
    uint64_t target_vaddr;
    uint32_t lr_filter;
    uint32_t is_rot_hook;
    seqcount_t custom_seq;
    uint32_t custom_value[3];
    /* 一次性预解码原指令,hook 命中后免重复解码。覆盖的指令变体:
     *   - LDR/STR (imm12, 32-bit GP / SIMD&FP / 64-bit GP)
     *   - LDUR/STUR (unscaled imm9, 32-bit / 64-bit GP)
     *   - LDR (literal, 32-bit) — PC 相对加载
     * 失败 (insn_decoded=false) 不致命,case 2 会跳过。 */
    bool     insn_decoded;
    int      dec_rt;
    int      dec_rn;
    bool     dec_is_fp;
    bool     dec_is_load;       /* true=LDR/LDUR, false=STR/STUR */
    bool     dec_pc_rel;        /* true=LDR (literal),target = PC + offset */
    int      dec_size;          /* 数据宽度(字节):4 或 8 */
    int64_t  dec_offset;        /* 立即数偏移(已 sign-extend / scaled) */
    uint32_t trace_insn;        /* case 28 的动态 UMADDL 原指令 */
    pid_t    trace_tid;         /* 只在指定线程采集一次栈快照 */
    atomic_t trace_capture_state; /* 0=idle, 1=in-flight, 2=published */
    raw_spinlock_t range_lock;
    struct rmcn_range_geometry_entry *range_cache;
    uint64_t module_base;
    atomic_t free_view_command;
    atomic64_t free_view_hook_hits;
    atomic64_t free_view_stack_failures;
    unsigned long free_view_next_log;
    atomic64_t scalar_hook_hits;
    atomic64_t scalar_hook_applies;
    atomic64_t scalar_hook_failures;
    uint64_t scalar_last_native;
    uint64_t scalar_last_output;
    uint64_t scalar_last_cmd;
    uint32_t scalar_last_sequence;
    bool case35_camera_return;
    atomic_t rotation_input_last_token;
};

static struct rot_ctx rot_hooks[MAX_SHADOW_HOOKS];
static DEFINE_MUTEX(rot_hook_mutex);

#define RMCN_INSTANT_VELOCITY_INSN   0x1E21080AU /* FMUL S10,S0,S1 */
#define NZ_FIRE_RAYCAST_ENDPOINT_INSN 0xAA1603E0U /* MOV X0,X22 */
#define RMCN_INSTANT_VELOCITY_RVA    0x07DCBB94ULL
#define RMCN_ROTATION_INPUT_PAIR_INSN 0x2D058A81U /* STP S1,S2,[X20,#0x2C] */
#define RMCN_ROTATION_INPUT_PAIR_RVA  0x0833A04CULL /* current: CorrectCmdViewPitchYaw STP S1,S2,[X20,#0x2C] */
#define RMCN_CROSSHAIR_INPUT_PAIR_INSN 0x2D458281U /* LDP S1,S0,[X20,#0x2C] */
#define RMCN_CROSSHAIR_INPUT_PAIR_RVA  0x08AA8670ULL /* CameraThirdState.CorrectShootPitchYaw */
/* Common first/third-person shoot-angle return, verified in live memory.
 * LDP X20,X19,[SP,#0x20] changes only GPRs; returned angles are S0/S1. */
#define RMCN_CAMERA_SHOOT_RETURN_INSN 0xA9424FF4U
#define RMCN_CAMERA_SHOOT_RETURN_RVA  0x08AA0544ULL
#define RMCN_USERCMD_SEQUENCE_OFFSET       0x10ULL
#define RMCN_SPREAD_CONTEXT_INSN 0x1E204142U /* FMOV S2,S10 */
#define RMCN_SPREAD_CONTEXT_RVA  0x083BE3F4ULL
#define RMCN_TPP_SHOOT_INPUT_INSN 0x1E204008U /* FMOV S8,S0 */
#define RMCN_TPP_SHOOT_INPUT_RVA  0x083BE224ULL
/* Q30 radians per degree, shared by the active spread compensation path. */
#define RMCN_Q30_DEG2RAD          18740330LL
/* case40 normally receives a weapon pointer in c0/c1 to maintain the spread
 * cache. This flag changes those fields into a transient yaw/pitch pair for
 * the third-person parallax branch. */
#define RMCN_TPP_SHOOT_OVERRIDE_FLAG (1U << 8)
/* Case38 only samples formula metadata. Case40 refreshes the live weapon
 * spread every shot, so the calibrated formula can safely remain valid until
 * a weapon switch or a later explicit re-calibration. */
#define RMCN_SPREAD_CONTEXT_TTL  (10 * 60 * HZ)
#define RMCN_WEAPON_TOTAL_SPREAD_OFFSET 0x80ULL
#define RMCN_WEAPON_IS_ADS_OFFSET       0x158ULL
#define RMCN_SPREAD_MAX_TIMES 32
#define NZ_FIRE_RAYCAST_ENDPOINT_RVA  0x1145A2A4ULL
#define NZ_CASE8_EVENT_HIT            0x8001U
#define NZ_CASE8_EVENT_SUCCESS        0x8002U
#define NZ_CASE8_EVENT_FALLBACK       0x8003U
#define NZ_CASE8_EVENT_LIMIT          64ULL
#define RMCN_USER_PTR_MASK           0x00FFFFFFFFFFFFFFULL
#define RMCN_USER_MIN_ADDR           0x10000ULL
#define DFM_GAME_PTR_MIN             0x1000000000ULL
#define DFM_GAME_PTR_MAX             0x8000000000ULL
#define DFM_SLOT_TRACE_NOP_INSN       0xD503201FU
#define DFM_SLOT_TRACE_EVENT_X8_X9    0xD241U
#define DFM_SLOT_TRACE_EVENT_X10_X11  0xD242U
#define DFM_SLOT_TRACE_EVENT_X12_X13  0xD243U
#define DFM_SLOT_TRACE_EVENT_SP_LR    0xD244U
#define DFM_SLOT_TRACE_EVENT_LIMIT    96ULL
#define DFM_FORMULA_TRACE_INSN         0x0A230160U
#define DFM_FORMULA_EVENT_X8_X11       0xD251U
#define DFM_FORMULA_EVENT_X12_X13      0xD252U
#define DFM_FORMULA_EVENT_X19_X20      0xD253U
#define DFM_FORMULA_EVENT_SP_LR        0xD254U
#define DFM_FORMULA_EVENT_LIMIT        16ULL
#define DFM_INDEX_TRACE_INSN            0x9BAF216BU /* UMADDL X11,W11,W15,X8 */
#define DFM_INDEX_EVENT_X8_X9           0xD261U
#define DFM_INDEX_EVENT_X10_X11         0xD262U
#define DFM_INDEX_EVENT_X12_X13         0xD263U
#define DFM_INDEX_EVENT_X14_X15         0xD264U
#define DFM_INDEX_EVENT_X16_X17         0xD265U
#define DFM_INDEX_EVENT_SP_LR           0xD266U
#define DFM_INDEX_EVENT_RAW_SP590       0xD267U
#define DFM_INDEX_EVENT_SP230_SP818     0xD268U
#define DFM_INDEX_EVENT_CHAIN           0xD269U
#define DFM_INDEX_EVENT_X26             0xD26AU
#define DFM_INDEX_EVENT_X23             0xD26BU
#define DFM_INDEX_EVENT_LIMIT           96ULL
#define DFM_INDEX_FIELD_OFFSET          1360ULL
#define DFM_INDEX_CHAIN_OFFSET          13576ULL
#define DFM_SCALAR_HOOK_EVENT          0xD5A5U
#define DFM_SCALAR_HOOK_FPSTATE_FLAG   0x80000000U
#define DFM_OUTLINE_MATERIAL_LOAD_INSN   0xF9439288U /* LDR X8,[X20,#0x720] */
#define DFM_OUTLINE_MATERIAL_LOAD_RVA    0x10812CD8ULL
/* 同一段渲染快照代码里紧随材质之后的标志字节读取：
 *   0x10812CE8  LDRB W8,[X20,#0x728]  → AND #0xFF  → bDrawEffectPass
 *   0x10812D00  LDRB W8,[X20,#0x728]  → UBFX #2,#1 → bEffectPassNeedDepth
 * 断点命中时只改 X8，不写目标内存。 */
#define DFM_OUTLINE_FLAGS_LOAD_INSN       0x395CA288U /* LDRB W8,[X20,#0x728] */
#define DFM_OUTLINE_FLAGS_DRAW_RVA        0x10812CE0ULL
#define DFM_OUTLINE_FLAGS_DEPTH_RVA      (DFM_OUTLINE_MATERIAL_LOAD_RVA + 0x28ULL)
#define DFM_EFFECT_PASS_DRAW_BIT         0x01U
#define DFM_EFFECT_PASS_DEPTH_BIT        0x04U
#define DFM_COMPONENT_OWNER_OFFSET       0x0E8ULL
#define DFM_CHARACTER_NET_UPDATE_OFFSET  0x150ULL
#define DFM_CHARACTER_MAIN_MESH_OFFSET   0x3D0ULL
#define DFM_CHARACTER_BOT_FLAG_OFFSET    0x11F8ULL
#define DFM_CHARACTER_TEAM_COMP_OFFSET   0x10C0ULL
/* ADFMCharacter::DFMOutLineEffectComponent（旧赛季在 Character 上为 0x2448） */
#define DFM_CHARACTER_OUTLINE_OFFSET     0x2508ULL
#define DFM_WEAPON_CHARACTER_OWNER       0xA60ULL
#define DFM_TEAM_ID_OFFSET               0x108ULL
#define DFM_OUTLINE_RED_OFFSET           0x110ULL
#define DFM_OUTLINE_GREEN_OFFSET         0x108ULL
#define DFM_OUTLINE_GREEN_BUTTER_OFFSET  0x150ULL
/* 动态材质实例：新版在 0x1B0/0x1B8 插入两个 Lock 实例，后续指针 +8 */
#define DFM_OUTLINE_RED_DYNAMIC_OFFSET   0x1C8ULL
#define DFM_OUTLINE_GREEN_DYNAMIC_OFFSET 0x1C0ULL
#define DFM_OUTLINE_GREEN_BUTTER_DYNAMIC 0x208ULL
#define DFM_MESH_PRIMITIVE_FLAGS_OFFSET  0x279ULL
#define DFM_MESH_STENCIL_MASK_OFFSET     0x2A8ULL
#define DFM_MESH_STENCIL_VALUE_OFFSET    0x2ACULL
#define DFM_MESH_EFFECT_MATERIAL_OFFSET  0x720ULL
#define DFM_MESH_EFFECT_FLAGS_OFFSET     0x728ULL
#define DFM_MESH_ALLOW_OCCLUSION_OFFSET  0x728ULL
#define DFM_MESH_SKIP_BASE_PASS_OFFSET   0x728ULL
#define DFM_MESH_FORCE_UPDATE_OFFSET     0x8C0ULL
#define DFM_CHARACTER_NET_UPDATE_15_BITS 0x41700000U
typedef void (*fpsimd_save_flush_fn_t)(void);
static fpsimd_save_flush_fn_t fpsimd_save_flush_fn;
static atomic64_t dfm_slot_trace_hits = ATOMIC64_INIT(0);
static atomic64_t dfm_formula_trace_hits = ATOMIC64_INIT(0);
static atomic64_t dfm_index_trace_hits = ATOMIC64_INIT(0);
static bool dfm_index_trace_insn_valid(uint32_t insn)
{
    uint32_t rt;
    uint32_t rn;
    bool gp_load;

    /* UMADDL Xd,Wn,Wm,Xa: registers are variable, opcode is stable. */
    if ((insn & 0xFFE00000U) == 0x9BA00000U)
        return true;

    /* The current flattened hash lane reloads its scalar root with
     * LDR X8/W8,[SP,#imm]. The dynamic hook emulates this exact load while
     * transporting the adjacent pointer roots through the same ABI. */
    rt = insn & 0x1FU;
    rn = (insn >> 5) & 0x1FU;
    gp_load = (insn & 0xFFC00000U) == 0xF9400000U ||
              (insn & 0xFFC00000U) == 0xB9400000U;
    return gp_load && rn == 31U && rt == 8U;
}

/* These helpers are defined below with the other no-fault user accessors.
 * Keeping case 28 on the same checked path avoids raw __get_user calls on
 * tagged/PAC addresses while the debug exception is still in its atomic part. */
static bool rmcn_get_user_u32(uint64_t addr, uint32_t *out);
static bool rmcn_get_user_u64(uint64_t addr, uint64_t *out);
static bool rmcn_put_user_u64(uint64_t addr, uint64_t value);
static inline bool rmcn_float_is_finite(uint32_t raw);

/* sign-extend N-bit 立即数到 int64 */
static inline int64_t sign_extend(int64_t v, int bits)
{
    int64_t mask = 1LL << (bits - 1);
    return (v ^ mask) - mask;
}

/* 解码常见 LDR/STR 变体。覆盖游戏外挂里 90%+ 的真实命中目标。
 * 设计原则:扩大可 hook 指令集,但保持业务侧字段语义不变 — case 2
 * 仍按 32-bit 数据宽度操作,看到 dec_size!=4 自己 break。 */
static void predecode_for_rot(struct rot_ctx *ctx, struct task_struct *task)
{
    uint32_t insn;
    int rt, rn;

    if (!read_process_memory_kernel(task->tgid, ctx->target_vaddr, &insn, 4))
        return;

    rt = insn & 0x1F;
    rn = (insn >> 5) & 0x1F;

    /* ---- 1. LDR/STR (immediate, unsigned offset, imm12) ---- */
    if ((insn & 0xFFC00000) == 0x39400000) {
        /* LDRB Wt,[Xn,#imm12]:8-bit GP load（位标志位必用） */
        ctx->dec_size = 1; ctx->dec_is_fp = false; ctx->dec_is_load = true;
        ctx->dec_offset = ((int64_t)((insn >> 10) & 0xFFF));
    } else if ((insn & 0xFFC00000) == 0x39000000) {
        /* STRB Wt,[Xn,#imm12]:8-bit GP store */
        ctx->dec_size = 1; ctx->dec_is_fp = false; ctx->dec_is_load = false;
        ctx->dec_offset = ((int64_t)((insn >> 10) & 0xFFF));
    } else if ((insn & 0xFFC00000) == 0x79400000) {
        /* LDRH Wt,[Xn,#imm12]:16-bit GP load */
        ctx->dec_size = 2; ctx->dec_is_fp = false; ctx->dec_is_load = true;
        ctx->dec_offset = ((int64_t)((insn >> 10) & 0xFFF)) << 1;
    } else if ((insn & 0xFFC00000) == 0x79000000) {
        /* STRH Wt,[Xn,#imm12] */
        ctx->dec_size = 2; ctx->dec_is_fp = false; ctx->dec_is_load = false;
        ctx->dec_offset = ((int64_t)((insn >> 10) & 0xFFF)) << 1;
    } else if ((insn & 0xFFC00000) == 0xB9400000) {
        /* LDR (imm12, 32-bit GP) */
        ctx->dec_size = 4; ctx->dec_is_fp = false; ctx->dec_is_load = true;
        ctx->dec_offset = ((int64_t)((insn >> 10) & 0xFFF)) << 2;
    } else if ((insn & 0xFFC00000) == 0xB9000000) {
        /* STR (imm12, 32-bit GP) */
        ctx->dec_size = 4; ctx->dec_is_fp = false; ctx->dec_is_load = false;
        ctx->dec_offset = ((int64_t)((insn >> 10) & 0xFFF)) << 2;
    } else if ((insn & 0xFFC00000) == 0xF9400000) {
        /* LDR (imm12, 64-bit GP) — Android 上最常见的 GP load */
        ctx->dec_size = 8; ctx->dec_is_fp = false; ctx->dec_is_load = true;
        ctx->dec_offset = ((int64_t)((insn >> 10) & 0xFFF)) << 3;
    } else if ((insn & 0xFFC00000) == 0xF9000000) {
        /* STR (imm12, 64-bit GP) */
        ctx->dec_size = 8; ctx->dec_is_fp = false; ctx->dec_is_load = false;
        ctx->dec_offset = ((int64_t)((insn >> 10) & 0xFFF)) << 3;
    } else if ((insn & 0xFFC00000) == 0xBD400000) {
        /* LDR (imm12, SIMD&FP, 32-bit) — 浮点常量 load */
        ctx->dec_size = 4; ctx->dec_is_fp = true; ctx->dec_is_load = true;
        ctx->dec_offset = ((int64_t)((insn >> 10) & 0xFFF)) << 2;
    } else if ((insn & 0xFFC00000) == 0xBD000000) {
        /* STR (imm12, SIMD&FP, 32-bit) */
        ctx->dec_size = 4; ctx->dec_is_fp = true; ctx->dec_is_load = false;
        ctx->dec_offset = ((int64_t)((insn >> 10) & 0xFFF)) << 2;
    } else if ((insn & 0xFFC00000) == 0xFD400000) {
        /* LDR Dt, [Xn,#imm]:64-bit SIMD&FP load */
        ctx->dec_size = 8; ctx->dec_is_fp = true; ctx->dec_is_load = true;
        ctx->dec_offset = ((int64_t)((insn >> 10) & 0xFFF)) << 3;

    /* ---- 2. LDUR/STUR (unscaled offset, imm9 signed) ---- */
    } else if ((insn & 0xFFE00C00) == 0xB8400000) {
        /* LDUR (32-bit GP) */
        ctx->dec_size = 4; ctx->dec_is_fp = false; ctx->dec_is_load = true;
        ctx->dec_offset = sign_extend((insn >> 12) & 0x1FF, 9);
    } else if ((insn & 0xFFE00C00) == 0xB8000000) {
        /* STUR (32-bit GP) */
        ctx->dec_size = 4; ctx->dec_is_fp = false; ctx->dec_is_load = false;
        ctx->dec_offset = sign_extend((insn >> 12) & 0x1FF, 9);
    } else if ((insn & 0xFFE00C00) == 0xF8400000) {
        /* LDUR (64-bit GP) */
        ctx->dec_size = 8; ctx->dec_is_fp = false; ctx->dec_is_load = true;
        ctx->dec_offset = sign_extend((insn >> 12) & 0x1FF, 9);
    } else if ((insn & 0xFFE00C00) == 0xF8000000) {
        /* STUR (64-bit GP) */
        ctx->dec_size = 8; ctx->dec_is_fp = false; ctx->dec_is_load = false;
        ctx->dec_offset = sign_extend((insn >> 12) & 0x1FF, 9);

    /* ---- 3. LDR (literal) — PC 相对加载 ---- */
    } else if ((insn & 0xFF000000) == 0x18000000) {
        /* LDR Wt, [PC + offset]:32-bit,offset = sign_extend(imm19) << 2 */
        ctx->dec_size = 4; ctx->dec_is_fp = false; ctx->dec_is_load = true;
        ctx->dec_pc_rel = true;
        ctx->dec_offset = sign_extend((insn >> 5) & 0x7FFFF, 19) << 2;
        ctx->dec_rn     = 31;
        ctx->insn_decoded = true;
        ctx->dec_rt       = rt;
        return;
    } else if ((insn & 0xFF000000) == 0x58000000) {
        /* LDR Xt, [PC + offset]:64-bit GP literal */
        ctx->dec_size = 8; ctx->dec_is_fp = false; ctx->dec_is_load = true;
        ctx->dec_pc_rel = true;
        ctx->dec_offset = sign_extend((insn >> 5) & 0x7FFFF, 19) << 2;
        ctx->dec_rn     = 31;
        ctx->insn_decoded = true;
        ctx->dec_rt       = rt;
        return;

    /* ---- 4. LDRSW (sign-extending word load, imm12) ---- */
    } else if ((insn & 0xFFC00000) == 0xB9800000) {
        /* LDRSW Xt, [Xn,#imm]:加载 32-bit 然后符号扩展到 64-bit。
         * 业务只读低 32-bit,与普通 LDR(32) 等价处理。 */
        ctx->dec_size = 4; ctx->dec_is_fp = false; ctx->dec_is_load = true;
        ctx->dec_offset = ((int64_t)((insn >> 10) & 0xFFF)) << 2;

    /* ---- 5. SIMD 128-bit LDR/STR (imm12, scaled by 16) ---- */
    } else if ((insn & 0xFFC00000) == 0x3DC00000) {
        /* LDR Qt, [Xn,#imm]:128-bit SIMD&FP load。
         * 业务仍按 32-bit 读，标记为 fp + size=4 供 case 2 使用。 */
        ctx->dec_size = 4; ctx->dec_is_fp = true; ctx->dec_is_load = true;
        ctx->dec_offset = ((int64_t)((insn >> 10) & 0xFFF)) << 4;
    } else if ((insn & 0xFFC00000) == 0x3D800000) {
        /* STR Qt, [Xn,#imm]:128-bit SIMD&FP store */
        ctx->dec_size = 4; ctx->dec_is_fp = true; ctx->dec_is_load = false;
        ctx->dec_offset = ((int64_t)((insn >> 10) & 0xFFF)) << 4;

    /* ---- 6. LDP/STP (pair, imm7 signed, scaled) ----
     * 游戏常见:一次 load 两个 float 坐标 (xy)。我们解码主寄存器 (Rt) 的
     * 信息,case 2 仍可工作(单乘);Rt2 = bits[14:10],业务暂未用。
     *
     * LDP/STP encoding 在 LDR/STR 之外,要单独 mask:
     *   bits[31:30]=opc, bits[26]=V(SIMD), bits[24:22]=opc2(L=1 load),
     *   bits[27:25]=101 (LDP/STP class)
     * 简化:用整个 0xFFC00000 mask 匹配关键编码点。 */
    } else if ((insn & 0xFFC00000) == 0x29400000) {
        /* LDP Wt, Wt2, [Xn,#imm]:32-bit GP pair load */
        ctx->dec_size = 4; ctx->dec_is_fp = false; ctx->dec_is_load = true;
        ctx->dec_offset = sign_extend((insn >> 15) & 0x7F, 7) << 2;
    } else if ((insn & 0xFFC00000) == 0x29000000) {
        /* STP Wt, Wt2, [Xn,#imm]:32-bit GP pair store */
        ctx->dec_size = 4; ctx->dec_is_fp = false; ctx->dec_is_load = false;
        ctx->dec_offset = sign_extend((insn >> 15) & 0x7F, 7) << 2;
    } else if ((insn & 0xFFC00000) == 0xA9400000) {
        /* LDP Xt, Xt2, [Xn,#imm]:64-bit GP pair load (Android arm64 ABI
         * 函数序言常见的 ldp x29,x30,[sp]+) */
        ctx->dec_size = 8; ctx->dec_is_fp = false; ctx->dec_is_load = true;
        ctx->dec_offset = sign_extend((insn >> 15) & 0x7F, 7) << 3;
    } else if ((insn & 0xFFC00000) == 0xA9000000) {
        /* STP Xt, Xt2, [Xn,#imm]:64-bit GP pair store */
        ctx->dec_size = 8; ctx->dec_is_fp = false; ctx->dec_is_load = false;
        ctx->dec_offset = sign_extend((insn >> 15) & 0x7F, 7) << 3;
    } else if ((insn & 0xFFC00000) == 0x2D400000) {
        /* LDP St, St2, [Xn,#imm]:32-bit SIMD&FP pair load (一次拿两个 float) */
        ctx->dec_size = 4; ctx->dec_is_fp = true; ctx->dec_is_load = true;
        ctx->dec_offset = sign_extend((insn >> 15) & 0x7F, 7) << 2;
    } else if ((insn & 0xFFC00000) == 0x2D000000) {
        /* STP St, St2, [Xn,#imm]:32-bit SIMD&FP pair store */
        ctx->dec_size = 4; ctx->dec_is_fp = true; ctx->dec_is_load = false;
        ctx->dec_offset = sign_extend((insn >> 15) & 0x7F, 7) << 2;
    } else {
        return;
    }

    ctx->insn_decoded = true;
    ctx->dec_rt       = rt;
    ctx->dec_rn       = rn;
}

static bool rot_hook_type_supported(uint32_t hook_type)
{
    switch (hook_type) {
    case 1:
    case 2:
    case 4:
    case 5:
    case 8:
    case 24:
    case 25:
    case 28:
    case NBG_SHADOW_DYNAMIC_HOOK_TYPE:
    case NBG_SHADOW_FP_LDP_SCALE_HOOK_TYPE:
    case NBG_SHADOW_DFM_OUTLINE_RENDER_TYPE:
    case NBG_SHADOW_DFM_OUTLINE_FLAGS_TYPE:
    case NBG_SHADOW_RMCN_FREE_VIEW_TYPE:
    case NBG_SHADOW_RMCN_ROTATION_INPUT_TYPE:
    case NBG_SHADOW_RMCN_CROSSHAIR_INPUT_TYPE:
    case NBG_SHADOW_RMCN_NO_SPREAD_TYPE:
    case NBG_SHADOW_RMCN_TPP_SHOOT_INPUT_TYPE:
        return true;
    default:
        return false;
    }
}

/* ---- 失控进化散布补偿：纯整数 Q30 数学 ----
 *
 * HWBP 回调运行在异常上下文，内核模块不能生成 FP/SIMD 指令，也不能
 * 依赖 libgcc 软浮点。下面只用整数完成散布逆解。
 */
#define RMCN_Q30_ONE       1073741824LL
#define RMCN_Q30_HALF       536870912LL
#define RMCN_Q30_PI        3373259426LL
#define RMCN_Q30_HALF_PI   1686629713LL
#define RMCN_Q30_TWO_PI    6746518852LL
#define RMCN_Q30_RAD2DEG  61520874802LL
#define RMCN_Q30_CORDIC_K   652032874LL

static const int64_t rmcn_cordic_atan_q30[31] = {
    843314857LL, 497837829LL, 263043837LL, 133525159LL,
     67021687LL,  33543516LL,  16775851LL,   8388437LL,
      4194283LL,   2097149LL,   1048576LL,    524288LL,
       262144LL,    131072LL,      65536LL,     32768LL,
        16384LL,      8192LL,       4096LL,      2048LL,
         1024LL,       512LL,        256LL,       128LL,
           64LL,        32LL,         16LL,         8LL,
            4LL,         2LL,          1LL
};

static inline int64_t rmcn_q30_mul(int64_t a, int64_t b)
{
    return (int64_t)(((__int128)a * (__int128)b) >> 30);
}

static inline int64_t rmcn_q30_div(int64_t a, int64_t b)
{
    if (!b)
        return 0;
    /* 当前物理域在 +/-2Q30 内。显式收口，避免 a*Q30 的 s64 UB。 */
    if (a > 4 * RMCN_Q30_ONE || a < -4 * RMCN_Q30_ONE)
        return 0;
    return (a * RMCN_Q30_ONE) / b;
}

static uint64_t rmcn_isqrt_u64(uint64_t value)
{
    uint64_t result = 0;
    uint64_t bit = 1ULL << 62;

    while (bit > value)
        bit >>= 2;
    while (bit) {
        if (value >= result + bit) {
            value -= result + bit;
            result = (result >> 1) + bit;
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }
    return result;
}

static inline int64_t rmcn_q30_sqrt(int64_t value)
{
    if (value <= 0)
        return 0;
    if ((uint64_t)value > (~0ULL >> 30))
        return 0;
    return (int64_t)rmcn_isqrt_u64((uint64_t)value << 30);
}

static int64_t rmcn_float_bits_to_q30(uint32_t raw)
{
    uint32_t exponent = (raw >> 23) & 0xFFU;
    uint64_t mantissa;
    int shift;
    int64_t value;

    if (!exponent)
        return 0;
    if (exponent == 0xFFU)
        return 0;

    mantissa = (uint64_t)(raw & 0x7FFFFFU) | 0x800000ULL;
    shift = (int)exponent - 120;
    if (shift >= 0) {
        if (shift > 38)
            return 0;
        value = (int64_t)(mantissa << shift);
    } else {
        int right = -shift;
        uint64_t round = right > 0 && right < 64 ? (1ULL << (right - 1)) : 0;

        if (right >= 64)
            value = 0;
        else
            value = (int64_t)((mantissa + round) >> right);
    }

    return (raw & 0x80000000U) ? -value : value;
}

static uint32_t rmcn_q30_to_float_bits(int64_t value)
{
    uint64_t magnitude;
    uint64_t significand;
    uint32_t sign = 0;
    int top = 0;
    int exponent;
    int shift;

    if (!value)
        return 0;
    if (value < 0) {
        sign = 0x80000000U;
        magnitude = (uint64_t)(-value);
    } else {
        magnitude = (uint64_t)value;
    }

    {
        uint64_t scan = magnitude;
        while (scan >>= 1)
            top++;
    }

    exponent = top - 30 + 127;
    if (exponent <= 0)
        return sign;
    if (exponent >= 255)
        return sign | 0x7F800000U;

    shift = top - 23;
    if (shift > 0) {
        uint64_t base = magnitude >> shift;
        uint64_t remainder = magnitude & ((1ULL << shift) - 1);
        uint64_t halfway = 1ULL << (shift - 1);

        if (remainder > halfway || (remainder == halfway && (base & 1ULL)))
            base++;
        significand = base;
    } else {
        significand = magnitude << (-shift);
    }

    if (significand >= 0x1000000ULL) {
        significand >>= 1;
        exponent++;
        if (exponent >= 255)
            return sign | 0x7F800000U;
    }

    return sign | ((uint32_t)exponent << 23) |
           ((uint32_t)significand & 0x7FFFFFU);
}

static bool rmcn_put_user_u32_pair(uint64_t addr, uint32_t first,
                                   uint32_t second);

static void rmcn_q30_sincos(int64_t angle, int64_t *out_sin, int64_t *out_cos)
{
    int64_t x = RMCN_Q30_CORDIC_K;
    int64_t y = 0;
    int64_t z;
    bool negate_cos = false;
    int i;

    while (angle > RMCN_Q30_PI)
        angle -= RMCN_Q30_TWO_PI;
    while (angle < -RMCN_Q30_PI)
        angle += RMCN_Q30_TWO_PI;

    if (angle > RMCN_Q30_HALF_PI) {
        angle = RMCN_Q30_PI - angle;
        negate_cos = true;
    } else if (angle < -RMCN_Q30_HALF_PI) {
        angle = -RMCN_Q30_PI - angle;
        negate_cos = true;
    }

    z = angle;
    for (i = 0; i < 31; i++) {
        int64_t old_x = x;
        int64_t old_y = y;

        if (z >= 0) {
            x = old_x - (old_y >> i);
            y = old_y + (old_x >> i);
            z -= rmcn_cordic_atan_q30[i];
        } else {
            x = old_x + (old_y >> i);
            y = old_y - (old_x >> i);
            z += rmcn_cordic_atan_q30[i];
        }
    }

    *out_sin = y;
    *out_cos = negate_cos ? -x : x;
}

static int64_t rmcn_q30_atan2(int64_t y, int64_t x)
{
    int64_t z = 0;
    int64_t original_y = y;
    int i;

    if (!y)
        return x < 0 ? RMCN_Q30_PI : 0;
    if (!x)
        return y > 0 ? RMCN_Q30_HALF_PI : -RMCN_Q30_HALF_PI;

    if (x < 0) {
        x = -x;
        y = -y;
        z = original_y >= 0 ? RMCN_Q30_PI : -RMCN_Q30_PI;
    }

    for (i = 0; i < 31; i++) {
        int64_t old_x = x;
        int64_t old_y = y;

        if (old_y > 0) {
            x = old_x + (old_y >> i);
            y = old_y - (old_x >> i);
            z += rmcn_cordic_atan_q30[i];
        } else if (old_y < 0) {
            x = old_x - (old_y >> i);
            y = old_y + (old_x >> i);
            z -= rmcn_cordic_atan_q30[i];
        } else {
            break;
        }
    }
    return z;
}

static inline int64_t rmcn_q30_asin(int64_t value)
{
    int64_t remain;

    if (value >= RMCN_Q30_ONE)
        return RMCN_Q30_HALF_PI;
    if (value <= -RMCN_Q30_ONE)
        return -RMCN_Q30_HALF_PI;
    remain = RMCN_Q30_ONE - rmcn_q30_mul(value, value);
    return rmcn_q30_atan2(value, rmcn_q30_sqrt(remain));
}

static inline int64_t rmcn_q30_clamp(int64_t value, int64_t low,
                                     int64_t high)
{
    if (value < low)
        return low;
    if (value > high)
        return high;
    return value;
}

static atomic64_t rmcn_case38_hits = ATOMIC64_INIT(0);
static atomic64_t rmcn_case38_captures = ATOMIC64_INIT(0);
static atomic64_t rmcn_case40_hits = ATOMIC64_INIT(0);
static atomic64_t rmcn_case40_comp_successes = ATOMIC64_INIT(0);
static atomic64_t rmcn_spread_comp_attempts = ATOMIC64_INIT(0);
static atomic64_t rmcn_spread_comp_successes = ATOMIC64_INIT(0);
static atomic64_t rmcn_spread_cache_misses = ATOMIC64_INIT(0);
static atomic64_t rmcn_spread_compute_rejects = ATOMIC64_INIT(0);
static atomic64_t rmcn_spread_shot_matches = ATOMIC64_INIT(0);
static atomic64_t rmcn_spread_shot_mismatches = ATOMIC64_INIT(0);
static atomic64_t rmcn_spread_shot_unpaired = ATOMIC64_INIT(0);
static uint32_t rmcn_spread_last_sequence;
static uint32_t rmcn_spread_last_seed;
static uint32_t rmcn_spread_last_bits;
static uint32_t rmcn_spread_last_projectile_index;
static uint32_t rmcn_spread_last_target_yaw_bits;
static uint32_t rmcn_spread_last_target_pitch_bits;
static uint32_t rmcn_spread_last_comp_yaw_bits;
static uint32_t rmcn_spread_last_comp_pitch_bits;
static uint32_t rmcn_spread_last_live_angle0_bits;
static uint32_t rmcn_spread_last_live_angle1_bits;
static int32_t rmcn_spread_last_sequence_delta;

struct rmcn_spread_context {
    pid_t pid;
    unsigned long stamp;
    uint64_t formula;
    uint64_t parameter;
    uint64_t weapon;
    uint32_t captured_seed;
    uint32_t captured_index;
    uint32_t captured_spread_bits;
    uint8_t captured_is_ads;
    int32_t x_times;
    int32_t y_times;
    uint32_t x_offset_bits;
    uint32_t y_offset_bits;
    int32_t prime_count;
    int32_t primes[RMCN_SPREAD_MAX_TIMES];
};

/* case35 publishes the target command angle and case38 consumes it at the
 * exact CalculateShootDir call.  Keeping this separate from the cached
 * formula prevents a previous frame's angle from being paired with a new
 * shot seed. */
struct rmcn_spread_target_snapshot {
    pid_t pid;
    unsigned long stamp;
    uint32_t sequence;
    uint32_t yaw_bits;
    uint32_t pitch_bits;
    bool active;
};

struct rmcn_spread_comp_snapshot {
    pid_t pid;
    unsigned long stamp;
    uint32_t sequence;
    uint32_t target_yaw_bits;
    uint32_t target_pitch_bits;
    uint32_t compensated_yaw_bits;
    uint32_t compensated_pitch_bits;
};

#define RMCN_SPREAD_COMP_RING_SIZE 256U
#define RMCN_SPREAD_COMP_RING_MASK (RMCN_SPREAD_COMP_RING_SIZE - 1U)

static DEFINE_RAW_SPINLOCK(rmcn_spread_context_lock);
static struct rmcn_spread_context rmcn_spread_context;
struct rmcn_spread_formula_template {
    bool valid;
    int32_t prime_count;
    int32_t primes[RMCN_SPREAD_MAX_TIMES];
};
static struct rmcn_spread_formula_template rmcn_spread_formula_template;
static bool rmcn_spread_context_preloaded;
static struct rmcn_spread_target_snapshot rmcn_spread_target;
static struct rmcn_spread_comp_snapshot rmcn_spread_comp_snapshot;
static struct rmcn_spread_comp_snapshot
    rmcn_spread_comp_ring[RMCN_SPREAD_COMP_RING_SIZE];
static pid_t rmcn_spread_expected_pid;
static uint64_t rmcn_spread_expected_weapon;
static bool rmcn_spread_capture_enabled;
static pid_t rmcn_spread_preserve_detach_pid;
static atomic64_t nz_case8_hits = ATOMIC64_INIT(0);
static atomic64_t nz_case8_successes = ATOMIC64_INIT(0);
static atomic64_t nz_case8_fallbacks = ATOMIC64_INIT(0);

static void nz_case8_push_event(const struct rot_ctx *ctx,
                                const struct pt_regs *regs,
                                uint32_t type, atomic64_t *counter)
{
    uint64_t count;

    if (!ctx || !regs || !counter)
        return;
    count = (uint64_t)atomic64_inc_return(counter);
    if (count <= NZ_CASE8_EVENT_LIMIT)
        watch_push_custom_event(ctx->target_vaddr, regs->regs[30], type,
                                (uint32_t)count);
}

static inline bool rmcn_float_is_finite(uint32_t raw)
{
    return ((raw >> 23) & 0xFFU) != 0xFFU;
}

static inline uint64_t rmcn_strip_user_ptr(uint64_t addr)
{
    return addr & RMCN_USER_PTR_MASK;
}

/* DFM UObject/component pointers are 8-byte aligned and live in the 39-bit
 * high userspace region. access_ok() alone accepted 0x3f000000, which later
 * produced the observed 0x3f000150 translation fault in case 31. */
static inline bool dfm_game_ptr_valid(uint64_t addr)
{
    addr = rmcn_strip_user_ptr(addr);
    return addr >= DFM_GAME_PTR_MIN && addr < DFM_GAME_PTR_MAX &&
           (addr & (sizeof(uint64_t) - 1U)) == 0;
}

static bool rmcn_user_range_ok(uint64_t addr, size_t size)
{
    addr = rmcn_strip_user_ptr(addr);
    if (addr < RMCN_USER_MIN_ADDR || !size)
        return false;
    if (addr + size < addr)
        return false;
    return access_ok((void __user *)addr, size);
}

static bool rmcn_get_user_u8(uint64_t addr, uint8_t *out)
{
    uint8_t v = 0;
    int ret;

    if (!out || !rmcn_user_range_ok(addr, sizeof(v)))
        return false;
    addr = rmcn_strip_user_ptr(addr);
    pagefault_disable();
    ret = __get_user(v, (uint8_t __user *)addr);
    pagefault_enable();
    if (ret)
        return false;
    *out = v;
    return true;
}

static bool rmcn_get_user_u32(uint64_t addr, uint32_t *out)
{
    uint32_t v = 0;
    int ret;

    if (!out || !rmcn_user_range_ok(addr, sizeof(v)))
        return false;
    addr = rmcn_strip_user_ptr(addr);
    pagefault_disable();
    ret = __get_user(v, (uint32_t __user *)addr);
    pagefault_enable();
    if (ret)
        return false;
    *out = v;
    return true;
}

static bool rmcn_get_user_i32(uint64_t addr, int32_t *out)
{
    int32_t v = 0;
    int ret;

    if (!out || !rmcn_user_range_ok(addr, sizeof(v)))
        return false;
    addr = rmcn_strip_user_ptr(addr);
    pagefault_disable();
    ret = __get_user(v, (int32_t __user *)addr);
    pagefault_enable();
    if (ret)
        return false;
    *out = v;
    return true;
}

static bool rmcn_get_user_u64(uint64_t addr, uint64_t *out)
{
    uint64_t v = 0;
    int ret;

    if (!out || !rmcn_user_range_ok(addr, sizeof(v)))
        return false;
    addr = rmcn_strip_user_ptr(addr);
    pagefault_disable();
    ret = __get_user(v, (uint64_t __user *)addr);
    pagefault_enable();
    if (ret)
        return false;
    *out = v;
    return true;
}

static int32_t rmcn_ran1_step(int32_t value)
{
    int32_t k = value / 127773;
    int64_t next = 16807LL * ((int64_t)value -
                             (int64_t)k * 127773LL) -
                   2836LL * (int64_t)k;

    if (next < 0)
        next += 2147483647LL;
    return (int32_t)next;
}

/* UniformRandom.randomFloat resets ran1 for every supplied seed. */
static int32_t rmcn_ran1_sample(int32_t seed)
{
    int32_t state;
    int32_t table[32];
    int32_t iy;
    int j;

    if (seed == (int32_t)0x80000000U || seed == 0)
        state = 1;
    else
        state = seed < 0 ? -seed : seed;

    for (j = 39; j >= 0; j--) {
        state = rmcn_ran1_step(state);
        if (j < 32)
            table[j] = state;
    }
    iy = table[0];
    state = rmcn_ran1_step(state);
    j = iy / 67108864;
    if (j < 0)
        j = 0;
    else if (j > 31)
        j = 31;
    iy = table[j];
    return iy;
}

static inline int64_t rmcn_random01_q30(int32_t seed)
{
    /* The game converts the positive ran1 result with scvtf #31. */
    return (int64_t)((uint32_t)rmcn_ran1_sample(seed) >> 1);
}

static inline int64_t rmcn_random_range_q30(int32_t seed,
                                            int64_t low, int64_t high)
{
    return low + rmcn_q30_mul(high - low, rmcn_random01_q30(seed));
}

static int64_t rmcn_clt_axis_q30(int32_t seed, int count,
                                 const int32_t *primes, int prime_count,
                                 bool *ok)
{
    int64_t sum = 0;
    int i;

    if (!ok)
        return 0;
    if (count < 1)
        count = 1;
    if (count > RMCN_SPREAD_MAX_TIMES ||
        (count > 1 && count - 1 > prime_count)) {
        *ok = false;
        return 0;
    }

    for (i = 0; i < count; i++) {
        sum += rmcn_random01_q30(seed);
        if (i + 1 < count)
            seed = (int32_t)((uint32_t)seed * (uint32_t)primes[i]);
    }

    return ((sum - (int64_t)count * RMCN_Q30_HALF) * 2) / count;
}

static bool rmcn_spread_xy_q30(int32_t seed, bool is_ads,
                               int x_times, int y_times,
                               int64_t x_offset, int64_t y_offset,
                               const int32_t *primes, int prime_count,
                               int64_t *out_x, int64_t *out_y)
{
    int64_t x;
    int64_t y;
    int64_t radius2;
    bool ok = true;

    if (!out_x || !out_y)
        return false;
    if (is_ads) {
        int64_t half_range;

        x = rmcn_random_range_q30(seed, -RMCN_Q30_HALF,
                                  RMCN_Q30_HALF) +
            rmcn_random_range_q30(
                (int32_t)((uint32_t)seed + 1U),
                -RMCN_Q30_HALF, RMCN_Q30_HALF);
        radius2 = RMCN_Q30_ONE - rmcn_q30_mul(x, x);
        if (radius2 < 0)
            radius2 = 0;
        half_range = rmcn_q30_sqrt(radius2) / 2;
        y = rmcn_random_range_q30(
                (int32_t)((uint32_t)seed + 2U),
                -half_range, half_range) +
            rmcn_random_range_q30(
                (int32_t)((uint32_t)seed + 3U),
                -half_range, half_range);
    } else {
        x = rmcn_clt_axis_q30(seed, x_times, primes, prime_count, &ok);
        y = rmcn_clt_axis_q30(
            (int32_t)((uint32_t)seed * 17U),
            y_times, primes, prime_count, &ok);
        if (!ok)
            return false;

        radius2 = RMCN_Q30_ONE - rmcn_q30_mul(x, x);
        if (radius2 < 0)
            radius2 = 0;
        y = rmcn_q30_mul(y, rmcn_q30_sqrt(radius2));

        radius2 = rmcn_q30_mul(x, x) + rmcn_q30_mul(y, y);
        if ((x_offset || y_offset) && radius2 < RMCN_Q30_ONE) {
            int64_t length;

            x += x_offset;
            y += y_offset;
            radius2 = rmcn_q30_mul(x, x) + rmcn_q30_mul(y, y);
            if (radius2 > RMCN_Q30_ONE) {
                length = rmcn_q30_sqrt(radius2);
                if (length > 0) {
                    x = rmcn_q30_div(x, length);
                    y = rmcn_q30_div(y, length);
                }
            }
        }
    }

    *out_x = x;
    *out_y = y;
    return true;
}

static bool rmcn_inverse_spread_angle(uint32_t yaw_raw,
                                      uint32_t pitch_raw,
                                      int64_t spread_x,
                                      int64_t spread_y,
                                      int64_t spread,
                                      uint32_t *out_yaw,
                                      uint32_t *out_pitch)
{
    int64_t target_yaw_deg;
    int64_t target_pitch_deg;
    int64_t target_yaw;
    int64_t target_pitch;
    int64_t a;
    int64_t b;
    int64_t length;
    int64_t denominator;
    int64_t sin_target;
    int64_t cos_target;
    int64_t asin_arg;
    int64_t input_pitch;
    int64_t sin_input;
    int64_t cos_input;
    int64_t z0;
    int64_t input_yaw;

    if (!out_yaw || !out_pitch || spread <= 0 ||
        spread > RMCN_Q30_ONE)
        return false;

    target_yaw_deg = rmcn_float_bits_to_q30(yaw_raw);
    target_pitch_deg = rmcn_float_bits_to_q30(pitch_raw);
    target_yaw = rmcn_q30_mul(target_yaw_deg, RMCN_Q30_DEG2RAD);
    target_pitch = rmcn_q30_mul(target_pitch_deg, RMCN_Q30_DEG2RAD);
    a = rmcn_q30_mul(spread_x, spread);
    b = rmcn_q30_mul(spread_y, spread);
    length = rmcn_q30_sqrt(
        RMCN_Q30_ONE + rmcn_q30_mul(a, a) + rmcn_q30_mul(b, b));
    denominator = rmcn_q30_sqrt(
        RMCN_Q30_ONE + rmcn_q30_mul(a, a));
    if (!length || !denominator)
        return false;

    rmcn_q30_sincos(target_pitch, &sin_target, &cos_target);
    (void)cos_target;
    asin_arg = rmcn_q30_div(
        rmcn_q30_mul(length, sin_target), denominator);
    asin_arg = rmcn_q30_clamp(
        asin_arg, -RMCN_Q30_ONE, RMCN_Q30_ONE);
    input_pitch = rmcn_q30_asin(asin_arg) -
                  rmcn_q30_atan2(a, RMCN_Q30_ONE);
    rmcn_q30_sincos(input_pitch, &sin_input, &cos_input);
    z0 = cos_input - rmcn_q30_mul(a, sin_input);
    input_yaw = target_yaw - rmcn_q30_atan2(b, z0);
    input_yaw %= RMCN_Q30_TWO_PI;
    if (input_yaw < 0)
        input_yaw += RMCN_Q30_TWO_PI;

    *out_yaw = rmcn_q30_to_float_bits(
        rmcn_q30_mul(input_yaw, RMCN_Q30_RAD2DEG));
    *out_pitch = rmcn_q30_to_float_bits(
        rmcn_q30_mul(input_pitch, RMCN_Q30_RAD2DEG));
    return true;
}

static void rmcn_clear_spread_context(pid_t pid)
{
    unsigned long flags;

    raw_spin_lock_irqsave(&rmcn_spread_context_lock, flags);
    if (pid <= 0 || rmcn_spread_context.pid == pid) {
        memset(&rmcn_spread_context, 0, sizeof(rmcn_spread_context));
        rmcn_spread_context_preloaded = false;
    }
    if (pid <= 0 || rmcn_spread_target.pid == pid)
        memset(&rmcn_spread_target, 0, sizeof(rmcn_spread_target));
    if (pid <= 0 || rmcn_spread_comp_snapshot.pid == pid)
        memset(&rmcn_spread_comp_snapshot, 0,
               sizeof(rmcn_spread_comp_snapshot));
    if (pid <= 0 || rmcn_spread_expected_pid == pid)
        memset(rmcn_spread_comp_ring, 0,
               sizeof(rmcn_spread_comp_ring));
    if (pid <= 0 || rmcn_spread_expected_pid == pid) {
        rmcn_spread_expected_pid = 0;
        rmcn_spread_expected_weapon = 0;
        rmcn_spread_capture_enabled = false;
    }
    if (pid <= 0 || rmcn_spread_preserve_detach_pid == pid)
        rmcn_spread_preserve_detach_pid = 0;
    raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
}

static void rmcn_set_spread_detach_preserve(pid_t pid, bool preserve)
{
    unsigned long flags;

    raw_spin_lock_irqsave(&rmcn_spread_context_lock, flags);
    if (preserve && pid > 0 && rmcn_spread_expected_pid == pid &&
        rmcn_spread_context.pid == pid)
        rmcn_spread_preserve_detach_pid = pid;
    else if (pid <= 0 || rmcn_spread_preserve_detach_pid == pid)
        rmcn_spread_preserve_detach_pid = 0;
    raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
}

static bool rmcn_consume_spread_detach_preserve(pid_t pid)
{
    unsigned long flags;
    bool preserve = false;

    raw_spin_lock_irqsave(&rmcn_spread_context_lock, flags);
    if (pid > 0 && rmcn_spread_preserve_detach_pid == pid &&
        rmcn_spread_expected_pid == pid &&
        rmcn_spread_context.pid == pid && rmcn_spread_capture_enabled) {
        preserve = true;
        rmcn_spread_preserve_detach_pid = 0;
    }
    raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
    return preserve;
}

static void rmcn_set_spread_expectation(pid_t pid, uint64_t weapon,
                                        bool enabled)
{
    unsigned long flags;
    bool weapon_identity_changed;

    weapon = rmcn_strip_user_ptr(weapon);
    if (weapon < RMCN_USER_MIN_ADDR)
        weapon = 0;

    raw_spin_lock_irqsave(&rmcn_spread_context_lock, flags);
    /*
     * Userspace resolves WeaponCustom while CalculateShootDir keeps a
     * different runtime weapon layer in X23.  Use the userspace pointer only
     * as a stable identity token for switch invalidation; comparing it with
     * X23 suppresses every capture even though the live object exposes the
     * verified spread fields.
     */
    weapon_identity_changed = rmcn_spread_expected_pid == pid &&
                              rmcn_spread_expected_weapon != weapon;
    if (!enabled || rmcn_spread_expected_pid != pid ||
        weapon_identity_changed) {
        memset(&rmcn_spread_context, 0, sizeof(rmcn_spread_context));
        rmcn_spread_context_preloaded = false;
        memset(&rmcn_spread_target, 0, sizeof(rmcn_spread_target));
        memset(&rmcn_spread_comp_snapshot, 0,
               sizeof(rmcn_spread_comp_snapshot));
        memset(rmcn_spread_comp_ring, 0,
               sizeof(rmcn_spread_comp_ring));
    }
    rmcn_spread_expected_pid = enabled ? pid : 0;
    rmcn_spread_expected_weapon = enabled ? weapon : 0;
    rmcn_spread_capture_enabled = enabled;
    raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
}

static bool rmcn_preload_spread_profile(pid_t pid, uint64_t packed_profile,
                                        uint32_t x_offset_bits,
                                        uint32_t y_offset_bits,
                                        bool inline_state)
{
    struct rmcn_spread_context next;
    struct rmcn_spread_formula_template formula_template;
    uint64_t weapon = 0;
    uint32_t spread_bits = 0;
    uint8_t is_ads = 0;
    unsigned long flags;
    int required_primes;

    memset(&next, 0, sizeof(next));
    memset(&formula_template, 0, sizeof(formula_template));
    if (inline_state) {
        next.x_times = (int32_t)(packed_profile & 0x3FULL);
        next.y_times = (int32_t)((packed_profile >> 6) & 0x3FULL);
        spread_bits = (uint32_t)(packed_profile >> 12);
        is_ads = (uint8_t)((packed_profile >> 44) & 1ULL);
    } else {
        next.x_times = (int32_t)(uint32_t)packed_profile;
        next.y_times = (int32_t)(uint32_t)(packed_profile >> 32);
    }
    next.x_offset_bits = x_offset_bits;
    next.y_offset_bits = y_offset_bits;
    if (pid <= 0 || next.x_times < 1 ||
        next.x_times > RMCN_SPREAD_MAX_TIMES || next.y_times < 1 ||
        next.y_times > RMCN_SPREAD_MAX_TIMES ||
        !rmcn_float_is_finite(x_offset_bits) ||
        !rmcn_float_is_finite(y_offset_bits) ||
        (x_offset_bits & 0x7FFFFFFFU) > 0x3F800000U ||
        (y_offset_bits & 0x7FFFFFFFU) > 0x3F800000U)
        return false;

    raw_spin_lock_irqsave(&rmcn_spread_context_lock, flags);
    if (rmcn_spread_capture_enabled && rmcn_spread_expected_pid == pid) {
        weapon = rmcn_spread_expected_weapon;
        formula_template = rmcn_spread_formula_template;
    }
    raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
    if (weapon < RMCN_USER_MIN_ADDR)
        return false;

    required_primes = max(next.x_times - 1, next.y_times - 1);
    if (required_primes > 0 &&
        (!formula_template.valid ||
         formula_template.prime_count < required_primes))
        return false;
    if ((!inline_state &&
         (!rmcn_get_user_u32(weapon + RMCN_WEAPON_TOTAL_SPREAD_OFFSET,
                             &spread_bits) ||
          !rmcn_get_user_u8(weapon + RMCN_WEAPON_IS_ADS_OFFSET,
                            &is_ads))) ||
        !rmcn_float_is_finite(spread_bits) ||
        (spread_bits & 0x7FFFFFFFU) == 0U ||
        (spread_bits & 0x7FFFFFFFU) > 0x3F800000U)
        return false;

    next.pid = pid;
    next.stamp = jiffies;
    next.weapon = weapon;
    next.captured_spread_bits = spread_bits;
    next.captured_is_ads = is_ads;
    next.prime_count = formula_template.prime_count;
    if (next.prime_count > 0)
        memcpy(next.primes, formula_template.primes,
               (size_t)next.prime_count * sizeof(next.primes[0]));

    raw_spin_lock_irqsave(&rmcn_spread_context_lock, flags);
    if (!rmcn_spread_capture_enabled || rmcn_spread_expected_pid != pid ||
        rmcn_spread_expected_weapon != weapon) {
        raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
        return false;
    }
    rmcn_spread_context = next;
    rmcn_spread_context_preloaded = true;
    raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
    return true;
}

static bool rmcn_capture_spread_context(pid_t pid, uint64_t formula,
                                        uint64_t parameter,
                                        uint64_t weapon,
                                        uint32_t seed,
                                        uint32_t projectile_index,
                                        uint32_t spread_bits)
{
    struct rmcn_spread_context next;
    uint64_t prime_array = 0;
    uint32_t weapon_spread = 0;
    uint8_t is_ads = 0;
    unsigned long flags;
    int i;

    memset(&next, 0, sizeof(next));
    formula = rmcn_strip_user_ptr(formula);
    parameter = rmcn_strip_user_ptr(parameter);
    weapon = rmcn_strip_user_ptr(weapon);
    raw_spin_lock_irqsave(&rmcn_spread_context_lock, flags);
    if (!rmcn_spread_capture_enabled ||
        rmcn_spread_expected_pid != pid) {
        raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
        return false;
    }
    raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
    if (pid <= 0 || formula < RMCN_USER_MIN_ADDR ||
        parameter < RMCN_USER_MIN_ADDR || weapon < RMCN_USER_MIN_ADDR ||
        !rmcn_float_is_finite(spread_bits) ||
        (spread_bits & 0x7FFFFFFFU) > 0x3F800000U ||
        !rmcn_get_user_i32(parameter + 0x58ULL, &next.x_times) ||
        !rmcn_get_user_i32(parameter + 0x5CULL, &next.y_times) ||
        !rmcn_get_user_u32(parameter + 0x60ULL, &next.x_offset_bits) ||
        !rmcn_get_user_u32(parameter + 0x64ULL, &next.y_offset_bits) ||
        !rmcn_get_user_u32(weapon + RMCN_WEAPON_TOTAL_SPREAD_OFFSET,
                           &weapon_spread) ||
        !rmcn_get_user_u8(weapon + RMCN_WEAPON_IS_ADS_OFFSET, &is_ads))
        return false;

    if (next.x_times < 1 || next.x_times > RMCN_SPREAD_MAX_TIMES ||
        next.y_times < 1 || next.y_times > RMCN_SPREAD_MAX_TIMES ||
        !rmcn_float_is_finite(next.x_offset_bits) ||
        !rmcn_float_is_finite(next.y_offset_bits) ||
        !rmcn_float_is_finite(weapon_spread) ||
        (next.x_offset_bits & 0x7FFFFFFFU) > 0x3F800000U ||
        (next.y_offset_bits & 0x7FFFFFFFU) > 0x3F800000U ||
        (weapon_spread & 0x7FFFFFFFU) > 0x3F800000U)
        return false;

    if (rmcn_get_user_u64(formula + 0x10ULL, &prime_array)) {
        prime_array = rmcn_strip_user_ptr(prime_array);
        if (prime_array >= RMCN_USER_MIN_ADDR)
            (void)rmcn_get_user_i32(prime_array + 0x18ULL,
                                    &next.prime_count);
    }
    if (next.prime_count < 0)
        next.prime_count = 0;
    if (next.prime_count > RMCN_SPREAD_MAX_TIMES)
        next.prime_count = RMCN_SPREAD_MAX_TIMES;
    for (i = 0; i < next.prime_count; i++) {
        if (!rmcn_get_user_i32(
                prime_array + 0x20ULL + (uint64_t)i * 4ULL,
                &next.primes[i])) {
            next.prime_count = i;
            break;
        }
    }
    if ((next.x_times > 1 || next.y_times > 1) &&
        next.prime_count < max(next.x_times - 1, next.y_times - 1))
        return false;

    next.pid = pid;
    next.stamp = jiffies;
    next.formula = formula;
    next.parameter = parameter;
    next.weapon = weapon;
    next.captured_seed = seed;
    next.captured_index = projectile_index;
    next.captured_spread_bits = spread_bits;
    next.captured_is_ads = is_ads;

    raw_spin_lock_irqsave(&rmcn_spread_context_lock, flags);
    if (rmcn_spread_capture_enabled &&
        rmcn_spread_expected_pid == pid) {
        rmcn_spread_context = next;
        rmcn_spread_context_preloaded = false;
        rmcn_spread_formula_template.valid = true;
        rmcn_spread_formula_template.prime_count = next.prime_count;
        memcpy(rmcn_spread_formula_template.primes, next.primes,
               sizeof(rmcn_spread_formula_template.primes));
    } else {
        raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
        return false;
    }
    raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
    WRITE_ONCE(rmcn_spread_last_seed, seed + projectile_index);
    WRITE_ONCE(rmcn_spread_last_bits, spread_bits);
    return true;
}

static bool rmcn_snapshot_spread_context(pid_t pid,
                                         struct rmcn_spread_context *out)
{
    unsigned long flags;
    bool ready = false;

    if (!out || pid <= 0)
        return false;
    raw_spin_lock_irqsave(&rmcn_spread_context_lock, flags);
    if (rmcn_spread_capture_enabled &&
        rmcn_spread_expected_pid == pid &&
        rmcn_spread_context.pid == pid && rmcn_spread_context.stamp &&
        time_before(jiffies, rmcn_spread_context.stamp +
                    RMCN_SPREAD_CONTEXT_TTL)) {
        *out = rmcn_spread_context;
        ready = true;
    }
    raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
    if (!ready)
        atomic64_inc(&rmcn_spread_cache_misses);
    return ready;
}

static uint32_t rmcn_spread_context_diag_flags(pid_t pid)
{
    unsigned long flags;
    uint32_t status = 0;

    if (pid <= 0)
        return 0;
    raw_spin_lock_irqsave(&rmcn_spread_context_lock, flags);
    if (rmcn_spread_capture_enabled && rmcn_spread_expected_pid == pid) {
        status |= NBG_SHADOW_DIAG_SPREAD_CAPTURE_ENABLED;
        if (rmcn_spread_context.pid == pid && rmcn_spread_context.stamp &&
            time_before(jiffies, rmcn_spread_context.stamp +
                        RMCN_SPREAD_CONTEXT_TTL)) {
            status |= NBG_SHADOW_DIAG_SPREAD_CONTEXT_READY;
            if (rmcn_spread_context_preloaded)
                status |= NBG_SHADOW_DIAG_SPREAD_CONTEXT_PRELOADED;
        }
    }
    raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
    return status;
}

static void rmcn_publish_spread_target(pid_t pid, uint32_t sequence,
                                       uint32_t yaw_bits,
                                       uint32_t pitch_bits)
{
    unsigned long flags;

    if (pid <= 0 || !sequence ||
        !rmcn_float_is_finite(yaw_bits) ||
        !rmcn_float_is_finite(pitch_bits))
        return;
    raw_spin_lock_irqsave(&rmcn_spread_context_lock, flags);
    if (rmcn_spread_capture_enabled && rmcn_spread_expected_pid == pid) {
        rmcn_spread_target.pid = pid;
        rmcn_spread_target.stamp = jiffies;
        rmcn_spread_target.sequence = sequence;
        rmcn_spread_target.yaw_bits = yaw_bits;
        rmcn_spread_target.pitch_bits = pitch_bits;
        rmcn_spread_target.active = true;
    }
    raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
}

static void rmcn_clear_spread_target(pid_t pid)
{
    unsigned long flags;

    raw_spin_lock_irqsave(&rmcn_spread_context_lock, flags);
    if (pid <= 0 || rmcn_spread_target.pid == pid)
        memset(&rmcn_spread_target, 0, sizeof(rmcn_spread_target));
    raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
}

static bool rmcn_snapshot_spread_target(
    pid_t pid, struct rmcn_spread_target_snapshot *out)
{
    unsigned long flags;
    bool ready = false;

    if (!out || pid <= 0)
        return false;
    raw_spin_lock_irqsave(&rmcn_spread_context_lock, flags);
    if (rmcn_spread_capture_enabled && rmcn_spread_expected_pid == pid &&
        rmcn_spread_target.active && rmcn_spread_target.pid == pid &&
        rmcn_spread_target.stamp &&
        time_before(jiffies, rmcn_spread_target.stamp + HZ)) {
        *out = rmcn_spread_target;
        ready = true;
    }
    raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
    return ready;
}

static bool rmcn_snapshot_compensated_input(
    pid_t pid, uint32_t sequence, struct rmcn_spread_comp_snapshot *out)
{
    struct rmcn_spread_comp_snapshot entry;
    unsigned long flags;
    bool matched = false;

    if (pid <= 0 || sequence == 0 || !out)
        return false;
    raw_spin_lock_irqsave(&rmcn_spread_context_lock, flags);
    entry = rmcn_spread_comp_ring[sequence & RMCN_SPREAD_COMP_RING_MASK];
    if (rmcn_spread_capture_enabled && rmcn_spread_expected_pid == pid &&
        entry.pid == pid && entry.sequence == sequence && entry.stamp &&
        time_before(jiffies, entry.stamp + HZ)) {
        *out = entry;
        matched = true;
    }
    raw_spin_unlock_irqrestore(&rmcn_spread_context_lock, flags);
    return matched;
}

static bool rmcn_compute_compensated_view(
    const struct rmcn_spread_context *context,
    uint32_t seed_base, uint32_t projectile_index,
    uint32_t target_yaw, uint32_t target_pitch,
    uint32_t *out_yaw, uint32_t *out_pitch,
    uint32_t *spread_bits_out)
{
    uint32_t spread_bits = 0;
    uint8_t is_ads;
    uint8_t live_is_ads = 0;
    int64_t spread;
    int64_t x_offset;
    int64_t y_offset;
    int64_t spread_x;
    int64_t spread_y;
    int32_t seed;

    if (!context || !out_yaw || !out_pitch ||
        context->weapon < RMCN_USER_MIN_ADDR ||
        !rmcn_float_is_finite(target_yaw) ||
        !rmcn_float_is_finite(target_pitch) ||
        context->captured_is_ads > 1U ||
        (context->captured_spread_bits &&
         (!rmcn_float_is_finite(context->captured_spread_bits) ||
          (context->captured_spread_bits & 0x7FFFFFFFU) > 0x3F800000U)))
        return false;

    is_ads = context->captured_is_ads;
    if (rmcn_get_user_u8(context->weapon + RMCN_WEAPON_IS_ADS_OFFSET,
                         &live_is_ads) && live_is_ads <= 1U)
        is_ads = live_is_ads;

    /* The formula/parameter tuple is calibrated by case38, but the current
     * weapon spread changes with ADS, movement and recovery. Prefer the live
     * field for every case40 invocation. Some weapons publish zero before
     * the shot update, so retain the last real S10 for that pre-shot window. */
    if (!rmcn_get_user_u32(
            context->weapon + RMCN_WEAPON_TOTAL_SPREAD_OFFSET,
            &spread_bits) ||
        !rmcn_float_is_finite(spread_bits) ||
        (spread_bits & 0x7FFFFFFFU) > 0x3F800000U ||
        ((spread_bits & 0x7FFFFFFFU) == 0U &&
         context->captured_spread_bits != 0U)) {
        spread_bits = context->captured_spread_bits;
    }
    if (!rmcn_float_is_finite(spread_bits) ||
        (spread_bits & 0x7FFFFFFFU) > 0x3F800000U)
        return false;

    if ((spread_bits & 0x7FFFFFFFU) == 0U) {
        *out_yaw = target_yaw;
        *out_pitch = target_pitch;
        if (spread_bits_out)
            *spread_bits_out = 0U;
        return true;
    }

    spread = rmcn_float_bits_to_q30(spread_bits);
    x_offset = rmcn_float_bits_to_q30(context->x_offset_bits);
    y_offset = rmcn_float_bits_to_q30(context->y_offset_bits);
    if (spread <= 0 || spread > RMCN_Q30_ONE ||
        x_offset < -RMCN_Q30_ONE || x_offset > RMCN_Q30_ONE ||
        y_offset < -RMCN_Q30_ONE || y_offset > RMCN_Q30_ONE)
        return false;

    /* The command sequence and the CalculateShootDir seed are separate
     * counters.  Use the seed observed at this exact call site. */
    seed = (int32_t)((uint32_t)seed_base + projectile_index);
    if (!rmcn_spread_xy_q30(seed, is_ads != 0,
                            context->x_times, context->y_times,
                            x_offset, y_offset, context->primes,
                            context->prime_count, &spread_x, &spread_y))
        return false;
    if (spread_bits_out)
        *spread_bits_out = spread_bits;
    return rmcn_inverse_spread_angle(target_yaw, target_pitch,
                                     spread_x, spread_y, spread,
                                     out_yaw, out_pitch);
}

/* FireRaycast 的 X23 是本次射线终点 FVector*。只改当前调用的
 * 12 字节临时参数，失败时回滚原值。 */
static bool nz_case8_write_endpoint(uint64_t endpoint,
                                    uint32_t target_x,
                                    uint32_t target_y,
                                    uint32_t target_z)
{
    uint32_t original_x;
    uint32_t original_y;
    uint32_t original_z;
    int ret_x;
    int ret_y;
    int ret_z;

    if (!rmcn_float_is_finite(target_x) ||
        !rmcn_float_is_finite(target_y) ||
        !rmcn_float_is_finite(target_z) ||
        !rmcn_user_range_ok(endpoint, 3 * sizeof(uint32_t)) ||
        !rmcn_get_user_u32(endpoint, &original_x) ||
        !rmcn_get_user_u32(endpoint + 4, &original_y) ||
        !rmcn_get_user_u32(endpoint + 8, &original_z))
        return false;

    endpoint = rmcn_strip_user_ptr(endpoint);
    pagefault_disable();
    ret_x = __put_user(target_x, (uint32_t __user *)endpoint);
    ret_y = __put_user(target_y, (uint32_t __user *)(endpoint + 4));
    ret_z = __put_user(target_z, (uint32_t __user *)(endpoint + 8));
    if (ret_x || ret_y || ret_z) {
        __put_user(original_x, (uint32_t __user *)endpoint);
        __put_user(original_y, (uint32_t __user *)(endpoint + 4));
        __put_user(original_z, (uint32_t __user *)(endpoint + 8));
    }
    pagefault_enable();
    return ret_x == 0 && ret_y == 0 && ret_z == 0;
}

static bool rmcn_put_user_u64(uint64_t addr, uint64_t value)
{
    int ret;

    if (!rmcn_user_range_ok(addr, sizeof(value)))
        return false;
    addr = rmcn_strip_user_ptr(addr);
    pagefault_disable();
    ret = __put_user(value, (uint64_t __user *)addr);
    pagefault_enable();
    return ret == 0;
}

static bool rmcn_put_user_u32(uint64_t addr, uint32_t value)
{
    int ret;

    if (!rmcn_user_range_ok(addr, sizeof(value)))
        return false;
    addr = rmcn_strip_user_ptr(addr);
    pagefault_disable();
    ret = __put_user(value, (uint32_t __user *)addr);
    pagefault_enable();
    return ret == 0;
}

static bool rmcn_put_user_u8(uint64_t addr, uint8_t value)
{
    int ret;

    if (!rmcn_user_range_ok(addr, sizeof(value)))
        return false;
    addr = rmcn_strip_user_ptr(addr);
    pagefault_disable();
    ret = __put_user(value, (uint8_t __user *)addr);
    pagefault_enable();
    return ret == 0;
}

static bool rmcn_put_user_u32_pair(uint64_t addr, uint32_t first,
                                   uint32_t second)
{
    uint32_t original_first = 0;
    uint32_t original_second = 0;
    int first_ret;
    int second_ret = -EFAULT;

    if (!rmcn_user_range_ok(addr, sizeof(uint32_t) * 2) ||
        !rmcn_get_user_u32(addr, &original_first) ||
        !rmcn_get_user_u32(addr + sizeof(uint32_t), &original_second))
        return false;

    addr = rmcn_strip_user_ptr(addr);
    pagefault_disable();
    first_ret = __put_user(first, (uint32_t __user *)addr);
    if (!first_ret) {
        second_ret = __put_user(second,
            (uint32_t __user *)(addr + sizeof(uint32_t)));
        if (second_ret)
            __put_user(original_first, (uint32_t __user *)addr);
    }
    pagefault_enable();
    (void)original_second;
    return first_ret == 0 && second_ret == 0;
}

static bool dfm_outline_character_context(uint64_t candidate,
                                          int32_t local_team,
                                          uint64_t *outline_out,
                                          bool *bot_out)
{
    uint64_t team_component = 0;
    uint64_t outline = 0;
    uint64_t outline_owner = 0;
    uint64_t main_mesh = 0;
    uint32_t net_update_bits = 0;
    int32_t team_id = 0;
    int32_t bot_flag = 0;

    candidate = rmcn_strip_user_ptr(candidate);
    if (!dfm_game_ptr_valid(candidate) || local_team <= 0 ||
        !outline_out || !bot_out ||
        !rmcn_get_user_u32(candidate + DFM_CHARACTER_NET_UPDATE_OFFSET,
                           &net_update_bits) ||
        net_update_bits != DFM_CHARACTER_NET_UPDATE_15_BITS)
        return false;

    if (!rmcn_get_user_u64(candidate + DFM_CHARACTER_MAIN_MESH_OFFSET,
                           &main_mesh) ||
        !dfm_game_ptr_valid(main_mesh))
        return false;

    if (!rmcn_get_user_u64(candidate + DFM_CHARACTER_TEAM_COMP_OFFSET,
                           &team_component))
        return false;
    team_component = rmcn_strip_user_ptr(team_component);
    if (!dfm_game_ptr_valid(team_component) ||
        !rmcn_get_user_i32(team_component + DFM_TEAM_ID_OFFSET, &team_id) ||
        team_id <= 0 || team_id == local_team)
        return false;

    if (!rmcn_get_user_u64(candidate + DFM_CHARACTER_OUTLINE_OFFSET,
                           &outline))
        return false;
    outline = rmcn_strip_user_ptr(outline);
    if (!dfm_game_ptr_valid(outline) ||
        !rmcn_get_user_u64(outline + DFM_COMPONENT_OWNER_OFFSET,
                           &outline_owner) ||
        rmcn_strip_user_ptr(outline_owner) != candidate)
        return false;

    rmcn_get_user_i32(candidate + DFM_CHARACTER_BOT_FLAG_OFFSET, &bot_flag);
    *outline_out = outline;
    *bot_out = bot_flag == 256;
    return true;
}

static bool dfm_outline_resolve_character(uint64_t mesh,
                                          int32_t local_team,
                                          uint64_t *outline_out,
                                          bool *bot_out)
{
    uint64_t owner = 0;
    uint64_t character_owner = 0;

    mesh = rmcn_strip_user_ptr(mesh);
    if (!dfm_game_ptr_valid(mesh) ||
        !rmcn_get_user_u64(mesh + DFM_COMPONENT_OWNER_OFFSET, &owner))
        return false;
    owner = rmcn_strip_user_ptr(owner);
    if (!dfm_game_ptr_valid(owner))
        return false;

    /* Character meshes resolve directly. Weapon meshes use only the verified
     * CharacterOwner link. Generic Owner/Instigator/AttachParent probing is
     * deliberately excluded from this debug-exception callback. */
    if (dfm_outline_character_context(owner, local_team,
                                      outline_out, bot_out))
        return true;

    if (!rmcn_get_user_u64(owner + DFM_WEAPON_CHARACTER_OWNER,
                           &character_owner))
        return false;
    character_owner = rmcn_strip_user_ptr(character_owner);
    return character_owner != owner && dfm_game_ptr_valid(character_owner) &&
           dfm_outline_character_context(character_owner, local_team,
                                         outline_out, bot_out);
}

static bool dfm_outline_material(uint64_t outline, bool bot,
                                 uint64_t *material_out,
                                 uint32_t *stencil_out)
{
    static const uint64_t human_offsets[] = {
        DFM_OUTLINE_RED_DYNAMIC_OFFSET,
        DFM_OUTLINE_RED_OFFSET,
    };
    static const uint64_t bot_offsets[] = {
        DFM_OUTLINE_GREEN_BUTTER_DYNAMIC,
        DFM_OUTLINE_GREEN_BUTTER_OFFSET,
        DFM_OUTLINE_GREEN_DYNAMIC_OFFSET,
        DFM_OUTLINE_GREEN_OFFSET,
    };
    const uint64_t *offsets = bot ? bot_offsets : human_offsets;
    const size_t count = bot ? ARRAY_SIZE(bot_offsets) :
                               ARRAY_SIZE(human_offsets);
    size_t i;

    outline = rmcn_strip_user_ptr(outline);
    if (!dfm_game_ptr_valid(outline) || !material_out || !stencil_out)
        return false;

    for (i = 0; i < count; i++) {
        uint64_t material = 0;

        if (rmcn_get_user_u64(outline + offsets[i], &material) &&
            dfm_game_ptr_valid(material)) {
            *material_out = rmcn_strip_user_ptr(material);
            *stencil_out = bot ? (i < 2 ? 59U : 32U) : 30U;
            return true;
        }
    }
    return false;
}

/* 纯断点模式：不写目标内存。
 * 旧实现对每个 mesh 写 6 个字段（PrimitiveFlags / StencilMask / StencilValue /
 * EffectFlags / AllowOcclusionCull / SkipBasePass / ForceUpdate），这些写入
 * 是可被反作弊扫描到的痕迹。现在全部去掉，只靠命中时改 X8 与该
 * 断点处的临时寄存器值完成替换；函数保留为校验/诊断入口。 */
static void dfm_outline_enable_mesh(uint64_t mesh, uint32_t stencil)
{
    mesh = rmcn_strip_user_ptr(mesh);
    if (!dfm_game_ptr_valid(mesh))
        return;

    (void)stencil;
}

static uint32_t shadow_fp32_mul_bits(uint32_t lhs, uint32_t rhs)
{
    uint32_t sign = ((lhs >> 31) ^ (rhs >> 31)) << 31;
    uint32_t exp_lhs = (lhs >> 23) & 0xFF;
    uint32_t exp_rhs = (rhs >> 23) & 0xFF;
    uint32_t mant_lhs;
    uint32_t mant_rhs;
    uint64_t product;
    int32_t exponent;

    if (exp_lhs == 0 || exp_rhs == 0)
        return sign;

    mant_lhs = (lhs & 0x7FFFFF) | 0x800000;
    mant_rhs = (rhs & 0x7FFFFF) | 0x800000;
    product = (uint64_t)mant_lhs * (uint64_t)mant_rhs;
    exponent = (int32_t)exp_lhs + (int32_t)exp_rhs - 127;

    if (product & (1ULL << 47)) {
        product >>= 24;
        exponent += 1;
    } else {
        product >>= 23;
    }

    if (exponent >= 255)
        return sign | 0x7F800000;
    if (exponent <= 0)
        return sign;
    return sign | ((uint32_t)exponent << 23) |
           ((uint32_t)product & 0x7FFFFF);
}

static bool rmcn_range_value_equal(const uint32_t *lhs, const uint32_t *rhs,
                                   uint32_t count)
{
    uint32_t i;

    for (i = 0; i < count; i++) {
        if (lhs[i] != rhs[i])
            return false;
    }
    return true;
}

static bool rmcn_range_dimension_valid(uint32_t raw, uint32_t minimum)
{
    return rmcn_float_is_finite(raw) && !(raw & 0x80000000U) &&
           raw >= minimum && raw <= RMCN_RANGE_DIM_MAX;
}

static bool rmcn_range_geometry_valid(uint32_t kind,
                                      const uint32_t values[3],
                                      uint32_t *value_count)
{
    if (!values || !value_count)
        return false;

    if (kind == RMCN_RANGE_CAPSULE_KIND) {
        *value_count = 2;
        return rmcn_range_dimension_valid(values[0],
                                          RMCN_RANGE_RADIUS_MIN) &&
               rmcn_range_dimension_valid(values[1], RMCN_RANGE_DIM_MIN);
    }
    if (kind == RMCN_RANGE_BOX_KIND) {
        *value_count = 3;
        return rmcn_range_dimension_valid(values[0], RMCN_RANGE_DIM_MIN) &&
               rmcn_range_dimension_valid(values[1], RMCN_RANGE_DIM_MIN) &&
               rmcn_range_dimension_valid(values[2], RMCN_RANGE_DIM_MIN);
    }
    return false;
}

static struct rmcn_range_geometry_entry *
rmcn_range_cache_lookup(struct rot_ctx *ctx, uint64_t address, bool create)
{
    uint32_t start;
    uint32_t i;

    if (!ctx || !ctx->range_cache || !address)
        return NULL;

    start = (uint32_t)((address >> 4) & (RMCN_RANGE_CACHE_SIZE - 1U));
    for (i = 0; i < RMCN_RANGE_CACHE_SIZE; i++) {
        struct rmcn_range_geometry_entry *entry =
            &ctx->range_cache[(start + i) & (RMCN_RANGE_CACHE_SIZE - 1U)];

        if (entry->address == address)
            return entry;
        if (!entry->address) {
            if (!create)
                return NULL;
            entry->address = address;
            return entry;
        }
    }
    return NULL;
}

static bool rmcn_range_write_values(uint64_t address,
                                    const uint32_t previous[3],
                                    const uint32_t values[3],
                                    uint32_t count)
{
    if (count == 2)
        return rmcn_put_user_u32_pair(address, values[0], values[1]);
    if (count != 3)
        return false;

    if (!rmcn_put_user_u32(address, values[0]))
        return false;
    if (!rmcn_put_user_u32(address + sizeof(uint32_t), values[1])) {
        rmcn_put_user_u32(address, previous[0]);
        return false;
    }
    if (!rmcn_put_user_u32(address + 2 * sizeof(uint32_t), values[2])) {
        rmcn_put_user_u32_pair(address, previous[0], previous[1]);
        return false;
    }
    return true;
}

/* range_lock is held by the caller. The cache keeps the first unscaled
 * geometry value, so changing the multiplier never compounds the old value. */
static bool rmcn_range_apply_geometry(struct rot_ctx *ctx, uint64_t address,
                                      uint32_t kind,
                                      uint32_t input_values[3],
                                      uint32_t factor, uint32_t output[3])
{
    struct rmcn_range_geometry_entry *entry;
    uint32_t scaled[3] = { 0, 0, 0 };
    uint32_t count;
    uint32_t i;
    bool preserve_original;

    if (!ctx || !input_values || !output)
        return false;

    count = kind == RMCN_RANGE_CAPSULE_KIND ? 2U :
            kind == RMCN_RANGE_BOX_KIND ? 3U : 0U;
    entry = rmcn_range_cache_lookup(ctx, address, false);
    preserve_original = entry && count && entry->kind == kind &&
                        entry->value_count == count &&
                        (rmcn_range_value_equal(input_values, entry->applied,
                                                count) ||
                         rmcn_range_value_equal(input_values, entry->original,
                                                count));

    /* Scaled dimensions can exceed DIM_MAX. Recognize our cached applied
     * values before validating a new, unscaled geometry; otherwise the next
     * hit loses the original and disable/update cannot restore it. */
    if (!preserve_original &&
        !rmcn_range_geometry_valid(kind, input_values, &count)) {
        if (entry)
            entry->value_count = 0;
        return false;
    }

    if (!entry)
        entry = rmcn_range_cache_lookup(ctx, address, true);
    if (!entry)
        return false;

    if (!preserve_original) {
        entry->kind = kind;
        entry->value_count = count;
        for (i = 0; i < count; i++) {
            entry->original[i] = input_values[i];
            entry->applied[i] = input_values[i];
        }
    }

    for (i = 0; i < count; i++)
        scaled[i] = shadow_fp32_mul_bits(entry->original[i], factor);

    if (!rmcn_range_value_equal(input_values, scaled, count) &&
        !rmcn_range_write_values(address, input_values, scaled, count))
        return false;

    for (i = 0; i < count; i++) {
        entry->applied[i] = scaled[i];
        output[i] = scaled[i];
    }
    return true;
}

static unsigned int rmcn_range_restore_and_free(struct rot_ctx *ctx)
{
    struct rmcn_range_geometry_entry *cache;

    if (!ctx)
        return 0;
    cache = ctx->range_cache;
    ctx->range_cache = NULL;
    if (!cache)
        return 0;

    /* 几何尺寸恢复依赖写内存，该路径已移除。 */
    kfree(cache);
    return 0;
}

static void rmcn_free_view_log_status(struct rot_ctx *ctx)
{
    unsigned long next;

    if (!ctx)
        return;
    next = READ_ONCE(ctx->free_view_next_log);
    if (time_before(jiffies, next) ||
        cmpxchg(&ctx->free_view_next_log, next,
                jiffies + RMCN_FREE_VIEW_LOG_PERIOD) != next)
        return;

    NBG_INFO("rmcn_free_view status pid=%d hits=%lld stack_fail=%lld\n",
             ctx->pid,
             (long long)atomic64_read(&ctx->free_view_hook_hits),
             (long long)atomic64_read(&ctx->free_view_stack_failures));
}

static int rmcn_free_view_command(struct rot_ctx *ctx, uint32_t operation)
{
    if (!ctx || (operation != RMCN_FREE_VIEW_ENABLE &&
                 operation != RMCN_FREE_VIEW_DISABLE))
        return -ENOENT;
    atomic_set(&ctx->free_view_command,
               operation == RMCN_FREE_VIEW_ENABLE ? 1 : 2);
    NBG_INFO("rmcn_free_view command queued pid=%d op=%u addr=0x%llx\n",
             ctx->pid, operation, (unsigned long long)ctx->target_vaddr);
    return 0;
}

/* 命中回调:在原子段执行,拿到 ctx 后按 is_rot_hook 走分支 */
NBG_NO_CFI
static void rot_hook_callback(struct pt_regs *regs, void *priv)
{
    struct rot_ctx *ctx = (struct rot_ctx *)priv;
    uint32_t cv0, cv1, cv2;
    unsigned int custom_seq;

    if (!ctx || !regs || !READ_ONCE(ctx->active))
        return;

    /* yaw/pitch/flags 必须来自同一次用户层更新，否则自动开火
     * gate 可能与上一帧角度组合。seqcount 让三个 u32 成为一个快照。 */
    do {
        custom_seq = read_seqcount_begin(&ctx->custom_seq);
        cv0 = READ_ONCE(ctx->custom_value[0]);
        cv1 = READ_ONCE(ctx->custom_value[1]);
        cv2 = READ_ONCE(ctx->custom_value[2]);
    } while (read_seqcount_retry(&ctx->custom_seq, custom_seq));

    switch (READ_ONCE(ctx->is_rot_hook)) {
    case NBG_SHADOW_RMCN_FREE_VIEW_TYPE: {
        uint64_t saved_x20 = 0;
        uint64_t saved_x19 = 0;
        int command;

        atomic64_inc(&ctx->free_view_hook_hits);
        rmcn_free_view_log_status(ctx);
        if (!rmcn_get_user_u64(regs->sp + 48, &saved_x20) ||
            !rmcn_get_user_u64(regs->sp + 56, &saved_x19)) {
            atomic64_inc(&ctx->free_view_stack_failures);
            break;
        }
        regs->regs[20] = saved_x20;
        regs->regs[19] = saved_x19;

        command = atomic_xchg(&ctx->free_view_command, 0);
        if (command) {
            regs->regs[0] = command == 1 ? 1 : 0;
            regs->regs[1] = command == 1 ? 1 : 0;
            regs->regs[2] = 0;
            regs->regs[3] = 0;
            regs->regs[30] = ctx->target_vaddr + 4;
            regs->pc = ctx->module_base +
                       RMCN_FREE_VIEW_SET_OBSERVER_RVA - 4;
        }
        break;
    }
    case NBG_SHADOW_DFM_OUTLINE_RENDER_TYPE: {
        uint64_t mesh;
        uint64_t original_material = 0;
        uint64_t outline = 0;
        uint64_t material = 0;
        uint32_t stencil = 0;
        bool bot = false;

        /* The breakpoint core advances PC by four, so reproduce the skipped
         * LDR for every mesh before applying the enemy-only substitution. */
        if (!ctx->insn_decoded || ctx->dec_is_fp || !ctx->dec_is_load ||
            ctx->dec_pc_rel || ctx->dec_size != 8 || ctx->dec_rn != 20 ||
            ctx->dec_rt != 8 ||
            ctx->dec_offset != DFM_MESH_EFFECT_MATERIAL_OFFSET ||
            !current || current->flags & (PF_EXITING | PF_KTHREAD))
            break;

        mesh = rmcn_strip_user_ptr(regs->regs[20]);
        if (!dfm_game_ptr_valid(mesh) ||
            !rmcn_get_user_u64(mesh + DFM_MESH_EFFECT_MATERIAL_OFFSET,
                               &original_material)) {
            regs->regs[8] = 0;
            break;
        }
        regs->regs[8] = original_material;

        {
            static atomic64_t mat_hits = ATOMIC64_INIT(0);
            const uint64_t h = atomic64_inc_return(&mat_hits);
            if (h <= 5 || (h & 0x1FF) == 0)
                NBG_INFO("dfm mat hit=%llu mesh=0x%llx mat=0x%llx\n",
                         (unsigned long long)h,
                         (unsigned long long)mesh,
                         (unsigned long long)original_material);
        }

        if (cv0 == 0) {
            static atomic64_t noteam = ATOMIC64_INIT(0);
            const uint64_t h = atomic64_inc_return(&noteam);
            if (h <= 3 || (h & 0x3FF) == 0)
                NBG_INFO("dfm skip: local_team=0 hits=%llu\n",
                         (unsigned long long)h);
            break;
        }

        if (!dfm_outline_resolve_character(mesh, (int32_t)cv0,
                                           &outline, &bot)) {
            uint64_t owner = 0;
            uint32_t nuf = 0;
            static atomic64_t nores = ATOMIC64_INIT(0);
            const uint64_t h = atomic64_inc_return(&nores);
            rmcn_get_user_u64(mesh + DFM_COMPONENT_OWNER_OFFSET, &owner);
            owner = rmcn_strip_user_ptr(owner);
            if (owner && dfm_game_ptr_valid(owner))
                rmcn_get_user_u32(owner + DFM_CHARACTER_NET_UPDATE_OFFSET,
                                  &nuf);
            if (h <= 5 || (h & 0x1FF) == 0)
                NBG_INFO("dfm nochar h=%llu mesh=0x%llx owner=0x%llx nuf=0x%x\n",
                         (unsigned long long)h,
                         (unsigned long long)mesh,
                         (unsigned long long)owner, nuf);
            break;
        }

        if (!dfm_outline_material(outline, bot, &material, &stencil)) {
            static atomic64_t nomat = ATOMIC64_INIT(0);
            const uint64_t h = atomic64_inc_return(&nomat);
            if (h <= 5 || (h & 0x1FF) == 0)
                NBG_INFO("dfm nomat h=%llu outline=0x%llx bot=%d\n",
                         (unsigned long long)h,
                         (unsigned long long)outline, bot ? 1 : 0);
            break;
        }

        if (bot && cv2 != 0)
            stencil = cv2;
        else if (!bot && cv1 != 0)
            stencil = cv1;
        regs->regs[8] = material;
        {
            static atomic64_t oks = ATOMIC64_INIT(0);
            const uint64_t h = atomic64_inc_return(&oks);
            if (h <= 10 || (h & 0x3F) == 0)
                NBG_INFO("dfm OK h=%llu mesh=0x%llx mat=0x%llx orig=0x%llx stencil=%u bot=%d\n",
                         (unsigned long long)h,
                         (unsigned long long)mesh,
                         (unsigned long long)material,
                         (unsigned long long)original_material, stencil,
                         bot ? 1 : 0);
        }
        dfm_outline_enable_mesh(mesh, stencil);
        break;
    }
    case NBG_SHADOW_DFM_OUTLINE_FLAGS_TYPE: {
        /* 同一个字节 0x728 的三个位被分三次读：
         *   bit0 bDrawEffectPass        （0x10812CE8）
         *   bit1 bReverseDrawEffectPassCulling
         *   bit2 bEffectPassNeedDepth   （0x10812D00）
         * 这里只抬高 bit0，让引擎走 EffectPass 通道；
         * 不写目标内存，只改本次 LDRB 的目标寄存器。 */
        if (!ctx->insn_decoded || ctx->dec_is_fp || !ctx->dec_is_load ||
            ctx->dec_pc_rel || ctx->dec_size != 1 ||
            ctx->dec_rn != 20 || ctx->dec_rt != 8 ||
            ctx->dec_offset != DFM_MESH_EFFECT_FLAGS_OFFSET)
            break;

        {
            static atomic64_t flags_hits = ATOMIC64_INIT(0);
            const uint64_t h = atomic64_inc_return(&flags_hits);
            if (h <= 3 || (h & 0x3FF) == 0)
                NBG_INFO("dfm flags hit=%llu x20=0x%llx raw=0x%llx\n",
                         (unsigned long long)h,
                         (unsigned long long)regs->regs[20],
                         (unsigned long long)(regs->regs[8] & 0xFF));
        }

        /* 置 bit0（bDrawEffectPass），其余位保持原值。 */
        regs->regs[8] = (regs->regs[8] & ~0xFFULL) |
                        ((regs->regs[8] & 0xFFULL) | DFM_EFFECT_PASS_DRAW_BIT);
        break;
    }
    case 24: {
        const uint64_t hit = atomic64_inc_return(&dfm_slot_trace_hits);

        /* This point is an official NOP between slot selection and the two
         * Transform swaps. The raw breakpoint core advances PC by four. */
        if (hit <= DFM_SLOT_TRACE_EVENT_LIMIT) {
            watch_push_custom_event(regs->regs[8], regs->regs[9],
                                    DFM_SLOT_TRACE_EVENT_X8_X9,
                                    (uint32_t)hit);
            watch_push_custom_event(regs->regs[10], regs->regs[11],
                                    DFM_SLOT_TRACE_EVENT_X10_X11,
                                    (uint32_t)hit);
            watch_push_custom_event(regs->regs[12], regs->regs[13],
                                    DFM_SLOT_TRACE_EVENT_X12_X13,
                                    (uint32_t)hit);
            watch_push_custom_event(regs->sp, regs->regs[30],
                                    DFM_SLOT_TRACE_EVENT_SP_LR,
                                    (uint32_t)hit);
        }
        break;
    }
    case 25: {
        const uint64_t hit = atomic64_inc_return(&dfm_formula_trace_hits);

        /* Capture the current-season affine slot inputs once. The raw
         * breakpoint core advances PC, so reproduce BIC W0,W11,W3 exactly. */
        if (hit <= DFM_FORMULA_EVENT_LIMIT) {
            watch_push_custom_event(regs->regs[8], regs->regs[11],
                                    DFM_FORMULA_EVENT_X8_X11,
                                    (uint32_t)hit);
            watch_push_custom_event(regs->regs[12], regs->regs[13],
                                    DFM_FORMULA_EVENT_X12_X13,
                                    (uint32_t)hit);
            watch_push_custom_event(regs->regs[19], regs->regs[20],
                                    DFM_FORMULA_EVENT_X19_X20,
                                    (uint32_t)hit);
            watch_push_custom_event(regs->sp, regs->regs[30],
                                    DFM_FORMULA_EVENT_SP_LR,
                                    (uint32_t)hit);
        }
        regs->regs[0] = (uint32_t)(regs->regs[11] & ~regs->regs[3]);
        break;
    }
    case 28:
    case NBG_SHADOW_DYNAMIC_HOOK_TYPE: {
        const uint64_t hit = atomic64_inc_return(&dfm_index_trace_hits);
        const bool dynamic_layout =
            READ_ONCE(ctx->is_rot_hook) == NBG_SHADOW_DYNAMIC_HOOK_TYPE;
        uint64_t stack_scalar = 0;
        uint64_t stack_direct = 0;
        uint64_t stack_indirect = 0;
        const uint32_t scalar_offset = dynamic_layout ? cv0 : 0x590U;
        const uint32_t direct_pointer_offset = dynamic_layout ? cv1 : 0x230U;
        const uint32_t indirect_pointer_offset = dynamic_layout ? cv2 : 0x818U;
        const uint32_t opcode = ctx->trace_insn & 0xFFE00000U;
        const uint32_t rd = ctx->trace_insn & 0x1FU;
        const uint32_t rn = (ctx->trace_insn >> 5) & 0x1FU;
        const uint32_t ra = (ctx->trace_insn >> 10) & 0x1FU;
        const uint32_t rm = (ctx->trace_insn >> 16) & 0x1FU;
        const uint64_t rn_value = rn == 31U ? 0 : regs->regs[rn];
        const uint64_t rm_value = rm == 31U ? 0 : regs->regs[rm];
        uint64_t ra_value = ra == 31U ? 0 : regs->regs[ra];
        const bool umaddl = opcode == 0x9BA00000U;
        const bool stack_load =
            ctx->insn_decoded && ctx->dec_is_load && !ctx->dec_is_fp &&
            !ctx->dec_pc_rel && (ctx->dec_size == 4 || ctx->dec_size == 8) &&
            ctx->dec_rn == 31 && ctx->dec_rt == 8 &&
            ctx->dec_offset >= 0 &&
            (uint64_t)ctx->dec_offset == (uint64_t)scalar_offset;
        const bool capture_instruction = umaddl || stack_load;
        const bool tid_match = !ctx->trace_tid ||
                               (current && current->pid == ctx->trace_tid);

        if (dynamic_layout && hit <= 8ULL)
            NBG_INFO("shadow dynamic callback pid=%d tid=%d trace_tid=%d pc=0x%llx insn=%08x decoded=%d size=%d rn=%d rt=%d off=%lld state=%d\n",
                     current ? current->tgid : 0, current ? current->pid : 0,
                     ctx->trace_tid, (unsigned long long)regs->pc,
                     ctx->trace_insn, ctx->insn_decoded ? 1 : 0,
                     ctx->dec_size, ctx->dec_rn, ctx->dec_rt,
                     (long long)ctx->dec_offset,
                     atomic_read(&ctx->trace_capture_state));

        /* The callback runs from the synchronous debug exception path.  Only
         * the requested thread gets one snapshot; all other hits immediately
         * fall through to instruction emulation. */
        if (capture_instruction && tid_match && regs &&
            (!dynamic_layout || (scalar_offset && direct_pointer_offset &&
                                 indirect_pointer_offset)) &&
            scalar_offset <= 0x2000U && direct_pointer_offset <= 0x2000U &&
            indirect_pointer_offset <= 0x2000U &&
            atomic_cmpxchg(&ctx->trace_capture_state, 0, 1) == 0) {
            uint32_t stack_scalar32 = 0;
            bool scalar_ok = false;
            bool direct_ok = false;
            bool indirect_ok = false;
            bool read_ok;

            /* W8 and the legacy UMADDL scalar are 32-bit stack fields. */
            if (ctx->dec_size == 4 || umaddl) {
                scalar_ok = rmcn_get_user_u32(regs->sp + scalar_offset,
                                              &stack_scalar32);
                stack_scalar = stack_scalar32;
            } else {
                scalar_ok = rmcn_get_user_u64(regs->sp + scalar_offset,
                                              &stack_scalar);
            }
            direct_ok = rmcn_get_user_u64(regs->sp + direct_pointer_offset,
                                          &stack_direct);
            indirect_ok = rmcn_get_user_u64(regs->sp + indirect_pointer_offset,
                                            &stack_indirect);
            read_ok = scalar_ok && direct_ok && indirect_ok;
            if (dynamic_layout && hit <= 8ULL)
                NBG_INFO("shadow dynamic read pid=%d tid=%d sp=0x%llx scalar=%d direct=%d indirect=%d offsets=0x%x/0x%x/0x%x\n",
                         current ? current->tgid : 0,
                         current ? current->pid : 0,
                         (unsigned long long)regs->sp,
                         scalar_ok ? 1 : 0, direct_ok ? 1 : 0,
                         indirect_ok ? 1 : 0, scalar_offset,
                         direct_pointer_offset, indirect_pointer_offset);
            if (read_ok) {
                /* Three compact events are enough for userspace to assemble
                 * one hit: SP/LR, scalar and the two pointer roots. */
                watch_push_custom_event(regs->sp, regs->regs[30],
                                        DFM_INDEX_EVENT_SP_LR, (uint32_t)hit);
                watch_push_custom_event(0, stack_scalar,
                                        DFM_INDEX_EVENT_RAW_SP590,
                                        (uint32_t)hit);
                watch_push_custom_event(stack_direct, stack_indirect,
                                        DFM_INDEX_EVENT_SP230_SP818,
                                        (uint32_t)hit);
                /* Keep the legacy chain marker so an older user client can
                 * finish its three-part capture while newer clients ignore it. */
                watch_push_custom_event(0, 0, DFM_INDEX_EVENT_CHAIN,
                                        (uint32_t)hit);
                watch_push_custom_event(regs->regs[23], 0,
                                        DFM_INDEX_EVENT_X23,
                                        (uint32_t)hit);
                watch_push_custom_event(regs->regs[26], 0,
                                        DFM_INDEX_EVENT_X26,
                                        (uint32_t)hit);
                atomic_set(&ctx->trace_capture_state, 2);
            } else {
                /* A transient unmapped stack slot must not permanently arm a
                 * failed capture; the next execution can provide a frame. */
                atomic_set(&ctx->trace_capture_state, 0);
            }
        }

        /* Preserve the original instruction result after the capture. */
        if (umaddl)
            ra_value += (uint64_t)(uint32_t)rn_value *
                        (uint64_t)(uint32_t)rm_value;
        else if (stack_load && rd < 31U)
            ra_value = ctx->dec_size == 4
                           ? (uint64_t)(uint32_t)stack_scalar
                           : stack_scalar;
        if ((umaddl || stack_load) && rd < 31U)
            regs->regs[rd] = ra_value;
        break;
    }
    case NBG_SHADOW_FP_LDP_SCALE_HOOK_TYPE: {
        struct user_fpsimd_state *fpst;
        uint64_t geometry;
        uint32_t kind = 0;
        uint32_t values[3] = { 0, 0, 0 };
        uint32_t output[3] = { 0, 0, 0 };
        unsigned long flags;
        bool third_ready = true;
        bool applied = false;
        const bool diagnostics = (cv1 & RMCN_RANGE_DIAG_FLAG) != 0U;
        uint64_t hit = 0;
        uint64_t applies = 0;

        /* The hardware-breakpoint core advances PC over the original LDP.
         * Always reproduce S6/S5; eligible player geometry is also updated
         * in place so later narrow-phase loads observe the same dimensions. */
        if (!current || current->flags & (PF_EXITING | PF_KTHREAD) ||
            !fpsimd_save_flush_fn || !ctx->range_cache)
            break;
        geometry = rmcn_strip_user_ptr(regs->regs[1]);
        if (diagnostics)
            hit = atomic64_inc_return(&ctx->scalar_hook_hits);
        if (!rmcn_get_user_u32(geometry, &kind) ||
            !rmcn_get_user_u32(geometry + sizeof(uint32_t), &values[0]) ||
            !rmcn_get_user_u32(geometry + 2 * sizeof(uint32_t), &values[1])) {
            if (diagnostics)
                atomic64_inc(&ctx->scalar_hook_failures);
            break;
        }
        output[0] = values[0];
        output[1] = values[1];

        if (kind == RMCN_RANGE_BOX_KIND)
            third_ready = rmcn_get_user_u32(
                geometry + 3 * sizeof(uint32_t), &values[2]);
        if (third_ready && rmcn_float_is_finite(cv0) &&
            cv0 >= RMCN_RANGE_FACTOR_MIN && cv0 <= RMCN_RANGE_FACTOR_MAX) {
            raw_spin_lock_irqsave(&ctx->range_lock, flags);
            applied = rmcn_range_apply_geometry(
                ctx, geometry + sizeof(uint32_t), kind, values, cv0, output);
            raw_spin_unlock_irqrestore(&ctx->range_lock, flags);
        }

        if (diagnostics) {
            if (applied)
                applies = atomic64_inc_return(&ctx->scalar_hook_applies);
            if (hit <= 64U || !(hit & 0xFFFU) ||
                (applied && (applies <= 64U || !(applies & 0xFFFU))))
                watch_push_custom_event(
                    geometry + sizeof(uint32_t),
                    ((uint64_t)values[1] << 32) | values[0],
                    RMCN_RANGE_EVENT_INPUT, (uint32_t)hit);
            if (applied && (applies <= 64U || !(applies & 0xFFFU)))
                watch_push_custom_event(
                    geometry + sizeof(uint32_t),
                    ((uint64_t)output[1] << 32) | output[0],
                    RMCN_RANGE_EVENT_OUTPUT, (uint32_t)applies);
        }

        fpsimd_save_flush_fn();
        fpst = &current->thread.uw.fpsimd_state;
        fpst->vregs[6] =
            (fpst->vregs[6] & ~(__uint128_t)0xFFFFFFFFUL) |
            (__uint128_t)output[0];
        fpst->vregs[5] =
            (fpst->vregs[5] & ~(__uint128_t)0xFFFFFFFFUL) |
            (__uint128_t)output[1];
        smp_wmb();
        set_thread_flag(TIF_FOREIGN_FPSTATE);
        break;
    }
    case 2: {
        /* 浮点寄存器注入：硬件断点命中后跳过当前原指令，直接更新
         * current->thread 的 SIMD/FP 状态。
         * custom_value[0] = 目标 SIMD/FP 寄存器编号(S0=0,S1=1,...)
         * custom_value[1] = 写入低 32-bit 的 float 原始位
         * custom_value[2] = 可选 X30/LR 低 32 位过滤；0 表示不过滤。
         *
         * 该路径不读取目标地址，也不要求被断指令是 FP LDR，因此可以
         * 在相邻的 GP LDR 与 FP LDR 断点上分别注入 S0、S1，让后续原生
         * FMUL/FADD 等指令继续执行。 */
        uint32_t rt_cfg = cv0;
        uint32_t value  = cv1;
        uint32_t lr_lo  = cv2;
        uint32_t rt_final;
        const uint64_t hit =
            atomic64_inc_return(&ctx->scalar_hook_hits);

        if (hit <= 64 || !(hit & 0xFFU)) {
            uint32_t marker = (uint32_t)hit;
            if (fpsimd_save_flush_fn)
                marker |= DFM_SCALAR_HOOK_FPSTATE_FLAG;
            watch_push_custom_event(ctx->target_vaddr, regs->pc,
                                    DFM_SCALAR_HOOK_EVENT, marker);
        }

        if (lr_lo && ((uint32_t)regs->regs[30] != lr_lo))
            break;

        rt_final = rt_cfg;
        if (rt_final >= 32) {
            if (!ctx->insn_decoded)
                break;
            rt_final = ctx->dec_rt;
        }
        if (rt_final >= 32 || !fpsimd_save_flush_fn)
            break;
        if (!current || current->flags & (PF_EXITING | PF_KTHREAD))
            break;

        {
            struct user_fpsimd_state *fpst = &current->thread.uw.fpsimd_state;
            __uint128_t mask = ~(__uint128_t)0xFFFFFFFFUL;

            fpsimd_save_flush_fn();
            fpst->vregs[rt_final] = (fpst->vregs[rt_final] & mask) |
                                    (__uint128_t)value;
            smp_wmb();
            set_thread_flag(TIF_FOREIGN_FPSTATE);
        }
        break;
    }

    case 1: {
        /* 跳转改写:让 PC 跳到 target_vaddr + offset。-4 抵消硬件 +4 */
        uint32_t offset = cv0;
        uint64_t target = ctx->target_vaddr + offset;
        regs->pc = target - 4;
        break;
    }

    case 4: {
        /* 弹道补偿:把 (regs[0]+0x50/0x54/0x58) 改成三个 custom_value,
         * 同时让 v0/v1/v2 = 这三个值;再把 PC 推到本 getter 的 RET。
         * bm_bp_entry 还会统一 +4,所以这里只额外 +8,避免跳过后面的 case7。 */
        uint64_t sc = regs->regs[0];
        uint32_t v0 = cv0;
        uint32_t v1 = cv1;
        uint32_t v2 = cv2;
        if (sc < 0x1000) break;

        pagefault_disable();
        if (access_ok((void __user *)(sc + 0x50), 12)) {
            __put_user(v0, (uint32_t __user *)(sc + 0x50));
            __put_user(v1, (uint32_t __user *)(sc + 0x54));
            __put_user(v2, (uint32_t __user *)(sc + 0x58));
        }
        pagefault_enable();

        if (current && !(current->flags & (PF_EXITING | PF_KTHREAD))) {
            struct user_fpsimd_state *fpst = &current->thread.uw.fpsimd_state;
            fpst->vregs[0] = (fpst->vregs[0] & ~(__uint128_t)0xFFFFFFFFUL) | (__uint128_t)v0;
            fpst->vregs[1] = (fpst->vregs[1] & ~(__uint128_t)0xFFFFFFFFUL) | (__uint128_t)v1;
            fpst->vregs[2] = (fpst->vregs[2] & ~(__uint128_t)0xFFFFFFFFUL) | (__uint128_t)v2;
            /* HWBP-12:三个 128-bit 字段写完后再设标志,保证调度路径
             * 在 fpsimd_restore_current_state 时看到完整结果。 */
            smp_wmb();
            set_thread_flag(TIF_FOREIGN_FPSTATE);
        }

        regs->pc += 8;
        break;
    }
    case 5: {
        /* 弹道寄存器注入:不写 [X0] 内存,只替换当前目标浮点寄存器。
         * custom_value[0] = 目标 SIMD/FP 寄存器编号(S0=0,S1=1,S2=2)
         * custom_value[1] = 要写入的 float 原始 bit
         * custom_value[2] = 可选 X30/LR 低 32 位过滤；0 表示不过滤。 */
        uint32_t rt_cfg = cv0;
        uint32_t value  = cv1;
        uint32_t lr_lo  = cv2;
        uint32_t rt_final;

        if (lr_lo && ((uint32_t)regs->regs[30] != lr_lo))
            break;

        rt_final = rt_cfg;
        if (rt_final >= 32) {
            if (!ctx->insn_decoded)
                break;
            rt_final = ctx->dec_rt;
        }
        if (rt_final >= 32)
            break;
        if (!current || current->flags & (PF_EXITING | PF_KTHREAD))
            break;

        {
            struct user_fpsimd_state *fpst = &current->thread.uw.fpsimd_state;
            __uint128_t mask = ~(__uint128_t)0xFFFFFFFFUL;

            if (fpsimd_save_flush_fn)
                fpsimd_save_flush_fn();

            fpst->vregs[rt_final] = (fpst->vregs[rt_final] & mask) |
                                    (__uint128_t)value;
            smp_wmb();
            set_thread_flag(TIF_FOREIGN_FPSTATE);
        }
        break;
    }
    case 8: {
        /* UInstantHitFireRaycastSubComponent::FireRaycast：
         *   0x1145A2A4 MOV X0,X22   <- 本 hook，必须仿真
         * X23 指向本次射线终点，custom_value[0..2] 是目标世界 XYZ。 */

        nz_case8_push_event(ctx, regs, NZ_CASE8_EVENT_HIT, &nz_case8_hits);

        /* bm_bp_entry 会跳过原指令，先仿真 MOV X0,X22。 */
        regs->regs[0] = regs->regs[22];
        if (!nz_case8_write_endpoint(regs->regs[23], cv0, cv1, cv2)) {
            nz_case8_push_event(ctx, regs, NZ_CASE8_EVENT_FALLBACK,
                                &nz_case8_fallbacks);
            break;
        }
        smp_wmb();
        nz_case8_push_event(ctx, regs, NZ_CASE8_EVENT_SUCCESS,
                            &nz_case8_successes);
        break;
    }
    case NBG_SHADOW_RMCN_ROTATION_INPUT_TYPE: {
        if (ctx->case35_camera_return) {
            uint64_t saved_x20 = 0, saved_x19 = 0;
            const uint64_t cmd = rmcn_strip_user_ptr(regs->regs[19]);
            uint32_t sequence = 0;
            atomic64_inc(&ctx->scalar_hook_hits);
            /* Always reproduce LDP X20,X19,[SP,#0x20]. */
            if (!rmcn_get_user_u64(regs->sp + 0x20ULL, &saved_x20) ||
                !rmcn_get_user_u64(regs->sp + 0x28ULL, &saved_x19)) {
                atomic64_inc(&ctx->scalar_hook_failures);
                break;
            }
            regs->regs[20] = saved_x20;
            regs->regs[19] = saved_x19;
            if (current && !(current->flags & (PF_EXITING | PF_KTHREAD)) &&
                fpsimd_save_flush_fn) {
                struct user_fpsimd_state *fpst;
                const __uint128_t mask = ~(__uint128_t)0xFFFFFFFFUL;
                uint32_t pitch, yaw, target_pitch, target_yaw;
                bool target_active = false;
                fpsimd_save_flush_fn();
                fpst = &current->thread.uw.fpsimd_state;
                pitch = (uint32_t)fpst->vregs[0];
                yaw = (uint32_t)fpst->vregs[1];
                target_pitch = pitch;
                target_yaw = yaw;
                WRITE_ONCE(ctx->scalar_last_native,
                           ((uint64_t)pitch << 32) | yaw);
                if ((cv2 & 1U) && rmcn_float_is_finite(cv0) &&
                    rmcn_float_is_finite(cv1) &&
                    (cv0 & 0x7FFFFFFFU) <= 0x43B40000U &&
                    (cv1 & 0x7FFFFFFFU) <= 0x42B40000U) {
                    target_yaw = yaw = cv0;
                    target_pitch = pitch = cv1;
                    target_active = true;
                }
                (void)rmcn_get_user_u32(cmd + RMCN_USERCMD_SEQUENCE_OFFSET,
                                        &sequence);
                if (target_active && sequence != 0 &&
                    (cv2 & NBG_RMCN_SYNC_INPUT_SPREAD_FLAG)) {
                    struct rmcn_spread_context spread_context;
                    if (rmcn_snapshot_spread_context(current->tgid,
                                                     &spread_context)) {
                        uint32_t corrected_yaw = yaw, corrected_pitch = pitch;
                        uint32_t spread_bits = 0;
                        atomic64_inc(&rmcn_spread_comp_attempts);
                        if (rmcn_compute_compensated_view(
                                &spread_context, sequence,
                                spread_context.captured_index,
                                target_yaw, target_pitch, &corrected_yaw,
                                &corrected_pitch, &spread_bits)) {
                            struct rmcn_spread_comp_snapshot entry;
                            unsigned long spread_flags;
                            yaw = corrected_yaw;
                            pitch = corrected_pitch;
                            atomic64_inc(&rmcn_spread_comp_successes);
                            WRITE_ONCE(rmcn_spread_last_sequence, sequence);
                            WRITE_ONCE(rmcn_spread_last_seed,
                                       sequence + spread_context.captured_index);
                            WRITE_ONCE(rmcn_spread_last_projectile_index,
                                       spread_context.captured_index);
                            WRITE_ONCE(rmcn_spread_last_bits, spread_bits);
                            WRITE_ONCE(rmcn_spread_last_target_yaw_bits,
                                       target_yaw);
                            WRITE_ONCE(rmcn_spread_last_target_pitch_bits,
                                       target_pitch);
                            WRITE_ONCE(rmcn_spread_last_comp_yaw_bits, yaw);
                            WRITE_ONCE(rmcn_spread_last_comp_pitch_bits,
                                       pitch);
                            entry.pid = current->tgid;
                            entry.stamp = jiffies;
                            entry.sequence = sequence;
                            entry.target_yaw_bits = target_yaw;
                            entry.target_pitch_bits = target_pitch;
                            entry.compensated_yaw_bits = yaw;
                            entry.compensated_pitch_bits = pitch;
                            raw_spin_lock_irqsave(&rmcn_spread_context_lock,
                                                  spread_flags);
                            rmcn_spread_comp_snapshot = entry;
                            rmcn_spread_comp_ring[
                                sequence & RMCN_SPREAD_COMP_RING_MASK] = entry;
                            raw_spin_unlock_irqrestore(&rmcn_spread_context_lock,
                                                       spread_flags);
                        } else {
                            atomic64_inc(&rmcn_spread_compute_rejects);
                        }
                    }
                }
                if (target_active) {
                    /* The same inverse input is sent to UserCmd and the
                     * original game spread math; the spread field is intact. */
                    fpst->vregs[0] = (fpst->vregs[0] & mask) | pitch;
                    fpst->vregs[1] = (fpst->vregs[1] & mask) | yaw;
                    smp_wmb();
                    set_thread_flag(TIF_FOREIGN_FPSTATE);
                    atomic64_inc(&ctx->scalar_hook_applies);
                }
                if (target_active && sequence != 0)
                    rmcn_publish_spread_target(current->tgid, sequence,
                                               target_yaw, target_pitch);
                else
                    rmcn_clear_spread_target(current->tgid);
                WRITE_ONCE(ctx->scalar_last_output,
                           ((uint64_t)pitch << 32) | yaw);
                WRITE_ONCE(ctx->scalar_last_cmd, cmd);
                WRITE_ONCE(ctx->scalar_last_sequence, sequence);
            } else {
                atomic64_inc(&ctx->scalar_hook_failures);
            }
            break;
        }
        {
        /* MgrMyPlayer.CorrectCmdViewPitchYaw(UserCmd,float):
         * STP S1,S2,[X20,#0x2C] is the official ViewYaw/ViewPitch store.
         * case35 changes only that pair; all other camera and movement paths
         * remain native. */
        struct user_fpsimd_state *fpst;
        const uint64_t cmd = rmcn_strip_user_ptr(regs->regs[20]);
        const bool active = (cv2 & 1U) != 0U;
        uint32_t sequence = 0;
        uint32_t output_yaw;
        uint32_t output_pitch;

        if (!current || current->flags & (PF_EXITING | PF_KTHREAD) ||
            !fpsimd_save_flush_fn || cmd < RMCN_USER_MIN_ADDR)
            break;

        fpsimd_save_flush_fn();
        fpst = &current->thread.uw.fpsimd_state;
        /* The native STP source order is S1=ViewYaw, S2=ViewPitch. */
        output_yaw = (uint32_t)fpst->vregs[1];
        output_pitch = (uint32_t)fpst->vregs[2];
        (void)rmcn_get_user_u32(cmd + RMCN_USERCMD_SEQUENCE_OFFSET,
                                &sequence);

        if (active && rmcn_float_is_finite(cv0) &&
            rmcn_float_is_finite(cv1) &&
            (cv0 & 0x7FFFFFFFU) <= 0x43B40000U &&
            (cv1 & 0x7FFFFFFFU) <= 0x42B40000U) {
            output_yaw = cv0;
            output_pitch = cv1;
            if ((cv2 & 2U) && sequence != 0)
                rmcn_publish_spread_target(current->tgid, sequence,
                                           output_yaw, output_pitch);
            else
                rmcn_clear_spread_target(current->tgid);
        } else {
            rmcn_clear_spread_target(current->tgid);
        }

        /* Emulate the skipped STP at the official command address. */
        if (!rmcn_put_user_u32_pair(cmd + 0x2CULL,
                                    output_yaw, output_pitch))
            break;
        smp_wmb();
        break;
        }
    }
    case NBG_SHADOW_RMCN_CROSSHAIR_INPUT_TYPE: {
        /* CameraThirdState.CorrectShootPitchYaw:
         *   LDP S1,S0,[X20,#0x2C]
         * is the upper camera-angle pair input. The HWBP core skips the
         * original instruction, so this callback must reproduce the native
         * load on pass-through and replace S1/S0 only while active.
         * custom_value[0] = yaw bits -> S1
         * custom_value[1] = pitch bits -> S0
         * custom_value[2] bit0 = active. */
        struct user_fpsimd_state *fpst;
        const __uint128_t low32_mask = ~(__uint128_t)0xFFFFFFFFUL;
        const uint64_t pair = rmcn_strip_user_ptr(regs->regs[20]);
        uint32_t native_yaw = 0;
        uint32_t native_pitch = 0;

        atomic64_inc(&ctx->scalar_hook_hits);
        if (!current || (current->flags & (PF_EXITING | PF_KTHREAD)) ||
            !fpsimd_save_flush_fn || pair < RMCN_USER_MIN_ADDR)
            break;

        /* Emulate LDP S1,S0,[X20,#0x2C] before applying the optional pair. */
        if (!rmcn_get_user_u32(pair + 0x2CULL, &native_yaw) ||
            !rmcn_get_user_u32(pair + 0x30ULL, &native_pitch))
            break;

        fpsimd_save_flush_fn();
        fpst = &current->thread.uw.fpsimd_state;
        fpst->vregs[1] = (fpst->vregs[1] & low32_mask) |
                          (__uint128_t)native_yaw;
        fpst->vregs[0] = (fpst->vregs[0] & low32_mask) |
                          (__uint128_t)native_pitch;

        if ((cv2 & 1U) && rmcn_float_is_finite(cv0) &&
            rmcn_float_is_finite(cv1) &&
            (cv0 & 0x7FFFFFFFU) <= 0x43B40000U &&
            (cv1 & 0x7FFFFFFFU) <= 0x42B40000U) {
            fpst->vregs[1] = (fpst->vregs[1] & low32_mask) |
                             (__uint128_t)cv0;
            fpst->vregs[0] = (fpst->vregs[0] & low32_mask) |
                             (__uint128_t)cv1;
        }
        smp_wmb();
        set_thread_flag(TIF_FOREIGN_FPSTATE);
        break;
    }
    case NBG_SHADOW_RMCN_NO_SPREAD_TYPE: {
        struct user_fpsimd_state *fpst;
        const __uint128_t low32_mask = ~(__uint128_t)0xFFFFFFFFUL;
        const uint32_t shot_seed = (uint32_t)regs->regs[21];
        const uint32_t projectile_index = (uint32_t)regs->regs[20];
        uint32_t live_angle0_bits;
        uint32_t live_angle1_bits;
        uint32_t spread;

        atomic64_inc(&rmcn_case38_hits);
        if (!current || (current->flags & (PF_EXITING | PF_KTHREAD)) ||
            !fpsimd_save_flush_fn)
            break;

        fpsimd_save_flush_fn();
        fpst = &current->thread.uw.fpsimd_state;
        live_angle0_bits = (uint32_t)fpst->vregs[0];
        live_angle1_bits = (uint32_t)fpst->vregs[1];
        WRITE_ONCE(rmcn_spread_last_seed, shot_seed + projectile_index);
        WRITE_ONCE(rmcn_spread_last_projectile_index, projectile_index);
        WRITE_ONCE(rmcn_spread_last_live_angle0_bits,
                   live_angle0_bits);
        WRITE_ONCE(rmcn_spread_last_live_angle1_bits,
                   live_angle1_bits);
        spread = (uint32_t)fpst->vregs[10];
        /* Reproduce the skipped FMOV S2,S10 exactly. */
        fpst->vregs[2] = (fpst->vregs[2] & low32_mask) |
                          (__uint128_t)spread;
        if ((cv2 & 1U) && rmcn_capture_spread_context(
                current->tgid, regs->regs[22], regs->regs[19],
                regs->regs[23], shot_seed, projectile_index, spread)) {
            atomic64_inc(&rmcn_case38_captures);
        }
        /* case38 is capture-only. Applying the inverse here changes a
         * transient CalculateShootDir vector that is later replaced by the
         * official command pipeline. case40 applies the inverse to the shared
         * upstream ray input before the mode-specific corrections. */
        smp_wmb();
        set_thread_flag(TIF_FOREIGN_FPSTATE);
        break;
    }
    case NBG_SHADOW_RMCN_TPP_SHOOT_INPUT_TYPE: {
        /* Current build: CalculateShootDir begins with
         *   FMOV S9,S1
         *   FMOV S8,S0  <- this hook
         *
         * At this boundary S0 is viewYaw and S1 is viewPitch.  c0/c1 are the
         * transient target yaw/pitch pair; W3/W7 are the formula seed and
         * projectile index. */
        struct user_fpsimd_state *fpst;
        struct rmcn_spread_context spread_context;
        struct rmcn_spread_target_snapshot published_target;
        const __uint128_t low32_mask = ~(__uint128_t)0xFFFFFFFFUL;
        const uint64_t cmd = rmcn_strip_user_ptr(regs->regs[19]);
        uint32_t sequence = 0;
        uint32_t native_yaw = 0;
        uint32_t native_pitch = 0;
        uint32_t target_yaw = 0;
        uint32_t target_pitch = 0;
        uint32_t desired_yaw = 0;
        uint32_t desired_pitch = 0;
        uint32_t output_yaw = 0;
        uint32_t output_pitch = 0;
        uint32_t compensated_spread = 0;
        unsigned long spread_flags;
        const bool shoot_override =
            (cv2 & RMCN_TPP_SHOOT_OVERRIDE_FLAG) != 0U;
        const bool direct_calculate_payload =
            (cv2 & NBG_RMCN_TPP_SHOOT_CALCULATE_DIR_FLAG) != 0U;
        bool calculate_dir_hook = direct_calculate_payload;
        bool published_target_ready = false;
        bool compensated = false;

        atomic64_inc(&rmcn_case40_hits);

        if (!current || current->flags & (PF_EXITING | PF_KTHREAD) ||
            !fpsimd_save_flush_fn)
            break;

        fpsimd_save_flush_fn();
        fpst = &current->thread.uw.fpsimd_state;

        if (cv2 & NBG_RMCN_SYNC_INPUT_SPREAD_FLAG) {
            struct rmcn_spread_comp_snapshot matched_input;
            struct rmcn_spread_target_snapshot latest_target;
            const uint32_t shoot_seed = (uint32_t)regs->regs[3];
            uint32_t output_yaw = (uint32_t)fpst->vregs[0];
            uint32_t output_pitch = (uint32_t)fpst->vregs[1];
            const bool matched = rmcn_snapshot_compensated_input(
                current->tgid, shoot_seed, &matched_input);
            if (matched) {
                output_yaw = matched_input.compensated_yaw_bits;
                output_pitch = matched_input.compensated_pitch_bits;
                atomic64_inc(&rmcn_spread_shot_matches);
                atomic64_inc(&rmcn_case40_comp_successes);
                WRITE_ONCE(rmcn_spread_last_sequence_delta, 0);
            } else if (rmcn_snapshot_spread_target(current->tgid,
                                                   &latest_target)) {
                atomic64_inc(&rmcn_spread_shot_mismatches);
                WRITE_ONCE(rmcn_spread_last_sequence_delta,
                           (int32_t)(shoot_seed - latest_target.sequence));
            } else {
                atomic64_inc(&rmcn_spread_shot_unpaired);
            }
            /* FMOV S9,S1 ran just before the breakpoint. Keep both the
             * native and the synchronized branch's saved FP inputs paired;
             * no weapon field and no game instruction is modified. */
            fpst->vregs[0] = (fpst->vregs[0] & low32_mask) |
                             (__uint128_t)output_yaw;
            fpst->vregs[1] = (fpst->vregs[1] & low32_mask) |
                             (__uint128_t)output_pitch;
            fpst->vregs[8] = (fpst->vregs[8] & low32_mask) |
                             (__uint128_t)output_yaw;
            fpst->vregs[9] = (fpst->vregs[9] & low32_mask) |
                             (__uint128_t)output_pitch;
            smp_wmb();
            set_thread_flag(TIF_FOREIGN_FPSTATE);
            break;
        }

        /* case35 publishes the same target pair at the official command
         * boundary.  The control thread can update case40 just after the
         * game's CalculateShootDir call has already entered, leaving c2 at
         * the native/pass-through value for that one shot.  Do not lose the
         * shot in that race: the published snapshot is short-lived, is only
         * created for an active tracking target, and carries the exact target
         * pair that case35 committed. */
        if (!calculate_dir_hook)
            published_target_ready = rmcn_snapshot_spread_target(
                current->tgid, &published_target);
        if (!calculate_dir_hook && published_target_ready)
            calculate_dir_hook = true;

        if (calculate_dir_hook) {
            uint32_t seed_base = (uint32_t)regs->regs[3];
            uint32_t projectile_index = (uint32_t)regs->regs[7];
            bool target_ready = false;

            /* CalculateShootDir's native ordering is yaw,pitch.  Start from
             * the live values, then replace only when the user layer marks a
             * firing frame and supplied a finite target pair. */
            native_yaw = (uint32_t)fpst->vregs[0];
            native_pitch = (uint32_t)fpst->vregs[1];
            output_yaw = native_yaw;
            output_pitch = native_pitch;
            target_yaw = native_yaw;
            target_pitch = native_pitch;
            /* The function itself is the shot-direction stage. Do not lose
             * a first shot merely because the external fire poll is late.
             * The marker also prevents pointer payloads being read as angles. */
            if (direct_calculate_payload && (cv2 & 1U) &&
                rmcn_float_is_finite(cv0) &&
                rmcn_float_is_finite(cv1) &&
                (cv0 & 0x7FFFFFFFU) <= 0x43B40000U &&
                (cv1 & 0x7FFFFFFFU) <= 0x42B40000U) {
                target_yaw = cv0;
                target_pitch = cv1;
                output_yaw = target_yaw;
                output_pitch = target_pitch;
                target_ready = true;
            } else if (published_target_ready &&
                       rmcn_float_is_finite(published_target.yaw_bits) &&
                       rmcn_float_is_finite(published_target.pitch_bits) &&
                       (published_target.yaw_bits & 0x7FFFFFFFU) <=
                           0x43B40000U &&
                       (published_target.pitch_bits & 0x7FFFFFFFU) <=
                           0x42B40000U) {
                target_yaw = published_target.yaw_bits;
                target_pitch = published_target.pitch_bits;
                output_yaw = target_yaw;
                output_pitch = target_pitch;
                target_ready = true;
            }

            /* Both the direct userspace override and the short-lived
             * case35 snapshot are valid target sources.  The old branch only
             * ran the inverse-spread solver for the snapshot path, so the
             * active direct path incremented case40 hits while leaving
             * compensation at zero.  Resolve the source first, then run the
             * same per-shot solver for either source. */
            if (target_ready &&
                rmcn_snapshot_spread_context(current->tgid,
                                              &spread_context)) {
                uint32_t seed_base = (uint32_t)regs->regs[3];
                uint32_t projectile_index = (uint32_t)regs->regs[7];
                atomic64_inc(&rmcn_spread_comp_attempts);
                compensated = rmcn_compute_compensated_view(
                    &spread_context, seed_base, projectile_index,
                    target_yaw, target_pitch, &desired_yaw,
                    &desired_pitch, &compensated_spread);
                if (compensated) {
                    output_yaw = desired_yaw;
                    output_pitch = desired_pitch;
                    atomic64_inc(&rmcn_spread_comp_successes);
                    atomic64_inc(&rmcn_case40_comp_successes);
                    WRITE_ONCE(rmcn_spread_last_sequence, seed_base);
                    WRITE_ONCE(rmcn_spread_last_seed,
                               seed_base + projectile_index);
                    WRITE_ONCE(rmcn_spread_last_projectile_index,
                               projectile_index);
                    WRITE_ONCE(rmcn_spread_last_bits,
                               compensated_spread);
                    WRITE_ONCE(rmcn_spread_last_target_yaw_bits,
                               target_yaw);
                    WRITE_ONCE(rmcn_spread_last_target_pitch_bits,
                               target_pitch);
                    WRITE_ONCE(rmcn_spread_last_comp_yaw_bits,
                               desired_yaw);
                    WRITE_ONCE(rmcn_spread_last_comp_pitch_bits,
                               desired_pitch);
                } else {
                    atomic64_inc(&rmcn_spread_compute_rejects);
                }
            }

            /* FMOV S9,S1 has already executed before this breakpoint.
             * Both the hot-update path and FNEG S0,S9 below consume that
             * saved pitch, so changing S1 alone only fixes yaw.  Refresh
             * S9 as well as emulating the skipped FMOV S8,S0. */
            fpst->vregs[0] = (fpst->vregs[0] & low32_mask) |
                             (__uint128_t)output_yaw;
            fpst->vregs[1] = (fpst->vregs[1] & low32_mask) |
                             (__uint128_t)output_pitch;
            fpst->vregs[8] = (fpst->vregs[8] & low32_mask) |
                             (__uint128_t)output_yaw;
            fpst->vregs[9] = (fpst->vregs[9] & low32_mask) |
                             (__uint128_t)output_pitch;
            WRITE_ONCE(rmcn_spread_last_live_angle0_bits, output_yaw);
            WRITE_ONCE(rmcn_spread_last_live_angle1_bits, output_pitch);
            smp_wmb();
            set_thread_flag(TIF_FOREIGN_FPSTATE);
            break;
        }

        /* The current hook address is CalculateShootDir's
         * FMOV S8,S0 boundary.  Its native ABI is S0=viewYaw,
         * S1=viewPitch, including the compatibility path where the
         * calculate-dir marker is absent.  The old fallback reversed these
         * registers, which made level shots appear correct while any
         * non-zero vertical angle missed. */
        native_yaw = (uint32_t)fpst->vregs[0];
        native_pitch = (uint32_t)fpst->vregs[1];
        WRITE_ONCE(rmcn_spread_last_live_angle0_bits, native_yaw);
        WRITE_ONCE(rmcn_spread_last_live_angle1_bits, native_pitch);
        output_yaw = native_yaw;
        output_pitch = native_pitch;
        target_yaw = native_yaw;
        target_pitch = native_pitch;
        if (shoot_override && rmcn_float_is_finite(cv0) &&
            rmcn_float_is_finite(cv1) &&
            (cv0 & 0x7FFFFFFFU) <= 0x43B40000U &&
            (cv1 & 0x7FFFFFFFU) <= 0x42B40000U) {
            /* c0/c1 are the third-person muzzle-origin target yaw/pitch.
             * This boundary must not update the persistent camera or UserCmd
             * view pair. */
            target_yaw = cv0;
            target_pitch = cv1;
            output_yaw = target_yaw;
            output_pitch = target_pitch;
        }
        if (cmd >= RMCN_USER_MIN_ADDR)
            (void)rmcn_get_user_u32(cmd + RMCN_USERCMD_SEQUENCE_OFFSET,
                                    &sequence);

        if ((cv2 & 3U) == 3U && sequence &&
            rmcn_float_is_finite(target_yaw) &&
            rmcn_float_is_finite(target_pitch) &&
            (target_yaw & 0x7FFFFFFFU) <= 0x43B40000U &&
            (target_pitch & 0x7FFFFFFFU) <= 0x42B40000U &&
            rmcn_snapshot_spread_context(current->tgid, &spread_context)) {
            atomic64_inc(&rmcn_spread_comp_attempts);
            /* CorrectCmdShootPitchYaw runs before this shot reaches the
             * case38 CalculateShootDir capture.  UserCmd.Sequence is the
             * seed base for the command being built now; using the saved
             * case38 seed here would lag one round during automatic fire.
             * The cached projectile index and formula are stable across this
             * short handoff. */
            compensated = rmcn_compute_compensated_view(
                &spread_context, sequence,
                spread_context.captured_index, target_yaw, target_pitch,
                &desired_yaw, &desired_pitch, &compensated_spread);
            if (compensated) {
                output_yaw = desired_yaw;
                output_pitch = desired_pitch;
                atomic64_inc(&rmcn_spread_comp_successes);
                atomic64_inc(&rmcn_case40_comp_successes);
                WRITE_ONCE(rmcn_spread_last_sequence, sequence);
                WRITE_ONCE(rmcn_spread_last_bits, compensated_spread);
                WRITE_ONCE(rmcn_spread_last_target_yaw_bits, target_yaw);
                WRITE_ONCE(rmcn_spread_last_target_pitch_bits,
                           target_pitch);
                WRITE_ONCE(rmcn_spread_last_comp_yaw_bits, desired_yaw);
                WRITE_ONCE(rmcn_spread_last_comp_pitch_bits, desired_pitch);
                WRITE_ONCE(rmcn_spread_last_sequence_delta,
                           (int32_t)(sequence -
                                     (sequence +
                                      spread_context.captured_index)));
                raw_spin_lock_irqsave(&rmcn_spread_context_lock,
                                      spread_flags);
                rmcn_spread_comp_snapshot.pid = current->tgid;
                rmcn_spread_comp_snapshot.stamp = jiffies;
                rmcn_spread_comp_snapshot.sequence = sequence;
                rmcn_spread_comp_snapshot.target_yaw_bits = target_yaw;
                rmcn_spread_comp_snapshot.target_pitch_bits = target_pitch;
                rmcn_spread_comp_snapshot.compensated_yaw_bits = desired_yaw;
                rmcn_spread_comp_snapshot.compensated_pitch_bits =
                    desired_pitch;
                rmcn_spread_comp_ring[
                    sequence & RMCN_SPREAD_COMP_RING_MASK] =
                    rmcn_spread_comp_snapshot;
                raw_spin_unlock_irqrestore(&rmcn_spread_context_lock,
                                           spread_flags);
            } else {
                atomic64_inc(&rmcn_spread_compute_rejects);
            }
        }

        fpst->vregs[0] = (fpst->vregs[0] & low32_mask) |
                         (__uint128_t)output_yaw;
        fpst->vregs[1] = (fpst->vregs[1] & low32_mask) |
                         (__uint128_t)output_pitch;
        fpst->vregs[8] = (fpst->vregs[8] & low32_mask) |
                         (__uint128_t)output_yaw;
        /* The saved pitch is already live at the FMOV S8,S0 boundary. */
        fpst->vregs[9] = (fpst->vregs[9] & low32_mask) |
                         (__uint128_t)output_pitch;
        smp_wmb();
        set_thread_flag(TIF_FOREIGN_FPSTATE);
        break;
    }
    default:
        break;
    }
}

static pid_t shadow_normalize_tgid(pid_t pid, struct task_struct **task_out)
{
    struct task_struct *task = NULL;
    pid_t tgid = pid;

    if (task_out)
        *task_out = NULL;
    if (pid <= 0)
        return pid;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) {
        get_task_struct(task);
        tgid = task->tgid;
    }
    rcu_read_unlock();

    if (task_out)
        *task_out = task;
    else if (task)
        put_task_struct(task);
    return tgid;
}

static bool shadow_rva_matches(uint64_t base, uint64_t target, uint64_t rva)
{
    return base >= RMCN_USER_MIN_ADDR && target > base &&
           target - base == rva;
}

static bool shadow_exact_hook_spec(uint32_t hook_type,
                                   uint32_t *expected_insn,
                                   uint64_t *expected_rva)
{
    if (!expected_insn || !expected_rva)
        return false;

    switch (hook_type) {
    case 8:
        *expected_insn = NZ_FIRE_RAYCAST_ENDPOINT_INSN;
        *expected_rva = NZ_FIRE_RAYCAST_ENDPOINT_RVA;
        return true;
    case 24:
        *expected_insn = DFM_SLOT_TRACE_NOP_INSN;
        *expected_rva = 0;
        return true;
    case 25:
        *expected_insn = DFM_FORMULA_TRACE_INSN;
        *expected_rva = 0;
        return true;
    case NBG_SHADOW_RMCN_ROTATION_INPUT_TYPE:
        *expected_insn = RMCN_ROTATION_INPUT_PAIR_INSN;
        *expected_rva = RMCN_ROTATION_INPUT_PAIR_RVA;
        return true;
    case NBG_SHADOW_RMCN_CROSSHAIR_INPUT_TYPE:
        *expected_insn = RMCN_CROSSHAIR_INPUT_PAIR_INSN;
        *expected_rva = RMCN_CROSSHAIR_INPUT_PAIR_RVA;
        return true;
    case NBG_SHADOW_RMCN_NO_SPREAD_TYPE:
        *expected_insn = RMCN_SPREAD_CONTEXT_INSN;
        *expected_rva = RMCN_SPREAD_CONTEXT_RVA;
        return true;
    case NBG_SHADOW_RMCN_TPP_SHOOT_INPUT_TYPE:
        *expected_insn = RMCN_TPP_SHOOT_INPUT_INSN;
        *expected_rva = RMCN_TPP_SHOOT_INPUT_RVA;
        return true;
    case 28:
    case NBG_SHADOW_DYNAMIC_HOOK_TYPE:
        /* The current-season ring selector changes register allocation per
         * build. Validation is performed by dfm_index_trace_insn_valid(). */
        *expected_insn = 0;
        *expected_rva = 0;
        return false;
    case NBG_SHADOW_FP_LDP_SCALE_HOOK_TYPE:
        *expected_insn = RMCN_RANGE_PAIR_LOAD_INSN;
        *expected_rva = RMCN_RANGE_PAIR_LOAD_RVA;
        return true;
    case NBG_SHADOW_DFM_OUTLINE_RENDER_TYPE:
        *expected_insn = DFM_OUTLINE_MATERIAL_LOAD_INSN;
        *expected_rva = DFM_OUTLINE_MATERIAL_LOAD_RVA;
        return true;
    case NBG_SHADOW_DFM_OUTLINE_FLAGS_TYPE:
        *expected_insn = DFM_OUTLINE_FLAGS_LOAD_INSN;
        *expected_rva = DFM_OUTLINE_FLAGS_DRAW_RVA;
        return true;
    case NBG_SHADOW_RMCN_FREE_VIEW_TYPE:
        *expected_insn = RMCN_FREE_VIEW_EPILOGUE_INSN;
        *expected_rva = RMCN_FREE_VIEW_EPILOGUE_RVA;
        return true;
    default:
        return false;
    }
}

static bool shadow_ctx_can_emulate(const struct rot_ctx *ctx, uint32_t hook_type)
{
    if (!ctx)
        return false;

    switch (hook_type) {
    case 2:
        return fpsimd_save_flush_fn != NULL;
    case NBG_SHADOW_FP_LDP_SCALE_HOOK_TYPE:
        return fpsimd_save_flush_fn != NULL && ctx->range_cache != NULL &&
               ctx->insn_decoded && ctx->dec_is_fp && ctx->dec_is_load &&
               !ctx->dec_pc_rel && ctx->dec_size == 4 &&
               ctx->dec_rn == 1 && ctx->dec_rt == 6 &&
               ctx->dec_offset == 4;
    case 8:
        return true;
    case NBG_SHADOW_RMCN_ROTATION_INPUT_TYPE:
    case NBG_SHADOW_RMCN_CROSSHAIR_INPUT_TYPE:
        return fpsimd_save_flush_fn != NULL;
    case NBG_SHADOW_RMCN_NO_SPREAD_TYPE:
    case NBG_SHADOW_RMCN_TPP_SHOOT_INPUT_TYPE:
        return fpsimd_save_flush_fn != NULL;
    case NBG_SHADOW_DFM_OUTLINE_RENDER_TYPE:
        return ctx->insn_decoded && !ctx->dec_is_fp && ctx->dec_is_load &&
               !ctx->dec_pc_rel && ctx->dec_size == 8 &&
               ctx->dec_rn == 20 && ctx->dec_rt == 8 &&
               ctx->dec_offset == DFM_MESH_EFFECT_MATERIAL_OFFSET;
    case NBG_SHADOW_DFM_OUTLINE_FLAGS_TYPE:
        return ctx->insn_decoded && !ctx->dec_is_fp && ctx->dec_is_load &&
               !ctx->dec_pc_rel && ctx->dec_size == 1 &&
               ctx->dec_rn == 20 && ctx->dec_rt == 8 &&
               ctx->dec_offset == DFM_MESH_EFFECT_FLAGS_OFFSET;
    case NBG_SHADOW_RMCN_FREE_VIEW_TYPE:
        return ctx->module_base >= RMCN_USER_MIN_ADDR;
    default:
        return true;
    }
}

/* ---- 公开接口 ---- */

int shadow_add_hook(struct shadow_req *req)
{
    struct rot_ctx *ctx = NULL;
    struct raw_bp_req rreq;
    struct task_struct *task = NULL;
    uint32_t original_insn = 0;
    uint32_t requested_type;
    uint32_t hook_type;
    uint32_t expected_insn = 0;
    uint64_t expected_rva = 0;
    pid_t hook_pid;
    bool read_ok;
    bool exact_validate;
    bool case35_camera_return = false;
    int i, ret;

    if (!req || (req->target_vaddr & 0x3))
    {
        NBG_FAIL_CODE(2201, -EINVAL);
        return -EINVAL;
    }

    requested_type = (uint32_t)req->is_rot_hook;
    if (!rot_hook_type_supported(requested_type)) {
        NBG_INFO("shadow unsupported type=%d pid=%d addr=0x%llx\n",
                 req->is_rot_hook, req->pid,
                 (unsigned long long)req->target_vaddr);
        NBG_FAIL_CODE(2207, -EOPNOTSUPP);
        return -EOPNOTSUPP;
    }

    hook_pid = shadow_normalize_tgid(req->pid, &task);
    if (!task) {
        NBG_FAIL_CODE(2208, -ESRCH);
        return -ESRCH;
    }

    /* 统一提前读取原指令；XOM 读 0 时走 base+RVA 校验。 */
    read_ok = read_process_memory_kernel(hook_pid, req->target_vaddr,
                                         &original_insn,
                                         sizeof(original_insn));
    hook_type = requested_type;
    if (!rot_hook_type_supported(hook_type)) {
        put_task_struct(task);
        NBG_INFO("shadow unsupported resolved type=%u requested=%u pid=%d addr=0x%llx insn=%08x\n",
                 hook_type, requested_type, hook_pid,
                 (unsigned long long)req->target_vaddr, original_insn);
        NBG_FAIL_CODE(2207, -EOPNOTSUPP);
        return -EOPNOTSUPP;
    }

    /* 用内核读取 XOM 代码页并核对被仿真的原指令。版本偏移漂移时
     * 必须拒绝安装，不能跳过一条未知指令后再强写寄存器。 */
    exact_validate = shadow_exact_hook_spec(hook_type, &expected_insn,
                                            &expected_rva);
    if (hook_type == NBG_SHADOW_RMCN_ROTATION_INPUT_TYPE &&
        shadow_rva_matches(req->vaddr, req->target_vaddr,
                           RMCN_CAMERA_SHOOT_RETURN_RVA)) {
        case35_camera_return = true;
        expected_insn = RMCN_CAMERA_SHOOT_RETURN_INSN;
        expected_rva = RMCN_CAMERA_SHOOT_RETURN_RVA;
        exact_validate = true;
    }
    if (!exact_validate && hook_type == 5U &&
        req->vaddr >= RMCN_USER_MIN_ADDR &&
        req->target_vaddr > req->vaddr &&
        req->target_vaddr - req->vaddr == RMCN_INSTANT_VELOCITY_RVA) {
        expected_insn = RMCN_INSTANT_VELOCITY_INSN;
        expected_rva = RMCN_INSTANT_VELOCITY_RVA;
        exact_validate = true;
    }
    if ((hook_type == 28U || hook_type == NBG_SHADOW_DYNAMIC_HOOK_TYPE) &&
        (!read_ok || !dfm_index_trace_insn_valid(original_insn))) {
        put_task_struct(task);
        NBG_INFO("shadow dynamic index opcode reject pid=%d addr=0x%llx insn=%08x\n",
                 hook_pid, (unsigned long long)req->target_vaddr,
                 original_insn);
        NBG_FAIL_CODE(2206, -EINVAL);
        return -EINVAL;
    }
    if (exact_validate) {
        const bool xom_zero = read_ok && original_insn == 0;
        const bool base_rva_ok = shadow_rva_matches(req->vaddr,
                                                    req->target_vaddr,
                                                    expected_rva);
        if ((read_ok && original_insn != expected_insn && !xom_zero) ||
            (read_ok && xom_zero && !base_rva_ok) ||
            (!read_ok && !base_rva_ok)) {
            put_task_struct(task);
            NBG_INFO("shadow opcode reject type=%u req=%u pid=%d addr=0x%llx insn=%08x\n",
                     hook_type, requested_type, hook_pid,
                     (unsigned long long)req->target_vaddr, original_insn);
            NBG_FAIL_CODE(2206, -EINVAL);
            return -EINVAL;
        }
        if (xom_zero || !read_ok)
            NBG_INFO("shadow rva validated type=%u pid=%d base=0x%llx rva=0x%llx read_ok=%d\n",
                     hook_type, hook_pid,
                     (unsigned long long)req->vaddr,
                     (unsigned long long)expected_rva, read_ok ? 1 : 0);
    }
    if (hook_type == NBG_SHADOW_RMCN_FREE_VIEW_TYPE) {
        uint32_t observer_insn = 0;

        /* Do not redirect a camera callback into an unrelated method if
         * only the LDP at the hook location survived a game update. */
        if (!shadow_rva_matches(req->vaddr, req->target_vaddr,
                                RMCN_FREE_VIEW_EPILOGUE_RVA) ||
            !read_process_memory_kernel(
                hook_pid,
                req->vaddr + RMCN_FREE_VIEW_SET_OBSERVER_RVA,
                &observer_insn, sizeof(observer_insn)) ||
            observer_insn != RMCN_FREE_VIEW_SET_OBSERVER_INSN) {
            put_task_struct(task);
            NBG_INFO("rmcn free view observer opcode reject pid=%d base=0x%llx insn=%08x\n",
                     hook_pid, (unsigned long long)req->vaddr,
                     observer_insn);
            NBG_FAIL_CODE(2206, -EINVAL);
            return -EINVAL;
        }
    }
    mutex_lock(&rot_hook_mutex);

    /* 同 (tgid, target) 已在表里 → 只更新参数 */
    for (i = 0; i < MAX_SHADOW_HOOKS; i++) {
        if (!READ_ONCE(rot_hooks[i].active))
            continue;
        if (rot_hooks[i].pid != hook_pid)
            continue;
        if (rot_hooks[i].target_vaddr != req->target_vaddr)
            continue;

        if (READ_ONCE(rot_hooks[i].is_rot_hook) != hook_type) {
            mutex_unlock(&rot_hook_mutex);
            put_task_struct(task);
            NBG_INFO("shadow target type conflict old=%u new=%u pid=%d addr=0x%llx\n",
                     READ_ONCE(rot_hooks[i].is_rot_hook), hook_type,
                     hook_pid,
                     (unsigned long long)req->target_vaddr);
            return -EEXIST;
        }

        WRITE_ONCE(rot_hooks[i].is_rot_hook, hook_type);
        WRITE_ONCE(rot_hooks[i].trace_insn, original_insn);
        WRITE_ONCE(rot_hooks[i].trace_tid,
                   (hook_type == NBG_SHADOW_DYNAMIC_HOOK_TYPE &&
                    req->vaddr > 0 &&
                    req->vaddr <= 0x7fffffffULL) ? (pid_t)req->vaddr : 0);
        if (hook_type == 28U || hook_type == NBG_SHADOW_DYNAMIC_HOOK_TYPE)
            atomic_set(&rot_hooks[i].trace_capture_state, 0);
        if (hook_type == NBG_SHADOW_RMCN_ROTATION_INPUT_TYPE)
            atomic_set(&rot_hooks[i].rotation_input_last_token, -1);
        WRITE_ONCE(rot_hooks[i].lr_filter,
                   (req->vaddr == (req->target_vaddr & ~0xFFFULL)) ?
                   0 : (uint32_t)req->vaddr);
        preempt_disable();
        write_seqcount_begin(&rot_hooks[i].custom_seq);
        WRITE_ONCE(rot_hooks[i].custom_value[0], req->custom_rot[0]);
        WRITE_ONCE(rot_hooks[i].custom_value[1], req->custom_rot[1]);
        WRITE_ONCE(rot_hooks[i].custom_value[2], req->custom_rot[2]);
        write_seqcount_end(&rot_hooks[i].custom_seq);
        preempt_enable();
        if (hook_type == NBG_SHADOW_RMCN_NO_SPREAD_TYPE) {
            rmcn_set_spread_expectation(
                hook_pid,
                ((uint64_t)req->custom_rot[1] << 32) |
                    req->custom_rot[0],
                (req->custom_rot[2] & 1U) != 0U);
            rmcn_set_spread_detach_preserve(
                hook_pid, (req->custom_rot[2] & 2U) != 0U);
        } else if (hook_type == NBG_SHADOW_RMCN_TPP_SHOOT_INPUT_TYPE &&
                   !(req->custom_rot[2] & RMCN_TPP_SHOOT_OVERRIDE_FLAG)) {
            const uint64_t weapon =
                ((uint64_t)req->custom_rot[1] << 32) |
                    req->custom_rot[0];
            rmcn_set_spread_expectation(
                hook_pid, weapon,
                rmcn_strip_user_ptr(weapon) >= RMCN_USER_MIN_ADDR);
        }
        mutex_unlock(&rot_hook_mutex);
        put_task_struct(task);
        return 0;
    }

    /* 找空槽 */
    for (i = 0; i < MAX_SHADOW_HOOKS; i++) {
        if (!rot_hooks[i].active) {
            ctx = &rot_hooks[i];
            break;
        }
    }
    if (!ctx) {
        mutex_unlock(&rot_hook_mutex);
        put_task_struct(task);
        NBG_FAIL_CODE(2202, -ENOSPC);
        return -ENOSPC;
    }

    memset(ctx, 0, sizeof(*ctx));
    seqcount_init(&ctx->custom_seq);
    raw_spin_lock_init(&ctx->range_lock);
    ctx->pid             = hook_pid;
    ctx->target_vaddr    = req->target_vaddr;
    ctx->lr_filter       = (req->vaddr == (req->target_vaddr & ~0xFFFULL)) ?
                           0 : (uint32_t)req->vaddr;
    ctx->is_rot_hook     = hook_type;
    ctx->case35_camera_return = case35_camera_return;
    ctx->trace_insn      = original_insn;
    if (hook_type == NBG_SHADOW_RMCN_FREE_VIEW_TYPE)
        ctx->module_base = req->target_vaddr -
                           RMCN_FREE_VIEW_EPILOGUE_RVA;
    ctx->trace_tid       = (hook_type == NBG_SHADOW_DYNAMIC_HOOK_TYPE &&
                            req->vaddr > 0 &&
                            req->vaddr <= 0x7fffffffULL) ?
                           (pid_t)req->vaddr : 0;
    atomic_set(&ctx->trace_capture_state, 0);
    atomic_set(&ctx->rotation_input_last_token, -1);
    atomic64_set(&ctx->scalar_hook_hits, 0);
    atomic64_set(&ctx->scalar_hook_applies, 0);
    atomic64_set(&ctx->scalar_hook_failures, 0);
    if (hook_type == 24U)
        atomic64_set(&dfm_slot_trace_hits, 0);
    if (hook_type == 25U)
        atomic64_set(&dfm_formula_trace_hits, 0);
    if (hook_type == 28U || hook_type == NBG_SHADOW_DYNAMIC_HOOK_TYPE)
        atomic64_set(&dfm_index_trace_hits, 0);
    preempt_disable();
    write_seqcount_begin(&ctx->custom_seq);
    ctx->custom_value[0] = req->custom_rot[0];
    ctx->custom_value[1] = req->custom_rot[1];
    ctx->custom_value[2] = req->custom_rot[2];
    write_seqcount_end(&ctx->custom_seq);
    preempt_enable();
    if (hook_type == NBG_SHADOW_RMCN_NO_SPREAD_TYPE) {
        rmcn_set_spread_expectation(
            hook_pid,
            ((uint64_t)req->custom_rot[1] << 32) |
                req->custom_rot[0],
            (req->custom_rot[2] & 1U) != 0U);
        rmcn_set_spread_detach_preserve(
            hook_pid, (req->custom_rot[2] & 2U) != 0U);
    } else if (hook_type == NBG_SHADOW_RMCN_TPP_SHOOT_INPUT_TYPE &&
               !(req->custom_rot[2] & RMCN_TPP_SHOOT_OVERRIDE_FLAG)) {
        const uint64_t weapon =
            ((uint64_t)req->custom_rot[1] << 32) | req->custom_rot[0];
        rmcn_set_spread_expectation(
            hook_pid, weapon,
            rmcn_strip_user_ptr(weapon) >= RMCN_USER_MIN_ADDR);
    }

    if (hook_type == NBG_SHADOW_FP_LDP_SCALE_HOOK_TYPE) {
        ctx->range_cache = kcalloc(RMCN_RANGE_CACHE_SIZE,
                                   sizeof(*ctx->range_cache), GFP_KERNEL);
        if (!ctx->range_cache) {
            memset(ctx, 0, sizeof(*ctx));
            mutex_unlock(&rot_hook_mutex);
            put_task_struct(task);
            NBG_FAIL_CODE(2212, -ENOMEM);
            return -ENOMEM;
        }
    }
    if (hook_type == NBG_SHADOW_RMCN_FREE_VIEW_TYPE) {
        atomic_set(&ctx->free_view_command, 0);
        atomic64_set(&ctx->free_view_hook_hits, 0);
        atomic64_set(&ctx->free_view_stack_failures, 0);
        ctx->free_view_next_log = jiffies;
    }

    predecode_for_rot(ctx, task);
    if (!shadow_ctx_can_emulate(ctx, hook_type)) {
        kfree(ctx->range_cache);
        ctx->range_cache = NULL;
        memset(ctx, 0, sizeof(*ctx));
        mutex_unlock(&rot_hook_mutex);
        put_task_struct(task);
        NBG_INFO("shadow emulate reject type=%u req=%u pid=%d addr=0x%llx insn=%08x\n",
                 hook_type, requested_type, hook_pid,
                 (unsigned long long)req->target_vaddr, original_insn);
        NBG_FAIL_CODE(2209, -EINVAL);
        return -EINVAL;
    }

    rreq.pid          = hook_pid;
    rreq.target_vaddr = req->target_vaddr;
    rreq.callback     = rot_hook_callback;
    rreq.priv         = ctx;

    /* Publish only after every field and predecode result is complete. */
    WRITE_ONCE(ctx->active, true);
    ret = raw_hwbp_add(&rreq);
    if (ret) {
        NBG_FAIL_CODE(2203, ret);
        WRITE_ONCE(ctx->active, false);
        kfree(ctx->range_cache);
        ctx->range_cache = NULL;
    } else {
        NBG_INFO("shadow add backend=hwbp type=%u pid=%d addr=0x%llx\n",
                 hook_type, hook_pid,
                 (unsigned long long)req->target_vaddr);
    }
    mutex_unlock(&rot_hook_mutex);
    put_task_struct(task);
    return ret;
}

int shadow_update_rot(struct shadow_req *req)
{
    int i, updated = 0;
    int command_error = 0;
    pid_t hook_pid;

    if (!req)
    {
        NBG_FAIL_CODE(2211, -EINVAL);
        return -EINVAL;
    }
    hook_pid = shadow_normalize_tgid(req->pid, NULL);

    mutex_lock(&rot_hook_mutex);
    for (i = 0; i < MAX_SHADOW_HOOKS; i++) {
        if (!READ_ONCE(rot_hooks[i].active))
            continue;
        if (hook_pid > 0 && rot_hooks[i].pid != hook_pid)
            continue;
        if (req->target_vaddr && rot_hooks[i].target_vaddr != req->target_vaddr)
            continue;

        if (READ_ONCE(rot_hooks[i].is_rot_hook) ==
            NBG_SHADOW_RMCN_FREE_VIEW_TYPE) {
            int ret = rmcn_free_view_command(&rot_hooks[i],
                                             req->custom_rot[2]);
            if (!ret)
                updated++;
            else if (!command_error)
                command_error = ret;
            continue;
        }

        if (READ_ONCE(rot_hooks[i].is_rot_hook) ==
                NBG_SHADOW_RMCN_NO_SPREAD_TYPE &&
            (req->custom_rot[2] & NBG_SHADOW_SPREAD_PROFILE_LOAD)) {
            if (rmcn_preload_spread_profile(
                    rot_hooks[i].pid, req->vaddr,
                    req->custom_rot[0], req->custom_rot[1],
                    (req->custom_rot[2] &
                     NBG_SHADOW_SPREAD_PROFILE_INLINE_STATE) != 0U)) {
                updated++;
            } else if (!command_error) {
                command_error = -EAGAIN;
            }
            continue;
        }

        preempt_disable();
        write_seqcount_begin(&rot_hooks[i].custom_seq);
        WRITE_ONCE(rot_hooks[i].custom_value[0], req->custom_rot[0]);
        WRITE_ONCE(rot_hooks[i].custom_value[1], req->custom_rot[1]);
        WRITE_ONCE(rot_hooks[i].custom_value[2], req->custom_rot[2]);
        write_seqcount_end(&rot_hooks[i].custom_seq);
        preempt_enable();
        if (READ_ONCE(rot_hooks[i].is_rot_hook) ==
            NBG_SHADOW_RMCN_NO_SPREAD_TYPE) {
            rmcn_set_spread_expectation(
                rot_hooks[i].pid,
                ((uint64_t)req->custom_rot[1] << 32) |
                    req->custom_rot[0],
                (req->custom_rot[2] & 1U) != 0U);
            rmcn_set_spread_detach_preserve(
                rot_hooks[i].pid,
                (req->custom_rot[2] & 2U) != 0U);
        } else if (READ_ONCE(rot_hooks[i].is_rot_hook) ==
                   NBG_SHADOW_RMCN_TPP_SHOOT_INPUT_TYPE &&
                   !(req->custom_rot[2] & RMCN_TPP_SHOOT_OVERRIDE_FLAG)) {
            const uint64_t weapon =
                ((uint64_t)req->custom_rot[1] << 32) |
                    req->custom_rot[0];
            rmcn_set_spread_expectation(
                rot_hooks[i].pid, weapon,
                rmcn_strip_user_ptr(weapon) >= RMCN_USER_MIN_ADDR);
        }
        updated++;
    }
    mutex_unlock(&rot_hook_mutex);

    if (command_error)
        return command_error;
    if (updated <= 0)
        NBG_FAIL_CODE(2212, -ENOENT);
    return updated > 0 ? 0 : -ENOENT;
}

void shadow_query_diag(ShadowDiag *diag)
{
    pid_t requested_pid;
    int i;

    if (!diag)
        return;

    requested_pid = diag->pid;
    memset(diag, 0, sizeof(*diag));
    diag->abi_version = NBG_SHADOW_DIAG_ABI_VERSION;
    diag->pid = requested_pid;

    mutex_lock(&rot_hook_mutex);
    for (i = 0; i < MAX_SHADOW_HOOKS; i++) {
        if (!READ_ONCE(rot_hooks[i].active))
            continue;
        if (requested_pid > 0 && rot_hooks[i].pid != requested_pid)
            continue;
        if (READ_ONCE(rot_hooks[i].is_rot_hook) ==
            NBG_SHADOW_RMCN_NO_SPREAD_TYPE)
            diag->case38_active = 1;
        if (READ_ONCE(rot_hooks[i].is_rot_hook) ==
            NBG_SHADOW_RMCN_ROTATION_INPUT_TYPE &&
            rot_hooks[i].case35_camera_return) {
            diag->reserved32[1] = 1;
            diag->reserved64[0] += atomic64_read(&rot_hooks[i].scalar_hook_hits);
            diag->reserved64[1] += atomic64_read(&rot_hooks[i].scalar_hook_applies);
            diag->reserved64[2] += atomic64_read(&rot_hooks[i].scalar_hook_failures);
            diag->reserved64[3] = READ_ONCE(rot_hooks[i].scalar_last_native);
            diag->reserved64[4] = READ_ONCE(rot_hooks[i].scalar_last_output);
            diag->reserved64[5] = READ_ONCE(rot_hooks[i].scalar_last_cmd);
            diag->reserved64[6] = READ_ONCE(rot_hooks[i].scalar_last_sequence);
            diag->reserved64[7] = rot_hooks[i].target_vaddr;
        }
    }
    diag->reserved32[8] = NBG_SHADOW_DIAG_CAMERA_RETURN_V1;
    mutex_unlock(&rot_hook_mutex);
    diag->reserved32[0] = rmcn_spread_context_diag_flags(requested_pid);
    diag->case38_hits = atomic64_read(&rmcn_case38_hits);
    diag->case38_captures = atomic64_read(&rmcn_case38_captures);
    diag->spread_comp_attempts =
        atomic64_read(&rmcn_spread_comp_attempts);
    diag->spread_comp_successes =
        atomic64_read(&rmcn_spread_comp_successes);
    diag->spread_cache_misses =
        atomic64_read(&rmcn_spread_cache_misses);
    diag->spread_compute_rejects =
        atomic64_read(&rmcn_spread_compute_rejects);
    diag->spread_last_sequence = READ_ONCE(rmcn_spread_last_sequence);
    diag->spread_last_seed = READ_ONCE(rmcn_spread_last_seed);
    diag->spread_last_bits = READ_ONCE(rmcn_spread_last_bits);
    diag->spread_shot_matches =
        atomic64_read(&rmcn_spread_shot_matches);
    diag->spread_shot_mismatches =
        atomic64_read(&rmcn_spread_shot_mismatches);
    diag->spread_shot_unpaired =
        atomic64_read(&rmcn_spread_shot_unpaired);
    diag->spread_last_projectile_index =
        READ_ONCE(rmcn_spread_last_projectile_index);
    diag->spread_last_target_yaw_bits =
        READ_ONCE(rmcn_spread_last_target_yaw_bits);
    diag->spread_last_target_pitch_bits =
        READ_ONCE(rmcn_spread_last_target_pitch_bits);
    diag->spread_last_comp_yaw_bits =
        READ_ONCE(rmcn_spread_last_comp_yaw_bits);
    diag->spread_last_comp_pitch_bits =
        READ_ONCE(rmcn_spread_last_comp_pitch_bits);
    diag->spread_last_live_angle0_bits =
        READ_ONCE(rmcn_spread_last_live_angle0_bits);
    diag->spread_last_live_angle1_bits =
        READ_ONCE(rmcn_spread_last_live_angle1_bits);
    diag->spread_last_sequence_delta =
        (int64_t)READ_ONCE(rmcn_spread_last_sequence_delta);
    diag->case40_hits = atomic64_read(&rmcn_case40_hits);
    diag->case40_comp_successes =
        atomic64_read(&rmcn_case40_comp_successes);
}

int shadow_del_hook(struct shadow_req *req)
{
    int i;
    int raw_ret = -ENOENT;
    bool removed_ctx = false;
    bool clear_spread_context = false;
    unsigned int range_restored = 0;
    pid_t hook_pid;

    if (!req)
    {
        NBG_FAIL_CODE(2221, -EINVAL);
        return -EINVAL;
    }
    hook_pid = shadow_normalize_tgid(req->pid, NULL);

    mutex_lock(&rot_hook_mutex);
    if (req->target_vaddr)
        raw_ret = raw_hwbp_del_pid(hook_pid, req->target_vaddr);
    else
        raw_ret = hook_pid > 0 ? raw_hwbp_del_pid(hook_pid, 0)
                               : raw_hwbp_del(0);

    if (raw_ret == 0 || raw_ret == -ENOENT) {
        for (i = 0; i < MAX_SHADOW_HOOKS; i++) {
            if (!READ_ONCE(rot_hooks[i].active) ||
                (req->target_vaddr &&
                 rot_hooks[i].target_vaddr != req->target_vaddr) ||
                (hook_pid > 0 && rot_hooks[i].pid != hook_pid))
                continue;
            if (READ_ONCE(rot_hooks[i].is_rot_hook) ==
                    NBG_SHADOW_RMCN_NO_SPREAD_TYPE ||
                READ_ONCE(rot_hooks[i].is_rot_hook) ==
                    NBG_SHADOW_RMCN_TPP_SHOOT_INPUT_TYPE)
                clear_spread_context = true;
            WRITE_ONCE(rot_hooks[i].active, false);
            if (READ_ONCE(rot_hooks[i].is_rot_hook) ==
                NBG_SHADOW_FP_LDP_SCALE_HOOK_TYPE)
                range_restored += rmcn_range_restore_and_free(&rot_hooks[i]);
            removed_ctx = true;
        }
    }
    if (range_restored)
        NBG_INFO("shadow range restore pid=%d count=%u\n",
                 hook_pid, range_restored);
    mutex_unlock(&rot_hook_mutex);
    if (clear_spread_context &&
        !(req->target_vaddr &&
          rmcn_consume_spread_detach_preserve(hook_pid)))
        rmcn_clear_spread_context(hook_pid);

    return raw_ret == 0 || removed_ctx ? 0 : raw_ret;
}

/* ---- 模块生命周期(代理 entry.c 调用)---- */

int shadow_init_module(void)
{
    memset(rot_hooks, 0, sizeof(rot_hooks));
    rmcn_clear_spread_context(0);
    atomic64_set(&rmcn_case38_hits, 0);
    atomic64_set(&rmcn_case38_captures, 0);
    atomic64_set(&rmcn_case40_hits, 0);
    atomic64_set(&rmcn_case40_comp_successes, 0);
    atomic64_set(&rmcn_spread_comp_attempts, 0);
    atomic64_set(&rmcn_spread_comp_successes, 0);
    atomic64_set(&rmcn_spread_cache_misses, 0);
    atomic64_set(&rmcn_spread_compute_rejects, 0);
    atomic64_set(&rmcn_spread_shot_matches, 0);
    atomic64_set(&rmcn_spread_shot_mismatches, 0);
    atomic64_set(&rmcn_spread_shot_unpaired, 0);
    WRITE_ONCE(rmcn_spread_last_sequence, 0);
    WRITE_ONCE(rmcn_spread_last_seed, 0);
    WRITE_ONCE(rmcn_spread_last_bits, 0);
    WRITE_ONCE(rmcn_spread_last_projectile_index, 0);
    WRITE_ONCE(rmcn_spread_last_target_yaw_bits, 0);
    WRITE_ONCE(rmcn_spread_last_target_pitch_bits, 0);
    WRITE_ONCE(rmcn_spread_last_comp_yaw_bits, 0);
    WRITE_ONCE(rmcn_spread_last_comp_pitch_bits, 0);
    WRITE_ONCE(rmcn_spread_last_live_angle0_bits, 0);
    WRITE_ONCE(rmcn_spread_last_live_angle1_bits, 0);
    WRITE_ONCE(rmcn_spread_last_sequence_delta, 0);
    atomic64_set(&nz_case8_hits, 0);
    atomic64_set(&nz_case8_successes, 0);
    atomic64_set(&nz_case8_fallbacks, 0);
    {
        static const char * const fpsimd_save_flush_symbols[] = {
            "fpsimd_save_and_flush_cpu_state",
            "fpsimd_save_and_flush_current_state",
            NULL,
        };
        fpsimd_save_flush_fn = (fpsimd_save_flush_fn_t)
            resolve_first_symbol(fpsimd_save_flush_symbols);
    }
    watch_logger_init();

    return 0;
}

void shadow_exit_module(void)
{
    int i;

    raw_hwbp_clear_all();
    raw_hwwp_clear_all();
    /* 等所有 in-flight bm_bp_entry / bm_wp_entry 回调退出,
     * 再清 logger。watch_logger_exit 内部不做 clear_all,
     * 只是再 sync 一次 + 清本地状态。 */
    synchronize_rcu();
    mutex_lock(&rot_hook_mutex);
    for (i = 0; i < MAX_SHADOW_HOOKS; i++) {
        WRITE_ONCE(rot_hooks[i].active, false);
        rmcn_range_restore_and_free(&rot_hooks[i]);
    }
    mutex_unlock(&rot_hook_mutex);
    watch_logger_exit();
}
