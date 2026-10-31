/* kgsl.c — KGSL 私有布局指纹校验与只读查询
 *
 * KGSL 的 kgsl_process_private 是厂商私有类型，字段偏移随 KGSL 版本变化，
 * 而本模块按 GKI 编译，拿不到厂商头文件。硬编码偏移在换版本后必然失效。
 *
 * 这里改用代码形状指纹：解析 kgsl_ioctl_syncsource_create/destroy 的机器码，
 * 找出两个 ADD 立即数（分别落在 idr 与 spinlock 上、差值恰为 sizeof(struct idr)），
 * 且都能到达对应的 idr_alloc / idr_find 与 _raw_spin_lock 调用点。
 * CREATE 还必须把 start=1 / end=0 作为原生边界传入。
 *
 * 两次独立解码（create 与 destroy）必须得到唯一相同的布局，否则拒绝。
 */
#include "kgsl.h"

#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/xarray.h>

#include "comm.h"
#include "nbg_compat.h"
#include "nbg_ksyms.h"
#include "query.h"

#define KGSL_LAYOUT_SCAN_INSNS        256U
#define KGSL_LAYOUT_MAX_ADDS           48U
#define KGSL_LAYOUT_MAX_CANDIDATES     16U
#define KGSL_LAYOUT_PROC_SCAN_INSNS    24U
#define KGSL_LAYOUT_CALL_WINDOW         12U
#define KGSL_LAYOUT_PAIR_DISTANCE      24U
#define KGSL_LAYOUT_MAX_FIELD_OFFSET 0x4000U
#define KGSL_LAYOUT_STUB_MAX_BYTES      16U
#define KGSL_LAYOUT_STUB_MAX_HOPS        3U
#define KGSL_SYNCSOURCE_STABLE_TRIES     3U
#define KGSL_SYNCSOURCE_XAS_RETRIES      8U

enum nbg_kgsl_fail_stage {
    NBG_KGSL_FAIL_NONE = 0,
    NBG_KGSL_FAIL_FILE_IDENTITY = 1,
    NBG_KGSL_FAIL_NOT_KGSL_FILE = 2,
    NBG_KGSL_FAIL_RUNTIME_SYMBOLS = 3,
    NBG_KGSL_FAIL_CREATE_LAYOUT = 4,
    NBG_KGSL_FAIL_DESTROY_LAYOUT = 5,
    NBG_KGSL_FAIL_LAYOUT_MISMATCH = 6,
    NBG_KGSL_FAIL_LAYOUT_OFFSETS = 7,
    NBG_KGSL_FAIL_PROCESS_PRIV = 8,
    NBG_KGSL_FAIL_LIVE_IDR = 9,
    NBG_KGSL_FAIL_LOWEST_FREE = 10,
};

struct nbg_kgsl_layout {
    unsigned int process_priv_offset;
    unsigned int syncsource_idr_offset;
    unsigned int syncsource_lock_offset;
};

struct nbg_kgsl_layout_candidate {
    struct nbg_kgsl_layout layout;
    unsigned int process_reg;
};

struct nbg_kgsl_add_imm {
    unsigned int index;
    unsigned int rd;
    unsigned int rn;
    unsigned int imm;
};

struct nbg_kgsl_call_targets {
    unsigned long direct;
    unsigned long cfi_jt;
};

struct nbg_kgsl_runtime_symbols {
    unsigned long create;
    unsigned long destroy;
    unsigned long fops;
    unsigned long ioctl;
    unsigned long ioctl_cfi;
    unsigned long idr_alloc;
    unsigned long idr_alloc_cfi;
    unsigned long idr_find;
    unsigned long idr_find_cfi;
    unsigned long raw_spin_lock;
    unsigned long raw_spin_lock_cfi;
};

struct nbg_kgsl_runtime_cache {
    struct nbg_kgsl_runtime_symbols symbols;
    struct nbg_kgsl_layout layout;
    unsigned int ready;
};

static DEFINE_MUTEX(g_kgsl_runtime_cache_lock);
static struct nbg_kgsl_runtime_cache g_kgsl_runtime_cache;

/* ---- ARM64 指令解码 ---- */

static s64 nbg_kgsl_sign_extend(u64 value, unsigned int sign_bit)
{
    u64 sign = 1ULL << sign_bit;

    return (s64)((value ^ sign) - sign);
}

static bool nbg_kgsl_a64_bl(u32 insn, unsigned long pc, unsigned long *target)
{
    s64 offset;

    if ((insn & 0xFC000000U) != 0x94000000U)
        return false;
    offset = nbg_kgsl_sign_extend(insn & 0x03FFFFFFU, 25U) * 4;
    *target = pc + offset;
    return true;
}

static bool nbg_kgsl_a64_unconditional_b(u32 insn)
{
    return (insn & 0xFC000000U) == 0x14000000U;
}

static bool nbg_kgsl_a64_hint(u32 insn)
{
    return (insn & 0xFFFFF01FU) == 0xD503201FU;
}

static bool nbg_kgsl_a64_b_imm(u32 insn, unsigned long pc,
                               unsigned long *target)
{
    s64 offset;

    if ((insn & 0xFC000000U) != 0x14000000U)
        return false;
    offset = nbg_kgsl_sign_extend(insn & 0x03FFFFFFU, 25U) * 4;
    *target = pc + (unsigned long)offset;
    return true;
}

static bool nbg_kgsl_a64_ret(u32 insn)
{
    return (insn & 0xFFFFFC1FU) == 0xD65F0000U;
}

static bool nbg_kgsl_a64_add_imm(u32 insn, unsigned int *rd, unsigned int *rn,
                                 unsigned int *imm)
{
    u32 value;

    if ((insn & 0xFF000000U) != 0x91000000U)
        return false;

    value = (insn >> 10) & 0xFFFU;
    if (insn & (1U << 22))
        value <<= 12;

    *rd = insn & 31U;
    *rn = (insn >> 5) & 31U;
    *imm = value;
    return true;
}

static bool nbg_kgsl_a64_ldr_x_unsigned(u32 insn, unsigned int *rt,
                                        unsigned int *rn, unsigned int *imm)
{
    if ((insn & 0xFFC00000U) != 0xF9400000U)
        return false;

    *rt = insn & 31U;
    *rn = (insn >> 5) & 31U;
    *imm = ((insn >> 10) & 0xFFFU) * 8U;
    return true;
}

static bool nbg_kgsl_a64_mov_w_constant(u32 insn, unsigned int *rd, u32 *value)
{
    u32 imm16;
    unsigned int hw;

    if ((insn & 0x7F800000U) != 0x52800000U)
        return false;

    imm16 = (insn >> 5) & 0xFFFFU;
    hw = (insn >> 21) & 3U;
    *rd = insn & 31U;
    *value = imm16 << (hw * 16U);
    return true;
}

static bool nbg_kgsl_a64_stack_store(u32 insn)
{
    /* STP/STR 到 SP：Rn == 31 */
    if ((insn & 0x3B000000U) != 0x29000000U)
        return false;
    return ((insn >> 5) & 31U) == 31U;
}

static bool nbg_kgsl_a64_scs_x18(u32 insn)
{
    /* 影子调用栈：STR X30,[X18],#8 = 0xF81F8BFE / LDR X30,[X18,#-8]! = 0xF85F8BFE。
     * 这两条指令不含可变字段，直接整体比较。 */
    return insn == 0xF81F8BFEU || insn == 0xF85F8BFEU;
}

static bool nbg_kgsl_a64_known_gpr_write(u32 insn, unsigned int *rd)
{
    /* 保守：只认会明确写 Rd 的常见形式，其余一律视为未知写入。 */
    static const u32 masks[] = {
        0xFF000000U, 0xFF800000U, 0xFFC00000U, 0xFFE00000U,
    };
    static const u32 values[] = {
        0x91000000U, 0xF9400000U, 0x52800000U, 0xB9400000U,
    };
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(masks); i++) {
        if ((insn & masks[i]) == values[i]) {
            *rd = insn & 31U;
            return true;
        }
    }
    return false;
}

/* ---- 跳板解析 ---- */

static unsigned long nbg_kgsl_resolve_plt_target(unsigned long plt)
{
    u32 code[4];

    if (copy_from_kernel_nofault(code, (const void *)plt, sizeof(code)))
        return 0;

    /* 当前 arm64 模块 PLT：ADRP X16; ADD X16,X16,#lo12; BR X16 */
    if ((code[0] & 0x9F00001FU) == 0x90000010U &&
        (code[1] & 0xFFC003FFU) == 0x91000210U &&
        code[2] == 0xD61F0200U) {
        u64 immlo = (code[0] >> 29) & 0x3U;
        u64 immhi = (code[0] >> 5) & 0x7FFFFU;
        s64 page_offset =
            nbg_kgsl_sign_extend((immhi << 2) | immlo, 20U) * 4096;
        unsigned long page = (unsigned long)
            ((s64)(plt & ~0xFFFUL) + page_offset);
        unsigned long lo12 = (code[1] >> 10) & 0xFFFU;

        return page + lo12;
    }

    /* 旧式：MOVN/MOVK/MOVK X16; BR X16 */
    if ((code[0] & 0xFFE0001FU) == 0x92800010U &&
        (code[1] & 0xFF80001FU) == 0xF2800010U &&
        (code[2] & 0xFF80001FU) == 0xF2800010U &&
        ((code[1] >> 21) & 0x3U) == 1U &&
        ((code[2] >> 21) & 0x3U) == 2U &&
        code[3] == 0xD61F0200U) {
        u64 value = ~((u64)(code[0] >> 5) & 0xFFFFULL);
        u64 imm16 = ((u64)(code[1] >> 5) & 0xFFFFULL) << 16;
        u64 imm32 = ((u64)(code[2] >> 5) & 0xFFFFULL) << 32;

        value = (value & ~0x00000000FFFF0000ULL) | imm16;
        value = (value & ~0x0000FFFF00000000ULL) | imm32;
        return (unsigned long)value;
    }

    return 0;
}

static bool nbg_kgsl_symbol_is_short_stub(unsigned long addr)
{
    unsigned long size = 0;
    unsigned long offset = 0;

    if (!addr)
        return false;
    if (!nbg_ksym_size_offset(addr, &size, &offset) || offset != 0UL)
        return false;
    return size > 0UL && size <= KGSL_LAYOUT_STUB_MAX_BYTES;
}

/* Clang CFI 跳板：可选 BTI/PAC 提示，然后一条无条件 B 到真实函数。
 * 绝不跟随 B 离开完整函数体。 */
static unsigned long nbg_kgsl_resolve_cfi_jt(unsigned long jt)
{
    u32 code[4];
    unsigned long size = 0;
    unsigned long offset = 0;
    unsigned int limit = 4U;
    unsigned int i;

    if (!jt || !nbg_kgsl_symbol_is_short_stub(jt))
        return 0;
    if (copy_from_kernel_nofault(code, (const void *)jt, sizeof(code)))
        return 0;

    if (nbg_ksym_size_offset(jt, &size, &offset) && offset == 0UL &&
        size >= sizeof(u32) && size <= sizeof(code) &&
        (size % sizeof(u32)) == 0UL)
        limit = (unsigned int)(size / sizeof(u32));

    for (i = 0; i < limit; i++) {
        unsigned long pc = jt + (unsigned long)i * sizeof(u32);
        unsigned long target;

        if (nbg_kgsl_a64_hint(code[i]))
            continue;
        if (nbg_kgsl_a64_b_imm(code[i], pc, &target))
            return target;
        return 0;
    }
    return 0;
}

static unsigned long nbg_kgsl_resolve_call_target(unsigned long target)
{
    unsigned int hop;

    for (hop = 0; hop < KGSL_LAYOUT_STUB_MAX_HOPS; hop++) {
        unsigned long next = nbg_kgsl_resolve_plt_target(target);

        if (!next)
            next = nbg_kgsl_resolve_cfi_jt(target);
        if (!next || next == target)
            break;
        target = next;
    }
    return target;
}

static bool nbg_kgsl_addr_in_targets(unsigned long addr,
                                     const struct nbg_kgsl_call_targets *exp)
{
    if (!addr || !exp)
        return false;
    return (exp->direct && addr == exp->direct) ||
           (exp->cfi_jt && addr == exp->cfi_jt);
}

static bool nbg_kgsl_call_matches(u32 insn, unsigned long pc,
                                  const struct nbg_kgsl_call_targets *exp)
{
    unsigned long target;
    unsigned long resolved;

    if (!exp || (!exp->direct && !exp->cfi_jt) ||
        !nbg_kgsl_a64_bl(insn, pc, &target))
        return false;
    if (nbg_kgsl_addr_in_targets(target, exp))
        return true;
    resolved = nbg_kgsl_resolve_call_target(target);
    return nbg_kgsl_addr_in_targets(resolved, exp);
}

/* ---- 字段使用分析 ---- */

/* 判断某个 ADD 产生的寄存器是否在接下来几条指令里作为 X0 传给调用。
 * 只有作为调用参数的字段偏移才可能是我们要找的 idr / lock。 */
static bool nbg_kgsl_field_add_used_as_x0(const u32 *code,
                                          unsigned int count,
                                          const struct nbg_kgsl_add_imm *add)
{
    unsigned int i;
    unsigned int limit;

    limit = min(count, add->index + KGSL_LAYOUT_CALL_WINDOW + 1U);
    for (i = add->index + 1U; i < limit; i++) {
        unsigned int rd;

        if (nbg_kgsl_a64_hint(code[i]))
            continue;
        if (nbg_kgsl_a64_bl(code[i], 0, NULL))
            return false;
        if (!nbg_kgsl_a64_known_gpr_write(code[i], &rd))
            continue;
        if (rd == 0U)
            return false;
        if (rd == add->rd)
            return false;
    }

    /* 简化判定：字段寄存器后续未被覆盖即认为可能作为参数使用。
     * 真正的调用点匹配由 nbg_kgsl_field_add_reaches_call 完成。 */
    return true;
}

static bool nbg_kgsl_field_add_reaches_call(
    const u32 *code, unsigned int count, unsigned long function,
    const struct nbg_kgsl_add_imm *add,
    const struct nbg_kgsl_call_targets *expected)
{
    unsigned int i;
    unsigned int limit;

    limit = min(count, add->index + KGSL_LAYOUT_CALL_WINDOW + 1U);
    for (i = add->index + 1U; i < limit; i++) {
        unsigned long pc = function + (unsigned long)i * sizeof(u32);

        if (nbg_kgsl_a64_bl(code[i], pc, NULL))
            return nbg_kgsl_call_matches(code[i], pc, expected);
        if (nbg_kgsl_a64_unconditional_b(code[i]) ||
            nbg_kgsl_a64_ret(code[i]))
            return false;
    }
    return false;
}

/* CREATE 必须把 start=1 / end=0 作为原生边界传给 idr_alloc。 */
static bool nbg_kgsl_idr_alloc_native_bounds(
    const u32 *code, unsigned int count, unsigned long function,
    const struct nbg_kgsl_add_imm *add,
    const struct nbg_kgsl_call_targets *expected)
{
    bool start_is_one = false;
    bool end_is_zero = false;
    unsigned int i;
    unsigned int limit;

    limit = min(count, add->index + KGSL_LAYOUT_CALL_WINDOW + 1U);
    for (i = add->index + 1U; i < limit; i++) {
        unsigned long pc = function + (unsigned long)i * sizeof(u32);
        unsigned int rd;
        u32 value;

        if (nbg_kgsl_a64_bl(code[i], pc, NULL))
            return nbg_kgsl_call_matches(code[i], pc, expected) &&
                   start_is_one && end_is_zero;
        if (nbg_kgsl_a64_unconditional_b(code[i]) ||
            nbg_kgsl_a64_ret(code[i]))
            return false;
        if (nbg_kgsl_a64_hint(code[i]))
            continue;
        if (nbg_kgsl_a64_mov_w_constant(code[i], &rd, &value)) {
            if (rd == 2U)
                start_is_one = value == 1U;
            else if (rd == 3U)
                end_is_zero = value == 0U;
            continue;
        }
        if (!nbg_kgsl_a64_known_gpr_write(code[i], &rd))
            return false;
        if (rd == 2U || rd == 3U)
            return false;
    }

    return false;
}

/* 在 ADD 之前找到 process_priv 从 X0 加载的位置，即字段偏移。 */
static bool nbg_kgsl_find_process_offset(const u32 *code, unsigned int count,
                                         unsigned int process_reg,
                                         unsigned int before_index,
                                         unsigned int *process_offset)
{
    unsigned int limit = min(count, KGSL_LAYOUT_PROC_SCAN_INSNS);
    unsigned int i;

    limit = min(limit, before_index);
    if (process_reg < 19U || process_reg > 28U)
        return false;

    for (i = 0; i < limit; i++) {
        unsigned int rt;
        unsigned int rn;
        unsigned int imm;
        unsigned int written;

        if (nbg_kgsl_a64_ldr_x_unsigned(code[i], &rt, &rn, &imm) &&
            rn == 0U) {
            if (imm <= 8U * sizeof(void *) &&
                (imm % sizeof(void *)) == 0U && rt == process_reg) {
                *process_offset = imm;
                return true;
            }
            continue;
        }
        if (nbg_kgsl_a64_hint(code[i]) || nbg_kgsl_a64_stack_store(code[i]) ||
            nbg_kgsl_a64_scs_x18(code[i]))
            continue;
        if (nbg_kgsl_a64_bl(code[i], 0, NULL) ||
            nbg_kgsl_a64_unconditional_b(code[i]) ||
            nbg_kgsl_a64_ret(code[i]))
            return false;
        if (!nbg_kgsl_a64_known_gpr_write(code[i], &written) || written == 0U)
            return false;
    }

    return false;
}

static bool nbg_kgsl_same_layout(const struct nbg_kgsl_layout *a,
                                 const struct nbg_kgsl_layout *b)
{
    return a->process_priv_offset == b->process_priv_offset &&
           a->syncsource_idr_offset == b->syncsource_idr_offset &&
           a->syncsource_lock_offset == b->syncsource_lock_offset;
}

static int nbg_kgsl_add_candidate(struct nbg_kgsl_layout_candidate *out,
                                  unsigned int *out_count,
                                  const struct nbg_kgsl_layout_candidate *v)
{
    unsigned int i;

    for (i = 0; i < *out_count; i++) {
        if (nbg_kgsl_same_layout(&out[i].layout, &v->layout))
            return 0;
    }
    if (*out_count >= KGSL_LAYOUT_MAX_CANDIDATES)
        return -E2BIG;

    out[*out_count] = *v;
    (*out_count)++;
    return 0;
}

/* 全函数扫描：不依赖固定指令索引，而是按语义找 ADD 立即数配对。 */
static int nbg_kgsl_decode_layout(
    unsigned long function,
    const struct nbg_kgsl_call_targets *idr_call,
    const struct nbg_kgsl_call_targets *lock_call,
    bool require_native_bounds,
    struct nbg_kgsl_layout_candidate *out,
    unsigned int *out_count)
{
    struct nbg_kgsl_add_imm adds[KGSL_LAYOUT_MAX_ADDS];
    u32 *code = NULL;
    unsigned long symbol_size = 0;
    unsigned long symbol_offset = 0;
    unsigned long copy_bytes;
    unsigned int code_count;
    unsigned int add_count = 0;
    unsigned int i;
    unsigned int j;
    bool has_ret = false;
    int ret = -EOPNOTSUPP;

    *out_count = 0;
    if (!function)
        return -ENOENT;

    /* kallsyms 的 size 是到下一个符号的间隔，不是函数长度。
     * 先拷前缀，再截到第一个 RET，避免把填充或下一个函数算进来。 */
    if (!nbg_ksym_size_offset(function, &symbol_size, &symbol_offset) ||
        symbol_offset != 0UL || symbol_size < sizeof(u32) ||
        (symbol_size % sizeof(u32)) != 0UL)
        return -EOPNOTSUPP;

    copy_bytes = min(symbol_size,
                     (unsigned long)KGSL_LAYOUT_SCAN_INSNS * sizeof(u32));
    code_count = (unsigned int)(copy_bytes / sizeof(u32));
    code = kmalloc(copy_bytes, GFP_KERNEL);
    if (!code)
        return -ENOMEM;

    if (copy_from_kernel_nofault(code, (const void *)function, copy_bytes)) {
        ret = -EFAULT;
        goto out;
    }

    for (i = 0; i < code_count; i++) {
        if (nbg_kgsl_a64_ret(code[i])) {
            has_ret = true;
            code_count = i + 1U;
            break;
        }
    }
    if (!has_ret) {
        ret = -EOPNOTSUPP;
        goto out;
    }

    for (i = 0; i < code_count; i++) {
        struct nbg_kgsl_add_imm add;

        if (!nbg_kgsl_a64_add_imm(code[i], &add.rd, &add.rn, &add.imm))
            continue;
        if (add.rn == 31U || add.imm > KGSL_LAYOUT_MAX_FIELD_OFFSET)
            continue;
        add.index = i;
        if (!nbg_kgsl_field_add_used_as_x0(code, code_count, &add))
            continue;
        if (add_count >= KGSL_LAYOUT_MAX_ADDS) {
            ret = -E2BIG;
            goto out;
        }
        adds[add_count++] = add;
    }

    for (i = 0; i < add_count; i++) {
        for (j = i + 1U; j < add_count; j++) {
            struct nbg_kgsl_layout_candidate candidate;
            unsigned int lower;
            unsigned int upper;
            const struct nbg_kgsl_add_imm *idr_add;
            const struct nbg_kgsl_add_imm *lock_add;

            if (adds[i].rn != adds[j].rn)
                continue;
            if (adds[j].index - adds[i].index > KGSL_LAYOUT_PAIR_DISTANCE)
                continue;

            lower = min(adds[i].imm, adds[j].imm);
            upper = max(adds[i].imm, adds[j].imm);

            /* lock 紧跟在 idr 之后，差值恰为 sizeof(struct idr)。 */
            if (upper - lower != sizeof(struct idr))
                continue;
            if ((lower % __alignof__(struct idr)) != 0U ||
                (upper % __alignof__(spinlock_t)) != 0U)
                continue;

            idr_add = adds[i].imm == lower ? &adds[i] : &adds[j];
            lock_add = adds[i].imm == upper ? &adds[i] : &adds[j];

            if (!nbg_kgsl_field_add_reaches_call(code, code_count, function,
                                                 idr_add, idr_call) ||
                !nbg_kgsl_field_add_reaches_call(code, code_count, function,
                                                 lock_add, lock_call))
                continue;

            if (require_native_bounds &&
                !nbg_kgsl_idr_alloc_native_bounds(code, code_count, function,
                                                  idr_add, idr_call))
                continue;

            memset(&candidate, 0, sizeof(candidate));
            candidate.process_reg = adds[i].rn;
            if (!nbg_kgsl_find_process_offset(
                    code, code_count, candidate.process_reg, adds[i].index,
                    &candidate.layout.process_priv_offset))
                continue;

            candidate.layout.syncsource_idr_offset = lower;
            candidate.layout.syncsource_lock_offset = upper;

            ret = nbg_kgsl_add_candidate(out, out_count, &candidate);
            if (ret)
                goto out;
        }
    }

    ret = *out_count ? 0 : -EOPNOTSUPP;

out:
    kfree(code);
    return ret;
}

/* ---- 运行时符号解析 ---- */

static unsigned long nbg_kgsl_lookup_cfi(const char *name)
{
    char cfi_name[KSYM_NAME_LEN];
    ssize_t len;

    if (!name)
        return 0;
    len = strscpy(cfi_name, name, sizeof(cfi_name));
    if (len <= 0 || (size_t)len + sizeof(".cfi_jt") > sizeof(cfi_name))
        return 0;
    strscpy(cfi_name + len, ".cfi_jt", sizeof(cfi_name) - len);
    return nbg_ksym_lookup_name(cfi_name);
}

static int nbg_kgsl_resolve_identity(struct nbg_kgsl_runtime_symbols *symbols)
{
    memset(symbols, 0, sizeof(*symbols));
    symbols->fops = nbg_ksym_lookup_name("kgsl_fops");
    symbols->ioctl = nbg_ksym_lookup_name("kgsl_ioctl");
    symbols->ioctl_cfi = nbg_kgsl_lookup_cfi("kgsl_ioctl");

    return (symbols->fops || symbols->ioctl || symbols->ioctl_cfi) ?
        0 : -EOPNOTSUPP;
}

static int nbg_kgsl_resolve_runtime(struct nbg_kgsl_runtime_symbols *symbols,
                                    struct nbg_kgsl_layout *layout,
                                    enum nbg_kgsl_fail_stage *stage)
{
    struct nbg_kgsl_layout_candidate create[KGSL_LAYOUT_MAX_CANDIDATES];
    struct nbg_kgsl_layout_candidate destroy[KGSL_LAYOUT_MAX_CANDIDATES];
    struct nbg_kgsl_call_targets idr_alloc_t;
    struct nbg_kgsl_call_targets idr_find_t;
    struct nbg_kgsl_call_targets spin_lock_t;
    unsigned int create_count = 0;
    unsigned int destroy_count = 0;
    unsigned int matches = 0;
    unsigned int i;
    unsigned int j;
    int ret;

    memset(layout, 0, sizeof(*layout));

    if (!symbols->fops && !symbols->ioctl && !symbols->ioctl_cfi) {
        if (stage)
            *stage = NBG_KGSL_FAIL_FILE_IDENTITY;
        return -EOPNOTSUPP;
    }

    symbols->create = nbg_kgsl_resolve_call_target(
        nbg_ksym_lookup_name("kgsl_ioctl_syncsource_create"));
    symbols->destroy = nbg_kgsl_resolve_call_target(
        nbg_ksym_lookup_name("kgsl_ioctl_syncsource_destroy"));
    symbols->idr_alloc = nbg_ksym_lookup_name("idr_alloc");
    symbols->idr_alloc_cfi = nbg_kgsl_lookup_cfi("idr_alloc");
    symbols->idr_find = nbg_ksym_lookup_name("idr_find");
    symbols->idr_find_cfi = nbg_kgsl_lookup_cfi("idr_find");
    symbols->raw_spin_lock = nbg_ksym_lookup_name("_raw_spin_lock");
    symbols->raw_spin_lock_cfi = nbg_kgsl_lookup_cfi("_raw_spin_lock");

    if (symbols->idr_alloc)
        symbols->idr_alloc = nbg_kgsl_resolve_call_target(symbols->idr_alloc);
    if (symbols->idr_find)
        symbols->idr_find = nbg_kgsl_resolve_call_target(symbols->idr_find);
    if (symbols->raw_spin_lock)
        symbols->raw_spin_lock =
            nbg_kgsl_resolve_call_target(symbols->raw_spin_lock);

    if (!symbols->create || !symbols->destroy ||
        !symbols->idr_alloc || !symbols->idr_find ||
        !symbols->raw_spin_lock) {
        if (stage)
            *stage = NBG_KGSL_FAIL_RUNTIME_SYMBOLS;
        return -EOPNOTSUPP;
    }

    memset(&idr_alloc_t, 0, sizeof(idr_alloc_t));
    memset(&idr_find_t, 0, sizeof(idr_find_t));
    memset(&spin_lock_t, 0, sizeof(spin_lock_t));
    idr_alloc_t.direct = symbols->idr_alloc;
    idr_alloc_t.cfi_jt = symbols->idr_alloc_cfi;
    idr_find_t.direct = symbols->idr_find;
    idr_find_t.cfi_jt = symbols->idr_find_cfi;
    spin_lock_t.direct = symbols->raw_spin_lock;
    spin_lock_t.cfi_jt = symbols->raw_spin_lock_cfi;

    ret = nbg_kgsl_decode_layout(symbols->create, &idr_alloc_t, &spin_lock_t,
                                 true, create, &create_count);
    if (ret) {
        if (stage)
            *stage = NBG_KGSL_FAIL_CREATE_LAYOUT;
        return ret;
    }

    ret = nbg_kgsl_decode_layout(symbols->destroy, &idr_find_t, &spin_lock_t,
                                 false, destroy, &destroy_count);
    if (ret) {
        if (stage)
            *stage = NBG_KGSL_FAIL_DESTROY_LAYOUT;
        return ret;
    }

    /* 两次独立解码必须得到唯一相同布局，否则拒绝。 */
    for (i = 0; i < create_count; i++) {
        for (j = 0; j < destroy_count; j++) {
            if (!nbg_kgsl_same_layout(&create[i].layout, &destroy[j].layout))
                continue;
            *layout = create[i].layout;
            matches++;
        }
    }

    if (matches != 1U) {
        if (stage)
            *stage = NBG_KGSL_FAIL_LAYOUT_MISMATCH;
        return -EOPNOTSUPP;
    }

    if (layout->syncsource_idr_offset > KGSL_LAYOUT_MAX_FIELD_OFFSET ||
        layout->syncsource_lock_offset !=
            layout->syncsource_idr_offset + sizeof(struct idr)) {
        if (stage)
            *stage = NBG_KGSL_FAIL_LAYOUT_OFFSETS;
        return -EOPNOTSUPP;
    }

    return 0;
}

static bool nbg_kgsl_file_matches(const struct file *file,
                                  const struct nbg_kgsl_runtime_symbols *symbols)
{
    const struct file_operations *fops;
    unsigned long unlocked_ioctl;
    unsigned long compat_ioctl;

    if (!file || !file_inode(file) || !S_ISCHR(file_inode(file)->i_mode))
        return false;

    fops = READ_ONCE(file->f_op);
    if (!fops)
        return false;

    if (symbols->fops && (unsigned long)fops == symbols->fops)
        return true;

    unlocked_ioctl = (unsigned long)READ_ONCE(fops->unlocked_ioctl);
#ifdef CONFIG_COMPAT
    compat_ioctl = (unsigned long)READ_ONCE(fops->compat_ioctl);
#else
    compat_ioctl = 0;
#endif

    return (symbols->ioctl &&
            (unlocked_ioctl == symbols->ioctl ||
             compat_ioctl == symbols->ioctl)) ||
           (symbols->ioctl_cfi &&
            (unlocked_ioctl == symbols->ioctl_cfi ||
             compat_ioctl == symbols->ioctl_cfi));
}

static int nbg_kgsl_use_cached(const struct file *file,
                               struct nbg_kgsl_layout *layout,
                               enum nbg_kgsl_fail_stage *stage)
{
    if (!nbg_kgsl_file_matches(file, &g_kgsl_runtime_cache.symbols)) {
        if (stage)
            *stage = NBG_KGSL_FAIL_NOT_KGSL_FILE;
        return -ENODEV;
    }

    *layout = g_kgsl_runtime_cache.layout;
    return 0;
}

static int nbg_kgsl_get_runtime(struct file *file,
                                struct nbg_kgsl_layout *layout,
                                enum nbg_kgsl_fail_stage *stage)
{
    struct nbg_kgsl_runtime_symbols symbols;
    struct nbg_kgsl_layout resolved;
    int ret;

    if (smp_load_acquire(&g_kgsl_runtime_cache.ready))
        return nbg_kgsl_use_cached(file, layout, stage);

    mutex_lock(&g_kgsl_runtime_cache_lock);
    if (READ_ONCE(g_kgsl_runtime_cache.ready)) {
        ret = nbg_kgsl_use_cached(file, layout, stage);
        goto out_unlock;
    }

    /* 身份确认之前不通过符号去读厂商代码。 */
    ret = nbg_kgsl_resolve_identity(&symbols);
    if (ret) {
        if (stage)
            *stage = NBG_KGSL_FAIL_FILE_IDENTITY;
        goto out_unlock;
    }
    if (!nbg_kgsl_file_matches(file, &symbols)) {
        if (stage)
            *stage = NBG_KGSL_FAIL_NOT_KGSL_FILE;
        ret = -ENODEV;
        goto out_unlock;
    }

    ret = nbg_kgsl_resolve_runtime(&symbols, &resolved, stage);
    if (ret)
        goto out_unlock;

    g_kgsl_runtime_cache.symbols = symbols;
    g_kgsl_runtime_cache.layout = resolved;
    smp_store_release(&g_kgsl_runtime_cache.ready, 1U);
    *layout = resolved;
    ret = 0;

out_unlock:
    mutex_unlock(&g_kgsl_runtime_cache_lock);
    return ret;
}

/* ---- 活体 IDR 校验与最低空闲 ID ---- */

static int nbg_kgsl_validate_idr(struct idr *idr)
{
    unsigned int base;
    unsigned int next;
    gfp_t flags;
    void *head;
    struct xa_node *node;
    struct xa_node *parent;
    struct xarray *array;
    u8 shift;
    u8 offset;
    u8 count;
    u8 nr_values;
    int ret = 0;

    if (copy_from_kernel_nofault(&base, &idr->idr_base, sizeof(base)) ||
        copy_from_kernel_nofault(&next, &idr->idr_next, sizeof(next)) ||
        copy_from_kernel_nofault(&flags, &idr->idr_rt.xa_flags,
                                 sizeof(flags)))
        return -EFAULT;

    if (base != 0U || next != 0U || (flags & IDR_RT_MARKER) != IDR_RT_MARKER)
        return -EOPNOTSUPP;

    rcu_read_lock();
    if (copy_from_kernel_nofault(&head, &idr->idr_rt.xa_head, sizeof(head))) {
        ret = -EFAULT;
        goto out_rcu;
    }
    if (!head)
        goto out_rcu;
    if (xa_is_retry(head)) {
        ret = -EAGAIN;
        goto out_rcu;
    }
    if (!xa_is_node(head)) {
        /* syncsource 从 1 开始分配，非空合法树不会用 index-0 直接表示。 */
        ret = -EOPNOTSUPP;
        goto out_rcu;
    }

    node = xa_to_node(head);
    if (copy_from_kernel_nofault(&parent, &node->parent, sizeof(parent)) ||
        copy_from_kernel_nofault(&array, &node->array, sizeof(array)) ||
        copy_from_kernel_nofault(&shift, &node->shift, sizeof(shift)) ||
        copy_from_kernel_nofault(&offset, &node->offset, sizeof(offset)) ||
        copy_from_kernel_nofault(&count, &node->count, sizeof(count)) ||
        copy_from_kernel_nofault(&nr_values, &node->nr_values,
                                 sizeof(nr_values))) {
        ret = -EFAULT;
        goto out_rcu;
    }

    if (parent || array != &idr->idr_rt || offset != 0U || count == 0U ||
        count > XA_CHUNK_SIZE || nr_values > count ||
        shift >= BITS_PER_LONG || (shift % XA_CHUNK_SHIFT) != 0U)
        ret = -EOPNOTSUPP;

out_rcu:
    rcu_read_unlock();
    return ret;
}

static int nbg_kgsl_find_lowest_free_once(struct idr *idr, u32 min_id,
                                          u32 *out_id)
{
    XA_STATE(xas, &idr->idr_rt, min_id);
    void *entry = NULL;
    unsigned int attempt;
    int ret = 0;

    rcu_read_lock();
    for (attempt = 0; attempt < KGSL_SYNCSOURCE_XAS_RETRIES; attempt++) {
        entry = xas_find_marked(&xas, (unsigned long)INT_MAX, XA_FREE_MARK);
        if (!xas_retry(&xas, entry))
            break;
    }

    if (attempt == KGSL_SYNCSOURCE_XAS_RETRIES) {
        ret = -EAGAIN;
    } else if (xas_error(&xas)) {
        ret = xas_error(&xas);
    } else if (xas.xa_node == XAS_RESTART) {
        ret = -ENOSPC;
    } else if (entry) {
        /* 空闲标记遍历应停在 NULL 槽。非 NULL 说明并发分配者
         * 在清 XA_FREE_MARK 前发布了对象，整轮重试而不是猜。 */
        ret = -EAGAIN;
    } else if (xas.xa_index < min_id ||
               xas.xa_index > (unsigned long)INT_MAX) {
        ret = -EAGAIN;
    } else {
        *out_id = (u32)xas.xa_index;
    }

    rcu_read_unlock();
    return ret;
}

/* 两次采样一致才采信，拒绝明显的并发写入。 */
static int nbg_kgsl_find_stable_lowest_free(struct idr *idr, u32 min_id,
                                            u32 *out_id)
{
    unsigned int attempt;

    for (attempt = 0; attempt < KGSL_SYNCSOURCE_STABLE_TRIES; attempt++) {
        u32 first;
        u32 second;
        int ret;

        ret = nbg_kgsl_find_lowest_free_once(idr, min_id, &first);
        if (ret)
            return ret;
        ret = nbg_kgsl_find_lowest_free_once(idr, min_id, &second);
        if (ret)
            return ret;
        if (first == second) {
            *out_id = first;
            return 0;
        }
        cpu_relax();
    }

    return -EAGAIN;
}

static int nbg_kgsl_peek_file(struct file *file, u32 min_id,
                              const u32 *excluded, u32 excluded_count,
                              u32 *out_id, enum nbg_kgsl_fail_stage *stage)
{
    struct nbg_kgsl_layout layout;
    void *dev_priv;
    void *process_priv;
    struct idr *idr;
    u32 index = 0;
    u32 attempt;
    int ret;

    ret = nbg_kgsl_get_runtime(file, &layout, stage);
    if (ret)
        return ret;

    dev_priv = READ_ONCE(file->private_data);
    if (!dev_priv) {
        *stage = NBG_KGSL_FAIL_NOT_KGSL_FILE;
        return -ENODEV;
    }

    if (copy_from_kernel_nofault(
            &process_priv,
            (const char *)dev_priv + layout.process_priv_offset,
            sizeof(process_priv)) || !process_priv) {
        *stage = NBG_KGSL_FAIL_PROCESS_PRIV;
        return -EOPNOTSUPP;
    }

    idr = (struct idr *)((char *)process_priv +
                         layout.syncsource_idr_offset);
    ret = nbg_kgsl_validate_idr(idr);
    if (ret) {
        if (ret == -EOPNOTSUPP)
            *stage = NBG_KGSL_FAIL_LIVE_IDR;
        return ret;
    }

    /* 整个排除搜索期间固定同一个 file，避免并发 close/reuse
     * 导致两个不同的 IDR 混用。 */
    for (attempt = 0; attempt <= excluded_count; attempt++) {
        u32 candidate;

        ret = nbg_kgsl_find_stable_lowest_free(idr, min_id, &candidate);
        if (ret) {
            *stage = NBG_KGSL_FAIL_LOWEST_FREE;
            return ret;
        }
        while (index < excluded_count && excluded[index] < candidate)
            index++;
        if (index == excluded_count || excluded[index] != candidate) {
            *out_id = candidate;
            return 0;
        }
        if (candidate == INT_MAX)
            return -ENOSPC;
        min_id = candidate + 1U;
        index++;
    }

    return -EAGAIN;
}

/* ---- 目标进程 fd 解析 ---- */

static struct file *nbg_kgsl_target_file(int pid, u32 fd,
                                         enum nbg_kgsl_fail_stage *stage)
{
    struct task_struct *task;
    struct file *file = NULL;
    struct files_struct *files;
    struct fdtable *table;
    int ret;

    *stage = NBG_KGSL_FAIL_FILE_IDENTITY;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();
    if (!task)
        return ERR_PTR(-ESRCH);

    /* 与 exec/凭据变更串行化。带锁的 fdtable 查找在
     * SLAB_TYPESAFE_BY_RCU 的 file slab 上也成立。 */
    ret = mutex_lock_killable(&task->signal->cred_guard_mutex);
    if (ret)
        goto out_task;

    *stage = NBG_KGSL_FAIL_NOT_KGSL_FILE;
    ret = -EBADF;
    task_lock(task);
    files = task->files;
    if (files) {
        spin_lock(&files->file_lock);
        table = files_fdtable(files);
        if (fd <= INT_MAX && fd < table->max_fds) {
            file = rcu_dereference_raw(table->fd[fd]);
            if (file)
                get_file(file);
        }
        spin_unlock(&files->file_lock);
    } else {
        ret = -ESRCH;
    }
    task_unlock(task);
    mutex_unlock(&task->signal->cred_guard_mutex);

out_task:
    put_task_struct(task);
    return file ? file : ERR_PTR(ret);
}

/* ---- GPU object 元数据查询 ---- */

/* 这个前向声明刻意与厂商 handler 的 CFI 类型一致。
 * 绝不把 file ioctl 回调强转成内部 INFO 签名。 */
struct kgsl_device_private;
typedef long (*nbg_kgsl_info_fn)(struct kgsl_device_private *,
                                 unsigned int, void *);

static DEFINE_MUTEX(g_kgsl_query_lock);
static struct nbg_kgsl_runtime_symbols g_kgsl_query_identity;
static nbg_kgsl_info_fn g_kgsl_query_info;
static bool g_kgsl_query_ready;

static unsigned long nbg_kgsl_callable_symbol(const char *name)
{
    unsigned long jt = nbg_kgsl_lookup_cfi(name);

    /* 老 GKI 的间接调用要走 CFI 跳板。上面的裸地址只用于指纹。 */
    return jt ? jt : nbg_ksym_lookup_name(name);
}

static int nbg_kgsl_query_runtime(enum nbg_kgsl_fail_stage *stage)
{
    int ret = 0;

    if (smp_load_acquire(&g_kgsl_query_ready))
        return 0;

    mutex_lock(&g_kgsl_query_lock);
    if (g_kgsl_query_ready)
        goto out;

    ret = nbg_kgsl_resolve_identity(&g_kgsl_query_identity);
    if (ret) {
        *stage = NBG_KGSL_FAIL_FILE_IDENTITY;
        goto out;
    }

    /* 可选：缺失不得影响 VALIDATE_FD 与 SYNCSOURCE_PEEK。 */
    g_kgsl_query_info = (nbg_kgsl_info_fn)
        nbg_kgsl_callable_symbol("kgsl_ioctl_gpuobj_info");
    smp_store_release(&g_kgsl_query_ready, true);

out:
    mutex_unlock(&g_kgsl_query_lock);
    return ret;
}

long nbg_kgsl_syncsource_peek(void __user *arg)
{
    NBG_KGSL_SYNC_PEEK_REQ req;
    struct file *file;
    enum nbg_kgsl_fail_stage stage = NBG_KGSL_FAIL_NONE;
    int ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    req.out_id = 0;
    req.out_backend = 0;

    if (req.kgsl_fd < 0 || req.min_id == 0U ||
        req.min_id > (u32)INT_MAX || req.flags != 0U ||
        req.reserved[0] != 0U || req.reserved[1] != 0U ||
        req.abi_version != NBG_KGSL_SYNC_ABI_VERSION)
        return -EINVAL;

    file = fget((unsigned int)req.kgsl_fd);
    if (!file)
        return -EBADF;

    ret = nbg_kgsl_peek_file(file, req.min_id, NULL, 0, &req.out_id, &stage);
    fput(file);

    if (!ret)
        req.out_backend = NBG_KGSL_SYNC_BACKEND_IDR_RCU;
    if (!ret || stage != NBG_KGSL_FAIL_NONE) {
        req.reserved[0] = (u32)stage;
        if (copy_to_user(arg, &req, sizeof(req)))
            ret = -EFAULT;
    }
    return ret;
}

static int nbg_kgsl_query_gpuobj(struct file *file,
                                 NBG_KGSL_QUERY_REQ *req)
{
    NBG_KGSL_GPUOBJ_INFO info = { .id = req->object_id };
    struct kgsl_device_private *dev_priv;
    long result;

    req->out_fail_stage = NBG_KGSL_FAIL_RUNTIME_SYMBOLS;
    if (!g_kgsl_query_info)
        return -EOPNOTSUPP;

    dev_priv = READ_ONCE(file->private_data);
    if (!dev_priv) {
        req->out_fail_stage = NBG_KGSL_FAIL_NOT_KGSL_FILE;
        return -ENODEV;
    }

    /* 原生 INFO 自己获取/释放临时 mem_entry 引用，并读取厂商私有
     * memdesc 字段。这里只允许这一个只读 handler，没有用户命令、
     * 用户指针、分配/导入或 SET_INFO 路径。 */
    result = g_kgsl_query_info(
        dev_priv, _IOWR(0x09, 0x47, NBG_KGSL_GPUOBJ_INFO), &info);

    req->out_fail_stage = NBG_KGSL_FAIL_LOWEST_FREE;
    if (result < -MAX_ERRNO || result > 0)
        return -EPROTO;
    if (result < 0) {
        req->out_errno = (s32)-result;
    } else {
        if (info.id != req->object_id || info.id == 0)
            return -EPROTO;
        info.padding = 0;
        req->out_info = info;
    }

    req->out_backend = NBG_KGSL_QUERY_BACKEND_NATIVE_INFO;
    req->out_fail_stage = 0;
    return 0;
}

long nbg_kgsl_query(void __user *arg)
{
    NBG_KGSL_QUERY_REQ req;
    struct file *file;
    u32 *excluded = NULL;
    u32 i;
    int ret;
    enum nbg_kgsl_fail_stage stage = NBG_KGSL_FAIL_NONE;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    if (req.abi_version != NBG_KGSL_QUERY_ABI_VERSION || req.pid <= 0 ||
        req.flags || req.reserved[0] || req.reserved[1])
        return -EINVAL;

    req.out_id = req.out_backend = req.out_errno = req.out_fail_stage = 0;
    memset(&req.out_info, 0, sizeof(req.out_info));

    if (req.op < NBG_KGSL_QUERY_VALIDATE_FD ||
        req.op > NBG_KGSL_QUERY_GPUOBJ_INFO)
        return -EINVAL;

    if (req.op == NBG_KGSL_QUERY_SYNCSOURCE_PEEK) {
        if (req.object_id || !req.min_id || req.min_id > INT_MAX ||
            req.excluded_count > NBG_KGSL_QUERY_MAX_EXCLUDED_IDS ||
            (!!req.excluded_count != !!req.excluded_ids))
            return -EINVAL;

        if (req.excluded_count) {
            excluded = memdup_user(u64_to_user_ptr(req.excluded_ids),
                                   req.excluded_count * sizeof(*excluded));
            if (IS_ERR(excluded))
                return PTR_ERR(excluded);
            for (i = 0; i < req.excluded_count; i++) {
                if (!excluded[i] || excluded[i] > INT_MAX ||
                    (i && excluded[i] <= excluded[i - 1U])) {
                    ret = -EINVAL;
                    goto out;
                }
            }
        }
    } else if (req.min_id || req.excluded_count || req.excluded_ids ||
               (req.op == NBG_KGSL_QUERY_VALIDATE_FD && req.object_id)) {
        return -EINVAL;
    }

    ret = nbg_kgsl_query_runtime(&req.out_fail_stage);
    if (ret)
        goto out;

    file = nbg_kgsl_target_file(req.pid, req.target_fd,
                                &req.out_fail_stage);
    if (IS_ERR(file)) {
        ret = PTR_ERR(file);
        if (ret == -EBADF) {
            req.out_errno = EBADF;
            req.out_fail_stage = 0;
            ret = 0;
        }
        goto out;
    }

    req.out_fail_stage = NBG_KGSL_FAIL_NOT_KGSL_FILE;
    if (!nbg_kgsl_file_matches(file, &g_kgsl_query_identity)) {
        ret = -ENODEV;
        goto out_file;
    }
    req.out_fail_stage = 0;

    switch (req.op) {
    case NBG_KGSL_QUERY_VALIDATE_FD:
        req.out_backend = NBG_KGSL_QUERY_BACKEND_FILE;
        ret = 0;
        break;
    case NBG_KGSL_QUERY_SYNCSOURCE_PEEK:
        ret = nbg_kgsl_peek_file(file, req.min_id, excluded,
                                 req.excluded_count, &req.out_id, &stage);
        req.out_fail_stage = stage;
        if (ret == -ENOSPC) {
            req.out_errno = ENOSPC;
            req.out_fail_stage = 0;
            ret = 0;
        }
        if (!ret)
            req.out_backend = NBG_KGSL_QUERY_BACKEND_IDR_RCU;
        break;
    case NBG_KGSL_QUERY_GPUOBJ_INFO:
        ret = nbg_kgsl_query_gpuobj(file, &req);
        break;
    }

out_file:
    fput(file);
out:
    kfree(excluded);
    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;
    return ret;
}
