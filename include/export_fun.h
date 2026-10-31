/* export_fun.h - common helpers for resolving unexported kernel symbols.
 *
 * This is the NBG-local subset of lsdriver's export_fun.h idea:
 * use a temporary kprobe on kallsyms_lookup_name, then build small helpers
 * around symbol lookup, legacy CFI slowpath patching, and kprobe/kretprobe
 * registration.
 *
 * Deliberately not included here:
 *   - kprobe blacklist modification
 *   - executable memory allocation for inline hooks
 *   - raw KCALL asm wrappers
 */
#ifndef _NBG_EXPORT_FUN_H_
#define _NBG_EXPORT_FUN_H_

#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>

#include "nbg_compat.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)

typedef unsigned long (*nbg_kallsyms_lookup_name_t)(const char *name);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
static int nbg_lookup_probe_return(struct kretprobe_instance *ri,
                                   struct pt_regs *regs)
{
    return 0;
}
#endif

NBG_NO_CFI
static unsigned long nbg_call_kallsyms_lookup_name(unsigned long addr,
                                                   const char *name)
{
    nbg_kallsyms_lookup_name_t fn = (nbg_kallsyms_lookup_name_t)addr;
    return fn(name);
}

static __maybe_unused unsigned long generic_kallsyms_lookup_name(const char *name)
{
    static unsigned long kallsyms_addr;
    static DEFINE_MUTEX(kallsyms_mutex);
    unsigned long addr;

    addr = READ_ONCE(kallsyms_addr);
    if (addr)
        return nbg_call_kallsyms_lookup_name(addr, name);

    mutex_lock(&kallsyms_mutex);
    addr = READ_ONCE(kallsyms_addr);
    if (!addr) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
        struct kretprobe rp;
        int ret;

        /* Android 13/5.10 exports the return-probe API, but can trim the
         * single kprobe API. Bootstrap through the former, not recursively
         * through a register_kprobe pointer requiring this same lookup.
         * Keep the temporary probe DISABLED: resolve its address without
         * installing an active handler on other CPUs. */
        memset(&rp, 0, sizeof(rp));
        rp.kp.symbol_name = "kallsyms_lookup_name";
        rp.kp.flags = KPROBE_FLAG_DISABLED;
        rp.handler = nbg_lookup_probe_return;
        rp.maxactive = 1;
        ret = register_kretprobe(&rp);
        if (ret < 0) {
            mutex_unlock(&kallsyms_mutex);
            return 0;
        }
        addr = (unsigned long)rp.kp.addr;
        unregister_kretprobe(&rp);
#else
        struct kprobe kp;
        int ret;

        memset(&kp, 0, sizeof(kp));
        kp.symbol_name = "kallsyms_lookup_name";

        ret = register_kprobe(&kp);
        if (ret < 0) {
            mutex_unlock(&kallsyms_mutex);
            return 0;
        }

        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
#endif
        if (!addr) {
            mutex_unlock(&kallsyms_mutex);
            return 0;
        }
        WRITE_ONCE(kallsyms_addr, addr);
    }
    mutex_unlock(&kallsyms_mutex);
    return nbg_call_kallsyms_lookup_name(addr, name);
}

#else

static __maybe_unused inline unsigned long generic_kallsyms_lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}

#endif

static __maybe_unused unsigned long resolve_first_symbol(const char * const *names)
{
    int i;

    if (!names)
        return 0;
    for (i = 0; names[i]; i++) {
        unsigned long addr = generic_kallsyms_lookup_name(names[i]);
        if (addr)
            return addr;
    }
    return 0;
}

#define NBG_AARCH64_RET_INSN 0xD65F03C0U

typedef int (*nbg_aarch64_insn_patch_text_t)(void *addrs[], u32 insns[], int cnt);

NBG_NO_CFI
static __maybe_unused bool bypass_cfi(void)
{
    static bool is_cfi_bypassed;
    static const char * const cfi_cands[] = {
        "__cfi_slowpath",
        "__cfi_slowpath_diag",
        "_cfi_slowpath",
        NULL,
    };
    unsigned long patch_text_addr;
    unsigned long cfi_addr;
    nbg_aarch64_insn_patch_text_t patch_text;
    void *patch_addrs[1];
    u32 patch_insns[1] = { NBG_AARCH64_RET_INSN };

    if (READ_ONCE(is_cfi_bypassed))
        return true;

    patch_text_addr = generic_kallsyms_lookup_name("aarch64_insn_patch_text");
    if (!patch_text_addr)
        return false;

    cfi_addr = resolve_first_symbol(cfi_cands);
    if (!cfi_addr)
        return false;

    patch_text = (nbg_aarch64_insn_patch_text_t)patch_text_addr;
    patch_addrs[0] = (void *)cfi_addr;
    if (patch_text(patch_addrs, patch_insns, 1) != 0)
        return false;

    WRITE_ONCE(is_cfi_bypassed, true);
    return true;
}

static __maybe_unused unsigned long resolve_first_symbol_named(
    const char * const *names, const char **hit_name)
{
    int i;

    if (hit_name)
        *hit_name = NULL;
    if (!names)
        return 0;
    for (i = 0; names[i]; i++) {
        unsigned long addr = generic_kallsyms_lookup_name(names[i]);
        if (addr) {
            if (hit_name)
                *hit_name = names[i];
            return addr;
        }
    }
    return 0;
}

static __maybe_unused int nbg_register_kprobe_named(
    struct kprobe *kp, const char * const *names, const char **hit_out)
{
    unsigned long addr;
    const char *hit = NULL;

    if (!kp || !names)
        return -EINVAL;

    addr = resolve_first_symbol_named(names, &hit);
    if (!addr)
        return -ENOENT;

    kp->addr = (kprobe_opcode_t *)addr;
    kp->symbol_name = NULL;
    if (hit_out)
        *hit_out = hit;
    return nbg_register_kprobe(kp);
}

static __maybe_unused int nbg_register_kretprobe_named(
    struct kretprobe *krp, const char * const *names, const char **hit_out)
{
    unsigned long addr;
    const char *hit = NULL;

    if (!krp || !names)
        return -EINVAL;

    addr = resolve_first_symbol_named(names, &hit);
    if (!addr)
        return -ENOENT;

    krp->kp.addr = (kprobe_opcode_t *)addr;
    krp->kp.symbol_name = NULL;
    if (hit_out)
        *hit_out = hit;
    return register_kretprobe(krp);
}

static __maybe_unused int nbg_register_kretprobe_addr(
    struct kretprobe *krp, unsigned long addr)
{
    if (!krp || !addr)
        return -EINVAL;

    krp->kp.addr = (kprobe_opcode_t *)addr;
    krp->kp.symbol_name = NULL;
    return register_kretprobe(krp);
}

/* kallsyms_lookup_size_offset 包装：KGSL 指纹用它区分函数本体与跳板。
 * 该符号在部分 GKI 分支不导出，统一走 kallsyms 解析。 */
typedef int (*nbg_ksym_size_offset_t)(unsigned long addr, unsigned long *size,
                                      unsigned long *offset);

static __maybe_unused int nbg_ksym_size_offset(unsigned long addr,
                                               unsigned long *size,
                                               unsigned long *offset)
{
    static nbg_ksym_size_offset_t cached;

    if (!cached)
        cached = (nbg_ksym_size_offset_t)
            generic_kallsyms_lookup_name("kallsyms_lookup_size_offset");
    if (!cached || !size || !offset)
        return 0;
    return cached(addr, size, offset);
}

static __maybe_unused unsigned long nbg_ksym_lookup_name(const char *name)
{
    return generic_kallsyms_lookup_name(name);
}

#endif /* _NBG_EXPORT_FUN_H_ */
