/* fd_install.c - ENEN-style anon-inode fd installation entry */
#define pr_fmt(fmt) KBUILD_MODNAME ": fd_install: " fmt

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>

#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <asm/memory.h>
#include <asm/pgtable.h>
#include <asm/unistd.h>

#include "comm.h"
#include "export_fun.h"
#include "nbg_compat.h"
#include "nbg_gki_compat.h"
#include "nbg_log.h"

#if !defined(CONFIG_ARM64)
#error "NBG fd installation requires ARM64"
#endif

typedef asmlinkage long (*nbg_syscall_fn_t)(const struct pt_regs *);
typedef void (*nbg_set_fixmap_t)(enum fixed_addresses index,
                                phys_addr_t phys, pgprot_t prot);
typedef long (*nbg_copy_nofault_t)(void *dst, const void *src, size_t size);
typedef void (*nbg_flush_poc_t)(unsigned long start, unsigned long end);
typedef void (*nbg_flush_area_t)(void *start, size_t size);
typedef int (*nbg_stop_machine_t)(int (*fn)(void *), void *data,
                                 const struct cpumask *cpu_mask);
typedef int (*nbg_task_work_add_t)(struct task_struct *task,
                                   struct callback_head *work,
                                   enum task_work_notify_mode mode);

static nbg_syscall_fn_t *g_sys_call_table;
static nbg_syscall_fn_t g_orig_syscall;
static int g_hooked_nr = -1;
static struct kprobe g_reboot_kprobe;
static bool g_reboot_kprobe_registered;
static nbg_set_fixmap_t g_set_fixmap;
static nbg_copy_nofault_t g_copy_nofault;
static nbg_flush_poc_t g_flush_poc;
static nbg_flush_area_t g_flush_area;
static nbg_stop_machine_t g_stop_machine;
static nbg_task_work_add_t g_task_work_add;

struct nbg_patch_text_info {
    void *destination;
    const void *source;
    size_t size;
    atomic_t cpu_count;
};

struct nbg_install_work {
    struct callback_head callback;
    int __user *out_fd;
};

static unsigned long nbg_lookup_syscall_symbol(const char *name)
{
    char cfi_name[KSYM_NAME_LEN];
    static const char suffix[] = ".cfi_jt";
    size_t name_len;
    size_t suffix_len = sizeof(suffix) - 1;
    unsigned long address;

    if (!name || !name[0])
        return 0;

    name_len = strlen(name);
    if ((name_len < suffix_len ||
         strcmp(name + name_len - suffix_len, suffix) != 0) &&
        strscpy(cfi_name, name, sizeof(cfi_name)) > 0 &&
        strlen(cfi_name) + suffix_len + 1 <= sizeof(cfi_name)) {
        size_t offset = strlen(cfi_name);

        strscpy(cfi_name + offset, suffix, sizeof(cfi_name) - offset);
        address = generic_kallsyms_lookup_name(cfi_name);
        if (address)
            return address;
    }

    return generic_kallsyms_lookup_name(name);
}

NBG_NO_CFI
static struct mm_struct *nbg_get_init_mm(void)
{
    return (struct mm_struct *)generic_kallsyms_lookup_name("init_mm");
}

static unsigned long nbg_syscall_phys_from_virt(unsigned long address,
                                                int *error)
{
    struct mm_struct *mm = nbg_get_init_mm();
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    *error = 0;
    if (!mm) {
        *error = -ENOENT;
        return 0;
    }

    pgd = pgd_offset(mm, address);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto not_mapped;

    p4d = p4d_offset(pgd, address);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto not_mapped;
#if defined(p4d_leaf)
    if (p4d_leaf(*p4d))
        return __p4d_to_phys(*p4d) + (address & ~P4D_MASK);
#endif

    pud = pud_offset(p4d, address);
    if (pud_none(*pud) || pud_bad(*pud))
        goto not_mapped;
#if defined(pud_leaf)
    if (pud_leaf(*pud))
        return __pud_to_phys(*pud) + (address & ~PUD_MASK);
#endif

    pmd = pmd_offset(pud, address);
#if defined(pmd_leaf)
    if (pmd_leaf(*pmd))
        return __pmd_to_phys(*pmd) + (address & ~PMD_MASK);
#endif
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto not_mapped;

    pte = pte_offset_kernel(pmd, address);
    if (!pte || !pte_present(*pte))
        goto not_mapped;

    return __pte_to_phys(*pte) + (address & ~PAGE_MASK);

not_mapped:
    *error = -ENOENT;
    return 0;
}

NBG_NO_CFI
static int nbg_patch_text_nosync(void *destination, const void *source,
                                 size_t size)
{
    unsigned long phys;
    void *mapping;
    int error;
    int ret;

    phys = nbg_syscall_phys_from_virt((unsigned long)destination, &error);
    if (error)
        return error;

    g_set_fixmap(FIX_TEXT_POKE0, phys, PAGE_KERNEL);
    mapping = (void *)fix_to_virt(FIX_TEXT_POKE0) + (phys & ~PAGE_MASK);
    ret = (int)g_copy_nofault(mapping, source, size);
    g_set_fixmap(FIX_TEXT_POKE0, 0, __pgprot(0));

    if (!ret) {
        unsigned long start = (unsigned long)destination;

        if (g_flush_poc)
            g_flush_poc(start, start + size);
        else
            g_flush_area(destination, size);
    }
    return ret;
}

static int nbg_patch_text_on_all_cpus(void *data)
{
    struct nbg_patch_text_info *info = data;
    int ret = 0;

    if (atomic_inc_return(&info->cpu_count) == num_online_cpus()) {
        ret = nbg_patch_text_nosync(info->destination, info->source,
                                    info->size);
        atomic_inc(&info->cpu_count);
    } else {
        while (atomic_read(&info->cpu_count) <= num_online_cpus())
            cpu_relax();
        isb();
    }
    return ret;
}

NBG_NO_CFI
static int nbg_patch_text(void *destination, const void *source, size_t size)
{
    struct nbg_patch_text_info info = {
        .destination = destination,
        .source = source,
        .size = size,
        .cpu_count = ATOMIC_INIT(0),
    };

    return g_stop_machine(nbg_patch_text_on_all_cpus, &info,
                          cpu_online_mask);
}

static int nbg_patch_syscall_table(int nr, nbg_syscall_fn_t replacement)
{
    if (!g_sys_call_table)
        return -ENOENT;
    if (nr < 0 || nr >= __NR_syscalls)
        return -EINVAL;
    return nbg_patch_text(&g_sys_call_table[nr], &replacement,
                          sizeof(replacement));
}

NBG_NO_CFI
static asmlinkage long nbg_syscall_install_handler(const struct pt_regs *regs)
{
    if (!regs || __kuid_val(current_uid()) > 1000)
        return -ENOSYS;
    if ((u32)regs->regs[0] != NBG_INSTALL_MAGIC1 ||
        (u32)regs->regs[1] != NBG_INSTALL_MAGIC2)
        return -ENOSYS;

    return nbg_comm_install_fd_to_user(regs->regs[3]);
}

static nbg_syscall_fn_t nbg_lookup_ni_syscall(void)
{
    nbg_syscall_fn_t fn;

    fn = (nbg_syscall_fn_t)nbg_lookup_syscall_symbol(
        "__arm64_sys_ni_syscall");
    if (fn)
        return fn;
    return (nbg_syscall_fn_t)nbg_lookup_syscall_symbol("sys_ni_syscall");
}

static int nbg_syscall_hook_init(void)
{
    nbg_syscall_fn_t ni_syscall;
    int nr;
    int ret;

    g_sys_call_table = (nbg_syscall_fn_t *)nbg_lookup_syscall_symbol(
        "sys_call_table");
    ni_syscall = nbg_lookup_ni_syscall();
    if (!g_sys_call_table || !ni_syscall)
        return -ENOENT;

    for (nr = 0; nr < __NR_syscalls; nr++) {
        if (READ_ONCE(g_sys_call_table[nr]) != ni_syscall)
            continue;

        ret = nbg_patch_syscall_table(nr, nbg_syscall_install_handler);
        if (ret)
            continue;

        g_orig_syscall = ni_syscall;
        g_hooked_nr = nr;
        NBG_INFO("fd install syscall hook registered nr=%d\n", nr);
        return 0;
    }
    return -ENOENT;
}

static void nbg_install_work_callback(struct callback_head *callback)
{
    struct nbg_install_work *work =
        container_of(callback, struct nbg_install_work, callback);

    nbg_comm_install_fd_to_user((unsigned long)work->out_fd);
    kfree(work);
}

NBG_NO_CFI
static int nbg_reboot_kprobe_pre(struct kprobe *probe, struct pt_regs *regs)
{
    struct pt_regs *user_regs;
    struct nbg_install_work *work;

    (void)probe;
    if (!regs || __kuid_val(current_uid()) > 1000)
        return 0;

    user_regs = (struct pt_regs *)regs->regs[0];
    if (!user_regs || (u32)user_regs->regs[0] != NBG_INSTALL_MAGIC1 ||
        (u32)user_regs->regs[1] != NBG_INSTALL_MAGIC2)
        return 0;

    work = kmalloc(sizeof(*work), GFP_ATOMIC);
    if (!work)
        return 0;
    work->out_fd = (int __user *)(unsigned long)user_regs->regs[3];
    init_task_work(&work->callback, nbg_install_work_callback);
    if (g_task_work_add(current, &work->callback, TWA_RESUME)) {
        kfree(work);
        NBG_WARN("reboot fallback task_work_add failed\n");
    }
    return 0;
}

static int nbg_reboot_hook_init(void)
{
    memset(&g_reboot_kprobe, 0, sizeof(g_reboot_kprobe));
    g_reboot_kprobe.symbol_name = "__arm64_sys_reboot";
    g_reboot_kprobe.pre_handler = nbg_reboot_kprobe_pre;
    if (nbg_register_kprobe(&g_reboot_kprobe))
        return -ENOENT;
    g_reboot_kprobe_registered = true;
    return 0;
}

int nbg_fd_install_init(void)
{
    unsigned long flush_poc;
    int ret;

    g_set_fixmap = (nbg_set_fixmap_t)generic_kallsyms_lookup_name(
        "__set_fixmap");
    g_copy_nofault = (nbg_copy_nofault_t)generic_kallsyms_lookup_name(
        "copy_to_kernel_nofault");
    g_stop_machine = (nbg_stop_machine_t)generic_kallsyms_lookup_name(
        "stop_machine");
    flush_poc = generic_kallsyms_lookup_name("dcache_clean_inval_poc");
    if (flush_poc)
        g_flush_poc = (nbg_flush_poc_t)flush_poc;
    else
        g_flush_area = (nbg_flush_area_t)generic_kallsyms_lookup_name(
            "__flush_dcache_area");
    g_task_work_add = (nbg_task_work_add_t)generic_kallsyms_lookup_name(
        "task_work_add");

    if (!g_set_fixmap || !g_copy_nofault || !g_stop_machine ||
        (!g_flush_poc && !g_flush_area) || !g_task_work_add)
        return -ENOENT;

    ret = nbg_syscall_hook_init();
    if (!ret)
        return 0;

    ret = nbg_reboot_hook_init();
    if (ret)
        NBG_FAIL_CODE(1201, ret);
    return ret;
}

void nbg_fd_install_exit(void)
{
    if (g_reboot_kprobe_registered) {
        nbg_unregister_kprobe(&g_reboot_kprobe);
        g_reboot_kprobe_registered = false;
    }

    if (g_sys_call_table && g_hooked_nr >= 0 && g_orig_syscall) {
        int ret = nbg_patch_syscall_table(g_hooked_nr, g_orig_syscall);

        if (ret)
            NBG_ERR("failed to restore syscall nr=%d ret=%d\n",
                    g_hooked_nr, ret);
    }
    g_hooked_nr = -1;
    g_orig_syscall = NULL;
    g_sys_call_table = NULL;
}
