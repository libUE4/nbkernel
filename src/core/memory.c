/* memory.c — 跨进程内存读取
 *
 * 页表遍历取得物理地址，再经预先建立的 non-cacheable 直映射读取目标内存。
 * 该路径不经过 PTE 权限位，因此能读到 present 但用户态不可访问的页面。
 *
 * linearmap 在模块初始化时建立一次：遍历 memblock 的全部内存区域，
 * 以 MT_NORMAL_NC 属性把它们映射到内核虚拟地址空间。之后每次读取只需
 * 一次页表遍历定位物理地址，加一次线性偏移。
 */
#include "memory.h"

#include <linux/highmem.h>
#include <linux/io.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>
#include <asm/memory.h>
#include <asm/pgtable.h>

#include "nbg_compat.h"
#include "nbg_ksyms.h"

#ifndef PAGE_ALIGN_START
#define PAGE_ALIGN_START(x) ((x) & PAGE_MASK)
#endif

#ifndef PAGE_ALIGN_END
#define PAGE_ALIGN_END(x) PAGE_ALIGN(x)
#endif

#ifndef pmd_cont
#define pmd_cont(x) 0
#endif

#ifndef pmd_leaf_size
#define pmd_leaf_size(x) PMD_SIZE
#endif

#ifndef CONT_PMD_SIZE
#define CONT_PMD_SIZE PMD_SIZE
#endif

#ifndef CONT_PMD_MASK
#define CONT_PMD_MASK (~(CONT_PMD_SIZE - 1))
#endif

#ifndef CONT_PTE_SIZE
#define CONT_PTE_SIZE PAGE_SIZE
#endif

#ifndef CONT_PTE_MASK
#define CONT_PTE_MASK (~(CONT_PTE_SIZE - 1))
#endif

#define NBG_STACK_PFN_COUNT   16UL
#define NBG_KMALLOC_PFN_COUNT (NBG_STACK_PFN_COUNT * 32UL)
#define NBG_READ_MAX          (4UL * 1024UL * 1024UL)

/* vmap/vmalloc 符号在部分 GKI 分支不导出，统一走 kallsyms 解析。 */
typedef struct vm_struct *(*nbg_get_vm_area_caller_t)(unsigned long,
                                                      unsigned long,
                                                      const void *);
typedef int (*nbg_apply_to_page_range_t)(struct mm_struct *, unsigned long,
                                         unsigned long, pte_fn_t, void *);
typedef void (*nbg_free_vm_area_t)(struct vm_struct *);

static nbg_get_vm_area_caller_t nbg_get_vm_area_caller;
static nbg_apply_to_page_range_t nbg_apply_to_page_range;
static nbg_free_vm_area_t nbg_free_vm_area;
static struct mm_struct *nbg_init_mm;
static struct memblock *nbg_memblock;

struct nbg_linearmap {
    unsigned long phys;
    unsigned long size;
    unsigned long virt_nc;
};

static struct nbg_linearmap *g_linearmap;
static unsigned long g_linearmap_count;
static bool g_linearmap_ready;
static struct rw_semaphore g_linearmap_lock;

struct nbg_vmap_ctx {
    unsigned long *pfns;
    pgprot_t prot;
    unsigned long index;
};

static int noinline nbg_vmap_apply(pte_t *pte, unsigned long addr,
                                   void *private)
{
    struct nbg_vmap_ctx *ctx = private;

    *pte = pfn_pte(ctx->pfns[ctx->index++], ctx->prot);
    return 0;
}

static void *nbg_vmap_pfn(unsigned long *pfns, unsigned long count,
                          pgprot_t prot)
{
    struct nbg_vmap_ctx ctx = {
        .pfns = pfns,
        .prot = prot,
        .index = 0,
    };
    struct vm_struct *area;

    if (!nbg_get_vm_area_caller || !nbg_apply_to_page_range ||
        !nbg_free_vm_area || !nbg_init_mm)
        return NULL;

    area = nbg_get_vm_area_caller(count * PAGE_SIZE, 0,
                                  __builtin_return_address(0));
    if (!area)
        return NULL;

    if (nbg_apply_to_page_range(nbg_init_mm, (unsigned long)area->addr,
                                count * PAGE_SIZE, nbg_vmap_apply, &ctx)) {
        nbg_free_vm_area(area);
        return NULL;
    }

    return area->addr;
}

static void *nbg_phys_map(unsigned long phys, size_t size, pgprot_t prot)
{
    unsigned long phys_start = PAGE_ALIGN_START(phys);
    unsigned long phys_end = PAGE_ALIGN_END(phys + size);
    unsigned long count = (phys_end - phys_start) >> PAGE_SHIFT;
    unsigned long offset = phys - phys_start;
    unsigned long stack_pfns[NBG_STACK_PFN_COUNT];
    unsigned long *pfns;
    bool use_vmalloc = false;
    void *mapped;
    unsigned long i;

    if (!count)
        return NULL;

    if (count <= NBG_STACK_PFN_COUNT) {
        pfns = stack_pfns;
    } else if (count <= NBG_KMALLOC_PFN_COUNT) {
        pfns = kmalloc_array(count, sizeof(*pfns), GFP_KERNEL);
        if (!pfns)
            return NULL;
    } else {
        pfns = vmalloc_array(count, sizeof(*pfns));
        if (!pfns)
            return NULL;
        use_vmalloc = true;
    }

    for (i = 0; i < count; i++)
        pfns[i] = PHYS_PFN(phys_start) + i;

    mapped = nbg_vmap_pfn(pfns, count, prot);

    if (count > NBG_STACK_PFN_COUNT) {
        if (use_vmalloc)
            vfree(pfns);
        else
            kfree(pfns);
    }

    if (!mapped)
        return NULL;

    return (void *)((unsigned long)mapped + offset);
}

static void nbg_phys_unmap(void *mapped)
{
    vunmap((void *)PAGE_ALIGN_START((unsigned long)mapped));
}

static int nbg_linearmap_build_regions(void)
{
    struct memblock_type *memory = &nbg_memblock->memory;
    pgprot_t prot = __pgprot(PROT_DEFAULT | PTE_PXN | PTE_UXN | PTE_WRITE |
                             PTE_ATTRINDX(MT_NORMAL_NC));
    unsigned long index = 0;
    unsigned long i;

    for (i = 0; i < memory->cnt; i++) {
        struct memblock_region *region = &memory->regions[i];
        void *mapped;

        if (region->flags & MEMBLOCK_NOMAP)
            continue;

        if (g_linearmap[index].virt_nc) {
            index++;
            continue;
        }

        mapped = nbg_phys_map(region->base, region->size, prot);
        if (!mapped) {
            while (index > 0) {
                index--;
                if (g_linearmap[index].virt_nc) {
                    nbg_phys_unmap((void *)g_linearmap[index].virt_nc);
                    g_linearmap[index].virt_nc = 0;
                }
            }
            return -EAGAIN;
        }

        g_linearmap[index].virt_nc = (unsigned long)mapped;
        g_linearmap[index].phys = region->base;
        g_linearmap[index].size = region->size;
        index++;
    }

    return 0;
}

/* Caller must hold g_linearmap_lock for writing. */
static void nbg_linearmap_destroy_locked(void)
{
    unsigned long i;

    if (!g_linearmap)
        return;

    for (i = 0; i < g_linearmap_count; i++) {
        if (g_linearmap[i].virt_nc) {
            nbg_phys_unmap((void *)g_linearmap[i].virt_nc);
            g_linearmap[i].virt_nc = 0;
        }
    }

    g_linearmap_ready = false;
    kfree(g_linearmap);
    g_linearmap = NULL;
    g_linearmap_count = 0;
}

static int nbg_linearmap_build(void)
{
    struct memblock_type *memory = &nbg_memblock->memory;
    int ret = 0;
    unsigned long i;

    down_write(&g_linearmap_lock);

    if (!g_linearmap_count) {
        for (i = 0; i < memory->cnt; i++) {
            if (!(memory->regions[i].flags & MEMBLOCK_NOMAP))
                g_linearmap_count++;
        }
    }

    if (!g_linearmap_count) {
        up_write(&g_linearmap_lock);
        return -ENOENT;
    }

    if (!g_linearmap) {
        g_linearmap = kcalloc(g_linearmap_count, sizeof(*g_linearmap),
                              GFP_KERNEL);
        if (!g_linearmap) {
            up_write(&g_linearmap_lock);
            return -ENOMEM;
        }
    }

    if (!g_linearmap_ready) {
        ret = nbg_linearmap_build_regions();
        if (ret)
            nbg_linearmap_destroy_locked();
        else
            g_linearmap_ready = true;
    }

    up_write(&g_linearmap_lock);
    return ret;
}

static unsigned long nbg_phys_to_virt_nc(unsigned long phys)
{
    unsigned long result = 0;
    unsigned long i;

    down_read(&g_linearmap_lock);

    if (!g_linearmap || !g_linearmap_ready)
        goto out;

    for (i = 0; i < g_linearmap_count; i++) {
        unsigned long base = g_linearmap[i].phys;
        unsigned long size = g_linearmap[i].size;

        if (phys >= base && phys < base + size) {
            unsigned long virt = g_linearmap[i].virt_nc;

            result = virt ? virt + (phys - base) : 0;
            break;
        }
    }

out:
    up_read(&g_linearmap_lock);
    return result;
}

static inline size_t nbg_size_inside_page(unsigned long addr, size_t count)
{
    size_t remain = PAGE_SIZE - (addr & ~PAGE_MASK);

    return min(remain, count);
}

/* Walk the target page tables to a physical address. *size receives the
 * number of bytes still contiguous from this physical address within the
 * same mapping granule, so a large page yields one long run. */
static unsigned long nbg_follow_phys(struct mm_struct *mm, unsigned long virt,
                                     size_t *size)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    pgd = pgd_offset(mm, virt);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return ~0UL;

    p4d = p4d_offset(pgd, virt);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return ~0UL;

    pud = pud_offset(p4d, virt);
    if (pud_none(*pud))
        return ~0UL;

    if (pud_leaf(*pud)) {
        unsigned long pfn = pud_pfn(*pud);

        if (!pfn)
            return ~0UL;
        if (size)
            *size = PUD_SIZE - (virt & ~PUD_MASK);
        return PFN_PHYS(pfn) | (virt & ~PUD_MASK);
    }

    pmd = pmd_offset(pud, virt);
    if (pmd_none(*pmd))
        return ~0UL;

    if (pmd_leaf(*pmd)) {
        unsigned long pfn = pmd_pfn(*pmd);
        unsigned long offset;
        unsigned long granule;
        phys_addr_t phys;

        if (!pfn)
            return ~0UL;

        if (pmd_cont(*pmd)) {
            unsigned long base_va = virt & CONT_PMD_MASK;
            pmd_t *first = pmd_offset(pud, base_va);

            granule = CONT_PMD_SIZE;
            offset = virt & ~CONT_PMD_MASK;
            phys = PFN_PHYS(pmd_pfn(*first)) + offset;
        } else {
            granule = pmd_leaf_size(*pmd);
            offset = virt & ~PMD_MASK;
            phys = PFN_PHYS(pfn) | offset;
        }

        if (size)
            *size = granule - offset;
        return phys;
    }

    pte = pte_offset_kernel(pmd, virt);
    if (!pte_present(*pte) || !pte_pfn(*pte))
        return ~0UL;

    {
        unsigned long pfn = pte_pfn(*pte);
        unsigned long offset;
        unsigned long granule;
        phys_addr_t phys;

        if (pte_cont(*pte)) {
            unsigned long base_va = virt & CONT_PTE_MASK;
            pte_t *first = pte_offset_kernel(pmd, base_va);

            granule = CONT_PTE_SIZE;
            offset = virt & ~CONT_PTE_MASK;
            phys = PFN_PHYS(pte_pfn(*first)) + offset;
        } else {
            granule = PAGE_SIZE;
            offset = virt & ~PAGE_MASK;
            phys = PFN_PHYS(pfn) | offset;
        }

        if (size)
            *size = granule - offset;
        return phys;
    }
}

/* Read through the non-cacheable linearmap. Returns bytes copied, or a
 * negative errno when nothing was copied at all. */
static ssize_t nbg_nc_read(struct mm_struct *mm, unsigned long addr,
                           void *buffer, size_t count)
{
    char *out = buffer;
    size_t copied = 0;

    while (count > 0) {
        size_t this_len = nbg_size_inside_page(addr, count);
        unsigned long phys = nbg_follow_phys(mm, addr, &this_len);
        unsigned long virt;

        if (phys == ~0UL)
            break;

        this_len = min(this_len, count);
        virt = nbg_phys_to_virt_nc(phys);
        if (!virt)
            break;

        memcpy(out, (void *)virt, this_len);

        out += this_len;
        addr += this_len;
        copied += this_len;
        count -= this_len;
    }

    if (!copied)
        return -EFAULT;
    return copied;
}

/* Same walker, but the destination is a userspace pointer. */
static ssize_t nbg_nc_read_user(struct mm_struct *mm, unsigned long addr,
                                void __user *buffer, size_t count)
{
    char *out = (char __user *)buffer;
    size_t copied = 0;

    while (count > 0) {
        size_t this_len = nbg_size_inside_page(addr, count);
        unsigned long phys = nbg_follow_phys(mm, addr, &this_len);
        unsigned long virt;
        size_t failed;

        if (phys == ~0UL)
            break;

        this_len = min(this_len, count);
        virt = nbg_phys_to_virt_nc(phys);
        if (!virt)
            break;

        failed = copy_to_user(out, (void *)virt, this_len);
        if (failed) {
            copied += this_len - failed;
            break;
        }

        out += this_len;
        addr += this_len;
        copied += this_len;
        count -= this_len;
    }

    if (!copied)
        return -EFAULT;
    return copied;
}

static struct mm_struct *nbg_get_mm(pid_t pid, struct task_struct **task_out)
{
    struct task_struct *task;
    struct mm_struct *mm;

    if (pid <= 0)
        return NULL;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();

    if (!task)
        return NULL;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return NULL;
    }

    if (task_out)
        *task_out = task;
    else
        put_task_struct(task);

    return mm;
}

int nbg_memory_init(void)
{
    nbg_get_vm_area_caller = (nbg_get_vm_area_caller_t)
        generic_kallsyms_lookup_name("get_vm_area_caller");
    nbg_apply_to_page_range = (nbg_apply_to_page_range_t)
        generic_kallsyms_lookup_name("apply_to_page_range");
    nbg_free_vm_area = (nbg_free_vm_area_t)
        generic_kallsyms_lookup_name("free_vm_area");
    nbg_init_mm = (struct mm_struct *)generic_kallsyms_lookup_name("init_mm");
    nbg_memblock = (struct memblock *)generic_kallsyms_lookup_name("memblock");

    if (!nbg_memblock)
        return -ENOENT;

    init_rwsem(&g_linearmap_lock);

    return nbg_linearmap_build();
}

void nbg_memory_cache_cleanup(void)
{
    down_write(&g_linearmap_lock);
    nbg_linearmap_destroy_locked();
    up_write(&g_linearmap_lock);
}

bool read_process_memory_mm(struct mm_struct *mm, uintptr_t addr,
                            void *buffer, size_t size)
{
    ssize_t ret;

    if (!mm || !buffer || !size)
        return false;

    ret = nbg_nc_read(mm, (unsigned long)addr, buffer, size);
    return ret == (ssize_t)size;
}

bool read_process_memory_kernel(pid_t pid, uintptr_t addr, void *buffer,
                                size_t size)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm;
    ssize_t ret;

    if (!buffer || !size)
        return false;

    mm = nbg_get_mm(pid, &task);
    if (!mm)
        return false;

    ret = nbg_nc_read(mm, (unsigned long)addr, buffer, size);

    mmput(mm);
    if (task)
        put_task_struct(task);

    return ret == (ssize_t)size;
}

int nbg_read_memory(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                    size_t size, size_t *nbytes)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm;
    ssize_t ret;

    if (nbytes)
        *nbytes = 0;
    if (!user_addr || !size || size > NBG_READ_MAX)
        return -EINVAL;

    mm = nbg_get_mm(pid, &task);
    if (!mm)
        return -ESRCH;

    ret = nbg_nc_read_user(mm, (unsigned long)remote_addr,
                           (void __user *)user_addr, size);

    mmput(mm);
    if (task)
        put_task_struct(task);

    if (ret < 0)
        return (int)ret;

    if (nbytes)
        *nbytes = (size_t)ret;
    return ret == (ssize_t)size ? 0 : -EFAULT;
}

/* The NC path never resolves a fault, so the fault variant is the same
 * operation. Kept as a separate entry so callers keep their ABI. */
int nbg_read_memory_fault(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                          size_t size, size_t *nbytes)
{
    return nbg_read_memory(pid, remote_addr, user_addr, size, nbytes);
}
