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
#include "nbg_alloc.h"

#include <linux/highmem.h>
#include <linux/hardirq.h>
#include <linux/io.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/version.h>

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

/* 这三个符号不导出，只能经 kallsyms 拿到地址再调用。5.10/5.15 用 LTO 版 CFI，
 * 类型 ID 在内核链接时统一分配，模块单独编译拿不到同一 ID，插桩的间接调用
 * 会直接 panic；__nocfi 让这里不插桩。6.1+ 是 KCFI，按类型哈希校验，不受影响。 */
static void *NBG_NO_CFI nbg_vmap_pfn(unsigned long *pfns, unsigned long count,
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
        /* vmalloc_array 在 5.10 与 6.12 上分别是未知符号 / vmalloc_array_noprof，
         * 直接引用会让模块在真机上加载失败；vmalloc 各版本都导出。 */
        if (count > SIZE_MAX / sizeof(*pfns))
            return NULL;
        pfns = vmalloc(count * sizeof(*pfns));
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
        unsigned long phys;

        if (!pfn)
            return ~0UL;
        if (size)
            *size = PUD_SIZE - (virt & ~PUD_MASK);
        phys = PFN_PHYS(pfn) | (virt & ~PUD_MASK);
        if (phys > 0x400000000UL)
            pr_err("nbg: walk pud virt=0x%lx entry=0x%llx pfn=0x%lx phys=0x%lx\n",
                   virt, (unsigned long long)pud_val(*pud), pfn, phys);
        return phys;
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
        if (phys > 0x400000000UL)
            pr_err("nbg: walk pmd virt=0x%lx entry=0x%llx pfn=0x%lx phys=0x%llx\n",
                   virt, (unsigned long long)pmd_val(*pmd), pfn,
                   (unsigned long long)phys);
        return phys;
    }

    pte = pte_offset_kernel(pmd, virt);
    if (!pte_present(*pte) || !pte_pfn(*pte)) {
        pr_err_ratelimited("nbg: pte miss virt=0x%lx pte=0x%llx present=%d pfn=%d\n",
                           virt, (unsigned long long)pte_val(*pte),
                           pte_present(*pte) ? 1 : 0, pte_pfn(*pte) ? 1 : 0);
        return ~0UL;
    }

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

/* DminLine: CTR_EL0[19:16]，最小 D/统一 cache 行长(log2 字数)。
 * DC CVAC 一次只清包含该 VA 的那一条 line，by-VA 循环步长必须用最小行长，
 * 否则在 cache_line_size()(最大行长/CWG) > DminLine 的 SoC 上会跳过中间行漏刷。 */
static inline unsigned long nbg_dcache_min_line(void)
{
    unsigned long ctr;

    asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
    return 4UL << ((ctr >> 16) & 0xf);
}

/* Cache-maintenance variant: the target page may still have dirty lines in
 * some CPU's D-cache, so invalidate by VA on the cacheable alias before
 * reading the non-cacheable one. */
static void nbg_dcache_invalidate(unsigned long phys, size_t len)
{
    unsigned long line = nbg_dcache_min_line();
    unsigned long c_va = (unsigned long)phys_to_virt(phys);
    unsigned long start = c_va & ~(line - 1);
    unsigned long end = (c_va + len + line - 1) & ~(line - 1);
    unsigned long va;

    for (va = start; va < end; va += line)
        asm volatile("dc cvac, %0" : : "r"(va) : "memory");
    asm volatile("dsb sy" : : : "memory");
}

/* Read/write through the non-cacheable linearmap. Mirrors enkernel's
 * nc_memrw: one walker, one copy, direction chosen by `write`. */
/* kvmalloc_array / vmalloc_array 在 6.10+ 会展开成 *_noprof 符号，而设备
 * 内核只导出旧名字；统一走 nbg_alloc.h 的版本适配层。 */
static ssize_t nbg_nc_memrw(struct mm_struct *mm, unsigned long addr,
                            char __user *buf, size_t count, int write)
{
    ssize_t copied = 0;

    if (!mm)
        return -EINVAL;

    while (count > 0) {
        size_t this_len = nbg_size_inside_page(addr, count);
        unsigned long phys = nbg_follow_phys(mm, addr, &this_len);
        unsigned long virt;
        size_t failed_len;

        if (phys == ~0UL)
            break;

        this_len = min(this_len, count);

        /* 跨设备 / 保留区的物理地址不归 linearmap 管，不做映射查找。 */
        if (!pfn_valid(__phys_to_pfn(phys & PAGE_MASK))) {
            pr_err_ratelimited("nbg: phys not in dram phys=0x%lx addr=0x%lx\n",
                               phys, addr);
            break;
        }

        virt = nbg_phys_to_virt_nc(phys);
        if (!virt) {
            pr_err_ratelimited("nbg: no nc mapping phys=0x%lx addr=0x%lx count=%lu\n",
                               phys, addr, g_linearmap_count);
            break;
        }

        if (!write) {
            failed_len = copy_to_user(buf, (void *)virt, this_len);
        } else {
            failed_len = copy_from_user((void *)virt, buf, this_len);
        }

        if (failed_len) {
            copied += this_len - failed_len;
            break;
        }

        buf += this_len;
        addr += this_len;
        copied += this_len;
        count -= this_len;
    }

    return copied;
}

/* GUP faults in each requested page and returns a short-lived page reference.
 * mmap_lock keeps the target VMA stable; the page reference prevents reclaim
 * or migration from recycling it before the bytes have been copied. */
static int nbg_fault_read_mm(struct mm_struct *mm, unsigned long addr,
                             void *buffer, size_t size, size_t *nbytes)
{
    size_t copied = 0;
    u8 *output = buffer;
    int ret = 0;

    if (nbytes) *nbytes = 0;
    if (!mm || !buffer || !size)
        return -EINVAL;

    compat_mmap_read_lock(mm);
    while (copied < size) {
        struct page *page = NULL;
        unsigned int flags = 0;
        unsigned long current_addr = addr + copied;
        size_t offset = offset_in_page(current_addr);
        size_t bytes = min_t(size_t, size - copied, PAGE_SIZE - offset);
        void *mapped;

        /* A NULL locked argument keeps GUP from dropping mmap_lock while the
         * caller continues to use the mm and its VMA. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
        ret = get_user_pages_remote(mm, current_addr, 1, flags, &page, NULL);
#else
        ret = get_user_pages_remote(mm, current_addr, 1, flags, &page,
                                    NULL, NULL);
#endif
        if (ret != 1) {
            if (ret >= 0) ret = -EFAULT;
            break;
        }

        mapped = compat_kmap_page(page);
        memcpy(output + copied, (u8 *)mapped + offset, bytes);
        compat_kunmap_page(mapped);
        put_page(page);
        copied += bytes;
        ret = 0;
        if (!(copied & ((16U * PAGE_SIZE) - 1U)))
            cond_resched();
    }
    compat_mmap_read_unlock(mm);
    if (nbytes) *nbytes = copied;
    return copied == size ? 0 : (ret ? ret : -EFAULT);
}

/* Cache-maintenance variant: invalidate the cacheable alias before the copy. */
static ssize_t nbg_nc_memrw_cached(struct mm_struct *mm, unsigned long addr,
                                   char __user *buf, size_t count, int write)
{
    ssize_t copied = 0;

    if (!mm)
        return -EINVAL;

    while (count > 0) {
        size_t this_len = nbg_size_inside_page(addr, count);
        unsigned long phys = nbg_follow_phys(mm, addr, &this_len);
        unsigned long virt;
        size_t failed_len;

        if (phys == ~0UL)
            break;

        this_len = min(this_len, count);
        virt = nbg_phys_to_virt_nc(phys);
        if (!virt)
            break;

        nbg_dcache_invalidate(phys, this_len);

        if (!write) {
            failed_len = copy_to_user(buf, (void *)virt, this_len);
        } else {
            failed_len = copy_from_user((void *)virt, buf, this_len);
        }

        if (failed_len) {
            copied += this_len - failed_len;
            break;
        }

        buf += this_len;
        addr += this_len;
        copied += this_len;
        count -= this_len;
    }

    return copied;
}

/* Kernel-buffer read used by in-module callers. */
static ssize_t nbg_nc_read(struct mm_struct *mm, unsigned long addr,
                           void *buffer, size_t count)
{
    char *out = buffer;
    size_t copied = 0;

    if (!mm)
        return -EINVAL;

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

    {
        int lr = nbg_linearmap_build();

        pr_err("nbg: linearmap ret=%d count=%lu ready=%d\n", lr,
               g_linearmap_count, g_linearmap_ready ? 1 : 0);
        if (g_linearmap_count && g_linearmap) {
            unsigned long i;

            for (i = 0; i < g_linearmap_count; i++)
                pr_err("nbg: lm[%lu] phys=0x%lx size=0x%lx virt=0x%lx\n",
                       i, g_linearmap[i].phys, g_linearmap[i].size,
                       g_linearmap[i].virt_nc);
        }
        return lr;
    }
}

/* 仅在模块退出时调用：linearmap 是模块级资源，不随客户端断开销毁。 */
void nbg_memory_exit(void)
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

/* Write into the target through the same NC linearmap. */
bool write_process_memory_kernel(pid_t pid, uintptr_t addr,
                                 const void *buffer, size_t size)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm;
    size_t copied = 0;

    if (!buffer || !size)
        return false;

    mm = nbg_get_mm(pid, &task);
    if (!mm)
        return false;

    {
        const char *in = buffer;
        unsigned long cur = (unsigned long)addr;
        size_t left = size;

        while (left > 0) {
            size_t this_len = nbg_size_inside_page(cur, left);
            unsigned long phys = nbg_follow_phys(mm, cur, &this_len);
            unsigned long virt;

            if (phys == ~0UL)
                break;

            this_len = min(this_len, left);
            virt = nbg_phys_to_virt_nc(phys);
            if (!virt)
                break;

            memcpy((void *)virt, in, this_len);
            nbg_dcache_invalidate(phys, this_len);

            in += this_len;
            cur += this_len;
            copied += this_len;
            left -= this_len;
        }
    }

    mmput(mm);
    if (task)
        put_task_struct(task);

    return copied == size;
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

/* Shared ioctl bridge: remote <-> user buffer, direction and cache policy
 * selected by the caller. Mirrors enkernel's access_remote_vm_nc{, _cache}. */
static int nbg_rw_memory(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                         size_t size, size_t *nbytes, bool write,
                         bool cache_flush)
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

    if (cache_flush)
        ret = nbg_nc_memrw_cached(mm, (unsigned long)remote_addr,
                                  (char __user *)user_addr, size, write);
    else
        ret = nbg_nc_memrw(mm, (unsigned long)remote_addr,
                           (char __user *)user_addr, size, write);

    if (ret < 0)
        pr_err_ratelimited("nbg: rw pid=%d addr=0x%lx size=%zu w=%d ret=%zd linearmap=%d/%lu mm=%px cur=%px pgd=%px\n",
                           pid, (unsigned long)remote_addr, size, write, ret,
                           g_linearmap_ready ? 1 : 0, g_linearmap_count,
                           mm, current->mm, (void *)mm->pgd);

    mmput(mm);
    if (task)
        put_task_struct(task);

    if (nbytes)
        *nbytes = ret > 0 ? (size_t)ret : 0;
    if (ret < 0)
        return (int)ret;
    return ret == (ssize_t)size ? 0 : -EFAULT;
}

int nbg_read_memory(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                    size_t size, size_t *nbytes)
{
    return nbg_rw_memory(pid, remote_addr, user_addr, size, nbytes, false,
                         false);
}

int nbg_read_memory_fault(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                          size_t size, size_t *nbytes)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm;
    void *buffer;
    size_t copied = 0;
    int ret;

    if (nbytes) *nbytes = 0;
    if (pid <= 0 || !remote_addr || !user_addr || !size ||
        size > NBG_MAX_RW_SIZE || remote_addr + size < remote_addr)
        return -EINVAL;
    if (in_atomic() || irqs_disabled())
        return -EBUSY;
    buffer = nbg_kvmalloc(size, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;
    mm = nbg_get_mm(pid, &task);
    if (!mm) {
        kvfree(buffer);
        return -ESRCH;
    }
    ret = nbg_fault_read_mm(mm, (unsigned long)remote_addr, buffer, size,
                            &copied);
    mmput(mm);
    if (task) put_task_struct(task);
    if (!ret && copy_to_user((void __user *)user_addr, buffer, size)) {
        ret = -EFAULT;
        copied = 0;
    }
    kvfree(buffer);
    if (nbytes) *nbytes = copied;
    return ret;
}

/* Cache-maintenance read: invalidate the cacheable alias before copying from
 * the NC mapping, for pages that may still be dirty in some CPU's D-cache. */
int nbg_read_memory_cache(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                          size_t size, size_t *nbytes)
{
    return nbg_rw_memory(pid, remote_addr, user_addr, size, nbytes, false,
                         true);
}

int nbg_write_memory(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                     size_t size, size_t *nbytes)
{
    return nbg_rw_memory(pid, remote_addr, user_addr, size, nbytes, true,
                         false);
}

int nbg_write_memory_cache(pid_t pid, uintptr_t remote_addr,
                           uintptr_t user_addr, size_t size, size_t *nbytes)
{
    return nbg_rw_memory(pid, remote_addr, user_addr, size, nbytes, true,
                         true);
}

/* ---- 可复用的 mm 上下文 ---- */

int nbg_read_ctx_init_pid(struct nbg_read_ctx *ctx, pid_t pid)
{
    struct task_struct *task;
    struct mm_struct *mm;

    if (!ctx || pid <= 0)
        return -EINVAL;

    ctx->pid = 0;
    ctx->mm = NULL;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();
    if (!task)
        return -ESRCH;

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return -EINVAL;

    ctx->pid = pid;
    ctx->mm = mm;
    return 0;
}

int nbg_read_ctx_init_current(struct nbg_read_ctx *ctx, pid_t expected_tgid)
{
    struct mm_struct *mm;

    if (!ctx || expected_tgid <= 0)
        return -EINVAL;

    ctx->pid = 0;
    ctx->mm = NULL;

    if (current->tgid != expected_tgid)
        return -ESRCH;

    mm = get_task_mm(current);
    if (!mm)
        return -EINVAL;

    ctx->pid = expected_tgid;
    ctx->mm = mm;
    return 0;
}

long nbg_read_ctx_read(struct nbg_read_ctx *ctx, uint64_t addr, void *buf,
                       size_t size)
{
    ssize_t ret;

    if (!ctx || !ctx->mm || !buf)
        return -EINVAL;
    if (size == 0 || size > NBG_READ_MAX)
        return -EINVAL;

    ret = nbg_nc_read(ctx->mm, (unsigned long)addr, buf, size);
    if (ret < 0)
        return ret;
    if ((uint64_t)ret != size)
        return -EFAULT;

    return 0;
}

void nbg_read_ctx_release(struct nbg_read_ctx *ctx)
{
    if (!ctx)
        return;
    if (ctx->mm)
        mmput(ctx->mm);
    ctx->pid = 0;
    ctx->mm = NULL;
}

long nbg_read_kernel(pid_t pid, uint64_t addr, void *buf, size_t size)
{
    struct nbg_read_ctx ctx;
    long ret;

    ret = nbg_read_ctx_init_pid(&ctx, pid);
    if (ret)
        return ret;

    ret = nbg_read_ctx_read(&ctx, addr, buf, size);
    nbg_read_ctx_release(&ctx);
    return ret;
}

/* 批量离散读取：一次取 mm，逐个 iov 走 NC 直读，逐个回写 status。
 * 与单次读取同语义，只是省掉重复的 find_vpid / get_task_mm。 */
static int nbg_readv_mode(pid_t pid, READV_ENTRY __user *iov, uint32_t count)
{
    struct nbg_read_ctx ctx;
    READV_ENTRY *entries;
    uint32_t i;
    bool need_mm = false;
    int ret;

    if (!iov || !count || count > NBG_IOV_MAX)
        return -EINVAL;

    entries = nbg_kvmalloc_array(count, sizeof(*entries), GFP_KERNEL);
    if (!entries)
        return -ENOMEM;

    if (copy_from_user(entries, iov, count * sizeof(*entries))) {
        kvfree(entries);
        return -EFAULT;
    }

    for (i = 0; i < count; i++) {
        entries[i].status = 0;
        if (!entries[i].size)
            continue;
        if (!entries[i].addr || !entries[i].buffer)
            entries[i].status = -EINVAL;
        else if (entries[i].size > NBG_READ_MAX)
            entries[i].status = -EMSGSIZE;
        else if (!access_ok((void __user *)entries[i].buffer,
                            entries[i].size))
            entries[i].status = -EFAULT;
        else
            need_mm = true;
    }

    if (need_mm) {
        ret = nbg_read_ctx_init_pid(&ctx, pid);
        if (ret) {
            for (i = 0; i < count; i++) {
                if (entries[i].size && entries[i].status == 0)
                    entries[i].status = ret;
            }
            goto copy_back;
        }

        for (i = 0; i < count; i++) {
            ssize_t got;

            if (!entries[i].size || entries[i].status)
                continue;

            got = nbg_nc_memrw(ctx.mm, (unsigned long)entries[i].addr,
                               (char __user *)entries[i].buffer,
                               entries[i].size, false);
            if (got < 0)
                entries[i].status = (int)got;
            else if ((uint32_t)got != entries[i].size)
                entries[i].status = -EFAULT;

            cond_resched();
            if (fatal_signal_pending(current)) {
                for (i++; i < count; i++) {
                    if (entries[i].size && entries[i].status == 0)
                        entries[i].status = -EINTR;
                }
                break;
            }
        }
        nbg_read_ctx_release(&ctx);
    }

copy_back:
    if (copy_to_user(iov, entries, count * sizeof(*entries))) {
        kvfree(entries);
        return -EFAULT;
    }
    kvfree(entries);
    return 0;
}

int nbg_readv_memory(pid_t pid, READV_ENTRY __user *iov, uint32_t count)
{
    return nbg_readv_mode(pid, iov, count);
}
