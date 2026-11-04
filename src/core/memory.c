/* memory.c — remote process memory access
 *
 * Reads and writes walk the target page tables directly and take a short page
 * reference while copying. The explicit fault-read operation resolves a
 * missing page through the kernel fault-fixup path, then retries the same PTE
 * path. No GUP or long-term page pin is used.
 */
#include "memory.h"
#include "nbg_compat.h"
#include "nbg_ksyms.h"
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/hardirq.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/page_ref.h>
#include <asm/pgtable.h>
#include <asm/memory.h>
#include <asm/processor.h>

#define NBG_MM_CACHE_TTL        (HZ)
#define NBG_READ_STACK_CHUNK    1024U

static DEFINE_MUTEX(nbg_mm_cache_lock);
static struct pid *nbg_cached_pid_ref;
static struct task_struct *nbg_cached_task;
static unsigned long nbg_cached_expires;

typedef int (*nbg_fixup_user_fault_t)(struct mm_struct *mm,
                                      unsigned long address,
                                      unsigned int fault_flags,
                                      bool *unlocked);

static nbg_fixup_user_fault_t nbg_fixup_user_fault_fn;

/* arm64's is_zero_pfn inline imports zero_pfn, which is not in every GKI
 * export list. Keep the exact PFN comparison against the kernel's own value;
 * never accept arbitrary special PTEs or treat the shared zero page writable. */
static unsigned long *nbg_kernel_zero_pfn;

static bool nbg_is_zero_pfn(unsigned long pfn)
{
    return pfn == READ_ONCE(*nbg_kernel_zero_pfn);
}

typedef void (*nbg_flush_icache_range_t)(unsigned long start,
                                         unsigned long end);
static nbg_flush_icache_range_t nbg_flush_icache_range_fn;

/* 5.15+ arm64 keeps flush_icache_range() as a header inline and exports its
 * two implementation pieces instead of the old __flush_icache_range symbol.
 * Resolve both layouts so OP_FLUSH_ICACHE has the same semantics across the
 * supported GKI branches. */
typedef void (*nbg_caches_clean_inval_pou_t)(unsigned long start,
                                             unsigned long end);
typedef void (*nbg_kick_all_cpus_sync_t)(void);
static nbg_caches_clean_inval_pou_t nbg_caches_clean_inval_pou_fn;
static nbg_kick_all_cpus_sync_t nbg_kick_all_cpus_sync_fn;

/* Android GKI enables CONFIG_PAGE_PINNER on multiple branches.  The public
 * put_page()/folio_put() inline path calls page_pinner_put_page(), which
 * creates direct relocations against page_pinner_inited and
 * __page_pinner_* helpers.  Several vendor 5.10/5.15/6.x kernels keep those
 * symbols private, so a module that otherwise matches the ABI fails at insmod
 * with "Unknown symbol page_pinner_inited".
 *
 * The memory code only takes a short, ordinary page reference while holding the
 * target page-table lock; it never uses pin_user_pages/FOLL_PIN.  Drop that
 * ordinary ref with the raw page_ref primitive plus the exported slow release
 * helper.  The PTE walker rejects devmap pages before refs are taken, so this
 * helper is used only for normal RAM pages.
 */
static inline bool nbg_page_ref_try_get(struct page *page)
{
    struct page *head;

    if (!page)
        return false;
    head = compound_head(page);
    return get_page_unless_zero(head) != 0;
}

static inline void nbg_page_ref_put(struct page *page)
{
    struct page *head;

    if (!page)
        return;
    head = compound_head(page);
    if (!page_ref_dec_and_test(head))
        return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    __folio_put(page_folio(head));
#else
    __put_page(head);
#endif
}

NBG_NO_CFI
static int nbg_call_fixup_user_fault(struct mm_struct *mm,
                                     unsigned long address,
                                     unsigned int flags, bool *unlocked)
{
    nbg_fixup_user_fault_t fn = READ_ONCE(nbg_fixup_user_fault_fn);

    if (!fn)
        return -ENOSYS;
    return fn(mm, address, flags, unlocked);
}

NBG_NO_CFI
static bool nbg_call_flush_icache_range(unsigned long start,
                                        unsigned long end)
{
    nbg_flush_icache_range_t old_fn = READ_ONCE(nbg_flush_icache_range_fn);
    nbg_caches_clean_inval_pou_t clean_fn =
        READ_ONCE(nbg_caches_clean_inval_pou_fn);
    nbg_kick_all_cpus_sync_t kick_fn = READ_ONCE(nbg_kick_all_cpus_sync_fn);

    if (old_fn) {
        old_fn(start, end);
        return true;
    }
    if (!clean_fn || !kick_fn)
        return false;
    clean_fn(start, end);
    kick_fn();
    return true;
}

int nbg_memory_init(void)
{
    unsigned long addr;

    nbg_kernel_zero_pfn =
        (unsigned long *)generic_kallsyms_lookup_name("zero_pfn");
    if (!nbg_kernel_zero_pfn)
        return -ENOENT;

    addr = generic_kallsyms_lookup_name("fixup_user_fault");
    if (!addr)
        return -ENOENT;

    WRITE_ONCE(nbg_fixup_user_fault_fn, (nbg_fixup_user_fault_t)addr);
    /* Optional on older kernels: keep module loading independent of this
     * helper while enabling reliable remote text patches where available. */
    addr = generic_kallsyms_lookup_name("__flush_icache_range");
    if (!addr)
        addr = generic_kallsyms_lookup_name("flush_icache_range");
    WRITE_ONCE(nbg_flush_icache_range_fn,
               (nbg_flush_icache_range_t)addr);
    if (!addr) {
        WRITE_ONCE(nbg_caches_clean_inval_pou_fn,
                   (nbg_caches_clean_inval_pou_t)
                       generic_kallsyms_lookup_name("caches_clean_inval_pou"));
        WRITE_ONCE(nbg_kick_all_cpus_sync_fn,
                   (nbg_kick_all_cpus_sync_t)
                       generic_kallsyms_lookup_name("kick_all_cpus_sync"));
    }
    return 0;
}

static void nbg_target_cache_drop_locked(void)
{
    struct task_struct *task;
    struct pid *pid_ref;

    task = nbg_cached_task;
    pid_ref = nbg_cached_pid_ref;

    nbg_cached_pid_ref = NULL;
    nbg_cached_task = NULL;
    nbg_cached_expires = 0;

    if (task)
        put_task_struct(task);
    if (pid_ref)
        put_pid(pid_ref);
}

static unsigned long nbg_remote_task_size_limit(void)
{
#ifdef TASK_SIZE_MAX
    return TASK_SIZE_MAX;
#elif defined(TASK_SIZE_64)
    return TASK_SIZE_64;
#else
    return TASK_SIZE;
#endif
}

static int nbg_normalize_remote_range(uintptr_t remote_addr, size_t size,
                                      unsigned long *start_out)
{
    unsigned long start;
    unsigned long limit;

    if (!remote_addr || !size)
        return -EINVAL;

    start = untagged_addr((unsigned long)remote_addr);
    limit = nbg_remote_task_size_limit();
    if (!start || start >= limit || size > limit - start)
        return -EINVAL;

    if (start_out)
        *start_out = start;
    return 0;
}

static int nbg_validate_user_range(uintptr_t user_addr, size_t size)
{
    unsigned long start;

    if (!user_addr || !size)
        return -EINVAL;

    start = (unsigned long)user_addr;
    if (size - 1 > ULONG_MAX - start)
        return -EINVAL;
    if (!access_ok((void __user *)start, size))
        return -EFAULT;
    return 0;
}

static int get_target_mm_cached(pid_t pid_nr, struct mm_struct **out)
{
    struct pid *pid_ref;
    struct task_struct *task;
    struct mm_struct *mm;
    bool alive;

    if (!out || pid_nr <= 0)
        return -EINVAL;
    *out = NULL;

    if (in_atomic() || irqs_disabled())
        return -EBUSY;

    pid_ref = find_get_pid(pid_nr);
    if (!pid_ref)
        return -ESRCH;

    mutex_lock(&nbg_mm_cache_lock);

    if (nbg_cached_pid_ref == pid_ref && nbg_cached_task) {
        alive = pid_alive(nbg_cached_task) &&
                !(READ_ONCE(nbg_cached_task->flags) & PF_EXITING);
        if (alive && time_before(jiffies, nbg_cached_expires)) {
            mm = get_task_mm(nbg_cached_task);
            if (mm) {
                nbg_cached_expires = jiffies + NBG_MM_CACHE_TTL;
                *out = mm;
                mutex_unlock(&nbg_mm_cache_lock);
                put_pid(pid_ref);
                return 0;
            }
        }
        nbg_target_cache_drop_locked();
    } else if (nbg_cached_pid_ref) {
        nbg_target_cache_drop_locked();
    }

    task = get_pid_task(pid_ref, PIDTYPE_PID);
    if (!task) {
        mutex_unlock(&nbg_mm_cache_lock);
        put_pid(pid_ref);
        return -ESRCH;
    }

    if (READ_ONCE(task->flags) & PF_EXITING) {
        mutex_unlock(&nbg_mm_cache_lock);
        put_task_struct(task);
        put_pid(pid_ref);
        return -ESRCH;
    }

    mm = get_task_mm(task);
    if (!mm) {
        mutex_unlock(&nbg_mm_cache_lock);
        put_task_struct(task);
        put_pid(pid_ref);
        return -ESRCH;
    }

    nbg_cached_pid_ref = pid_ref;
    nbg_cached_task = task;
    nbg_cached_expires = jiffies + NBG_MM_CACHE_TTL;
    *out = mm;

    mutex_unlock(&nbg_mm_cache_lock);
    return 0;
}

void nbg_memory_cache_cleanup(void)
{
    mutex_lock(&nbg_mm_cache_lock);
    nbg_target_cache_drop_locked();
    mutex_unlock(&nbg_mm_cache_lock);
}

/* Caller holds mm->mmap_lock for reading. The page-table entry is protected
 * while a transient page reference is acquired, so migration/unmap cannot
 * leave the copy path using a recycled PFN. This is a direct PTE lookup and
 * never faults a missing page in. */
static int nbg_pte_get_present_page_locked(struct mm_struct *mm,
                                           unsigned long addr,
                                           struct page **page_out,
                                           bool allow_zero_page)
{
    struct vm_area_struct *vma;
    struct page *page;
    spinlock_t *ptl;
    unsigned long pfn;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;
    pgd_t pgdval;
    p4d_t p4dval;
    pud_t pudval;
    pmd_t pmdval;
    pte_t pteval;

    if (!mm || !page_out)
        return -EINVAL;
    *page_out = NULL;

    vma = find_vma(mm, addr);
    if (!vma || addr < vma->vm_start)
        return -EFAULT;

    pgd = pgd_offset(mm, addr);
    pgdval = READ_ONCE(*pgd);
    if (pgd_none(pgdval) || pgd_bad(pgdval))
        return -EFAULT;

    p4d = p4d_offset(pgd, addr);
    p4dval = READ_ONCE(*p4d);
    if (p4d_none(p4dval) || p4d_bad(p4dval))
        return -EFAULT;

    pud = pud_offset(p4d, addr);
    pudval = READ_ONCE(*pud);
    if (pud_none(pudval))
        return -EFAULT;
    if (pud_leaf(pudval)) {
        ptl = pud_lock(mm, pud);
        pudval = READ_ONCE(*pud);
        if (!pud_leaf(pudval) || !pud_present(pudval) || compat_pud_devmap(pudval)) {
            spin_unlock(ptl);
            return -EAGAIN;
        }

        pfn = pud_pfn(pudval) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
        if (!pfn_valid(pfn)) {
            spin_unlock(ptl);
            return -EFAULT;
        }
        page = pfn_to_page(pfn);
        if (!nbg_page_ref_try_get(page)) {
            spin_unlock(ptl);
            return -EAGAIN;
        }
        spin_unlock(ptl);
        *page_out = page;
        return 0;
    }
    if (pud_bad(pudval))
        return -EFAULT;

    pmd = pmd_offset(pud, addr);
    pmdval = READ_ONCE(*pmd);
    if (pmd_none(pmdval))
        return -EFAULT;
    if (pmd_leaf(pmdval)) {
        ptl = pmd_lock(mm, pmd);
        pmdval = READ_ONCE(*pmd);
        if (!pmd_leaf(pmdval) || !pmd_present(pmdval) || compat_pmd_devmap(pmdval)) {
            spin_unlock(ptl);
            return -EAGAIN;
        }

        pfn = pmd_pfn(pmdval) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
        if (!pfn_valid(pfn)) {
            spin_unlock(ptl);
            return -EFAULT;
        }
        page = pfn_to_page(pfn);
        if (!nbg_page_ref_try_get(page)) {
            spin_unlock(ptl);
            return -EAGAIN;
        }
        spin_unlock(ptl);
        *page_out = page;
        return 0;
    }
    if (pmd_bad(pmdval))
        return -EFAULT;

    ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
    if (!ptep)
        return -EAGAIN;

    pteval = READ_ONCE(*ptep);
    if (!pte_present(pteval) || compat_pte_devmap(pteval)) {
        pte_unmap_unlock(ptep, ptl);
        return -EFAULT;
    }

    pfn = pte_pfn(pteval);
    if (pte_special(pteval) && (!allow_zero_page || !nbg_is_zero_pfn(pfn))) {
        pte_unmap_unlock(ptep, ptl);
        return -EFAULT;
    }
    if (!pfn_valid(pfn)) {
        pte_unmap_unlock(ptep, ptl);
        return -EFAULT;
    }
    page = pfn_to_page(pfn);
    if (!nbg_page_ref_try_get(page)) {
        pte_unmap_unlock(ptep, ptl);
        return -EAGAIN;
    }

    pte_unmap_unlock(ptep, ptl);
    *page_out = page;
    return 0;
}

static int nbg_remote_read_kernel_pte_mm(struct mm_struct *mm,
                                         unsigned long remote_start,
                                         void *buffer, size_t size,
                                         size_t *nbytes)
{
    unsigned long current_addr;
    size_t remaining;
    size_t done;
    u8 *out;
    int ret;

    if (nbytes)
        *nbytes = 0;
    if (!mm || !buffer || !size)
        return -EINVAL;

    current_addr = remote_start;
    remaining = size;
    done = 0;
    out = buffer;
    ret = 0;

    compat_mmap_read_lock(mm);
    while (remaining) {
        struct page *page;
        size_t offset;
        size_t chunk;
        void *mapped;

        ret = nbg_pte_get_present_page_locked(mm, current_addr, &page, true);
        if (ret)
            break;

        offset = current_addr & ~PAGE_MASK;
        chunk = min_t(size_t, remaining, PAGE_SIZE - offset);
        mapped = compat_kmap_page(page);
        memcpy(out + done, (u8 *)mapped + offset, chunk);
        compat_kunmap_page(mapped);
        nbg_page_ref_put(page);

        current_addr += chunk;
        remaining -= chunk;
        done += chunk;
        if (!(done & ((16U * PAGE_SIZE) - 1U)))
            cond_resched();
    }
    compat_mmap_read_unlock(mm);

    if (nbytes)
        *nbytes = done;
    if (ret)
        return ret;
    return done == size ? 0 : -EFAULT;
}

/* mmap_lock is held for read on entry and remains held on every return. */
static int nbg_fault_in_remote_page_locked(struct mm_struct *mm,
                                           unsigned long address)
{
    unsigned int fault_flags = 0;
    bool unlocked = false;

    if (mm != current->mm)
        fault_flags |= FAULT_FLAG_REMOTE;
    return nbg_call_fixup_user_fault(mm, address, fault_flags, &unlocked);
}

static int nbg_remote_read_kernel_fault_mm(struct mm_struct *mm,
                                           unsigned long remote_start,
                                           void *buffer, size_t size,
                                           size_t *nbytes)
{
    unsigned long current_addr;
    size_t remaining;
    size_t done;
    u8 *out;
    int ret;

    if (nbytes)
        *nbytes = 0;
    if (!mm || !buffer || !size)
        return -EINVAL;

    current_addr = remote_start;
    remaining = size;
    done = 0;
    out = buffer;
    ret = 0;

    compat_mmap_read_lock(mm);
    while (remaining) {
        struct page *page;
        size_t offset;
        size_t chunk;
        void *mapped;
        unsigned int pte_retries;
        bool fault_attempted;

        pte_retries = 0;
        fault_attempted = false;
retry_pte:
        ret = nbg_pte_get_present_page_locked(mm, current_addr, &page, true);
        if (ret == -EAGAIN && pte_retries++ < 2) {
            cond_resched();
            goto retry_pte;
        }
        if (ret == -EFAULT && !fault_attempted) {
            fault_attempted = true;
            ret = nbg_fault_in_remote_page_locked(mm, current_addr);
            if (!ret)
                goto retry_pte;
        }
        if (ret)
            break;

        offset = current_addr & ~PAGE_MASK;
        chunk = min_t(size_t, remaining, PAGE_SIZE - offset);
        mapped = compat_kmap_page(page);
        memcpy(out + done, (u8 *)mapped + offset, chunk);
        compat_kunmap_page(mapped);
        nbg_page_ref_put(page);

        current_addr += chunk;
        remaining -= chunk;
        done += chunk;
        if (!(done & ((16U * PAGE_SIZE) - 1U)))
            cond_resched();
    }
    compat_mmap_read_unlock(mm);

    if (nbytes)
        *nbytes = done;
    if (ret)
        return ret;
    return done == size ? 0 : -EFAULT;
}

static int nbg_remote_read_user_pte_mm(struct mm_struct *mm,
                                       unsigned long remote_start,
                                       uintptr_t user_addr, size_t size,
                                       size_t *nbytes)
{
    unsigned long current_addr;
    uintptr_t current_user;
    size_t remaining;
    size_t done;
    u8 tmp[NBG_READ_STACK_CHUNK];
    int ret;

    if (nbytes)
        *nbytes = 0;
    ret = nbg_validate_user_range(user_addr, size);
    if (ret)
        return ret;

    current_addr = remote_start;
    current_user = user_addr;
    remaining = size;
    done = 0;
    ret = 0;

    while (remaining) {
        size_t want;
        size_t got;

        want = min_t(size_t, remaining, sizeof(tmp));
        got = 0;
        ret = nbg_remote_read_kernel_pte_mm(mm, current_addr, tmp, want,
                                            &got);
        if (got && copy_to_user((void __user *)current_user, tmp, got)) {
            ret = -EFAULT;
            break;
        }

        current_addr += got;
        current_user += got;
        remaining -= got;
        done += got;
        if (ret || got != want)
            break;
    }

    if (nbytes)
        *nbytes = done;
    if (ret)
        return ret;
    return done == size ? 0 : -EFAULT;
}

static int nbg_remote_read_user_fault_mm(struct mm_struct *mm,
                                         unsigned long remote_start,
                                         uintptr_t user_addr, size_t size,
                                         size_t *nbytes)
{
    unsigned long current_addr;
    uintptr_t current_user;
    size_t remaining;
    size_t done;
    u8 tmp[NBG_READ_STACK_CHUNK];
    int ret;

    if (nbytes)
        *nbytes = 0;
    ret = nbg_validate_user_range(user_addr, size);
    if (ret)
        return ret;

    current_addr = remote_start;
    current_user = user_addr;
    remaining = size;
    done = 0;
    ret = 0;

    while (remaining) {
        size_t want;
        size_t got;

        want = min_t(size_t, remaining, sizeof(tmp));
        got = 0;
        ret = nbg_remote_read_kernel_fault_mm(mm, current_addr, tmp, want,
                                              &got);
        if (got && copy_to_user((void __user *)current_user, tmp, got)) {
            ret = -EFAULT;
            break;
        }

        current_addr += got;
        current_user += got;
        remaining -= got;
        done += got;
        if (ret || got != want)
            break;
    }

    if (nbytes)
        *nbytes = done;
    if (ret)
        return ret;
    return done == size ? 0 : -EFAULT;
}

static int nbg_remote_write_kernel_pte_mm(struct mm_struct *mm,
                                          unsigned long remote_start,
                                          const void *buffer, size_t size,
                                          size_t *nbytes)
{
    unsigned long current_addr;
    size_t remaining;
    size_t done;
    const u8 *in;
    int ret;

    if (nbytes)
        *nbytes = 0;
    if (!mm || !buffer || !size)
        return -EINVAL;

    current_addr = remote_start;
    remaining = size;
    done = 0;
    in = buffer;
    ret = 0;

    compat_mmap_read_lock(mm);
    while (remaining) {
        struct page *page;
        size_t offset;
        size_t chunk;
        void *mapped;

        ret = nbg_pte_get_present_page_locked(mm, current_addr, &page, false);
        if (ret)
            break;

        offset = current_addr & ~PAGE_MASK;
        chunk = min_t(size_t, remaining, PAGE_SIZE - offset);
        mapped = compat_kmap_page(page);
        memcpy((u8 *)mapped + offset, in + done, chunk);
        compat_kunmap_page(mapped);
        flush_dcache_page(page);
        set_page_dirty_lock(page);
        nbg_page_ref_put(page);

        current_addr += chunk;
        remaining -= chunk;
        done += chunk;
        if (!(done & ((16U * PAGE_SIZE) - 1U)))
            cond_resched();
    }
    compat_mmap_read_unlock(mm);

    if (nbytes)
        *nbytes = done;
    if (ret)
        return ret;
    return done == size ? 0 : -EFAULT;
}

bool read_process_memory_mm(struct mm_struct *mm, uintptr_t addr,
                            void *buffer, size_t size)
{
    unsigned long remote_start;
    size_t done;
    int ret;

    if (!mm || !buffer || !size || size > NBG_MAX_RW_SIZE)
        return false;
    if (in_atomic() || irqs_disabled())
        return false;

    ret = nbg_normalize_remote_range(addr, size, &remote_start);
    if (ret)
        return false;

    ret = nbg_remote_read_kernel_pte_mm(mm, remote_start, buffer, size,
                                        &done);
    return ret == 0 && done == size;
}

bool read_process_memory_kernel(pid_t pid, uintptr_t addr,
                                void *buffer, size_t size)
{
    struct mm_struct *mm;
    unsigned long remote_start;
    size_t done;
    int ret;

    if (!buffer || !size || size > NBG_MAX_RW_SIZE)
        return false;
    if (in_atomic() || irqs_disabled())
        return false;

    ret = nbg_normalize_remote_range(addr, size, &remote_start);
    if (ret)
        return false;

    ret = get_target_mm_cached(pid, &mm);
    if (ret)
        return false;

    ret = nbg_remote_read_kernel_pte_mm(mm, remote_start, buffer, size,
                                        &done);
    mmput(mm);
    return ret == 0 && done == size;
}

bool write_process_memory_kernel(pid_t pid, uintptr_t addr,
                                 const void *buffer, size_t size)
{
    struct mm_struct *mm;
    unsigned long remote_start;
    size_t done;
    int ret;

    if (!buffer || !size || size > NBG_MAX_RW_SIZE)
        return false;
    if (in_atomic() || irqs_disabled())
        return false;

    ret = nbg_normalize_remote_range(addr, size, &remote_start);
    if (ret)
        return false;

    ret = get_target_mm_cached(pid, &mm);
    if (ret)
        return false;

    ret = nbg_remote_write_kernel_pte_mm(mm, remote_start, buffer, size,
                                         &done);
    mmput(mm);
    return ret == 0 && done == size;
}

static int rw_process_memory_user(pid_t pid, uintptr_t remote_addr,
                                  uintptr_t user_addr, size_t size,
                                  size_t *nbytes, bool write_remote)
{
    struct mm_struct *mm;
    void *kbuf;
    unsigned long remote_start;
    size_t done;
    int ret;

    if (nbytes)
        *nbytes = 0;
    if (pid <= 0 || !remote_addr || !user_addr || !size)
        return -EINVAL;
    if (size > NBG_MAX_RW_SIZE)
        return -EMSGSIZE;
    ret = nbg_normalize_remote_range(remote_addr, size, &remote_start);
    if (ret)
        return ret;
    ret = nbg_validate_user_range(user_addr, size);
    if (ret)
        return ret;
    if (in_atomic() || irqs_disabled())
        return -EBUSY;

    kbuf = kvmalloc(size, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (write_remote && copy_from_user(kbuf, (void __user *)user_addr, size)) {
        kvfree(kbuf);
        return -EFAULT;
    }

    ret = get_target_mm_cached(pid, &mm);
    if (ret) {
        kvfree(kbuf);
        return ret;
    }

    done = 0;
    if (write_remote) {
        ret = nbg_remote_write_kernel_pte_mm(mm, remote_start, kbuf, size,
                                             &done);
    } else {
        ret = nbg_remote_read_kernel_pte_mm(mm, remote_start, kbuf, size,
                                            &done);
    }
    mmput(mm);

    if (!write_remote && ret == 0 && copy_to_user((void __user *)user_addr,
                                                  kbuf, size)) {
        done = 0;
        ret = -EFAULT;
    }

    kvfree(kbuf);
    if (nbytes)
        *nbytes = done;
    return ret;
}

static int read_process_memory_user_fast(pid_t pid, uintptr_t remote_addr,
                                         uintptr_t user_addr, size_t size,
                                         size_t *nbytes)
{
    struct mm_struct *mm;
    unsigned long remote_start;
    size_t done;
    int ret;

    if (nbytes)
        *nbytes = 0;
    if (pid <= 0 || !remote_addr || !user_addr || !size)
        return -EINVAL;
    if (size > NBG_MAX_RW_SIZE)
        return -EMSGSIZE;
    ret = nbg_normalize_remote_range(remote_addr, size, &remote_start);
    if (ret)
        return ret;
    ret = nbg_validate_user_range(user_addr, size);
    if (ret)
        return ret;
    if (in_atomic() || irqs_disabled())
        return -EBUSY;

    ret = get_target_mm_cached(pid, &mm);
    if (ret)
        return ret;

    if (mm == current->mm) {
        mmput(mm);
        return rw_process_memory_user(pid, remote_addr, user_addr, size,
                                      nbytes, false);
    }

    done = 0;
    ret = nbg_remote_read_user_pte_mm(mm, remote_start, user_addr, size,
                                      &done);
    mmput(mm);

    if (nbytes)
        *nbytes = done;
    return ret;
}

static int read_process_memory_user_fault(pid_t pid, uintptr_t remote_addr,
                                          uintptr_t user_addr, size_t size,
                                          size_t *nbytes)
{
    struct mm_struct *mm;
    unsigned long remote_start;
    size_t done;
    int ret;

    if (nbytes)
        *nbytes = 0;
    if (pid <= 0 || !remote_addr || !user_addr || !size)
        return -EINVAL;
    if (size > NBG_MAX_RW_SIZE)
        return -EMSGSIZE;
    ret = nbg_normalize_remote_range(remote_addr, size, &remote_start);
    if (ret)
        return ret;
    ret = nbg_validate_user_range(user_addr, size);
    if (ret)
        return ret;
    if (in_atomic() || irqs_disabled())
        return -EBUSY;

    ret = get_target_mm_cached(pid, &mm);
    if (ret)
        return ret;

    done = 0;
    ret = nbg_remote_read_user_fault_mm(mm, remote_start, user_addr, size,
                                        &done);
    mmput(mm);

    if (nbytes)
        *nbytes = done;
    return ret;
}

int nbg_read_memory(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                    size_t size, size_t *nbytes)
{
    return read_process_memory_user_fast(pid, remote_addr, user_addr,
                                         size, nbytes);
}

int nbg_read_memory_fault(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                          size_t size, size_t *nbytes)
{
    return read_process_memory_user_fault(pid, remote_addr, user_addr,
                                          size, nbytes);
}

int nbg_write_memory(pid_t pid, uintptr_t remote_addr, uintptr_t user_addr,
                     size_t size, size_t *nbytes)
{
    return rw_process_memory_user(pid, remote_addr, user_addr, size,
                                  nbytes, true);
}

int nbg_flush_icache(pid_t pid, uintptr_t remote_addr, size_t size)
{
    unsigned long start;
    unsigned long end;
    int ret;
    if (pid <= 0 || !size || size > NBG_MAX_RW_SIZE)
        return -ENOSYS;
    ret = nbg_normalize_remote_range(remote_addr, size, &start);
    if (ret)
        return ret;
    end = start + size;
    if (end < start)
        return -EINVAL;
    return nbg_call_flush_icache_range(start, end) ? 0 : -ENOSYS;
}

static int nbg_readv_memory_mode(pid_t pid, READV_ENTRY __user *iov,
                                 uint32_t count, bool fault_in)
{
    READV_ENTRY *entries;
    struct mm_struct *mm;
    uint32_t i;
    bool need_mm;
    bool same_mm;
    bool interrupted;
    int ret;

    if (!iov || !count || count > NBG_IOV_MAX)
        return -EINVAL;
    if (in_atomic() || irqs_disabled())
        return -EBUSY;

    entries = kvmalloc(count * sizeof(*entries), GFP_KERNEL);
    if (!entries)
        return -ENOMEM;

    if (copy_from_user(entries, iov, count * sizeof(*entries))) {
        kvfree(entries);
        return -EFAULT;
    }

    need_mm = false;
    for (i = 0; i < count; i++) {
        entries[i].status = 0;
        if (!entries[i].size) {
            continue;
        } else if (!entries[i].addr || !entries[i].buffer) {
            entries[i].status = -EINVAL;
        } else if (entries[i].size > NBG_MAX_RW_SIZE) {
            entries[i].status = -EMSGSIZE;
        } else if (nbg_normalize_remote_range(entries[i].addr,
                                              entries[i].size, NULL)) {
            entries[i].status = -EINVAL;
        } else if (nbg_validate_user_range((uintptr_t)entries[i].buffer,
                                           entries[i].size)) {
            entries[i].status = -EFAULT;
        } else {
            need_mm = true;
        }
    }

    mm = NULL;
    same_mm = false;
    interrupted = false;
    if (need_mm) {
        ret = get_target_mm_cached(pid, &mm);
        if (ret) {
            for (i = 0; i < count; i++) {
                if (entries[i].size && entries[i].status == 0)
                    entries[i].status = ret;
            }
            goto copy_back;
        }
        same_mm = (mm == current->mm);

        for (i = 0; i < count; i++) {
            unsigned long remote_start;
            size_t done;

            if (!entries[i].size || entries[i].status)
                continue;

            ret = nbg_normalize_remote_range(entries[i].addr,
                                             entries[i].size, &remote_start);
            if (ret) {
                entries[i].status = ret;
                continue;
            }

            if (same_mm) {
                void *bounce;

                bounce = kvmalloc(entries[i].size, GFP_KERNEL);
                if (!bounce) {
                    entries[i].status = -ENOMEM;
                    continue;
                }
                done = 0;
                entries[i].status = fault_in
                    ? nbg_remote_read_kernel_fault_mm(mm, remote_start, bounce,
                                                      entries[i].size, &done)
                    : nbg_remote_read_kernel_pte_mm(mm, remote_start, bounce,
                                                    entries[i].size, &done);
                if (entries[i].status == 0 &&
                    copy_to_user(entries[i].buffer, bounce, entries[i].size))
                    entries[i].status = -EFAULT;
                kvfree(bounce);
            } else {
                done = 0;
                entries[i].status = fault_in
                    ? nbg_remote_read_user_fault_mm(mm, remote_start,
                                                    (uintptr_t)entries[i].buffer,
                                                    entries[i].size, &done)
                    : nbg_remote_read_user_pte_mm(mm, remote_start,
                                                  (uintptr_t)entries[i].buffer,
                                                  entries[i].size, &done);
            }

            cond_resched();
            if (fatal_signal_pending(current)) {
                interrupted = true;
                break;
            }
        }

        if (interrupted) {
            for (i++; i < count; i++) {
                if (entries[i].size && entries[i].status == 0)
                    entries[i].status = -EINTR;
            }
        }
    }

copy_back:
    if (copy_to_user(iov, entries, count * sizeof(*entries))) {
        if (mm)
            mmput(mm);
        kvfree(entries);
        return -EFAULT;
    }

    if (mm)
        mmput(mm);
    kvfree(entries);
    return 0;
}

int nbg_readv_memory(pid_t pid, READV_ENTRY __user *iov, uint32_t count)
{
    return nbg_readv_memory_mode(pid, iov, count, false);
}

int nbg_readv_memory_fault(pid_t pid, READV_ENTRY __user *iov, uint32_t count)
{
    return nbg_readv_memory_mode(pid, iov, count, true);
}

/* ---- 可复用的 mm 上下文（供查询接口使用） ---- */

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
    unsigned long remote_start;
    size_t done;
    int ret;

    if (!ctx || !ctx->mm || !buf)
        return -EINVAL;
    if (size == 0 || size > NBG_MAX_RW_SIZE)
        return -EINVAL;

    ret = nbg_normalize_remote_range((uintptr_t)addr, size, &remote_start);
    if (ret)
        return ret;

    done = 0;
    ret = nbg_remote_read_kernel_pte_mm(ctx->mm, remote_start, buf, size,
                                        &done);
    if (ret)
        return ret;
    return done == size ? 0 : -EFAULT;
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
