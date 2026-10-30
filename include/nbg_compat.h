/* nbg_compat.h — 跨内核版本兼容垫片
 *
 * 用途:封装 5.x ~ 6.x 内核之间发生过 API 变更的几处接口,模块代码统一
 * 调 compat_xxx,具体走哪条分支由本头里的 LINUX_VERSION_CODE 决定。
 *
 * 加新条目时:
 *   1. 给一个独立小节(===== 标题 =====)
 *   2. 标出影响版本边界
 *   3. 让 compat_xxx 在所有版本下语义一致
 */
#ifndef _NBG_COMPAT_H_
#define _NBG_COMPAT_H_

#include <linux/version.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/dcache.h>
#include <linux/compiler.h>

/*
 * Android 12/13 kernels enable Clang CFI for the kernel and modules.  A
 * function pointer obtained from kallsyms is intentionally outside the
 * compiler's whole-program type graph; calls through such pointers must be
 * isolated in a small no-sanitize function instead of disabling CFI globally.
 */
/* Use the kernel's own spelling here.  5.10/5.15 use Clang CFI, while
 * 6.1+ GKI uses KCFI; hard-coding no_sanitize("cfi") leaves the latter
 * instrumented and an indirect call into an assembly cache routine can
 * panic with a CFI type mismatch. */
#ifdef __nocfi
# define NBG_NO_CFI __nocfi
#elif defined(__clang__)
# define NBG_NO_CFI __attribute__((no_sanitize("cfi")))
#else
# define NBG_NO_CFI
#endif

#include "nbg_gki_compat.h"

/* ===== VMA 遍历:6.1 起改用 maple tree iterator ===== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
  #define USE_VMA_ITERATOR 1
#else
  #define USE_VMA_ITERATOR 0
#endif

/* ===== mmap_lock:5.8 引入 mmap_read_lock,旧版用 down_read(&mmap_sem) ===== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  #define compat_mmap_read_lock(mm)      mmap_read_lock(mm)
  #define compat_mmap_read_unlock(mm)    mmap_read_unlock(mm)
  #define compat_mmap_write_lock(mm)     mmap_write_lock(mm)
  #define compat_mmap_write_unlock(mm)   mmap_write_unlock(mm)
#else
  #define compat_mmap_read_lock(mm)      down_read(&(mm)->mmap_sem)
  #define compat_mmap_read_unlock(mm)    up_read(&(mm)->mmap_sem)
  #define compat_mmap_write_lock(mm)     down_write(&(mm)->mmap_sem)
  #define compat_mmap_write_unlock(mm)   up_write(&(mm)->mmap_sem)
#endif

/* ===== kmap:5.11 起 kmap_atomic 被 kmap_local_page 取代 ===== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
  #define compat_kmap_page(p)            kmap_local_page(p)
  #define compat_kunmap_page(addr)       kunmap_local(addr)
#else
  #define compat_kmap_page(p)            kmap_atomic(p)
  #define compat_kunmap_page(addr)       kunmap_atomic(addr)
#endif

/* ===== mmgrab:4.11 之前没有,本地 inline 一份 ===== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
  static inline void mmgrab(struct mm_struct *mm)
  {
      atomic_inc(&mm->mm_count);
  }
#endif

/* ===== refcount_t:4.11 引入,旧内核退化成 atomic_t ===== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
  #include <linux/atomic.h>
  typedef atomic_t refcount_t;
  #define refcount_inc(r)  atomic_inc(r)
  #define refcount_dec(r)  atomic_dec(r)
  #define refcount_read(r) atomic_read(r)
#else
  #include <linux/refcount.h>
#endif

/* ===== sched/task split:5.14 起需显式 include sched/task.h ===== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
  #include <linux/sched/task.h>
#endif

/* ===== filldir 返回类型:6.1 起从 int 改 bool ===== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
  #define FILLDIR_RETURN_TYPE  bool
  #define FILLDIR_CONTINUE     true
#else
  #define FILLDIR_RETURN_TYPE  int
  #define FILLDIR_CONTINUE     0
#endif

/* ===== 其他版本相关常量(留作扩展) ===== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
  #define COMPAT_NEED_PROTO_REGISTER 0
#else
  #define COMPAT_NEED_PROTO_REGISTER 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
  #define COMPAT_PERF_CTX_ARRAY 0
#else
  #define COMPAT_PERF_CTX_ARRAY 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
  #define COMPAT_PTE_OFFSET_CAN_FAIL 1
#else
  #define COMPAT_PTE_OFFSET_CAN_FAIL 0
#endif

/* ===== dentry 子节点链表:6.12 起 d_subdirs/d_child 改为 hlist ===== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
  #define compat_for_each_child_dentry(child, parent) \
      for ((child) = d_first_child(parent); (child); \
           (child) = d_next_sibling(child))
#else
  #define compat_for_each_child_dentry(child, parent) \
      list_for_each_entry((child), &(parent)->d_subdirs, d_child)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
  #define for_each_thread(p, t) \
      for (t = p; (t = next_thread(t)) != p; )
#endif

/* ===== task_call_func:task_call_f 在 6.1 前未定义 =====
 * 6.1+ 在 linux/wait.h 里导出 typedef，更早的内核只有内部调用者。
 * 这里的类型与 6.1 的定义逐字一致，ro_task_call 通过 kallsyms 调用。 */
#ifndef NBG_HAVE_TASK_CALL_F
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
typedef int (*task_call_f)(struct task_struct *p, void *arg);
#endif
#endif

/* ===== *_devmap:6.18 删除 =====
 * 6.18 移除了 pud/pmd/pte_devmap()，device-private 页由 is_device_private_page()
 * 判定。调用点语义不变：返回非零表示不得走普通页表读写路径。 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
  #define compat_pud_devmap(pudval) 0
  #define compat_pmd_devmap(pmdval) 0
  #define compat_pte_devmap(pteval) 0
#else
  #define compat_pud_devmap(pudval) pud_devmap(pudval)
  #define compat_pmd_devmap(pmdval) pmd_devmap(pmdval)
  #define compat_pte_devmap(pteval) pte_devmap(pteval)
#endif

/* ===== MODULE_IMPORT_NS:6.18 起只收字符串字面量 =====
 * 6.17 及以前是 MODULE_IMPORT_NS(ns)，宏内部自己 __stringify；
 * 6.18 改成 MODULE_IMPORT_NS("ns")，裸标识符会报 expected ';'。 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
  #define NBG_MODULE_IMPORT_NS(ns) MODULE_IMPORT_NS(#ns)
#else
  #define NBG_MODULE_IMPORT_NS(ns) MODULE_IMPORT_NS(ns)
#endif

#endif /* _NBG_COMPAT_H_ */
