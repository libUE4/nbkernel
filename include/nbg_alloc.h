/* nbg_alloc.h — allocator ABI shim
 *
 * External modules on Android vendor/GKI mixes can trip over allocator inline
 * CRC drift, especially kmalloc_caches / kmalloc_trace.  Keep allocations on
 * the exported backend entry points and zero/copy locally, so one feature set
 * spans more patch-level kernels inside the same family.
 */
#ifndef _NBG_ALLOC_H_
#define _NBG_ALLOC_H_

#include <linux/gfp.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>

static __always_inline void *nbg_kmalloc(size_t size, gfp_t flags)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    return __kmalloc_noprof(size, flags);
#else
    return __kmalloc(size, flags);
#endif
}

static __always_inline void *nbg_kzalloc(size_t size, gfp_t flags)
{
    void *p;

    p = nbg_kmalloc(size, flags);
    if (p)
        memset(p, 0, size);
    return p;
}

static __always_inline void *nbg_kcalloc(size_t n, size_t size, gfp_t flags)
{
    size_t bytes;

    if (size && n > SIZE_MAX / size)
        return NULL;

    bytes = n * size;
    return nbg_kzalloc(bytes, flags);
}

static __always_inline void *nbg_kmalloc_array(size_t n, size_t size, gfp_t flags)
{
    size_t bytes;

    if (size && n > SIZE_MAX / size)
        return NULL;

    bytes = n * size;
    return nbg_kmalloc(bytes, flags);
}

static __always_inline void *nbg_kmemdup(const void *src, size_t len, gfp_t flags)
{
    void *p;

    if (!src)
        return NULL;

    p = nbg_kmalloc(len, flags);
    if (p)
        memcpy(p, src, len);
    return p;
}

static __always_inline void *nbg_kmemdup_nul(const void *src, size_t len, gfp_t flags)
{
    char *p;

    if (!src || len == SIZE_MAX)
        return NULL;

    p = nbg_kmalloc(len + 1, flags);
    if (p) {
        memcpy(p, src, len);
        p[len] = '\0';
    }
    return p;
}

static __always_inline char *nbg_kstrdup(const char *src, gfp_t flags)
{
    size_t len;
    char *p;

    if (!src)
        return NULL;

    len = strlen(src) + 1;
    p = nbg_kmalloc(len, flags);
    if (p)
        memcpy(p, src, len);
    return p;
}

#endif /* _NBG_ALLOC_H_ */
