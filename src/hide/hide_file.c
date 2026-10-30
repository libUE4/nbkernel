/* hide_file.c — 任意路径文件 / 目录隐藏
 *
 * 工作方式:替换某个父目录 inode 的 fop->iterate_shared(影响 ls)和
 * iop->lookup(影响 open/stat/cd/...),被隐藏的 basename 在两条路径
 * 都被截掉。
 *
 *   hooked_dir         一个被钩的目录,内含 hidden_names 列表 + refcnt
 *   hooked_dirs        所有 hooked_dir 的全局链表
 *
 * 卸载安全:
 *   - SRCU 保护已进入 generic_filter_iterate_shared / hooked_lookup 的
 *     reader；
 *   - cloned fops 的 owner 指向 THIS_MODULE，已经打开但尚未 iterate 的
 *     file descriptor 会阻止 rmmod；
 *   - 运行期 unhide 后，hd 留在 retired 链表，直到真正 module_exit 再
 *     释放，因此 file->f_op 不会指向已释放的 new_fops。
 */
#include "hide_file.h"
#include "devpts_filter.h"
#include "hide_internal.h"
#include "nbg_compat.h"
#include "nbg_log.h"
#include "nbg_target.h"

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include "nbg_alloc.h"
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/srcu.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/uidgid.h>

#define HIDDEN_NAME_APP_ONLY 0x1U
#define HIDDEN_NAME_PREFIX   0x2U
#define HIDDEN_NAME_DEVPTS   0x4U

struct hidden_name {
    char name[256];
    unsigned int flags;
    struct dentry *target_dentry;
    struct list_head list;
};

struct hooked_dir {
    struct dentry *dentry;
    const struct file_operations  *orig_fops;
    struct file_operations        new_fops;
    const struct inode_operations *orig_iops;
    struct inode_operations       new_iops;
    struct list_head hidden_names;
    struct list_head hook_list;
    int refcnt;
};

static LIST_HEAD(hooked_dirs);
static LIST_HEAD(retired_hooked_dirs);
static DEFINE_SPINLOCK(hooked_dirs_lock);

/* SRCU covers readers already inside our hooks. fops->owner covers files
 * opened before a runtime unhide and retired_hooked_dirs keeps their cloned
 * fops storage alive until module_exit. DEFINE_STATIC_SRCU is already static. */
DEFINE_STATIC_SRCU(hidden_file_srcu);

struct filter_ctx {
    struct dir_context ctx;
    struct dir_context *orig_ctx;
    struct hooked_dir *hd;
};

static int generic_filter_iterate_shared(struct file *file, struct dir_context *ctx);

/* ========== 辅助 ========== */

static void restore_hooked_dir_ops(struct hooked_dir *hd)
{
    struct inode *inode;

    if (!hd || !hd->dentry || !hd->dentry->d_inode)
        return;

    inode = hd->dentry->d_inode;
    inode_lock(inode);
    if (inode->i_fop == &hd->new_fops)
        rcu_assign_pointer(inode->i_fop, hd->orig_fops);
    if (inode->i_op == &hd->new_iops)
        WRITE_ONCE(inode->i_op, hd->orig_iops);
    inode_unlock(inode);
}

/* SRCU covers in-flight callbacks; cloned fops are retained until module exit
 * so an already-open directory descriptor never points at freed memory. */

static void free_hidden_names(struct hooked_dir *hd)
{
    struct hidden_name *hn, *tmp;
    list_for_each_entry_safe(hn, tmp, &hd->hidden_names, list) {
        list_del(&hn->list);
        if (hn->target_dentry) {
            if (d_is_positive(hn->target_dentry))
                nbg_dcache_rehash(hn->target_dentry);
            dput(hn->target_dentry);
            hn->target_dentry = NULL;
        }
        kfree(hn);
    }
}

static void free_hooked_dir(struct hooked_dir *hd)
{
    free_hidden_names(hd);
    if (hd->dentry)
        dput(hd->dentry);
    kfree(hd);
}

/* Once i_op/i_fop are restored, an old open directory can still carry
 * &hd->new_fops in struct file. Keep hd allocated until module_exit; its
 * fops owner pins this module while any such file exists. */
static void retire_hooked_dir(struct hooked_dir *hd)
{
    unsigned long flags;

    if (!hd)
        return;

    spin_lock_irqsave(&hooked_dirs_lock, flags);
    list_add_tail(&hd->hook_list, &retired_hooked_dirs);
    spin_unlock_irqrestore(&hooked_dirs_lock, flags);
}

static void normalize_path(char *path)
{
    size_t len = strlen(path);
    while (len > 1 && path[len-1] == '/') {
        path[len-1] = '\0';
        len--;
    }
}

static bool hidden_name_applies(const struct hidden_name *hn)
{
    if (!hn)
        return false;
    if (!(hn->flags & HIDDEN_NAME_APP_ONLY))
        return true;

    /* App-only entries must not alter the view of unrelated user apps. */
    return nbg_target_current_is_game();
}

static bool hidden_name_matches(const struct hidden_name *hn,
                                const char *name, int namlen)
{
    size_t nlen;

    if (!hn || !name || namlen < 0)
        return false;
    nlen = strlen(hn->name);
    if (hn->flags & HIDDEN_NAME_PREFIX)
        return (size_t)namlen >= nlen &&
               strncmp(hn->name, name, nlen) == 0;
    return nlen == (size_t)namlen &&
           strncmp(hn->name, name, (size_t)namlen) == 0;
}

static bool hidden_path_should_prefix(const char *parent,
                                      const char *basename)
{
    if (!parent || !basename)
        return false;

    if (strcmp(parent, "/sys/module") == 0 &&
        (strcmp(basename, "module_") == 0 ||
         strcmp(basename, "!") == 0))
        return true;

    if (strcmp(parent, "/sdcard") == 0 &&
        strcmp(basename, "52_") == 0)
        return true;

    return false;
}

/* ========== filldir 过滤 + lookup hook ========== */

NBG_NO_CFI
static FILLDIR_RETURN_TYPE filter_filldir(struct dir_context *ctx, const char *name, int namlen,
                           loff_t offset, u64 ino, unsigned int d_type)
{
    struct filter_ctx *fctx = container_of(ctx, struct filter_ctx, ctx);
    struct hooked_dir *hd = fctx->hd;
    struct hidden_name *hn;
    bool hidden = false;
    bool devpts_hit = false;
    unsigned long flags;

    if (!hd)
        return fctx->orig_ctx->actor(fctx->orig_ctx, name, namlen, offset, ino, d_type);

    /* 走真锁(F-2 修复):trylock fallback 会让攻击者通过持续 hide_file/
     * unhide_file 制造竞争,在窗口期看到本应隐藏的文件。filter_filldir
     * 在 SRCU read-side 内,hooked_dirs_lock 仅保护 hidden_names 链表
     * 这条本地数据,持锁时间极短(strcmp 一遍)。 */
    spin_lock_irqsave(&hooked_dirs_lock, flags);
    list_for_each_entry(hn, &hd->hidden_names, list) {
                if (hidden_name_matches(hn, name, namlen)) {
                    hidden = hidden_name_applies(hn);
                    devpts_hit = hidden &&
                                 (hn->flags & HIDDEN_NAME_DEVPTS);
                    break;
                }
    }
    spin_unlock_irqrestore(&hooked_dirs_lock, flags);

    if (hidden) {
        if (devpts_hit)
            devpts_filter_note_getattr_hit();
        return FILLDIR_CONTINUE;
    }
    return fctx->orig_ctx->actor(fctx->orig_ctx, name, namlen, offset, ino, d_type);
}

/* hooked_lookup — 拦截 open/stat/cd 等所有路径解析。
 * 直接返回 NULL 等于"该路径不存在",避免命中真实 dentry。
 *
 * SRCU 保护:整个体在 srcu_read_lock 内执行,release 路径
 * synchronize_srcu 会等到所有 in-flight lookup 返回才 free hd。 */
NBG_NO_CFI
static struct dentry *hooked_lookup(struct inode *dir, struct dentry *dentry,
                                     unsigned int flags)
{
    struct hooked_dir *hd;
    struct hidden_name *hn;
    unsigned long irqflags;
    struct dentry *(*orig_lookup)(struct inode *, struct dentry *, unsigned int) = NULL;
    bool hidden = false;
    bool devpts_hit = false;
    int srcu_idx;
    struct dentry *result = NULL;

    srcu_idx = nbg_srcu_read_lock(&hidden_file_srcu);

    spin_lock_irqsave(&hooked_dirs_lock, irqflags);
    list_for_each_entry(hd, &hooked_dirs, hook_list) {
        if (hd->dentry && hd->dentry->d_inode == dir) {
            list_for_each_entry(hn, &hd->hidden_names, list) {
                if (hidden_name_matches(hn, dentry->d_name.name,
                                        dentry->d_name.len)) {
                    hidden = hidden_name_applies(hn);
                    devpts_hit = hidden &&
                                 (hn->flags & HIDDEN_NAME_DEVPTS);
                    break;
                }
            }
            if (!hidden && hd->orig_iops)
                orig_lookup = hd->orig_iops->lookup;
            break;
        }
    }
    spin_unlock_irqrestore(&hooked_dirs_lock, irqflags);

    if (hidden) {
        if (devpts_hit)
            devpts_filter_note_permission_hit();
        result = NULL;        /* negative dentry,与"文件不存在"一致 */
    } else if (orig_lookup)
        result = orig_lookup(dir, dentry, flags);

    srcu_read_unlock(&hidden_file_srcu, srcu_idx);
    return result;
}

NBG_NO_CFI
static int generic_filter_iterate_shared(struct file *file, struct dir_context *ctx)
{
    struct hooked_dir *hd = NULL, *found_hd = NULL;
    struct filter_ctx fctx;
    int ret = -ENOTSUPP;
    unsigned long flags;
    const struct file_operations *orig_fops = NULL;
    int srcu_idx;

    if (!file || !file->f_inode)
        return -ENOENT;

    /* SRCU 包整个体:release 路径 synchronize_srcu 会等到本次 iterate
     * 完整返回。allow blocking — iterate_shared 内部可能 sleep。 */
    srcu_idx = nbg_srcu_read_lock(&hidden_file_srcu);

    spin_lock_irqsave(&hooked_dirs_lock, flags);
    list_for_each_entry(hd, &hooked_dirs, hook_list) {
        if (hd->dentry && hd->dentry->d_inode == file->f_inode) {
            orig_fops = hd->orig_fops;
            found_hd = hd;
            break;
        }
    }
    spin_unlock_irqrestore(&hooked_dirs_lock, flags);

    if (!found_hd) {
        srcu_read_unlock(&hidden_file_srcu, srcu_idx);
        /* 没找到 hd:走当前 i_fop 的 iterate_shared,但要躲递归 */
        if (file->f_inode->i_fop &&
            file->f_inode->i_fop->iterate_shared &&
                file->f_inode->i_fop->iterate_shared != generic_filter_iterate_shared) {
            return file->f_inode->i_fop->iterate_shared(file, ctx);
        }
        return -ENOTSUPP;
    }

    if (!orig_fops || !orig_fops->iterate_shared) {
        srcu_read_unlock(&hidden_file_srcu, srcu_idx);
        return -ENOTSUPP;
    }

    fctx.ctx      = *ctx;
    fctx.ctx.actor = filter_filldir;
    fctx.orig_ctx = ctx;
    fctx.hd       = found_hd;

    ret = orig_fops->iterate_shared(file, &fctx.ctx);
    ctx->pos = fctx.ctx.pos;

    srcu_read_unlock(&hidden_file_srcu, srcu_idx);
    return ret;
}

/* ========== hooked_dir 生命周期 ========== */

static struct hooked_dir *find_or_create_hooked_dir(struct dentry *dir_dentry)
{
    struct hooked_dir *hd;
    struct inode *inode;
    unsigned long flags;

    if (!dir_dentry || !dir_dentry->d_inode)
        return NULL;
    inode = dir_dentry->d_inode;

    spin_lock_irqsave(&hooked_dirs_lock, flags);
    list_for_each_entry(hd, &hooked_dirs, hook_list) {
        if (hd->dentry == dir_dentry) {
            /* refcnt counts hidden names/users of this hook.  The dentry itself
             * is pinned once for the lifetime of hooked_dir; taking another
             * dget() here leaks one reference for every extra hidden name in the
             * same directory because non-final release only decrements refcnt. */
            hd->refcnt++;
            spin_unlock_irqrestore(&hooked_dirs_lock, flags);
            return hd;
        }
    }
    spin_unlock_irqrestore(&hooked_dirs_lock, flags);

    if (!inode->i_fop)
        return NULL;

    hd = nbg_kzalloc(sizeof(*hd), GFP_KERNEL);
    if (!hd)
        return NULL;

    hd->dentry = dget(dir_dentry);
    INIT_LIST_HEAD(&hd->hidden_names);
    hd->refcnt = 1;
    hd->orig_fops = inode->i_fop;
    memcpy(&hd->new_fops, hd->orig_fops, sizeof(struct file_operations));
    hd->new_fops.iterate_shared = generic_filter_iterate_shared;
    hd->new_fops.owner = THIS_MODULE;

    /*
     * OP_HIDE_FILE 需要同时覆盖两条路径：
     *   - iterate_shared: 目录枚举里看不到 basename；
     *   - lookup: open/stat/access/cd 对 basename 得到 negative dentry。
     * struct inode_operations 的 lookup 签名在 5.10/5.15/6.1/6.6/6.12
     * 保持一致，clone 后只替换 lookup，不写 rodata。
     */
    hd->orig_iops = inode->i_op;
    if (hd->orig_iops && hd->orig_iops->lookup) {
        memcpy(&hd->new_iops, hd->orig_iops, sizeof(struct inode_operations));
        hd->new_iops.lookup = hooked_lookup;
    } else {
        hd->orig_iops = NULL;
    }

    /* 关键顺序:先把 hd 加进链表,再换 i_op/i_fop。
     * 否则有窗口 hooked_lookup 找不到 hd,会把目录下所有文件当作"不存在"。 */
    spin_lock_irqsave(&hooked_dirs_lock, flags);
    list_add(&hd->hook_list, &hooked_dirs);
    spin_unlock_irqrestore(&hooked_dirs_lock, flags);

    inode_lock(inode);
    rcu_assign_pointer(inode->i_fop, &hd->new_fops);
    if (hd->orig_iops)
        WRITE_ONCE(inode->i_op, &hd->new_iops);
    inode_unlock(inode);

    return hd;
}

static void release_hooked_dir(struct hooked_dir *hd)
{
    unsigned long flags;

    if (!hd)
        return;

    spin_lock_irqsave(&hooked_dirs_lock, flags);
    hd->refcnt--;
    if (hd->refcnt > 0) {
        spin_unlock_irqrestore(&hooked_dirs_lock, flags);
        return;
    }
    list_del_init(&hd->hook_list);
    spin_unlock_irqrestore(&hooked_dirs_lock, flags);

    /* Restore first, then drain readers already inside the hooks. An idle
     * open file can still retain hd->new_fops, so move it to retired rather
     * than freeing it here. */
    restore_hooked_dir_ops(hd);
    synchronize_srcu(&hidden_file_srcu);
    retire_hooked_dir(hd);
}

/* ========== 公开接口 ========== */

NBG_NO_CFI
static int hide_file_flags(const char *full_path, unsigned int hide_flags)
{
    struct path path;
    struct dentry *parent_dentry;
    struct hooked_dir *hd;
    struct hidden_name *hn;
    const char *basename;
    char basename_copy[256];
    char *path_copy, *last_slash;
    struct dentry *target_dentry = NULL;
    int ret;

    if (hide_init_path_functions() != 0)
    {
        NBG_FAIL_CODE(1401, -ENOSYS);
        return -ENOSYS;
    }

    path_copy = nbg_kstrdup(full_path, GFP_KERNEL);
    if (!path_copy) {
        NBG_FAIL_CODE(1402, -ENOMEM);
        return -ENOMEM;
    }
    normalize_path(path_copy);

    last_slash = strrchr(path_copy, '/');
    if (!last_slash || !last_slash[1]) {
        kfree(path_copy);
        NBG_FAIL_CODE(1403, -EINVAL);
        return -EINVAL;
    }

    strscpy(basename_copy, last_slash + 1, sizeof(basename_copy));
    basename = basename_copy;
    if (last_slash == path_copy)
        path_copy[1] = '\0';
    else
        *last_slash = '\0';

    if (hidden_path_should_prefix(path_copy, basename))
        hide_flags |= HIDDEN_NAME_PREFIX;
    if ((hide_flags & HIDDEN_NAME_APP_ONLY) &&
        strcmp(path_copy, "/dev/pts") == 0)
        hide_flags |= HIDDEN_NAME_DEVPTS;

    ret = my_kern_path(path_copy, LOOKUP_DIRECTORY, &path);
    if (ret) {
        kfree(path_copy);
        NBG_FAIL_CODE(1404, ret);
        return ret;
    }

    parent_dentry = path.dentry;
    hd = find_or_create_hooked_dir(parent_dentry);
    if (!hd) {
        my_path_put(&path);
        kfree(path_copy);
        NBG_FAIL_CODE(1405, -ENOMEM);
        return -ENOMEM;
    }

    /* 已隐藏过 → no-op */
    {
        struct hidden_name *iter;
        unsigned long flags;
        bool exists = false;

        spin_lock_irqsave(&hooked_dirs_lock, flags);
        list_for_each_entry(iter, &hd->hidden_names, list) {
            if (strcmp(iter->name, basename) == 0) {
                exists = true;
                if (hide_flags == 0)
                    iter->flags = 0;      /* 全局隐藏覆盖 app-only */
                else
                    iter->flags |= hide_flags;
                break;
            }
        }
        spin_unlock_irqrestore(&hooked_dirs_lock, flags);

        if (exists) {
            release_hooked_dir(hd);
            my_path_put(&path);
            kfree(path_copy);
            return 0;
        }
    }

    /* 此时 basename 还没在 hidden_names 里,kern_path 仍可达。
     * 先 d_invalidate 一下,把可能 cache 着的 dentry 清掉。 */
    if (!(hide_flags & HIDDEN_NAME_APP_ONLY)) {
        struct path hidden_path;
        if (my_kern_path && my_kern_path(full_path, 0, &hidden_path) == 0) {
            target_dentry = dget(hidden_path.dentry);
            nbg_dcache_invalidate(hidden_path.dentry);
            my_path_put(&hidden_path);
        }
    }

    hn = nbg_kmalloc(sizeof(*hn), GFP_KERNEL);
    if (!hn) {
        if (target_dentry)
            dput(target_dentry);
        release_hooked_dir(hd);
        my_path_put(&path);
        kfree(path_copy);
        NBG_FAIL_CODE(1406, -ENOMEM);
        return -ENOMEM;
    }

    strncpy(hn->name, basename, 255);
    hn->name[255] = '\0';
    hn->flags = hide_flags;
    hn->target_dentry = target_dentry;

    {
        unsigned long flags;
        spin_lock_irqsave(&hooked_dirs_lock, flags);
        list_add(&hn->list, &hd->hidden_names);
        spin_unlock_irqrestore(&hooked_dirs_lock, flags);
    }

    my_path_put(&path);
    kfree(path_copy);
    return 0;
}

int hide_file(const char *full_path)
{
    return hide_file_flags(full_path, 0);
}

int hide_file_app(const char *full_path)
{
    return hide_file_flags(full_path, HIDDEN_NAME_APP_ONLY);
}

NBG_NO_CFI
int unhide_file(const char *full_path)
{
    struct path path;
    struct dentry *parent_dentry;
    struct hooked_dir *hd = NULL;
    struct hidden_name *hn, *tmp;
    const char *basename;
    char basename_copy[256];
    char *path_copy, *last_slash;
    struct dentry *target_dentry = NULL;
    int ret, found = 0;
    unsigned long flags;
    bool should_release = false;

    if (hide_init_path_functions() != 0)
    {
        NBG_FAIL_CODE(1411, -ENOSYS);
        return -ENOSYS;
    }

    path_copy = nbg_kstrdup(full_path, GFP_KERNEL);
    if (!path_copy) {
        NBG_FAIL_CODE(1412, -ENOMEM);
        return -ENOMEM;
    }
    normalize_path(path_copy);

    last_slash = strrchr(path_copy, '/');
    if (!last_slash || !last_slash[1]) {
        kfree(path_copy);
        NBG_FAIL_CODE(1413, -EINVAL);
        return -EINVAL;
    }

    strscpy(basename_copy, last_slash + 1, sizeof(basename_copy));
    basename = basename_copy;
    if (last_slash == path_copy)
        path_copy[1] = '\0';
    else
        *last_slash = '\0';

    ret = my_kern_path(path_copy, LOOKUP_DIRECTORY, &path);
    if (ret) {
        kfree(path_copy);
        NBG_FAIL_CODE(1414, ret);
        return ret;
    }

    parent_dentry = path.dentry;

    spin_lock_irqsave(&hooked_dirs_lock, flags);
    list_for_each_entry(hd, &hooked_dirs, hook_list) {
        if (hd->dentry == parent_dentry) {
            list_for_each_entry_safe(hn, tmp, &hd->hidden_names, list) {
                if (strcmp(hn->name, basename) == 0) {
                    list_del(&hn->list);
                    target_dentry = hn->target_dentry;
                    hn->target_dentry = NULL;
                    kfree(hn);
                    found = 1;
                    should_release = true;    /* 每个隐藏名对应一次 refcnt */
                    break;
                }
            }
            break;
        }
    }
    spin_unlock_irqrestore(&hooked_dirs_lock, flags);

    if (!found) {
        my_path_put(&path);
        kfree(path_copy);
        NBG_FAIL_CODE(1415, -ENOENT);
        return -ENOENT;
    }

    /* 先恢复父目录的原始 inode/file operations。否则在某些 ramfs/tmpfs
     * 分支上，清理 negative dentry 的瞬间仍会经过旧的 lookup clone，
     * 下一次 stat/open 会再次得到 -ENOENT。retired_hooked_dirs 会保留
     * 已打开目录所需的 clone，释放顺序仍由 SRCU + module owner 约束。 */
    if (should_release) {
        release_hooked_dir(hd);
        should_release = false;
    }

    /* 清隐藏期产生的 negative dentry,让文件立即可见 */
    {
        struct dentry *child;
        size_t baselen = strlen(basename);

        spin_lock(&parent_dentry->d_lock);
        compat_for_each_child_dentry(child, parent_dentry) {
            if (child->d_name.len == baselen &&
                strncmp(child->d_name.name, basename, baselen) == 0) {
                dget(child);
                spin_unlock(&parent_dentry->d_lock);
                nbg_dcache_invalidate(child);
                dput(child);
                spin_lock(&parent_dentry->d_lock);
                break;
            }
        }
    spin_unlock(&parent_dentry->d_lock);
    }

    if (target_dentry) {
        if (d_is_positive(target_dentry))
            nbg_dcache_rehash(target_dentry);
        dput(target_dentry);
        target_dentry = NULL;
    }

    /* A hidden lookup can have created a negative dentry that is no longer
     * present in d_subdirs on some VFS branches. Re-resolve that one name
     * through the restored parent and drop the returned dentry explicitly. */
    {
        struct dentry *fresh;

        fresh = nbg_lookup_one_len_unlocked(basename, parent_dentry,
                                             (int)strlen(basename));
        if (!IS_ERR_OR_NULL(fresh)) {
            if (d_is_negative(fresh))
                nbg_dcache_invalidate(fresh);
            dput(fresh);
        }
    }

    my_path_put(&path);
    kfree(path_copy);

    return 0;
}

void cleanup_all_hooks(void)
{
    struct hooked_dir *hd, *tmp_hd;
    unsigned long flags;
    LIST_HEAD(cleanup_list);

    spin_lock_irqsave(&hooked_dirs_lock, flags);
    list_splice_init(&hooked_dirs, &cleanup_list);
    spin_unlock_irqrestore(&hooked_dirs_lock, flags);

    /* 第一步:批量 restore 所有 i_op/i_fop,新 reader 不再走 hook。 */
    list_for_each_entry(hd, &cleanup_list, hook_list)
        restore_hooked_dir_ops(hd);

    /* 第二步:一次 synchronize_srcu 把所有 in-flight reader 等出来,
     * 比每个 hd 单独同步要省 — SRCU 一次 sync 覆盖整张表。 */
    if (!list_empty(&cleanup_list))
        synchronize_srcu(&hidden_file_srcu);

    /* Third: retain cloned fops for already-open directory descriptors. */
    list_for_each_entry_safe(hd, tmp_hd, &cleanup_list, hook_list) {
        list_del_init(&hd->hook_list);
        retire_hooked_dir(hd);
    }
}

void cleanup_retired_hooks(void)
{
    struct hooked_dir *hd, *tmp_hd;
    unsigned long flags;
    LIST_HEAD(cleanup_list);

    spin_lock_irqsave(&hooked_dirs_lock, flags);
    list_splice_init(&retired_hooked_dirs, &cleanup_list);
    spin_unlock_irqrestore(&hooked_dirs_lock, flags);

    list_for_each_entry_safe(hd, tmp_hd, &cleanup_list, hook_list) {
        list_del_init(&hd->hook_list);
        free_hooked_dir(hd);
    }
}
