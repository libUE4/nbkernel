/* file_io.c — 内核态受限文件读写
 *
 * 以内核凭据打开并读写文件，绕过用户态的路径解析与 DAC 限制。
 * 路径被限定在 /data/adb 下：写入只允许该目录的直接子项，读取额外
 * 允许 /data/adb/model/<leaf> 这一层固定中间目录。
 *
 * 全程 O_NOFOLLOW，避免符号链接把访问引到别处。
 */
#include "file_io.h"

#include <linux/cred.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#include "comm.h"
#include "nbg_compat.h"
#include "nbg_ksyms.h"

#define NBG_FILE_ROOT   "/data/adb"
#define NBG_FILE_PREFIX NBG_FILE_ROOT "/"
#define NBG_MODEL_ROOT  NBG_FILE_ROOT "/model"
#define NBG_MODEL_PREFIX NBG_MODEL_ROOT "/"
#define NBG_FILE_WRITE_FLAGS \
    (NBG_FILE_WRITE_CREATE | NBG_FILE_WRITE_TRUNCATE)

typedef struct file *(*nbg_filp_open_t)(const char *, int, umode_t);
typedef ssize_t (*nbg_kernel_read_t)(struct file *, void *, size_t, loff_t *);
typedef ssize_t (*nbg_kernel_write_t)(struct file *, const void *, size_t,
                                      loff_t *);
typedef const struct cred *(*nbg_override_creds_t)(const struct cred *);
typedef void (*nbg_revert_creds_t)(const struct cred *);
typedef int (*nbg_set_secctx_t)(struct cred *, const char *);
/* prepare_kernel_cred / __put_cred 在部分 GKI 内核不导出，直接引用会让
 * 模块加载时报 Unknown symbol，因此统一走 kallsyms 解析。 */
typedef struct cred *(*nbg_prepare_kernel_cred_t)(struct task_struct *);
typedef void (*nbg_put_cred_t)(struct cred *);

static nbg_prepare_kernel_cred_t nbg_prepare_kernel_cred_fn;
static nbg_put_cred_t nbg_put_cred_fn;

static void nbg_file_resolve_symbols(void)
{
    if (!nbg_prepare_kernel_cred_fn)
        nbg_prepare_kernel_cred_fn = (nbg_prepare_kernel_cred_t)
            generic_kallsyms_lookup_name("prepare_kernel_cred");
    if (!nbg_put_cred_fn)
        nbg_put_cred_fn = (nbg_put_cred_t)
            generic_kallsyms_lookup_name("__put_cred");
}

/* 与内核 put_cred 等价，但不内联展开到未导出的 __put_cred。
 * cred->usage 在 6.2 才改成 atomic_long_t，旧内核仍是 atomic_t。 */
static void nbg_file_put_cred(struct cred *cred)
{
    bool drop;

    if (!cred)
        return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
    drop = atomic_long_dec_and_test(&cred->usage);
#else
    drop = atomic_dec_and_test(&cred->usage);
#endif

    if (!drop || !nbg_put_cred_fn)
        return;

    nbg_put_cred_fn(cred);
}

static struct cred *g_file_cred;
static DEFINE_MUTEX(g_file_io_lock);

static bool nbg_file_caller_allowed(void)
{
    uid_t uid = __kuid_val(current_uid());

    return uid == 0 || uid == 1000;
}

static bool nbg_file_valid_leaf(const char *name)
{
    return name[0] != '\0' && !strchr(name, '/') &&
           strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

/* 写入只允许 /data/adb 的直接子项；读取额外接受恰好一层固定中间目录
 * /data/adb/model/<leaf>。 */
static int nbg_file_validate_path(NBG_FILE_IO_REQ *req, bool writing,
                                  bool *model_path)
{
    const char *path;
    const char *name;
    size_t prefix_len = sizeof(NBG_FILE_PREFIX) - 1;
    size_t model_prefix_len = sizeof(NBG_MODEL_PREFIX) - 1;

    if (model_path)
        *model_path = false;

    if (!memchr(req->path, '\0', sizeof(req->path)))
        return -ENAMETOOLONG;

    path = req->path;
    if (!writing && strncmp(path, NBG_MODEL_PREFIX, model_prefix_len) == 0) {
        name = path + model_prefix_len;
        if (!nbg_file_valid_leaf(name))
            return -EACCES;
        if (model_path)
            *model_path = true;
        return 0;
    }

    if (strncmp(path, NBG_FILE_PREFIX, prefix_len) != 0 ||
        path[prefix_len] == '\0')
        return -EACCES;

    name = path + prefix_len;
    if (!nbg_file_valid_leaf(name))
        return -EACCES;
    return 0;
}

static int nbg_file_validate_model_dir(void)
{
    nbg_filp_open_t open_file;
    struct file *directory;
    int ret = 0;

    open_file = (nbg_filp_open_t)generic_kallsyms_lookup_name("filp_open");
    if (!open_file)
        return -ENOENT;

    directory = open_file(NBG_MODEL_ROOT,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (IS_ERR(directory))
        return PTR_ERR(directory);

    /* 模型安装方可能用应用自有目录或 0777，这里不加 owner/mode 门槛，
     * 只保留固定路径、no-follow 与类型检查。 */
    if (!S_ISDIR(file_inode(directory)->i_mode))
        ret = -EACCES;

    filp_close(directory, NULL);
    return ret;
}

static int nbg_file_validate_buffer(const NBG_FILE_IO_REQ *req, bool writing)
{
    if (req->size > NBG_FILE_IO_MAX)
        return -E2BIG;
    if (!writing && req->size == 0)
        return -EINVAL;
    if (req->offset > LLONG_MAX ||
        req->size > (uint64_t)LLONG_MAX - req->offset)
        return -EOVERFLOW;
    if (req->size != 0 &&
        (req->buf == 0 ||
         !access_ok((void __user *)(unsigned long)req->buf,
                    (size_t)req->size)))
        return -EFAULT;
    return 0;
}

long nbg_file_read(void __user *arg)
{
    nbg_filp_open_t open_file;
    nbg_kernel_read_t kernel_read_fn;
    nbg_override_creds_t override;
    nbg_revert_creds_t revert;
    const struct cred *old_cred;
    NBG_FILE_IO_REQ req;
    struct file *file = NULL;
    char *buffer = NULL;
    loff_t pos;
    uint64_t done = 0;
    bool model_path = false;
    long ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    req.out_size = 0;
    req.out_file_size = 0;

    if (!nbg_file_caller_allowed())
        return -EACCES;
    if (req.flags != 0 || req.reserved != 0)
        return -EINVAL;

    ret = nbg_file_validate_path(&req, false, &model_path);
    if (ret)
        return ret;
    ret = nbg_file_validate_buffer(&req, false);
    if (ret)
        return ret;
    if (!g_file_cred)
        return -ENODEV;

    open_file = (nbg_filp_open_t)generic_kallsyms_lookup_name("filp_open");
    kernel_read_fn = (nbg_kernel_read_t)
        generic_kallsyms_lookup_name("kernel_read");
    override = (nbg_override_creds_t)
        generic_kallsyms_lookup_name("override_creds");
    revert = (nbg_revert_creds_t)
        generic_kallsyms_lookup_name("revert_creds");
    if (!open_file || !kernel_read_fn || !override || !revert)
        return -ENOENT;

    buffer = kmalloc(min_t(size_t, (size_t)req.size, PAGE_SIZE), GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    mutex_lock(&g_file_io_lock);
    old_cred = override(g_file_cred);

    if (model_path) {
        ret = nbg_file_validate_model_dir();
        if (ret)
            goto out;
    }

    file = open_file(req.path,
                     O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
    if (IS_ERR(file)) {
        ret = PTR_ERR(file);
        file = NULL;
        goto out;
    }
    if (!S_ISREG(file_inode(file)->i_mode)) {
        ret = -EINVAL;
        goto out;
    }

    req.out_file_size = (uint64_t)i_size_read(file_inode(file));
    pos = (loff_t)req.offset;
    while (done < req.size) {
        size_t chunk = min_t(uint64_t, req.size - done, PAGE_SIZE);
        ssize_t count = kernel_read_fn(file, buffer, chunk, &pos);

        if (count < 0) {
            ret = count;
            goto out;
        }
        if (count == 0)
            break;
        if (copy_to_user((char __user *)(unsigned long)(req.buf + done),
                         buffer, count)) {
            ret = -EFAULT;
            goto out;
        }
        done += count;
    }

    req.out_size = done;
    ret = 0;

out:
    if (file)
        filp_close(file, NULL);
    revert(old_cred);
    mutex_unlock(&g_file_io_lock);
    kfree(buffer);

    if (ret)
        return ret;
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

long nbg_file_write(void __user *arg)
{
    nbg_filp_open_t open_file;
    nbg_kernel_write_t kernel_write_fn;
    nbg_override_creds_t override;
    nbg_revert_creds_t revert;
    const struct cred *old_cred;
    NBG_FILE_IO_REQ req;
    struct file *file = NULL;
    char *buffer = NULL;
    loff_t pos;
    uint64_t done = 0;
    int open_flags = O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
    long ret;

    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    req.out_size = 0;
    req.out_file_size = 0;

    if (!nbg_file_caller_allowed())
        return -EACCES;
    if ((req.flags & ~NBG_FILE_WRITE_FLAGS) != 0 || req.reserved != 0)
        return -EINVAL;
    if ((req.flags & NBG_FILE_WRITE_TRUNCATE) && req.offset != 0)
        return -EINVAL;

    ret = nbg_file_validate_path(&req, true, NULL);
    if (ret)
        return ret;
    ret = nbg_file_validate_buffer(&req, true);
    if (ret)
        return ret;
    if (!g_file_cred)
        return -ENODEV;

    if (req.flags & NBG_FILE_WRITE_CREATE)
        open_flags |= O_CREAT;
    if (req.flags & NBG_FILE_WRITE_TRUNCATE)
        open_flags |= O_TRUNC;

    open_file = (nbg_filp_open_t)generic_kallsyms_lookup_name("filp_open");
    kernel_write_fn = (nbg_kernel_write_t)
        generic_kallsyms_lookup_name("kernel_write");
    override = (nbg_override_creds_t)
        generic_kallsyms_lookup_name("override_creds");
    revert = (nbg_revert_creds_t)
        generic_kallsyms_lookup_name("revert_creds");
    if (!open_file || !kernel_write_fn || !override || !revert)
        return -ENOENT;

    if (req.size != 0) {
        buffer = kmalloc(min_t(size_t, (size_t)req.size, PAGE_SIZE),
                         GFP_KERNEL);
        if (!buffer)
            return -ENOMEM;
    }

    mutex_lock(&g_file_io_lock);
    old_cred = override(g_file_cred);

    file = open_file(req.path, open_flags, 0600);
    if (IS_ERR(file)) {
        ret = PTR_ERR(file);
        file = NULL;
        goto out;
    }
    if (!S_ISREG(file_inode(file)->i_mode)) {
        ret = -EINVAL;
        goto out;
    }

    pos = (loff_t)req.offset;
    while (done < req.size) {
        size_t chunk = min_t(uint64_t, req.size - done, PAGE_SIZE);
        ssize_t count;

        if (copy_from_user(buffer,
                           (char __user *)(unsigned long)(req.buf + done),
                           chunk)) {
            ret = -EFAULT;
            goto out;
        }
        count = kernel_write_fn(file, buffer, chunk, &pos);
        if (count < 0) {
            ret = count;
            goto out;
        }
        if (count == 0) {
            ret = -EIO;
            goto out;
        }
        done += count;
    }

    req.out_size = done;
    req.out_file_size = (uint64_t)i_size_read(file_inode(file));
    ret = 0;

out:
    if (file)
        filp_close(file, NULL);
    revert(old_cred);
    mutex_unlock(&g_file_io_lock);
    kfree(buffer);

    if (ret)
        return ret;
    return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
}

int nbg_file_io_init(void)
{
    nbg_set_secctx_t set_ctx;
    const char *secctx = "u:r:ksu:s0";
    struct cred *cred;
    int ret;

    nbg_file_resolve_symbols();
    if (!nbg_prepare_kernel_cred_fn)
        return -ENOENT;

    cred = nbg_prepare_kernel_cred_fn(&init_task);
    if (!cred)
        return -ENOMEM;

    set_ctx = (nbg_set_secctx_t)
        generic_kallsyms_lookup_name("set_security_override_from_ctx");
    if (!set_ctx) {
        /* 拿不到 SELinux 覆盖能力时不要假装成功：后续打开会被拒。 */
        nbg_file_put_cred(cred);
        return -ENOENT;
    }

    /* 保留 init_task 的 root 身份，但换用 root 管理器的 SELinux 域。
     * 未知上下文返回 -EINVAL，不能把分配或权限失败当成域不存在。 */
    ret = set_ctx(cred, secctx);
    if (ret == -EINVAL) {
        secctx = "u:r:magisk:s0";
        ret = set_ctx(cred, secctx);
    }
    if (ret == -EINVAL) {
        secctx = "u:r:su:s0";
        ret = set_ctx(cred, secctx);
    }
    if (ret) {
        pr_err("nbg: file io selinux ctx %s failed: %d\n", secctx, ret);
        nbg_file_put_cred(cred);
        return ret;
    }

    g_file_cred = cred;
    pr_info("nbg: file io context %s\n", secctx);
    return 0;
}

void nbg_file_io_exit(void)
{
    if (g_file_cred) {
        nbg_file_put_cred(g_file_cred);
        g_file_cred = NULL;
    }
}
