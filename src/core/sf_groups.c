/* sf_groups.c — 补齐 surfaceflinger 访问所需的辅助组
 *
 * 某些资源（input、inet）的 DAC 检查看的是 fsgid 加补充组，而不是 uid。
 * 注入到 surfaceflinger 里的代码虽然 uid 对，但补充组可能不全，于是
 * 打不开对应节点。这里把缺失的组补进当前线程的 cred。
 *
 * 改的是 current 的 cred，走 prepare_creds/commit_creds，绝不在原地
 * 修改别的任务的 cred 指针。
 */
#include "sf_groups.h"
#include "nbg_user_ns.h"

#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/version.h>

#include "comm.h"
#include "nbg_compat.h"
#include "nbg_ksyms.h"

#define NBG_AID_SYSTEM 1000U
#define NBG_AID_INPUT  1004U
#define NBG_AID_INET   3003U

#define NBG_SF_EXE_PATH "/system/bin/surfaceflinger"
#define NBG_SF_COMM     "surfaceflinger"

/* 这几个符号在部分 GKI 分支不导出，统一走 kallsyms。 */
typedef struct file *(*nbg_get_task_exe_file_t)(struct task_struct *);
typedef struct group_info *(*nbg_groups_alloc_t)(int);
typedef void (*nbg_groups_sort_t)(struct group_info *);
typedef int (*nbg_groups_search_t)(const struct group_info *, kgid_t);
typedef int (*nbg_set_current_groups_t)(struct group_info *);
/* put_group_info 会内联展开到未导出的 groups_free，直接引用会让模块加载失败。 */
typedef void (*nbg_groups_free_t)(struct group_info *);

/* group_info::usage 在 6.12 改成了 refcount_t，早期内核仍是 atomic_t。 */
static bool nbg_group_info_drop(struct group_info *groups)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    return refcount_dec_and_test(&groups->usage);
#else
    return atomic_dec_and_test(&groups->usage);
#endif
}

static void nbg_put_group_info_safe(struct group_info *groups)
{
    nbg_groups_free_t free_fn;

    if (!groups)
        return;

    free_fn = (nbg_groups_free_t)generic_kallsyms_lookup_name("groups_free");
    if (!free_fn)
        /* 取不到释放函数时宁可泄一次内核小对象，也不要在加载期多一个未定义符号。 */
        return;

    if (nbg_group_info_drop(groups))
        free_fn(groups);
}

static bool nbg_sf_has_system_uids(const struct cred *cred)
{
    kuid_t system_uid = KUIDT_INIT(NBG_AID_SYSTEM);

    return cred->user_ns == nbg_init_user_ns_addr() &&
           uid_eq(cred->uid, system_uid) &&
           uid_eq(cred->euid, system_uid) &&
           uid_eq(cred->suid, system_uid) &&
           uid_eq(cred->fsuid, system_uid);
}

static bool nbg_sf_has_identity(void)
{
    nbg_get_task_exe_file_t get_exe;
    struct file *exe_file;
    char leader_comm[TASK_COMM_LEN];
    char *path_buffer;
    char *path;
    bool allowed = false;

    get_task_comm(leader_comm, current->group_leader);
    if (strcmp(leader_comm, NBG_SF_COMM) != 0)
        return false;

    get_exe = (nbg_get_task_exe_file_t)
        generic_kallsyms_lookup_name("get_task_exe_file");
    if (!get_exe)
        return false;

    exe_file = get_exe(current->group_leader);
    if (!exe_file)
        return false;

    path_buffer = (char *)__get_free_page(GFP_KERNEL);
    if (!path_buffer)
        goto out_file;

    path = d_path(&exe_file->f_path, path_buffer, PAGE_SIZE);
    if (!IS_ERR(path) && strcmp(path, NBG_SF_EXE_PATH) == 0)
        allowed = true;

    free_page((unsigned long)path_buffer);
out_file:
    fput(exe_file);
    return allowed;
}

bool nbg_sf_is_caller(void)
{
    return nbg_sf_has_system_uids(current_cred()) && nbg_sf_has_identity();
}

/* DAC 检查用 fsgid 加补充组。 */
static bool nbg_sf_cred_has_gid(const struct cred *cred, kgid_t gid)
{
    nbg_groups_search_t search;

    if (gid_eq(cred->fsgid, gid))
        return true;

    search = (nbg_groups_search_t)
        generic_kallsyms_lookup_name("groups_search");
    if (!search || !cred->group_info)
        return false;
    return search(cred->group_info, gid) != 0;
}

static uint32_t nbg_sf_present_mask(const struct cred *cred)
{
    uint32_t mask = 0;

    if (nbg_sf_cred_has_gid(cred, KGIDT_INIT(NBG_AID_INPUT)))
        mask |= NBG_SF_GROUP_INPUT;
    if (nbg_sf_cred_has_gid(cred, KGIDT_INIT(NBG_AID_INET)))
        mask |= NBG_SF_GROUP_INET;
    return mask;
}

static int nbg_sf_append_groups(uint32_t missing)
{
    nbg_groups_alloc_t groups_alloc;
    nbg_groups_sort_t groups_sort;
    nbg_set_current_groups_t set_groups;
    const struct cred *cred = current_cred();
    const struct group_info *old_groups = cred->group_info;
    struct group_info *new_groups;
    int add_count = 0;
    int index;
    int ret;

    if (missing & NBG_SF_GROUP_INPUT)
        add_count++;
    if (missing & NBG_SF_GROUP_INET)
        add_count++;
    if (!add_count)
        return 0;
    if (!old_groups)
        return -EINVAL;
    if (old_groups->ngroups > NGROUPS_MAX - add_count)
        return -E2BIG;

    groups_alloc = (nbg_groups_alloc_t)
        generic_kallsyms_lookup_name("groups_alloc");
    groups_sort = (nbg_groups_sort_t)
        generic_kallsyms_lookup_name("groups_sort");
    set_groups = (nbg_set_current_groups_t)
        generic_kallsyms_lookup_name("set_current_groups");
    if (!groups_alloc || !set_groups)
        return -ENOENT;

    new_groups = groups_alloc(old_groups->ngroups + add_count);
    if (!new_groups)
        return -ENOMEM;

    for (index = 0; index < old_groups->ngroups; index++)
        new_groups->gid[index] = old_groups->gid[index];
    if (missing & NBG_SF_GROUP_INPUT)
        new_groups->gid[index++] = KGIDT_INIT(NBG_AID_INPUT);
    if (missing & NBG_SF_GROUP_INET)
        new_groups->gid[index++] = KGIDT_INIT(NBG_AID_INET);

    /* groups_search() 是二分查找，而 set_current_groups() 在本内核上
     * 不做排序；排序本来由 setgroups 系统调用负责。 */
    if (groups_sort)
        groups_sort(new_groups);

    /* set_current_groups() 内部走 prepare_creds/commit_creds，
     * 不像 setgroups 系统调用那样要求 CAP_SETGID。 */
    ret = set_groups(new_groups);
    nbg_put_group_info_safe(new_groups);
    return ret;
}

long nbg_sf_groups_acquire(void __user *arg)
{
    NBG_SF_GROUPS_REQ req;
    uint32_t before;
    uint32_t missing;
    int ret;

    if (!arg)
        return -EFAULT;
    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;

    if (req.abi_version != NBG_SF_GROUPS_ABI_VERSION || req.reserved != 0 ||
        req.out_present != 0 || req.out_added != 0 ||
        req.out_group_count != 0 || req.out_reserved[0] != 0 ||
        req.out_reserved[1] != 0 || req.out_reserved[2] != 0)
        return -EINVAL;

    if (!nbg_sf_is_caller())
        return -EACCES;

    before = nbg_sf_present_mask(current_cred());
    missing = NBG_SF_GROUP_REQUIRED & ~before;
    ret = nbg_sf_append_groups(missing);
    if (ret)
        return ret;

    req.out_present = nbg_sf_present_mask(current_cred());
    req.out_added = req.out_present & ~before;
    req.out_group_count = current_cred()->group_info->ngroups;
    if (req.out_present != NBG_SF_GROUP_REQUIRED)
        return -EIO;
    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;

    if (req.out_added)
        pr_info("nbg: sf groups tgid=%d tid=%d added=0x%x groups=%u\n",
                task_tgid_nr(current), task_pid_nr(current), req.out_added,
                req.out_group_count);
    return 0;
}
