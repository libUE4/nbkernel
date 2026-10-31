/* entry.c — 模块装载入口与卸载出口
 *
 * nbg_init 序:
 *   raw_hwbp_init / raw_hwwp_init / shadow_init_module
 *   touch subsystem
 *   nbg_comm_init                       ── custom socket ioctl 通信入口
 *
 * 触摸、内存读写、断点、隐藏 PID/File/devpts 与自定义 socket 通信。
 * 可选的 KGSL 层由下方兼容性开关控制。
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include "hide_core.h"
#include "hide_internal.h"
#include "devpts_filter.h"
#include "hide_file.h"
#include "hide_kgsl.h"
#include "hide_module.h"
#include "hwbp_capture.h"
#include "hwbp_raw.h"
#include "hwbp_regset_filter.h"
#include "hwbp_shadow.h"
#include "touch.h"
#include "comm.h"
#include "memory.h"
#include "udp_capture.h"
#include "file_io.h"
#include "nbg_log.h"
#include "nbg_ksyms.h"
#include "nbg_compat.h"

#define NBG_LOAD_FAULTINFO_HOOKS 1
#define NBG_LOAD_DEVPTS_FILTER 1
#define NBG_LOAD_KGSL_HIDE 1
#define NBG_LOAD_HIDE_SELF 1
#define NBG_LOAD_HWDEBUG_REGSET_FILTER 1
#define NBG_SELF_SYSFS_PATH "/sys/module/NBG"


#if NBG_LOAD_FAULTINFO_HOOKS
static bool nbg_raw_hwbp_ready;
static bool nbg_raw_hwwp_ready;
static bool nbg_hwbp_capture_ready;

static void nbg_faultinfo_cleanup(void)
{
    if (nbg_hwbp_capture_ready) {
        hwbp_capture_exit();
        nbg_hwbp_capture_ready = false;
    }
    if (nbg_raw_hwwp_ready) {
        raw_hwwp_exit();
        nbg_raw_hwwp_ready = false;
    }
    if (nbg_raw_hwbp_ready) {
        raw_hwbp_exit();
        nbg_raw_hwbp_ready = false;
    }
}
#else
static void nbg_faultinfo_cleanup(void) { }
#endif

static void nbg_feature_layers_cleanup(void)
{
#if NBG_LOAD_DEVPTS_FILTER
    /* Stop automatic target discovery before tearing down shared VFS hooks. */
    devpts_filter_clear();
#endif
#if NBG_LOAD_HWDEBUG_REGSET_FILTER
    hwbp_regset_filter_cleanup();
#endif
#if NBG_LOAD_HIDE_SELF
    net_protocols_hide_cleanup();
    kprobes_list_hide_cleanup();
    mod_tree_hide_cleanup();
    module_list_unhide();
    proc_modules_hide_cleanup();
    kallsyms_hide_cleanup();
#endif
#if NBG_LOAD_KGSL_HIDE
    hide_kgsl_cleanup();
#endif
}

static int nbg_init(void)
{
    int ret;

    ret = nbg_gki_compat_init();
    if (ret) {
        NBG_FAIL_CODE(1002, ret);
        return ret;
    }

    ret = nbg_memory_init();
    if (ret) {
        NBG_FAIL_CODE(1000, ret);
        return ret;
    }

#if NBG_LOAD_KGSL_HIDE
    ret = hide_kgsl_install();
    NBG_FAIL_CODE(1111, ret);
#endif

#if NBG_LOAD_HIDE_SELF
    ret = kallsyms_hide_module(THIS_MODULE->name);
    NBG_FAIL_CODE(1101, ret);
    ret = proc_modules_hide_install();
    NBG_FAIL_CODE(1102, ret);
    ret = module_list_hide();
    NBG_FAIL_CODE(1104, ret);
    /* Keep the module's sysfs directory on the same VFS filtering path as
     * other hidden names. auto_unhide_all() restores it before module exit. */
    ret = hide_file(NBG_SELF_SYSFS_PATH);
    NBG_FAIL_CODE(1103, ret);
    ret = mod_tree_hide_install();
    NBG_FAIL_CODE(1105, ret);
    ret = kprobes_list_hide_install();
    NBG_FAIL_CODE(1106, ret);
    ret = net_protocols_hide_install();
    NBG_FAIL_CODE(1107, ret);
#endif

#if NBG_LOAD_DEVPTS_FILTER
    /* Arm before a game process exists.  The filter uses the package/process
     * identity until userspace later supplies an exact session PID. */
    ret = devpts_filter_install();
    /* Some vendor kernels can temporarily reject kprobe registration during
     * early boot or remove a single optional hook from kallsyms.  Keep the
     * module load path deterministic: record the code and allow the ioctl path
     * to retry later, rather than failing insmod for one optional visibility
     * layer.  When install succeeds the feature remains fully active. */
    NBG_FAIL_CODE(1110, ret);
#endif

#if NBG_LOAD_FAULTINFO_HOOKS
    if (!bypass_cfi())
        NBG_FAIL_CODE(1001, -ENOENT);

    ret = raw_hwbp_init();
    if (ret) {
        NBG_FAIL_CODE(1011, ret);
        if (ret != -ENOENT && ret != -ENOSPC) {
            nbg_feature_layers_cleanup();
            return ret;
        }
        /* Some newest GKI/QEMU kernels no longer expose debug_fault_info.
         * Keep the module loadable for memory and visibility paths and
         * leave HWBP operations unavailable on that branch instead of failing
         * finit_module. */
    } else {
        nbg_raw_hwbp_ready = true;

        /* watchpoint 可选 — 失败仅退化,不阻止模块加载 */
        ret = raw_hwwp_init();
        if (ret)
            NBG_FAIL_CODE(1012, ret);
        else
            nbg_raw_hwwp_ready = true;

        ret = hwbp_capture_init();
        if (ret) {
            NBG_FAIL_CODE(1016, ret);
            nbg_faultinfo_cleanup();
            nbg_feature_layers_cleanup();
            return ret;
        }
        nbg_hwbp_capture_ready = true;
    }

#if NBG_LOAD_HWDEBUG_REGSET_FILTER
    ret = hwbp_regset_filter_install();
    NBG_FAIL_CODE(1109, ret);
#endif
#else
    ret = 0;
#endif

    ret = shadow_init_module();
    if (ret) {
        NBG_FAIL_CODE(1013, ret);
        nbg_feature_layers_cleanup();
        nbg_faultinfo_cleanup();
        return ret;
    }

    ret = touch_init();
    if (ret) {
        NBG_FAIL_CODE(1015, ret);
        nbg_feature_layers_cleanup();
        auto_unhide_all(0);
        cleanup_retired_hooks();
        shadow_exit_module();
#if NBG_LOAD_FAULTINFO_HOOKS
        nbg_faultinfo_cleanup();
#endif
        return ret;
    }

    ret = nbg_comm_init();
    if (ret) {
        NBG_FAIL_CODE(1014, ret);
        touch_exit();
        nbg_feature_layers_cleanup();
        auto_unhide_all(0);
        cleanup_retired_hooks();
        shadow_exit_module();
#if NBG_LOAD_FAULTINFO_HOOKS
        nbg_faultinfo_cleanup();
#endif
        return ret;
    }

    /* Touch is initialized lazily on first DOWN. The input implementation
     * reserves high MT slots on the physical touchscreen so real and injected
     * contacts remain in one Android MotionEvent stream. */

    /* 文件 IO 的 SELinux 覆盖上下文失败不应拖垮模块加载：
     * 拿不到上下文时相关命令返回 -ENODEV，其余功能照常。 */
    if (nbg_file_io_init())
        pr_warn("nbg: file io unavailable, file commands disabled\n");

    return 0;
}

static void nbg_exit(void)
{
    nbg_comm_exit();
    nbg_udp_capture_exit();
    nbg_file_io_exit();
    nbg_memory_exit();
    auto_unhide_all(0);
    /* cloned directory fops hold THIS_MODULE while an fd can reference them;
     * module_exit is reached only after those references are gone. */
    cleanup_retired_hooks();
    touch_exit();
    shadow_exit_module();
    /* Stop visibility hooks before raw BP/WP state is torn down. */
    nbg_feature_layers_cleanup();
#if NBG_LOAD_FAULTINFO_HOOKS
    nbg_faultinfo_cleanup();
#endif
    synchronize_rcu();
}

module_init(nbg_init);
module_exit(nbg_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("QTI raw network helper");
NBG_MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
