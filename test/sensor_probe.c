/* sensor_probe.c — 受限写会话验证
 *
 * 只验证 OP_SENSOR_OPEN 的准入与拒绝路径，不做任何写入，
 * 因此不会修改 system_server 的任何内存。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "comm.h"

static int g_pass, g_fail, g_skip;
static int g_fd = -1;

static void ok(const char *fmt, ...)
{
    va_list ap;

    g_pass++;
    printf("  PASS ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static void bad(const char *fmt, ...)
{
    va_list ap;

    g_fail++;
    printf("  FAIL ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static void skip(const char *fmt, ...)
{
    va_list ap;

    g_skip++;
    printf("  SKIP ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static int call(unsigned int cmd, void *arg)
{
    errno = 0;
    if (ioctl(g_fd, cmd, arg) < 0)
        return -errno;
    return 0;
}

static int connect_driver(void)
{
    INIT_KEY init;
    int family;

    for (family = 1; family < 50; family++) {
        int fd = socket(family, SOCK_RAW, NBG_SOCKET_PROTOCOL);

        if (fd < 0)
            continue;

        memset(&init, 0, sizeof(init));
        init.abi_version = NBG_ABI_VERSION;
        init.token = NBG_AUTH_TOKEN;
        if (ioctl(fd, OP_INIT_KEY, &init) == 0 && init.accepted) {
            g_fd = fd;
            printf("[+] 已连接 family=%d\n", family);
            return 0;
        }
        close(fd);
    }
    return -1;
}

static int find_pid_by_comm(const char *comm)
{
    NBG_GET_PID_REQ req;

    memset(&req, 0, sizeof(req));
    snprintf(req.name, sizeof(req.name), "%s", comm);
    if (call(OP_GET_PID, &req))
        return -1;
    return req.out_pid;
}

/* 用 root 身份打开 system_server 的受限会话。 */
static void test_open_system_server(void)
{
    NBG_SENSOR_OPEN_REQ req;
    int pid;
    int ret;

    printf("\n[OP_SENSOR_OPEN] system_server\n");

    pid = find_pid_by_comm("system_server");
    if (pid <= 0) {
        skip("找不到 system_server");
        return;
    }
    printf("       system_server pid=%d\n", pid);

    memset(&req, 0, sizeof(req));
    req.version = NBG_SENSOR_OPEN_ABI_VERSION;
    req.pid = pid;
    ret = call(OP_SENSOR_OPEN, &req);
    if (ret == 0) {
        ok("fd=%d base=0x%llx size=0x%llx uid=%u", req.out_fd,
           (unsigned long long)req.out_module_base,
           (unsigned long long)req.out_module_size, req.out_uid);
        /* 只打开不写入，立即关闭触发清理路径。 */
        close(req.out_fd);
        ok("已关闭会话 fd");
    } else if (ret == -EACCES) {
        skip("调用方身份不符 (需要 root 或 surfaceflinger)");
    } else if (ret == -ENOENT) {
        bad("system_server 里没有 libsensorservice.so 映射");
    } else if (ret == -EBUSY) {
        skip("已有活动会话");
    } else {
        bad("ret=%d (%s)", ret, strerror(-ret));
    }
}

/* 版本号错误必须被拒绝。 */
static void test_bad_version(void)
{
    NBG_SENSOR_OPEN_REQ req;
    int pid;
    int ret;

    printf("\n[OP_SENSOR_OPEN] 版本号错误\n");

    pid = find_pid_by_comm("system_server");
    if (pid <= 0) {
        skip("找不到 system_server");
        return;
    }

    memset(&req, 0, sizeof(req));
    req.version = NBG_SENSOR_OPEN_ABI_VERSION + 99;
    req.pid = pid;
    ret = call(OP_SENSOR_OPEN, &req);
    if (ret == -EINVAL)
        ok("正确返回 -EINVAL");
    else
        bad("ret=%d (%s)，期望 -EINVAL", ret, strerror(-ret));
}

/* 非 system_server 目标必须被拒绝。 */
static void test_bad_target(void)
{
    NBG_SENSOR_OPEN_REQ req;
    int ret;

    printf("\n[OP_SENSOR_OPEN] 目标不是 system_server\n");

    memset(&req, 0, sizeof(req));
    req.version = NBG_SENSOR_OPEN_ABI_VERSION;
    req.pid = getpid();
    ret = call(OP_SENSOR_OPEN, &req);
    if (ret == -EACCES)
        ok("正确拒绝自身进程 (-EACCES)");
    else if (ret == 0) {
        bad("居然接受了自身进程，fd=%d", req.out_fd);
        close(req.out_fd);
    } else
        bad("ret=%d (%s)，期望 -EACCES", ret, strerror(-ret));
}

/* 不存在的 pid 必须被拒绝。 */
static void test_bad_pid(void)
{
    NBG_SENSOR_OPEN_REQ req;
    int ret;

    printf("\n[OP_SENSOR_OPEN] 不存在的 pid\n");

    memset(&req, 0, sizeof(req));
    req.version = NBG_SENSOR_OPEN_ABI_VERSION;
    req.pid = 999999;
    ret = call(OP_SENSOR_OPEN, &req);
    if (ret == -ESRCH)
        ok("正确返回 -ESRCH");
    else
        bad("ret=%d (%s)，期望 -ESRCH", ret, strerror(-ret));
}

/* 布防参数校验：所有用例都传非法参数，驱动应在写任何内存前就拒绝。
 * 这些路径不会修改 system_server 的任何字节。 */
static void test_arm_validation(void)
{
    NBG_SENSOR_OPEN_REQ open_req;
    NBG_SENSOR_ARM_REQ arm;
    unsigned long long base;
    int pid;
    int ret;
    int fd;

    printf("\n[NBG_SENSOR_IOC_ARM] 参数校验（不写入内存）\n");

    pid = find_pid_by_comm("system_server");
    if (pid <= 0) {
        skip("找不到 system_server");
        return;
    }

    memset(&open_req, 0, sizeof(open_req));
    open_req.version = NBG_SENSOR_OPEN_ABI_VERSION;
    open_req.pid = pid;
    ret = call(OP_SENSOR_OPEN, &open_req);
    if (ret) {
        skip("无法打开会话 ret=%d", ret);
        return;
    }
    fd = open_req.out_fd;
    base = open_req.out_module_base;
    printf("       会话 fd=%d base=0x%llx size=0x%llx\n", fd, base,
           (unsigned long long)open_req.out_module_size);

#define ARM_CALL(req, expect, desc)                                        \
    do {                                                                   \
        errno = 0;                                                         \
        ret = ioctl(fd, NBG_SENSOR_IOC_ARM, &(req)) < 0 ? -errno : 0;       \
        if (ret == (expect))                                               \
            ok(desc);                                                      \
        else                                                               \
            bad(desc "：得到 %d (%s)，期望 %d", ret, strerror(-ret),        \
                (expect));                                                 \
    } while (0)

    /* 版本号错误 */
    memset(&arm, 0, sizeof(arm));
    arm.version = NBG_SENSOR_ARM_ABI_VERSION + 1;
    arm.got_addr = base + 0x1000;
    arm.original = base + 0x2000;
    arm.delta_addr = base + 0x3000;
    arm.replacement = arm.delta_addr + 16;
    ARM_CALL(arm, -EINVAL, "版本号错误被拒");

    /* got_addr 未 8 字节对齐 */
    memset(&arm, 0, sizeof(arm));
    arm.version = NBG_SENSOR_ARM_ABI_VERSION;
    arm.got_addr = base + 0x1004;
    arm.original = base + 0x2000;
    arm.delta_addr = base + 0x3000;
    arm.replacement = arm.delta_addr + 16;
    ARM_CALL(arm, -EINVAL, "got_addr 未 8 字节对齐被拒");

    /* delta_addr 未 16 字节对齐 */
    memset(&arm, 0, sizeof(arm));
    arm.version = NBG_SENSOR_ARM_ABI_VERSION;
    arm.got_addr = base + 0x1000;
    arm.original = base + 0x2000;
    arm.delta_addr = base + 0x3008;
    arm.replacement = arm.delta_addr + 16;
    ARM_CALL(arm, -EINVAL, "delta_addr 未 16 字节对齐被拒");

    /* replacement 不等于 delta+16 */
    memset(&arm, 0, sizeof(arm));
    arm.version = NBG_SENSOR_ARM_ABI_VERSION;
    arm.got_addr = base + 0x1000;
    arm.original = base + 0x2000;
    arm.delta_addr = base + 0x3000;
    arm.replacement = arm.delta_addr + 32;
    ARM_CALL(arm, -EINVAL, "replacement 不是 delta+16 被拒");

    /* original 为 0 */
    memset(&arm, 0, sizeof(arm));
    arm.version = NBG_SENSOR_ARM_ABI_VERSION;
    arm.got_addr = base + 0x1000;
    arm.original = 0;
    arm.delta_addr = base + 0x3000;
    arm.replacement = arm.delta_addr + 16;
    ARM_CALL(arm, -EINVAL, "original 为 0 被拒");

    /* original 落在 delta 空穴内 */
    memset(&arm, 0, sizeof(arm));
    arm.version = NBG_SENSOR_ARM_ABI_VERSION;
    arm.got_addr = base + 0x1000;
    arm.delta_addr = base + 0x3000;
    arm.original = arm.delta_addr + 8;
    arm.replacement = arm.delta_addr + 16;
    ARM_CALL(arm, -EINVAL, "original 落在 delta 空穴内被拒");

    /* got_addr 落在 delta 空穴内 */
    memset(&arm, 0, sizeof(arm));
    arm.version = NBG_SENSOR_ARM_ABI_VERSION;
    arm.delta_addr = base + 0x3000;
    arm.got_addr = arm.delta_addr + 8;
    arm.original = base + 0x2000;
    arm.replacement = arm.delta_addr + 16;
    ARM_CALL(arm, -EINVAL, "got_addr 落在 delta 空穴内被拒");

    /* 地址完全在模块范围外 */
    memset(&arm, 0, sizeof(arm));
    arm.version = NBG_SENSOR_ARM_ABI_VERSION;
    arm.delta_addr = 0x10000000UL;
    arm.got_addr = 0x10001000UL;
    arm.original = 0x10002000UL;
    arm.replacement = arm.delta_addr + 16;
    ARM_CALL(arm, -EACCES, "模块范围外地址被拒");

#undef ARM_CALL

    close(fd);
}

int main(void)
{
    printf("========================================\n");
    printf(" NBG 受限写会话验证（不写入任何内存）\n");
    printf("========================================\n");

    if (connect_driver()) {
        printf("[-] 无法连接驱动\n");
        return 1;
    }

    test_open_system_server();
    test_bad_version();
    test_bad_target();
    test_bad_pid();
    test_arm_validation();

    printf("\n========================================\n");
    printf(" 汇总 pass=%d fail=%d skip=%d\n", g_pass, g_fail, g_skip);
    printf("========================================\n");
    if (g_fd >= 0)
        close(g_fd);
    return g_fail ? 1 : 0;
}
