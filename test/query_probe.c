/* query_probe.c — 查询接口验证程序
 *
 * 连上驱动的 socket family 后，逐项调用 OP_GET_PID / OP_GET_PIDS /
 * OP_MODULE_BASE_EX / OP_MODULE_BASE2_EX / OP_MODULE_PATH_EX / OP_GET_TLS /
 * OP_GET_THREAD_TID / OP_GET_THREAD_TIDS / OP_GET_THREAD_STACK /
 * OP_QUERY_MAPPING / OP_QUERY_ACCESS / OP_QUERY_SIGNAL，并打印结果。
 *
 * 用法: query_probe [包名]   默认 com.tencent.tmgp.dfm
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "comm.h"
static int g_pass, g_fail, g_skip;

static void ok(const char *fmt, ...)
{
    va_list ap;

    g_pass++;
    printf("  \033[32mPASS\033[0m ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static void bad(const char *fmt, ...)
{
    va_list ap;

    g_fail++;
    printf("  \033[31mFAIL\033[0m ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static void skip(const char *fmt, ...)
{
    va_list ap;

    g_skip++;
    printf("  \033[90mSKIP\033[0m ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static int g_fd = -1;

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
            printf("[+] 已连接 family=%d authed=%u\n", family,
                   init.authed_clients);
            return 0;
        }
        close(fd);
    }
    return -1;
}

static int find_pid(const char *name)
{
    NBG_GET_PID_REQ req;
    int ret;

    memset(&req, 0, sizeof(req));
    snprintf(req.name, sizeof(req.name), "%s", name);
    ret = call(OP_GET_PID, &req);
    if (ret)
        return -1;
    return req.out_pid;
}

static int find_thread(const char *comm)
{
    NBG_GET_THREAD_TID_REQ req;
    int pid = find_pid("MainThread-UE4");

    if (pid <= 0)
        return -1;

    memset(&req, 0, sizeof(req));
    req.pid = pid;
    snprintf(req.comm, sizeof(req.comm), "%s", comm);
    if (call(OP_GET_THREAD_TID, &req))
        return -1;
    return req.out_tid;
}

static unsigned long long find_module_base(const char *name)
{
    NBG_MODULE_BASE_REQ req;
    int pid = find_pid("MainThread-UE4");

    if (pid <= 0)
        return 0;

    memset(&req, 0, sizeof(req));
    req.pid = pid;
    snprintf(req.name, sizeof(req.name), "%s", name);
    if (call(OP_MODULE_BASE_EX, &req))
        return 0;
    return req.out_base;
}

static void test_get_pid(const char *comm)
{
    NBG_GET_PID_REQ req;
    int ret;

    printf("\n[OP_GET_PID] comm=%s\n", comm);
    memset(&req, 0, sizeof(req));
    snprintf(req.name, sizeof(req.name), "%s", comm);
    ret = call(OP_GET_PID, &req);
    if (ret == 0)
        ok("out_pid=%d", req.out_pid);
    else if (ret == -ESRCH)
        skip("该 comm 无匹配进程 (%d)", ret);
    else
        bad("ret=%d (%s)", ret, strerror(-ret));
}

static void test_get_pids(const char *comm)
{
    NBG_GET_PIDS_REQ req;
    int ret;
    uint32_t i;

    printf("\n[OP_GET_PIDS] comm=%s\n", comm);
    memset(&req, 0, sizeof(req));
    snprintf(req.name, sizeof(req.name), "%s", comm);
    ret = call(OP_GET_PIDS, &req);
    if (ret == -ESRCH) {
        skip("无匹配进程");
        return;
    }
    if (ret) {
        bad("ret=%d (%s)", ret, strerror(-ret));
        return;
    }
    ok("count=%u total=%u", req.out_count, req.out_total);
    for (i = 0; i < req.out_count && i < 8; i++)
        printf("       pid[%u]=%d\n", i, req.out_pids[i]);
}

static void test_module(const char *name, int pid)
{
    NBG_MODULE_BASE_REQ req;
    NBG_MODULE_BASE2_REQ req2;
    NBG_MODULE_PATH_REQ reqp;
    int ret;

    printf("\n[OP_MODULE_BASE_EX] name=%s pid=%d\n", name, pid);
    memset(&req, 0, sizeof(req));
    req.pid = pid;
    snprintf(req.name, sizeof(req.name), "%s", name);
    ret = call(OP_MODULE_BASE_EX, &req);
    if (ret == 0)
        ok("base=0x%llx size=0x%llx",
           (unsigned long long)req.out_base,
           (unsigned long long)req.out_size);
    else if (ret == -ENOENT)
        skip("该模块未映射");
    else
        bad("ret=%d (%s)", ret, strerror(-ret));

    printf("\n[OP_MODULE_BASE2_EX] name=%s max_vma=0x1000000\n", name);
    memset(&req2, 0, sizeof(req2));
    req2.pid = pid;
    req2.max_vma_size = 0x1000000;
    snprintf(req2.name, sizeof(req2.name), "%s", name);
    ret = call(OP_MODULE_BASE2_EX, &req2);
    if (ret == 0)
        ok("base=0x%llx size=0x%llx",
           (unsigned long long)req2.out_base,
           (unsigned long long)req2.out_size);
    else if (ret == -ENOENT)
        skip("限长后无匹配 VMA");
    else
        bad("ret=%d (%s)", ret, strerror(-ret));

    printf("\n[OP_MODULE_PATH_EX] name=%s\n", name);
    memset(&reqp, 0, sizeof(reqp));
    reqp.pid = pid;
    snprintf(reqp.name, sizeof(reqp.name), "%s", name);
    ret = call(OP_MODULE_PATH_EX, &reqp);
    if (ret == 0)
        ok("path=%s", reqp.out_path);
    else if (ret == -ENOENT)
        skip("未找到");
    else
        bad("ret=%d (%s)", ret, strerror(-ret));
}

static void test_tls(int pid)
{
    NBG_GET_TLS_REQ req;
    int ret;

    printf("\n[OP_GET_TLS] pid=%d\n", pid);
    memset(&req, 0, sizeof(req));
    req.pid = pid;
    ret = call(OP_GET_TLS, &req);
    if (ret == 0)
        ok("tls=0x%llx", (unsigned long long)req.out_tls);
    else
        bad("ret=%d (%s)", ret, strerror(-ret));
}

static void test_threads(int pid, const char *comm)
{
    NBG_GET_THREAD_TID_REQ req;
    NBG_GET_THREAD_TIDS_REQ reqs;
    int ret;
    uint32_t i;

    printf("\n[OP_GET_THREAD_TID] pid=%d comm=%s\n", pid, comm);
    memset(&req, 0, sizeof(req));
    req.pid = pid;
    snprintf(req.comm, sizeof(req.comm), "%s", comm);
    ret = call(OP_GET_THREAD_TID, &req);
    if (ret == 0)
        ok("best_tid=%d", req.out_tid);
    else if (ret == -ESRCH)
        skip("无该名字线程");
    else
        bad("ret=%d (%s)", ret, strerror(-ret));

    printf("\n[OP_GET_THREAD_TIDS] pid=%d comm=%s\n", pid, comm);
    memset(&reqs, 0, sizeof(reqs));
    reqs.pid = pid;
    snprintf(reqs.comm, sizeof(reqs.comm), "%s", comm);
    ret = call(OP_GET_THREAD_TIDS, &reqs);
    if (ret == -ESRCH) {
        skip("无该名字线程");
        return;
    }
    if (ret) {
        bad("ret=%d (%s)", ret, strerror(-ret));
        return;
    }
    ok("count=%u total=%u", reqs.out_count, reqs.out_total);
    for (i = 0; i < reqs.out_count && i < 6; i++)
        printf("       tid=%d flags=0x%x exec_ns=%llu\n",
               reqs.out_threads[i].tid, reqs.out_threads[i].flags,
               (unsigned long long)reqs.out_threads[i].exec_ns);
}

static void test_stack(int tid)
{
    NBG_GET_THREAD_STACK_REQ req;
    int ret;

    printf("\n[OP_GET_THREAD_STACK] tid=%d\n", tid);
    memset(&req, 0, sizeof(req));
    req.tid = tid;
    ret = call(OP_GET_THREAD_STACK, &req);
    if (ret == 0)
        ok("named=%d low=0x%llx high=0x%llx tls=0x%llx", req.out_named,
           (unsigned long long)req.out_low,
           (unsigned long long)req.out_high,
           (unsigned long long)req.out_tls);
    else if (ret == -ENOENT || ret == -EOPNOTSUPP)
        skip("ret=%d (%s)", ret, strerror(-ret));
    else
        bad("ret=%d (%s)", ret, strerror(-ret));
}

static void test_mapping(int pid, unsigned long long addr,
                         unsigned long long unmapped)
{
    NBG_QUERY_MAPPING_REQ req;
    NBG_QUERY_ACCESS_REQ reqa;
    int ret;

    printf("\n[OP_QUERY_MAPPING] pid=%d addr=0x%llx\n", pid, addr);
    memset(&req, 0, sizeof(req));
    req.pid = pid;
    req.addr = addr;
    ret = call(OP_QUERY_MAPPING, &req);
    if (ret == 0)
        ok("phys=0x%llx page=0x%llx flags=0x%x",
           (unsigned long long)req.out_phys_addr,
           (unsigned long long)req.out_page_size, req.out_flags);
    else
        bad("ret=%d (%s)", ret, strerror(-ret));

    printf("\n[OP_QUERY_ACCESS] pid=%d addr=0x%llx\n", pid, addr);
    memset(&reqa, 0, sizeof(reqa));
    reqa.pid = pid;
    reqa.addr = addr;
    ret = call(OP_QUERY_ACCESS, &reqa);
    if (ret == 0)
        ok("range=0x%llx..0x%llx perm=0x%x state=%u",
           (unsigned long long)reqa.out_start,
           (unsigned long long)reqa.out_end, reqa.out_permissions,
           reqa.out_state);
    else
        bad("ret=%d (%s)", ret, strerror(-ret));

    /* 未映射地址应当两个接口都明确报错，而不是给出伪造结果。 */
    printf("\n[OP_QUERY_MAPPING] 未映射对照 addr=0x%llx\n", unmapped);
    memset(&req, 0, sizeof(req));
    req.pid = pid;
    req.addr = unmapped;
    ret = call(OP_QUERY_MAPPING, &req);
    if (ret == -ENOENT)
        ok("正确返回 -ENOENT");
    else if (ret == 0)
        bad("未映射地址却返回 phys=0x%llx",
            (unsigned long long)req.out_phys_addr);
    else
        bad("ret=%d (%s)", ret, strerror(-ret));

    printf("\n[OP_QUERY_ACCESS] 未映射对照 addr=0x%llx\n", unmapped);
    memset(&reqa, 0, sizeof(reqa));
    reqa.pid = pid;
    reqa.addr = unmapped;
    ret = call(OP_QUERY_ACCESS, &reqa);
    if (ret == 0 && reqa.out_state == NBG_ACCESS_UNMAPPED)
        ok("正确返回 UNMAPPED");
    else if (ret == 0)
        bad("state=%u 期望 UNMAPPED", reqa.out_state);
    else
        bad("ret=%d (%s)", ret, strerror(-ret));
}

static void test_signal(int tid, int signo)
{
    NBG_QUERY_SIGNAL_REQ req;
    int ret;

    printf("\n[OP_QUERY_SIGNAL] tid=%d signo=%d\n", tid, signo);
    memset(&req, 0, sizeof(req));
    req.tid = tid;
    req.signo = signo;
    ret = call(OP_QUERY_SIGNAL, &req);
    if (ret == 0)
        ok("handler=0x%llx flags=0x%llx blocked=0x%llx tgid=%d",
           (unsigned long long)req.out_handler,
           (unsigned long long)req.out_flags,
           (unsigned long long)req.out_blocked, req.out_tgid);
    else
        bad("ret=%d (%s)", ret, strerror(-ret));
}


static void test_pacga(int pid)
{
    NBG_PACGA_REQ req;
    int ret;

    printf("\n[OP_EXECUTE_PACGA] pid=%d\n", pid);

    memset(&req, 0, sizeof(req));
    req.pid = pid;
    req.data = 0x1122334455667788ULL;
    req.modifier = 0x99AABBCCDDEEFF00ULL;
    ret = call(OP_EXECUTE_PACGA, &req);
    if (ret) {
        bad("ret=%d (%s)", ret, strerror(-ret));
        return;
    }

    if (!req.out_supported) {
        skip("内核未开指针认证或硬件无 generic-auth");
        return;
    }
    ok("result=0x%016llx", (unsigned long long)req.out_result);

    {
        NBG_PACGA_REQ again;

        memset(&again, 0, sizeof(again));
        again.pid = pid;
        again.data = req.data;
        again.modifier = req.modifier;
        if (call(OP_EXECUTE_PACGA, &again) == 0 &&
            again.out_supported && again.out_result == req.out_result)
            ok("重复调用结果一致");
        else
            bad("重复调用结果不一致");
    }

    {
        NBG_PACGA_REQ diff;

        memset(&diff, 0, sizeof(diff));
        diff.pid = pid;
        diff.data = req.data;
        diff.modifier = req.modifier ^ 0xFFULL;
        if (call(OP_EXECUTE_PACGA, &diff) == 0 && diff.out_supported &&
            diff.out_result != req.out_result)
            ok("修改 modifier 后结果变化");
        else
            bad("修改 modifier 后结果未变");
    }
}

int main(int argc, char **argv)
{
    const char *pkg = argc > 1 ? argv[1] : "com.tencent.tmgp.dfm";
    char comm[64];
    int pid = -1;

    printf("========================================\n");
    printf(" NBG 查询接口验证\n");
    printf("========================================\n");
    printf("目标包名: %s\n", pkg);

    if (connect_driver()) {
        printf("[-] 无法连接驱动\n");
        printf("    token=0x%08X abi=%u\n", (unsigned)NBG_AUTH_TOKEN,
               (unsigned)NBG_ABI_VERSION);
        printf("    确认已 insmod，且测试程序与驱动使用同一份 secret.h\n");
        return 1;
    }

    /* 游戏进程 comm 被 Android 截断到 15 字节 */
    snprintf(comm, sizeof(comm), "%s", pkg);
    if (strlen(comm) > 15)
        memmove(comm, comm + 1, strlen(comm));

    pid = find_pid(pkg);
    if (pid <= 0) {
        snprintf(comm, sizeof(comm), "%.15s", pkg);
        pid = find_pid(comm);
    }
    /* UE4 游戏的 comm 常为 MainThread-UE4，不跟随包名。 */
    if (pid <= 0) {
        pid = find_pid("MainThread-UE4");
        if (pid > 0)
            snprintf(comm, sizeof(comm), "%s", "MainThread-UE4");
    }
    if (pid <= 0) {
        printf("[-] 找不到 %s 的进程，跳过依赖 pid 的用例\n", pkg);
        test_get_pid("MainThread-UE4");
        test_get_pids("MainThread-UE4");
        goto done;
    }
    printf("[+] 目标 pid=%d\n", pid);

    test_get_pid(comm);
    test_get_pids(comm);
    test_module("libUE4.so", pid);
    test_tls(pid);
    test_threads(pid, "MainThread-UE4");
    test_threads(pid, "GameThread");
    /* 子线程栈走 Bionic 的 stack_and_tls:<tid> 命名，主线程不走。 */
    test_stack(find_thread("GameThread"));
    /* 用模块真实基址，而不是肯定未映射的 0x400000。 */
    test_mapping(pid, find_module_base("libUE4.so"), 0x400000ULL);
    test_signal(pid, 11);
    test_pacga(pid);

done:
    printf("\n========================================\n");
    printf(" 汇总 pass=%d fail=%d skip=%d\n", g_pass, g_fail, g_skip);
    printf("========================================\n");
    if (g_fd >= 0)
        close(g_fd);
    return g_fail ? 1 : 0;
}
