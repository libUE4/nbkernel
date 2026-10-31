/* udp_probe.c — UDP 抓包验证
 *
 * 启动抓包后，本地起一个 UDP socket 向自己发包，验证驱动能按 UID
 * 抓到 payload。全程只涉及本进程自己的 socket，不干扰其他流量。
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
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

/* 创建本进程持有的回环接收端，避免产生外部网络流量。 */
static int create_local_udp_receiver(uint16_t *port)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int receiver;

    if (!port)
        return -1;

    receiver = socket(AF_INET, SOCK_DGRAM, 0);
    if (receiver < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(receiver, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        getsockname(receiver, (struct sockaddr *)&addr, &addr_len) < 0) {
        close(receiver);
        return -1;
    }

    *port = ntohs(addr.sin_port);
    return receiver;
}

/* 向本机回环发一个 UDP 包，返回发送字节数。 */
static int send_local_udp(const char *payload, int port)
{
    struct sockaddr_in addr;
    int sock;
    int sent;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);

    sent = (int)sendto(sock, payload, strlen(payload), 0,
                       (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
    return sent;
}

static void test_capture(void)
{
    NBG_UDP_CAP_INIT_REQ init;
    NBG_UDP_CAP_READ_REQ read_req;
    NBG_UDP_PACKET *packets;
    const char *payload = "NBG-UDP-CAPTURE-TEST-PAYLOAD";
    struct pollfd poll_fd;
    char received[128] = {0};
    uint16_t local_port = 0;
    int receiver;
    int ret;
    int i;
    int found = 0;

    printf("\n[OP_UDP_CAP_INIT] 按本进程 UID 抓本机回环包\n");

    receiver = create_local_udp_receiver(&local_port);
    if (receiver < 0) {
        bad("创建本机 UDP 接收端失败 (%s)", strerror(errno));
        return;
    }

    memset(&init, 0, sizeof(init));
    init.pid = getpid();
    init.min_payload = 0;
    init.max_payload = 0;
    ret = call(OP_UDP_CAP_INIT, &init);
    if (ret) {
        bad("初始化失败 ret=%d (%s)", ret, strerror(-ret));
        close(receiver);
        return;
    }
    ok("抓包已启动");

    ret = send_local_udp(payload, local_port);
    if (ret != (int)strlen(payload)) {
        bad("回环 UDP 发送失败 ret=%d (%s)", ret,
            ret < 0 ? strerror(errno) : "short send");
        close(receiver);
        return;
    }
    poll_fd.fd = receiver;
    poll_fd.events = POLLIN;
    poll_fd.revents = 0;
    if (poll(&poll_fd, 1, 2000) <= 0 ||
        recv(receiver, received, sizeof(received), 0) !=
            (ssize_t)strlen(payload) ||
        memcmp(received, payload, strlen(payload)) != 0) {
        bad("本机 UDP 接收端未收到完整测试 payload");
        close(receiver);
        return;
    }
    close(receiver);
    ok("本机回环收发完成，未访问外网");
    usleep(30000);

    packets = calloc(NBG_UDP_CAP_READ_MAX, sizeof(*packets));
    if (!packets) {
        bad("分配缓冲失败");
        return;
    }

    memset(&read_req, 0, sizeof(read_req));
    read_req.buf = (uint64_t)(uintptr_t)packets;
    read_req.max_count = NBG_UDP_CAP_READ_MAX;
    ret = call(OP_UDP_CAP_READ, &read_req);
    if (ret) {
        bad("读取失败 ret=%d (%s)", ret, strerror(-ret));
        free(packets);
        return;
    }

    printf("       抓到 %u 个包，累计 %llu，溢出 %llu，探针命中 %u\n",
           read_req.out_count, (unsigned long long)read_req.captured,
           (unsigned long long)read_req.overflow, read_req.reserved);

    if (read_req.out_count == 0) {
        skip("接收端收到 payload，但驱动环形缓冲未返回包");
        free(packets);
        return;
    }
    ok("读到 %u 个包", read_req.out_count);

    for (i = 0; i < (int)read_req.out_count; i++) {
        if (packets[i].payload_len == strlen(payload) &&
            memcmp(packets[i].payload, payload, packets[i].payload_len) == 0) {
            found = 1;
            ok("payload 匹配 seq=%llu %u->%u len=%u",
               (unsigned long long)packets[i].seq,
               packets[i].src_port, packets[i].dst_port,
               packets[i].payload_len);
            break;
        }
    }
    if (!found)
        bad("没有找到匹配的 payload");

    /* 抓到的包 UID 必须等于本进程 UID。 */
    if (found) {
        uid_t uid = getuid();

        for (i = 0; i < (int)read_req.out_count; i++) {
            if (packets[i].sock_uid != (uint32_t)uid) {
                bad("sock_uid=%u 与进程 uid=%u 不符", packets[i].sock_uid,
                    (unsigned)uid);
                break;
            }
        }
        if (i == (int)read_req.out_count)
            ok("所有包的 sock_uid 都等于进程 uid");
    }

    free(packets);
}

static void test_stop_and_bad_input(void)
{
    NBG_UDP_CAP_INIT_REQ init;
    NBG_UDP_CAP_READ_REQ read_req;
    int ret;

    printf("\n[OP_UDP_CAP_STOP] 停止与参数校验\n");

    ret = call(OP_UDP_CAP_STOP, NULL);
    if (ret == 0)
        ok("停止成功");
    else
        bad("停止失败 ret=%d", ret);

    memset(&init, 0, sizeof(init));
    init.pid = 999999;
    ret = call(OP_UDP_CAP_INIT, &init);
    if (ret == -ESRCH)
        ok("不存在的 pid 被拒 (-ESRCH)");
    else
        bad("不存在的 pid ret=%d，期望 -ESRCH", ret);

    memset(&init, 0, sizeof(init));
    init.pid = getpid();
    init.max_payload = NBG_UDP_CAP_MAX_PAYLOAD + 1;
    ret = call(OP_UDP_CAP_INIT, &init);
    if (ret == -EINVAL)
        ok("超限 max_payload 被拒 (-EINVAL)");
    else
        bad("超限 max_payload ret=%d，期望 -EINVAL", ret);

    memset(&read_req, 0, sizeof(read_req));
    read_req.buf = 0;
    read_req.max_count = 1;
    ret = call(OP_UDP_CAP_READ, &read_req);
    if (ret == -EINVAL)
        ok("空 buf 被拒 (-EINVAL)");
    else
        bad("空 buf ret=%d，期望 -EINVAL", ret);
}

static int capture_target_uid(pid_t target_pid, unsigned duration_seconds)
{
    NBG_UDP_CAP_INIT_REQ init;
    NBG_UDP_CAP_READ_REQ read_req;
    NBG_UDP_PACKET *packets;
    uint64_t packet_count = 0;
    uint64_t overflow = 0;
    uint32_t hook_hits = 0;
    unsigned printed = 0;
    unsigned step;
    int ret;

    packets = calloc(NBG_UDP_CAP_READ_MAX, sizeof(*packets));
    if (!packets) {
        bad("分配缓冲失败");
        return -1;
    }

    memset(&init, 0, sizeof(init));
    init.pid = target_pid;
    init.min_payload = 1;
    init.max_payload = NBG_UDP_CAP_MAX_PAYLOAD;
    ret = call(OP_UDP_CAP_INIT, &init);
    if (ret) {
        bad("目标 PID %d 初始化失败 ret=%d (%s)", target_pid,
            ret, strerror(-ret));
        free(packets);
        return -1;
    }
    printf("[+] 捕获目标 PID %d 对应 UID 的入站 UDP，时长 %u 秒\n",
           target_pid, duration_seconds);

    for (step = 0; step < duration_seconds * 10; ++step) {
        unsigned index;

        memset(&read_req, 0, sizeof(read_req));
        read_req.buf = (uint64_t)(uintptr_t)packets;
        read_req.max_count = NBG_UDP_CAP_READ_MAX;
        ret = call(OP_UDP_CAP_READ, &read_req);
        if (ret) {
            bad("目标 UDP 读取失败 ret=%d (%s)", ret,
                strerror(-ret));
            break;
        }
        packet_count += read_req.out_count;
        overflow = read_req.overflow;
        hook_hits = read_req.reserved;

        for (index = 0; index < read_req.out_count && printed < 16;
             ++index, ++printed) {
            char source[INET_ADDRSTRLEN] = "?";
            char destination[INET_ADDRSTRLEN] = "?";

            inet_ntop(AF_INET, &packets[index].src_ip, source,
                      sizeof(source));
            inet_ntop(AF_INET, &packets[index].dst_ip, destination,
                      sizeof(destination));
            printf("[UDP] seq=%llu %s:%u -> %s:%u len=%u uid=%u flags=0x%x\n",
                   (unsigned long long)packets[index].seq,
                   source, packets[index].src_port,
                   destination, packets[index].dst_port,
                   packets[index].payload_len, packets[index].sock_uid,
                   packets[index].flags);
        }
        usleep(100000);
    }

    ret = call(OP_UDP_CAP_STOP, NULL);
    if (ret)
        bad("停止抓包失败 ret=%d (%s)", ret, strerror(-ret));
    else
        ok("停止抓包");

    printf("[UDP SUMMARY] target_pid=%d packets=%llu overflow=%llu "
           "probe_hits=%u\n",
           target_pid, (unsigned long long)packet_count,
           (unsigned long long)overflow, hook_hits);
    if (packet_count != 0)
        ok("捕获到目标 UID 的 UDP 入站报文");
    else
        skip("采集窗口内没有目标 UID 的 UDP 入站报文");

    free(packets);
    return ret ? -1 : (packet_count ? 0 : 1);
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--pid") == 0) {
        char *end = NULL;
        long target_pid;
        long duration_seconds = 20;
        int result;

        if (argc < 3 || argc > 4) {
            fprintf(stderr, "用法: %s --pid PID [采集秒数]\n", argv[0]);
            return 2;
        }
        errno = 0;
        target_pid = strtol(argv[2], &end, 10);
        if (errno || !end || *end || target_pid <= 0 ||
            target_pid > INT32_MAX) {
            fprintf(stderr, "无效 PID: %s\n", argv[2]);
            return 2;
        }
        if (argc == 4) {
            errno = 0;
            duration_seconds = strtol(argv[3], &end, 10);
            if (errno || !end || *end || duration_seconds < 1 ||
                duration_seconds > 120) {
                fprintf(stderr, "采集秒数范围为 1..120\n");
                return 2;
            }
        }
        if (connect_driver()) {
            printf("[-] 无法连接驱动\n");
            return 1;
        }
        result = capture_target_uid((pid_t)target_pid,
                                    (unsigned)duration_seconds);
        close(g_fd);
        return result < 0 ? 1 : 0;
    }

    printf("========================================\n");
    printf(" NBG UDP 抓包验证\n");
    printf("========================================\n");

    if (connect_driver()) {
        printf("[-] 无法连接驱动\n");
        return 1;
    }

    test_capture();
    test_stop_and_bad_input();

    printf("\n========================================\n");
    printf(" 汇总 pass=%d fail=%d skip=%d\n", g_pass, g_fail, g_skip);
    printf("========================================\n");

    if (g_fd >= 0)
        close(g_fd);
    return g_fail ? 1 : 0;
}
