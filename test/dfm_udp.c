/* dfm_udp.c — 抓取 DFM 的 UDP 报文
 *
 * 按目标进程 UID 过滤，持续读环形缓冲并打印报文摘要与 payload 前若干字节。
 * 只读旁路，不修改报文，不影响游戏网络。
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
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

#define DEFAULT_PKG "com.tencent.tmgp.dfm"
#define MAX_PACKETS 32

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
            return 0;
        }
        close(fd);
    }
    return -1;
}

/* 用驱动自己的进程查询接口拿 pid。
 * 注意：这个接口按 task comm 匹配，而 UE4 游戏的 comm 是线程名
 * （如 MainThread-UE4），不是包名，所以包名往往查不到。 */
static int find_pid(const char *name)
{
    FIND_PID_REQ req;
    int ret;

    memset(&req, 0, sizeof(req));
    req.name = (char *)name;
    req.pid = 0;
    ret = call(OP_FIND_PID, &req);
    if (ret)
        return -1;
    return req.pid;
}

static void hexdump(const uint8_t *data, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i & 15) == 15 && i + 1 < len)
            printf(" ");
    }
}

static void print_ascii(const uint8_t *data, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        uint8_t c = data[i];

        putchar((c >= 32 && c < 127) ? c : '.');
    }
}

int main(int argc, char **argv)
{
    const char *pkg = (argc > 1) ? argv[1] : DEFAULT_PKG;
    int duration = (argc > 2) ? atoi(argv[2]) : 20;    NBG_UDP_CAP_INIT_REQ init;
    NBG_UDP_CAP_READ_REQ read_req;
    NBG_UDP_PACKET *packets;
    int pid;
    int ret;
    int total = 0;
    time_t deadline;

    printf("========================================\n");
    printf(" DFM UDP 抓包\n");
    printf("========================================\n");

    if (connect_driver()) {
        printf("[-] 无法连接驱动\n");
        return 1;
    }

    pid = find_pid(pkg);
    if (pid <= 0) {
        /* 参数可以直接给 pid：UE4 进程的 comm 是线程名，不是包名。 */
        pid = atoi(pkg);
        if (pid <= 0) {
            printf("[-] 找不到进程 %s，且参数不是 pid\n", pkg);
            close(g_fd);
            return 1;
        }
    }
    printf("[+] pid=%d\n", pid);

    memset(&init, 0, sizeof(init));
    init.pid = pid;
    init.min_payload = 0;
    init.max_payload = 0;
    ret = call(OP_UDP_CAP_INIT, &init);
    if (ret) {
        printf("[-] 启动抓包失败 ret=%d (%s)\n", ret, strerror(-ret));
        close(g_fd);
        return 1;
    }
    printf("[+] 抓包已启动，持续 %d 秒\n\n", duration);

    packets = calloc(MAX_PACKETS, sizeof(*packets));
    if (!packets) {
        printf("[-] 分配缓冲失败\n");
        call(OP_UDP_CAP_STOP, NULL);
        close(g_fd);
        return 1;
    }

    deadline = time(NULL) + duration;
    while (time(NULL) < deadline) {
        uint32_t i;

        memset(&read_req, 0, sizeof(read_req));
        read_req.buf = (uint64_t)(uintptr_t)packets;
        read_req.max_count = MAX_PACKETS;
        ret = call(OP_UDP_CAP_READ, &read_req);
        if (ret) {
            printf("[-] 读取失败 ret=%d (%s)\n", ret, strerror(-ret));
            break;
        }
        if (read_req.out_count == 0) {
            usleep(100000);
            continue;
        }

        for (i = 0; i < read_req.out_count; i++) {
            NBG_UDP_PACKET *p = &packets[i];
            struct in_addr src = { .s_addr = p->src_ip };
            struct in_addr dst = { .s_addr = p->dst_ip };
            int show = p->payload_len > 48 ? 48 : p->payload_len;

            total++;
            printf("#%llu %s:%u -> %s:%u len=%u%s\n",
                   (unsigned long long)p->seq,
                   inet_ntoa(src), p->src_port,
                   inet_ntoa(dst), p->dst_port,
                   p->payload_len,
                   (p->flags & NBG_UDP_CAP_F_TRUNC) ? " TRUNC" : "");
            printf("    hex: ");
            hexdump(p->payload, show);
            printf("\n    txt: ");
            print_ascii(p->payload, show);
            printf("\n");
        }
    }

    printf("\n[+] 共抓 %d 个包，累计 %llu，溢出 %llu，探针命中 %u\n",
           total, (unsigned long long)read_req.captured,
           (unsigned long long)read_req.overflow, read_req.reserved);

    call(OP_UDP_CAP_STOP, NULL);
    free(packets);
    close(g_fd);
    return 0;
}
