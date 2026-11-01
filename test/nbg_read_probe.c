/* nbg_read_probe - verify the NBG driver channel and read target memory through it.
 *
 * usage: nbg_read_probe <pid> [module] [hex_addr] [size]
 *   - scans socket families for the NBG family
 *   - authenticates with OP_INIT_KEY
 *   - resolves module base with OP_MODULE_BASE
 *   - reads with OP_READ_MEM
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "comm.h"
#include "secret.h"

static int open_nbg(void)
{
    int family;

    for (family = 1; family < 50; family++) {
        INIT_KEY key;
        int fd = socket(family, SOCK_RAW, NBG_SOCKET_PROTOCOL);

        if (fd < 0)
            continue;
        memset(&key, 0, sizeof(key));
        key.abi_version = NBG_ABI_VERSION;
        key.token = NBG_AUTH_TOKEN;
        if (ioctl(fd, OP_INIT_KEY, &key) == 0 && key.accepted == 1U) {
            printf("[+] 驱动已就绪: family=%d abi=%u clients=%u\n",
                   family, key.abi_version, key.authed_clients);
            return fd;
        }
        close(fd);
    }
    printf("[-] 未找到 NBG 驱动通道 (errno=%d %s)\n", errno, strerror(errno));
    return -1;
}

int main(int argc, char **argv)
{
    int fd;
    pid_t pid;
    const char *module;
    unsigned long addr = 0;
    unsigned long size = 16;
    MODULE_BASE base;
    COPY_MEMORY memory;
    unsigned char buffer[4096];
    unsigned long i;

    if (argc < 2) {
        printf("usage: %s <pid> [module] [hex_addr] [size]\n", argv[0]);
        return 1;
    }
    pid = (pid_t)atoi(argv[1]);
    module = argc > 2 ? argv[2] : "libUE4.so";
    if (argc > 3)
        addr = strtoul(argv[3], NULL, 16);
    if (argc > 4)
        size = strtoul(argv[4], NULL, 16);
    if (size > sizeof(buffer))
        size = sizeof(buffer);

    fd = open_nbg();
    if (fd < 0)
        return 1;

    memset(&base, 0, sizeof(base));
    base.pid = pid;
    base.name = (char *)module;
    if (ioctl(fd, OP_MODULE_BASE, &base) != 0) {
        printf("[-] OP_MODULE_BASE 失败: errno=%d (%s)\n", errno, strerror(errno));
        close(fd);
        return 1;
    }
    printf("[+] %s 基址=0x%lx\n", module, (unsigned long)base.base);

    if (addr == 0)
        addr = (unsigned long)base.base;

    memset(buffer, 0, sizeof(buffer));
    memset(&memory, 0, sizeof(memory));
    memory.pid = pid;
    memory.addr = (uintptr_t)addr;
    memory.buffer = buffer;
    memory.size = size;
    if (ioctl(fd, OP_READ_MEM, &memory) != 0) {
        printf("[-] OP_READ_MEM 失败: errno=%d (%s)\n", errno, strerror(errno));
        close(fd);
        return 1;
    }

    printf("[+] 读取 0x%lx + 0x%lx:\n", addr, size);
    for (i = 0; i < size; i++) {
        printf("%02x ", buffer[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    if (size % 16)
        printf("\n");

    close(fd);
    return 0;
}
