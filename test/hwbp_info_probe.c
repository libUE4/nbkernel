/* Read-only probe for the NBG hardware-breakpoint capacity ioctl. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define NBG_ABI_VERSION      1U
#define NBG_AUTH_TOKEN       0x8A27C440u
#define NBG_SOCKET_PROTOCOL  0x4E47
#define OP_INIT_KEY          0x900
#define OP_HWBP_INFO         0x91C

struct init_key {
    uint32_t abi_version;
    uint32_t token;
    uint32_t accepted;
    uint32_t family;
    uint32_t authed_clients;
};

struct hwbp_info {
    uint64_t breakpoints;
    uint64_t watchpoints;
};

int main(void)
{
    int family;
    int last_error = ENODEV;

    for (family = 1; family < 50; ++family) {
        struct init_key key = {
            .abi_version = NBG_ABI_VERSION,
            .token = NBG_AUTH_TOKEN,
        };
        struct hwbp_info info = {0};
        int fd = socket(family, SOCK_RAW, NBG_SOCKET_PROTOCOL);

        if (fd < 0) {
            last_error = errno;
            continue;
        }
        if (ioctl(fd, OP_INIT_KEY, &key) != 0 || key.accepted != 1) {
            last_error = errno;
            close(fd);
            continue;
        }
        if (ioctl(fd, OP_HWBP_INFO, &info) != 0) {
            last_error = errno;
            close(fd);
            continue;
        }

        printf("family=%d brps=%llu wrps=%llu auth_clients=%u\n", family,
               (unsigned long long)info.breakpoints,
               (unsigned long long)info.watchpoints, key.authed_clients);
        close(fd);
        return 0;
    }

    errno = last_error;
    perror("NBG OP_HWBP_INFO");
    return 1;
}
