/* Read-only EL1 debug-feature capability query through the NBG socket ABI. */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define NBG_ABI_VERSION           1U
#define NBG_AUTH_TOKEN            0x8A27C440u
#define NBG_SOCKET_PROTOCOL       0x4E47
#define OP_INIT_KEY               0x900
#define OP_HWBP_CAPS              0x935
#define NBG_HWBP_CAPS_ABI_VERSION 1U
#define NBG_HWBP_CAPS_FLAG_ABLE   (1U << 0)

struct init_key {
    uint32_t abi_version;
    uint32_t token;
    uint32_t accepted;
    uint32_t family;
    uint32_t authed_clients;
};

struct hwbp_caps {
    uint32_t abi_version;
    uint32_t flags;
    uint64_t dfr0;
    uint64_t dfr1;
    uint32_t physical_breakpoints;
    uint32_t physical_watchpoints;
    uint32_t usable_breakpoints;
    uint32_t usable_watchpoints;
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
        struct hwbp_caps caps = {
            .abi_version = NBG_HWBP_CAPS_ABI_VERSION,
        };
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
        if (ioctl(fd, OP_HWBP_CAPS, &caps) != 0) {
            last_error = errno;
            close(fd);
            if (last_error == ENOTTY) {
                fputs("loaded module does not implement OP_HWBP_CAPS\n", stderr);
                return 2;
            }
            continue;
        }

        printf("family=%d physical=%uBP/%uWP usable=%uBP/%uWP\n", family,
               caps.physical_breakpoints, caps.physical_watchpoints,
               caps.usable_breakpoints, caps.usable_watchpoints);
        printf("DFR0=0x%016" PRIx64 " DFR1=0x%016" PRIx64
               " ABLE=%u range-bp=%s\n",
               caps.dfr0, caps.dfr1, (unsigned)((caps.dfr1 >> 40) & 0xfU),
               (caps.flags & NBG_HWBP_CAPS_FLAG_ABLE) ? "advertised" : "not-advertised");
        close(fd);
        return 0;
    }

    errno = last_error;
    perror("NBG OP_HWBP_CAPS");
    return 1;
}
