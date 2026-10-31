/* Restore the NBG module to the kernel module list before a hot reload. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../secret.h"
#include "comm.h"

int main(void)
{
    int family;

    for (family = 1; family < 50; family++) {
        INIT_KEY key = {
            .abi_version = NBG_ABI_VERSION,
            .token = NBG_AUTH_TOKEN,
        };
        int fd = socket(family, SOCK_RAW, NBG_SOCKET_PROTOCOL);

        if (fd < 0)
            continue;
        if (ioctl(fd, OP_INIT_KEY, &key) == 0 && key.accepted == 1U) {
            if (ioctl(fd, OP_UNHIDE_MODULE, NULL) != 0) {
                fprintf(stderr, "UNHIDE=FAIL errno=%d (%s)\n",
                        errno, strerror(errno));
                close(fd);
                return 1;
            }
            printf("UNHIDE=PASS family=%d\n", family);
            close(fd);
            return 0;
        }
        close(fd);
    }

    fprintf(stderr, "AUTH=FAIL errno=%d (%s)\n", errno, strerror(errno));
    return 1;
}
