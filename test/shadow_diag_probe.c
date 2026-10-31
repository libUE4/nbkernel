/* Read-only shadow-hook state query for one PID. */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../secret.h"
#include "comm.h"

static int open_driver(void)
{
    for (int family = 1; family < 50; family++) {
        INIT_KEY key = { .abi_version = NBG_ABI_VERSION,
                         .token = NBG_AUTH_TOKEN };
        int fd = socket(family, SOCK_RAW, NBG_SOCKET_PROTOCOL);
        if (fd < 0)
            continue;
        if (ioctl(fd, OP_INIT_KEY, &key) == 0 && key.accepted == 1U)
            return fd;
        close(fd);
    }
    return -1;
}

int main(int argc, char **argv)
{
    int fd = open_driver();
    ShadowDiag diag;
    int pid = argc > 1 ? atoi(argv[1]) : 0;

    if (fd < 0) {
        printf("auth=FAIL errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    memset(&diag, 0, sizeof(diag));
    diag.abi_version = NBG_SHADOW_DIAG_ABI_VERSION;
    diag.pid = pid;
    if (ioctl(fd, OP_SHADOW_DIAG, &diag) != 0) {
        printf("diag=FAIL pid=%d errno=%d (%s)\n", pid, errno,
               strerror(errno));
        close(fd);
        return 1;
    }
    printf("diag=PASS pid=%d case38=%u hits=%" PRIu64
           " captures=%" PRIu64 " attempts=%" PRIu64
           " successes=%" PRIu64 "\n",
           pid, diag.case38_active, diag.case38_hits,
           diag.case38_captures, diag.spread_comp_attempts,
           diag.spread_comp_successes);
    close(fd);
    return 0;
}
