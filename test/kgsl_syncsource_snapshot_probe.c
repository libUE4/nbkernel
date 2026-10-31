#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "comm.h"

static int connect_driver(void)
{
    int family;

    for (family = 1; family < 50; ++family) {
        INIT_KEY key = {
            .abi_version = NBG_ABI_VERSION,
            .token = NBG_AUTH_TOKEN,
        };
        int fd = socket(family, SOCK_RAW, NBG_SOCKET_PROTOCOL);

        if (fd < 0)
            continue;
        if (ioctl(fd, OP_INIT_KEY, &key) == 0 && key.accepted == 1U) {
            printf("AUTH family=%d clients=%u\n", family,
                   key.authed_clients);
            return fd;
        }
        close(fd);
    }
    return -1;
}

int main(int argc, char **argv)
{
    KgslSyncsourceSnapshotReq request = {
        .abi_version = NBG_KGSL_SYNCSOURCE_ABI_VERSION,
        .max_id = 130,
    };
    int fd;
    unsigned int id;

    if (argc != 2 || sscanf(argv[1], "%d", &request.pid) != 1 ||
        request.pid <= 0) {
        fprintf(stderr, "usage: %s PID\n", argv[0]);
        return 2;
    }

    fd = connect_driver();
    if (fd < 0) {
        fprintf(stderr, "AUTH failed: errno=%d (%s)\n", errno,
                strerror(errno));
        return 1;
    }
    if (ioctl(fd, OP_KGSL_SYNCSOURCE_SNAPSHOT, &request) != 0) {
        fprintf(stderr, "SNAPSHOT failed: errno=%d (%s)\n", errno,
                strerror(errno));
        close(fd);
        return 1;
    }
    close(fd);

    printf("SNAPSHOT pid=%d max=%u flags=0x%x occupied=%u first_free=%u "
           "idr=0x%x lock=0x%x sample_ns=%" PRIu64 "\n",
           request.pid, request.max_id, request.flags,
           request.occupied_count, request.first_free,
           request.idr_offset, request.lock_offset, request.sample_ns);
    printf("WORDS %016" PRIx64 " %016" PRIx64 " %016" PRIx64
           " %016" PRIx64 "\n",
           request.occupied[0], request.occupied[1],
           request.occupied[2], request.occupied[3]);
    printf("IDS");
    for (id = 1; id <= request.max_id; ++id) {
        if (request.occupied[(id - 1U) >> 6] &
            (1ULL << ((id - 1U) & 63U)))
            printf(" %u", id);
    }
    printf("\n");

    return (request.flags & NBG_KGSL_SYNCSOURCE_LAYOUT_VERIFIED) ? 0 : 1;
}
