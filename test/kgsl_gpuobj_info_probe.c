#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "comm.h"

_Static_assert(sizeof(KgslGpuObjectInfo) == 48, "KGSL output ABI");
_Static_assert(sizeof(KgslGpuObjectInfoReq) == 80, "NBG request ABI");

static int connect_driver(void)
{
    for (int family = 1; family < 50; ++family) {
        int fd = socket(family, SOCK_RAW | SOCK_CLOEXEC, NBG_SOCKET_PROTOCOL);
        INIT_KEY key = {NBG_ABI_VERSION, NBG_AUTH_TOKEN, 0, 0, 0};
        if (fd < 0)
            continue;
        if (ioctl(fd, OP_INIT_KEY, &key) == 0 && key.accepted == 1 &&
            key.family == (uint32_t)family)
            return fd;
        close(fd);
    }
    return -1;
}

int main(int argc, char **argv)
{
    KgslGpuObjectInfoReq req = {0};
    char *end;
    unsigned long object;
    if (argc != 4) {
        fprintf(stderr, "usage: %s PID TARGET_FD OBJECT_ID\n", argv[0]);
        return 2;
    }
    req.abi_version = NBG_KGSL_GPUOBJ_INFO_ABI_VERSION;
    req.pid = (int32_t)strtol(argv[1], &end, 10);
    if (*end || req.pid <= 0)
        return 2;
    req.target_fd = (int32_t)strtol(argv[2], &end, 0);
    if (*end || req.target_fd < 0)
        return 2;
    object = strtoul(argv[3], &end, 0);
    if (*end || !object || object > UINT32_MAX)
        return 2;
    req.object_id = (uint32_t)object;
    int fd = connect_driver();
    if (fd < 0) {
        fprintf(stderr, "driver unavailable: %s\n", strerror(errno));
        return 3;
    }
    int rc = ioctl(fd, OP_KGSL_GPUOBJ_INFO, &req);
    int saved = errno;
    close(fd);
    if (rc != 0) {
        fprintf(stderr, "metadata bridge failed: errno=%d (%s)\n",
                saved, strerror(saved));
        return 4;
    }
    printf("GPU_INFO pid=%d fd=%d object=0x%x result=%" PRId64
           " gpu=0x%" PRIx64 " flags=0x%" PRIx64 " size=0x%" PRIx64
           " virtual_length=0x%" PRIx64 " virtual_address=0x%" PRIx64
           " returned_id=0x%x sampled_ns=%" PRIu64 "\n",
           req.pid, req.target_fd, req.object_id, req.result,
           req.info.gpu_address, req.info.flags, req.info.size,
           req.info.virtual_length, req.info.virtual_address, req.info.id,
           req.sample_ns);
    return 0;
}
