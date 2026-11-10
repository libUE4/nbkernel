#include <cerrno>
#include <cstdio>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "comm.h"

int main()
{
    for (int family = 1; family < 50; ++family) {
        const int fd = socket(family, SOCK_RAW | SOCK_CLOEXEC,
                              NBG_SOCKET_PROTOCOL);
        if (fd < 0)
            continue;
        INIT_KEY key{};
        key.abi_version = NBG_ABI_VERSION;
        key.token = NBG_AUTH_TOKEN;
        if (ioctl(fd, OP_INIT_KEY, &key) != 0 || !key.accepted) {
            close(fd);
            continue;
        }
        const int ret = ioctl(fd, OP_UNHIDE_MODULE, nullptr);
        const int error = errno;
        close(fd);
        if (ret != 0) {
            errno = error;
            std::perror("unhide NBG module");
            return 1;
        }
        std::printf("unhide requested through authenticated family %d\n",
                    family);
        return 0;
    }
    std::fprintf(stderr, "no authenticated NBG family\n");
    return 1;
}
