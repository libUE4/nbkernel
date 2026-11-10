#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "comm.h"

static int connect_nbg()
{
    int opened = 0;
    int last_socket_errno = 0;
    int last_init_errno = 0;
    int init_responses = 0;
    for (int family = 1; family < 50; ++family) {
        const int fd = socket(family, SOCK_RAW, NBG_SOCKET_PROTOCOL);
        if (fd < 0) {
            last_socket_errno = errno;
            continue;
        }
        ++opened;
        INIT_KEY key{};
        key.abi_version = NBG_ABI_VERSION;
        key.token = NBG_AUTH_TOKEN;
        if (ioctl(fd, OP_INIT_KEY, &key) == 0) {
            ++init_responses;
            if (key.accepted) {
                std::printf("NBG family=%d accepted=%u reported=%u\n",
                            family, key.accepted, key.family);
                return fd;
            }
        } else {
            last_init_errno = errno;
        }
        if (errno != 0)
            std::fprintf(stderr, "family=%d init errno=%d accepted=%u reported=%u\n",
                         family, errno, key.accepted, key.family);
        close(fd);
    }
    std::fprintf(stderr,
                 "NBG unavailable opened=%d responses=%d socket_errno=%d init_errno=%d\n",
                 opened, init_responses, last_socket_errno, last_init_errno);
    return -1;
}

static void print_bytes(const uint8_t *bytes, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        std::printf("%02x", bytes[i]);
    std::putchar('\n');
}

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 4) {
        std::fprintf(stderr, "usage: %s PID LIBUE4_BASE [eor|cache]\n", argv[0]);
        return 2;
    }
    const int pid = std::atoi(argv[1]);
    const uint64_t base = std::strtoull(argv[2], nullptr, 0);
    const bool cache_probe = argc == 4 && std::strcmp(argv[3], "cache") == 0;
    if (argc == 4 && !cache_probe && std::strcmp(argv[3], "eor") != 0) {
        std::fprintf(stderr, "mode must be eor or cache\n");
        return 2;
    }
    if (pid <= 0 || base < 0x10000U) {
        std::fprintf(stderr, "invalid pid/base\n");
        return 2;
    }

    const int fd = connect_nbg();
    if (fd < 0) {
        std::perror("connect NBG driver");
        return 1;
    }

    HwbpCaptureReq request{};
    request.abi_version = NBG_HWBP_CAPTURE_ABI_VERSION;
    request.action = cache_probe ? NBG_HWBP_CAPTURE_ARM_KDF_CACHE
                                 : NBG_HWBP_CAPTURE_ARM_KDF;
    request.pid = pid;
    request.target_vaddr = base + (cache_probe ? 0x1122a81cULL
                                               : 0x1122a94cULL);
    request.expected_instruction = cache_probe
                                       ? NBG_HWBP_CAPTURE_KDF_CACHE_MOV
                                       : NBG_HWBP_CAPTURE_KDF_EOR;
    request.timeout_ms = 120000U;
    if (ioctl(fd, OP_HWBP_CAPTURE, &request) != 0) {
        std::perror("arm KDF driver breakpoint");
        close(fd);
        return 1;
    }
    std::printf("armed mode=%s pid=%d target=0x%llx state=%u\n",
                cache_probe ? "cache" : "eor", pid,
                static_cast<unsigned long long>(request.target_vaddr),
                request.state);
    std::fflush(stdout);

    for (unsigned int poll = 0; poll < 1200U; ++poll) {
        usleep(100000U);
        request.action = NBG_HWBP_CAPTURE_READ;
        if (ioctl(fd, OP_HWBP_CAPTURE, &request) != 0) {
            std::perror("read KDF driver breakpoint");
            close(fd);
            return 1;
        }
        if (request.state == NBG_HWBP_CAPTURE_HIT) {
            std::printf("hit_tid=%d pc=0x%llx sp=0x%llx flags=0x%x\n",
                        request.hit_tid,
                        static_cast<unsigned long long>(request.hit_pc),
                        static_cast<unsigned long long>(request.sp),
                        request.flags);
            std::printf("x9=0x%016llx x10=0x%016llx "
                        "x19=0x%016llx x25=0x%016llx\n",
                        static_cast<unsigned long long>(request.registers[9]),
                        static_cast<unsigned long long>(request.registers[10]),
                        static_cast<unsigned long long>(request.registers[19]),
                        static_cast<unsigned long long>(request.registers[25]));
            if (cache_probe)
                std::printf("x22=0x%016llx cache_object=0x%016llx\n",
                            static_cast<unsigned long long>(request.registers[22]),
                            static_cast<unsigned long long>(request.registers[9]));
            if (request.pointee_valid_mask & 1U) {
                std::printf("srv_stack=0x%llx srv32=",
                            static_cast<unsigned long long>(
                                request.pointee_address[0]));
                print_bytes(request.pointee_data[0], 32U);
            } else {
                std::puts("srv_stack=unreadable");
            }
            close(fd);
            return 0;
        }
        if (request.state == NBG_HWBP_CAPTURE_TIMED_OUT) {
            std::puts("capture timed out; breakpoint retired");
            close(fd);
            return 3;
        }
    }
    request.action = NBG_HWBP_CAPTURE_CANCEL;
    ioctl(fd, OP_HWBP_CAPTURE, &request);
    close(fd);
    std::puts("client polling timeout; capture canceled");
    return 3;
}
