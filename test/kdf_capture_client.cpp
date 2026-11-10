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
    for (int family = 1; family < 50; ++family) {
        const int fd = socket(family, SOCK_RAW | SOCK_CLOEXEC,
                              NBG_SOCKET_PROTOCOL);
        if (fd < 0)
            continue;
        INIT_KEY key{};
        key.abi_version = NBG_ABI_VERSION;
        key.token = NBG_AUTH_TOKEN;
        if (ioctl(fd, OP_INIT_KEY, &key) == 0 && key.accepted)
            return fd;
        close(fd);
    }
    return -1;
}

static void print_hex(const uint8_t *bytes, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        std::printf("%02x", bytes[i]);
    std::putchar('\n');
}

static bool read_target(int fd, int pid, uint64_t address, void *out, size_t size)
{
    COPY_MEMORY memory{};
    memory.pid = pid;
    memory.addr = address;
    memory.buffer = out;
    memory.size = size;
    std::memset(out, 0, size);
    return ioctl(fd, OP_READ_MEM, &memory) == 0;
}

static void read_validation(int fd, const HwbpCaptureReq &capture)
{
    const uint64_t actor = capture.registers[22] & 0x0000ffffffffffffULL;
    uint8_t public_key[32]{};
    uint64_t session = 0;
    uint8_t slots[0x50]{};
    if (actor < 0x10000U) {
        std::puts("validation=invalid_actor");
        return;
    }
    if (read_target(fd, capture.pid, actor + 0x554U,
                    public_key, sizeof(public_key))) {
        std::printf("observed_o1=");
        print_hex(public_key, sizeof(public_key));
    } else {
        std::puts("observed_o1=unreadable");
    }
    if (!read_target(fd, capture.pid, actor + 0x548U,
                     &session, sizeof(session))) {
        std::puts("observed_key16=unreadable_session_pointer");
        return;
    }
    session &= 0x0000ffffffffffffULL;
    if (session < 0x10000U ||
        !read_target(fd, capture.pid, session, slots, sizeof(slots))) {
        std::puts("observed_key16=unreadable_slots");
        return;
    }
    uint32_t index = 0;
    std::memcpy(&index, slots + 0x3cU, sizeof(index));
    if (index > 1U) {
        std::printf("observed_key16=invalid_index_%u\n", index);
        return;
    }
    std::printf("observed_slot=%u observed_key16=", index);
    print_hex(slots + 0x10U + index * 16U, 16U);
}

int main(int argc, char **argv)
{
    const bool read_last = argc == 3 && std::strcmp(argv[2], "--read-last") == 0;
    if (argc != 2 && !read_last) {
        std::fprintf(stderr, "usage: %s PID [--read-last]\n", argv[0]);
        return 2;
    }
    const int pid = std::atoi(argv[1]);
    if (pid <= 0) {
        std::fprintf(stderr, "invalid pid\n");
        return 2;
    }

    const int fd = connect_nbg();
    if (fd < 0) {
        std::perror("connect NBG driver");
        return 1;
    }
    char module_name[] = "libUE4.so";
    MODULE_BASE module{pid, module_name, 0};
    if (ioctl(fd, OP_MODULE_BASE, &module) != 0 || module.base < 0x10000U) {
        std::perror("query libUE4 base");
        close(fd);
        return 1;
    }

    HwbpCaptureReq request{};
    request.abi_version = NBG_HWBP_CAPTURE_ABI_VERSION;
    request.action = NBG_HWBP_CAPTURE_ARM_KDF;
    request.pid = pid;
    request.target_vaddr = module.base + 0x1122a94cULL;
    request.expected_instruction = NBG_HWBP_CAPTURE_KDF_EOR;
    request.timeout_ms = 120000U;
    if (!read_last && ioctl(fd, OP_HWBP_CAPTURE, &request) != 0) {
        std::perror("arm KDF driver breakpoint");
        close(fd);
        return 1;
    }
    std::printf("mode=%s family-ok base=0x%llx target=0x%llx state=%u\n",
                read_last ? "read-last" : "armed",
                static_cast<unsigned long long>(module.base),
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
            if (request.pointee_valid_mask & 1U) {
                std::printf("srv32=");
                print_hex(request.pointee_data[0], 32U);
            } else {
                std::puts("srv32=unreadable");
            }
            if (request.pid == pid) {
                read_validation(fd, request);
            } else {
                std::puts("validation=pid_mismatch");
            }
            std::fflush(stdout);
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
