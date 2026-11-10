#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "include/comm.h"

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

static void print_hex(FILE *out, const uint8_t *bytes, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        std::fprintf(out, "%02x", bytes[i]);
    std::fputc('\n', out);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s PID private-output.txt\n", argv[0]);
        return 2;
    }
    char *end = nullptr;
    const long parsed_pid = std::strtol(argv[1], &end, 10);
    if (!end || *end || parsed_pid <= 0 || parsed_pid > 0x7fffffffL)
        return 2;

    const int pid = static_cast<int>(parsed_pid);
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
    request.abi_version = NBG_HWBP_CAPTURE_ABI_VERSION_3;
    request.action = NBG_HWBP_CAPTURE_ARM_KDF_DUAL;
    request.pid = pid;
    request.target_vaddr = module.base + 0x1122a94cULL;
    request.secondary_target = module.base + 0x1122adb8ULL;
    request.expected_instruction = NBG_HWBP_CAPTURE_KDF_EOR;
    request.timeout_ms = 120000U;
    if (ioctl(fd, OP_HWBP_CAPTURE, &request) != 0) {
        std::perror("arm EOR/publish capture");
        close(fd);
        return 1;
    }
    std::fprintf(stderr, "armed pid=%d eor=0x%llx publish=0x%llx\n", pid,
        static_cast<unsigned long long>(request.target_vaddr),
        static_cast<unsigned long long>(request.secondary_target));

    for (unsigned poll = 0; poll < 1200U; ++poll) {
        usleep(100000U);
        request.action = NBG_HWBP_CAPTURE_READ;
        if (ioctl(fd, OP_HWBP_CAPTURE, &request) != 0) {
            std::perror("read capture");
            close(fd);
            return 1;
        }
        if (request.state == NBG_HWBP_CAPTURE_HIT)
            break;
        if (request.state == NBG_HWBP_CAPTURE_TIMED_OUT) {
            std::fprintf(stderr, "capture timeout; eor_seen=%u\n",
                         request.entry_valid);
            close(fd);
            return 3;
        }
    }

    if (request.state != NBG_HWBP_CAPTURE_HIT || !request.entry_valid ||
        !request.kdf_srv_valid || !request.session_valid ||
        request.hit_pc != request.secondary_target ||
        request.session_key_size != 16U || request.session_active_slot > 1U) {
        std::fprintf(stderr,
            "incomplete capture state=%u eor=%u srv=%u session=%u size=%u index=%u\n",
            request.state, request.entry_valid, request.kdf_srv_valid,
            request.session_valid, request.session_key_size,
            request.session_active_slot);
        close(fd);
        return 4;
    }

    FILE *out = std::fopen(argv[2], "wx");
    if (!out) {
        std::perror("create private output");
        close(fd);
        return 1;
    }
    (void)fchmod(fileno(out), S_IRUSR | S_IWUSR);
    std::fprintf(out, "pid=%d\nmodule_base=0x%llx\nobject=0x%llx\n",
        pid, static_cast<unsigned long long>(module.base),
        static_cast<unsigned long long>(request.session_object));
    std::fprintf(out, "eor_tid=%d publish_tid=%d active_slot=%u key_size=%u\n",
        request.entry_tid, request.hit_tid, request.session_active_slot,
        request.session_key_size);
    std::fprintf(out, "x9=0x%016llx\nx10=0x%016llx\n"
                      "x19=0x%016llx\nx25=0x%016llx\n",
        static_cast<unsigned long long>(request.kdf_registers[0]),
        static_cast<unsigned long long>(request.kdf_registers[1]),
        static_cast<unsigned long long>(request.kdf_registers[2]),
        static_cast<unsigned long long>(request.kdf_registers[3]));
    std::fprintf(out, "srv32=");
    print_hex(out, request.kdf_srv32, sizeof(request.kdf_srv32));
    std::fprintf(out, "slot0=");
    print_hex(out, request.session_slots[0], sizeof(request.session_slots[0]));
    std::fprintf(out, "slot1=");
    print_hex(out, request.session_slots[1], sizeof(request.session_slots[1]));
    std::fprintf(out, "selected=");
    print_hex(out, request.session_slots[request.session_active_slot], 16);
    const int write_error = std::ferror(out);
    const int close_error = std::fclose(out);
    close(fd);
    if (write_error || close_error) {
        std::fprintf(stderr, "failed writing output\n");
        return 1;
    }
    std::fprintf(stderr,
        "captured matched EOR/publish tid=%d; output stored privately\n",
        request.hit_tid);
    return 0;
}
