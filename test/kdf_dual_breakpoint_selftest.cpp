#include "comm.h"
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" char nbg_test_kdf_eor_pc[];
extern "C" char nbg_test_kdf_publish_pc[];

static_assert(offsetof(HwbpCaptureReq, secondary_target) ==
              NBG_HWBP_CAPTURE_V2_SIZE);
static_assert(sizeof(HwbpCaptureReq) == NBG_HWBP_CAPTURE_V3_SIZE);

static uint8_t actor[0x550] __attribute__((aligned(16)));
static uint8_t session[0x50] __attribute__((aligned(16)));
static const uint8_t srv[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static constexpr uint64_t input9 = 0x0123456789abcdefULL;
static constexpr uint64_t input10 = 0x1021324354657687ULL;
static constexpr uint64_t input19 = 0x89abcdef01234567ULL;
static constexpr uint64_t input25 = 0xfedcba9876543210ULL;
static constexpr uint8_t slot0[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static constexpr uint8_t slot1[16] = {
    0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,
    0x78,0x69,0x5a,0x4b,0x3c,0x2d,0x1e,0x0f
};

struct ChildResult {
    uint64_t eor_value;
    uint64_t session_pointer;
};

__attribute__((noinline)) static ChildResult execute_pair()
{
    ChildResult result{};
    const uint64_t owner = reinterpret_cast<uintptr_t>(actor);
    const uint64_t srv_address = reinterpret_cast<uintptr_t>(srv);
    asm volatile(
        "sub sp, sp, #0x200\n"
        "mov x22, %2\n"
        "mov x20, %3\n"
        "ldr q0, [x20]\n"
        "ldr q1, [x20, #16]\n"
        "stp q0, q1, [sp, #0x130]\n"
        "mov x9, %4\n"
        "mov x10, %5\n"
        "mov x19, %6\n"
        "mov x25, %7\n"
        ".global nbg_test_kdf_eor_pc\n"
        "nbg_test_kdf_eor_pc:\n"
        "eor x12, x9, x25\n"
        "ldr x24, [x22, #0x548]\n"
        ".global nbg_test_kdf_publish_pc\n"
        "nbg_test_kdf_publish_pc:\n"
        "ldr x19, [x22, #0x548]\n"
        "mov %0, x12\n"
        "mov %1, x19\n"
        "add sp, sp, #0x200\n"
        : "=r"(result.eor_value), "=r"(result.session_pointer)
        : "r"(owner), "r"(srv_address), "r"(input9), "r"(input10),
          "r"(input19), "r"(input25)
        : "x9", "x10", "x12", "x19", "x20", "x22", "x24", "x25",
          "memory", "cc");
    return result;
}

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

int main()
{
    const uint64_t session_pointer = reinterpret_cast<uintptr_t>(session);
    std::memcpy(actor + 0x548, &session_pointer, sizeof(session_pointer));
    const uint32_t key_size = 16;
    const uint32_t active_slot = 1;
    std::memcpy(session + 0x38, &key_size, sizeof(key_size));
    std::memcpy(session + 0x3c, &active_slot, sizeof(active_slot));
    std::memcpy(session + 0x10, slot0, sizeof(slot0));
    std::memcpy(session + 0x20, slot1, sizeof(slot1));

    const int fd = connect_nbg();
    if (fd < 0) {
        std::perror("connect NBG driver");
        return 1;
    }
    int start[2], result[2];
    if (pipe(start) || pipe(result))
        return 1;
    const pid_t child = fork();
    if (child < 0)
        return 1;
    if (child == 0) {
        close(fd);
        close(start[1]);
        close(result[0]);
        char token;
        const ChildResult warmup = execute_pair();
        if (write(result[1], &warmup, sizeof(warmup)) != sizeof(warmup))
            _exit(13);
        if (read(start[0], &token, 1) != 1)
            _exit(10);
        const ChildResult actual = execute_pair();
        if (write(result[1], &actual, sizeof(actual)) != sizeof(actual))
            _exit(11);
        _exit(0);
    }

    close(start[0]);
    close(result[1]);
    ChildResult warmed{};
    if (read(result[0], &warmed, sizeof(warmed)) != sizeof(warmed) ||
        warmed.eor_value != (input9 ^ input25) ||
        warmed.session_pointer != session_pointer)
        return 4;

    HwbpCaptureReq request{};
    request.abi_version = NBG_HWBP_CAPTURE_ABI_VERSION_3;
    request.action = NBG_HWBP_CAPTURE_ARM_KDF_DUAL;
    request.pid = child;
    request.target_vaddr = reinterpret_cast<uintptr_t>(nbg_test_kdf_eor_pc);
    request.secondary_target =
        reinterpret_cast<uintptr_t>(nbg_test_kdf_publish_pc);
    request.expected_instruction = NBG_HWBP_CAPTURE_KDF_EOR;
    request.timeout_ms = 5000;
    const int armed = ioctl(fd, OP_HWBP_CAPTURE, &request);
    if (armed != 0) {
        std::perror("arm EOR/publish test");
        close(start[1]);
        waitpid(child, nullptr, 0);
        close(fd);
        return 2;
    }

    const char token = 1;
    if (write(start[1], &token, 1) != 1)
        return 4;
    ChildResult actual{};
    const ssize_t bytes = read(result[0], &actual, sizeof(actual));
    usleep(10000);
    request.action = NBG_HWBP_CAPTURE_READ;
    const int read_status = ioctl(fd, OP_HWBP_CAPTURE, &request);
    const bool kdf_ok = request.entry_valid == 1U &&
        request.entry_tid == child &&
        request.entry_owner == reinterpret_cast<uintptr_t>(actor) &&
        request.kdf_registers[0] == input9 &&
        request.kdf_registers[1] == input10 &&
        request.kdf_registers[2] == input19 &&
        request.kdf_registers[3] == input25 &&
        request.kdf_srv_valid &&
        std::memcmp(request.kdf_srv32, srv, sizeof(srv)) == 0;
    const bool ring_ok = request.session_valid &&
        request.session_object == session_pointer &&
        request.session_key_size == 16U &&
        request.session_active_slot == 1U &&
        std::memcmp(request.session_slots[0], slot0, sizeof(slot0)) == 0 &&
        std::memcmp(request.session_slots[1], slot1, sizeof(slot1)) == 0;
    const bool capture_ok = read_status == 0 &&
        request.state == NBG_HWBP_CAPTURE_HIT && request.hit_tid == child &&
        request.hit_pc == request.secondary_target &&
        request.registers[22] == reinterpret_cast<uintptr_t>(actor) &&
        request.flags == NBG_HWBP_CAPTURE_FLAG_KDF_PUBLISH;
    const bool preserved = bytes == sizeof(actual) &&
        actual.eor_value == (input9 ^ input25) &&
        actual.session_pointer == session_pointer;
    std::printf("capture=%d kdf=%d ring=%d preserve=%d index=%u\n",
        capture_ok, kdf_ok, ring_ok, preserved, request.session_active_slot);

    int status = 0;
    waitpid(child, &status, 0);
    close(fd);
    return capture_ok && kdf_ok && ring_ok && preserved &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 3;
}
