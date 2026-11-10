#include "comm.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" char nbg_test_eor_pc[];
static constexpr uint64_t input9 = 0x0123456789abcdefULL;
static constexpr uint64_t input25 = 0xfedcba9876543210ULL;

__attribute__((noinline)) static uint64_t execute_eor()
{
    uint64_t out;
    asm volatile(
        "mov x9, %1\n"
        "mov x25, %2\n"
        ".global nbg_test_eor_pc\n"
        "nbg_test_eor_pc:\n"
        "eor x12, x9, x25\n"
        "mov %0, x12\n"
        : "=r"(out) : "r"(input9), "r"(input25)
        : "x9", "x12", "x25", "memory");
    return out;
}

int main()
{
    int fd = -1;
    for (int family = 1; family < 50; ++family) {
        int trial = socket(family, SOCK_RAW | SOCK_CLOEXEC, NBG_SOCKET_PROTOCOL);
        if (trial < 0) continue;
        INIT_KEY key{};
        key.abi_version = NBG_ABI_VERSION;
        key.token = NBG_AUTH_TOKEN;
        if (ioctl(trial, OP_INIT_KEY, &key) == 0 && key.accepted == 1) {
            fd = trial;
            std::printf("authenticated_family=%d\n", family);
            break;
        }
        close(trial);
    }
    if (fd < 0) { std::puts("no_driver"); return 1; }
    int start[2], result[2], finish[2];
    if (pipe(start) || pipe(result) || pipe(finish)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(fd);
        close(start[1]); close(result[0]); close(finish[1]);
        char token;
        // Fault executable pages in before the driver's no-fault opcode read.
        uint64_t warmup = execute_eor();
        if (write(result[1], &warmup, sizeof(warmup)) != sizeof(warmup)) _exit(13);
        if (read(start[0], &token, 1) != 1) _exit(10);
        uint64_t actual = execute_eor();
        if (write(result[1], &actual, sizeof(actual)) != sizeof(actual)) _exit(11);
        if (read(finish[0], &token, 1) != 1) _exit(12);
        _exit(0);
    }
    close(start[0]); close(result[1]); close(finish[0]);
    uint64_t warmed = 0;
    if (read(result[0], &warmed, sizeof(warmed)) != sizeof(warmed) ||
        warmed != (input9 ^ input25)) return 4;
    HwbpCaptureReq capture{};
    capture.abi_version = NBG_HWBP_CAPTURE_ABI_VERSION;
    capture.pid = child;
    capture.action = NBG_HWBP_CAPTURE_ARM_KDF;
    capture.target_vaddr = reinterpret_cast<uintptr_t>(nbg_test_eor_pc);
    capture.expected_instruction = NBG_HWBP_CAPTURE_KDF_EOR;
    capture.timeout_ms = 1000;
    const int armed = ioctl(fd, OP_HWBP_CAPTURE, &capture);
    std::printf("arm=%d errno=%d state=%u child=%d pc=0x%llx\n", armed,
                armed ? errno : 0, capture.state, child,
                static_cast<unsigned long long>(capture.target_vaddr));
    if (armed != 0) {
        close(start[1]); close(finish[1]); waitpid(child, nullptr, 0); close(fd);
        return 2;
    }
    char token = 1;
    const ssize_t started = write(start[1], &token, 1);
    if (started != 1) return 4;
    uint64_t actual = 0;
    const ssize_t bytes = read(result[0], &actual, sizeof(actual));
    usleep(10000);
    capture.action = NBG_HWBP_CAPTURE_READ;
    int read_status = ioctl(fd, OP_HWBP_CAPTURE, &capture);
    const bool hit = read_status == 0 && capture.state == NBG_HWBP_CAPTURE_HIT &&
        capture.hit_pc == reinterpret_cast<uintptr_t>(nbg_test_eor_pc) &&
        capture.hit_tid == child && capture.registers[9] == input9 &&
        capture.registers[25] == input25;
    const bool preserved = bytes == sizeof(actual) && actual == (input9 ^ input25);
    std::printf("read=%d state=%u hits=%u registers_match=%d eor_result_preserved=%d\n",
                read_status, capture.state, capture.hit_count, hit, preserved);
    capture.action = NBG_HWBP_CAPTURE_CANCEL;
    int cancelled = ioctl(fd, OP_HWBP_CAPTURE, &capture);
    std::printf("cancel=%d errno=%d\n", cancelled, cancelled ? errno : 0);
    const ssize_t finished = write(finish[1], &token, 1);
    if (finished != 1) return 4;
    int status;
    waitpid(child, &status, 0);
    close(fd);
    return hit && preserved && cancelled == 0 && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0 ? 0 : 3;
}
