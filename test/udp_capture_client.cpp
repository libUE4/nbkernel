/* Explicit opt-in receiver. Usage: udp_capture_client PID [seconds] [output.bin]
 * Output is a sequence of fixed 2088-byte nbg_udp_cap_packet records.
 * No automatic module loading or packet injection.
 */
#include "comm.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <vector>

static volatile sig_atomic_t quit = 0;
static void stop(int) { quit = 1; }

static int open_driver() {
    for (int family = 1; family < 46; ++family) {
        const int fd = socket(family, SOCK_RAW | SOCK_CLOEXEC, NBG_SOCKET_PROTOCOL);
        if (fd < 0) continue;
        INIT_KEY key{};
        key.abi_version = NBG_ABI_VERSION;
        key.token = NBG_AUTH_TOKEN;
        if (ioctl(fd, OP_INIT_KEY, &key) == 0 && key.accepted) return fd;
        close(fd);
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 4) {
        std::fprintf(stderr, "usage: %s PID [seconds=10] [output.bin]\n", argv[0]);
        return 2;
    }
    char *end = nullptr;
    const long pid = std::strtol(argv[1], &end, 10);
    if (!end || *end || pid <= 0 || pid > 0x7fffffffL) return 2;
    long seconds = 10;
    if (argc >= 3) {
        seconds = std::strtol(argv[2], &end, 10);
        if (!end || *end || seconds < 1 || seconds > 3600) return 2;
    }
    FILE *out = argc >= 4 ? std::fopen(argv[3], "wb") : nullptr;
    if (argc >= 4 && !out) { std::perror("output"); return 1; }
    const int fd = open_driver();
    if (fd < 0) {
        std::fprintf(stderr, "authenticated NBG socket unavailable\n");
        if (out) std::fclose(out);
        return 1;
    }
    nbg_udp_cap_init_req init{};
    init.pid = static_cast<int32_t>(pid);
    if (ioctl(fd, OP_UDP_CAPTURE_INIT, &init)) {
        std::perror("udp capture init");
        close(fd); if (out) std::fclose(out); return 1;
    }
    std::signal(SIGINT, stop); std::signal(SIGTERM, stop);
    std::vector<nbg_udp_cap_packet> batch(NBG_UDP_CAP_READ_MAX);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    uint64_t packets = 0, overflow = 0, captured = 0;
    int result = 0;
    while (!quit && std::chrono::steady_clock::now() < deadline) {
        nbg_udp_cap_read_req req{};
        req.buf = reinterpret_cast<uintptr_t>(batch.data());
        req.max_count = batch.size();
        if (ioctl(fd, OP_UDP_CAPTURE_READ, &req)) { std::perror("udp read"); result = 1; break; }
        if (req.out_count > batch.size()) { result = 1; break; }
        packets += req.out_count; overflow = req.overflow; captured = req.captured;
        if (out && req.out_count &&
            std::fwrite(batch.data(), sizeof(batch[0]), req.out_count, out) != req.out_count) {
            std::perror("output write"); result = 1; break;
        }
        usleep(req.out_count == NBG_UDP_CAP_READ_MAX ? 1000 : 10000);
    }
    if (ioctl(fd, OP_UDP_CAPTURE_STOP)) { std::perror("udp stop"); result = 1; }
    close(fd); // owner close also stops capture, including on process death
    if (out && std::fclose(out)) result = 1;
    std::printf("packets=%llu captured=%llu overflow=%llu\n",
        static_cast<unsigned long long>(packets), static_cast<unsigned long long>(captured),
        static_cast<unsigned long long>(overflow));
    return result;
}
