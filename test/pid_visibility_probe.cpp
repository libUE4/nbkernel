/*
 * Focused PID visibility probe.
 *
 * The program creates a synthetic child, hides only that PID through the
 * authenticated driver ABI, and compares ordinary procfs views with kernel
 * backed views that do not depend on /proc directory enumeration.
 */

#include "comm.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>

#ifndef SYS_pidfd_open
#if defined(__NR_pidfd_open)
#define SYS_pidfd_open __NR_pidfd_open
#else
#define SYS_pidfd_open 434
#endif
#endif

#ifndef SYS_process_vm_readv
#if defined(__NR_process_vm_readv)
#define SYS_process_vm_readv __NR_process_vm_readv
#else
#define SYS_process_vm_readv 270
#endif
#endif

namespace {

volatile sig_atomic_t g_child_stop = 0;
volatile uint64_t g_child_marker = 0x53414D504C455F50ULL;
constexpr char kFixtureProcessName[] = "fixture_pid_tgt";

void child_signal(int) {
    g_child_stop = 1;
}

bool write_full(int fd, const void *data, size_t size) {
    const uint8_t *p = static_cast<const uint8_t *>(data);
    while (size > 0) {
        ssize_t n = write(fd, p, size);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        p += n;
        size -= static_cast<size_t>(n);
    }
    return true;
}

bool read_full(int fd, void *data, size_t size) {
    uint8_t *p = static_cast<uint8_t *>(data);
    while (size > 0) {
        ssize_t n = read(fd, p, size);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        p += n;
        size -= static_cast<size_t>(n);
    }
    return true;
}

struct DriverConnection {
    int fd = -1;
    int family = -1;

    bool open() {
        for (int candidate = 1; candidate < 50; ++candidate) {
            int socket_fd = socket(candidate, SOCK_RAW, NBG_SOCKET_PROTOCOL);
            if (socket_fd < 0)
                continue;

            INIT_KEY key{};
            key.abi_version = NBG_ABI_VERSION;
            key.token = NBG_AUTH_TOKEN;
            if (ioctl(socket_fd, OP_INIT_KEY, &key) == 0 &&
                key.accepted == 1 && key.family == static_cast<uint32_t>(candidate)) {
                fd = socket_fd;
                family = candidate;
                return true;
            }
            close(socket_fd);
        }
        return false;
    }

    bool hide(pid_t pid, int *saved_errno) {
        HidePidReq request{static_cast<int32_t>(pid)};
        errno = 0;
        int rc = ioctl(fd, OP_HIDE_PID, &request);
        if (saved_errno)
            *saved_errno = errno;
        return rc == 0;
    }

    bool unhide(pid_t pid, int *saved_errno) {
        HidePidReq request{static_cast<int32_t>(pid)};
        errno = 0;
        int rc = ioctl(fd, OP_UNHIDE_PID, &request);
        if (saved_errno)
            *saved_errno = errno;
        return rc == 0;
    }

    ~DriverConnection() {
        if (fd >= 0)
            close(fd);
    }
};

struct ProbeResult {
    const char *name;
    bool known;
    bool present;
    int error;
    std::string detail;
};

ProbeResult result(const char *name, bool known, bool present, int error,
                   const char *detail = nullptr) {
    ProbeResult out{name, known, present, error, detail ? detail : ""};
    return out;
}

bool proc_root_contains(pid_t pid) {
    errno = 0;
    DIR *dir = opendir("/proc");
    if (!dir)
        return false;

    char wanted[32];
    snprintf(wanted, sizeof(wanted), "%d", pid);
    bool found = false;
    for (struct dirent *entry = readdir(dir); entry; entry = readdir(dir)) {
        if (strcmp(entry->d_name, wanted) == 0) {
            found = true;
            break;
        }
    }
    closedir(dir);
    return found;
}

ProbeResult probe_proc_root(pid_t pid) {
    bool found = proc_root_contains(pid);
    return result("proc_readdir", true, found, found ? 0 : errno);
}

ProbeResult probe_proc_file(pid_t pid, const char *leaf) {
    char path[96];
    snprintf(path, sizeof(path), "/proc/%d/%s", pid, leaf);
    errno = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    int saved = errno;
    if (fd < 0)
        return result(leaf, true, false, saved);

    char byte = 0;
    ssize_t n = read(fd, &byte, 1);
    saved = errno;
    close(fd);
    return result(leaf, true, n >= 0, n >= 0 ? 0 : saved);
}

ProbeResult probe_task_dir(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    errno = 0;
    DIR *dir = opendir(path);
    int saved = errno;
    if (!dir)
        return result("task_dir", true, false, saved);

    bool found_numeric = false;
    for (struct dirent *entry = readdir(dir); entry; entry = readdir(dir)) {
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
            found_numeric = true;
            break;
        }
    }
    closedir(dir);
    return result("task_dir", true, found_numeric, 0);
}

ProbeResult probe_kill0(pid_t pid) {
    errno = 0;
    int rc = kill(pid, 0);
    int saved = errno;
    if (rc == 0)
        return result("kill_0", true, true, 0, "signal check reached task");
    if (saved == EPERM)
        return result("kill_0", true, true, saved, "permission denied but task exists");
    return result("kill_0", true, false, saved);
}

ProbeResult probe_pidfd(pid_t pid) {
    errno = 0;
    long fd = syscall(SYS_pidfd_open, pid, 0U);
    int saved = errno;
    if (fd < 0) {
        if (saved == ENOSYS || saved == EINVAL || saved == EPERM)
            return result("pidfd_open", false, false, saved, "unsupported or denied");
        return result("pidfd_open", true, false, saved);
    }
    close(static_cast<int>(fd));
    return result("pidfd_open", true, true, 0);
}

ProbeResult probe_vm_read(pid_t pid, uintptr_t remote_address) {
    uint64_t value = 0;
    struct iovec local{&value, sizeof(value)};
    struct iovec remote{reinterpret_cast<void *>(remote_address), sizeof(value)};
    errno = 0;
    ssize_t n = syscall(SYS_process_vm_readv, pid, &local, 1U, &remote, 1U, 0U);
    int saved = errno;
    if (n == static_cast<ssize_t>(sizeof(value))) {
        char detail[64];
        snprintf(detail, sizeof(detail), "value=0x%llx",
                 static_cast<unsigned long long>(value));
        return result("process_vm_readv", true, true, 0, detail);
    }
    return result("process_vm_readv", true, false, saved);
}

void print_results(const char *phase, pid_t pid, const ProbeResult *items, size_t count) {
    printf("[%s] pid=%d\n", phase, pid);
    for (size_t i = 0; i < count; ++i) {
        const ProbeResult &item = items[i];
        const char *state = !item.known ? "UNSUPPORTED" :
                            (item.present ? "FOUND" : "HIDDEN");
        printf("  %-18s %-11s errno=%d%s%s\n", item.name, state, item.error,
               item.detail.empty() ? "" : " detail=", item.detail.c_str());
    }
}

size_t collect_snapshot(pid_t pid, uintptr_t remote_address, ProbeResult *out,
                        size_t capacity) {
    if (capacity < 8)
        return 0;
    size_t count = 0;
    out[count++] = probe_proc_root(pid);
    out[count++] = probe_proc_file(pid, "stat");
    out[count++] = probe_proc_file(pid, "status");
    out[count++] = probe_task_dir(pid);
    out[count++] = probe_kill0(pid);
    out[count++] = probe_pidfd(pid);
    out[count++] = probe_vm_read(pid, remote_address);
    out[count++] = probe_proc_file(pid, "cmdline");
    return count;
}

bool find_result(const ProbeResult *items, size_t count, const char *name,
                 bool *known, bool *present) {
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(items[i].name, name) == 0) {
            if (known)
                *known = items[i].known;
            if (present)
                *present = items[i].present;
            return true;
        }
    }
    return false;
}

}  // namespace

int main() {
    printf("PID_VISIBILITY_PROBE start uid=%d\n", static_cast<int>(getuid()));

    DriverConnection driver;
    if (!driver.open()) {
        fprintf(stderr, "DRIVER_AUTH_FAIL errno=%d (%s)\n", errno, strerror(errno));
        return 2;
    }
    printf("DRIVER_AUTH_OK family=%d\n", driver.family);

    int pipe_fds[2];
    if (pipe(pipe_fds) != 0) {
        perror("pipe");
        return 3;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 3;
    }
    if (child == 0) {
        close(pipe_fds[0]);
        signal(SIGTERM, child_signal);
        signal(SIGINT, child_signal);
        prctl(PR_SET_NAME, kFixtureProcessName, 0, 0, 0);
        uintptr_t marker_address = reinterpret_cast<uintptr_t>(&g_child_marker);
        if (!write_full(pipe_fds[1], &marker_address, sizeof(marker_address)))
            _exit(111);
        while (!g_child_stop)
            sleep(1);
        _exit(0);
    }

    close(pipe_fds[1]);
    uintptr_t marker_address = 0;
    if (!read_full(pipe_fds[0], &marker_address, sizeof(marker_address))) {
        fprintf(stderr, "CHILD_HANDSHAKE_FAIL errno=%d (%s)\n", errno, strerror(errno));
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        return 4;
    }
    close(pipe_fds[0]);

    ProbeResult baseline[8];
    size_t baseline_count = collect_snapshot(child, marker_address, baseline,
                                             sizeof(baseline) / sizeof(baseline[0]));
    print_results("BASELINE", child, baseline, baseline_count);

    int hide_errno = 0;
    if (!driver.hide(child, &hide_errno)) {
        fprintf(stderr, "HIDE_FAIL pid=%d errno=%d (%s)\n", child, hide_errno,
                strerror(hide_errno));
        kill(child, SIGTERM);
        waitpid(child, nullptr, 0);
        return 5;
    }
    printf("HIDE_OK pid=%d\n", child);
    usleep(100000);

    ProbeResult hidden[8];
    size_t hidden_count = collect_snapshot(child, marker_address, hidden,
                                           sizeof(hidden) / sizeof(hidden[0]));
    print_results("AFTER_HIDE", child, hidden, hidden_count);

    bool proc_filtered = false;
    bool proc_known = false;
    bool proc_present = true;
    bool kill_known = false;
    bool kill_present = false;
    bool vm_known = false;
    bool vm_present = false;
    find_result(hidden, hidden_count, "proc_readdir", &proc_known, &proc_present);
    find_result(hidden, hidden_count, "kill_0", &kill_known, &kill_present);
    find_result(hidden, hidden_count, "process_vm_readv", &vm_known, &vm_present);
    proc_filtered = proc_known && !proc_present;
    printf("SUMMARY proc_filtered=%d kernel_signal_visible=%d vm_visible=%d\n",
           proc_filtered ? 1 : 0,
           (kill_known && kill_present) ? 1 : 0,
           (vm_known && vm_present) ? 1 : 0);

    int unhide_errno = 0;
    bool unhide_ok = driver.unhide(child, &unhide_errno);
    printf("UNHIDE_%s pid=%d errno=%d\n", unhide_ok ? "OK" : "FAIL", child,
           unhide_errno);
    usleep(100000);

    ProbeResult restored[8];
    size_t restored_count = collect_snapshot(child, marker_address, restored,
                                             sizeof(restored) / sizeof(restored[0]));
    print_results("AFTER_UNHIDE", child, restored, restored_count);

    kill(child, SIGTERM);
    waitpid(child, nullptr, 0);
    printf("PID_VISIBILITY_PROBE done\n");
    return (proc_filtered && unhide_ok) ? 0 : 6;
}
