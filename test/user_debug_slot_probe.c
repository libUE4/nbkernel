/*
 * Functional probe for the user-visible ARM64 hardware-debug regset.
 *
 * The child is a normal ptrace tracee.  The parent first registers an NBG raw
 * watchpoint for that child, then installs one ordinary ptrace watchpoint and
 * reads NT_ARM_HW_WATCH back.  The expected result is a valid resource header
 * with the ordinary record preserved; the unrelated raw slot is not exposed.
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/comm.h"

#ifndef NT_ARM_HW_WATCH
#define NT_ARM_HW_WATCH 0x403
#endif

#define RAW_WP_W 0x2U
#define USER_WCR_W_8B (0x1U | (2U << 1) | (2U << 3) | (0xFFU << 5))

struct user_hwdebug_reg {
    uint64_t addr;
    uint32_t ctrl;
    uint32_t pad;
};

struct probe_hwdebug_state {
    uint32_t dbg_info;
    uint32_t pad;
    struct user_hwdebug_reg regs[16];
};

static volatile uint64_t probe_target __attribute__((aligned(8)));
static volatile uint64_t raw_probe_target __attribute__((aligned(8)));

static int open_driver(void)
{
    int family;

    for (family = 1; family < 50; family++) {
        INIT_KEY key = {
            .abi_version = NBG_ABI_VERSION,
            .token = NBG_AUTH_TOKEN,
        };
        int fd = socket(family, SOCK_RAW, NBG_SOCKET_PROTOCOL);

        if (fd < 0)
            continue;
        if (ioctl(fd, OP_INIT_KEY, &key) == 0 && key.accepted == 1U)
            return fd;
        close(fd);
    }
    errno = ENODEV;
    return -1;
}

static int wait_stopped(pid_t pid)
{
    int status;

    if (waitpid(pid, &status, __WALL) != pid)
        return -1;
    if (!WIFSTOPPED(status)) {
        errno = ECHILD;
        return -1;
    }
    return 0;
}

static int count_active(const struct probe_hwdebug_state *state)
{
    int i;
    int active = 0;
    int n = (int)(state->dbg_info & 0xffU);

    if (n < 0)
        n = 0;
    if (n > 16)
        n = 16;
    for (i = 0; i < n; i++)
        if (state->regs[i].ctrl & 1U)
            active++;
    return active;
}

static int has_record_at(const struct probe_hwdebug_state *state,
                         uint64_t address)
{
    int i;
    int n = (int)(state->dbg_info & 0xffU);

    if (n > 16)
        n = 16;
    for (i = 0; i < n; i++)
        if ((state->regs[i].ctrl & 1U) && state->regs[i].addr == address)
            return 1;
    return 0;
}

int main(void)
{
    WatchReq watch = {0};
    struct probe_hwdebug_state baseline_state;
    struct probe_hwdebug_state set_state;
    struct probe_hwdebug_state get_state;
    struct iovec iov;
    pid_t child;
    int fd;
    int baseline_ret;
    int set_ret;
    int get_ret;
    int status;
    int result;

    {
        int module_fd = open("/NBG.ko", O_RDONLY);
        int load_ret;

        if (module_fd < 0) {
            perror("open module");
            return 2;
        }
        load_ret = (int)syscall(SYS_finit_module, module_fd, "", 0);
        close(module_fd);
        if (load_ret < 0) {
            perror("finit_module");
            return 2;
        }
    }

    fd = open_driver();
    if (fd < 0) {
        perror("open_driver");
        return 2;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        close(fd);
        return 2;
    }
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            _exit(120);
        raise(SIGSTOP);
        _exit(0);
    }

    if (wait_stopped(child) < 0) {
        perror("wait_stopped");
        kill(child, SIGKILL);
        waitpid(child, NULL, __WALL);
        close(fd);
        return 2;
    }

    watch.pid = child;
    watch.watch_addr = (uint64_t)(uintptr_t)&raw_probe_target;

    memset(&set_state, 0, sizeof(set_state));
    set_state.regs[0].addr = (uint64_t)(uintptr_t)&probe_target;
    set_state.regs[0].ctrl = USER_WCR_W_8B;
    iov.iov_base = &set_state;
    iov.iov_len = offsetof(struct probe_hwdebug_state, regs[1]);
    errno = 0;
    set_ret = ptrace(PTRACE_SETREGSET, child, (void *)NT_ARM_HW_WATCH,
                     &iov);
    printf("SET ret=%d errno=%d\n", set_ret, set_ret < 0 ? errno : 0);

    memset(&baseline_state, 0, sizeof(baseline_state));
    iov.iov_base = &baseline_state;
    iov.iov_len = sizeof(baseline_state);
    errno = 0;
    baseline_ret = ptrace(PTRACE_GETREGSET, child,
                          (void *)NT_ARM_HW_WATCH, &iov);
    printf("BASELINE_GET ret=%d errno=%d active=%d first_addr=0x%016" PRIx64
           " first_ctrl=0x%08" PRIx32 "\n",
           baseline_ret, baseline_ret < 0 ? errno : 0,
           count_active(&baseline_state), baseline_state.regs[0].addr,
           baseline_state.regs[0].ctrl);

    watch.bp_type = RAW_WP_W;
    watch.bp_len = 8;
    if (ioctl(fd, OP_WATCH_ADD, &watch) < 0) {
        perror("OP_WATCH_ADD");
        ptrace(PTRACE_KILL, child, 0, 0);
        waitpid(child, NULL, __WALL);
        close(fd);
        return 3;
    }

    memset(&get_state, 0xA5, sizeof(get_state));
    iov.iov_base = &get_state;
    iov.iov_len = sizeof(get_state);
    errno = 0;
    get_ret = ptrace(PTRACE_GETREGSET, child, (void *)NT_ARM_HW_WATCH,
                     &iov);
    printf("GET ret=%d errno=%d iov_len=%zu info=%u active=%d first_addr=0x%016" PRIx64
           " first_ctrl=0x%08" PRIx32 "\n",
           get_ret, get_ret < 0 ? errno : 0, iov.iov_len,
           get_state.dbg_info, count_active(&get_state),
           get_state.regs[0].addr, get_state.regs[0].ctrl);

    watch.bp_type = 0;
    watch.bp_len = 0;
    if (ioctl(fd, OP_WATCH_DELETE, &watch) < 0)
        perror("OP_WATCH_DELETE");
    ptrace(PTRACE_CONT, child, 0, 0);
    waitpid(child, &status, __WALL);
    close(fd);

    result = set_ret == 0 && baseline_ret == 0 &&
        count_active(&baseline_state) > 0 && get_ret == 0 &&
        count_active(&get_state) == count_active(&baseline_state) &&
        has_record_at(&get_state, (uint64_t)(uintptr_t)&probe_target) &&
        !has_record_at(&get_state,
                       (uint64_t)(uintptr_t)&raw_probe_target);
    printf("RESULT user_slot_preserved=%s\n", result ? "PASS" : "FAIL");
    fflush(stdout);
    sync();
    reboot(RB_POWER_OFF);
    for (;;)
        pause();
}
