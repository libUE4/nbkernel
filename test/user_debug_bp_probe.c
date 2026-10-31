/* Functional probe for automatic raw execution-breakpoint triggering. */
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

#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x402
#endif

#define USER_BCR_X_4B 0x1E5U
#define SHADOW_TRACE_TYPE 24
#define TRACE_EVENT_X8_X9 0xD241U
#define TRACE_EVENT_X10_X11 0xD242U
#define TRACE_EVENT_X12_X13 0xD243U
#define TRACE_EVENT_SP_LR 0xD244U

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

__attribute__((noinline)) static void user_break_site(void)
{
    __asm__ volatile("nop\nret\n");
}

__attribute__((noinline)) static void raw_trigger_site(void)
{
    __asm__ volatile(
        ".global nbg_user_bp_trigger_site\n"
        "nbg_user_bp_trigger_site:\n"
        "nop\n"
        "ret\n");
}

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

    if (waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
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

static int read_trace_events(int fd)
{
    WatchReadReq req;
    int total = 0;
    uint32_t i;

    memset(&req, 0, sizeof(req));
    if (ioctl(fd, OP_WATCH_READ, &req) < 0)
        return -1;
    for (i = 0; i < req.count; i++) {
        if (req.events[i].bp_type == TRACE_EVENT_X8_X9 ||
            req.events[i].bp_type == TRACE_EVENT_X10_X11 ||
            req.events[i].bp_type == TRACE_EVENT_X12_X13 ||
            req.events[i].bp_type == TRACE_EVENT_SP_LR)
            total++;
    }
    return total;
}

int main(void)
{
    ShadowHookReq bp = {0};
    struct probe_hwdebug_state baseline;
    struct probe_hwdebug_state filtered;
    struct probe_hwdebug_state set_state;
    struct iovec iov;
    pid_t child;
    int fd;
    int set_ret;
    int baseline_ret;
    int add_ret;
    int get_ret;
    int events;
    int status;
    int result;

    {
        int module_fd = open("/NBG.ko", O_RDONLY);
        int load_ret;

        if (module_fd < 0)
            return 2;
        load_ret = (int)syscall(SYS_finit_module, module_fd, "", 0);
        close(module_fd);
        if (load_ret < 0)
            return 2;
    }

    fd = open_driver();
    if (fd < 0)
        return 2;

    child = fork();
    if (child < 0) {
        close(fd);
        return 2;
    }
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            _exit(120);
        raise(SIGSTOP);
        raw_trigger_site();
        _exit(0);
    }

    if (wait_stopped(child) < 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, __WALL);
        close(fd);
        return 2;
    }

    memset(&set_state, 0, sizeof(set_state));
    /* Keep a normal user breakpoint at a different address.  It must remain
     * visible while the raw breakpoint below drives the automatic callback. */
    set_state.regs[0].addr = (uint64_t)(uintptr_t)user_break_site;
    set_state.regs[0].ctrl = USER_BCR_X_4B;
    iov.iov_base = &set_state;
    iov.iov_len = offsetof(struct probe_hwdebug_state, regs[1]);
    errno = 0;
    set_ret = ptrace(PTRACE_SETREGSET, child, (void *)NT_ARM_HW_BREAK,
                     &iov);

    memset(&baseline, 0, sizeof(baseline));
    iov.iov_base = &baseline;
    iov.iov_len = sizeof(baseline);
    errno = 0;
    baseline_ret = ptrace(PTRACE_GETREGSET, child,
                          (void *)NT_ARM_HW_BREAK, &iov);

    bp.pid = child;
    bp.target_vaddr = (uint64_t)(uintptr_t)raw_trigger_site;
    bp.is_rot_hook = SHADOW_TRACE_TYPE;
    errno = 0;
    add_ret = ioctl(fd, OP_SHADOW_ADD, &bp);

    memset(&filtered, 0xA5, sizeof(filtered));
    iov.iov_base = &filtered;
    iov.iov_len = sizeof(filtered);
    errno = 0;
    get_ret = ptrace(PTRACE_GETREGSET, child, (void *)NT_ARM_HW_BREAK,
                     &iov);

    printf("SET=%d BASELINE_GET=%d baseline_active=%d ADD=%d GET=%d"
           " filtered_active=%d first_addr=0x%016" PRIx64
           " first_ctrl=0x%08" PRIx32 "\n",
           set_ret, baseline_ret, count_active(&baseline), add_ret, get_ret,
           count_active(&filtered), filtered.regs[0].addr,
           filtered.regs[0].ctrl);

    ptrace(PTRACE_CONT, child, 0, 0);
    waitpid(child, &status, __WALL);
    usleep(20000);
    events = read_trace_events(fd);
    printf("AUTO_TRIGGER trace_events=%d\n", events);

    (void)ioctl(fd, OP_SHADOW_DELETE, &bp);
    close(fd);
    result = set_ret == 0 && baseline_ret == 0 &&
        count_active(&baseline) > 0 && add_ret == 0 && get_ret == 0 &&
        count_active(&filtered) == count_active(&baseline) &&
        has_record_at(&filtered, (uint64_t)(uintptr_t)user_break_site) &&
        !has_record_at(&filtered, (uint64_t)(uintptr_t)raw_trigger_site) &&
        events >= 4;
    printf("RESULT breakpoint_auto_trigger=%s\n",
           result ? "PASS" : "FAIL");
    fflush(stdout);
    sync();
    reboot(RB_POWER_OFF);
    for (;;)
        pause();
}
