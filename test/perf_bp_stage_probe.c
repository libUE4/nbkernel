/* Compare the public perf breakpoint path with the NBG raw BP path. */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <unistd.h>

#include "../secret.h"
#include "comm.h"

#define PERF_TARGET_TYPE 24

extern const unsigned char nbg_perf_probe_site[];

__attribute__((naked, noinline, used)) static void perf_probe_site_fn(void)
{
    __asm__ volatile(
        ".global nbg_perf_probe_site\n"
        "nbg_perf_probe_site:\n"
        "nop\n"
        "ret\n");
}

static int open_driver(void)
{
    for (int family = 1; family < 50; family++) {
        INIT_KEY key = { .abi_version = NBG_ABI_VERSION,
                         .token = NBG_AUTH_TOKEN };
        int fd = socket(family, SOCK_RAW, NBG_SOCKET_PROTOCOL);
        if (fd < 0)
            continue;
        if (ioctl(fd, OP_INIT_KEY, &key) == 0 && key.accepted == 1U)
            return fd;
        close(fd);
    }
    return -1;
}

static void perf_attempt(const char *label, pid_t tid, unsigned int pages)
{
    struct perf_event_attr attr;
    long page_size = sysconf(_SC_PAGESIZE);
    size_t map_len = page_size > 0 ? (size_t)page_size * (1U + pages) : 0;
    int fd;
    void *mapping;

    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.sample_period = 1;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.wakeup_events = 1;
    attr.bp_type = HW_BREAKPOINT_X;
    attr.bp_addr = (uint64_t)(uintptr_t)nbg_perf_probe_site;
    attr.bp_len = HW_BREAKPOINT_LEN_4;

    errno = 0;
    fd = (int)syscall(SYS_perf_event_open, &attr, tid, -1, -1,
                      PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
        printf("%s open=FAIL errno=%d (%s)\n", label, errno, strerror(errno));
        return;
    }
    printf("%s open=PASS fd=%d\n", label, fd);

    errno = 0;
    mapping = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED) {
        printf("%s mmap=FAIL len=%zu errno=%d (%s)\n", label, map_len,
               errno, strerror(errno));
    } else {
        printf("%s mmap=PASS len=%zu\n", label, map_len);
        munmap(mapping, map_len);
    }
    close(fd);
}

static int add_driver_bp(int fd, ShadowHookReq *req)
{
    memset(req, 0, sizeof(*req));
    req->pid = getpid();
    req->target_vaddr = (uint64_t)(uintptr_t)nbg_perf_probe_site;
    req->is_rot_hook = PERF_TARGET_TYPE;
    return ioctl(fd, OP_SHADOW_ADD, req);
}

int main(void)
{
    int fd = open_driver();
    ShadowHookReq req;
    pid_t tid = (pid_t)syscall(SYS_gettid);

    if (fd < 0) {
        printf("driver auth=FAIL errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    printf("driver auth=PASS pid=%d tid=%d site=0x%" PRIx64 "\n", getpid(),
           tid, (uint64_t)(uintptr_t)nbg_perf_probe_site);

    perf_attempt("before_driver_bp_pages0", tid, 0);
    perf_attempt("before_driver_bp_pages8", tid, 8);

    if (add_driver_bp(fd, &req) != 0) {
        printf("driver BP add=FAIL errno=%d (%s)\n", errno, strerror(errno));
        close(fd);
        return 1;
    }
    printf("driver BP add=PASS\n");
    perf_probe_site_fn();
    perf_attempt("after_driver_bp_pages0", tid, 0);
    perf_attempt("after_driver_bp_pages8", tid, 8);

    (void)ioctl(fd, OP_SHADOW_DELETE, &req);
    close(fd);
    printf("driver BP delete=done\n");
    return 0;
}
