/* Focused userspace probe for the driver's raw ARM64 BP/WP paths. */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../secret.h"
#include "comm.h"

#define RAW_WP_W 0x2U
#define DFM_SLOT_TRACE_TYPE 24
#define DFM_SLOT_TRACE_EVENT_X8_X9   0xD241U
#define DFM_SLOT_TRACE_EVENT_X10_X11 0xD242U
#define DFM_SLOT_TRACE_EVENT_X12_X13 0xD243U
#define DFM_SLOT_TRACE_EVENT_SP_LR   0xD244U

static volatile uint64_t g_watch_target __attribute__((aligned(8)));

extern const unsigned char nbg_probe_bp_site[];

__attribute__((naked, noinline)) static void execute_probe_site(void)
{
    __asm__ volatile(
        ".global nbg_probe_bp_site\n"
        "nbg_probe_bp_site:\n"
        "nop\n"
        "ret\n");
}

static int open_driver(uint32_t *family_out)
{
    int family;
    int last_error = ENODEV;

    for (family = 1; family < 50; family++) {
        INIT_KEY key = {
            .abi_version = NBG_ABI_VERSION,
            .token = NBG_AUTH_TOKEN,
        };
        int fd = socket(family, SOCK_RAW, NBG_SOCKET_PROTOCOL);

        if (fd < 0) {
            last_error = errno;
            continue;
        }
        if (ioctl(fd, OP_INIT_KEY, &key) == 0 && key.accepted == 1U) {
            *family_out = (uint32_t)family;
            return fd;
        }
        last_error = errno;
        close(fd);
    }

    errno = last_error;
    return -1;
}

static int read_events(int fd, WatchEvent *events, size_t capacity)
{
    size_t total = 0;

    while (total < capacity) {
        WatchReadReq batch;
        uint32_t i;

        memset(&batch, 0, sizeof(batch));
        if (ioctl(fd, OP_WATCH_READ, &batch) != 0)
            return -1;
        if (batch.count == 0)
            break;
        for (i = 0; i < batch.count && total < capacity; i++)
            events[total++] = batch.events[i];
    }
    return (int)total;
}

static int clear_events(int fd)
{
    WatchEvent discard[WATCH_BATCH_MAX * 2U];

    if (ioctl(fd, OP_WATCH_CLEAR, NULL) != 0)
        return -1;
    return read_events(fd, discard, WATCH_BATCH_MAX * 2U) < 0 ? -1 : 0;
}

static int test_execute_breakpoint(int fd)
{
    ShadowHookReq req;
    WatchEvent events[WATCH_BATCH_MAX];
    int event_count;
    int expected = 0;
    int i;

    memset(&req, 0, sizeof(req));
    req.pid = getpid();
    req.target_vaddr = (uint64_t)(uintptr_t)nbg_probe_bp_site;
    req.is_rot_hook = DFM_SLOT_TRACE_TYPE;

    if (clear_events(fd) != 0) {
        printf("BP clear: FAIL errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    if (ioctl(fd, OP_SHADOW_ADD, &req) != 0) {
        printf("BP add: FAIL site=0x%" PRIx64 " errno=%d (%s)\n",
               req.target_vaddr, errno, strerror(errno));
        return 1;
    }
    printf("BP add: PASS pid=%d site=0x%" PRIx64 " type=%d\n",
           getpid(), req.target_vaddr, req.is_rot_hook);

    usleep(20000);
    execute_probe_site();
    usleep(20000);

    event_count = read_events(fd, events, WATCH_BATCH_MAX);
    if (event_count < 0) {
        printf("BP read: FAIL errno=%d (%s)\n", errno, strerror(errno));
    } else {
        for (i = 0; i < event_count; i++) {
            uint32_t type = events[i].bp_type;
            if ((type == DFM_SLOT_TRACE_EVENT_X8_X9 ||
                 type == DFM_SLOT_TRACE_EVENT_X10_X11 ||
                 type == DFM_SLOT_TRACE_EVENT_X12_X13 ||
                 type == DFM_SLOT_TRACE_EVENT_SP_LR) &&
                events[i].pid == getpid() && events[i].hit_count == 1U)
                expected++;
            printf("BP event[%d]: type=0x%x pid=%d tid=%d hit=%u a=0x%" PRIx64
                   " b=0x%" PRIx64 "\n", i, type, events[i].pid,
                   events[i].tid, events[i].hit_count, events[i].watch_addr,
                   events[i].pc);
        }
        printf("BP hit: %s events=%d expected=%d/4\n",
               expected == 4 ? "PASS" : "FAIL", event_count, expected);
    }

    if (ioctl(fd, OP_SHADOW_DELETE, &req) != 0) {
        printf("BP delete: FAIL errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    if (clear_events(fd) != 0) {
        printf("BP post-delete clear: FAIL errno=%d (%s)\n", errno,
               strerror(errno));
        return 1;
    }
    execute_probe_site();
    usleep(10000);
    event_count = read_events(fd, events, WATCH_BATCH_MAX);
    printf("BP delete: %s post_delete_events=%d\n",
           event_count == 0 ? "PASS" : "FAIL", event_count);
    return event_count >= 0 && expected == 4 && event_count == 0 ? 0 : 1;
}

__attribute__((noinline)) static void trigger_watch_store(uint64_t value)
{
    g_watch_target = value;
    __asm__ volatile("dmb ish" ::: "memory");
}

static int test_write_watchpoint(int fd)
{
    WatchReq req;
    WatchEvent events[WATCH_BATCH_MAX];
    const uint64_t target = (uint64_t)(uintptr_t)&g_watch_target;
    const int32_t tid = (int32_t)syscall(SYS_gettid);
    int event_count;
    int valid = 0;
    int i;

    memset(&req, 0, sizeof(req));
    req.pid = getpid();
    req.watch_addr = target;
    req.bp_type = RAW_WP_W;
    req.bp_len = sizeof(g_watch_target);
    req.log_limit = 8;

    if (clear_events(fd) != 0) {
        printf("WP clear: FAIL errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    if (ioctl(fd, OP_WATCH_ADD, &req) != 0) {
        printf("WP add: FAIL addr=0x%" PRIx64 " errno=%d (%s)\n",
               target, errno, strerror(errno));
        return 1;
    }
    printf("WP add: PASS pid=%d addr=0x%" PRIx64 " len=%u type=W\n",
           getpid(), target, req.bp_len);

    usleep(20000);
    trigger_watch_store(0x1122334455667788ULL);
    usleep(20000);
    trigger_watch_store(0x8877665544332211ULL);
    usleep(20000);

    event_count = read_events(fd, events, WATCH_BATCH_MAX);
    if (event_count < 0) {
        printf("WP read: FAIL errno=%d (%s)\n", errno, strerror(errno));
    } else {
        for (i = 0; i < event_count; i++) {
            const WatchEvent *event = &events[i];
            if ((event->watch_addr & ~UINT64_C(7)) == (target & ~UINT64_C(7)) &&
                event->pc != 0 && event->pid == getpid() &&
                event->tid == tid && event->bp_type == RAW_WP_W &&
                event->hit_count > 0)
                valid++;
            printf("WP event[%d]: addr=0x%" PRIx64 " pc=0x%" PRIx64
                   " pid=%d tid=%d type=%u hit=%u\n", i,
                   event->watch_addr, event->pc, event->pid, event->tid,
                   event->bp_type, event->hit_count);
        }
        printf("WP hit: %s events=%d valid=%d value=0x%" PRIx64 "\n",
               valid > 0 ? "PASS" : "FAIL", event_count, valid,
               (uint64_t)g_watch_target);
    }

    if (ioctl(fd, OP_WATCH_DELETE, &req) != 0) {
        printf("WP delete: FAIL errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    if (clear_events(fd) != 0) {
        printf("WP post-delete clear: FAIL errno=%d (%s)\n", errno,
               strerror(errno));
        return 1;
    }
    trigger_watch_store(0x123456789abcdef0ULL);
    usleep(10000);
    event_count = read_events(fd, events, WATCH_BATCH_MAX);
    printf("WP delete: %s post_delete_events=%d\n",
           event_count == 0 ? "PASS" : "FAIL", event_count);
    return event_count >= 0 && valid > 0 && event_count == 0 &&
           g_watch_target == 0x123456789abcdef0ULL ? 0 : 1;
}

int main(void)
{
    uint32_t family = 0;
    HwbpInfo info;
    HwbpCaps caps;
    int fd;
    int bp_status;
    int wp_status;

    fd = open_driver(&family);
    if (fd < 0) {
        printf("driver auth: FAIL errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    printf("driver auth: PASS family=%u pid=%d\n", family, getpid());

    memset(&info, 0, sizeof(info));
    if (ioctl(fd, OP_HWBP_INFO, &info) == 0)
        printf("HWBP info: physical=%" PRIu64 "BP/%" PRIu64 "WP\n",
               info.breakpoints, info.watchpoints);
    else
        printf("HWBP info: FAIL errno=%d (%s)\n", errno, strerror(errno));

    memset(&caps, 0, sizeof(caps));
    caps.abi_version = NBG_HWBP_CAPS_ABI_VERSION;
    if (ioctl(fd, OP_HWBP_CAPS, &caps) == 0)
        printf("HWBP caps: usable=%uBP/%uWP DFR0=0x%016" PRIx64
               " DFR1=0x%016" PRIx64 " ABLE=%u\n",
               caps.usable_breakpoints, caps.usable_watchpoints, caps.dfr0,
               caps.dfr1, (unsigned)((caps.dfr1 >> 40) & 0xfU));
    else
        printf("HWBP caps: FAIL errno=%d (%s)\n", errno, strerror(errno));

    bp_status = test_execute_breakpoint(fd);
    wp_status = test_write_watchpoint(fd);
    (void)ioctl(fd, OP_WATCH_CLEAR, NULL);
    close(fd);

    printf("RESULT: execute_bp=%s write_wp=%s\n",
           bp_status == 0 ? "PASS" : "FAIL",
           wp_status == 0 ? "PASS" : "FAIL");
    return bp_status || wp_status;
}
