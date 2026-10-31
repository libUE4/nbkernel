/* Trace one already-NOPed instruction with the driver's case-24 hook. */
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../secret.h"
#include "comm.h"

#define TRACE_HOOK_TYPE 24
#define TRACE_EVENT_X8_X9   0xD241U
#define TRACE_EVENT_X10_X11 0xD242U
#define TRACE_EVENT_X12_X13 0xD243U
#define TRACE_EVENT_SP_LR   0xD244U

static volatile sig_atomic_t g_stop;

static void on_signal(int signo)
{
    (void)signo;
    g_stop = 1;
}

static int open_driver(void)
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
        if (ioctl(fd, OP_INIT_KEY, &key) == 0 && key.accepted == 1U)
            return fd;
        last_error = errno;
        close(fd);
    }

    errno = last_error;
    return -1;
}

static uint64_t monotonic_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static int drain_events(int fd, uint64_t *event_count, uint32_t *max_hit)
{
    for (;;) {
        WatchReadReq batch;
        uint32_t i;

        memset(&batch, 0, sizeof(batch));
        if (ioctl(fd, OP_WATCH_READ, &batch) != 0)
            return -1;
        if (batch.count == 0)
            return 0;

        for (i = 0; i < batch.count; i++) {
            const WatchEvent *event = &batch.events[i];

            if (event->bp_type != TRACE_EVENT_X8_X9 &&
                event->bp_type != TRACE_EVENT_X10_X11 &&
                event->bp_type != TRACE_EVENT_X12_X13 &&
                event->bp_type != TRACE_EVENT_SP_LR)
                continue;
            (*event_count)++;
            if (event->hit_count > *max_hit)
                *max_hit = event->hit_count;
            printf("TRACE_EVENT type=0x%x hit=%u pid=%d tid=%d a=0x%" PRIx64
                   " b=0x%" PRIx64 "\n",
                   event->bp_type, event->hit_count, event->pid,
                   event->tid, event->watch_addr, event->pc);
        }
        fflush(stdout);
    }
}

int main(int argc, char **argv)
{
    ShadowHookReq req;
    uint64_t address;
    uint64_t event_count = 0;
    uint32_t max_hit = 0;
    uint64_t deadline;
    unsigned long duration = 30;
    int pid;
    int fd;
    int result = 1;

    if (argc < 3 || argc > 4) {
        fprintf(stderr, "usage: %s PID ADDRESS [SECONDS]\n", argv[0]);
        return 2;
    }
    pid = atoi(argv[1]);
    address = strtoull(argv[2], NULL, 0);
    if (argc == 4)
        duration = strtoul(argv[3], NULL, 0);
    if (pid <= 0 || address == 0 || (address & 3U) != 0 || duration == 0) {
        fprintf(stderr, "invalid PID, ADDRESS, or SECONDS\n");
        return 2;
    }

    fd = open_driver();
    if (fd < 0) {
        fprintf(stderr, "auth=FAIL errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    (void)drain_events(fd, &event_count, &max_hit);
    event_count = 0;
    max_hit = 0;

    memset(&req, 0, sizeof(req));
    req.pid = pid;
    req.target_vaddr = address;
    req.is_rot_hook = TRACE_HOOK_TYPE;
    if (ioctl(fd, OP_SHADOW_ADD, &req) != 0) {
        fprintf(stderr, "TRACE_ADD=FAIL pid=%d addr=0x%" PRIx64
                " errno=%d (%s)\n",
                pid, address, errno, strerror(errno));
        close(fd);
        return 1;
    }

    printf("TRACE_READY pid=%d addr=0x%" PRIx64 " seconds=%lu\n",
           pid, address, duration);
    fflush(stdout);
    deadline = monotonic_ms() + duration * 1000ULL;
    while (!g_stop && monotonic_ms() < deadline) {
        if (drain_events(fd, &event_count, &max_hit) != 0) {
            fprintf(stderr, "TRACE_READ=FAIL errno=%d (%s)\n",
                    errno, strerror(errno));
            goto cleanup;
        }
        if (event_count > 0)
            break;
        usleep(50000);
    }
    if (drain_events(fd, &event_count, &max_hit) != 0) {
        fprintf(stderr, "TRACE_READ=FAIL errno=%d (%s)\n",
                errno, strerror(errno));
        goto cleanup;
    }
    result = event_count > 0 ? 0 : 3;

cleanup:
    if (ioctl(fd, OP_SHADOW_DELETE, &req) != 0)
        fprintf(stderr, "TRACE_DELETE=FAIL errno=%d (%s)\n",
                errno, strerror(errno));
    printf("TRACE_DONE events=%" PRIu64 " max_hit=%u result=%s\n",
           event_count, max_hit, result == 0 ? "HIT" : "NO_HIT");
    close(fd);
    return result;
}
