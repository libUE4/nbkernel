/* Independent present-only versus fault-in read regression test. */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "secret.h"
#include "comm.h"

struct target_info {
    uintptr_t address;
    size_t length;
    uint32_t page_size;
    int32_t status;
};

static int write_full(int fd, const void *buffer, size_t size)
{
    const uint8_t *p = buffer;
    while (size) {
        ssize_t n = write(fd, p, size);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        size -= (size_t)n;
    }
    return 0;
}

static int read_full(int fd, void *buffer, size_t size)
{
    uint8_t *p = buffer;
    while (size) {
        ssize_t n = read(fd, p, size);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        size -= (size_t)n;
    }
    return 0;
}

static uint8_t pattern_byte(size_t offset)
{
    return (uint8_t)((offset * 131U + (offset >> 3U) * 17U + 0x5aU) & 0xffU);
}

static int verify_pattern(const uint8_t *buffer, size_t offset, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i) {
        if (buffer[i] != pattern_byte(offset + i))
            return -1;
    }
    return 0;
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int run_target(int command_fd, int result_fd)
{
    struct target_info info = {0};
    char path[] = "/data/local/tmp/nbg_fault.XXXXXX";
    long page = sysconf(_SC_PAGESIZE);
    int fd;
    uint8_t *data;
    uint8_t *mapping;
    size_t length;
    size_t done;
    volatile uint8_t touch = 0;

    if (page <= 0) {
        info.status = -EINVAL;
        write_full(result_fd, &info, sizeof(info));
        return 2;
    }
    length = (size_t)page * 3U;
    fd = mkstemp(path);
    data = malloc(length);
    if (fd < 0 || !data) {
        info.status = -errno;
        write_full(result_fd, &info, sizeof(info));
        return 2;
    }
    for (done = 0; done < length; ++done)
        data[done] = pattern_byte(done);
    done = 0;
    while (done < length) {
        ssize_t n = pwrite(fd, data + done, length - done, (off_t)done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            info.status = n < 0 ? -errno : -EIO;
            write_full(result_fd, &info, sizeof(info));
            return 2;
        }
        done += (size_t)n;
    }
    fsync(fd);
    mapping = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapping == MAP_FAILED) {
        info.status = -errno;
        write_full(result_fd, &info, sizeof(info));
        return 2;
    }
    for (done = 0; done < length; done += (size_t)page)
        touch ^= mapping[done];
    (void)touch;
    unlink(path);
    close(fd);
    free(data);

    info.address = (uintptr_t)mapping;
    info.length = length;
    info.page_size = (uint32_t)page;
    if (write_full(result_fd, &info, sizeof(info)) != 0)
        return 2;

    for (;;) {
        char command;
        int32_t status = 0;
        if (read_full(command_fd, &command, 1) != 0 || command == 'Q')
            break;
        if (command != 'E')
            status = -EINVAL;
        else if (madvise(mapping, length, MADV_DONTNEED) != 0)
            status = -errno;
        __sync_synchronize();
        if (write_full(result_fd, &status, sizeof(status)) != 0)
            break;
    }
    munmap(mapping, length);
    return 0;
}

static int connect_driver(int *family_out)
{
    int family;
    for (family = 1; family < 50; ++family) {
        int fd = socket(family, SOCK_RAW, NBG_SOCKET_PROTOCOL);
        struct _INIT_KEY key = {0};
        if (fd < 0)
            continue;
        key.abi_version = NBG_ABI_VERSION;
        key.token = NBG_AUTH_TOKEN;
        if (ioctl(fd, OP_INIT_KEY, &key) == 0 && key.accepted == 1U &&
            key.family == (uint32_t)family) {
            *family_out = family;
            return fd;
        }
        close(fd);
    }
    return -1;
}

static int remote_read(int fd, unsigned int operation, pid_t pid,
                       uintptr_t address, void *buffer, size_t size)
{
    struct _COPY_MEMORY request = {pid, address, buffer, size};
    return ioctl(fd, operation, &request);
}

int main(int argc, char **argv)
{
    uint64_t seconds = argc > 1 ? strtoull(argv[1], NULL, 10) : 5;
    int commands[2];
    int results[2];
    pid_t child;
    struct target_info target;
    int family = 0;
    int driver_fd;
    uint8_t buffer[160];
    uint64_t deadline;
    uint64_t loops = 0;
    uint64_t total_ns = 0;
    uint64_t max_ns = 0;
    int failed = 0;

    if (!seconds || pipe(commands) != 0 || pipe(results) != 0)
        return 2;
    signal(SIGPIPE, SIG_IGN);
    child = fork();
    if (child == 0) {
        close(commands[1]);
        close(results[0]);
        _exit(run_target(commands[0], results[1]));
    }
    if (child < 0)
        return 2;
    close(commands[0]);
    close(results[1]);
    memset(&target, 0, sizeof(target));
    if (read_full(results[0], &target, sizeof(target)) != 0 || target.status) {
        fprintf(stderr, "target setup failed status=%d\n", target.status);
        return 2;
    }
    driver_fd = connect_driver(&family);
    if (driver_fd < 0) {
        fprintf(stderr, "driver auth failed\n");
        return 2;
    }
    printf("START seconds=%" PRIu64 " family=%d child=%d page=%u address=0x%" PRIxPTR "\n",
           seconds, family, child, target.page_size, target.address);
    deadline = now_ns() + seconds * 1000000000ULL;
    while (now_ns() < deadline) {
        char command = 'E';
        int32_t evict_status = 0;
        uint64_t started;
        uint64_t elapsed;
        const size_t small_offset = 113U;
        const size_t cross_offset = target.page_size - 37U;

        if (write_full(commands[1], &command, 1) != 0 ||
            read_full(results[0], &evict_status, sizeof(evict_status)) != 0 ||
            evict_status != 0) {
            fprintf(stderr, "evict failed loop=%" PRIu64 " status=%d\n", loops,
                    evict_status);
            failed = 1;
            break;
        }
        if (remote_read(driver_fd, OP_READ_MEM, child,
                        target.address + small_offset, buffer, 64) == 0) {
            fprintf(stderr, "normal read unexpectedly succeeded loop=%" PRIu64 "\n", loops);
            failed = 1;
            break;
        }
        started = now_ns();
        if (remote_read(driver_fd, OP_READ_MEM_FAULT, child,
                        target.address + small_offset, buffer, 64) != 0 ||
            verify_pattern(buffer, small_offset, 64) != 0) {
            fprintf(stderr, "fault read failed loop=%" PRIu64 " errno=%d\n", loops, errno);
            failed = 1;
            break;
        }
        elapsed = now_ns() - started;
        total_ns += elapsed;
        if (elapsed > max_ns)
            max_ns = elapsed;
        if (remote_read(driver_fd, OP_READ_MEM_FAULT, child,
                        target.address + cross_offset, buffer, 128) != 0 ||
            verify_pattern(buffer, cross_offset, 128) != 0) {
            fprintf(stderr, "cross-page fault read failed loop=%" PRIu64 " errno=%d\n",
                    loops, errno);
            failed = 1;
            break;
        }
        if (remote_read(driver_fd, OP_READ_MEM, child,
                        target.address + cross_offset, buffer, 128) != 0 ||
            verify_pattern(buffer, cross_offset, 128) != 0) {
            fprintf(stderr, "post-fault fast read failed loop=%" PRIu64 "\n", loops);
            failed = 1;
            break;
        }
        ++loops;
    }

    {
        char command = 'Q';
        int child_status = 0;
        write_full(commands[1], &command, 1);
        waitpid(child, &child_status, 0);
        if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0)
            failed = 1;
    }
    close(driver_fd);
    printf("RESULT loops=%" PRIu64 " avg_us=%.3f max_us=%.3f errors=%d\n",
           loops, loops ? (double)total_ns / (double)loops / 1000.0 : 0.0,
           (double)max_ns / 1000.0, failed);
    printf("%s\n", !failed && loops ? "PASS" : "FAIL");
    return !failed && loops ? 0 : 1;
}
