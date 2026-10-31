#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

static void print_result(const char *name, int result)
{
    printf("%s=%d errno=%d (%s)\n", name, result, errno, strerror(errno));
}

int main(void)
{
    char comm[17] = {};
    char link_path[64];
    char link_target[128] = {};
    struct stat st;
    struct dirent *entry;
    DIR *dir;
    int fd;
    ssize_t n;

    prctl(PR_SET_NAME, "com.tencent.tmg", 0, 0, 0);
    fd = open("/proc/self/comm", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        (void)read(fd, comm, sizeof(comm) - 1);
        close(fd);
    }
    printf("comm=%s", comm);

    errno = 0;
    print_result("stat_pts_0", stat("/dev/pts/0", &st));

    errno = 0;
    print_result("faccessat_pts_0", faccessat(AT_FDCWD, "/dev/pts/0", F_OK, 0));

    errno = 0;
    fd = open("/dev/pts/0", O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    print_result("open_pts_0", fd);
    if (fd >= 0)
        close(fd);

    dir = opendir("/dev/pts");
    if (!dir) {
        print_result("opendir_pts", -1);
    } else {
        printf("readdir_pts=");
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
                printf("%s,", entry->d_name);
        }
        puts("");
        closedir(dir);
    }

    errno = 0;
    fd = open("/dev/ptmx", O_RDWR | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    print_result("open_ptmx", fd);
    if (fd >= 0) {
        snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);
        errno = 0;
        n = readlink(link_path, link_target, sizeof(link_target) - 1);
        if (n >= 0)
            link_target[n] = '\0';
        printf("readlink_ptmx=%zd errno=%d target=%s\n", n, errno,
               n >= 0 ? link_target : "<none>");
        close(fd);
    }

    return 0;
}
