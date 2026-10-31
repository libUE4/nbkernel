/* scan_tramp.c — 在目标进程匿名可执行段里搜索 trampoline 特征
 *
 * 用来判断 xf_coord 那套密钥恢复方案在当前 DFM 版本上是否还有效。
 * 只读 /proc/<pid>/maps 与 /proc/<pid>/mem，不修改目标进程。
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const uint8_t kPattern[] = { 0xfe, 0x77, 0x3e, 0xa9, 0xfc, 0x77,
                                    0x3d, 0xa9, 0xfa, 0x6f, 0x3c, 0xa9 };
#define PATTERN_LEN (sizeof(kPattern))

static int is_target_region(const char *perms, const char *name)
{
    if (!strchr(perms, 'r') || !strchr(perms, 'x'))
        return 0;
    if (!name || !name[0])
        return 1;
    if (strncmp(name, "[anon:", 6) == 0)
        return 1;
    return 0;
}

int main(int argc, char **argv)
{
    char maps_path[64];
    char mem_path[64];
    FILE *maps;
    int mem;
    char line[512];
    unsigned long total = 0;
    int hits = 0;

    if (argc < 2) {
        printf("usage: scan_tramp <pid>\n");
        return 1;
    }

    snprintf(maps_path, sizeof(maps_path), "/proc/%s/maps", argv[1]);
    snprintf(mem_path, sizeof(mem_path), "/proc/%s/mem", argv[1]);

    maps = fopen(maps_path, "r");
    if (!maps) {
        perror("open maps");
        return 1;
    }
    mem = open(mem_path, O_RDONLY);
    if (mem < 0) {
        perror("open mem");
        fclose(maps);
        return 1;
    }

    while (fgets(line, sizeof(line), maps)) {
        unsigned long start;
        unsigned long end;
        char perms[8] = { 0 };
        char name[256] = { 0 };
        int fields;
        unsigned long size;
        uint8_t *buffer;
        ssize_t got;
        unsigned long i;

        fields = sscanf(line, "%lx-%lx %7s %*s %*s %*s %255[^\n]", &start, &end,
                        perms, name);
        if (fields < 3)
            continue;
        if (!is_target_region(perms, fields >= 4 ? name : NULL))
            continue;

        size = end - start;
        total += size;
        printf("region %lx-%lx size=%lx %s\n", start, end, size,
               fields >= 4 ? name : "");

        buffer = malloc(size);
        if (!buffer) {
            printf("  oom\n");
            continue;
        }
        got = pread(mem, buffer, size, (off_t)start);
        if (got <= 0) {
            printf("  read failed (%zd)\n", got);
            free(buffer);
            continue;
        }
        printf("  read %zd/%lu\n", got, size);

        for (i = 0; i + PATTERN_LEN <= (unsigned long)got; i++) {
            if (memcmp(buffer + i, kPattern, PATTERN_LEN) == 0) {
                printf("  HIT at %lx\n", start + i);
                hits++;
            }
        }
        free(buffer);
    }

    fclose(maps);
    close(mem);
    printf("\ntotal=%lx hits=%d\n", total, hits);
    return 0;
}
