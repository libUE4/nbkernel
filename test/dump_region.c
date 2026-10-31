/* dump_region.c — 把目标进程一段内存 dump 成十六进制
 *
 * 用来检查匿名可执行段的实际内容。
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char mem_path[64];
    int mem;
    unsigned long addr;
    unsigned long size;
    uint8_t *buffer;
    ssize_t got;
    unsigned long i;

    if (argc < 4) {
        printf("usage: dump_region <pid> <addr_hex> <size_hex>\n");
        return 1;
    }

    addr = strtoul(argv[2], NULL, 16);
    size = strtoul(argv[3], NULL, 16);

    snprintf(mem_path, sizeof(mem_path), "/proc/%s/mem", argv[1]);
    mem = open(mem_path, O_RDONLY);
    if (mem < 0) {
        perror("open mem");
        return 1;
    }

    buffer = malloc(size);
    if (!buffer) {
        printf("oom\n");
        return 1;
    }

    got = pread(mem, buffer, size, (off_t)addr);
    if (got <= 0) {
        printf("read failed %zd\n", got);
        return 1;
    }

    printf("=== %lx + %lx (read %zd) ===\n", addr, size, got);
    for (i = 0; i + 4 <= (unsigned long)got; i += 4) {
        uint32_t word;

        memcpy(&word, buffer + i, 4);
        printf("%08lx: %08x\n", addr + i, word);
    }

    close(mem);
    free(buffer);
    return 0;
}
