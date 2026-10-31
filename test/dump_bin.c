/* dump_bin.c — 把目标进程一段内存原样写成文件
 *
 * 用来把 handler 代码取回本地做反汇编。
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char mem_path[64];
    char out_path[128];
    int mem;
    int out;
    unsigned long addr;
    unsigned long size;
    uint8_t *buffer;
    ssize_t got;
    ssize_t written;

    if (argc < 5) {
        printf("usage: dump_bin <pid> <addr_hex> <size_hex> <outfile>\n");
        return 1;
    }

    addr = strtoul(argv[2], NULL, 16);
    size = strtoul(argv[3], NULL, 16);
    snprintf(out_path, sizeof(out_path), "%s", argv[4]);

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

    out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) {
        perror("open out");
        return 1;
    }

    written = write(out, buffer, (size_t)got);
    close(out);
    close(mem);
    free(buffer);

    printf("wrote %zd bytes to %s (from %lx)\n", written, out_path, addr);
    return 0;
}
