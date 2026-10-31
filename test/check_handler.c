/* check_handler.c — 从匹配的 trampoline 取 context/handler，校验 handler 指纹
 *
 * xf_coord 的判定链：
 *   trampoline: sha256(raw[8..0xa8]) == 3e5f110b...
 *   context   = le64(raw[0]) & 0x00ffffffffffffff
 *   handler   = le64(raw[0xa8])
 *   handler:    sha256(0x3000 bytes) == 0820f519...
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define main check_tramp_main
#include "check_tramp.c"
#undef main

static const char *kHandlerWant =
    "0820f519d3146f9e81e0fa868ac56af57e741fa9cf7494a7bf842bdc4762fd8f";

static uint64_t le64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;

    for (i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

int main(int argc, char **argv)
{
    char mem_path[64];
    int mem;
    int i;
    int handler_ok = 0;

    if (argc < 3) {
        printf("usage: check_handler <pid> <hit_addr_hex> [...]\n");
        return 1;
    }

    snprintf(mem_path, sizeof(mem_path), "/proc/%s/mem", argv[1]);
    mem = open(mem_path, O_RDONLY);
    if (mem < 0) {
        perror("open mem");
        return 1;
    }

    for (i = 2; i < argc; i++) {
        unsigned long hit = strtoul(argv[i], NULL, 16);
        uint8_t raw[0xb0];
        uint8_t digest[32];
        char hex[65];
        uint64_t context;
        uint64_t handler;
        uint8_t *code;
        ssize_t got;
        int j;

        got = pread(mem, raw, sizeof(raw), (off_t)(hit - 8));
        if (got != (ssize_t)sizeof(raw))
            continue;

        sha256(raw + 8, 0xa0, digest);
        for (j = 0; j < 32; j++)
            sprintf(hex + j * 2, "%02x", digest[j]);
        hex[64] = '\0';
        if (strcmp(hex, "3e5f110b6e3c82cc285883d20f19e1b987e808edd522a141e9bb32e332561f19"))
            continue;

        context = le64(raw) & 0x00ffffffffffffffULL;
        handler = le64(raw + 0xa8);

        code = malloc(0x3000);
        if (!code) {
            printf("%lx: oom\n", hit);
            continue;
        }
        got = pread(mem, code, 0x3000, (off_t)handler);
        if (got != 0x3000) {
            printf("%lx ctx=%llx handler=%llx read failed (%zd)\n", hit,
                   (unsigned long long)context,
                   (unsigned long long)handler, got);
            free(code);
            continue;
        }

        sha256(code, 0x3000, digest);
        for (j = 0; j < 32; j++)
            sprintf(hex + j * 2, "%02x", digest[j]);
        hex[64] = '\0';

        printf("%lx ctx=%llx handler=%llx\n  sha=%s %s\n", hit,
               (unsigned long long)context, (unsigned long long)handler, hex,
               strcmp(hex, kHandlerWant) == 0 ? "*** HANDLER MATCH ***" : "");
        if (strcmp(hex, kHandlerWant) == 0)
            handler_ok++;
        free(code);
    }

    printf("\nhandler_matched=%d\n", handler_ok);
    close(mem);
    return 0;
}
