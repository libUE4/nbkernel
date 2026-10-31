/* check_tramp.c — 校验候选 trampoline 的 SHA256 是否匹配
 *
 * xf_coord 的判定：从命中地址 -8 处取 0xb0 字节，对其中 [8,0xa8)
 * 这 160 字节做 SHA256，要求等于硬编码值。
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 目标 trampoline 指纹。 */
static const char *kWant =
    "3e5f110b6e3c82cc285883d20f19e1b987e808edd522a141e9bb32e332561f19";

static const uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotr(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    uint8_t block[128];
    size_t total = len + 1 + 8;
    size_t padded = ((total + 63) / 64) * 64;
    uint8_t *buf = calloc(1, padded);
    size_t offset;
    uint64_t bits = (uint64_t)len * 8;
    int i;

    if (!buf)
        return;
    memcpy(buf, data, len);
    buf[len] = 0x80;
    for (i = 0; i < 8; i++)
        buf[padded - 1 - i] = (uint8_t)(bits >> (i * 8));

    for (offset = 0; offset < padded; offset += 64) {
        uint32_t w[64];
        uint32_t a, b, c, d, e, f, g, hh;

        for (i = 0; i < 16; i++) {
            w[i] = ((uint32_t)buf[offset + i * 4] << 24) |
                   ((uint32_t)buf[offset + i * 4 + 1] << 16) |
                   ((uint32_t)buf[offset + i * 4 + 2] << 8) |
                   (uint32_t)buf[offset + i * 4 + 3];
        }
        for (i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^
                          (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^
                          (w[i - 2] >> 10);

            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        a = h[0]; b = h[1]; c = h[2]; d = h[3];
        e = h[4]; f = h[5]; g = h[6]; hh = h[7];

        for (i = 0; i < 64; i++) {
            uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + s1 + ch + kK[i] + w[i];
            uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = s0 + maj;

            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    for (i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)h[i];
    }
    free(buf);
}

int main(int argc, char **argv)
{
    char mem_path[64];
    int mem;
    int i;
    int matched = 0;

    if (argc < 3) {
        printf("usage: check_tramp <pid> <hit_addr_hex> [...]\n");
        return 1;
    }

    snprintf(mem_path, sizeof(mem_path), "/proc/%s/mem", argv[1]);
    mem = open(mem_path, O_RDONLY);
    if (mem < 0) {
        perror("open mem");
        return 1;
    }

    printf("want sha256 = %s\n\n", kWant);

    for (i = 2; i < argc; i++) {
        unsigned long hit = strtoul(argv[i], NULL, 16);
        unsigned long base = hit - 8;
        uint8_t raw[0xb0];
        uint8_t digest[32];
        char hex[65];
        ssize_t got;
        int j;

        got = pread(mem, raw, sizeof(raw), (off_t)base);
        if (got != (ssize_t)sizeof(raw)) {
            printf("%lx: read failed (%zd)\n", hit, got);
            continue;
        }

        sha256(raw + 8, 0xa0, digest);
        for (j = 0; j < 32; j++)
            sprintf(hex + j * 2, "%02x", digest[j]);
        hex[64] = '\0';

        printf("%lx: %s %s\n", hit, hex,
               strcmp(hex, kWant) == 0 ? "*** MATCH ***" : "");
        if (strcmp(hex, kWant) == 0)
            matched++;
    }

    close(mem);
    printf("\nmatched=%d\n", matched);
    return 0;
}
