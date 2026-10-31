#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define main check_main
#include "check_tramp.c"
#undef main

int main(void)
{
    uint8_t d[32];
    uint8_t z[160];
    int i;

    sha256((const uint8_t *)"abc", 3, d);
    printf("abc       -> ");
    for (i = 0; i < 32; i++)
        printf("%02x", d[i]);
    printf("\n");

    memset(z, 0, sizeof(z));
    sha256(z, 160, d);
    printf("160 zeros -> ");
    for (i = 0; i < 32; i++)
        printf("%02x", d[i]);
    printf("\n");

    return 0;
}
