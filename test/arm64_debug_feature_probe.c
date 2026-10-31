/*
 * Read-only Arm64 debug-feature probe.
 *
 * Linux can expose selected ID registers to EL0 when HWCAP_CPUID is set.
 * Some older kernels do not emulate newer registers; isolate each MRS behind
 * a SIGILL guard so probing an unavailable register only fails this process.
 */
#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(__aarch64__)
#error "This probe must be compiled for AArch64"
#endif

static sigjmp_buf probe_jmp;
static volatile sig_atomic_t probe_active;

static void probe_sigill(int signo)
{
    (void)signo;
    if (probe_active)
        siglongjmp(probe_jmp, 1);
}

static bool read_id_register(unsigned int which, uint64_t *value)
{
    if (sigsetjmp(probe_jmp, 1) != 0) {
        probe_active = 0;
        return false;
    }

    probe_active = 1;
    switch (which) {
    case 0:
        __asm__ volatile("mrs %0, ID_AA64DFR0_EL1" : "=r"(*value));
        break;
    case 1:
        __asm__ volatile("mrs %0, ID_AA64DFR1_EL1" : "=r"(*value));
        break;
    case 2:
        __asm__ volatile("mrs %0, ID_AA64DFR2_EL1" : "=r"(*value));
        break;
    default:
        probe_active = 0;
        return false;
    }
    probe_active = 0;
    return true;
}

int main(void)
{
    struct sigaction old_action;
    struct sigaction action;
    uint64_t dfr0 = 0;
    uint64_t dfr1 = 0;
    uint64_t dfr2 = 0;
    bool have_dfr0;
    bool have_dfr1;
    bool have_dfr2;

    memset(&action, 0, sizeof(action));
    action.sa_handler = probe_sigill;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGILL, &action, &old_action) != 0) {
        perror("sigaction(SIGILL)");
        return 1;
    }

    have_dfr0 = read_id_register(0, &dfr0);
    have_dfr1 = read_id_register(1, &dfr1);
    have_dfr2 = read_id_register(2, &dfr2);
    (void)sigaction(SIGILL, &old_action, NULL);

    if (have_dfr0) {
        printf("DFR0=0x%016" PRIx64 " BRPs=%u WRPs=%u\n", dfr0,
               (unsigned)(((dfr0 >> 12) & 0xfU) + 1U),
               (unsigned)(((dfr0 >> 20) & 0xfU) + 1U));
    } else {
        puts("DFR0=unavailable");
    }

    if (have_dfr1) {
        printf("DFR1=0x%016" PRIx64 " ABLE=%u\n", dfr1,
               (unsigned)((dfr1 >> 40) & 0xfU));
    } else {
        puts("DFR1=unavailable");
    }

    if (have_dfr2) {
        printf("DFR2=0x%016" PRIx64 " BWE=%u STEP=%u\n", dfr2,
               (unsigned)((dfr2 >> 4) & 0xfU),
               (unsigned)(dfr2 & 0xfU));
    } else {
        puts("DFR2=unavailable");
    }

    return have_dfr0 ? 0 : 2;
}
