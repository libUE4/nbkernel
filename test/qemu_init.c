/* qemu 冒烟测试用的最小 init。
 *
 * 这套内核 exec 带 shebang 的脚本会返回 ENOEXEC，而 DDK 镜像是 x86-64，
 * 装出来的 busybox 也无法在 arm64 guest 里跑。所以这里不带 libc，
 * 直接用裸 syscall：打开 /NBG.ko，finit_module 加载，打印结果后关机。
 */
typedef signed long s64;

static inline s64 svc4(s64 number, s64 a0, s64 a1, s64 a2, s64 a3)
{
    register s64 x8 asm("x8") = number;
    register s64 x0 asm("x0") = a0;
    register s64 x1 asm("x1") = a1;
    register s64 x2 asm("x2") = a2;
    register s64 x3 asm("x3") = a3;

    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
                 : "memory");
    return x0;
}

#define SYS_OPENAT 56
#define SYS_WRITE 64
#define SYS_FINIT_MODULE 273
#define SYS_REBOOT 142
#define AT_FDCWD (-100)

#define REBOOT_MAGIC1 0xfee1dead
#define REBOOT_MAGIC2 672274793
#define REBOOT_POWER_OFF 0x4321fedc

static void write_text(const char *text)
{
    s64 length = 0;

    while (text[length] != '\0')
        ++length;

    svc4(SYS_WRITE, 1, (s64)text, length, 0);
}

/* 只打印十进制，足够输出 errno。 */
static void write_decimal(s64 value)
{
    char digits[24];
    int count = 0;

    if (value < 0) {
        write_text("-");
        value = -value;
    }

    if (value == 0) {
        write_text("0");
        return;
    }

    while (value > 0 && count < (int)sizeof(digits)) {
        digits[count++] = (char)('0' + (value % 10));
        value /= 10;
    }

    while (count > 0) {
        char one = digits[--count];

        svc4(SYS_WRITE, 1, (s64)&one, 1, 0);
    }
}

void _start(void)
{
    s64 fd = svc4(SYS_OPENAT, AT_FDCWD, (s64)"/NBG.ko", 0, 0);

    if (fd < 0) {
        write_text("OPEN_FAIL rc=");
        write_decimal(fd);
        write_text("\n");
    } else {
        s64 result = svc4(SYS_FINIT_MODULE, fd, (s64)"", 0, 0);

        if (result == 0) {
            write_text("INIT_MODULE_OK\n");
        } else {
            write_text("INIT_MODULE_FAIL rc=");
            write_decimal(result);
            write_text("\n");
        }
    }

    svc4(SYS_REBOOT, REBOOT_MAGIC1, REBOOT_MAGIC2, REBOOT_POWER_OFF, 0);

    for (;;)
        ;
}
