/* gyro.c — 陀螺仪/加速度计数据覆盖
 *
 * system_server 通过 sendto 把 ASensorEvent 批量投递给应用。在
 * __arm64_sys_sendto 上挂 kprobe，直接在用户缓冲区里叠加偏移量，
 * 应用侧拿到的就是被改过的传感器读数。
 *
 * 内核态不能做浮点运算（会破坏 FP/SIMD 状态），所以用整数模拟
 * IEEE754 单精度加法。
 */
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "comm.h"
#include "gyro.h"
#include "nbg_compat.h"
#include "nbg_gki_compat.h"
#include "nbg_log.h"

#define NBG_SENSOR_EVENT_SIZE 104
#define NBG_SENSOR_TYPE_OFF   16
#define NBG_SENSOR_XY_OFF     24
#define NBG_SENDTO_LEN_MAX    (1000 * NBG_SENSOR_EVENT_SIZE)

#define NBG_SENSOR_TYPE_GYRO  4
/* ASensorEvent.type 就是 android.sensor.accelerometer = 1。 */
#define NBG_SENSOR_TYPE_ACCEL 1

#define NBG_GYRO_TYPE_GYRO    (1U << 0)
#define NBG_GYRO_TYPE_ACCEL   (1U << 1)

static bool g_gyro_enabled;
static u32 g_gyro_type_mask = NBG_GYRO_TYPE_GYRO | NBG_GYRO_TYPE_ACCEL;
static u32 g_gyro_x_raw;
static u32 g_gyro_y_raw;

static pid_t g_system_server_tgid = -1;
/* 诊断计数：命中 sendto 的次数、其中被识别为 system_server 的次数、
 * 以及实际改写过的传感器事件数。无日志构建下靠 ioctl 读回。 */
static atomic64_t g_gyro_sendto_hits = ATOMIC64_INIT(0);
static atomic64_t g_gyro_caller_hits = ATOMIC64_INIT(0);
static atomic64_t g_gyro_event_hits = ATOMIC64_INIT(0);

static struct kprobe g_sendto_kprobe;
static bool g_sendto_probe_registered;
static bool g_sendto_takes_ptregs;

/* 整数版 IEEE754 单精度加法：a、b、返回值都是 float 的位模式。 */
static u32 nbg_add_float_ieee754(u32 a, u32 b)
{
    u32 a_exp = (a >> 23) & 0xFF;
    u32 b_exp = (b >> 23) & 0xFF;
    u32 a_sign, b_sign, out_sign;
    u64 a_mant, b_mant, sum;
    u32 out_exp;

    if (a_exp == 0)
        return b;
    if (b_exp == 0)
        return a;
    if (a_exp == 0xFF)
        return a;
    if (b_exp == 0xFF)
        return b;

    a_sign = a & 0x80000000U;
    b_sign = b & 0x80000000U;
    a_mant = (u64)(a & 0x7FFFFFU) | 0x800000ULL;
    b_mant = (u64)(b & 0x7FFFFFU) | 0x800000ULL;

    if (a_exp < b_exp) {
        a_mant >>= (b_exp - a_exp);
        out_exp = b_exp;
    } else {
        b_mant >>= (a_exp - b_exp);
        out_exp = a_exp;
    }

    if (a_sign == b_sign) {
        sum = a_mant + b_mant;
        out_sign = a_sign;
    } else if (a_mant >= b_mant) {
        sum = a_mant - b_mant;
        out_sign = a_sign;
    } else {
        sum = b_mant - a_mant;
        out_sign = b_sign;
    }

    if (sum == 0)
        return 0;

    while ((sum >> 24) && out_exp <= 0xFD) {
        sum >>= 1;
        out_exp++;
    }
    while (!(sum & 0x800000) && out_exp > 1) {
        sum <<= 1;
        out_exp--;
    }

    return (u32)(out_sign | (out_exp << 23) | (sum & 0x7FFFFFU));
}

/* sendto 全系统高频调用，tgid 命中缓存后不再比较进程名。 */
/* system_server 的传感器事件由 binder/工作线程发出，线程名是
 * "binder:3790_1" 这种，不是 "system_server"；只有组长线程（tid==pid）
 * 才叫 system_server。所以必须看 group_leader 的名字，并且按 tgid 缓存。 */
static bool nbg_gyro_caller_is_system_server(void)
{
    pid_t tgid = current->tgid;
    pid_t cached = READ_ONCE(g_system_server_tgid);
    struct task_struct *leader;

    if (tgid == cached)
        return true;

    rcu_read_lock();
    leader = rcu_dereference(current->group_leader);
    if (leader && strcmp(leader->comm, "system_server") == 0) {
        rcu_read_unlock();
        WRITE_ONCE(g_system_server_tgid, tgid);
        return true;
    }
    rcu_read_unlock();

    return false;
}

static void nbg_gyro_patch_event(unsigned long uevent, u32 type_mask,
                                 u32 dx, u32 dy)
{
    s32 type = 0;
    u32 xy[2] = { 0, 0 };
    bool wanted = false;

    if (copy_from_user(&type, (void __user *)(uevent + NBG_SENSOR_TYPE_OFF),
                       sizeof(type)))
        return;

    if ((type_mask & NBG_GYRO_TYPE_GYRO) && type == NBG_SENSOR_TYPE_GYRO)
        wanted = true;
    if ((type_mask & NBG_GYRO_TYPE_ACCEL) && type == NBG_SENSOR_TYPE_ACCEL)
        wanted = true;
    if (!wanted)
        return;

    if (copy_from_user(xy, (void __user *)(uevent + NBG_SENSOR_XY_OFF),
                       sizeof(xy)))
        return;

    xy[0] = nbg_add_float_ieee754(xy[0], dx);
    xy[1] = nbg_add_float_ieee754(xy[1], dy);

    /* 写回失败不影响其它事件，应用侧读到的仍是更新前的读数。 */
    if (copy_to_user((void __user *)(uevent + NBG_SENSOR_XY_OFF), xy,
                     sizeof(xy)))
        return;
}

NBG_NO_CFI
static int nbg_gyro_sendto_pre(struct kprobe *probe, struct pt_regs *regs)
{
    unsigned long uevent;
    unsigned long length;
    unsigned int count, i;
    u32 type_mask, dx, dy;

    (void)probe;
    if (!READ_ONCE(g_gyro_enabled))
        return 0;

    atomic64_inc(&g_gyro_sendto_hits);

    if (!regs || !nbg_gyro_caller_is_system_server())
        return 0;

    atomic64_inc(&g_gyro_caller_hits);

    if (g_sendto_takes_ptregs) {
        struct pt_regs *user = (struct pt_regs *)regs->regs[0];

        if (!user)
            return 0;
        uevent = user->regs[1];
        length = user->regs[2];
    } else {
        uevent = regs->regs[1];
        length = regs->regs[2];
    }

    if (!uevent || !length || length > NBG_SENDTO_LEN_MAX)
        return 0;
    if (length % NBG_SENSOR_EVENT_SIZE)
        return 0;

    type_mask = READ_ONCE(g_gyro_type_mask);
    dx = READ_ONCE(g_gyro_x_raw);
    dy = READ_ONCE(g_gyro_y_raw);

    count = (unsigned int)(length / NBG_SENSOR_EVENT_SIZE);
    for (i = 0; i < count; i++)
        nbg_gyro_patch_event(uevent + (unsigned long)i * NBG_SENSOR_EVENT_SIZE,
                             type_mask, dx, dy);

    atomic64_add(count, &g_gyro_event_hits);

    return 0;
}

int nbg_gyro_ioctl(unsigned long argument)
{
    NBG_GYRO_REQ req;

    if (copy_from_user(&req, (void __user *)argument, sizeof(req)))
        return -EFAULT;

    /* action=2 只读诊断计数，不改开关。 */
    if (req.action == 2) {
        req.x = (int32_t)atomic64_read(&g_gyro_sendto_hits);
        req.y = (int32_t)atomic64_read(&g_gyro_caller_hits);
        req.type_mask = (uint32_t)atomic64_read(&g_gyro_event_hits);
        return copy_to_user((void __user *)argument, &req, sizeof(req))
                   ? -EFAULT
                   : 0;
    }

    if (req.action) {
        WRITE_ONCE(g_gyro_type_mask, req.type_mask);
        WRITE_ONCE(g_gyro_x_raw, (u32)req.x);
        WRITE_ONCE(g_gyro_y_raw, (u32)req.y);
        WRITE_ONCE(g_gyro_enabled, true);
    } else {
        WRITE_ONCE(g_gyro_enabled, false);
    }
    return 0;
}

static const char *const g_sendto_symbols[] = {
    "__arm64_sys_sendto",
    "__se_sys_sendto",
    "sys_sendto",
    NULL,
};

int nbg_gyro_init(void)
{
    int i;

    if (g_sendto_probe_registered)
        return 0;

    for (i = 0; g_sendto_symbols[i]; i++) {
        memset(&g_sendto_kprobe, 0, sizeof(g_sendto_kprobe));
        g_sendto_kprobe.symbol_name = g_sendto_symbols[i];
        g_sendto_kprobe.pre_handler = nbg_gyro_sendto_pre;

        if (nbg_register_kprobe(&g_sendto_kprobe) == 0) {
            g_sendto_probe_registered = true;
            /* __arm64_sys_* 的 regs 指向用户 pt_regs，参数要多解一层。 */
            g_sendto_takes_ptregs = (i == 0);
            NBG_INFO("gyro: kprobe installed @ %s\n", g_sendto_symbols[i]);
            return 0;
        }
    }

    NBG_WARN("gyro: no sendto symbol resolvable\n");
    return -ENOENT;
}

void nbg_gyro_exit(void)
{
    if (g_sendto_probe_registered) {
        nbg_unregister_kprobe(&g_sendto_kprobe);
        g_sendto_probe_registered = false;
    }
    WRITE_ONCE(g_gyro_enabled, false);
    WRITE_ONCE(g_system_server_tgid, -1);
}
