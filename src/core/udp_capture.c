/* udp_capture.c — UDP 报文旁路抓取
 *
 * 在 udp_queue_rcv_one_skb 上挂 kprobe，按 socket 的 UID 过滤，
 * 把命中报文复制进环形缓冲，供用户态按序取走。抓取过程不改变
 * 数据流向，也不修改报文内容。
 *
 * 缓冲区所有权：每个 packet 在任一时刻只属于「环形缓冲 / 读取槽 /
 * CPU 暂存」三者之一。所有权在 g_udp_lock 下交换，报文内容从不
 * 在该锁内搬运。
 */
#include "udp_capture.h"

#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/udp.h>
#include <linux/uidgid.h>
#include <linux/vmalloc.h>
#include <net/sock.h>

#include "comm.h"
#include "nbg_compat.h"

#define UDP_CAP_RING 256U

/* 与用户态 NBG_UDP_PACKET 布局一致，ABI 边界上必须逐字节相同。 */
struct nbg_udp_packet {
    u64 ts_ns;
    u64 seq;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u16 payload_len;
    u16 flags;
    u32 sock_uid;
    u32 reserved;
    u8 payload[NBG_UDP_CAP_MAX_PAYLOAD];
};

static_assert(sizeof(struct nbg_udp_packet) == sizeof(NBG_UDP_PACKET),
              "udp packet ABI layout changed");
static_assert(offsetof(struct nbg_udp_packet, payload) ==
              offsetof(NBG_UDP_PACKET, payload),
              "udp packet payload offset changed");

static DEFINE_MUTEX(g_udp_init_lock);
static DEFINE_MUTEX(g_udp_read_lock);
static DEFINE_SPINLOCK(g_udp_lock);

static struct kprobe g_udp_kp;
static bool g_udp_hooked;
static bool g_udp_enabled;
static uid_t g_udp_uid;
static u16 g_udp_min_len = 16;
static u16 g_udp_max_len = NBG_UDP_CAP_MAX_PAYLOAD;
static u64 g_udp_seq;
static u64 g_udp_overflow;
static u64 g_udp_captured;
static u32 g_udp_head;
static u32 g_udp_tail;
static u32 g_udp_count;

static struct nbg_udp_packet *g_udp_pool;
static struct nbg_udp_packet *g_udp_ring[UDP_CAP_RING];
static struct nbg_udp_packet *g_udp_read_slots[NBG_UDP_CAP_READ_MAX];
static struct nbg_udp_packet *g_udp_stage;
static DEFINE_PER_CPU(struct nbg_udp_packet *, g_udp_scratch);

static uid_t nbg_udp_uid_from_pid(pid_t pid)
{
    struct task_struct *task;
    uid_t uid = 0;

    if (pid <= 0)
        return 0;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        uid = from_kuid(&init_user_ns, task_uid(task));
    rcu_read_unlock();
    return uid;
}

static bool nbg_udp_sock_uid_ok(const struct sock *sk)
{
    uid_t sock_uid;

    if (!sk)
        return false;
    sock_uid = from_kuid_munged(&init_user_ns, sk->sk_uid);
    return sock_uid == READ_ONCE(g_udp_uid);
}

static int nbg_udp_fill_packet(struct sk_buff *skb, struct nbg_udp_packet *out)
{
    const struct iphdr *ip;
    const struct udphdr *udp;
    int off;
    int plen;
    int copy;

    if (!skb || skb->protocol != htons(ETH_P_IP))
        return -EINVAL;

    ip = ip_hdr(skb);
    udp = udp_hdr(skb);
    if (!ip || !udp || ip->version != 4 || ip->protocol != IPPROTO_UDP)
        return -EINVAL;

    plen = ntohs(udp->len);
    if (plen < (int)sizeof(*udp))
        return -EINVAL;
    plen -= (int)sizeof(*udp);
    if (plen < (int)READ_ONCE(g_udp_min_len))
        return -EINVAL;

    out->src_ip = ip->saddr;
    out->dst_ip = ip->daddr;
    out->src_port = ntohs(udp->source);
    out->dst_port = ntohs(udp->dest);
    out->flags = 0;
    out->reserved = 0;

    copy = plen;
    if (copy > (int)READ_ONCE(g_udp_max_len)) {
        copy = READ_ONCE(g_udp_max_len);
        out->flags |= NBG_UDP_CAP_F_TRUNC;
    }
    if (copy > (int)NBG_UDP_CAP_MAX_PAYLOAD) {
        copy = NBG_UDP_CAP_MAX_PAYLOAD;
        out->flags |= NBG_UDP_CAP_F_TRUNC;
    }

    off = skb_transport_offset(skb) + (int)sizeof(*udp);
    if (skb_copy_bits(skb, off, out->payload, copy))
        return -EFAULT;

    /* 尾部清零交给读取侧：短包与丢弃包不必在这里付 2KiB 代价。 */
    out->payload_len = (u16)copy;
    return 0;
}

static int nbg_udp_rcv_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct sock *sk;
    struct sk_buff *skb;
    struct nbg_udp_packet *slot;
    struct nbg_udp_packet **scratch;
    unsigned long flags;

    (void)p;
    if (!smp_load_acquire(&g_udp_enabled))
        return 0;

    sk = (struct sock *)regs->regs[0];
    skb = (struct sk_buff *)regs->regs[1];
    if (!nbg_udp_sock_uid_ok(sk))
        return 0;

    /* kprobe handler 不会迁移且递归探针被抑制，所以本 CPU 的暂存包
     * 在发布前是私有的。配置变更会先注销并排空探针再更新。 */
    scratch = this_cpu_ptr(&g_udp_scratch);
    slot = *scratch;
    if (nbg_udp_fill_packet(skb, slot))
        return 0;
    slot->sock_uid = g_udp_uid;

    spin_lock_irqsave(&g_udp_lock, flags);
    if (!g_udp_enabled) {
        spin_unlock_irqrestore(&g_udp_lock, flags);
        return 0;
    }
    if (g_udp_count == UDP_CAP_RING) {
        g_udp_overflow++;
        g_udp_tail = (g_udp_tail + 1) % UDP_CAP_RING;
        g_udp_count--;
    }
    slot->seq = ++g_udp_seq;
    slot->ts_ns = ktime_get_ns();
    *scratch = g_udp_ring[g_udp_head];
    g_udp_ring[g_udp_head] = slot;
    g_udp_head = (g_udp_head + 1) % UDP_CAP_RING;
    g_udp_count++;
    g_udp_captured++;
    spin_unlock_irqrestore(&g_udp_lock, flags);
    return 0;
}
NOKPROBE_SYMBOL(nbg_udp_fill_packet);
NOKPROBE_SYMBOL(nbg_udp_rcv_pre);

static int nbg_udp_register_locked(void)
{
    int ret;

    if (g_udp_hooked)
        return 0;

    memset(&g_udp_kp, 0, sizeof(g_udp_kp));
    g_udp_kp.symbol_name = "udp_queue_rcv_one_skb";
    g_udp_kp.pre_handler = nbg_udp_rcv_pre;
    ret = register_kprobe(&g_udp_kp);
    if (ret) {
        pr_warn("nbg: udp probe on udp_queue_rcv_one_skb failed: %d\n", ret);
        return ret;
    }
    g_udp_hooked = true;
    return 0;
}

static void nbg_udp_unregister_locked(void)
{
    if (!g_udp_hooked)
        return;
    unregister_kprobe(&g_udp_kp);
    g_udp_hooked = false;
}

static int nbg_udp_ensure_ring(void)
{
    struct nbg_udp_packet *pool;
    struct nbg_udp_packet *stage;
    u32 i;
    int cpu;

    if (g_udp_pool)
        return 0;

    pool = vzalloc(sizeof(*pool) *
                   (UDP_CAP_RING + NBG_UDP_CAP_READ_MAX + num_possible_cpus()));
    if (!pool)
        return -ENOMEM;

    stage = vzalloc(sizeof(*stage) * NBG_UDP_CAP_READ_MAX);
    if (!stage) {
        vfree(pool);
        return -ENOMEM;
    }

    /* 调用方持有 init/read 两把锁，且探针尚未注册。 */
    for (i = 0; i < UDP_CAP_RING; i++)
        g_udp_ring[i] = &pool[i];
    for (i = 0; i < NBG_UDP_CAP_READ_MAX; i++)
        g_udp_read_slots[i] = &pool[UDP_CAP_RING + i];
    i = UDP_CAP_RING + NBG_UDP_CAP_READ_MAX;
    for_each_possible_cpu(cpu)
        per_cpu(g_udp_scratch, cpu) = &pool[i++];

    g_udp_stage = stage;
    g_udp_pool = pool;
    return 0;
}

static void nbg_udp_reset_locked(void)
{
    g_udp_head = 0;
    g_udp_tail = 0;
    g_udp_count = 0;
    g_udp_seq = 0;
    g_udp_overflow = 0;
    g_udp_captured = 0;
}

long nbg_udp_capture_init(void __user *arg)
{
    NBG_UDP_CAP_INIT_REQ req;
    unsigned long flags;
    uid_t uid;
    int ret;

    if (!arg)
        return -EINVAL;
    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (req.pid <= 0)
        return -EINVAL;
    if (req.max_payload && req.max_payload > NBG_UDP_CAP_MAX_PAYLOAD)
        return -EINVAL;

    uid = nbg_udp_uid_from_pid(req.pid);
    if (!uid)
        return -ESRCH;

    mutex_lock(&g_udp_init_lock);

    /* 先停用并注销探针，再复用它们的暂存槽。
     * 等锁期间不持有自旋锁。 */
    spin_lock_irqsave(&g_udp_lock, flags);
    WRITE_ONCE(g_udp_enabled, false);
    spin_unlock_irqrestore(&g_udp_lock, flags);
    nbg_udp_unregister_locked();

    mutex_lock(&g_udp_read_lock);
    ret = nbg_udp_ensure_ring();
    mutex_unlock(&g_udp_read_lock);
    if (ret) {
        mutex_unlock(&g_udp_init_lock);
        return ret;
    }

    ret = nbg_udp_register_locked();
    if (ret) {
        mutex_unlock(&g_udp_init_lock);
        return ret;
    }

    spin_lock_irqsave(&g_udp_lock, flags);
    WRITE_ONCE(g_udp_uid, uid);
    g_udp_min_len = req.min_payload ? req.min_payload : 16;
    g_udp_max_len = req.max_payload ? req.max_payload : NBG_UDP_CAP_MAX_PAYLOAD;
    if (g_udp_max_len > NBG_UDP_CAP_MAX_PAYLOAD)
        g_udp_max_len = NBG_UDP_CAP_MAX_PAYLOAD;
    nbg_udp_reset_locked();
    smp_store_release(&g_udp_enabled, true);
    spin_unlock_irqrestore(&g_udp_lock, flags);

    mutex_unlock(&g_udp_init_lock);
    return 0;
}

long nbg_udp_capture_read(void __user *arg)
{
    NBG_UDP_CAP_READ_REQ req;
    struct nbg_udp_packet *out;
    unsigned long flags;
    u32 want;
    u32 n;
    u32 i;

    if (!arg)
        return -EINVAL;
    if (copy_from_user(&req, arg, sizeof(req)))
        return -EFAULT;
    if (!req.buf)
        return -EINVAL;

    want = req.max_count;
    if (!want || want > NBG_UDP_CAP_READ_MAX)
        return -EINVAL;

    out = (struct nbg_udp_packet *)(uintptr_t)req.buf;

    mutex_lock(&g_udp_read_lock);
    n = 0;
    spin_lock_irqsave(&g_udp_lock, flags);
    while (n < want && g_udp_count) {
        struct nbg_udp_packet *packet = g_udp_ring[g_udp_tail];

        g_udp_ring[g_udp_tail] = g_udp_read_slots[n];
        g_udp_read_slots[n] = packet;
        g_udp_tail = (g_udp_tail + 1) % UDP_CAP_RING;
        g_udp_count--;
        n++;
    }
    req.out_count = n;
    req.overflow = g_udp_overflow;
    req.captured = g_udp_captured;
    req.reserved = 0;
    spin_unlock_irqrestore(&g_udp_lock, flags);

    /* 摘下的槽归读取方私有，即使环形缓冲回绕或被重置也不受影响。
     * 导出前清掉上一个报文留下的尾部字节。 */
    for (i = 0; i < n; i++) {
        size_t used = offsetof(struct nbg_udp_packet, payload) +
                      g_udp_read_slots[i]->payload_len;

        memcpy(&g_udp_stage[i], g_udp_read_slots[i], used);
        memset((char *)&g_udp_stage[i] + used, 0,
               sizeof(g_udp_stage[i]) - used);
    }

    if (n && copy_to_user(out, g_udp_stage, n * sizeof(*out))) {
        mutex_unlock(&g_udp_read_lock);
        return -EFAULT;
    }
    mutex_unlock(&g_udp_read_lock);

    if (copy_to_user(arg, &req, sizeof(req)))
        return -EFAULT;
    return 0;
}

long nbg_udp_capture_stop(void)
{
    unsigned long flags;

    mutex_lock(&g_udp_init_lock);
    spin_lock_irqsave(&g_udp_lock, flags);
    WRITE_ONCE(g_udp_enabled, false);
    nbg_udp_reset_locked();
    spin_unlock_irqrestore(&g_udp_lock, flags);
    nbg_udp_unregister_locked();
    mutex_unlock(&g_udp_init_lock);
    return 0;
}

void nbg_udp_capture_exit(void)
{
    nbg_udp_capture_stop();

    mutex_lock(&g_udp_read_lock);
    vfree(g_udp_pool);
    vfree(g_udp_stage);
    g_udp_pool = NULL;
    g_udp_stage = NULL;
    mutex_unlock(&g_udp_read_lock);
}
