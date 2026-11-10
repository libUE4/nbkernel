/* Receive-only capture ported from enkernel/udp_capture.c.
 * One explicitly enabled UID/session, owned by the authenticated NBG socket.
 * No packet changes, userspace copies or allocation in the probe callback.
 */
#include <linux/cpumask.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/udp.h>
#include <linux/uidgid.h>
#include <linux/vmalloc.h>
#include <net/sock.h>
#include <asm/ptrace.h>
#include "nbg_gki_compat.h"
#include "nbg_ksyms.h"
#include "nbg_log.h"
#include "udp_capture.h"
#include "udp_capture_ring.h"

static DEFINE_MUTEX(capture_lock);
static DEFINE_SPINLOCK(ring_lock);
static struct kprobe capture_probe;
static bool hooked, enabled;
static void *session_owner;
static kuid_t capture_uid;
static u16 min_len, max_len;
static struct nbg_udp_ring_cursor cursor;
static struct nbg_udp_cap_packet *pool, *stage;
static struct nbg_udp_cap_packet *ring[NBG_UDP_CAP_RING];
static struct nbg_udp_cap_packet *read_slots[NBG_UDP_CAP_READ_MAX];
static DEFINE_PER_CPU(struct nbg_udp_cap_packet *, scratch_packet);

static int capture_fill(struct sk_buff *skb, struct nbg_udp_cap_packet *out)
{
    struct iphdr ip;
    struct udphdr udp;
    int transport, offset, payload, copy;

    if (!skb || skb->protocol != htons(ETH_P_IP))
        return -EINVAL;
    if (skb_copy_bits(skb, skb_network_offset(skb), &ip, sizeof(ip)) ||
        ip.version != 4 || ip.ihl < 5 || ip.protocol != IPPROTO_UDP)
        return -EINVAL;
    transport = skb_transport_offset(skb);
    if (skb_copy_bits(skb, transport, &udp, sizeof(udp)))
        return -EINVAL;
    payload = ntohs(udp.len) - (int)sizeof(udp);
    offset = transport + sizeof(udp);
    if (payload < min_len || offset > (int)skb->len ||
        payload > (int)skb->len - offset)
        return -EINVAL;
    copy = min_t(int, payload, max_len);
    if (skb_copy_bits(skb, offset, out->payload, copy))
        return -EFAULT;
    out->src_ip = ip.saddr;
    out->dst_ip = ip.daddr;
    out->src_port = ntohs(udp.source);
    out->dst_port = ntohs(udp.dest);
    out->payload_len = copy;
    out->flags = copy < payload ? NBG_UDP_CAP_F_TRUNC : 0;
    out->sock_uid = from_kuid_munged(&init_user_ns, capture_uid);
    out->reserved = 0;
    return 0;
}

static int capture_pre(struct kprobe *probe, struct pt_regs *regs)
{
    struct sock *sk;
    struct sk_buff *skb;
    struct nbg_udp_cap_packet *packet, **scratch;
    unsigned long flags;
    u32 index;

    (void)probe;
    if (!smp_load_acquire(&enabled))
        return 0;
    sk = (struct sock *)regs->regs[0];
    skb = (struct sk_buff *)regs->regs[1];
    if (!sk || !uid_eq(sk->sk_uid, capture_uid))
        return 0;
    /* Non-migrating kprobe callback owns this CPU's preallocated slot. */
    scratch = this_cpu_ptr(&scratch_packet);
    packet = *scratch;
    if (!packet || capture_fill(skb, packet))
        return 0;
    spin_lock_irqsave(&ring_lock, flags);
    if (enabled) {
        index = nbg_udp_ring_push(&cursor);
        packet->seq = cursor.seq;
        packet->ts_ns = ktime_get_ns();
        *scratch = ring[index];
        ring[index] = packet;
    }
    spin_unlock_irqrestore(&ring_lock, flags);
    return 0;
}
NOKPROBE_SYMBOL(capture_fill);
NOKPROBE_SYMBOL(capture_pre);

/* capture_lock serializes ioctls and release, never taken by the probe. */
static void stop_locked(void)
{
    unsigned long flags;

    spin_lock_irqsave(&ring_lock, flags);
    WRITE_ONCE(enabled, false);
    spin_unlock_irqrestore(&ring_lock, flags);
    if (hooked) {
        nbg_unregister_kprobe(&capture_probe);
        hooked = false;
    }
    memset(&cursor, 0, sizeof(cursor));
    session_owner = NULL;
}

static int ensure_pool(void)
{
    u32 i;
    int cpu;

    if (pool)
        return 0;
    pool = vzalloc(sizeof(*pool) *
                   (NBG_UDP_CAP_RING + NBG_UDP_CAP_READ_MAX + num_possible_cpus()));
    if (!pool)
        return -ENOMEM;
    stage = vzalloc(sizeof(*stage) * NBG_UDP_CAP_READ_MAX);
    if (!stage) {
        vfree(pool);
        pool = NULL;
        return -ENOMEM;
    }
    for (i = 0; i < NBG_UDP_CAP_RING; ++i)
        ring[i] = &pool[i];
    for (i = 0; i < NBG_UDP_CAP_READ_MAX; ++i)
        read_slots[i] = &pool[NBG_UDP_CAP_RING + i];
    i = NBG_UDP_CAP_RING + NBG_UDP_CAP_READ_MAX;
    for_each_possible_cpu(cpu)
        per_cpu(scratch_packet, cpu) = &pool[i++];
    return 0;
}

static int start_locked(const struct nbg_udp_cap_init_req *req, void *owner)
{
    static const char * const names[] = { "udp_queue_rcv_one_skb", NULL };
    struct task_struct *task;
    kuid_t uid = INVALID_UID;
    u16 low = req->min_payload ? req->min_payload : 16;
    u16 high = req->max_payload ? req->max_payload : NBG_UDP_CAP_MAX_PAYLOAD;
    int ret;

    if (req->pid <= 0 || req->reserved0 || req->reserved1 ||
        high > NBG_UDP_CAP_MAX_PAYLOAD || low > high)
        return -EINVAL;
    if (session_owner && session_owner != owner)
        return -EBUSY;
    rcu_read_lock();
    task = pid_task(find_vpid(req->pid), PIDTYPE_PID);
    if (task)
        uid = task_uid(task);
    rcu_read_unlock();
    if (!uid_valid(uid))
        return -ESRCH;
    stop_locked(); /* drains callbacks before changing UID or scratch state */
    ret = ensure_pool();
    if (ret)
        return ret;
    capture_uid = uid;
    min_len = low;
    max_len = high;
    memset(&capture_probe, 0, sizeof(capture_probe));
    capture_probe.pre_handler = capture_pre;
    ret = nbg_register_kprobe_named(&capture_probe, names, NULL);
    if (ret) {
        NBG_WARN("udp capture receive probe unavailable: %d\n", ret);
        return ret;
    }
    hooked = true;
    session_owner = owner;
    smp_store_release(&enabled, true);
    return 0;
}

static long read_locked(unsigned long arg, void *owner)
{
    struct nbg_udp_cap_read_req req;
    struct nbg_udp_cap_packet __user *out;
    unsigned long flags;
    u32 count = 0, i;

    if (session_owner != owner)
        return session_owner ? -EACCES : -ENODATA;
    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;
    if (!req.buf || !req.max_count || req.max_count > NBG_UDP_CAP_READ_MAX ||
        req.reserved || req.reserved_tail)
        return -EINVAL;
    out = (void __user *)(unsigned long)req.buf;
    if (!access_ok(out, req.max_count * sizeof(*out)))
        return -EFAULT;
    spin_lock_irqsave(&ring_lock, flags);
    while (count < req.max_count && cursor.count) {
        u32 index = nbg_udp_ring_pop(&cursor);
        struct nbg_udp_cap_packet *packet = ring[index];

        ring[index] = read_slots[count];
        read_slots[count++] = packet;
    }
    req.out_count = count;
    req.overflow = cursor.overflow;
    req.captured = cursor.captured;
    spin_unlock_irqrestore(&ring_lock, flags);
    /* Zero the unused payload tail before exporting a fixed-size record. */
    for (i = 0; i < count; ++i) {
        size_t used = offsetof(struct nbg_udp_cap_packet, payload) + read_slots[i]->payload_len;

        memcpy(&stage[i], read_slots[i], used);
        memset((char *)&stage[i] + used, 0, sizeof(stage[i]) - used);
    }
    if (count && copy_to_user(out, stage, count * sizeof(*out)))
        return -EFAULT; /* already drained records are not requeued */
    if (copy_to_user((void __user *)arg, &req, sizeof(req)))
        return -EFAULT;
    return 0;
}

long nbg_udp_capture_ioctl(unsigned int cmd, unsigned long arg, void *owner)
{
    struct nbg_udp_cap_init_req req;
    long ret;

    if (!owner)
        return -EACCES;
    mutex_lock(&capture_lock);
    switch (cmd) {
    case NBG_UDP_IOC_INIT:
        ret = copy_from_user(&req, (void __user *)arg, sizeof(req))
            ? -EFAULT : start_locked(&req, owner);
        break;
    case NBG_UDP_IOC_READ:
        ret = read_locked(arg, owner);
        break;
    case NBG_UDP_IOC_STOP:
        ret = session_owner && session_owner != owner ? -EACCES : 0;
        if (!ret)
            stop_locked();
        break;
    default:
        ret = -ENOTTY;
    }
    mutex_unlock(&capture_lock);
    return ret;
}

void nbg_udp_capture_release(void *owner)
{
    mutex_lock(&capture_lock);
    if (session_owner == owner)
        stop_locked();
    mutex_unlock(&capture_lock);
}

void nbg_udp_capture_exit(void)
{
    mutex_lock(&capture_lock);
    stop_locked();
    vfree(pool);
    vfree(stage);
    pool = NULL;
    stage = NULL;
    mutex_unlock(&capture_lock);
}
