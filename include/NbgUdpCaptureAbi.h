/* NBG socket UDP capture ABI. Receive-only IPv4, explicitly enabled by PID.
 * Packet/init/read layouts match enkernel's udp_cap_* structs (64-bit ABI).
 * IP fields: network byte order; ports/length/counts: host byte order.
 */
#ifndef NBG_UDP_CAPTURE_ABI_H
#define NBG_UDP_CAPTURE_ABI_H
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define NBG_UDP_IOC_INIT 0x95EU
#define NBG_UDP_IOC_READ 0x95FU
#define NBG_UDP_IOC_STOP 0x960U
#define NBG_UDP_CAP_MAX_PAYLOAD 2048U
#define NBG_UDP_CAP_READ_MAX 32U
#define NBG_UDP_CAP_RING 256U
#define NBG_UDP_CAP_F_TRUNC (1U << 0)

struct nbg_udp_cap_packet {
    uint64_t seq;
    uint64_t ts_ns;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t payload_len;
    uint16_t flags;
    uint32_t sock_uid;
    uint32_t reserved;
    uint8_t payload[NBG_UDP_CAP_MAX_PAYLOAD];
};

struct nbg_udp_cap_init_req {
    int32_t pid;
    uint32_t reserved0;
    uint16_t min_payload; /* zero => 16 */
    uint16_t max_payload; /* zero => 2048; larger packets are truncated */
    uint32_t reserved1;
};

struct nbg_udp_cap_read_req {
    uint64_t buf; /* caller array of nbg_udp_cap_packet */
    uint32_t max_count;
    uint32_t out_count;
    uint64_t overflow;
    uint64_t captured;
    uint32_t reserved;
    uint32_t reserved_tail; /* explicit padding, must be zero */
};
#endif
