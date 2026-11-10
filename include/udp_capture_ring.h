#ifndef NBG_UDP_CAPTURE_RING_H
#define NBG_UDP_CAPTURE_RING_H
#include "NbgUdpCaptureAbi.h"

/* Caller serializes updates. Kept independent of allocation/copying so the
 * exact overflow and FIFO rules can be exercised by host tests. */
struct nbg_udp_ring_cursor {
    uint32_t head, tail, count;
    uint64_t seq, overflow, captured;
};

static inline uint32_t nbg_udp_ring_push(struct nbg_udp_ring_cursor *c)
{
    uint32_t index = c->head;
    if (c->count == NBG_UDP_CAP_RING) {
        ++c->overflow;
        c->tail = (c->tail + 1) % NBG_UDP_CAP_RING;
        --c->count;
    }
    c->head = (c->head + 1) % NBG_UDP_CAP_RING;
    ++c->count;
    ++c->seq;
    ++c->captured;
    return index;
}

static inline uint32_t nbg_udp_ring_pop(struct nbg_udp_ring_cursor *c)
{
    uint32_t index = c->tail;
    c->tail = (c->tail + 1) % NBG_UDP_CAP_RING;
    --c->count;
    return index;
}
#endif
