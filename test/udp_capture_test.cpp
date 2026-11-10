#include "NbgUdpCaptureAbi.h"
#include "udp_capture_ring.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <random>

static_assert(sizeof(nbg_udp_cap_packet) == 2088);
static_assert(offsetof(nbg_udp_cap_packet, payload) == 40);
static_assert(sizeof(nbg_udp_cap_init_req) == 16);
static_assert(sizeof(nbg_udp_cap_read_req) == 40);
static_assert(offsetof(nbg_udp_cap_read_req, captured) == 24);
static_assert(NBG_UDP_IOC_STOP != NBG_UDP_IOC_READ);

int main() {
    nbg_udp_ring_cursor cursor{};
    uint64_t ring[NBG_UDP_CAP_RING]{};
    std::deque<uint64_t> expected;
    std::mt19937 random(971);
    uint64_t overflows = 0, written = 0;
    for (int op = 0; op < 100000; ++op) {
        if (op < 512 || random() % 3) {
            if (expected.size() == NBG_UDP_CAP_RING) {
                expected.pop_front(); ++overflows;
            }
            const auto index = nbg_udp_ring_push(&cursor);
            ring[index] = ++written;
            expected.push_back(written);
        } else {
            const auto requested = random() % NBG_UDP_CAP_READ_MAX + 1;
            for (uint32_t i = 0; i < requested && cursor.count; ++i) {
                const auto index = nbg_udp_ring_pop(&cursor);
                assert(!expected.empty() && ring[index] == expected.front());
                expected.pop_front();
            }
        }
        assert(cursor.count == expected.size());
        assert(cursor.captured == written && cursor.seq == written);
        assert(cursor.overflow == overflows);
        assert(cursor.head < NBG_UDP_CAP_RING && cursor.tail < NBG_UDP_CAP_RING);
    }
    cursor = {};
    assert(cursor.count == 0 && cursor.captured == 0 && cursor.overflow == 0);
    std::puts("PASS: en ABI sizes/offsets, 100000 FIFO/wrap/overflow/batch operations, reset");
}
