#include "gyro_math.h"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

static uint32_t bits(float value)
{
    uint32_t out;
    std::memcpy(&out, &value, sizeof(out));
    return out;
}

static float value(uint32_t raw)
{
    float out;
    std::memcpy(&out, &raw, sizeof(out));
    return out;
}

int main()
{
    int64_t q = 0;
    uint32_t out = 0;
    uint32_t outX = 0, outY = 0;

    assert(NBG_GYRO_EVENT_SIZE == 104);
    assert(NBG_GYRO_EVENT_TYPE_OFFSET == 8);
    assert(NBG_GYRO_EVENT_DATA_OFFSET == 24);
    assert(nbg_gyro_type_selected(4, 1));
    assert(nbg_gyro_type_selected(16, 2));
    assert(nbg_gyro_type_selected(4, 3));
    assert(!nbg_gyro_type_selected(1, 3));
    assert(!nbg_gyro_type_selected(35, 3));
    assert(!nbg_gyro_type_selected(16, 1));

    // Standard event layout: timestamp low word 4 must not be mistaken for type.
    uint8_t event[NBG_GYRO_EVENT_SIZE]{};
    int32_t type = 1;
    uint32_t timestampLow = 4;
    std::memcpy(event + NBG_GYRO_EVENT_TYPE_OFFSET, &type, sizeof(type));
    std::memcpy(event + 16, &timestampLow, sizeof(timestampLow));
    int32_t observedType = 0;
    std::memcpy(&observedType, event + NBG_GYRO_EVENT_TYPE_OFFSET,
                sizeof(observedType));
    assert(observedType == 1 && !nbg_gyro_type_selected(observedType, 3));

    assert(nbg_gyro_bits_to_q32(bits(1.5f), &q) == 0);
    assert(q == (int64_t(3) << 31));
    assert(nbg_gyro_add_bits(bits(1.5f), int64_t(1) << 29, &out) == 0);
    assert(out == bits(1.625f));
    assert(nbg_gyro_add_bits(bits(-0.5f), int64_t(1) << 30, &out) == 0);
    assert(out == bits(-0.25f));

    assert(nbg_gyro_add_xy(bits(0.0f), bits(0.0f), int64_t(1) << 30,
                           -(int64_t(1) << 29), &outX, &outY) == 0);
    assert(outX == bits(0.25f) && outY == bits(-0.125f));
    assert(nbg_gyro_add_bits(bits(std::numeric_limits<float>::infinity()),
                             1, &out) != 0);

    const float approximate = value(nbg_gyro_q32_to_bits(
        (int64_t(1) << 32) / 10));
    assert(std::fabs(approximate - 0.1f) < 1.0e-7f);
    puts("PASS: Android sensor type/offset constants, gyro type mask, Q32.32 float deltas, signed X/Y and non-finite rejection");
    return 0;
}
