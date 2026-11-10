#ifndef _NBG_GYRO_MATH_H_
#define _NBG_GYRO_MATH_H_

#ifdef __KERNEL__
#include <linux/types.h>
typedef u32 nbg_gyro_u32;
typedef s64 nbg_gyro_s64;
typedef u64 nbg_gyro_u64;
#else
#include <stdint.h>
typedef uint32_t nbg_gyro_u32;
typedef int64_t nbg_gyro_s64;
typedef uint64_t nbg_gyro_u64;
#endif

#define NBG_GYRO_EVENT_SIZE 104U
#define NBG_GYRO_EVENT_TYPE_OFFSET 8U
#define NBG_GYRO_EVENT_DATA_OFFSET 24U

static inline int nbg_gyro_type_selected(int type, nbg_gyro_u32 type_mask)
{
    return (type == 4 && (type_mask & 0x01U)) ||
           (type == 16 && (type_mask & 0x02U));
}

/* Convert finite IEEE-754 binary32 to signed Q32.32 without kernel FP use. */
static inline int nbg_gyro_bits_to_q32(nbg_gyro_u32 bits,
                                       nbg_gyro_s64 *out)
{
    nbg_gyro_u32 exponent = (bits >> 23) & 0xffU;
    nbg_gyro_u64 significand, magnitude;
    int shift;
    int negative;

    if (!out || exponent == 0xffU)
        return -1;
    negative = (bits >> 31) != 0;
    if (exponent == 0) {
        *out = 0;
        return 0;
    }

    significand = (bits & 0x7fffffU) | 0x800000U;
    shift = (int)exponent - 118;
    if (shift >= 0) {
        if (shift > 39)
            return -1;
        magnitude = significand << shift;
    } else {
        const unsigned int right = (unsigned int)-shift;
        nbg_gyro_u64 remainder, halfway;
        if (right >= 64) {
            magnitude = 0;
        } else {
            magnitude = significand >> right;
            remainder = significand & ((((nbg_gyro_u64)1) << right) - 1U);
            halfway = ((nbg_gyro_u64)1) << (right - 1U);
            if (remainder > halfway ||
                (remainder == halfway && (magnitude & 1U)))
                ++magnitude;
        }
    }

    if (negative) {
        if (magnitude > (((nbg_gyro_u64)1) << 63))
            return -1;
        *out = magnitude == (((nbg_gyro_u64)1) << 63)
            ? (-0x7fffffffffffffffLL - 1LL)
            : -(nbg_gyro_s64)magnitude;
    } else {
        if (magnitude > 0x7fffffffffffffffULL)
            return -1;
        *out = (nbg_gyro_s64)magnitude;
    }
    return 0;
}

static inline nbg_gyro_u32 nbg_gyro_q32_to_bits(nbg_gyro_s64 value)
{
    nbg_gyro_u64 magnitude, significand;
    nbg_gyro_u32 sign = 0, exponent;
    int position, shift;

    if (!value)
        return 0;
    if (value < 0) {
        sign = 0x80000000U;
        magnitude = (nbg_gyro_u64)(-(value + 1)) + 1U;
    } else {
        magnitude = (nbg_gyro_u64)value;
    }

    position = 63 - __builtin_clzll(magnitude);
    exponent = (nbg_gyro_u32)(position + 95);
    if (position > 23) {
        nbg_gyro_u64 remainder, halfway;
        shift = position - 23;
        significand = magnitude >> shift;
        remainder = magnitude & ((((nbg_gyro_u64)1) << shift) - 1U);
        halfway = ((nbg_gyro_u64)1) << (shift - 1);
        if (remainder > halfway ||
            (remainder == halfway && (significand & 1U))) {
            ++significand;
            if (significand == 0x1000000ULL) {
                significand >>= 1;
                ++exponent;
            }
        }
    } else {
        significand = magnitude << (23 - position);
    }
    return sign | (exponent << 23) | ((nbg_gyro_u32)significand & 0x7fffffU);
}

static inline int nbg_gyro_add_bits(nbg_gyro_u32 value_bits,
                                    nbg_gyro_s64 delta_q32,
                                    nbg_gyro_u32 *out_bits)
{
    nbg_gyro_s64 value_q32, sum;

    if (nbg_gyro_bits_to_q32(value_bits, &value_q32) != 0 || !out_bits)
        return -1;
    if ((delta_q32 > 0 && value_q32 > 0x7fffffffffffffffLL - delta_q32) ||
        (delta_q32 < 0 && value_q32 < (-0x7fffffffffffffffLL - 1) - delta_q32))
        return -1;
    sum = value_q32 + delta_q32;
    *out_bits = nbg_gyro_q32_to_bits(sum);
    return 0;
}

static inline int nbg_gyro_add_xy(nbg_gyro_u32 x_bits,
                                  nbg_gyro_u32 y_bits,
                                  nbg_gyro_s64 delta_x_q32,
                                  nbg_gyro_s64 delta_y_q32,
                                  nbg_gyro_u32 *out_x_bits,
                                  nbg_gyro_u32 *out_y_bits)
{
    nbg_gyro_u32 x, y;

    if (!out_x_bits || !out_y_bits ||
        nbg_gyro_add_bits(x_bits, delta_x_q32, &x) ||
        nbg_gyro_add_bits(y_bits, delta_y_q32, &y))
        return -1;
    *out_x_bits = x;
    *out_y_bits = y;
    return 0;
}

#endif
