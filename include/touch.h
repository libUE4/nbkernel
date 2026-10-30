#ifndef _TOUCH_H_
#define _TOUCH_H_

#include <linux/types.h>

struct touch_diag {
    int32_t initialized;     /* 1=physical touchscreen slots are reserved */
    int32_t has_dev;          /* 1=physical touchscreen input_dev is bound */
    int32_t phys_width;       /* 物理屏幕 X 上限 */
    int32_t phys_height;      /* 物理屏幕 Y 上限 */
    int32_t user_width;       /* 用户态当前设置的 width (TOUCH_RES) */
    int32_t user_height;      /* 同上 */
    int32_t is_touching;      /* 当前虚拟 slot 是否按下 */
    int32_t has_touch_major;
    int32_t has_width_major;
    int32_t has_pressure;
    int32_t tracking_id;      /* 当前 tracking_id, -1=空闲 */
    int32_t reserved;
    char    dev_name[64];     /* input_dev->name */
};

int  touch_init(void);
void touch_exit(void);
int  touch_set_resolution(int w, int h);
int  touch_set_slots(int slots);
int  touch_slot_down(int slot, int x, int y);
int  touch_slot_move(int slot, int x, int y);
int  touch_slot_up(int slot);
void touch_up_all(void);
void touch_release_slots(unsigned long slot_mask);
int  touch_down(int x, int y);
int  touch_move(int x, int y);
int  touch_up(void);
void touch_query_state(struct touch_diag *out);

#endif
