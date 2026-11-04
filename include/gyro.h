/* gyro.h — 陀螺仪/加速度计数据覆盖 */
#ifndef _NBG_GYRO_H
#define _NBG_GYRO_H

#include <linux/errno.h>

int nbg_gyro_ioctl(unsigned long argument);
int nbg_gyro_init(void);
void nbg_gyro_exit(void);

#endif /* _NBG_GYRO_H */
