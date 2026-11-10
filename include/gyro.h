#ifndef _NBG_GYRO_H_
#define _NBG_GYRO_H_

#include "comm.h"

int nbg_gyro_init(void);
void nbg_gyro_exit(void);
int nbg_gyro_configure(NBG_GYRO_CONFIG *config);

#endif
