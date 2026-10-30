#ifndef NBG_READONLY_H
#define NBG_READONLY_H
#include "NbgReadOnlyAbi.h"
#include <linux/types.h>
long nbg_readonly_ioctl(unsigned int command, unsigned long argument);
long nbg_input_snapshot_ioctl(unsigned int command, unsigned long argument,
                              bool *subscribed);
void nbg_input_snapshot_release(bool *subscribed);
#endif
