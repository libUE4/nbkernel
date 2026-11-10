#ifndef NBG_UDP_CAPTURE_H
#define NBG_UDP_CAPTURE_H
#include <linux/types.h>
long nbg_udp_capture_ioctl(unsigned int cmd, unsigned long arg, void *owner);
void nbg_udp_capture_release(void *owner);
void nbg_udp_capture_exit(void);
#endif
