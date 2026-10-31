/* udp_capture.h — UDP 报文旁路抓取 */
#ifndef _NBG_UDP_CAPTURE_H
#define _NBG_UDP_CAPTURE_H

#include <linux/types.h>

long nbg_udp_capture_init(void __user *arg);
long nbg_udp_capture_read(void __user *arg);
long nbg_udp_capture_stop(void);
void nbg_udp_capture_exit(void);

#endif /* _NBG_UDP_CAPTURE_H */
