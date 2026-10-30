#ifndef _HWBP_CAPTURE_H_
#define _HWBP_CAPTURE_H_

#include "comm.h"

int hwbp_capture_init(void);
void hwbp_capture_exit(void);
int hwbp_capture_control(HwbpCaptureReq *request);

#endif /* _HWBP_CAPTURE_H_ */
