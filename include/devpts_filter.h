/* devpts_filter.h - PID-scoped devpts visibility filter */
#ifndef _DEVPTS_FILTER_H_
#define _DEVPTS_FILTER_H_

#include "comm.h"

/* Arm the app-scoped devpts view during module initialization.  It remains
 * active without a userspace client; OP_DEVPTS_FILTER only supplies a
 * session PID for status and cleanup coordination. */
int devpts_filter_install(void);
int devpts_filter_configure(DevptsFilterReq *req);
void devpts_filter_clear(void);
bool devpts_filter_current_is_active(void);
bool devpts_filter_path_hidden_for_current(const char *path);
void devpts_filter_note_permission_hit(void);
void devpts_filter_note_getattr_hit(void);

#endif /* _DEVPTS_FILTER_H_ */
