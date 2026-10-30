/* hide_kgsl.h - Qualcomm KGSL GPU sysfs/debugfs node hiding */
#ifndef _HIDE_KGSL_H_
#define _HIDE_KGSL_H_

#include <linux/types.h>

int hide_kgsl_install(void);
void hide_kgsl_remove_pid(pid_t pid);
void hide_kgsl_restore_pid(pid_t pid);
void hide_kgsl_cleanup(void);
bool hide_kgsl_available(void);

#endif /* _HIDE_KGSL_H_ */
