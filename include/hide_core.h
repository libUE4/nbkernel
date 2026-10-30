/* hide_core.h — hide 子系统生命周期与诊断接口 */
#ifndef _HIDE_CORE_H_
#define _HIDE_CORE_H_

#include <linux/types.h>

void auto_unhide_all(pid_t pid);
void hide_cleanup_runtime_state(void);

#endif /* _HIDE_CORE_H_ */
