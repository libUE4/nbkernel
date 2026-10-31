/* sf_groups.h — surfaceflinger 辅助组补齐 */
#ifndef _NBG_SF_GROUPS_H
#define _NBG_SF_GROUPS_H

#include <linux/types.h>

long nbg_sf_groups_acquire(void __user *arg);
bool nbg_sf_is_caller(void);

#endif /* _NBG_SF_GROUPS_H */
