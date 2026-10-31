/* kgsl.h — KGSL 布局指纹校验与只读查询 */
#ifndef _NBG_KGSL_H
#define _NBG_KGSL_H

#include <linux/types.h>

long nbg_kgsl_syncsource_peek(void __user *arg);
long nbg_kgsl_query(void __user *arg);

#endif /* _NBG_KGSL_H */
