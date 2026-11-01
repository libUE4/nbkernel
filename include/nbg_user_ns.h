/* init_user_ns 在部分 GKI 内核不导出，直接取地址会让模块加载时报
 * Unknown symbol。这里用 kallsyms 解析一次地址，供各处 uid 映射与
 * 命名空间比较使用；解析不到时返回 NULL，调用方降级处理。
 */
#ifndef NBG_USER_NS_H
#define NBG_USER_NS_H

#include <linux/sched.h>

struct user_namespace *nbg_init_user_ns_addr(void);

#endif /* NBG_USER_NS_H */
