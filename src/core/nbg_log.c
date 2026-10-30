/* nbg_log.c — 运行期日志级别(仅在 NBG_DEBUG 编译时进入构建)
 *
 * NBG_DEBUG 未定义时,nbg_log.h 把所有日志宏替换为 do{}while(0),
 * 这个 .c 也不需要 — Makefile 用 CONFIG-style 把它从 obj 里剔除。
 * 但 wildcard 模式收所有 .c,所以这里加 #ifdef 保护让 NBG_DEBUG 关闭
 * 时整个 TU 是空的(留个 EXPORT 占位符给 modpost)。
 */
#ifdef NBG_DEBUG

#include <linux/atomic.h>
#include <linux/module.h>
#include "nbg_log.h"

atomic_t nbg_log_level = ATOMIC_INIT(NBG_LVL_INFO);

void nbg_log_set_level(int level)
{
    if (level < NBG_LVL_NONE) level = NBG_LVL_NONE;
    if (level > NBG_LVL_DBG)  level = NBG_LVL_DBG;
    atomic_set(&nbg_log_level, level);
}

int nbg_log_get_level(void)
{
    return atomic_read(&nbg_log_level);
}

#endif /* NBG_DEBUG */
