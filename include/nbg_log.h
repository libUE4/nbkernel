/* nbg_log.h — 日志宏 + 编译期/运行期开关
 *
 * 两层开关:
 *
 *   编译期 NBG_DEBUG
 *     未定义       所有 NBG_xxx 宏被替换成空语句,零代码、零字符串入 .ko
 *     定义(任何值) 编译进来,运行期 level 控制是否真打印
 *
 *   运行期 nbg_log_level(atomic_t,默认 NBG_LVL_INFO)
 *     0 NONE        全静音
 *     1 ERR         只打错误
 *     2 WARN        + 警告
 *     3 INFO        + 信息(默认)
 *     4 DBG         + 调试细节(NBG_DBG)
 *
 * 改运行期级别:nbg_log_set_level(N)。也可以用户态通过 OP_SET_LOG_LEVEL
 * 触发(若已接入)。
 *
 * 编译时打开:./build.sh --debug   或   make NBG_DEBUG=1
 */
#ifndef _NBG_LOG_H_
#define _NBG_LOG_H_

#include <linux/printk.h>

#define NBG_LVL_NONE  0
#define NBG_LVL_ERR   1
#define NBG_LVL_WARN  2
#define NBG_LVL_INFO  3
#define NBG_LVL_DBG   4

#ifdef NBG_DEBUG

#include <linux/atomic.h>
#include <linux/ratelimit.h>

/* 在 nbg_log.c 定义,默认 NBG_LVL_INFO */
extern atomic_t nbg_log_level;

void nbg_log_set_level(int level);
int  nbg_log_get_level(void);

#define NBG_LOG_AT(lvl, kfn, fmt, ...) do {                           \
    if (atomic_read(&nbg_log_level) >= (lvl))                         \
        kfn("NBG[%s]: " fmt, __func__, ##__VA_ARGS__);                \
} while (0)

#define NBG_ERR(fmt, ...)   NBG_LOG_AT(NBG_LVL_ERR,  pr_err,  fmt, ##__VA_ARGS__)
#define NBG_WARN(fmt, ...)  NBG_LOG_AT(NBG_LVL_WARN, pr_warn, fmt, ##__VA_ARGS__)
#define NBG_INFO(fmt, ...)  NBG_LOG_AT(NBG_LVL_INFO, pr_info, fmt, ##__VA_ARGS__)
#define NBG_DBG(fmt, ...)   NBG_LOG_AT(NBG_LVL_DBG,  pr_info, "[DEBUG] " fmt, ##__VA_ARGS__)

/* Numeric low-frequency failure marker.
 * Format: "D c=<code> r=<errno>". Keep output compact and avoid subsystem names.
 */
#define NBG_FAIL_CODE(code, err) do {                                \
    int __nbg_err = (int)(err);                                      \
    if (__nbg_err)                                                   \
        pr_err_ratelimited("D c=%u r=%d\n",                         \
                           (unsigned int)(code), __nbg_err);         \
} while (0)

#else  /* !NBG_DEBUG — 全部编译为空 */

#define NBG_ERR(fmt, ...)   do { } while (0)
#define NBG_WARN(fmt, ...)  do { } while (0)
#define NBG_INFO(fmt, ...)  do { } while (0)
#define NBG_DBG(fmt, ...)   do { } while (0)
#define NBG_FAIL_CODE(code, err) do { (void)(code); (void)(err); } while (0)

static inline void nbg_log_set_level(int level) { (void)level; }
static inline int  nbg_log_get_level(void)      { return NBG_LVL_NONE; }

#endif /* NBG_DEBUG */

#endif /* _NBG_LOG_H_ */
