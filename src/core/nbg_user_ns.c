#include "nbg_user_ns.h"

#include "export_fun.h"

/* 只解析一次：init_user_ns 是编译期常量对象，地址在内核生命周期内不变。 */
struct user_namespace *nbg_init_user_ns_addr(void)
{
    static struct user_namespace *cached;

    if (!cached)
        cached = (struct user_namespace *)
            generic_kallsyms_lookup_name("init_user_ns");

    return cached;
}
