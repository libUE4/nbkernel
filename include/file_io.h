/* file_io.h — 内核态受限文件读写 */
#ifndef _NBG_FILE_IO_H
#define _NBG_FILE_IO_H

#include <linux/types.h>

int nbg_file_io_init(void);
void nbg_file_io_exit(void);

long nbg_file_read(void __user *arg);
long nbg_file_write(void __user *arg);

#endif /* _NBG_FILE_IO_H */
