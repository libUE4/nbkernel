/* Per-build constants shared by kernel and userland. */
#ifndef _NBG_SECRET_H_
#define _NBG_SECRET_H_

/* First ioctl on a socket must present this token via OP_INIT_KEY. */
#define NBG_AUTH_TOKEN 0x8A27C440u

#endif
