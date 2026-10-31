/* unhide_nbg.c — 解除 NBG 模块隐藏，便于卸载重刷
 *
 * 仅用于本机验证刷入流程。
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define NBG_ABI_VERSION 1U
#define NBG_AUTH_TOKEN 0x8A27C440U
#define NBG_SOCKET_PROTOCOL 0x4E47U
#define OP_INIT_KEY 0x900U
#define OP_UNHIDE_MODULE 0x919U

struct init_key
{
    uint32_t abi_version;
    uint32_t token;
    uint32_t accepted;
    uint32_t family;
    uint32_t authed_clients;
};

int main(void)
{
    for (int family = 1; family < 50; ++family)
    {
        int fd = socket(family, SOCK_RAW, NBG_SOCKET_PROTOCOL);
        struct init_key key;

        if (fd < 0)
            continue;

        memset(&key, 0, sizeof(key));
        key.abi_version = NBG_ABI_VERSION;
        key.token = NBG_AUTH_TOKEN;

        if (ioctl(fd, OP_INIT_KEY, &key) != 0 || key.accepted != 1)
        {
            close(fd);
            continue;
        }

        printf("authed family=%d\n", family);

        if (ioctl(fd, OP_UNHIDE_MODULE, NULL) == 0)
            printf("unhide ok\n");
        else
            printf("unhide failed errno=%d\n", errno);

        close(fd);
        return 0;
    }

    printf("no authenticated socket\n");
    return 1;
}
