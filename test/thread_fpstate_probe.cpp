#include "comm.h"
#include "NbgReadOnlyAbi.h"

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace
{
constexpr uint32_t kExpectedFpsr = 0x12;
static_assert(sizeof(NbgRoThreadFpState) == 56);
static_assert(offsetof(NbgRoThreadFpState, fpsr) == 48);

int ConnectDriver()
{
    unsigned opened = 0;
    std::printf("AUTH context uid=%u euid=%u\n",
        static_cast<unsigned>(getuid()), static_cast<unsigned>(geteuid()));
    for (int family = 1; family < 50; ++family)
    {
        const int descriptor = socket(family, SOCK_RAW, NBG_SOCKET_PROTOCOL);
        if (descriptor < 0)
        {
            continue;
        }
        INIT_KEY key{};
        key.abi_version = NBG_ABI_VERSION;
        key.token = NBG_AUTH_TOKEN;
        ++opened;
        errno = 0;
        const int result = ioctl(descriptor, OP_INIT_KEY, &key);
        const int error = errno;
        std::printf("AUTH probe family=%d result=%d errno=%d "
                    "accepted=%u reported_family=%u\n",
                    family, result, error, key.accepted, key.family);
        if (result == 0 && key.accepted == 1)
        {
            std::printf("AUTH family=%d\n", family);
            return descriptor;
        }
        close(descriptor);
    }
    std::printf("AUTH unavailable opened=%u\n", opened);
    return -1;
}

int Sample(int descriptor, int processId, int threadId)
{
    NbgRoThreadFpState sample{};
    sample.abi = NBG_RO_ABI;
    sample.pid = processId;
    sample.tid = threadId;
    int result = -EAGAIN;
    for (unsigned attempt = 0; attempt < 16; ++attempt)
    {
        if (ioctl(descriptor, NBG_RO_THREAD_FPSTATE, &sample) == 0)
        {
            result = 0;
            break;
        }
        result = -errno;
        if (errno != EAGAIN)
        {
            break;
        }
        usleep(1000);
    }
    std::printf("FPSTATE pid=%d tid=%d result=%d valid=%u "
                "fpsr=0x%X fpcr=0x%X tls=0x%llX sample_ns=%llu\n",
                processId, threadId, result, sample.valid, sample.fpsr,
                sample.fpcr, static_cast<unsigned long long>(sample.tls),
                static_cast<unsigned long long>(sample.sample_ns));
    if (result != 0)
    {
        return result;
    }
    return sample.abi == NBG_RO_ABI && sample.pid == processId &&
        sample.tid == threadId && sample.valid == NBG_RO_FPSTATE_VALID &&
        sample.tls != 0 && sample.sample_ns != 0 &&
        sample.process_start_ns != 0 && sample.thread_start_ns != 0
        ? static_cast<int>(sample.fpsr) : -EPROTO;
}
}

int main(int argc, char **argv)
{
    if (argc != 1 && argc != 3)
    {
        std::fprintf(stderr, "usage: %s [PID TID]\n", argv[0]);
        return 2;
    }
    const int descriptor = ConnectDriver();
    if (descriptor < 0)
    {
        std::fprintf(stderr, "AUTH failed errno=%d\n", errno);
        return 1;
    }
    NbgRoCaps capabilities{};
    capabilities.abi = NBG_RO_ABI;
    if (ioctl(descriptor, NBG_RO_CAPS, &capabilities) == 0)
    {
        std::printf("CAPS features=0x%llX fpstate=%u\n",
            static_cast<unsigned long long>(capabilities.features),
            (capabilities.features & NBG_RO_FEATURE_FPSTATE) != 0 ? 1U : 0U);
    }
    if (argc == 3)
    {
        const int result = Sample(descriptor, std::atoi(argv[1]),
                                  std::atoi(argv[2]));
        close(descriptor);
        return result >= 0 ? 0 : 1;
    }
    int readyPipe[2]{};
    int exitPipe[2]{};
    if (pipe(readyPipe) != 0 || pipe(exitPipe) != 0)
    {
        close(descriptor);
        return 2;
    }
    const pid_t child = fork();
    if (child == 0)
    {
        close(readyPipe[0]);
        close(exitPipe[1]);
        const uint64_t flags = kExpectedFpsr;
        asm volatile("msr fpsr, %0" : : "r"(flags));
        char byte = 'R';
        const bool ready = write(readyPipe[1], &byte, 1) == 1;
        if (ready)
        {
            static_cast<void>(read(exitPipe[0], &byte, 1));
        }
        _exit(ready ? 0 : 2);
    }
    close(readyPipe[1]);
    close(exitPipe[0]);
    char byte = 0;
    const bool ready = child > 0 && read(readyPipe[0], &byte, 1) == 1;
    const int result = ready ? Sample(descriptor, child, child) : -ECHILD;
    close(readyPipe[0]);
    close(exitPipe[1]);
    int status = 0;
    if (child > 0)
    {
        static_cast<void>(waitpid(child, &status, 0));
    }
    close(descriptor);
    const bool passed = ready && result == kExpectedFpsr &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0;
    std::printf("SYNTHETIC expected=0x%X result=%d passed=%u\n",
                kExpectedFpsr, result, passed ? 1U : 0U);
    return passed ? 0 : 1;
}
