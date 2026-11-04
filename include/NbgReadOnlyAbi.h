#ifndef NBG_READ_ONLY_ABI_H
#define NBG_READ_ONLY_ABI_H
#include <linux/types.h>
#define NBG_RO_ABI 1U
#define NBG_RO_CAPS 0x93CU
#define NBG_RO_MAPS 0x93DU
#define NBG_RO_THREAD 0x93EU
#define NBG_RO_FD 0x93FU
#define NBG_RO_FILE 0x940U
#define NBG_RO_INPUT_SUBSCRIBE 0x941U
#define NBG_RO_INPUT_LIST 0x942U
#define NBG_RO_INPUT_READ 0x943U
#define NBG_RO_THREAD_FPSTATE 0x944U
#define NBG_RO_GPU_INFO 0x93BU
#define NBG_RO_FEATURE_MAPS (1ULL << 0)
#define NBG_RO_FEATURE_THREAD (1ULL << 1)
#define NBG_RO_FEATURE_FD (1ULL << 2)
#define NBG_RO_FEATURE_FILE (1ULL << 3)
#define NBG_RO_FEATURE_INPUT (1ULL << 4)
#define NBG_RO_FEATURE_GPU (1ULL << 5)
#define NBG_RO_FEATURE_FPSTATE (1ULL << 6)
#define NBG_RO_REQUIRED_FEATURES 63ULL
#define NBG_RO_MAPS_MAX (4U * 1024U * 1024U)
#define NBG_RO_FILE_MAX 4096U
#define NBG_RO_INPUT_MAX_DEVICES 32U
#define NBG_RO_INPUT_MAX_EVENTS 64U
#define NBG_RO_INPUT_TOUCH 1U
#define NBG_RO_INPUT_KEYS 2U
#define NBG_RO_INPUT_DROPPED 1U
#define NBG_RO_THREAD_FIND 1U
#define NBG_RO_THREAD_IDENTITY 2U
#define NBG_RO_THREAD_SYSCALL 3U
#define NBG_RO_FPSTATE_VALID 1U
struct NbgRoCaps { __u32 abi, reserved; __u64 features; };
struct NbgRoMaps {
    __u32 abi; __s32 pid; __u64 buffer;
    __u32 capacity, length; __u64 process_start_ns;
};
struct NbgRoThread {
    __u32 abi, operation; __s32 pid, tid;
    __u64 process_start_ns, thread_start_ns;
    __s64 syscall_number; __u64 sp, pc;
    char comm[16];
};
struct NbgRoThreadFpState {
    __u32 abi;
    __s32 pid, tid;
    __u32 valid;
    __u64 tls, process_start_ns, thread_start_ns, sample_ns;
    __u32 fpsr, fpcr;
};
/* Explicit, architecture-independent Linux stat values, not a native struct stat. */
struct NbgRoFd {
    __u32 abi; __s32 pid, fd; __u32 reserved;
    __u64 process_start_ns, device, inode, rdev, size, blocks;
    __u32 mode, nlink, uid, gid, blksize, padding;
    __s64 atime_sec, mtime_sec, ctime_sec;
    __u32 atime_ns, mtime_ns, ctime_ns, padding2;
};
/* Read the file backing an existing VMA, preserving file-vs-memory semantics. */
struct NbgRoFile {
    __u32 abi; __s32 pid; __u64 address, buffer;
    __u32 size, copied; __u64 inode;
    __u32 device_major, device_minor;
};
struct NbgRoGpuObject {
    __u64 gpu_address, flags, size, virtual_length, virtual_address;
    __u32 id, reserved;
};
struct NbgRoGpuRequest {
    __u32 abi; __s32 pid, target_fd; __u32 object_id;
    __s64 result; __u64 sample_ns; struct NbgRoGpuObject info;
};
struct NbgRoInputSubscription { __u32 abi, enabled; };
struct NbgRoInputDevice {
    __u32 id, capabilities; __s32 x_min, x_max, y_min, y_max, slot_min, slot_max;
    __u64 cursor; __u8 key_bits[96];
};
struct NbgRoInputList {
    __u32 abi, count; struct NbgRoInputDevice devices[NBG_RO_INPUT_MAX_DEVICES];
};
struct NbgRoInputEvent { __u16 type, code; __s32 value; };
struct NbgRoInputRead {
    __u32 abi, device; __u64 cursor;
    __u32 count, flags;
    struct NbgRoInputEvent events[NBG_RO_INPUT_MAX_EVENTS];
};
#endif
