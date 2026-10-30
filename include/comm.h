/* comm.h - custom socket family ioctl ABI shared by driver and userland */
#ifndef _COMM_H_
#define _COMM_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#endif

#include "secret.h"

#define NBG_ABI_VERSION      1U
#define NBG_NAME_LEN         256U
#define NBG_PATH_LEN         256U
#define NBG_IOV_MAX          1024U
#define NBG_MAX_RW_SIZE      (512U * 1024U)
#define NBG_SOCKET_PROTOCOL  0x4E47
#ifndef WATCH_BATCH_MAX
#define WATCH_BATCH_MAX      32U
#endif

#ifndef NBG_AUTH_TOKEN
#define NBG_AUTH_TOKEN       0x4E424747u
#endif

enum OPERATIONS {
    OP_INIT_KEY       = 0x900,
    OP_READ_MEM       = 0x901,
    OP_WRITE_MEM      = 0x902,
    OP_MODULE_BASE    = 0x903,
    OP_TOUCH_DOWN     = 0x904,
    OP_TOUCH_MOVE     = 0x905,
    OP_TOUCH_UP       = 0x906,
    OP_SET_RESOLUTION = 0x907,
    OP_HIDE_PID       = 0x908,
    OP_HIDE_FILE      = 0x909,
    OP_UNHIDE_FILE    = 0x910,
    OP_SHADOW_ADD     = 0x911,
    OP_SHADOW_UPDATE  = 0x912,
    OP_SHADOW_DELETE  = 0x913,
    OP_WATCH_ADD      = 0x914,
    OP_WATCH_DELETE   = 0x915,
    OP_WATCH_CLEAR    = 0x916,
    OP_WATCH_READ     = 0x917,
    OP_UNHIDE_PID     = 0x918,
    OP_UNHIDE_MODULE  = 0x919,
    OP_FIND_PID       = 0x91A,
    OP_TOUCH_DIAG     = 0x91B,
    OP_HWBP_INFO      = 0x91C,
    OP_SET_LOG_LEVEL  = 0x91F,
    OP_READV_MEM      = 0x923,
    OP_HIDE_KGSL      = 0x924,
    OP_UNHIDE_KGSL    = 0x925,
    OP_TOUCH_SLOT_DOWN = 0x926,
    OP_TOUCH_SLOT_MOVE = 0x927,
    OP_TOUCH_SLOT_UP   = 0x928,
    OP_SET_TOUCH_SLOTS = 0x929,
    OP_SHADOW_DIAG     = 0x92A,
    OP_READ_MEM_FAULT = 0x92F,
    OP_DEVPTS_FILTER  = 0x930,
    OP_THREAD_ENV     = 0x932,
    OP_TARGET_THREAD_IOCTL_SESSION = 0x934,
    OP_HWBP_CAPS      = 0x935,
    OP_SIGNAL_HIDDEN_PID = 0x936,
    /* Flush the target AArch64 instruction-cache range after a guarded
     * remote text write. */
    OP_FLUSH_ICACHE   = 0x937,
    /* Snapshot the target KGSL syncsource IDR without allocating an ID or
     * issuing an ioctl in the target process. */
    OP_KGSL_SYNCSOURCE_SNAPSHOT = 0x938,
    /* Batch read through the demand-fault path. This preserves one read
     * session for protected mappings whose ordinary PTE view is stale. */
    OP_READV_MEM_FAULT = 0x939,
    /* Diagnostic-only, instruction-verified one-shot register capture. */
    OP_HWBP_CAPTURE = 0x93A,
    /* Read one existing KGSL object's metadata. No target task execution,
     * user-memory write, GPU allocation, free, or generic ioctl forwarding. */
    OP_KGSL_GPUOBJ_INFO = 0x93B,
};

typedef struct _INIT_KEY {
    uint32_t abi_version;
    uint32_t token;
    uint32_t accepted;
    uint32_t family;
    uint32_t authed_clients;
} INIT_KEY, *PINIT_KEY;

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void *buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _FLUSH_ICACHE_REQ {
    pid_t pid;
    uintptr_t addr;
    size_t size;
} FLUSH_ICACHE_REQ, *PFLUSH_ICACHE_REQ;

typedef struct _READV_ENTRY {
    uintptr_t addr;
    void *buffer;
    uint32_t size;
    int32_t status;
} READV_ENTRY, *PREADV_ENTRY;

typedef struct _READV_MEMORY {
    pid_t pid;
    READV_ENTRY *iovs;
    uint32_t count;
} READV_MEMORY, *PREADV_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char *name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

typedef struct _FIND_PID_REQ {
    char *name;
    pid_t pid;
} FIND_PID_REQ, *PFIND_PID_REQ;

typedef struct _TOUCH_POINT {
    int x;
    int y;
} TOUCH_POINT, *PTOUCH_POINT;

typedef struct _TOUCH_SLOT_POINT {
    int slot;
    int x;
    int y;
} TOUCH_SLOT_POINT, *PTOUCH_SLOT_POINT;

typedef struct _SCREEN_RES {
    int width;
    int height;
} SCREEN_RES, *PSCREEN_RES;

typedef struct _TOUCH_DIAG {
    int32_t initialized;
    int32_t has_dev;
    int32_t phys_width;
    int32_t phys_height;
    int32_t user_width;
    int32_t user_height;
    int32_t is_touching;
    int32_t has_touch_major;
    int32_t has_width_major;
    int32_t has_pressure;
    int32_t tracking_id;
    int32_t reserved;
    char dev_name[64];
} TOUCH_DIAG, *PTOUCH_DIAG;

typedef struct _HidePidReq {
    int32_t pid;
} HidePidReq, *PHidePidReq;

#define NBG_HIDDEN_SIGNAL_ABI_VERSION 1U
typedef struct _HiddenProcessSignalReq {
    uint32_t abi_version;
    int32_t signal;
    uint32_t matched;
    uint32_t delivered;
} HiddenProcessSignalReq, *PHiddenProcessSignalReq;

typedef struct _HideFileReq {
    char path[NBG_PATH_LEN];
} HideFileReq, *PHideFileReq;

/* Per-process devpts visibility filter.  The target sees matching pts nodes
 * as absent while the rest of the system keeps normal VFS behaviour. */
#define NBG_DEVPTS_FILTER_ABI_VERSION 1U
#define NBG_DEVPTS_FILTER_MAX_INDEX   31U
#define NBG_DEVPTS_FILTER_DISABLE     0U
#define NBG_DEVPTS_FILTER_ENABLE      1U
#define NBG_DEVPTS_FILTER_QUERY       2U

typedef struct _DevptsFilterReq {
    uint32_t abi_version;
    int32_t pid;
    uint32_t max_index;
    uint32_t enabled;
    uint64_t permission_hits;
    uint64_t getattr_hits;
} DevptsFilterReq, *PDevptsFilterReq;

typedef struct _ShadowHookReq {
    int32_t pid;
    uint64_t vaddr;
    uint64_t target_vaddr;
    uint32_t custom_rot[3];
    int32_t is_rot_hook;
} ShadowHookReq, *PShadowHookReq;

/* Type 28 is the legacy fixed-slot capture. Dynamic stack layouts use a
 * separate request type so an older client cannot reinterpret the payload. */
#define NBG_SHADOW_DYNAMIC_HOOK_TYPE 29U

/* RMCN broad-phase geometry hook. One execution breakpoint scales the
 * persistent capsule/box dimensions consumed by the later narrow phase. */
#define NBG_SHADOW_FP_LDP_SCALE_HOOK_TYPE 30U

/* DFM skinned-mesh render path. The callback emulates the skipped material
 * load, then substitutes the outline material for enemy-owned meshes. */
#define NBG_SHADOW_DFM_OUTLINE_RENDER_TYPE 31U

/* DFM skinned-mesh effect-pass flags. Second breakpoint on the byte load of
 * USkinnedMeshComponent::bDrawEffectPass (offset 0x728). The callback only
 * raises the bit in the destination register, never writes target memory. */
#define NBG_SHADOW_DFM_OUTLINE_FLAGS_TYPE 41U

/* RMCN ClientPlayerGo update epilogue. One execution breakpoint routes the
 * RMCN observer/free-view hook. */
#define NBG_SHADOW_RMCN_FREE_VIEW_TYPE 32U

/* RMCN official command-view bridge. The hook replaces the final
 * CorrectCmdViewPitchYaw pair store; the game's CorrectCmdShootPitchYaw
 * remains responsible for the dedicated ballistic fields. */
#define NBG_SHADOW_RMCN_ROTATION_INPUT_TYPE 35U
/* RMCN CameraThirdState.CorrectShootPitchYaw camera-angle pair input.
 * The skipped instruction is LDP S1,S0,[X20,#0x2C]; case36 replaces the
 * pair in FP state before the native camera-shoot-angle conversion. */
#define NBG_SHADOW_RMCN_CROSSHAIR_INPUT_TYPE 36U
/* RMCN official spread-context bridge. The skipped FMOV is always reproduced;
 * the hook only captures the live formula/parameter/weapon tuple. */
#define NBG_SHADOW_RMCN_SPREAD_CONTEXT_TYPE 38U
#define NBG_SHADOW_RMCN_NO_SPREAD_TYPE NBG_SHADOW_RMCN_SPREAD_CONTEXT_TYPE
/* RMCN final shoot-angle merge bridge. It adjusts transient S8/S9 after the
 * first/third-person branches; the official final fields remain produced and
 * stored by the game's own function. */
#define NBG_SHADOW_RMCN_TPP_SHOOT_INPUT_TYPE 40U
/* case40 current-build payload: c0/c1 are CalculateShootDir yaw/pitch;
 * the seed/index are read from W3/W7 at the FMOV S8,S0 boundary. */
#define NBG_RMCN_TPP_SHOOT_CALCULATE_DIR_FLAG (1U << 9)
/* Inverse spread belongs to the official command; case40 mirrors that input. */
#define NBG_RMCN_SYNC_INPUT_SPREAD_FLAG (1U << 10)

#define NBG_SHADOW_DIAG_ABI_VERSION 11U
#define NBG_SHADOW_DIAG_CAMERA_RETURN_V1 0x52333532U
/* ShadowDiag.reserved32 keeps the binary layout stable:
 *   [0] spread-context flags below
 *   [1] active case35 common-camera return hook; [8] return schema marker.
 * reserved64[0..7]: hits, applies, failures, native pair, output pair,
 * command pointer, sequence, hook address. Pair low32=yaw, high32=pitch. */
#define NBG_SHADOW_DIAG_SPREAD_CONTEXT_READY   (1U << 0)
#define NBG_SHADOW_DIAG_SPREAD_CAPTURE_ENABLED (1U << 1)
#define NBG_SHADOW_DIAG_SPREAD_CONTEXT_PRELOADED (1U << 2)
#define NBG_SHADOW_SPREAD_PROFILE_INLINE_STATE   (1U << 30)
#define NBG_SHADOW_SPREAD_PROFILE_LOAD          (1U << 31)

typedef struct _ShadowDiag {
    uint32_t abi_version;
    int32_t pid;
    uint32_t case38_active;
    uint32_t reserved32[9];
    uint64_t case38_hits;
    uint64_t case38_captures;
    uint64_t spread_comp_attempts;
    uint64_t spread_comp_successes;
    uint64_t spread_cache_misses;
    uint64_t spread_compute_rejects;
    uint64_t spread_last_sequence;
    uint64_t spread_last_seed;
    uint64_t spread_last_bits;
    uint64_t spread_shot_matches;
    uint64_t spread_shot_mismatches;
    uint64_t spread_shot_unpaired;
    uint64_t spread_last_projectile_index;
    uint64_t spread_last_target_yaw_bits;
    uint64_t spread_last_target_pitch_bits;
    uint64_t spread_last_comp_yaw_bits;
    uint64_t spread_last_comp_pitch_bits;
    uint64_t spread_last_live_angle0_bits;
    uint64_t spread_last_live_angle1_bits;
    uint64_t spread_last_sequence_delta;
    uint64_t case40_hits;
    uint64_t case40_comp_successes;
    /* reserved64[0..6] retain ABI space for retired diagnostics. */
    uint64_t reserved64[8];
} ShadowDiag, *PShadowDiag;

typedef struct _WatchReq {
    int32_t pid;
    uint64_t watch_addr;
    uint32_t bp_type;
    uint32_t bp_len;
    uint32_t log_limit;
    uint32_t pad;
} WatchReq, *PWatchReq;

typedef struct _WatchEvent {
    uint64_t watch_addr;
    uint64_t pc;
    int32_t tid;
    int32_t pid;
    uint32_t bp_type;
    uint32_t hit_count;
} WatchEvent, *PWatchEvent;

typedef struct _WatchReadReq {
    WatchEvent events[WATCH_BATCH_MAX];
    uint32_t count;
} WatchReadReq, *PWatchReadReq;

typedef struct _HwbpInfo {
    uint64_t breakpoints;
    uint64_t watchpoints;
} HwbpInfo, *PHwbpInfo;

#define NBG_HWBP_CAPS_ABI_VERSION 1U
#define NBG_HWBP_CAPS_FLAG_ABLE   (1U << 0)

/*
 * Read-only debug-feature capability query.  The DFR1 ABLE field is a
 * positive-only gate for hardware breakpoint work: a zero value does not make
 * any newer, unqueried feature available to the runtime.
 */
typedef struct _HwbpCaps {
    uint32_t abi_version;
    uint32_t flags;
    uint64_t dfr0;
    uint64_t dfr1;
    uint32_t physical_breakpoints;
    uint32_t physical_watchpoints;
    uint32_t usable_breakpoints;
    uint32_t usable_watchpoints;
} HwbpCaps, *PHwbpCaps;

/* This is intentionally not a general hook. ARM accepts only an instruction
 * verified as BR X8, which the callback reproduces exactly after sampling the
 * pre-branch register state for the offline segment emulator. */
#define NBG_HWBP_CAPTURE_ABI_VERSION_1 1U
#define NBG_HWBP_CAPTURE_ABI_VERSION 2U
#define NBG_HWBP_CAPTURE_V1_SIZE     344U
#define NBG_HWBP_CAPTURE_V2_SIZE     600U
#define NBG_HWBP_CAPTURE_POINTEE_COUNT 4U
#define NBG_HWBP_CAPTURE_POINTEE_SIZE 32U
#define NBG_HWBP_CAPTURE_STACK_SIZE  64U
#define NBG_HWBP_CAPTURE_STACK_VALID (1U << 4)
#define NBG_HWBP_CAPTURE_ARM         1U
#define NBG_HWBP_CAPTURE_READ        2U
#define NBG_HWBP_CAPTURE_CANCEL      3U
#define NBG_HWBP_CAPTURE_IDLE        0U
#define NBG_HWBP_CAPTURE_ARMED       1U
#define NBG_HWBP_CAPTURE_CAPTURING   2U
#define NBG_HWBP_CAPTURE_HIT         3U
#define NBG_HWBP_CAPTURE_TIMED_OUT   4U
#define NBG_HWBP_CAPTURE_CANCELED    5U
#define NBG_HWBP_CAPTURE_BR_X8       0xD61F0100U
#define NBG_HWBP_CAPTURE_FLAG_BRANCH_EMULATED (1U << 0)

typedef struct _HwbpCaptureReq {
    uint32_t abi_version;
    uint32_t action;
    int32_t pid;
    int32_t tid;
    uint64_t target_vaddr;
    uint32_t expected_instruction;
    uint32_t timeout_ms;
    uint32_t state;
    int32_t result;
    uint32_t hit_count;
    int32_t hit_tid;
    uint32_t flags;
    uint64_t hit_pc;
    uint64_t hit_branch_target;
    uint64_t hit_time_ns;
    uint64_t registers[31];
    uint64_t sp;
    uint64_t pstate;
    /* v2: an exact, optional raw-register match. Zero initialization disables
     * matching. Valid bits 0..3 cover X0, X1, X19, X20 respectively; bit 4
     * covers SP. A valid bit means the full field was copied before EL0 resumed;
     * it does not promise atomicity against other threads' writes. */
    uint32_t match_enabled;
    uint32_t match_register;
    uint64_t match_value;
    uint32_t pointee_valid_mask;
    uint32_t reserved_v2;
    uint64_t pointee_address[NBG_HWBP_CAPTURE_POINTEE_COUNT];
    uint8_t pointee_data[NBG_HWBP_CAPTURE_POINTEE_COUNT][NBG_HWBP_CAPTURE_POINTEE_SIZE];
    uint64_t stack_address;
    uint8_t stack_data[NBG_HWBP_CAPTURE_STACK_SIZE];
} HwbpCaptureReq, *PHwbpCaptureReq;

typedef struct _IntValue {
    int32_t value;
} IntValue, *PIntValue;

/* Hold one target thread in a task_work callback across a two-phase ioctl
 * transaction. Userspace supplies the raw EL0 register/stack image and an
 * optional table describing pointers stored inside that image. The driver
 * relocates both register and stack references into a temporary target frame. */
#define NBG_TARGET_THREAD_SESSION_ABI_VERSION 2U
#define NBG_TARGET_THREAD_SESSION_BEGIN       1U
#define NBG_TARGET_THREAD_SESSION_FINISH      2U
#define NBG_TARGET_THREAD_SESSION_ABORT       3U
#define NBG_TARGET_THREAD_SESSION_MAX_ARGUMENT_SIZE 4096U
#define NBG_TARGET_THREAD_SESSION_MAX_TIMEOUT_MS    5000U
#define NBG_TARGET_THREAD_SESSION_MAX_STACK   32768U
#define NBG_TARGET_THREAD_SESSION_MAX_HOLD_MS 2000U
#define NBG_TARGET_THREAD_REGISTER_COUNT      31U
#define NBG_TARGET_THREAD_SESSION_MAX_RELOCATIONS 256U

typedef struct _TargetThreadStackRelocation {
    uint32_t source_offset;
    uint32_t target_offset;
} TargetThreadStackRelocation, *PTargetThreadStackRelocation;

typedef struct _TargetThreadIoctlSessionReq {
    uint32_t abi_version;
    uint32_t phase;
    int32_t pid;
    int32_t tid;
    uint32_t target_fd;
    uint32_t command;
    uint32_t flags;
    uint32_t argument_size;
    uint32_t timeout_ms;
    uint32_t hold_timeout_ms;
    uint32_t stack_size;
    uint32_t stack_pointer_offset;
    uint32_t argument_offset;
    uint32_t syscall_number;
    uint64_t stack_image;
    uint64_t argument;
    uint64_t session_id;
    int64_t result;
    int32_t status;
    uint32_t reserved;
    uint64_t user_pc;
    uint64_t relative_mask;
    uint64_t registers[NBG_TARGET_THREAD_REGISTER_COUNT];
    uint64_t scratch;
    uint64_t context_sp;
    uint64_t stack_relocations;
    uint32_t stack_relocation_count;
    uint32_t relocation_reserved;
} TargetThreadIoctlSessionReq, *PTargetThreadIoctlSessionReq;

/* Read-only thread execution context.  The caller supplies a process leader
 * PID and one member TID; the driver verifies that they belong together.
 * This ABI deliberately contains no target-specific address or layout. */
#define NBG_THREAD_ENV_ABI_VERSION 1U
#define NBG_THREAD_ENV_TLS_VALID   (1U << 0)
#define NBG_THREAD_ENV_APGA_VALID  (1U << 1)

typedef struct _ThreadEnvReq {
    uint32_t abi_version;
    int32_t pid;
    int32_t tid;
    uint32_t valid;
    uint64_t tls;
    uint64_t apga_lo;
    uint64_t apga_hi;
} ThreadEnvReq, *PThreadEnvReq;

/* Read-only KGSL syncsource occupancy snapshot. Bit zero represents ID 1. */
#define NBG_KGSL_SYNCSOURCE_ABI_VERSION 1U
#define NBG_KGSL_SYNCSOURCE_MAX_ID      256U
#define NBG_KGSL_SYNCSOURCE_WORDS       4U
#define NBG_KGSL_SYNCSOURCE_LAYOUT_VERIFIED (1U << 0)

typedef struct _KgslSyncsourceSnapshotReq {
    uint32_t abi_version;
    int32_t pid;
    uint32_t max_id;
    uint32_t flags;
    uint32_t occupied_count;
    uint32_t first_free;
    uint32_t idr_offset;
    uint32_t lock_offset;
    uint64_t sample_ns;
    uint64_t occupied[NBG_KGSL_SYNCSOURCE_WORDS];
} KgslSyncsourceSnapshotReq, *PKgslSyncsourceSnapshotReq;

#define NBG_KGSL_GPUOBJ_INFO_ABI_VERSION 1U
typedef struct _KgslGpuObjectInfo {
    uint64_t gpu_address;
    uint64_t flags;
    uint64_t size;
    uint64_t virtual_length;
    uint64_t virtual_address;
    uint32_t id;
    uint32_t reserved;
} KgslGpuObjectInfo;

typedef struct _KgslGpuObjectInfoReq {
    uint32_t abi_version;
    int32_t pid;
    int32_t target_fd;
    uint32_t object_id;
    int64_t result;
    uint64_t sample_ns;
    KgslGpuObjectInfo info;
} KgslGpuObjectInfoReq;

#ifdef __KERNEL__
int nbg_comm_init(void);
void nbg_comm_exit(void);
int nbg_comm_registered_family(void);
int nbg_comm_authed_clients(void);
#endif

#endif /* _COMM_H_ */
