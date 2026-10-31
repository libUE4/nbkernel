# NBG-driver socket ioctl 测试程序

## 文件说明

| 文件 | 说明 |
|------|------|
| `ioctl_test.cpp` | socket ioctl smoke/risk 测试源码 |
| `jni/Android.mk` | ndk-build 可执行文件工程 |
| `libs/arm64-v8a/LS_test` | ndk-build 生成的 ARM64 测试程序 |
| `pid_visibility_probe.cpp` | 合成子进程隐藏与多视图 PID 可见性测试 |

## 运行前提

1. 驱动已加载: `insmod /path/to/NBG.ko`
2. root 权限: 测试程序需要创建 RAW socket 并访问驱动能力
3. 驱动和测试程序使用同一份 `include/comm.h` 与 `secret.h`

## 快速开始

```bash
${NDK_BUILD:-ndk-build} \
  NDK_PROJECT_PATH=/root/牛逼哥驱动/NBG-driver/test -j$(nproc)

adb push libs/arm64-v8a/LS_test /data/local/tmp/LS_test
adb shell chmod +x /data/local/tmp/LS_test
adb shell su -c "insmod /data/local/tmp/NBG.ko"
adb shell su -c "/data/local/tmp/LS_test"
```

## 当前测试覆盖

| 测试项 | 内容 |
|--------|------|
| family 扫描 | 按旧版方式顺序尝试 `family=1..49`，通过 `OP_INIT_KEY` 确认驱动 |
| 鉴权 | `OP_INIT_KEY` 校验 ABI version 和 token |
| 未鉴权拒绝 | 未 auth 的业务 ioctl 必须返回 `EACCES` |
| 非法请求 | zero size、oversize、坏远端地址、READV count 越界 |
| 自进程读写 | `OP_READ_MEM` / `OP_WRITE_MEM` |
| READV | `OP_READV_MEM` 两段读取与单条 status 回写 |
| 进程查询 | `OP_FIND_PID`、`OP_MODULE_BASE` |
| 控制查询 | touch diag、watch clear/read、HWBP info、HWBP guard 查询 |
| 自检 | 模块自身隐藏与基础 ABI 自检；已删除的 maps/cpuset/kprobes/dmesg 旧项跳过 |

## PID 可见性闭环

`pid_visibility_probe` 只操作它自己创建的合成子进程，不触碰游戏进程。它会依次记录：

- `/proc` 根目录枚举和 `/proc/PID/{stat,status,cmdline}`；
- `/proc/PID/task` 线程目录；
- `kill(PID, 0)` 和 `pidfd_open`；
- `process_vm_readv` 对已知测试标记的读取。

`AFTER_HIDE` 阶段用于区分 procfs 过滤与内核级可见性，结束前始终发送
`OP_UNHIDE_PID`，避免测试留下隐藏 PID。

判定规则：

- `proc_readdir/stat/status/task_dir/cmdline=HIDDEN` 表示 procfs 过滤生效；
- `kill_0=FOUND` 或 `pidfd_open=FOUND` 表示 PID 仍可由内核任务接口确认；

## 协议入口

共享 ABI 在 `../include/comm.h`。用户态最小流程:

1. 顺序尝试 `family=1..49`, `socket(family, SOCK_RAW, 0)`
2. `ioctl(fd, OP_INIT_KEY, &key)`
3. `key.accepted == 1` 后保存 fd
4. `ioctl(fd, OP_*, &cmd)`
