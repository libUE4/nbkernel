# UDP 下行抓取

移植自 `enkernel/udp_capture.c`。默认关闭，由已鉴权的 NBG socket 调用启动。
指定 PID 用于确定 socket UID；抓取范围是这个 UID 的 IPv4 UDP 接收包，
包括同 UID 的其他进程，不是严格的单 PID 网络过滤。
不修改、不发送、不解密报文，也不抓 TCP、IPv6 或上行包。

## 接口

公共头文件：`include/NbgUdpCaptureAbi.h`；通过原有 `OP_INIT_KEY` 鉴权。

| 操作 | 命令 | 参数 |
| --- | --- | --- |
| 初始化/重置 | `OP_UDP_CAPTURE_INIT` / `0x95E` | `nbg_udp_cap_init_req` |
| 批量取包 | `OP_UDP_CAPTURE_READ` / `0x95F` | `nbg_udp_cap_read_req` |
| 停止并清空 | `OP_UDP_CAPTURE_STOP` / `0x960` | `0` |

```cpp
nbg_udp_cap_init_req start{};
start.pid = pid;
// min_payload=0 => 16 bytes; max_payload=0 => 2048 bytes
ioctl(fd, OP_UDP_CAPTURE_INIT, &start);

nbg_udp_cap_packet packets[NBG_UDP_CAP_READ_MAX];
nbg_udp_cap_read_req read{};
read.buf = reinterpret_cast<uintptr_t>(packets);
read.max_count = NBG_UDP_CAP_READ_MAX;
ioctl(fd, OP_UDP_CAPTURE_READ, &read);
// consume packets[0..read.out_count), check all ioctl return values

ioctl(fd, OP_UDP_CAPTURE_STOP, 0);
```

256 条环形队列，满时覆盖最旧条目并增加 `overflow`；每次最多读取32条。
单条2088字节，其中包体最多2048字节，超长截断并设置 `NBG_UDP_CAP_F_TRUNC`。
`max_payload` 是截断长度，不是排除大包的条件。
`seq` 是会话序号；`ts_ns` 为单调时钟纳秒；IP 地址为网络字节序，端口和长度为主机字节序。
未使用的包体尾部清零。初始化、停止重置队列和计数。

一个 socket 拥有抓包会话；另一个 socket 初始化返回 `EBUSY`，读取/停止返回 `EACCES`。
拥有者 fd 关闭（含进程崩溃、退出）自动停止并注销 probe。
若 fd 仍被 fork/dup 后的其他持有者引用，最后引用关闭时才清理。
会话不会因目标 PID 退出自动停止，仍按初始化时取得的 UID 过滤，调用方应主动停止。

读取会从队列移除记录；用户缓冲区发生 `EFAULT` 时已移除记录不会重新入队。
`reserved*` 输入必须清零。错误 PID 返回 `ESRCH`，非法长度返回 `EINVAL`。
旧模块不支持命令时返回 `ENOTTY`；目标内核缺少可探测的
`udp_queue_rcv_one_skb` 时初始化失败，不会影响驱动其他功能加载。

## 构建与读取

驱动仍使用工程现有 DDK/内核模块构建流程。新增 `src/comm/udp_capture.o`
已加入 Makefile；无需在模块装载时启用抓包。

Android 工具单独构建，避免编译其他测试：

```sh
ndk-build -C test/udp_capture_android
```

将 `test/udp_capture_android/libs/arm64-v8a/nbg_udp_capture` 推到设备，root 运行：

```sh
./nbg_udp_capture PID 10 capture.bin
```

文件为连续的固定2088字节记录，无额外文件头。工具结束主动 STOP，打印读取量、
捕获总量和溢出数。示例默认16字节最小包体过滤来自 en 实现，可通过接口改变。
这里不包含 UDP 解密密钥或游戏协议解析。
