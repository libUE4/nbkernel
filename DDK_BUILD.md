# NBG-driver 原生编译说明

本项目驱动编译不要使用 Docker，也不要使用 `build_with_ddk.sh` 或 `./build.sh --ddk`。

当前推荐使用本机已经安装好的原生内核构建目录：

```bash
/opt/ddk/kdir/android15-6.6
```

## 快速编译

```bash
cd /root/牛逼哥驱动/NBG-driver
./build.sh
```

当前机器已有 `android15-6.6` 原生环境，直接执行 `./build.sh` 会走原生模式，输出：

```bash
output_ddk/6.6.ko
```

如果想强制禁止 Docker 回退，使用：

```bash
./build.sh --native android15-6.6
```

## 同步到加载目录

编译成功后，把新 ko 同步到加载脚本使用的目录：

```bash
cp output_ddk/6.6.ko 牛逼哥驱动/6.6.ko
md5sum output_ddk/6.6.ko 牛逼哥驱动/6.6.ko
```

两个 md5 一致说明同步成功。

## 常用命令

```bash
# 默认 Android 15 / kernel 6.6
./build.sh

# 强制原生模式，避免误走 Docker
./build.sh --native android15-6.6

# 开启驱动日志编译
./build.sh --debug --native android15-6.6

# 清理临时产物
make clean
```

## 支持的目标名

`build.sh` 内置目标到输出文件名映射：

| 目标 | 输出 |
| --- | --- |
| `android12-5.10` | `output_ddk/5.10.ko` |
| `android13-5.10` | `output_ddk/5.10-a13.ko` |
| `android13-5.15` | `output_ddk/5.15.ko` |
| `android14-5.15` | `output_ddk/5.15-a14.ko` |
| `android14-6.1` | `output_ddk/6.1.ko` |
| `android15-6.6` | `output_ddk/6.6.ko` |
| `android16-6.12` | `output_ddk/6.12.ko` |

前提是对应原生目录存在：

```bash
/opt/ddk/kdir/<目标名>/Makefile
```

## 不要使用的方式

以下方式会依赖 Docker 或 DDK 镜像，不要用于当前项目：

```bash
./build_with_ddk.sh
./build.sh --ddk android15-6.6
ddk build android15-6.6
ddk pull android15-6.6
```

如果 `./build.sh --native android15-6.6` 报：

```bash
内核环境不存在: /opt/ddk/kdir/android15-6.6
```

说明本机原生内核构建环境缺失。先补齐 `/opt/ddk/kdir/android15-6.6`，不要改用 Docker。

## 当前验证记录

最近一次验证命令：

```bash
cd /root/牛逼哥驱动/NBG-driver
./build.sh
cp output_ddk/6.6.ko 牛逼哥驱动/6.6.ko
```

结果：

```bash
output_ddk/6.6.ko
牛逼哥驱动/6.6.ko
md5: 6e6820a8484e8a034eb5415cdfae1b0e
```
