# ===========================================================================
#  NBG.ko — Android (arm64) 内核态外挂驱动
# ===========================================================================

MODULE_NAME := NBG
obj-m       := $(MODULE_NAME).o

# 显式对象列表:避免临时/实验 .c 被 wildcard 意外编进 .ko。
$(MODULE_NAME)-objs := \
	src/core/entry.o \
	src/core/gki_compat.o \
	src/core/memory.o \
	src/core/nbg_log.o \
	src/core/process.o \
	src/core/query.o \
	src/core/udp_capture.o \
	src/core/sf_groups.o \
	src/core/file_io.o \
	src/core/sensor_mem.o \
	src/core/readonly.o \
	src/core/target.o \
	src/comm/socket_ioctl.o \
	src/hide/hide_core.o \
	src/hide/devpts_filter.o \
	src/hide/hide_file.o \
	src/hide/hide_kgsl.o \
	src/hide/hide_module.o \
	src/hide/hide_proc.o \
	src/hwbp/hwbp_core.o \
	src/hwbp/hwbp_capture.o \
	src/hwbp/hwbp_regset_filter.o \
	src/hwbp/hwbp_logger.o \
	src/hwbp/hwbp_shadow.o \
	src/hwbp/hwbp_watch.o \
	src/input/touch.o \
	src/input/snapshot.o

# ---------- 编译参数 ----------
ccflags-y += -I$(src)/include
ccflags-y += -I$(src)
ccflags-y += -O2
ccflags-y += -fno-strict-aliasing
ccflags-y += -fno-jump-tables
ccflags-y += -fno-asynchronous-unwind-tables
ccflags-y += -fno-delete-null-pointer-checks

# 日志开关:make NBG_DEBUG=1 / make NBG_DEBUG=0(默认关)
# 关闭时所有 NBG_xxx 宏编译为空,运行时零开销、不留字符串。
NBG_DEBUG ?= 0
ifneq ($(NBG_DEBUG),0)
ccflags-y += -DNBG_DEBUG
endif

EXTRA_CFLAGS += -O2
EXTRA_CFLAGS += -fvisibility=hidden
EXTRA_CFLAGS += -fomit-frame-pointer
EXTRA_CFLAGS += -fno-pic
EXTRA_CFLAGS += -fno-stack-protector
EXTRA_CFLAGS += -Wno-unused-function -Wno-unused-variable
EXTRA_CFLAGS += $(call cc-option,-Wno-unused-but-set-variable)
EXTRA_CFLAGS += $(call cc-option,-Wno-error=unused-but-set-variable)
CFLAGS_MODULE += $(call cc-option,-Wno-unused-but-set-variable)
CFLAGS_MODULE += $(call cc-option,-Wno-error=unused-but-set-variable)

# ARM64 — 只针对 Cortex-A53 的 tune,不影响 ABI
EXTRA_CFLAGS += -march=armv8-a
EXTRA_CFLAGS += -mtune=cortex-a53

# 禁用 MODVERSIONS 警告升级为错误
KBUILD_MODPOST_WARN := 1

# ---------- 构建入口 ----------
# 内核树由 CI 提供：make KDIR=<kernel src>。
# 本地直接 make 会被拒绝，避免误用不匹配的 KDIR 产物。
KDIR  ?=
PWD  := $(shell pwd)

.PHONY: all clean clean-artifacts

all:
	@if [ -z "$(KDIR)" ]; then \
		echo "拒绝本地编译：请用 ./build.sh 触发远程构建。" >&2; \
		echo "如果确实需要指定内核树，显式传 KDIR=<path>。" >&2; \
		exit 1; \
	fi
	$(MAKE) -j -C $(KDIR) M=$(PWD) modules
	@llvm-objcopy --remove-section=.BTF --remove-section=.BTF.ext $(MODULE_NAME).ko 2>/dev/null || true
	@llvm-strip --strip-debug $(MODULE_NAME).ko 2>/dev/null || strip --strip-debug $(MODULE_NAME).ko
	@$(MAKE) --no-print-directory clean-artifacts

clean-artifacts:
	@rm -f *.o *.o.d .*.cmd *.mod *.mod.c *.mod.o *.symvers *.order *.o.tmp *.usyms .*.usyms.cmd .module-common.o .module-common.o.d .module-common.o.cmd
	@find src -type f \( \
		-name '*.o' -o -name '*.o.d' -o -name '.*.cmd' -o \
		-name '*.mod' -o -name '*.mod.c' -o -name '*.mod.o' -o \
		-name '*.symvers' -o -name '*.order' -o -name '*.o.tmp' -o \
		-name '*.usyms' -o -name '.*.usyms.cmd' \
	\) -delete
	@rm -rf .tmp_versions

clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers *.order .module-common.o .module-common.o.d .module-common.o.cmd
	rm -f src/comm/*.o src/comm/.*.cmd src/comm/*.o.d
	rm -f src/core/*.o src/core/.*.cmd src/core/*.o.d
	rm -f src/hide/*.o src/hide/.*.cmd src/hide/*.o.d
	rm -f src/hwbp/*.o src/hwbp/.*.cmd src/hwbp/*.o.d
	rm -f src/input/*.o src/input/.*.cmd src/input/*.o.d
	rm -f src/comm/*.o.tmp src/core/*.o.tmp src/hide/*.o.tmp src/hwbp/*.o.tmp src/input/*.o.tmp
