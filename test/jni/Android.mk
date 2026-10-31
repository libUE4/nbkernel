LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := LS_test
LOCAL_SRC_FILES := ../shmem_test.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../.. $(LOCAL_PATH)/../../include
LOCAL_CPPFLAGS := -std=c++17 -O2 -fno-exceptions -fno-rtti
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := nbg_kgsl_syncsource_snapshot_probe
LOCAL_SRC_FILES := ../kgsl_syncsource_snapshot_probe.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../.. $(LOCAL_PATH)/../../include
LOCAL_CFLAGS := -O2 -Wall -Wextra -Werror
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := nbg_shadow_call_trace
LOCAL_SRC_FILES := ../shadow_call_trace.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../.. $(LOCAL_PATH)/../../include
LOCAL_CFLAGS := -O2
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := nbg_module_unhide
LOCAL_SRC_FILES := ../module_unhide.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../.. $(LOCAL_PATH)/../../include
LOCAL_CFLAGS := -O2
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := nbg_thread_fpstate_probe
LOCAL_SRC_FILES := ../thread_fpstate_probe.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../.. $(LOCAL_PATH)/../../include
LOCAL_CPPFLAGS := -std=c++17 -O2 -Wall -Wextra -Werror
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := nbg_guard_probe
LOCAL_SRC_FILES := ../guard_probe.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../.. $(LOCAL_PATH)/../../include
LOCAL_CFLAGS := -O2
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := pid_visibility_probe
LOCAL_SRC_FILES := ../pid_visibility_probe.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../.. $(LOCAL_PATH)/../../include
LOCAL_CPPFLAGS := -std=c++17 -O2 -fno-exceptions -fno-rtti
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := query_probe
LOCAL_SRC_FILES := ../query_probe.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../.. $(LOCAL_PATH)/../../include
LOCAL_CFLAGS := -O2
include $(BUILD_EXECUTABLE)
