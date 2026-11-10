LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := nbg_udp_capture
LOCAL_SRC_FILES := ../../udp_capture_client.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../.. $(LOCAL_PATH)/../../../include
LOCAL_CPPFLAGS := -std=c++17 -O2 -Wall -Wextra -Werror
include $(BUILD_EXECUTABLE)
