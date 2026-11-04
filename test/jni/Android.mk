LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := LS_test
LOCAL_SRC_FILES := ../shmem_test.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../.. $(LOCAL_PATH)/../../include
LOCAL_CPPFLAGS := -std=c++17 -O2 -fno-exceptions -fno-rtti
include $(BUILD_EXECUTABLE)
