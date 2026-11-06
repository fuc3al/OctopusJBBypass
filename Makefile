export ARCHS = arm64 arm64e
export TARGET = iphone:clang:latest:15.0

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = OctopusJBHook
OctopusJBHook_FILES = src/OctopusJBHook.m
OctopusJBHook_FRAMEWORKS = Foundation UIKit
OctopusJBHook_CFLAGS = -fobjc-arc -O2 -DOCTO_JB_DEBUG
OctopusJBHook_LDFLAGS = -install_name @executable_path/Frameworks/libOctopusJBHook.dylib

include $(THEOS_MAKE_PATH)/library.mk
