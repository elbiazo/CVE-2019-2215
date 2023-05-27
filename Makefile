CXX             := clang++
CXXFLAGS        := -static -O3 -Wall -Wextra

ARCH            := x86_64
NDK_API         ?= 29
CROSS_COMPILE   := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64

TARGET_PLATFORM := $(ARCH)-linux-android

CXX_PATH        := $(CROSS_COMPILE)/bin/$(TARGET_PLATFORM)$(NDK_API)-$(CXX)

EXP_SRC     := exp.cc
EXP_OUTPUT  := cve-2019-2215-exp

# default rule
default: all

# phony rules
.PHONY: all

all: clean build-exp

build-exp:
	@echo Building: $(EXP_OUTPUT)
	@$(CXX_PATH) $(CXXFLAGS) -o $(EXP_OUTPUT) $(EXP_SRC)

clean:
	@echo Removing: $(EXP_OUTPUT)
	@rm -f $(EXP_OUTPUT)


push-exp:
	@echo Pushing: $(EXP_OUTPUT) to /data/local/tmp
	@adb push $(EXP_OUTPUT) /data/local/tmp

run: build-exp push-exp
	adb shell /data/local/tmp/cve-2019-2215-exp
