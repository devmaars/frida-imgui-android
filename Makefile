# Android SDK and NDK settings
ANDROID_SDK_HOME := $(HOME)/Android/Sdk
ANDROID_NDK_HOME := $(ANDROID_SDK_HOME)/ndk/21.4.7075529
ANDROID_BUILD_TOOLS_VERSION := 30.0.3
ANDROID_PLATFORM_VERSION := android-30
ANDROID_PLATFORM := $(ANDROID_SDK_HOME)/platforms/$(ANDROID_PLATFORM_VERSION)/android.jar
BUILD_TOOLS := $(ANDROID_SDK_HOME)/build-tools/$(ANDROID_BUILD_TOOLS_VERSION)
CMAKE_TOOLCHAIN := $(ANDROID_NDK_HOME)/build/cmake/android.toolchain.cmake

# Source and build directories
SOURCE_DIR := src
TEMP_DIR := temp
BUILD_DIR := build
JAVA_SRC_DIR := $(SOURCE_DIR)/java/me/maars
JAVA_TEMP_DIR := $(TEMP_DIR)/me/maars
JAVA_OUT_DIR := $(BUILD_DIR)/java

# Output file
DEXFILE := renderer.dex

# List of target architectures
ARCHS := armeabi-v7a arm64-v8a

# Create a build directory if it doesn't exist
build:
	mkdir -p $(BUILD_DIR)
	mkdir -p $(JAVA_OUT_DIR)

# Build rules
lib: build
	ARCHS="$(ARCHS)" \
	BUILD_DIR="$(BUILD_DIR)" \
	CMAKE_TOOLCHAIN="$(CMAKE_TOOLCHAIN)" \
	ANDROID_PLATFORM_VERSION="$(ANDROID_PLATFORM_VERSION)" \
	$(shell pwd)/build.sh lib

java: build
	ANDROID_PLATFORM="$(ANDROID_PLATFORM)" \
	JAVA_TEMP_DIR="$(JAVA_TEMP_DIR)" \
	JAVA_SRC_DIR="$(JAVA_SRC_DIR)" \
	JAVA_OUT_DIR="$(JAVA_OUT_DIR)" \
	BUILD_TOOLS="$(BUILD_TOOLS)" \
	DEXFILE="$(DEXFILE)" \
	$(shell pwd)/build.sh java

all: lib java

# Clean rule to remove the build directory
clean:
	rm -rf $(BUILD_DIR) $(TEMP_DIR)

.PHONY: build lib java clean
