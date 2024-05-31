# Set the NDK path, adjust if necessary

DEXFILE=renderer.dex
SOURCE_DIR := src
TEMP_DIR := temp
BUILD_DIR := build

ANDROID_NDK_HOME := $(HOME)/Android/Sdk/ndk/21.4.7075529
ANDROID_PLATFORM := $(HOME)/Android/Sdk/platforms/android-30/android.jar
BUILD_TOOLS := $(HOME)/Android/Sdk/build-tools/30.0.3
CMAKE_TOOLCHAIN := $(ANDROID_NDK_HOME)/build/cmake/android.toolchain.cmake

JAVA_SRC_DIR := $(SOURCE_DIR)/java/me/maars
JAVA_TEMP_DIR := $(TEMP_DIR)/me/maars
JAVA_OUT_DIR := $(BUILD_DIR)/dexfile

# List of target architectures
ARCHS := armeabi-v7a arm64-v8a

# Create a build directory if it doesn't exist
build:
	mkdir -p $(BUILD_DIR)
	mkdir -p $(JAVA_OUT_DIR)

# Build rule for native library
lib: build
	@for ARCH in $(ARCHS); do \
		mkdir -p build/$$ARCH; \
		cd build/$$ARCH; \
		cmake -DCMAKE_TOOLCHAIN_FILE=$(CMAKE_TOOLCHAIN) \
		  -DANDROID_ABI=$$ARCH \
		  -DANDROID_PLATFORM=android-30 \
		  ../..; \
		cmake --build .; \
		if [ $$? -ne 0 ]; then \
			echo "Error building for $$ARCH"; \
			exit 1; \
		fi; \
		cd ../..; \
	done

# Build rule for Java
java: build
	javac -source 11 -target 11 -classpath $(ANDROID_PLATFORM) -d temp $(JAVA_SRC_DIR)/RendererWrapper.java
	mv $(JAVA_TEMP_DIR)/RendererWrapper.class $(JAVA_OUT_DIR)/RendererWrapper.class
	$(BUILD_TOOLS)/d8 $(JAVA_OUT_DIR)/RendererWrapper.class --output $(JAVA_OUT_DIR)/
	mv $(JAVA_OUT_DIR)/classes.dex $(JAVA_OUT_DIR)/$(DEXFILE)

all: build lib java

# Clean rule to remove the build directory
clean:
	rm -rf build

.PHONY: build lib java clean
