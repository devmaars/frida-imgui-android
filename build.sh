#!/bin/bash

set -e

# Android SDK and NDK settings
ANDROID_SDK_HOME="${HOME}/Android/Sdk"
ANDROID_NDK_VERSION="21.4.7075529"
ANDROID_NDK_HOME="${ANDROID_SDK_HOME}/ndk/${ANDROID_NDK_VERSION}"
ANDROID_BUILD_TOOLS_VERSION="30.0.3"
ANDROID_PLATFORM_VERSION="android-30"
ANDROID_PLATFORM="${ANDROID_SDK_HOME}/platforms/${ANDROID_PLATFORM_VERSION}/android.jar"
BUILD_TOOLS="${ANDROID_SDK_HOME}/build-tools/${ANDROID_BUILD_TOOLS_VERSION}"
CMAKE_TOOLCHAIN="${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake"

# Source and build directories
SOURCE_DIR="src"
TEMP_DIR="temp"
BUILD_DIR="build"
JAVA_SRC_DIR="${SOURCE_DIR}/java/me/maars"
JAVA_TEMP_DIR="${TEMP_DIR}/me/maars"
JAVA_OUT_DIR="${BUILD_DIR}/java"

# Output file
DEXFILE="renderer.dex"

# List of target architectures
ARCHS="armeabi-v7a arm64-v8a"

mkdir -p "${TEMP_DIR}"
mkdir -p "${BUILD_DIR}"
mkdir -p "${JAVA_OUT_DIR}"

# Function to build the native library
build_lib() {
    for ARCH in ${ARCHS}; do
        mkdir -p "${BUILD_DIR}/${ARCH}"
        cd "${BUILD_DIR}/${ARCH}"
        cmake -DCMAKE_TOOLCHAIN_FILE="${CMAKE_TOOLCHAIN}" \
            -DANDROID_ABI="${ARCH}" \
            -DANDROID_PLATFORM="${ANDROID_PLATFORM_VERSION}" \
            ../..
        cmake --build .
        cd ../..
    done
    echo -e "\033[0;32mNative library build successful for all architectures\033[0m"
}

# Function to build the Java files
build_java() {
    javac -source 11 -target 11 -classpath "${ANDROID_PLATFORM}" -d temp "${JAVA_SRC_DIR}"/*.java
    mv "${JAVA_TEMP_DIR}"/*.class "${JAVA_OUT_DIR}/"

    "${BUILD_TOOLS}/d8" --release "${JAVA_OUT_DIR}"/*.class --output "${JAVA_OUT_DIR}"
    mv "${JAVA_OUT_DIR}/classes.dex" "${JAVA_OUT_DIR}/${DEXFILE}"

    echo -e "\033[0;32mJava build successful\033[0m"
}

# Check for arguments and call the appropriate function
case "$1" in
lib)
    build_lib
    ;;
java)
    build_java
    ;;
all)
    build_lib
    build_java
    ;;
*)
    echo "Usage: $0 {lib|java|all}"
    exit 1
    ;;
esac
