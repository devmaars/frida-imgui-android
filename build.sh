#!/bin/bash

# Set the NDK path, adjust if necessary
export ANDROID_NDK_HOME="$HOME/Android/Sdk/ndk/21.4.7075529"

# List of target architectures
ARCHS=("armeabi-v7a" "arm64-v8a")

# Create a build directory if it doesn't exist
mkdir -p build
cd build

# Loop through each architecture and build the shared library
for ARCH in "${ARCHS[@]}"; do
    mkdir -p $ARCH
    cd $ARCH
    cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
          -DANDROID_ABI=$ARCH \
          -DANDROID_PLATFORM=android-21 \
          ../..
    cmake --build .
    if (($? != 0)); then
        echo "Error building for $ARCH"
        exit 1
    fi
        
    cd ..
done

# echo "Current dir $(pwd)" 
adb push arm64-v8a/libimgui.so /data/local/tmp
adb shell chmod 777 /data/local/tmp/libimgui.so