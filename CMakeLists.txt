cmake_minimum_required(VERSION 3.6)

# Set the project name
project(FridaImGuiAndroid)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(SRC ${CMAKE_SOURCE_DIR}/src/cpp)
set(IMGUI_DIR ${SRC}/imgui)

file(GLOB IMGUI_SRC
    ${IMGUI_DIR}/*.cpp
)

# Add the shared library
add_library(imgui SHARED 
    ${IMGUI_SRC}
    ${SRC}/main.cpp
)

# Specify the include directories
target_include_directories(imgui PRIVATE
    ${SRC}/*
    ${IMGUI_DIR}
    ${ANDROID_NDK}/sysroot/usr/include/*
)

# Link libraries
find_library(log-lib log)
find_library(android-lib android)
find_library(GLESv3-lib GLESv3)
find_library(EGL-lib EGL)

target_link_libraries(imgui ${log-lib} ${android-lib} ${GLESv3-lib} ${EGL-lib})