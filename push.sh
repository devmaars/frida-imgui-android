LIB=build/arm64-v8a/libimgui.so # for 64-bit
# LIB=build/armeabi-v7a/libimgui.so # for 32-bit
DEX=build/java/renderer.dex

adb push $LIB /data/local/tmp
adb push $DEX /data/local/tmp

adb shell chmod 777 /data/local/tmp/libimgui.so
adb shell chmod 777 /data/local/tmp/renderer.dex

adb shell "su -c 'setenforce 0'"
