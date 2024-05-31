LIB=build/arm64-v8a/libimgui.so
# LIB=build/armeabi-v7a/libimgui.so
DEX=build/java/renderer.dex

adb push $LIB /data/local/tmp
adb push $DEX /data/local/tmp

adb shell chmod 777 /data/local/tmp/libimgui.so
adb shell chmod 777 /data/local/tmp/renderer.dex