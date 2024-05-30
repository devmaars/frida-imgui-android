# Frida Android IMGUI

## Work in progress

This is a work in progress project to create a simple IMGUI for Android using Frida.

## Build IMGUI

You must have the Android NDK installed and set up the PATH in the `build.sh` script.

```bash
./build.sh
```

You can also find the pre-built library in the `build` folder.

## How to use

Place the `libimgui.so` in `/data/local/tmp/` and you are ready to go.

Also dont forget to give the lib permission to execute.
```bash
adb push build/libimgui.so /data/local/tmp/
adb shell chmod 777 /data/local/tmp/libimgui.so
```

Frida `Module.load` might not work unless you change your SELinux policy.

```bash
adb shell setenforce 0
```

You can resolve all the symbols using the utilities functions in the script and call the functions directly.

## Contributing

Feel free to contribute to this project. I will be happy to accept pull requests.

## License

This project follow any rule set by the original IMGUI project.