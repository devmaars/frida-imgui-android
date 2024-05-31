# Frida Android IMGUI

## Work in progress

This is a work in progress project to create a simple IMGUI for Android using Frida.

## Build IMGUI

You must have the Android NDK, android build tools and cmake installed. And set up the all the environment variables in the `Makefile`.

```bash
make lib # to build the library
make java # to build the java wrapper
make all # to build both
```

The project build system and dependencies are changing fast so this README might not be up to date. Please refer to the `Makefile` for the most up to date information.

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

# TODO:
- [x] For some reason the imgui window is not showing up. Need to investigate.