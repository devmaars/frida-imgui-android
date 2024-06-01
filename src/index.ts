import { log, sleep } from './util.js';

console.log('Script loaded successfully 🚀');

const TMP_DIR = '/data/local/tmp';
const LIB_IMGUI_PATH = TMP_DIR + '/libimgui.so';
const RENDERER_DEX_PATH = TMP_DIR + '/renderer.dex';

Java.perform(() => {
  main().catch((err) => console.error(err, err.stack));
});

async function main() {
  console.log(`Process id: ${Process.id}`);

  const System = Java.use('java.lang.System');

  // const libimgui = Module.load(LIB_IMGUI_PATH);

  System.load(LIB_IMGUI_PATH);
  Java.openClassFile(RENDERER_DEX_PATH).load();

  // @ts-ignore
  const maps = File.readAllText('/proc/self/maps')
    .split('\n')
    .filter((line: string) => line.includes('libimgui'));
  console.log(maps);

  // let do_dlopen = NULL;
  // let call_constructor = NULL;
  // Process.findModuleByName('linker64') // change to linker32 if needed for 32-bit
  //   ?.enumerateSymbols()
  //   .forEach(function (symbol) {
  //     if (symbol.name.indexOf('do_dlopen') >= 0) {
  //       do_dlopen = symbol.address;
  //     }
  //     if (symbol.name.indexOf('call_constructor') >= 0) {
  //       call_constructor = symbol.address;
  //     }
  //   });

  // let lib_loaded = 0;
  // // let libimgui = null;
  // Interceptor.attach(do_dlopen, function () {
  //   // @ts-ignore
  //   const library_path = this.context.x0.readCString();
  //   console.log(`[+] Loading library: ${library_path}`);
  //   if (library_path.indexOf('libimgui') >= 0) {
  //     Interceptor.attach(call_constructor, function () {
  //       if (lib_loaded == 0) {
  //         lib_loaded = 1;
  //         // libimgui = Process.findModuleByName('libimgui.so');
  //         // console.log(`[+] libimgui is loaded at ${libimgui?.base}`);
  //       }
  //     });
  //   }
  // });

  // const __cxa_demangle = libimgui.getExportByName('__cxa_demangle');
  // const Demangle = new NativeFunction(__cxa_demangle, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

  // const demangledStatus = Memory.alloc(0x4);
  // function findImGuiSymbol(name: string) {
  //   const symbol = libimgui.enumerateExports().find((exp) => {
  //     const expName = Memory.allocUtf8String(exp.name);
  //     const realName = Demangle(expName, NULL, NULL, demangledStatus);
  //     if (demangledStatus.readU32() !== 0) return false;

  //     return realName.readCString()?.includes(name);
  //   });

  //   return symbol;
  // }

  //TODO: check /proc/self/maps for the address of libimgui.so

  // function getImGuiSymbol(name: string) {
  //   const symbol = findImGuiSymbol(name);
  //   if (!symbol) throw new Error(`Symbol ${name} not found`);

  //   return symbol.address;
  // }

  const Activity = Java.use('android.app.Activity');
  const MyGLSurfaceView = Java.use('me.maars.MyGLSurfaceView');

  console.log(MyGLSurfaceView);

  let rendererSet = false;
  let glSurfaceView: Java.Wrapper;

  Activity.onCreate.overload('android.os.Bundle').implementation = function (savedInstanceState: Java.Wrapper) {
    log('Activity.onCreate()');
    this.onCreate(savedInstanceState);

    glSurfaceView = MyGLSurfaceView.$new(this);
    glSurfaceView = Java.retain(glSurfaceView);
    console.log(glSurfaceView);

    rendererSet = true;
  };

  // const ImGui = {
  //   Begin: new NativeFunction(getImGuiSymbol('Begin'), 'bool', ['pointer']),
  //   End: new NativeFunction(getImGuiSymbol('End'), 'void', []),
  //   Text: new NativeFunction(getImGuiSymbol('Text'), 'void', ['pointer']),
  // };

  // const renderFrame = new NativeFunction(libimgui.getExportByName('renderFrame'), 'void', []);
  // console.log('renderFrame', renderFrame);

  // Interceptor.replace(
  //   renderFrame,
  //   new NativeCallback(
  //     () => {
  //       ImGui.Begin(Memory.allocUtf8String('Hello, world! From Frida 🚀'));
  //       ImGui.Text(Memory.allocUtf8String('Welcome to the ImGui demo!'));
  //       ImGui.End();
  //     },
  //     'void',
  //     [],
  //   ),
  // );
}
