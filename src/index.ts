import { log, getAbi, sleep } from './util.js';

Java.perform(() => {
  main().catch((err) => console.error(err, err.stack));
});

async function main() {
  await sleep(2000);

  const TMP_DIR = '/data/local/tmp';
  const LIB_IMGUI_PATH = TMP_DIR + '/libimgui.so';

  const imgui = Module.load(LIB_IMGUI_PATH);

  const __cxa_demangle = imgui.getExportByName('__cxa_demangle');
  console.log('__cxa_demangle:', __cxa_demangle);

  // const demangledStatus = Memory.alloc(0x4);
  const Demangle = new NativeFunction(__cxa_demangle, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);

  const findImGuiExport = (name: string) => {
    return imgui.enumerateExports().find((exp) => {
      const demangled = Memory.allocUtf8String(exp.name);
      const demangledName = Demangle(demangled, NULL, NULL, NULL);

      // console.log(
      //   'Demangled Name',
      //   demangledName.readUtf8String(),
      //   'Match',
      //   name,
      //   'Result',
      //   demangledName.readUtf8String()?.match(name) ? 'Yes' : 'No',
      // );

      return demangledName.readUtf8String()?.match(name);
    });
  };

  const getImGuiExport = (name: string) => {
    const ret = findImGuiExport(name);
    if (!ret) throw new Error(`Export ${name} not found`);

    return ret;
  };

  const egl = Module.load('libEGL.so');
  const gles3 = Module.load('libGLESv2.so');

  egl.enumerateExports().forEach((exp) => {
    const demangled = Memory.allocUtf8String(exp.name);
    const demangledName = Demangle(demangled, NULL, NULL, NULL);

    const res = demangledName.readUtf8String();
    if (res) {
      console.log(res);
    }

    // console.log(
    //   'Demangled Name',
    //   demangledName.readUtf8String(),
    //   'Match',
    //   'egl',
    //   'Result',
    //   demangledName.readUtf8String()?.match('egl') ? 'Yes' : 'No',
    // );
  });

  // const eglGetProcAddress = egl.getExportByName('eglGetProcAddress');
  // const glGetString = gles3.getExportByName('glGetString');

  // const eglGetProcAddressFunc = new NativeFunction(eglGetProcAddress, 'pointer', ['pointer']);
  // const glGetStringFunc = new NativeFunction(glGetString, 'pointer', ['int']);

  // const GL_VERSION = 0x1f02;
  // const GL_VENDOR = 0x1f00;
  // const GL_RENDERER = 0x1f01;
  // const GL_EXTENSIONS = 0x1f03;

  // const glGetStringVersion = (name: number) => {
  //   const ret = glGetStringFunc(name);
  //   return ret.readUtf8String();
  // };

  // console.log('GL_VERSION:', glGetStringVersion(GL_VERSION));
  // console.log('GL_VENDOR:', glGetStringVersion(GL_VENDOR));
  // console.log('GL_RENDERER:', glGetStringVersion(GL_RENDERER));
  // console.log('GL_EXTENSIONS:', glGetStringVersion(GL_EXTENSIONS));
}
