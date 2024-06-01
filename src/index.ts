import { log, sleep } from './util.js';

console.log("Script loaded successfully 🚀")

const TMP_DIR = '/data/local/tmp';
const RENDERER_DEX_PATH = TMP_DIR + '/renderer.dex';

Java.perform(() => {
  main().catch((err) => console.error(err, err.stack));
});

async function main() {
  Java.openClassFile(RENDERER_DEX_PATH).load();

  const Activity = Java.use('android.app.Activity');
  const MyGLSurfaceView = Java.use('me.maars.MyGLSurfaceView');

  console.log(MyGLSurfaceView)

  let rendererSet = false;
  let glSurfaceView: Java.Wrapper;

  Activity.onCreate.overload('android.os.Bundle').implementation = function (savedInstanceState: Java.Wrapper) {
    log('Activity.onCreate()');
    this.onCreate(savedInstanceState);

    // Check OpenGL ES version before creating GLSurfaceView
    if (!supportsOpenGLES3()) {
      console.error("This device does not support OpenGL ES 3.0");
      return;
    }

    glSurfaceView = MyGLSurfaceView.$new(this);
    glSurfaceView = Java.retain(glSurfaceView);
    console.log(glSurfaceView)

    rendererSet = true;
  };

  // Function to check if the device supports OpenGL ES 3.0
  function supportsOpenGLES3() {
    const GLES30 = Java.use('android.opengl.GLES30');
    return GLES30.$new() !== null;
  }
}