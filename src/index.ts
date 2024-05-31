// import './RendererWrapper.js';
import { log, sleep } from './util.js';

console.log("Script loaded successfully 🚀")

const TMP_DIR = '/data/local/tmp';
const RENDERER_DEX_PATH = TMP_DIR + '/renderer.dex';

Java.perform(() => {
  main().catch((err) => console.error(err, err.stack));
});

async function main() {
  // await sleep(2000);
  Java.openClassFile(RENDERER_DEX_PATH).load();

  const Log = Java.use('android.util.Log');
  const Activity = Java.use('android.app.Activity');
  // const GLSurfaceView = Java.use('android.opengl.GLSurfaceView');
  const MyGLSurfaceView = Java.use('me.maars.MyGLSurfaceView');

  console.log(MyGLSurfaceView)

  let rendererSet = false;
  let glSurfaceView: Java.Wrapper;

  Activity.onCreate.overload('android.os.Bundle').implementation = function (savedInstanceState: Java.Wrapper) {
    log('Activity.onCreate()');
    this.onCreate(savedInstanceState);

    glSurfaceView = MyGLSurfaceView.$new(this);
    glSurfaceView = Java.retain(glSurfaceView);

    console.log(glSurfaceView)

    const viewGroup = Java.cast(this.getWindow().getDecorView().getRootView(), Java.use('android.view.ViewGroup'));
    viewGroup.addView(glSurfaceView);

    rendererSet = true;
  };
}
