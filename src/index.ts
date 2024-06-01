import { log, sleep } from './util.js';

console.log("Script loaded successfully 🚀")

const TMP_DIR = '/data/local/tmp';
const RENDERER_DEX_PATH = TMP_DIR + '/renderer.dex';

Java.perform(() => {
  main().catch((err) => console.error(err, err.stack));
});

async function main() {
  Java.openClassFile(RENDERER_DEX_PATH).load();

  const Context = Java.use('android.content.Context');
  const Intent = Java.use('android.content.Intent');
  const Activity = Java.use('android.app.Activity');
  // const MyGLActivity = Java.use('me.maars.MyGLActivity');
  const MyGLSurfaceView = Java.use('me.maars.MyGLSurfaceView');

  const WindowManager = Java.use('android.view.WindowManager');
  const WindowManager$LayoutParams = Java.use('android.view.WindowManager$LayoutParams');
  const Gravity = Java.use('android.view.Gravity');
  const ViewGroup$LayoutParams = Java.use('android.view.ViewGroup$LayoutParams');
  const PixelFormat = Java.use('android.graphics.PixelFormat');

  // console.log(MyGLActivity)
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

    const params = WindowManager$LayoutParams.$new(
      ViewGroup$LayoutParams.MATCH_PARENT.value,
      ViewGroup$LayoutParams.MATCH_PARENT.value,
      0, 0,
      WindowManager$LayoutParams.TYPE_APPLICATION.value,
      WindowManager$LayoutParams.FLAG_NOT_FOCUSABLE.value,
      PixelFormat.TRANSPARENT.value
    );

    params.gravity.value = Gravity.TOP.value | Gravity.CENTER_VERTICAL.value | Gravity.CENTER_HORIZONTAL.value;

    glSurfaceView = MyGLSurfaceView.$new(this);
    glSurfaceView = Java.retain(glSurfaceView);
    console.log(glSurfaceView)

      const wm = Java.cast(
        this.getSystemService(Context.WINDOW_SERVICE.value),
        Java.use('android.view.ViewManager'),
      );
      
      wm.addView(glSurfaceView, params);

      // This also work if you dont want to use WindowManager
    // const viewGroup = Java.cast(this.getWindow().getDecorView().getRootView(), Java.use('android.view.ViewGroup'));
    // viewGroup.addView(glSurfaceView);

    rendererSet = true;
  };

  Activity.onResume.implementation = function () {
    log('Activity.onResume()');
    this.onResume();
  }

  Activity.onPause.implementation = function () {
    log('Activity.onPause()');
    this.onPause();
  }

  // Function to check if the device supports OpenGL ES 3.0
  function supportsOpenGLES3() {
    const GLES30 = Java.use('android.opengl.GLES30');
    return GLES30.$new() !== null;
  }
}