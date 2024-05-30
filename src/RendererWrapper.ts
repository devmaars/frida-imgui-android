import { log } from './util.js';

Java.perform(() => {
  const GLES20 = Java.use('android.opengl.GLES20');
  const GLSurfaceView$Renderer = Java.use('android.opengl.GLSurfaceView$Renderer');

  Java.registerClass({
    name: 'me.maars.RendererWrapper',
    implements: [GLSurfaceView$Renderer],
    methods: {
      onSurfaceCreated(gl: any, config: any) {
        log('RendererWrapper.onSurfaceCreated()');

        // Transparent background
        GLES20.glClearColor(0.0, 0.0, 0.0, 0.0); // RGBA format, A=0.0 for transparent
      },
      onSurfaceChanged(gl: any, width: number, height: number) {
        log('RendererWrapper.onSurfaceChanged()');
      },
      onDrawFrame(gl: any) {
        log('RendererWrapper.onDrawFrame()');

        // Transparent background
        GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT.value | GLES20.GL_DEPTH_BUFFER_BIT.value);

        // Draw something
        // GLES20.glClearColor(1, 0, 0, 1);
        // GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT.value);
      },
    },
  });
});
