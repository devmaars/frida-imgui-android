package me.maars;

// import android.opengl.GLES20;
import android.opengl.GLES30;
import android.opengl.GLSurfaceView;
import android.util.Log;
// import android.view.ViewGroup;

import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.opengles.GL10;

public class MyGLRenderer implements GLSurfaceView.Renderer {
    private static final String TAG = "MyGLRenderer";

    @Override
    public void onSurfaceCreated(GL10 gl, EGLConfig config) {
        Log.d(TAG, "onSurfaceCreated");
    }

    @Override
    public void onDrawFrame(GL10 gl) {
        Log.d(TAG, "onDrawFrame");
        // Clear the screen
        // GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT);

        // draw something

        // GLES20.glClearColor(1, 0, 0, 1);
        // GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT);

        nativeOnDrawFrame();
    }

    @Override
    public void onSurfaceChanged(GL10 gl, int width, int height) {
        Log.d(TAG, "onSurfaceChanged");
        GLES30.glViewport(0, 0, width, height);

        nativeOnSurfaceChanged(width, height);
    }

    public native void nativeOnDrawFrame();

    public native void nativeOnSurfaceChanged(int w, int h);
}
