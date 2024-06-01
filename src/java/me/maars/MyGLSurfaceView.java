package me.maars;

import android.content.Context;
import android.opengl.GLSurfaceView;
import android.util.Log;
import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.opengles.GL10;

import static android.graphics.PixelFormat.TRANSPARENT;

public class MyGLSurfaceView extends GLSurfaceView implements GLSurfaceView.Renderer {
    protected final static String TAG = "MyGLSurfaceView";
    private final static String TMP_PATH = "/data/local/tmp";
    private final static String LIB_NAME = "libimgui.so";

    static {
        System.load(TMP_PATH + "/" + LIB_NAME);

        Log.d(TAG, "Loaded " + TMP_PATH + "/" + LIB_NAME);
    }

    public MyGLSurfaceView(Context ctx) {
        super(ctx);

        Log.d(TAG, "MyGLSurfaceView");

        setEGLContextClientVersion(3);
        setEGLConfigChooser(8, 8, 8, 8, 16, 0);
        getHolder().setFormat(TRANSPARENT);
        setZOrderOnTop(true);
        setRenderer(this);
    }

    @Override
    public void onSurfaceCreated(GL10 gl, EGLConfig config) {
        Log.d(TAG, "onSurfaceCreated");

        nativeOnSurfaceCreated();
    }

    @Override
    public void onSurfaceChanged(GL10 gl, int width, int height) {
        Log.d(TAG, "onSurfaceChanged");

        nativeOnSurfaceChanged(width, height);
    }

    @Override
    public void onDrawFrame(GL10 gl) {
        Log.d(TAG, "onDrawFrame");

        nativeOnDrawFrame();
    }

    public static native void nativeOnDrawFrame();

    public static native void nativeOnSurfaceChanged(int width, int height);

    public static native void nativeOnSurfaceCreated();

    public static native boolean handleTouch(float x, float y, int action);
}