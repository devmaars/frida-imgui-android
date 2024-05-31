
package me.maars;

import android.content.Context;
import android.opengl.GLSurfaceView;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.util.Log;

public class MyGLSurfaceView extends GLSurfaceView {
    private final static String TAG = "MyGLSurfaceView";
    private final static String TMP_PATH = "/data/local/tmp";
    private final static String LIB_NAME = "libimgui.so";

    private final MyGLRenderer renderer;

    static {
        System.load(TMP_PATH + "/" + LIB_NAME);
    }

    public MyGLSurfaceView(Context context) {
        super(context);

        Log.d(TAG, "MyGLSurfaceView constructor");

        setEGLContextClientVersion(3);

        renderer = new MyGLRenderer();
        setRenderer(renderer);
    }

    @Override
    public void surfaceCreated(SurfaceHolder holder) {
        Log.d(TAG, "surfaceCreated");

        super.surfaceCreated(holder);
        nativeSurfaceCreated(holder.getSurface());
    }

    @Override
    public void surfaceDestroyed(SurfaceHolder holder) {
        Log.d(TAG, "surfaceDestroyed");

        super.surfaceDestroyed(holder);
        nativeSurfaceDestroyed();
    }

    public native void nativeSurfaceCreated(Surface surface);

    public native void nativeSurfaceDestroyed();
}
