
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
        setRenderMode(RENDERMODE_CONTINUOUSLY); // Ensure continuous rendering
    }

    @Override
    public void surfaceCreated(SurfaceHolder holder) {
        super.surfaceCreated(holder);

        Log.d(TAG, "surfaceCreated");

        nativeSurfaceCreated(holder.getSurface());
    }

    @Override
    public void surfaceDestroyed(SurfaceHolder holder) {
        super.surfaceDestroyed(holder);

        Log.d(TAG, "surfaceDestroyed");

        nativeSurfaceDestroyed();
    }

    public native void nativeSurfaceCreated(Surface surface);

    public native void nativeSurfaceDestroyed();
}
