package me.maars;

import android.app.Activity;
import android.content.Context;
import android.opengl.GLSurfaceView;
import android.util.Log;
import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.opengles.GL10;
import android.view.MotionEvent;
import android.view.Surface;
import android.view.WindowManager;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;

import static android.view.WindowManager.LayoutParams;
import static android.graphics.PixelFormat.TRANSLUCENT;
import static android.graphics.PixelFormat.TRANSPARENT;
import static android.view.ViewGroup.LayoutParams.MATCH_PARENT;
import static android.view.WindowManager.LayoutParams.TYPE_APPLICATION;
import static android.view.WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE;
import static android.view.WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL;

public class MyGLSurfaceView extends GLSurfaceView implements GLSurfaceView.Renderer {
    private final static String TAG = "MyGLSurfaceView";
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

        startMenu(ctx);
    }

    @Override
    public void onSurfaceCreated(GL10 gl, EGLConfig config) {
        Log.d(TAG, "onSurfaceCreated");

        nativeOnSurfaceCreated(getHolder().getSurface());
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

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        Log.d(TAG, "onTouchEvent");

        if (handleTouch(event.getX(), event.getY(), event.getAction()))
            return true;

        // If ImGui doesn't handle the event, dispatch it to the underlying views
        View rootView = ((Activity) getContext()).getWindow().getDecorView().getRootView();
        return dispatchTouchEventToRoot(rootView, event);
    }

    private boolean dispatchTouchEventToRoot(View rootView, MotionEvent event) {
        if (rootView instanceof ViewGroup) {
            ViewGroup rootViewGroup = (ViewGroup) rootView;
            MotionEvent eventCopy = MotionEvent.obtain(event);

            for (int i = 0; i < rootViewGroup.getChildCount(); i++) {
                View child = rootViewGroup.getChildAt(i);
                if (child != this && child.dispatchTouchEvent(eventCopy))
                    return true;
            }
        }
        return false;
    }

    private void startMenu(Context ctx) {
        Log.d(TAG, "startMenu");

        // check if the view is already added
        if (getParent() != null) {
            return;
        }

        WindowManager wm = ((Activity) ctx).getWindowManager();
        LayoutParams params = new LayoutParams(
                MATCH_PARENT,
                MATCH_PARENT,
                TYPE_APPLICATION,
                FLAG_NOT_TOUCH_MODAL | FLAG_NOT_FOCUSABLE,
                TRANSLUCENT);

        params.gravity = Gravity.TOP | Gravity.CENTER_VERTICAL | Gravity.CENTER_HORIZONTAL;

        wm.addView(this, params);
    }

    private static native void nativeOnDrawFrame();

    private static native void nativeOnSurfaceChanged(int width, int height);

    private static native void nativeOnSurfaceCreated(Surface surface);

    private static native boolean handleTouch(float x, float y, int action);
}