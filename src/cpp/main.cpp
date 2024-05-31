#include <jni.h>
#include <android/log.h>
#include <android/native_window_jni.h>
#include "imgui.h"
#include "imgui_impl_android.h"
#include "imgui_impl_opengl3.h"
#include <stdexcept>
#include <EGL/egl.h>
#include <android_native_app_glue.h>
#include <GLES3/gl3.h>

#define LOG_TAG "ImGuiWrapper"
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__))
#define LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__))

static EGLDisplay g_EglDisplay = EGL_NO_DISPLAY;
static EGLSurface g_EglSurface = EGL_NO_SURFACE;
static EGLContext g_EglContext = EGL_NO_CONTEXT;
static bool show_demo_window = true;
static ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

extern "C"
{

    JNIEXPORT void JNICALL Java_me_maars_MyGLSurfaceView_nativeSurfaceCreated(JNIEnv *env, jobject thiz, jobject surface)
    {
        LOGD("nativeSurfaceCreated called");

        ANativeWindow *window = ANativeWindow_fromSurface(env, surface);
        if (window == nullptr)
        {
            LOGE("Failed to get ANativeWindow from surface");
            return;
        }

        LOGD("Window created successfully");

        g_EglDisplay = eglGetDisplay(EGL_DEFAULT_DISPLAY);
        if (g_EglDisplay == EGL_NO_DISPLAY)
        {
            LOGE("eglGetDisplay(EGL_DEFAULT_DISPLAY) returned EGL_NO_DISPLAY");
            return;
        }

        if (eglInitialize(g_EglDisplay, 0, 0) != EGL_TRUE)
        {
            LOGE("eglInitialize() returned with an error");
            return;
        }

        const EGLint egl_attributes[] = {
            EGL_BLUE_SIZE, 8,
            EGL_GREEN_SIZE, 8,
            EGL_RED_SIZE, 8,
            EGL_DEPTH_SIZE, 24,
            EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
            EGL_NONE};

        EGLint num_configs = 0;
        if (eglChooseConfig(g_EglDisplay, egl_attributes, nullptr, 0, &num_configs) != EGL_TRUE || num_configs == 0)
        {
            LOGE("eglChooseConfig() failed");
            return;
        }

        EGLConfig egl_config;
        if (eglChooseConfig(g_EglDisplay, egl_attributes, &egl_config, 1, &num_configs) != EGL_TRUE || num_configs == 0)
        {
            LOGE("Failed to choose EGL config");
            return;
        }

        EGLint egl_format;
        eglGetConfigAttrib(g_EglDisplay, egl_config, EGL_NATIVE_VISUAL_ID, &egl_format);
        ANativeWindow_setBuffersGeometry(window, 0, 0, egl_format);

        const EGLint egl_context_attributes[] = {EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE};
        g_EglContext = eglCreateContext(g_EglDisplay, egl_config, EGL_NO_CONTEXT, egl_context_attributes);
        if (g_EglContext == EGL_NO_CONTEXT)
        {
            LOGE("eglCreateContext() returned EGL_NO_CONTEXT");
            return;
        }

        g_EglSurface = eglCreateWindowSurface(g_EglDisplay, egl_config, reinterpret_cast<EGLNativeWindowType>(window), nullptr);
        if (g_EglSurface == EGL_NO_SURFACE)
        {
            LOGE("eglCreateWindowSurface() returned EGL_NO_SURFACE");
            return;
        }

        if (eglMakeCurrent(g_EglDisplay, g_EglSurface, g_EglSurface, g_EglContext) != EGL_TRUE)
        {
            LOGE("eglMakeCurrent() failed");
            return;
        }

        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGui::StyleColorsDark();

        if (!ImGui_ImplAndroid_Init(window) || !ImGui_ImplOpenGL3_Init("#version 300 es"))
        {
            LOGE("ImGui_ImplAndroid_Init or ImGui_ImplOpenGL3_Init failed");
            return;
        }
    }

    JNIEXPORT void JNICALL Java_me_maars_MyGLRenderer_nativeOnDrawFrame(JNIEnv *env, jobject thiz)
    {
        if (g_EglDisplay == EGL_NO_DISPLAY)
        {
            LOGD("g_EglDisplay is EGL_NO_DISPLAY");
            return;
        }

        ImGuiIO &io = ImGui::GetIO();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplAndroid_NewFrame();
        ImGui::NewFrame();

        if (show_demo_window)
            ImGui::ShowDemoWindow(&show_demo_window);

        ImGui::Begin("Hello, world!");
        ImGui::Text("This is some useful text.");
        ImGui::Checkbox("Demo Window", &show_demo_window);
        ImGui::End();

        ImGui::Render();
        glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
        glClearColor(clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        eglSwapBuffers(g_EglDisplay, g_EglSurface);
    }

    JNIEXPORT void JNICALL Java_me_maars_MyGLRenderer_nativeOnSurfaceChanged(JNIEnv *env, jobject thiz, jint width, jint height)
    {
        LOGD("nativeOnSurfaceChanged called with width=%d, height=%d", width, height);
    }

    JNIEXPORT void JNICALL Java_me_maars_MyGLSurfaceView_nativeSurfaceDestroyed(JNIEnv *env, jobject thiz)
    {
        LOGD("nativeSurfaceDestroyed called");

        if (g_EglDisplay != EGL_NO_DISPLAY)
        {
            eglMakeCurrent(g_EglDisplay, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
            if (g_EglContext != EGL_NO_CONTEXT)
            {
                eglDestroyContext(g_EglDisplay, g_EglContext);
            }
            if (g_EglSurface != EGL_NO_SURFACE)
            {
                eglDestroySurface(g_EglDisplay, g_EglSurface);
            }
            eglTerminate(g_EglDisplay);
        }

        g_EglDisplay = EGL_NO_DISPLAY;
        g_EglContext = EGL_NO_CONTEXT;
        g_EglSurface = EGL_NO_SURFACE;
        ImGui_ImplOpenGL3_Shutdown();
        ImGui_ImplAndroid_Shutdown();
        ImGui::DestroyContext();
    }

} // extern "C"
