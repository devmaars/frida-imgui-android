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
#include <pthread.h>
#include <unistd.h>

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

static bool g_Initialized = false;

void draw();

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

        ImGuiIO &io = ImGui::GetIO();
        io.IniFilename = nullptr;

        // set imgui display size
        io.DisplaySize = ImVec2(ANativeWindow_getWidth(window), ANativeWindow_getHeight(window));
        glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);

        LOGD("ImGui version: %s", IMGUI_VERSION);
        LOGD("Display size: %f, %f", io.DisplaySize.x, io.DisplaySize.y);

        ImGui::StyleColorsDark();

        if (!ImGui_ImplAndroid_Init(window) || !ImGui_ImplOpenGL3_Init("#version 300 es"))
        {
            LOGE("ImGui_ImplAndroid_Init or ImGui_ImplOpenGL3_Init failed");
            return;
        }

        ImFontConfig font_cfg;
        font_cfg.SizePixels = 22.0f;
        io.Fonts->AddFontDefault(&font_cfg);
        ImGui::GetStyle().ScaleAllSizes(3.0f);

        LOGD("ImGui initialized successfully");

        g_Initialized = true;
    }

    // JNIEXPORT void JNICALL Java_me_maars_MyGLRenderer_nativeOnDrawFrame(JNIEnv *env, jobject thiz)
    // {
    //     LOGD("nativeOnDrawFrame called");

    //     if (g_EglDisplay == EGL_NO_DISPLAY)
    //     {
    //         LOGD("g_EglDisplay is EGL_NO_DISPLAY");
    //         return;
    //     }

    //     ImGuiIO &io = ImGui::GetIO();
    //     ImGui_ImplOpenGL3_NewFrame();
    //     ImGui_ImplAndroid_NewFrame();
    //     ImGui::NewFrame();

    //     if (show_demo_window)
    //         ImGui::ShowDemoWindow(&show_demo_window);

    //     ImGui::Begin("Hello, world!");
    //     ImGui::Text("This is some useful text.");
    //     ImGui::Checkbox("Demo Window", &show_demo_window);
    //     ImGui::End();

    //     ImGui::Render();
    //     glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
    //     glClearColor(clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w);
    //     glClear(GL_COLOR_BUFFER_BIT);
    //     ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    //     eglSwapBuffers(g_EglDisplay, g_EglSurface);
    // }

    JNIEXPORT void JNICALL Java_me_maars_MyGLRenderer_nativeOnSurfaceChanged(JNIEnv *env, jobject thiz, jint width, jint height)
    {
        LOGD("nativeOnSurfaceChanged called with width=%d, height=%d", width, height);

        if (g_EglDisplay == EGL_NO_DISPLAY)
        {
            LOGD("g_EglDisplay is EGL_NO_DISPLAY");
            return;
        }

        ImGuiIO &io = ImGui::GetIO();
        io.DisplaySize = ImVec2(width, height);
        glViewport(0, 0, width, height);
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

pthread_t mainLoopThread;
bool running = true;

void *mainLoop(void *arg)
{
    while (running)
    {
        LOGD("Main loop running...");
        draw();
        sleep(1);
    }
    return nullptr;
}

void draw()
{
    if (!g_Initialized)
    {
        LOGD("g_Initialized is false");
        return;
    }

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

    LOGD("Drawn frame");
}

extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved)
{
    LOGD("JNI_OnLoad called");

    JNIEnv *env;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK)
    {
        return -1;
    }

    LOGD("JNI_OnLoad: Got JNIEnv");

    pthread_create(&mainLoopThread, nullptr, mainLoop, nullptr);

    return JNI_VERSION_1_6;
}
