#include <jni.h>
#include <android/log.h>
#include "imgui.h"
#include "imgui_impl_android.h"
#include "imgui_impl_opengl3.h"
#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <android/native_window.h>
#include <android/native_window_jni.h>

#define LOG_TAG "ImGuiWrapper"
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__))
#define LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__))

static bool g_Initialized = false;
static bool show_demo_window = true;
static bool show_another_window = false;
static ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

extern "C" void beginFrame();
extern "C" void renderFrame();
extern "C" void endFrame();

extern "C"
{
    JNIEXPORT void JNICALL Java_me_maars_MyGLSurfaceView_nativeOnDrawFrame(JNIEnv *env, jclass clazz)
    {
        LOGD("nativeOnDrawFrame");

        if (!g_Initialized)
            return;

        beginFrame();
        renderFrame();
        endFrame();
    }

    JNIEXPORT void JNICALL Java_me_maars_MyGLSurfaceView_nativeOnSurfaceChanged(JNIEnv *env, jclass clazz, jint width, jint height)
    {
        LOGD("nativeOnSurfaceChanged");

        if (!g_Initialized)
            return;

        ImGuiIO &io = ImGui::GetIO();
        io.DisplaySize = ImVec2((float)width, (float)height);
    }

    JNIEXPORT void JNICALL Java_me_maars_MyGLSurfaceView_nativeOnSurfaceCreated(JNIEnv *env, jclass clazz, jobject surface)
    {
        LOGD("nativeOnSurfaceCreated");

        if (g_Initialized)
            return;

        ANativeWindow *window = ANativeWindow_fromSurface(env, surface);
        if (!window)
        {
            LOGE("ANativeWindow_fromSurface failed");
            return;
        }

        // Setup Dear ImGui context
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO &io = ImGui::GetIO();

        // Setup Dear ImGui style
        ImGui::StyleColorsDark();
        // ImGui::StyleColorsLight();

        // Setup Platform/Renderer backends
        ImGui_ImplAndroid_Init(window);
        ImGui_ImplOpenGL3_Init("#version 300 es");

        ImFontConfig font_cfg;
        font_cfg.SizePixels = 22.0f;
        io.Fonts->AddFontDefault(&font_cfg);

        // Arbitrary scale-up
        // FIXME: Put some effort into DPI awareness
        ImGui::GetStyle().ScaleAllSizes(3.0f);
        io.FontGlobalScale = 1.2f;

        g_Initialized = true;

        LOGD("setup done");
    }

    JNIEXPORT jboolean JNICALL Java_me_maars_MyGLSurfaceView_handleTouch(JNIEnv *env, jclass clazz, jfloat x, jfloat y, jint action)
    {
        LOGD("handleTouch");

        if (!g_Initialized)
            return false;

        ImGuiIO &io = ImGui::GetIO();

        switch (action)
        {
        case 0: // ACTION_DOWN
            io.AddMousePosEvent(x, y);
            io.AddMouseButtonEvent(0, true);
            break;
        case 1: // ACTION_UP
            io.AddMouseButtonEvent(0, false);
            io.AddMousePosEvent(-1, -1);
            break;
        case 2: // ACTION_MOVE
            io.AddMousePosEvent(x, y);
            break;
        default:
            return false;
            break;
        }

        return io.WantCaptureMouse ? true : false;
    }

} // extern "C"

void beginFrame()
{
    ImGuiIO &io = ImGui::GetIO();

    LOGD("Start rendering...");
    LOGD("DisplaySize: %f, %f", io.DisplaySize.x, io.DisplaySize.y);

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplAndroid_NewFrame();
    ImGui::NewFrame();
}

void endFrame()
{
    ImGuiIO &io = ImGui::GetIO();

    ImGui::Render();
    glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
}

/*
    * ImGui rendering
     Render frame is meant to be hooked from frida
     So that we can can render ImGui frame from frida
     By default, it will render a simple demo frame
 */
void renderFrame()
{
    LOGD("renderFrame");

    // 1. Show the big demo window (Most of the sample code is in ImGui::ShowDemoWindow()! You can browse its code to learn more about Dear ImGui!).
    if (show_demo_window)
        ImGui::ShowDemoWindow(&show_demo_window);

    // 2. Show a simple window that we create ourselves. We use a Begin/End pair to create a named window.
    {
        static float f = 0.0f;
        static int counter = 0;

        ImGuiIO &io = ImGui::GetIO();

        ImGui::Begin("Hello, world!"); // Create a window called "Hello, world!" and append into it.

        ImGui::Text(
            "This is some useful text."); // Display some text (you can use a format strings too)
        ImGui::Checkbox("Demo Window",
                        &show_demo_window); // Edit bools storing our window open/close state
        ImGui::Checkbox("Another Window", &show_another_window);

        ImGui::SliderFloat("float", &f, 0.0f,
                           1.0f); // Edit 1 float using a slider from 0.0f to 1.0f
        ImGui::ColorEdit3("clear color",
                          (float *)&clear_color); // Edit 3 floats representing a color

        if (ImGui::Button(
                "Button")) // Buttons return true when clicked (most widgets return true when edited/activated)
            counter++;
        ImGui::SameLine();
        ImGui::Text("counter = %d", counter);

        ImGui::Text("Application average %.3f ms/frame (%.1f FPS)", 1000.0f / io.Framerate,
                    io.Framerate);
        ImGui::End();
    }

    // 3. Show another simple window.
    if (show_another_window)
    {
        ImGui::Begin("Another Window",
                     &show_another_window); // Pass a pointer to our bool variable (the window will have a closing button that will clear the bool when clicked)
        ImGui::Text("Hello from another window!");
        if (ImGui::Button("Close Me"))
            show_another_window = false;
        ImGui::End();
    }
}