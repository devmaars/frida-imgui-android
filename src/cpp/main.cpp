#include <jni.h>
#include <android/log.h>
#include <android/native_window_jni.h> // for ANativeWindow_fromSurface
#include "imgui.h"
#include "imgui_impl_android.h"
#include "imgui_impl_opengl3.h"

#define LOG_TAG "ImGuiWrapper"
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__))
#define LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__))
#define LOGWTF(...) ((void)__android_log_print(ANDROID_LOG_FATAL, LOG_TAG, __VA_ARGS__))

// JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved);

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    LOGD("Hello from JNI_OnLoad!");
    return JNI_VERSION_1_6;
}

extern "C"
{
    JNIEXPORT void JNICALL Java_com_example_myimguiapp_ImGuiWrapper_init(JNIEnv *env, jobject thiz, jobject surface)
    {
        ANativeWindow *window = ANativeWindow_fromSurface(env, surface);
        if (window == nullptr)
        {
            // Handle error
            return;
        }

        LOGD("Hello from ImGuiWrapper!");

        // Create an ImGui context
        // IMGUI_CHECKVERSION();
        // ImGui::CreateContext();

        // Set up Platform/Renderer bindings
        // ImGui_ImplAndroid_Init(window);
        // ImGui_ImplOpenGL3_Init("#version 300 es");
    }
}

// extern "C"
// {
//     JNIEXPORT void JNICALL Java_me_maars_RendererWrapper_init(JNIEnv *env, jobject thiz, jobject surface)
//     {
//         ANativeWindow *window = ANativeWindow_fromSurface(env, surface);
//         if (window == nullptr)
//         {
//             // Handle error
//             return;
//         }

//         // Create an ImGui context
//         IMGUI_CHECKVERSION();
//         ImGui::CreateContext();

//         // Set up Platform/Renderer bindings
//         ImGui_ImplAndroid_Init(window);
//         ImGui_ImplOpenGL3_Init("#version 300 es");
//     }

//     JNIEXPORT void JNICALL Java_me_maars_RendererWrapper_newFrame(JNIEnv *env, jobject thiz)
//     {
//         ImGui_ImplOpenGL3_NewFrame();
//         ImGui_ImplAndroid_NewFrame();
//         ImGui::NewFrame();

//         ImGui::ShowDemoWindow();
//     }

//     JNIEXPORT void JNICALL Java_me_maars_RendererWrapper_render(JNIEnv *env, jobject thiz)
//     {
//         ImGui::Render();
//         ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
//     }

//     JNIEXPORT void JNICALL Java_com_example_myimguiapp_ImGuiWrapper_shutdown(JNIEnv *env, jobject thiz)
//     {
//         ImGui_ImplOpenGL3_Shutdown();
//         ImGui_ImplAndroid_Shutdown();
//         ImGui::DestroyContext();
//     }
// }
