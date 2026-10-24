// JNI side of the Windows adapter: class app.lanbridge.core.WinTun (desktop build only).
#include <jni.h>

#include <cstdio>
#include <mutex>
#include <string>

#include "util.h"
#include "wintun_win.h"

namespace {

std::mutex g_errMu;
std::string g_err;

void setErr(const std::string& e) {
    std::lock_guard<std::mutex> g(g_errMu);
    g_err = e;
}

std::wstring jw(JNIEnv* env, jstring s) {
    if (!s) return std::wstring();
    const jchar* c = env->GetStringChars(s, nullptr);
    jsize n = env->GetStringLength(s);
    std::wstring w((const wchar_t*)c, (size_t)n);
    env->ReleaseStringChars(s, c);
    return w;
}

std::string ju(JNIEnv* env, jstring s) { return lb::wintun::toUtf8(jw(env, s)); }

jstring mk(JNIEnv* env, const std::string& utf8) {
    std::wstring w = lb::wintun::fromUtf8(utf8);
    return env->NewString((const jchar*)w.data(), (jsize)w.size());
}

// "{7A1B8E3C-5D44-4F0B-9C21-6E0A5B7D2F11}" (braces optional)
bool parseGuid(const std::string& t, GUID& g) {
    unsigned d1, d2, d3, b[8];
    const char* s = t.c_str();
    if (*s == '{') s++;
    if (sscanf(s, "%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x", &d1, &d2, &d3, &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6],
               &b[7]) != 11)
        return false;
    g.Data1 = d1;
    g.Data2 = (unsigned short)d2;
    g.Data3 = (unsigned short)d3;
    for (int i = 0; i < 8; i++) g.Data4[i] = (unsigned char)b[i];
    return true;
}

}  // namespace

extern "C" {

JNIEXPORT jstring JNICALL Java_app_lanbridge_core_WinTun_load(JNIEnv* env, jobject, jstring path) {
    std::string e = lb::wintun::load(jw(env, path));
    if (!e.empty()) setErr(e);
    return mk(env, e);
}

JNIEXPORT jint JNICALL Java_app_lanbridge_core_WinTun_open(JNIEnv* env, jobject, jstring name, jstring guid) {
    GUID g;
    if (!parseGuid(ju(env, guid), g)) {
        setErr("неверный GUID адаптера");
        return -1;
    }
    std::string err;
    int fd = lb::wintun::open(jw(env, name), g, err);
    if (fd < 0) setErr(err);
    return (jint)fd;
}

JNIEXPORT jint JNICALL Java_app_lanbridge_core_WinTun_swapPair(JNIEnv*, jobject) {
    std::string err;
    int fd = lb::wintun::swapPair(err);
    if (fd < 0) setErr(err);
    return (jint)fd;
}

JNIEXPORT jstring JNICALL Java_app_lanbridge_core_WinTun_configure(JNIEnv* env, jobject, jstring ip4, jint prefix4,
                                                                   jstring ip6, jint prefix6, jint mtu, jint metric) {
    lb::wintun::IpConfig c;
    c.ip4 = ju(env, ip4);
    c.prefix4 = (int)prefix4;
    c.ip6 = ju(env, ip6);
    c.prefix6 = (int)prefix6;
    c.mtu = (int)mtu;
    c.metric = (int)metric;
    return mk(env, lb::wintun::configure(c));
}

JNIEXPORT void JNICALL Java_app_lanbridge_core_WinTun_close(JNIEnv*, jobject) { lb::wintun::close(); }

JNIEXPORT jstring JNICALL Java_app_lanbridge_core_WinTun_error(JNIEnv* env, jobject) {
    std::lock_guard<std::mutex> g(g_errMu);
    return mk(env, g_err);
}

JNIEXPORT jstring JNICALL Java_app_lanbridge_core_WinTun_stats(JNIEnv* env, jobject) {
    return mk(env, lb::wintun::stats());
}

JNIEXPORT jboolean JNICALL Java_app_lanbridge_core_WinTun_isElevated(JNIEnv*, jobject) {
    return lb::wintun::isElevated() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_app_lanbridge_core_WinTun_relaunchElevated(JNIEnv* env, jobject, jstring exe, jstring args) {
    return lb::wintun::relaunchElevated(jw(env, exe), jw(env, args)) ? JNI_TRUE : JNI_FALSE;
}

// "<exit code>\n<output>"
JNIEXPORT jstring JNICALL Java_app_lanbridge_core_WinTun_run(JNIEnv* env, jobject, jstring cmd, jint timeoutMs) {
    std::string out;
    int code = lb::wintun::runHidden(jw(env, cmd), (int)timeoutMs, out);
    return mk(env, std::to_string(code) + "\n" + out);
}

JNIEXPORT void JNICALL Java_app_lanbridge_core_WinTun_keepAwake(JNIEnv*, jobject, jboolean on) {
    lb::wintun::keepAwake(on == JNI_TRUE);
}

}  // extern "C"
