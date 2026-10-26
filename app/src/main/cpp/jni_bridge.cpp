// JNI glue for app.lanbridge.core.Native. All text crosses the boundary as UTF-8 byte arrays.
#include <jni.h>

#include <cstdint>
#include <string>
#include <vector>

#include "engine.h"
#include "ipv6.h"
#include "util.h"

namespace {

lb::Engine& engine() {
    static lb::Engine* e = [] {
        lb::Engine* x = new lb::Engine();  // lives for the whole process
#ifdef _WIN32
        // A Windows PC does not take part in the mirroring of real addresses (see Offer::noMirror).
        lb::Config c;
        c.mirrorReal = false;
        x->setConfig(c);
#endif
        return x;
    }();
    return *e;
}

std::string toStr(JNIEnv* env, jbyteArray a) {
    if (!a) return std::string();
    jsize n = env->GetArrayLength(a);
    std::string s((size_t)n, '\0');
    if (n > 0) env->GetByteArrayRegion(a, 0, n, reinterpret_cast<jbyte*>(&s[0]));
    return s;
}

std::vector<uint8_t> toVec(JNIEnv* env, jbyteArray a) {
    std::vector<uint8_t> v;
    if (!a) return v;
    jsize n = env->GetArrayLength(a);
    v.resize((size_t)n);
    if (n > 0) env->GetByteArrayRegion(a, 0, n, reinterpret_cast<jbyte*>(v.data()));
    return v;
}

jbyteArray fromBytes(JNIEnv* env, const uint8_t* p, size_t n) {
    jbyteArray a = env->NewByteArray((jsize)n);
    if (a && n > 0) env->SetByteArrayRegion(a, 0, (jsize)n, reinterpret_cast<const jbyte*>(p));
    return a;
}

jbyteArray fromStr(JNIEnv* env, const std::string& s) {
    return fromBytes(env, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

}  // namespace

extern "C" {

JNIEXPORT jbyteArray JNICALL Java_app_lanbridge_core_Native_prepare(JNIEnv* env, jobject, jbyteArray stun,
                                                                   jbyteArray localIps, jbyteArray name, jint ttlSec) {
    try {
        std::vector<uint8_t> offer;
        int rc = engine().prepare(lb::splitList(toStr(env, stun)), lb::splitList(toStr(env, localIps)), toStr(env, name),
                                  (int)ttlSec, offer);
        if (rc != 0) return nullptr;
        return fromBytes(env, offer.data(), offer.size());
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_app_lanbridge_core_Native_describeOffer(JNIEnv* env, jobject, jbyteArray blob) {
    try {
        std::string text;
        engine().describe(toVec(env, blob), text);
        return fromStr(env, text);
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jint JNICALL Java_app_lanbridge_core_Native_setPeer(JNIEnv* env, jobject, jbyteArray blob) {
    try {
        return (jint)engine().setPeer(toVec(env, blob));
    } catch (...) {
        return -1;
    }
}

JNIEXPORT jbyteArray JNICALL Java_app_lanbridge_core_Native_netLayout(JNIEnv* env, jobject) {
    try {
        std::string t = engine().netLayout();
        if (t.empty()) return nullptr;
        return fromStr(env, t);
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_app_lanbridge_core_Native_prepareGroup(JNIEnv* env, jobject, jbyteArray stun,
                                                                        jbyteArray localIps, jbyteArray name, jint ttlSec) {
    try {
        std::vector<uint8_t> code;
        int rc = engine().prepareGroup(lb::splitList(toStr(env, stun)), lb::splitList(toStr(env, localIps)),
                                       toStr(env, name), (int)ttlSec, code);
        if (rc != 0) return nullptr;
        return fromBytes(env, code.data(), code.size());
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_app_lanbridge_core_Native_renewGroup(JNIEnv* env, jobject, jint ttlSec) {
    try {
        std::vector<uint8_t> code;
        if (engine().renewGroup((int)ttlSec, code) != 0) return nullptr;
        return fromBytes(env, code.data(), code.size());
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jint JNICALL Java_app_lanbridge_core_Native_joinGroup(JNIEnv* env, jobject, jbyteArray blob) {
    try {
        return (jint)engine().joinGroup(toVec(env, blob));
    } catch (...) {
        return -1;
    }
}

JNIEXPORT jint JNICALL Java_app_lanbridge_core_Native_swapTun(JNIEnv*, jobject, jint fd) {
    try {
        return (jint)engine().swapTun((int)fd);
    } catch (...) {
        return -1;
    }
}

JNIEXPORT jboolean JNICALL Java_app_lanbridge_core_Native_setProfile(JNIEnv* env, jobject, jbyteArray name,
                                                                    jbyteArray avatar) {
    try {
        return engine().setProfile(toStr(env, name), toVec(env, avatar)) ? JNI_TRUE : JNI_FALSE;
    } catch (...) {
        return JNI_FALSE;
    }
}

JNIEXPORT jbyteArray JNICALL Java_app_lanbridge_core_Native_members(JNIEnv* env, jobject) {
    try {
        return fromStr(env, engine().members());
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_app_lanbridge_core_Native_memberAvatar(JNIEnv* env, jobject, jint slot) {
    try {
        std::vector<uint8_t> a;
        if (!engine().memberAvatar((int)slot, a)) return nullptr;
        return fromBytes(env, a.data(), a.size());
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_app_lanbridge_core_Native_hintTopic(JNIEnv* env, jobject) {
    try {
        return fromStr(env, engine().hintTopic());
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_app_lanbridge_core_Native_sealHint(JNIEnv* env, jobject) {
    try {
        std::vector<uint8_t> n;
        if (!engine().sealHint(n)) return nullptr;
        return fromBytes(env, n.data(), n.size());
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jint JNICALL Java_app_lanbridge_core_Native_openHint(JNIEnv* env, jobject, jbyteArray note) {
    try {
        return (jint)engine().openHint(toVec(env, note));
    } catch (...) {
        return -1;
    }
}

JNIEXPORT jint JNICALL Java_app_lanbridge_core_Native_start(JNIEnv*, jobject, jint tunFd, jint mtu) {
    try {
        return (jint)engine().start((int)tunFd, (int)mtu);
    } catch (...) {
        return -1;
    }
}

JNIEXPORT void JNICALL Java_app_lanbridge_core_Native_retry(JNIEnv*, jobject) {
    try {
        engine().retry();
    } catch (...) {
    }
}

JNIEXPORT void JNICALL Java_app_lanbridge_core_Native_stop(JNIEnv*, jobject) {
    try {
        engine().stop();
    } catch (...) {
    }
}

JNIEXPORT jlongArray JNICALL Java_app_lanbridge_core_Native_status(JNIEnv* env, jobject) {
    jlongArray arr = env->NewLongArray(lb::STATUS_FIELDS);
    if (!arr) return nullptr;
    try {
        int64_t st[lb::STATUS_FIELDS];
        engine().status(st);
        jlong tmp[lb::STATUS_FIELDS];
        for (int i = 0; i < lb::STATUS_FIELDS; i++) tmp[i] = (jlong)st[i];
        env->SetLongArrayRegion(arr, 0, lb::STATUS_FIELDS, tmp);
    } catch (...) {
    }
    return arr;
}

JNIEXPORT jbyteArray JNICALL Java_app_lanbridge_core_Native_info(JNIEnv* env, jobject) {
    try {
        return fromStr(env, engine().info());
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_app_lanbridge_core_Native_flows(JNIEnv* env, jobject) {
    try {
        return fromStr(env, engine().flows());
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT void JNICALL Java_app_lanbridge_core_Native_resetFlows(JNIEnv*, jobject) {
    try {
        engine().resetFlows();
    } catch (...) {
    }
}

JNIEXPORT jbyteArray JNICALL Java_app_lanbridge_core_Native_lastError(JNIEnv* env, jobject) {
    try {
        return fromStr(env, engine().lastError());
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL Java_app_lanbridge_core_Native_log(JNIEnv* env, jobject) {
    try {
        return fromStr(env, lb::logDump());
    } catch (...) {
        return nullptr;
    }
}

JNIEXPORT void JNICALL Java_app_lanbridge_core_Native_logLine(JNIEnv* env, jobject, jbyteArray msg) {
    try {
        lb::logWrite(lb::sanitize(toStr(env, msg), 400));
    } catch (...) {
    }
}

JNIEXPORT jint JNICALL Java_app_lanbridge_core_Native_socketFd(JNIEnv*, jobject) {
    try {
        return (jint)engine().socketFd();
    } catch (...) {
        return -1;
    }
}

JNIEXPORT jint JNICALL Java_app_lanbridge_core_Native_socketFd6(JNIEnv*, jobject) {
    try {
        return (jint)engine().socketFd6();
    } catch (...) {
        return -1;
    }
}

}  // extern "C"
