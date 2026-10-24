/*
 * Machine-dependent JNI types for 64-bit Windows (same definitions as the JDK's include/win32/jni_md.h), so the
 * core can be cross-compiled for Windows next to the JDK's portable jni.h.
 */
#ifndef _JAVASOFT_JNI_MD_H_
#define _JAVASOFT_JNI_MD_H_

#define JNIEXPORT __declspec(dllexport)
#define JNIIMPORT __declspec(dllimport)
#define JNICALL __stdcall

typedef long jint;
typedef __int64 jlong;
typedef signed char jbyte;

#endif /* !_JAVASOFT_JNI_MD_H_ */
