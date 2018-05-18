//
// Created by Juan Pérez de Algaba on 18/5/18.
//

#include <jni.h>

#ifndef CRYPTOBENCH_WOLFCRYPT_H
#define CRYPTOBENCH_WOLFCRYPT_H

#endif //CRYPTOBENCH_WOLFCRYPT_H


JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_DH(JNIEnv *env, jobject instance);


JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_MD5(JNIEnv *env, jobject instance);

JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_AES(JNIEnv *env, jobject instance);