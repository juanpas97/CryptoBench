//
// Created by Juan Pérez de Algaba on 18/5/18.
//

#include <jni.h>

#include <android/log.h>
#include <stdio.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/aes.h>

#define HEAP_HINT NULL


static int devId = INVALID_DEVID;

#define BITS_TO_BYTES(b)                (b/8)
#define MIN_OAEP_PADDING                (2*BITS_TO_BYTES(160)+2)

#define RSA_LENGTH                      (BITS_TO_BYTES(2048))

#define RSA_OAEP_DECRYPTED_DATA_LENGTH  (RSA_LENGTH-MIN_OAEP_PADDING)
#define RSA_OAEP_ENCRYPTED_DATA_LENGTH  (RSA_LENGTH)

#define MD5_DIGEST_SIZE WC_MD5_DIGEST_SIZE

enum {
    WC_MD5             =  0,      /* hash type unique */
    WC_MD5_BLOCK_SIZE  = 64,
    WC_MD5_DIGEST_SIZE = 16,
    WC_MD5_PAD_SIZE    = 56
};

#define  LOG_TAG    "WolfCrypt"

#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG ,__VA_ARGS__)

#define IN_BUFFER_LENGTH                (RSA_OAEP_DECRYPTED_DATA_LENGTH)
#define PRIVATE_KEY_LENGTH              (1190)
#define PUBLIC_KEY_LENGTH               (294)

extern unsigned char private_key[PRIVATE_KEY_LENGTH];
extern unsigned char public_key[PUBLIC_KEY_LENGTH];

unsigned char in_buffer[IN_BUFFER_LENGTH];
unsigned char encrypted_buffer[RSA_LENGTH];
unsigned char decrypted_buffer[RSA_LENGTH];



JNIEXPORT jdoubleArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_DH(JNIEnv *env, jobject instance) {

    jdoubleArray result;
    result = (*env)->NewDoubleArray(env,3);
    jdouble fill[3];

    jdouble error[1];

    int ret;
    word32 bytes;
    word32 idx = 0, privSz, pubSz, privSz2, pubSz2, agreeSz, agreeSz2;
    byte tmp[1024];
    byte priv[256];
    byte pub[256];
    byte priv2[256];
    byte pub2[256];
    byte agree[256];
    byte agree2[256];
    DhKey key;
    DhKey key2;
    WC_RNG rng;


//Prime number from https://tools.ietf.org/html/rfc3526#section-2

    byte p[256] = {0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
                   0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
                   0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
                   0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
                   0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
                   0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
                   0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
                   0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
                   0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
                   0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
                   0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,0x10, 0x24,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    int psize = sizeof(p);
    LOGD("Size of p is + [%i]",psize);


    byte g[] = {0, 2};


    (void) idx;
    (void) tmp;
    (void) bytes;


    int retrng = wc_InitRng(&rng);
    if (retrng != 0) {
        LOGD("Error at RNG"); //init of rng failed!
        return error;
    }

    ret = wc_RNG_GenerateBlock(&rng, g, sizeof(g));
    if (ret != 0) {
        LOGD("Error generating block for key"); //generating block failed!
        return error;
    }

    int sizeofg = sizeof(g);

    LOGD("The size of g is + [%i]",sizeofg);

    ret = wc_InitDhKey_ex(&key, HEAP_HINT, devId);
    if (ret != 0) {
        LOGD("Error at InitDHKey 1");
        return error;
    }

    ret = wc_InitDhKey_ex(&key2, HEAP_HINT, devId);
    if (ret != 0) {
        LOGD("Error at InitDHKey 2");
        return error;
    }


    ret = wc_DhSetKey(&key, p, sizeof(p), g, sizeof(g));
    if (ret != 0) {
        LOGD("Error setting key 1");
        return error;
    }

    ret = wc_DhSetKey(&key2, p, sizeof(p), g, sizeof(g));
    if (ret != 0) {
        LOGD("Error setting key 2");
        return error;
    }

    ret = wc_InitRng_ex(&rng, HEAP_HINT, devId);
    if (ret != 0) {
        LOGD("Error initialising RNG");
        return error;
    }

    ret = wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz);
    if (ret != 0) {
        LOGD("Error generating 1st keypair");
        return error;
    }

    ret = wc_DhGenerateKeyPair(&key2, &rng, priv2, &privSz2, pub2, &pubSz2);
    if (ret != 0) {
        LOGD("Error generating 2nd keypair");
        return error;
    }

    clock_t begin = clock();
    ret = wc_DhAgree(&key, agree, &agreeSz, priv, privSz, pub2, pubSz2);
    clock_t end = clock();
    double time_spent_encryption = (double)(end - begin) / CLOCKS_PER_SEC;

    fill[1] = time_spent_encryption;
    if (ret != 0) {
        LOGD("Error agreeing");
        return error;
    } else {
        LOGD("Success at 1st agreeing");
    }

    ret = wc_DhAgree(&key2, agree2, &agreeSz2, priv2, privSz2, pub, pubSz);
    if(ret != 0){
        LOGD("Error at 2nd agreeing");
    } else{
        LOGD("Success at 2nd agreeing");
    }

    if (agreeSz != agreeSz2 || XMEMCMP(agree, agree2, agreeSz)) {
        LOGD("Error at 1st comparing");
    }

    LOGD("Diffie Hellman Finished");

    (*env)->SetDoubleArrayRegion(env,result, 0, 3, fill);

    return result;
}

JNIEXPORT jdoubleArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_AES(JNIEnv *env, jobject instance) {

    jdoubleArray result;
    result = (*env)->NewDoubleArray(env,3);
    jdouble fill[3];

    jdouble error[1];

    Aes enc;
    byte cipher[AES_BLOCK_SIZE];

    Aes dec;
    byte plain[AES_BLOCK_SIZE];

    int ret = 0;

    RNG  rng;

    int  szkey = 32;
    byte key[szkey];

    int  sziv = 16;
    byte iv[sziv];

    int szmsg = 16;
    byte msg[szmsg];

    int retrng = wc_InitRng(&rng);
    if (retrng != 0) {
        LOGD("Error at RNG"); //init of rng failed!
    }

    ret = wc_RNG_GenerateBlock(&rng, key, sizeof(key));
    if (ret != 0) {
        LOGD("Error generating block at key"); //generating block failed!
    }

    ret = wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
    if (ret != 0) {
        LOGD("Error generating block at iv"); //generating block failed!
    }

    ret = wc_RNG_GenerateBlock(&rng, msg, sizeof(msg));
    if (ret != 0) {
        LOGD("Error generating block at msg"); //generating block failed!
    }


    LOGD("Begin of key");

    for (int i = 0; i < 32 ; ++i) {
        LOGD("%x",key[i]);
    }

    LOGD("Begin of IV");

    for (int i = 0; i < 16 ; ++i) {
        LOGD("%x",iv[i]);
    }

    LOGD("Begin of msg");

    for (int i = 0; i < 16 ; ++i) {
        LOGD("%x",msg[i]);
    }

    if (wc_AesInit(&enc, HEAP_HINT, devId) != 0) {
        LOGD("Error in aes init enc");
        return error;
    }else{
        LOGD("No problem at init enc");
    }

    if (wc_AesInit(&dec, HEAP_HINT, devId) != 0){
        LOGD("Error in aes init dec");
        return error;
    }else{
        LOGD("No problem at init dec");
    }

    ret = wc_AesSetKey(&enc, key, (int) sizeof(key), iv, AES_ENCRYPTION);
    if (ret != 0){
        LOGD("Error in AesSetKey Enc");
    }else{
        LOGD("No problem at AesSetKey Enc");
    }

    ret = wc_AesSetKey(&dec, key, (int) sizeof(key), iv, AES_DECRYPTION);
    if (ret != 0){
        LOGD("Error in AesSetKey Dec");
    }   else{
        LOGD("No problem at AesSetKey Dec ");
    }

    clock_t begin = clock();
    ret = wc_AesCbcEncrypt(&enc, cipher, msg, (int) sizeof(msg));
    clock_t end = clock();
    double time_spent_encryption = (double)(end - begin) / CLOCKS_PER_SEC;

    fill[0] = time_spent_encryption;
    if (ret != 0){
        LOGD("Error encrypting");
    }else{
        LOGD("Encryption finished");
    }

    clock_t begin1 = clock();
    ret = wc_AesCbcDecrypt(&dec, plain, cipher, (int) sizeof(cipher));
    clock_t end1 = clock();

    double time_spent_decryption = (double)(end1 - begin1) / CLOCKS_PER_SEC;

    fill[1] = time_spent_decryption;
    if(ret != 0){
        LOGD("Error Decrypting");
    }else{
        LOGD("Decryption finished");
    }

    if (XMEMCMP(plain, msg, (int) sizeof(plain))) {
        LOGD("Error comparing XMEMCMP");
    }

    wc_AesFree(&enc);
    wc_AesFree(&dec);

    LOGD("Finished AES/CBC 256");

    (*env)->SetDoubleArrayRegion(env,result, 0, 3, fill);

    return result;

}

JNIEXPORT jdoubleArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_MD5(JNIEnv *env, jobject instance) {

    jdoubleArray result;
    result = (*env)->NewDoubleArray(env,3);
    jdouble fill[3];

    jdouble error[1];

    Md5 md5;
    byte *hash[MD5_DIGEST_SIZE];

    int ret;
    int final;

    int szdata= 32;
    byte data[szdata];
    word32 len = sizeof(data);
    ret = wc_InitMd5(&md5);

    RNG  rng;

    int rngint = wc_InitRng(&rng);
    if (rngint != 0) {
        LOGD("Failure Init"); //init of rng failed!
    }

    ret = wc_RNG_GenerateBlock(&rng, data,szdata);

    if (ret != 0) {
        LOGD("Failure GenerateByte"); //generating block failed!
    }

    int i = 0;
    for (int i = 0; i < 32; ++i) {
        LOGD("%x",data[i]);
    }


    printf("\n");

    if (ret != 0) {

        LOGD("wc_Initmd5 failed");

    } else {
        clock_t begin1 = clock();

        ret = wc_Md5Update(&md5, data, len);

        if (ret != 0) {

            /* Md5 Update Failure Case. */
            LOGD("Error in update");

        }

        final = wc_Md5Final(&md5, hash);
        if (final != 0) {

            /* Md5 Final Failure Case. */
            LOGD("Error in Md5Final");
        }

        clock_t end1 = clock();

        double time_spent_decryption = (double)(end1 - begin1) / CLOCKS_PER_SEC;

        fill[1] = time_spent_decryption;
        LOGD("Hash finished");
    }

    (*env)->SetDoubleArrayRegion(env,result, 0, 3, fill);

    return result;

}

JNIEXPORT jdoubleArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_RSA(JNIEnv *env, jobject instance) {

    jdoubleArray result;
    result = (*env)->NewDoubleArray(env,3);
    jdouble fill[3];

    RsaKey key;
    RNG rng1;
    word32 index;
    int ret;
    jdoubleArray error[1];
    int encrypted_len;
    int decrypted_len;


    // encrypt data.
    index = 0;
    ret = wc_InitRng(&rng1);
    if (ret != 0) { LOGD("Error at wc_InitRng: %i.", ret); return error[0]; }
    ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) { LOGD("Error at wc_InitRsaKey: %i.", ret); return error[0]; }
    ret = wc_RsaPublicKeyDecode((const byte*)public_key, &index, &key, PUBLIC_KEY_LENGTH);
    if (ret != 0) { LOGD("Error at wc_RsaPublicKeyDecode: %i.", ret); return error[0]; }
    clock_t begin = clock();
    ret = wc_RsaPublicEncrypt_ex((const byte *)in_buffer, IN_BUFFER_LENGTH, (byte*)encrypted_buffer, RSA_LENGTH, &key, &rng1, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
    clock_t end = clock();

    double time_spent_encryption = (double)(end - begin) / CLOCKS_PER_SEC;

    fill[0] = time_spent_encryption;
    if (ret < 0) { LOGD("Error at wc_RsaPublicEncrypt_ex: %i.", ret); return error[0]; }
    encrypted_len = ret;
    LOGD("%i",encrypted_len);

    LOGD("Finished encryption");

    // decrypt data.
    index = 0;
    ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) { LOGD("Error at wc_InitRsaKey: %i.", ret); return error[0]; }
    ret = wc_RsaPrivateKeyDecode((const byte*)private_key, &index, &key, PRIVATE_KEY_LENGTH);
    clock_t begin1 = clock();
    if (ret != 0) { LOGD("Error at wc_RsaPrivateKeyDecode: %i.", ret); return error[0]; }
    ret = wc_RsaPrivateDecrypt_ex((const byte *)encrypted_buffer, encrypted_len, (byte*)decrypted_buffer, RSA_LENGTH, &key, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
    clock_t end1 = clock();

    double time_spent_decryption = (double)(end1 - begin1) / CLOCKS_PER_SEC;

    fill[1] = time_spent_decryption;
    if (ret < 0) { LOGD("Error at wc_RsaPrivateDecrypt_ex: %i.", ret); return error[0]; }
    decrypted_len = ret;
    wc_FreeRsaKey(&key);

    // compare data.
    if (decrypted_len != IN_BUFFER_LENGTH) { LOGD("Decrypted length should be %i but it is %i.", IN_BUFFER_LENGTH, decrypted_len); return error[0]; }
    for (int i = 0; i < IN_BUFFER_LENGTH; i++)
    {
        if (decrypted_buffer[i] != in_buffer[i]) { LOGD("Byte at index %i should be %i but it is %i.", i, 0xFF & in_buffer[i], 0xFF & decrypted_buffer[i]); return error[0]; }
    }

    // got here means no error.
    LOGD("All went O.K.");

    (*env)->SetDoubleArrayRegion(env,result, 0, 3, fill);

    return result;
}