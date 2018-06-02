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
#include <wolfssl/wolfcrypt/ecc.h>

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

    byte p[256] = {0xAD,0x10,0x7E,0x1E,0x91,0x23,0xA9,0xD0,0xD6,0x60,0xFA,0xA7,0x95,0x59,0xC5,0x1F,0xA2,0x0D,0x64,0xE5,0x68,0x3B,0x9F,0xD1,
                   0xB5,0x4B,0x15,0x97,0xB6,0x1D,0x0A,0x75,0xE6,0xFA,0x14,0x1D,0xF9,0x5A,0x56,0xDB,0xAF,0x9A,0x3C,0x40,0x7B,0xA1,0xDF,0x15,
                   0xEB,0x3D,0x68,0x8A,0x30,0x9C,0x18,0x0E,0x1D,0xE6,0xB8,0x5A,0x12,0x74,0xA0,0xA6,0x6D,0x3F,0x81,0x52,0xAD,0x6A,0xC2,0x12,
                   0x90,0x37,0xC9,0xED,0xEF,0xDA,0x4D,0xF8,0xD9,0x1E,0x8F,0xEF,0x55,0xB7,0x39,0x4B,0x7A,0xD5,0xB7,0xD0,0xB6,0xC1,0x22,0x07,
                   0xC9,0xF9,0x8D,0x11,0xED,0x34,0xDB,0xF6,0xC6,0xBA,0x0B,0x2C,0x8B,0xBC,0x27,0xBE,0x6A,0x00,0xE0,0xA0,0xB9,0xC4,0x97,0x08,
                   0xB3,0xBF,0x8A,0x31,0x70,0x91,0x88,0x36,0x81,0x28,0x61,0x30,0xBC,0x89,0x85,0xDB,0x16,0x02,0xE7,0x14,0x41,0x5D,0x93,0x30,
                   0x27,0x82,0x73,0xC7,0xDE,0x31,0xEF,0xDC,0x73,0x10,0xF7,0x12,0x1F,0xD5,0xA0,0x74,0x15,0x98,0x7D,0x9A,0xDC,0x0A,0x48,0x6D,
                   0xCD,0xF9,0x3A,0xCC,0x44,0x32,0x83,0x87,0x31,0x5D,0x75,0xE1,0x98,0xC6,0x41,0xA4,0x80,0xCD,0x86,0xA1,0xB9,0xE5,0x87,0xE8,
                   0xBE,0x60,0xE6,0x9C,0xC9,0x28,0xB2,0xB9,0xC5,0x21,0x72,0xE4,0x13,0x04,0x2E,0x9B,0x23,0xF1,0x0B,0x0E,0x16,0xE7,0x97,0x63,
                   0xC9,0xB5,0x3D,0xCF,0x4B,0xA8,0x0A,0x29,0xE3,0xFB,0x73,0xC1,0x6B,0x8E,0x75,0xB9,0x7E,0xF3,0x63,0xE2,0xFF,0xA3,0x1F,0x71,
                   0xCF,0x9D,0xE5,0x38,0x4E,0x71,0xB8,0x1C,0x0A,0xC4,0xDF,0xFE,0x0C,0x10,0xE6,0x4F};

    int psize = sizeof(p);
    LOGD("Size of p is + [%i]",psize);


    byte g[] = {0XAC,0X40,0X32,0XEF,0X4F,0X2D,0X9A,0XE3,0X9D,0XF3,0X0B,0X5C,0X8F,0XFD,0XAC,0X50,0X6C,0XDE,0XBE,0X7B,0X89,0X99,0X8C,0XAF,
                0X74,0X86,0X6A,0X08,0XCF,0XE4,0XFF,0XE3,0XA6,0X82,0X4A,0X4E,0X10,0XB9,0XA6,0XF0,0XDD,0X92,0X1F,0X01,0XA7,0X0C,0X4A,0XFA,
                0XAB,0X73,0X9D,0X77,0X00,0XC2,0X9F,0X52,0XC5,0X7D,0XB1,0X7C,0X62,0X0A,0X86,0X52,0XBE,0X5E,0X90,0X01,0XA8,0XD6,0X6A,0XD7,
                0XC1,0X76,0X69,0X10,0X19,0X99,0X02,0X4A,0XF4,0XD0,0X27,0X27,0X5A,0xC1,0x34,0x8B,0xB8,0xA7,0x62,0xD0,0x52,0x1B,0xC9,0x8A,
                0xE2,0x47,0x15,0x04,0x22,0xEA,0x1E,0xD4,0x09,0x93,0x9D,0x54,0xDA,0x74,0x60,0xCD,0xB5,0xF6,0xC6,0xB2,0x50,0x71,0x7C,0xBE,
                0xF1,0x80,0xEB,0x34,0x11,0x8E,0x98,0xD1,0x19,0x52,0x9A,0x45,0xD6,0xF8,0x34,0x56,0x6E,0x30,0x25,0xE3,0x16,0xA3,0x30,0xEF,
                0xBB,0x77,0xA8,0x6F,0x0C,0x1A,0xB1,0x5B,0x05,0x1A,0xE3,0xD4,0x28,0xC8,0xF8,0xAC,0xB7,0x0A,0x81,0x37,0x15,0x0B,0x8E,0xEB,
                0x10,0xE1,0x83,0xED,0xD1,0x99,0x63,0xDD,0xD9,0xE2,0x63,0xE4,0x77,0x05,0x89,0xEF,0x6A,0xA2,0x1E,0x7F,0x5F,0x2F,0xF3,0x81,
                0xB5,0x39,0xCC,0xE3,0x40,0x9D,0x13,0xCD,0x56,0x6A,0xFB,0xB4,0x8D,0x6C,0x01,0x91,0x81,0xE1,0xBC,0xFE,0x94,0xB3,0x02,0x69,
                0xED,0xFE,0x72,0xFE,0x9B,0x6A,0xA4,0xBD,0x7B,0x5A,0x0F,0x1C,0x71,0xCF,0xFF,0x4C,0x19,0xC4,0x18,0xE1,0xF6,0xEC,0x01,0x79,
                0x81,0xBC,0x08,0x7F,0x2A,0x70,0x65,0xB3,0x84,0xB8,0x90,0xD3,0x19,0x1F,0x2B,0xFA};


    (void) idx;
    (void) tmp;
    (void) bytes;


    /*int retrng = wc_InitRng(&rng);
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
*/
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

JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_AESCBC(JNIEnv *env, jobject instance) {

    jintArray result;
    result = (*env)->NewIntArray(env,3);
    jint fill[3];

    jint error[1];

    struct timeval st,et;

    Aes enc;
    byte cipher[AES_BLOCK_SIZE];

    Aes dec;
    byte plain[AES_BLOCK_SIZE];

    int ret = 0;

    RNG  rng;

    int  szkey = 16;
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

    for (int i = 0; i < 16 ; ++i) {
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
        return 0;
    }else{
        LOGD("No problem at init enc");
    }

    if (wc_AesInit(&dec, HEAP_HINT, devId) != 0){
        LOGD("Error in aes init dec");
        return 0;
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

    gettimeofday(&st,NULL);
    ret = wc_AesCbcEncrypt(&enc, cipher, msg, (int) sizeof(msg));
    gettimeofday(&et,NULL);
    int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[0] = encryption_time;

    if (ret != 0){
        LOGD("Error encrypting");
    }else{
        LOGD("Encryption finished");
    }

    gettimeofday(&st,NULL);
    ret = wc_AesCbcDecrypt(&dec, plain, cipher, (int) sizeof(cipher));
    gettimeofday(&et,NULL);

    int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[1] = decryption_time;

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

    (*env)->SetIntArrayRegion(env,result, 0, 3, fill);

    return result;

}

JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_AESCTR(JNIEnv *env, jobject instance) {

    jintArray result;
    result = (*env)->NewIntArray(env,3);
    jint fill[3];

    jdouble error[1];

    Aes enc;
    byte cipher[AES_BLOCK_SIZE];

    Aes dec;
    byte plain[AES_BLOCK_SIZE];

    int ret = 0;

    struct timeval st, et;

    RNG  rng;

    int  szkey = 16;
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

    for (int i = 0; i < 16 ; ++i) {
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


    gettimeofday(&st,NULL);
    wc_AesCtrEncrypt(&enc, cipher, msg, (int) sizeof(msg));
    gettimeofday(&et,NULL);
    int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[0] = encryption_time;

    gettimeofday(&st,NULL);
    wc_AesCtrEncrypt(&dec, plain, cipher, (int) sizeof(cipher));
    gettimeofday(&et,NULL);

    int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[1] = decryption_time;


    if (XMEMCMP(plain, msg, (int) sizeof(plain))) {
        LOGD("Error comparing XMEMCMP");
    }

    wc_AesFree(&enc);
    wc_AesFree(&dec);

    LOGD("Finished AES/CTR");

    (*env)->SetIntArrayRegion(env,result, 0, 3, fill);

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

JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_AESGCM(JNIEnv *env, jobject instance) {

    LOGD("Starting AESGCM");
    jintArray result;
    result = (*env)->NewIntArray(env,3);
    jint fill[3];

    byte large_output[1024];

    jint error[1];

    struct timeval st,et;

    Aes enc;
    byte cipher[AES_BLOCK_SIZE];

    Aes dec;
    byte plain[AES_BLOCK_SIZE];

    int ret = 0;

    RNG  rng;

    int  szkey = 16;
    byte key[szkey];

    int  sziv = 16;
    byte iv[sziv];

    int szmsg = 16;
    byte msg[szmsg];

    const byte p[] =
            {
                    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
                    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
                    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
                    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
                    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
                    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
                    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
                    0xba, 0x63, 0x7b, 0x39
            };

    byte resultP[sizeof(p)];

    const byte t1[] =
            {
                    0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
                    0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b
            };

    byte resultT[sizeof(t1)];

    const byte a[] =
            {
                    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                    0xab, 0xad, 0xda, 0xd2
            };

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

    for (int i = 0; i < 16 ; ++i) {
        LOGD("%x",key[i]);
    }

    LOGD("Begin of IV");

    for (int i = 0; i < 16 ; ++i) {
        LOGD("%x",iv[i]);
    }

    XMEMSET(resultP, 0, sizeof(resultP));

    if (wc_AesInit(&enc, HEAP_HINT, devId) != 0) {
        LOGD("Error in aes init enc");
        return 0;
    }else{
        LOGD("No problem at init enc");
    }

    if (wc_AesInit(&dec, HEAP_HINT, devId) != 0){
        LOGD("Error in aes init dec");
        return 0;
    }else{
        LOGD("No problem at init dec");
    }

    ret = wc_AesGcmSetKey(&enc, key, (int) sizeof(key));
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

    gettimeofday(&st,NULL);
    ret = wc_AesGcmEncrypt(&enc, cipher, msg, (int) sizeof(msg),iv, sizeof(iv),resultT, sizeof(resultT),a,
                           sizeof(a));
    gettimeofday(&et,NULL);
    int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[0] = encryption_time;

    if (ret != 0){
        LOGD("Error encrypting");
    }else{
        LOGD("Encryption finished");
    }

    gettimeofday(&st,NULL);
    ret = wc_AesGcmDecrypt(&enc, resultP, cipher, (int) sizeof(cipher),iv, sizeof(iv),resultT, sizeof(resultT),a,
                           sizeof(a));
    gettimeofday(&et,NULL);

    int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[1] = decryption_time;

    if(ret != 0){
        LOGD("Error Decrypting");
    }else{
        LOGD("Decryption finished");
    }

    wc_AesFree(&enc);
    wc_AesFree(&dec);

    LOGD("Finished AES/GCM");

    (*env)->SetIntArrayRegion(env,result, 0, 3, fill);

    return result;

}
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_ECDH(JNIEnv *env, jobject instance) {

    LOGD("Starting ECDH");
    jintArray result;
    result = (*env)->NewIntArray(env,3);
    jint fill[3];
    jintArray error[3];

    int ret;

    byte secret[1024];
    word32 secretsize = sizeof(secret);
    struct timeval st,et;
    

    ecc_key priv;
    ecc_key pub;
    WC_RNG rng_pub,rng_priv;

    ret = wc_InitRng_ex(&rng_priv, HEAP_HINT, devId);
    if (ret != 0) {
        LOGD("Error initialising RNG");

    }

    ret=wc_ecc_init(&priv);
    if(ret != 0){
        LOGD("Error at init");
    }

    ret = wc_ecc_make_key_ex(&rng_priv,32,&priv,ECC_SECP256R1);

    if(ret != 0){
        LOGD("Error making key");
        LOGD("Error is : %i", ret);
    }

    ret = wc_InitRng_ex(&rng_pub, HEAP_HINT, devId);
    if (ret != 0) {
        LOGD("Error initialising RNG");

    }

    ret=wc_ecc_init(&pub);
    if(ret != 0){
        LOGD("Error at init");
    }

    ret = wc_ecc_make_key_ex(&rng_pub,32,&pub,ECC_SECP256R1);

    if(ret != 0){
        LOGD("Error making key");
        LOGD("Error is : %i", ret);
    }

    gettimeofday(&st,NULL);
    ret = wc_ecc_shared_secret(&priv, &pub, secret, &secretsize);

    gettimeofday(&et,NULL);

    int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[1] = decryption_time;

    if(ret != 0){
        LOGD("Error sharing secret");
        LOGD("Error is : %i", ret);
    }

    LOGD("We are good");

    (*env)->SetIntArrayRegion(env,result, 0, 3, fill);

    return result;

}