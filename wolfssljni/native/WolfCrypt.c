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
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>

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
#define PRIVATE_KEY_LENGTH              (2048)
#define PUBLIC_KEY_LENGTH               (294)

 unsigned char private_key[PRIVATE_KEY_LENGTH];
 unsigned char public_key[PUBLIC_KEY_LENGTH];


unsigned char in_buffer[IN_BUFFER_LENGTH];
unsigned char encrypted_buffer[RSA_LENGTH];
unsigned char decrypted_buffer[RSA_LENGTH];

FILE *create_file()
{
    FILE *report = NULL;
    report = fopen("/sdcard/CryptoBench/Special_test.txt", "ab+");
    if (report) {
        LOGD("Report created");
        return report;
    }
    return NULL; // error
}

JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_DH(JNIEnv *env, jobject instance,jint rep_agree) {

    jintArray result;
    result = (*env)->NewIntArray(env,rep_agree);
    jint fill[rep_agree];

    jint error[1];

    struct timeval st,et;

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

    for(int i = 0; i < rep_agree; i++) {
        gettimeofday(&st, NULL);
        ret = wc_DhAgree(&key, agree, &agreeSz, priv, privSz, pub2, pubSz2);
        gettimeofday(&et, NULL);
        int key_agreement = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[i] = key_agreement;
        if (ret != 0) {
            LOGD("Error agreeing");
            return error;
        } else {
            LOGD("Success at 1st agreeing");
        }
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

    (*env)->SetIntArrayRegion(env,result, 0, rep_agree, fill);

    return result;
}

JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_AESCBC(JNIEnv *env, jobject instance, jint blocksize,jint rep_aes) {

    int len_array = rep_aes * 2;
    jintArray result;
    result = (*env)->NewIntArray(env,len_array);
    jint fill[len_array];

    struct timeval st,et;

    Aes enc;
    byte cipher[blocksize];

    Aes dec;
    byte plain[blocksize];

    int ret = 0;

    RNG  rng;

    unsigned char key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    int szmsg = blocksize;

    LOGD("Size of blocksize: %i",szmsg);

    byte msg[szmsg];

    int retrng = wc_InitRng(&rng);
    if (retrng != 0) {
        LOGD("Error at RNG"); //init of rng failed!
    }


    ret = wc_RNG_GenerateBlock(&rng, msg, sizeof(msg));
    if (ret != 0) {
        LOGD("Error generating block at msg"); //generating block failed!
    }


/*    LOGD("Begin of key");

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
    }*/

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

    int index_array = 0;
    for(int i = 0; i < rep_aes; i++) {
        gettimeofday(&st, NULL);
        ret = wc_AesCbcEncrypt(&enc, cipher, msg, (int) sizeof(msg));
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_array] = encryption_time;

        if (ret != 0) {
            LOGD("Error encrypting");
        } else {
            LOGD("Encryption finished");
        }

        gettimeofday(&st, NULL);
        ret = wc_AesCbcDecrypt(&dec, plain, cipher, (int) sizeof(cipher));
        gettimeofday(&et, NULL);

        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_array + 1] = decryption_time;

        if (ret != 0) {
            LOGD("Error Decrypting");
        } else {
            LOGD("Decryption finished");
        }

        index_array += 2;
    }
    wc_AesFree(&enc);
    wc_AesFree(&dec);

    LOGD("Finished AES/CBC 128");

    (*env)->SetIntArrayRegion(env,result, 0, len_array, fill);

    return result;

}

JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_AESCTR(JNIEnv *env, jobject instance,jint blocksize,jint rep_aes) {

    int len_array = rep_aes * 2;
    jintArray result;
    result = (*env)->NewIntArray(env,len_array);
    jint fill[len_array];

    jdouble error[1];

    Aes enc;
    byte cipher[blocksize];

    Aes dec;
    byte plain[blocksize];

    int ret = 0;

    struct timeval st, et;

    RNG  rng;


    unsigned char key[16] = {
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
                0x15, 0x88,
                0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    int szmsg = blocksize;
    byte msg[szmsg];

    int retrng = wc_InitRng(&rng);
    if (retrng != 0) {
        LOGD("Error at RNG"); //init of rng failed!
    }

    ret = wc_RNG_GenerateBlock(&rng, msg, sizeof(msg));
    if (ret != 0) {
        LOGD("Error generating block at msg"); //generating block failed!
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

    int index_array = 0;
    for(int i = 0; i < rep_aes;i++) {

        gettimeofday(&st, NULL);
        wc_AesCtrEncrypt(&enc, cipher, msg, (int) sizeof(msg));
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_array] = encryption_time;

        gettimeofday(&st, NULL);
        wc_AesCtrEncrypt(&dec, plain, cipher, (int) sizeof(cipher));
        gettimeofday(&et, NULL);

        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_array + 1] = decryption_time;
        index_array += 2;
    }
    wc_AesFree(&enc);
    wc_AesFree(&dec);

    LOGD("Finished AES/CTR");

    (*env)->SetIntArrayRegion(env,result, 0, len_array, fill);

    return result;

}

JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_MD5(JNIEnv *env, jobject instance,jint blocksize, jint rep_hash) {

    jintArray result;
    result = (*env)->NewIntArray(env,rep_hash);
    jint fill[rep_hash];

    jint error[1];

    struct timeval st,et;
    Md5 md5;
    byte *hash[MD5_DIGEST_SIZE];

    int ret;
    int final;

    int szdata= blocksize;
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

    /*int i = 0;
    for (int i = 0; i < 32; ++i) {
        LOGD("%x",data[i]);
    }
*/

    printf("\n");

    if (ret != 0) {

        LOGD("wc_Initmd5 failed");

    } else {

        for (int i = 0; i <rep_hash ; ++i) {


            gettimeofday(&st, NULL);

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

            gettimeofday(&et, NULL);

            int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

            fill[i] = generation_time;
        }
        LOGD("Hash finished");
    }

    (*env)->SetIntArrayRegion(env,result, 0, rep_hash, fill);

    return result;

}

JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_RSA(JNIEnv *env, jobject instance,jint blocksize,jint rep_rsa) {

    int len_array = rep_rsa * 2;
    jintArray result;
    result = (*env)->NewIntArray(env,len_array);
    jint fill[len_array];
    struct timeval st,et;

    RsaKey key,key_dec;
    RNG rng1;
    word32 index;
    int ret;

    int encrypted_len;
    int decrypted_len;

    RNG  rng;

    int szdata = blocksize;
    byte data[szdata];

    int rngint = wc_InitRng(&rng);
    if (rngint != 0) {
        LOGD("Failure Init"); //init of rng failed!
    }

    ret = wc_RNG_GenerateBlock(&rng, data,szdata);

    if (ret != 0) {
        LOGD("Failure GenerateByte"); //generating block failed!
    }

    // encrypt data.
    index = 0;
    ret = wc_InitRng(&rng1);
    if (ret != 0) { LOGD("Error at wc_InitRng: %i.", ret); return result; }
    ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) { LOGD("Error at wc_InitRsaKey: %i.", ret); return result; }
    ret = wc_RsaPublicKeyDecode((const byte*)public_key, &index, &key, PUBLIC_KEY_LENGTH);
    if (ret != 0) { LOGD("Error at wc_RsaPublicKeyDecode: %i.", ret); return result; }

    int index1 = 0;
    ret = wc_InitRsaKey(&key_dec, NULL);
    if (ret != 0) { LOGD("Error 2 at wc_InitRsaKey: %i.", ret); return result; }
    ret = wc_RsaPrivateKeyDecode((const byte*)private_key, &index1, &key_dec, PRIVATE_KEY_LENGTH);
    if (ret != 0) { LOGD("Error 2 at wc_RsaPrivateKeyDecode: %i.", ret); return result; }

    int index_result = 0;
    for (int i = 0; i < rep_rsa ; i++) {

        gettimeofday(&st, NULL);
        ret = wc_RsaPublicEncrypt_ex(data, IN_BUFFER_LENGTH, (byte *) encrypted_buffer, RSA_LENGTH,
                                     &key, &rng1, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1,
                                     NULL, 0);
        gettimeofday(&et, NULL);

        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_result] = encryption_time;

        if (ret < 0) {
            LOGD("Error at wc_RsaPublicEncrypt_ex: %i.", ret);
            return result;
        }
        encrypted_len = ret;
        LOGD("%i", encrypted_len);

        LOGD("Finished encryption / RSA");

        // decrypt data.


        gettimeofday(&st, NULL);
        ret = wc_RsaPrivateDecrypt_ex((const byte *) encrypted_buffer, encrypted_len,
                                      (byte *) decrypted_buffer, RSA_LENGTH, &key_dec,
                                      WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
        gettimeofday(&et, NULL);

        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_result + 1] = decryption_time;

        if (ret < 0) {
            LOGD("Error at wc_RsaPrivateDecrypt_ex: %i.", ret);
            return result;
        }
        decrypted_len = ret;
        index_result +=2;
    }

    LOGD("Finished decryption / RSA");
    // got here means no error.
    LOGD("All went O.K.");

    (*env)->SetIntArrayRegion(env,result, 0, len_array, fill);

    return result;
}

JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_AESGCM(JNIEnv *env, jobject instance,jint blocksize,jint rep_aes) {

    LOGD("Starting AESGCM");
    int len_array = rep_aes * 2;
    jintArray result;
    result = (*env)->NewIntArray(env,len_array);
    jint fill[len_array];
    struct timeval st, et;

    Aes enc;
    byte cipher[128];

    Aes dec;
    byte plain[128];

    int ret = 0;

    RNG rng;


    unsigned char key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };


    int szmsg = 128;
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

    ret = wc_RNG_GenerateBlock(&rng, msg, sizeof(msg));
    if (ret != 0) {
        LOGD("Error generating block at msg"); //generating block failed!
    }

    unsigned char iv[16] = {
            0x09, 0xcf, 0x15, 0x88, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0xae, 0x16, 0x28, 0xd2, 0xa6,
            0xab, 0xf7,

    };


    if (wc_AesInit(&enc, HEAP_HINT, devId) != 0) {
        LOGD("Error in aes init enc");
    } else {
        LOGD("No problem at init enc");
    }

    if (wc_AesInit(&dec, HEAP_HINT, devId) != 0) {
        LOGD("Error in aes init dec");
    } else {
        LOGD("No problem at init dec");
    }

    ret = wc_AesGcmSetKey(&enc, key, (int) sizeof(key));
    if (ret != 0) {
        LOGD("Error in AesSetKey Enc");
    } else {
        LOGD("No problem at AesSetKey Enc");
    }

    ret = wc_AesGcmSetKey(&dec, key, (int) sizeof(key));
    if (ret != 0) {
        LOGD("Error in AesSetKey Dec");
    } else {
        LOGD("No problem at AesSetKey Dec ");
    }

    int index_result = 0;
    for (int i = 0; i < rep_aes ; i++) {


        gettimeofday(&st, NULL);
        ret = wc_AesGcmEncrypt(&enc, cipher, msg, (int) sizeof(msg), iv, sizeof(iv), resultT,
                               sizeof(resultT), a,
                               sizeof(a));
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_result] = encryption_time;

        if (ret != 0) {
            LOGD("Error encrypting");
        } else {
            LOGD("Encryption finished");
        }
        gettimeofday(&st, NULL);
        ret = wc_AesGcmDecrypt(&enc, resultP, cipher, (int) sizeof(cipher), iv, sizeof(iv), resultT,
                               sizeof(resultT), a,
                               sizeof(a));
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_result + 1] = decryption_time;

        if (ret != 0) {
            LOGD("Error Decrypting");
        } else {
            LOGD("Decryption finished");
        }


        index_result +=2;
    }

    //wc_AesFree(&enc);
    //wc_AesFree(&dec);

    LOGD("Finished AES/GCM");

    (*env)->SetIntArrayRegion(env,result, 0, len_array, fill);

    return result;

}


JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_ECDH(JNIEnv *env, jobject instance, jint rep_agree) {


    LOGD("Starting ECDH");
    jintArray result;
    result = (*env)->NewIntArray(env,rep_agree);
    jint fill[rep_agree];
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

    for(int i = 0; i < rep_agree; i++) {
        gettimeofday(&st, NULL);
        ret = wc_ecc_shared_secret(&priv, &pub, secret, &secretsize);

        gettimeofday(&et, NULL);

        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[i] = decryption_time;

        if (ret != 0) {
            LOGD("Error sharing secret");
            LOGD("Error is : %i", ret);
        }
    }

    LOGD("We are good");

    (*env)->SetIntArrayRegion(env,result, 0, rep_agree, fill);

    return result;

}

JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_DHTime(JNIEnv *env, jobject instance,jint rep_key,jint rep_agree) {

    FILE* report = create_file();
    fprintf(report,"************WolfCrypt/DH**************\n");

    struct timeval st,et;

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


    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions = 0;
    while ((now - start) <= rep_key) {
        gettimeofday(&st,NULL);

    ret = wc_InitDhKey_ex(&key, HEAP_HINT, devId);
    if (ret != 0) {
        LOGD("Error at InitDHKey 1");
        return;
    }

    ret = wc_InitDhKey_ex(&key2, HEAP_HINT, devId);
    if (ret != 0) {
        LOGD("Error at InitDHKey 2");
        return;
    }


    ret = wc_DhSetKey(&key, p, sizeof(p), g, sizeof(g));
    if (ret != 0) {
        LOGD("Error setting key 1");
        return;
    }

    ret = wc_DhSetKey(&key2, p, sizeof(p), g, sizeof(g));
    if (ret != 0) {
        LOGD("Error setting key 2");
        return;
    }

    ret = wc_InitRng_ex(&rng, HEAP_HINT, devId);
    if (ret != 0) {
        LOGD("Error initialising RNG");
        return;
    }

    ret = wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz);
    if (ret != 0) {
        LOGD("Error generating 1st keypair");
        return;
    }

    ret = wc_DhGenerateKeyPair(&key2, &rng, priv2, &privSz2, pub2, &pubSz2);
    if (ret != 0) {
        LOGD("Error generating 2nd keypair");
        return;
    }
        gettimeofday(&et,NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fprintf(report, "Time to set key: %i ms\n",generation_time);

        now = time(NULL);
        repetitions +=1;

    }
    fprintf(report,"Times key set: %i \n",repetitions);

    start = time(NULL);
    now = time(NULL);
    repetitions = 0;
    while ((now - start) <= rep_agree) {
        gettimeofday(&st, NULL);
        ret = wc_DhAgree(&key, agree, &agreeSz, priv, privSz, pub2, pubSz2);
        gettimeofday(&et, NULL);
        int key_agreement = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        if (ret != 0) {
            LOGD("Error agreeing");
            return;
        } else {
            LOGD("Success at 1st agreeing");
        }
        fprintf(report, "Time to generate key agreement: %i ms\n",key_agreement);
        now = time(NULL);
        repetitions +=1;
    }

    fprintf(report, "Times performed: %i \n",repetitions);
    fprintf(report,"*****************************");
    fclose(report);

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



    return ;
}

JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_ECDHTime(JNIEnv *env, jobject instance, jint rep_key,jint rep_agree) {


    FILE* report = create_file();
    fprintf(report,"************WolfCrypt/ECDH**************\n");

    int ret;
    int repetitions = 0;
    byte secret[1024];
    word32 secretsize = sizeof(secret);
    struct timeval st,et;


    ecc_key priv;
    ecc_key pub;
    WC_RNG rng_pub,rng_priv;

    time_t start = time(NULL);
    time_t now = time(NULL);
    repetitions = 0;
    while ((now - start) <= rep_key) {

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

        gettimeofday(&et,NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fprintf(report, "Time to set key: %i ms\n",generation_time);

        now = time(NULL);
        repetitions +=1;

    }
    fprintf(report,"Times key set: %i \n",repetitions);

    start = time(NULL);
    now = time(NULL);
    repetitions = 0;
    while ((now - start) <= rep_agree) {
        gettimeofday(&st, NULL);
        ret = wc_ecc_shared_secret(&priv, &pub, secret, &secretsize);

        gettimeofday(&et, NULL);

        int key_agreement = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);


        if (ret != 0) {
            LOGD("Error sharing secret");
            LOGD("Error is : %i", ret);
        }

        fprintf(report, "Time to generate key agreement: %i ms\n",key_agreement);
        now = time(NULL);
        repetitions +=1;
    }

    fprintf(report, "Times performed: %i \n",repetitions);
    fprintf(report,"*****************************");
    fclose(report);

    LOGD("We are good");



    return;
}

JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_MD5Time(JNIEnv *env, jobject instance,jint blocksize, jint rep_hash) {

    FILE* report = create_file();
    fprintf(report,"************WolfCrypt/MD5**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);

    struct timeval st,et;
    Md5 md5;
    byte *hash[MD5_DIGEST_SIZE];

    int ret;
    int final;

    int szdata= blocksize;
    byte data[szdata];
    word32 len = sizeof(data);


    RNG  rng;

    int rngint = wc_InitRng(&rng);
    if (rngint != 0) {
        LOGD("Failure Init"); //init of rng failed!
    }

    ret = wc_RNG_GenerateBlock(&rng, data,szdata);

    if (ret != 0) {
        LOGD("Failure GenerateByte"); //generating block failed!
    }

    /*int i = 0;
    for (int i = 0; i < 32; ++i) {
        LOGD("%x",data[i]);
    }
*/
    int repetitions = 0;

    time_t start = time(NULL);
    time_t now = time(NULL);

    while ((now - start) <= rep_hash) {
    printf("\n");
    ret = wc_InitMd5(&md5);
    if (ret != 0) {

        LOGD("wc_Initmd5 failed");

    } else {


            gettimeofday(&st, NULL);

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

            gettimeofday(&et, NULL);

            int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

            fprintf(report, "Time to generate hash: %i ms\n", generation_time);
            }
        now = time(NULL);
        repetitions +=1;

    }
        fprintf(report, "Times performed: %i \n",repetitions);
        fprintf(report,"*****************************");
        fclose(report);


    return ;

}

JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_RSATime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_rsa) {

    int len_array = rep_rsa * 2;
    jintArray result;
    result = (*env)->NewIntArray(env,len_array);
    jint fill[len_array];
    struct timeval st,et;

    RsaKey key,key_dec;
    RNG rng1;
    word32 index;
    int ret;

    int encrypted_len;
    int decrypted_len;

    RNG  rng;

    int szdata = blocksize;
    byte data[szdata];

    int rngint = wc_InitRng(&rng);
    if (rngint != 0) {
        LOGD("Failure Init"); //init of rng failed!
    }

    ret = wc_RNG_GenerateBlock(&rng, data,szdata);

    if (ret != 0) {
        LOGD("Failure GenerateByte"); //generating block failed!
    }

    FILE* report = create_file();
    if(report == NULL){
        LOGD("Error reading the file");

    }

    fprintf(report,"************WolfCrypt/RSA**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);

    int repetitions_key = 0;
    time_t start_key = time(NULL);
    time_t now_key = time(NULL);

    while ((now_key - start_key) <= rep_key) {
        gettimeofday(&st,NULL);
        index = 0;
        ret = wc_InitRng(&rng1);
        if (ret != 0) { LOGD("Error at wc_InitRng: %i.", ret); return; }
        ret = wc_InitRsaKey(&key, NULL);
        if (ret != 0) { LOGD("Error at wc_InitRsaKey: %i.", ret); return; }
        ret = wc_RsaPublicKeyDecode((const byte*)public_key, &index, &key, PUBLIC_KEY_LENGTH);
        if (ret != 0) { LOGD("Error at wc_RsaPublicKeyDecode: %i.", ret); return; }

        int index1 = 0;
        ret = wc_InitRsaKey(&key_dec, NULL);
        if (ret != 0) { LOGD("Error 2 at wc_InitRsaKey: %i.", ret); return ; }
        ret = wc_RsaPrivateKeyDecode((const byte*)private_key, &index1, &key_dec, PRIVATE_KEY_LENGTH);
        if (ret != 0) { LOGD("Error 2 at wc_RsaPrivateKeyDecode: %i.", ret); return ; }

        gettimeofday(&et, NULL);
        int setting_key_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to set key: %i ms\n", setting_key_time);
        repetitions_key += 1;
        now_key = time(NULL);
    }
    fprintf(report,"Key set: %i times\n", repetitions_key);

    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions_rsa = 0;
    while ((now - start) <= rep_rsa) {

        gettimeofday(&st, NULL);
        ret = wc_RsaPublicEncrypt_ex(data, IN_BUFFER_LENGTH, (byte *) encrypted_buffer, RSA_LENGTH,
                                     &key, &rng1, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1,
                                     NULL, 0);
        gettimeofday(&et, NULL);

        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to encrypt: %i ms\n", encryption_time);

        if (ret < 0) {
            LOGD("Error at wc_RsaPublicEncrypt_ex: %i.", ret);
            return ;
        }
        encrypted_len = ret;
        LOGD("%i", encrypted_len);

        LOGD("Finished encryption / RSA");

        // decrypt data.


        gettimeofday(&st, NULL);
        ret = wc_RsaPrivateDecrypt_ex((const byte *) encrypted_buffer, encrypted_len,
                                      (byte *) decrypted_buffer, RSA_LENGTH, &key_dec,
                                      WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
        gettimeofday(&et, NULL);

        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to decrypt: %i ms\n", decryption_time);

        if (ret < 0) {
            LOGD("Error at wc_RsaPrivateDecrypt_ex: %i.", ret);
            return;
        }
        decrypted_len = ret;

        repetitions_rsa += 1;
        now = time(NULL);
    }

    LOGD("We are good");

    fprintf(report, "Times performed: %i \n", repetitions_rsa);
    fprintf(report,"*****************************");
    fclose (report);

    LOGD("Finished decryption / RSA");
    // got here means no error.
    LOGD("All went O.K.");


    return;
}

JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_AESCBCTime(JNIEnv *env, jobject instance, jint blocksize,jint rep_key,jint rep_aes) {



    struct timeval st,et;

    Aes enc;
    byte cipher[blocksize];

    Aes dec;
    byte plain[blocksize];

    int ret = 0;

    RNG  rng;

    unsigned char key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    int szmsg = blocksize;

    LOGD("Size of blocksize: %i",szmsg);

    byte msg[szmsg];

    int retrng = wc_InitRng(&rng);
    if (retrng != 0) {
        LOGD("Error at RNG"); //init of rng failed!
    }


    ret = wc_RNG_GenerateBlock(&rng, msg, sizeof(msg));
    if (ret != 0) {
        LOGD("Error generating block at msg"); //generating block failed!
    }


    FILE* report = create_file();
    if(report == NULL){
        LOGD("Error reading the file");

    }

    fprintf(report,"************WolfCrypt/AESCBC**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);

    int repetitions_key = 0;
    time_t start_key = time(NULL);
    time_t now_key = time(NULL);

    while ((now_key - start_key) <= rep_key) {
    gettimeofday(&st,NULL);
    if (wc_AesInit(&enc, HEAP_HINT, devId) != 0) {
        LOGD("Error in aes init enc");
        return ;
    }else{
        LOGD("No problem at init enc");
    }

    if (wc_AesInit(&dec, HEAP_HINT, devId) != 0){
        LOGD("Error in aes init dec");
        return ;
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
        gettimeofday(&et,NULL);
        int setting_key_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to set key: %i ms\n", setting_key_time);
        repetitions_key += 1;
        now_key = time(NULL);
    }
    fprintf(report,"Key set: %i times\n", repetitions_key);

    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions = 0;
    while ((now - start) <= rep_aes) {
        gettimeofday(&st, NULL);
        ret = wc_AesCbcEncrypt(&enc, cipher, msg, (int) sizeof(msg));
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to encrypt: %i ms\n", encryption_time);

        if (ret != 0) {
            LOGD("Error encrypting");
        } else {
            LOGD("Encryption finished");
        }

        gettimeofday(&st, NULL);
        ret = wc_AesCbcDecrypt(&dec, plain, cipher, (int) sizeof(cipher));
        gettimeofday(&et, NULL);

        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to decrypt: %i ms\n", decryption_time);

        if (ret != 0) {
            LOGD("Error Decrypting");
        } else {
            LOGD("Decryption finished");
        }

        now = time(NULL);
        repetitions  += 1;
    }

    fprintf(report,"Times performed: %i \n",repetitions);
    fprintf(report,"*****************************");
    fclose(report);
    wc_AesFree(&enc);
    wc_AesFree(&dec);

    LOGD("Finished AES/CBC 128");


    return;

}

JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_AESCTRTime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_aes) {

    FILE* report = create_file();

    Aes enc;
    byte cipher[blocksize];

    Aes dec;
    byte plain[blocksize];

    int ret = 0;

    struct timeval st, et;

    RNG  rng;


    unsigned char key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    int szmsg = blocksize;
    byte msg[szmsg];

    int retrng = wc_InitRng(&rng);
    if (retrng != 0) {
        LOGD("Error at RNG"); //init of rng failed!
    }

    ret = wc_RNG_GenerateBlock(&rng, msg, sizeof(msg));
    if (ret != 0) {
        LOGD("Error generating block at msg"); //generating block failed!
    }

    fprintf(report,"************WolfCrypt/AESCTR**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);

    int repetitions_key = 0;
    time_t start_key = time(NULL);
    time_t now_key = time(NULL);

    while ((now_key - start_key) <= rep_key) {
        gettimeofday(&st,NULL);
        if (wc_AesInit(&enc, HEAP_HINT, devId) != 0) {
            LOGD("Error in aes init enc");
            return;
        }else{
            LOGD("No problem at init enc");
        }

        if (wc_AesInit(&dec, HEAP_HINT, devId) != 0){
            LOGD("Error in aes init dec");
            return ;
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

        gettimeofday(&et,NULL);
        int setting_key_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to set key: %i ms\n", setting_key_time);
        repetitions_key += 1;
        now_key = time(NULL);
    }
    fprintf(report,"Key set: %i times\n", repetitions_key);

    time_t start = time(NULL);
    time_t now = time(NULL);

    int repetitions = 0;
    while ((now - start) <= rep_aes) {
        gettimeofday(&st, NULL);
        wc_AesCtrEncrypt(&enc, cipher, msg, (int) sizeof(msg));
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to encrypt: %i ms\n", encryption_time);

        gettimeofday(&st, NULL);
        wc_AesCtrEncrypt(&dec, plain, cipher, (int) sizeof(cipher));
        gettimeofday(&et, NULL);

        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to decrypt: %i ms\n", decryption_time);
        repetitions += 1;
        now = time(NULL);
    }

    fprintf(report,"Times performed: %i \n",repetitions);
    fprintf(report,"*****************************");
    fclose(report);

    wc_AesFree(&enc);
    wc_AesFree(&dec);

    LOGD("Finished AES/CTR");

    return;
}

JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_WolfCrypt_AESGCMTime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_aes) {

    LOGD("Starting AESGCM");
    int len_array = rep_aes * 2;
    jintArray result;
    result = (*env)->NewIntArray(env,len_array);
    jint fill[len_array];
    struct timeval st, et;

    Aes enc;
    byte cipher[128];

    Aes dec;
    byte plain[128];

    int ret = 0;

    RNG rng;


    unsigned char key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };


    int szmsg = 128;
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

    ret = wc_RNG_GenerateBlock(&rng, msg, sizeof(msg));
    if (ret != 0) {
        LOGD("Error generating block at msg"); //generating block failed!
    }

    unsigned char iv[16] = {
            0x09, 0xcf, 0x15, 0x88, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0xae, 0x16, 0x28, 0xd2, 0xa6,
            0xab, 0xf7,

    };
    FILE* report = create_file();

    fprintf(report,"************WolfCrypt/AESGCM**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);

    int repetitions_key = 0;
    time_t start_key = time(NULL);
    time_t now_key = time(NULL);

    while ((now_key - start_key) <= rep_key) {
        gettimeofday(&st,NULL);

    if (wc_AesInit(&enc, HEAP_HINT, devId) != 0) {
        LOGD("Error in aes init enc");
    } else {
        LOGD("No problem at init enc");
    }

    if (wc_AesInit(&dec, HEAP_HINT, devId) != 0) {
        LOGD("Error in aes init dec");
    } else {
        LOGD("No problem at init dec");
    }

    ret = wc_AesGcmSetKey(&enc, key, (int) sizeof(key));
    if (ret != 0) {
        LOGD("Error in AesSetKey Enc");
    } else {
        LOGD("No problem at AesSetKey Enc");
    }

    ret = wc_AesGcmSetKey(&dec, key, (int) sizeof(key));
    if (ret != 0) {
        LOGD("Error in AesSetKey Dec");
    } else {
        LOGD("No problem at AesSetKey Dec ");
    }
        gettimeofday(&et,NULL);
        int setting_key_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to set key: %i ms\n", setting_key_time);
        repetitions_key += 1;
        now_key = time(NULL);
    }
    fprintf(report,"Key set: %i times\n", repetitions_key);

    time_t start = time(NULL);
    time_t now = time(NULL);

    int repetitions = 0;
    while ((now - start) <= rep_aes) {

        gettimeofday(&st, NULL);
        ret = wc_AesGcmEncrypt(&enc, cipher, msg, (int) sizeof(msg), iv, sizeof(iv), resultT,
                               sizeof(resultT), a,
                               sizeof(a));
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to encrypt: %i ms\n", encryption_time);

        if (ret != 0) {
            LOGD("Error encrypting");
        } else {
            LOGD("Encryption finished");
        }
        gettimeofday(&st, NULL);
        ret = wc_AesGcmDecrypt(&enc, resultP, cipher, (int) sizeof(cipher), iv, sizeof(iv), resultT,
                               sizeof(resultT), a,
                               sizeof(a));
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);



        if (ret != 0) {
            LOGD("Error Decrypting");
        } else {
            LOGD("Decryption finished");
        }


        fprintf(report,"Time to decrypt: %i ms\n", decryption_time);
        repetitions += 1;
        now = time(NULL);
    }

    fprintf(report,"Times performed: %i \n",repetitions);
    fprintf(report,"*****************************");
    fclose(report);

    //wc_AesFree(&enc);
    //wc_AesFree(&dec);

    LOGD("Finished AES/GCM");

    (*env)->SetIntArrayRegion(env,result, 0, len_array, fill);

    return result;

}

unsigned char public_key[PUBLIC_KEY_LENGTH] = {
        0x30,0x82,0x01,0x22,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00,0x03,
        0x82,0x01,0x0F,0x00,0x30,0x82,0x01,0x0A,0x02,0x82,0x01,0x01,0x00,0xCB,0xC0,0xDB,0xBF,0xCA,0x6B,0xA4,
        0x9F,0xF4,0x90,0xA8,0x65,0x19,0xE2,0x58,0xA3,0x3A,0x36,0xB7,0xAD,0x04,0x1B,0xC2,0xF4,0xE7,0xAD,0x60,
        0xD7,0x74,0x76,0xF4,0xBB,0xCC,0x47,0x98,0x72,0xBC,0x66,0x65,0x18,0x9A,0x66,0x9F,0xAE,0x7E,0x03,0x8C,
        0x47,0x5C,0x89,0xC9,0x62,0x23,0xEE,0x2B,0x3A,0xCA,0x52,0x70,0x29,0x78,0xB6,0x7E,0xBF,0x0D,0x47,0xA1,
        0xC3,0x80,0x66,0xD5,0x8A,0xD3,0x3D,0xEB,0xDB,0xAB,0x80,0xF2,0x44,0x18,0x38,0xA5,0xFD,0x42,0xDF,0xC3,
        0x6C,0x27,0x6F,0xB0,0x5F,0x70,0x17,0xC8,0x11,0x2B,0x4A,0x6D,0xC7,0xD3,0x3A,0x47,0x5D,0xCD,0xBC,0x1C,
        0x6F,0x55,0x00,0x29,0x7D,0xCF,0x63,0x07,0xD9,0xD3,0xCE,0x98,0x4E,0x80,0xCE,0x09,0x88,0x46,0x2F,0x95,
        0x5F,0x05,0x2E,0x18,0x3D,0xC9,0x9A,0x2F,0x31,0x87,0x7A,0x5B,0x07,0xF7,0x6A,0x85,0xCA,0xF3,0xDD,0x55,
        0x43,0x14,0xEB,0xFE,0x44,0x18,0xA2,0xAD,0x58,0xA7,0xEE,0xBC,0x8B,0xA4,0xF8,0x9C,0xDA,0xBB,0x35,0x60,
        0xBE,0x50,0xD5,0x63,0x40,0x7C,0x4D,0x40,0xC4,0x0C,0xCD,0x4E,0xA5,0x58,0x25,0xFC,0xCF,0x28,0x37,0xC8,
        0x7F,0x3C,0x38,0x04,0x24,0x51,0x72,0x17,0x29,0xF4,0x3E,0x36,0x4B,0xD8,0x43,0x57,0x31,0x68,0xCA,0x15,
        0x3E,0x96,0x3B,0xDB,0xE7,0x95,0xB6,0x12,0xB3,0xA4,0xC7,0xB2,0x1E,0x40,0x67,0xED,0xC8,0xAE,0x9A,0x4E,
        0x6A,0x80,0xB4,0xC4,0x24,0x07,0xD6,0x66,0x97,0xB8,0x7F,0x87,0x85,0x66,0x3F,0xD1,0x73,0xC6,0x3C,0x26,
        0x3D,0x88,0x4B,0x99,0x15,0x3E,0x35,0x32,0xC1,0x02,0x03,0x01,0x00,0x01
};

unsigned char private_key[PRIVATE_KEY_LENGTH]={0x30,0x82,0x04,0xA3,0x02,0x01,0x00,0x02,0x82,0x01,0x01,0x00,0xCB,
                                               0xC0,0xDB,0xBF,0xCA,0x6B,0xA4,0x9F,0xF4,0x90,0xA8,0x65,0x19,0xE2,
                                               0x58,0xA3,0x3A,0x36,0xB7,0xAD,0x04,0x1B,0xC2,0xF4,0xE7,0xAD,0x60,
                                               0xD7,0x74,0x76,0xF4,0xBB,0xCC,0x47,0x98,0x72,0xBC,0x66,0x65,0x18,
                                               0x9A,0x66,0x9F,0xAE,0x7E,0x03,0x8C,0x47,0x5C,0x89,0xC9,0x62,0x23,
                                               0xEE,0x2B,0x3A,0xCA,0x52,0x70,0x29,0x78,0xB6,0x7E,0xBF,0x0D,0x47,
                                               0xA1,0xC3,0x80,0x66,0xD5,0x8A,0xD3,0x3D,0xEB,0xDB,0xAB,0x80,0xF2,
                                               0x44,0x18,0x38,0xA5,0xFD,0x42,0xDF,0xC3,0x6C,0x27,0x6F,0xB0,0x5F,
                                               0x70,0x17,0xC8,0x11,0x2B,0x4A,0x6D,0xC7,0xD3,0x3A,0x47,0x5D,0xCD,
                                               0xBC,0x1C,0x6F,0x55,0x00,0x29,0x7D,0xCF,0x63,0x07,0xD9,0xD3,0xCE,
                                               0x98,0x4E,0x80,0xCE,0x09,0x88,0x46,0x2F,0x95,0x5F,0x05,0x2E,0x18,
                                               0x3D,0xC9,0x9A,0x2F,0x31,0x87,0x7A,0x5B,0x07,0xF7,0x6A,0x85,0xCA,
                                               0xF3,0xDD,0x55,0x43,0x14,0xEB,0xFE,0x44,0x18,0xA2,0xAD,0x58,0xA7,
                                               0xEE,0xBC,0x8B,0xA4,0xF8,0x9C,0xDA,0xBB,0x35,0x60,0xBE,0x50,0xD5,
                                               0x63,0x40,0x7C,0x4D,0x40,0xC4,0x0C,0xCD,0x4E,0xA5,0x58,0x25,0xFC,
                                               0xCF,0x28,0x37,0xC8,0x7F,0x3C,0x38,0x04,0x24,0x51,0x72,0x17,0x29,
                                               0xF4,0x3E,0x36,0x4B,0xD8,0x43,0x57,0x31,0x68,0xCA,0x15,0x3E,0x96,
                                               0x3B,0xDB,0xE7,0x95,0xB6,0x12,0xB3,0xA4,0xC7,0xB2,0x1E,0x40,0x67,
                                               0xED,0xC8,0xAE,0x9A,0x4E,0x6A,0x80,0xB4,0xC4,0x24,0x07,0xD6,0x66,
                                               0x97,0xB8,0x7F,0x87,0x85,0x66,0x3F,0xD1,0x73,0xC6,0x3C,0x26,0x3D,
                                               0x88,0x4B,0x99,0x15,0x3E,0x35,0x32,0xC1,0x02,0x03,0x01,0x00,0x01,
                                               0x02,0x82,0x01,0x00,0x38,0x60,0xD6,0xED,0x4C,0xBF,0x58,0x40,0x02,
                                               0x55,0xFC,0xA2,0x6C,0xF5,0x1A,0x7D,0x9F,0xE0,0x00,0x16,0xD9,0xAA,
                                               0x2C,0xD9,0xC3,0x39,0x50,0x30,0x8D,0xC3,0x54,0x98,0x9A,0x3F,0xBD,
                                               0x49,0x12,0x24,0x6B,0x18,0xD1,0xB0,0x4F,0xC2,0xE2,0x8F,0x6C,0xC3,
                                               0x5A,0x31,0xAE,0x0D,0x7F,0xCF,0xA9,0x1A,0x8D,0x5D,0x1E,0x37,0xFB,
                                               0x74,0xD3,0xC1,0x5D,0x95,0x52,0x87,0x5C,0x02,0x18,0x58,0x5F,0x77,
                                               0x24,0xCA,0x15,0xBC,0x8A,0x4C,0x99,0x3F,0x23,0x7E,0xDE,0x80,0x37,
                                               0xFC,0xB7,0x34,0xCA,0x62,0xBE,0x0B,0x76,0x8A,0x79,0xA6,0x10,0x96,
                                               0x58,0x36,0x2A,0x05,0x24,0xA6,0x46,0x5F,0xEF,0xEF,0x29,0x8B,0xEC,
                                               0x54,0x84,0x99,0x9B,0x67,0xF0,0xF0,0xD7,0xE7,0x2A,0xF0,0x10,0x2B,
                                               0x9E,0x72,0xBB,0xE1,0x91,0x58,0x16,0x46,0x39,0xE4,0xBD,0x2B,0xE2,
                                               0xDB,0x62,0xF3,0xB0,0x72,0xB8,0xCA,0x84,0x7C,0xFA,0xEA,0x6E,0x1B,
                                               0x79,0xD2,0x9D,0x81,0x50,0x22,0xC7,0xA3,0x44,0xE6,0x2C,0x26,0x8C,
                                               0xD5,0xE4,0xB5,0x24,0x25,0x24,0xC0,0xA3,0x6E,0xD7,0x4D,0x5E,0x0F,
                                               0xF1,0xA3,0x5F,0xC6,0xE2,0x41,0xB6,0xA7,0xF3,0x0E,0xD4,0x72,0xDC,
                                               0x29,0xF7,0xB5,0x37,0x91,0x60,0x06,0x25,0xE3,0xDD,0x08,0xE5,0xBE,
                                               0x0B,0xE3,0x25,0x99,0x21,0xD5,0xAB,0x36,0x29,0x38,0x1A,0x3C,0xE0,
                                               0x6A,0x65,0xA3,0xF4,0xDF,0xBD,0xFC,0x56,0x76,0x20,0xDB,0x72,0x12,
                                               0xCA,0xF7,0xD3,0xFE,0xD7,0x80,0xAD,0x51,0xAD,0xC6,0xB9,0x85,0x3F,
                                               0xBF,0x77,0xF4,0x4B,0xC9,0x14,0xAA,0x45,0xD7,0x04,0xF1,0xB8,0x39,
                                               0x02,0x81,0x81,0x00,0xEE,0xDD,0x03,0x47,0x7E,0xF3,0xB7,0xE7,0x44,
                                               0x27,0x2F,0xB9,0xBE,0x6E,0xF3,0x4A,0x63,0x7D,0xED,0x57,0xA7,0xC1,
                                               0x02,0x45,0x58,0xC8,0xAE,0x96,0x41,0xC6,0x6B,0x4C,0x94,0xDE,0x52,
                                               0xDA,0xB3,0x1C,0x6E,0x9B,0x4A,0x14,0xB6,0x77,0x48,0x8D,0xE9,0xC8,
                                               0xBD,0x2C,0x7A,0xB7,0x76,0x3E,0x6A,0x02,0xB6,0x17,0x71,0x0F,0x6D,
                                               0xBD,0x00,0x67,0x9C,0x19,0xD6,0x9D,0x48,0x5E,0xCE,0x2F,0x92,0xD8,
                                               0x1E,0x43,0x04,0x92,0x05,0xDA,0x9C,0x33,0xC2,0xD9,0x14,0x3B,0xD9,
                                               0xB8,0xF6,0xE8,0x42,0x72,0x68,0x45,0xD2,0x24,0x77,0xAD,0x97,0x9C,
                                               0xFE,0x5E,0x90,0x81,0x08,0x04,0x07,0xCE,0xA7,0xCB,0xF6,0xC0,0x5A,
                                               0x52,0x7C,0x4E,0xE7,0x34,0x7D,0xAE,0xE0,0x2A,0x40,0x5C,0xD4,0x85,
                                               0xF4,0x7B,0x02,0x81,0x81,0x00,0xDA,0x5F,0x03,0x26,0xB0,0xC4,0xE6,
                                               0x6F,0x4A,0x92,0x7F,0x89,0xE2,0x5F,0x80,0x74,0x67,0xDE,0x04,0xBD,
                                               0x62,0x80,0xF1,0x77,0x0E,0x7B,0x8F,0xA1,0x5E,0xBB,0x06,0x98,0x22,
                                               0x68,0x08,0x08,0xE2,0x1D,0xB9,0x50,0x9C,0xD7,0x88,0x32,0x8A,0xA1,
                                               0xAE,0xF4,0xE9,0x2D,0x03,0xE1,0x70,0x7B,0xE3,0x33,0x8B,0x5F,0x5D,
                                               0x4C,0x68,0x63,0xCC,0x21,0xD8,0x65,0x1B,0xE4,0xA0,0x79,0x07,0xCD,
                                               0xA0,0x2E,0x65,0x13,0x86,0x56,0x5C,0xDC,0x84,0x48,0x91,0xF5,0x49,
                                               0x58,0x11,0x19,0x3F,0x67,0x04,0x2D,0xAF,0xB4,0xBE,0x9B,0xC4,0x25,
                                               0x55,0x58,0x19,0x13,0x78,0x2E,0x43,0xE9,0xCF,0xD0,0x5D,0xC6,0xA2,
                                               0xEB,0x2C,0x3A,0x39,0x8C,0x8D,0x35,0xDA,0x74,0xBB,0x39,0xCA,0x51,
                                               0x17,0xB5,0xC6,0xF3,0x02,0x81,0x80,0x55,0x61,0x87,0x04,0x8D,0x6A,
                                               0x8C,0xB8,0x0B,0xF2,0x7D,0xEA,0xC5,0x19,0x5F,0xB9,0x9D,0x6A,0xAB,
                                               0xE6,0x03,0x3E,0xC8,0x93,0x05,0x33,0x66,0xC4,0xAA,0xEA,0x43,0xFC,
                                               0x71,0xD2,0x2E,0x87,0xA2,0x32,0x6D,0x8E,0xF0,0xA2,0x0A,0xBF,0x04,
                                               0x9E,0x45,0x8C,0xCD,0xA2,0x12,0x93,0x75,0x9E,0xC5,0xC2,0x06,0x58,
                                               0xC6,0xBF,0x1F,0x18,0xCA,0x06,0x3F,0x14,0x35,0x54,0xAF,0x43,0xC4,
                                               0x2B,0xD9,0x2F,0x8B,0x51,0xA5,0x56,0x94,0xE5,0x19,0xA4,0x9E,0xE7,
                                               0x7D,0x86,0x0F,0x43,0x40,0x6E,0xB1,0x21,0xB8,0x08,0x0D,0x1F,0x9F,
                                               0xEF,0xDB,0x1B,0xF1,0x08,0xD8,0x5A,0x67,0x05,0x19,0xCD,0x52,0xC9,
                                               0x63,0x80,0x4A,0x48,0xE5,0xCA,0x46,0x76,0xCA,0xDE,0x31,0x9E,0xA8,
                                               0xB7,0x05,0xF8,0x83,0xF5,0x02,0x81,0x80,0x6A,0x8B,0x81,0x16,0x17,
                                               0x99,0x7A,0x75,0x42,0x85,0x48,0x05,0x16,0x96,0x52,0x2E,0x79,0x9F,
                                               0x31,0xE0,0xD5,0x76,0xE4,0x59,0x9A,0x8F,0x5E,0xFC,0xF5,0x23,0x7B,
                                               0x8C,0x2E,0xFD,0x63,0x2E,0x32,0x65,0x1E,0x4D,0xDE,0xB8,0xAA,0x93,
                                               0x3E,0x60,0xB4,0xE4,0x7A,0x00,0xA4,0xAC,0x12,0x1D,0xE0,0x34,0xFE,
                                               0x03,0x81,0x9A,0x0E,0x34,0xE3,0x1C,0x80,0x60,0x94,0xC3,0x70,0x28,
                                               0x9D,0x4E,0x0E,0xA1,0x94,0x5F,0x7A,0x64,0x18,0xDA,0xDF,0x10,0x29,
                                               0x66,0xEC,0x6A,0x33,0xAD,0x85,0xE9,0xD5,0x78,0x15,0x0A,0xB3,0x15,
                                               0x7D,0x16,0x5A,0x15,0xA9,0xE6,0x7D,0xF4,0xD4,0xDD,0xF7,0xAF,0x4A,
                                               0x91,0xE8,0x5B,0xA6,0x30,0xA2,0x73,0x99,0x52,0x75,0x4C,0x0F,0x2D,
                                               0x9B,0x31,0x05,0xC8,0x83,0x51,0x02,0x81,0x81,0x00,0x9A,0xA2,0xA1,
                                               0x8B,0x3C,0xAC,0xAE,0x9E,0x5F,0x30,0x3C,0xCB,0x06,0x0B,0x8E,0xA4,
                                               0xCB,0xBB,0xFC,0x90,0x48,0xB0,0x67,0xFF,0x8B,0x5A,0xDF,0xA2,0xBC,
                                               0x0F,0x20,0xA8,0x2C,0xD9,0x4D,0xC5,0x2B,0xA8,0xC7,0xE0,0x39,0xC3,
                                               0xAC,0xF6,0xBC,0x47,0xD1,0x55,0x00,0xEA,0xE0,0x79,0xB8,0xBC,0x1C,
                                               0xE3,0x76,0x2D,0xD0,0x7D,0x82,0xCD,0x91,0x38,0x93,0xA8,0xB7,0x2F,
                                               0x81,0x66,0x7E,0x79,0x7E,0x38,0xA2,0x05,0xED,0x75,0x30,0xCE,0xED,
                                               0xCF,0x86,0x78,0xC2,0x96,0xCF,0x85,0xD7,0xB8,0x94,0x94,0x54,0xBE,
                                               0x7E,0x09,0x58,0xCA,0x2E,0x36,0x44,0x27,0xA4,0x1C,0xD9,0x66,0x4B,
                                               0x97,0xDE,0x31,0x4B,0x02,0xFB,0xD4,0x4E,0x35,0x1F,0x86,0x1C,0x89,
                                               0x59,0xD2,0x09,0x0C,0x55,0x73,0x82,0x70};