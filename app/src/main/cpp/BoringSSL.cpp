
// /
// Created by Juan Pérez de Algaba on 17/5/18.
//

#include <jni.h>

#include <string>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <android/log.h>
#include "opensslboring/md5.h"
#include "opensslboring/evp.h"
#include "opensslboring/aes.h"
#include <opensslboring/rsa.h>
#include <opensslboring/dh.h>
#include <opensslboring/pem.h>
#include <opensslboring/err.h>
#include <opensslboring/rand.h>
#include <opensslboring/engine.h>
#include <opensslboring/crypto.h>
#include <opensslboring/ossl_typ.h>

#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PRINT_KEYS

#define  LOG_TAG    "BoringSSL"

#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG ,__VA_ARGS__)

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

RSA * createRSA(unsigned char * key,int value){
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(value)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
    return rsa;
}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_RSA(JNIEnv *env, jobject instance,jint blocksize,jint rep_rsa) {

    jintArray result;
    int array_len = rep_rsa * 2;
    result = env->NewIntArray(array_len);
    jint fill[array_len];

    struct timeval st,et;

    char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
"wQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

    char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
"-----END RSA PRIVATE KEY-----\n";

    char plainText[blocksize];

    for (int i = 0; i < blocksize ; ++i) {
        plainText[i] = rand();
    }

    unsigned char  encrypted[4098]={};
    unsigned char decrypted[4098]={};

    RSA *rsa= NULL;

    BIO *keybio ;
    keybio = BIO_new_mem_buf(publicKey, -1);
    if (keybio==NULL)
    {
        LOGD( "Failed to create key BIO");
        return result;
    }

    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);

    if(rsa == NULL)
    {
        LOGD( "Failed to create RSA");
    }

    if(rsa == NULL)
    {
        LOGD( "Failed to create RSA_priv");
    }

    int index_Array = 0;
    for (int i = 0; i < rep_rsa; ++i) {


        gettimeofday(&st, NULL);
        int encrypted_length = RSA_public_encrypt(strlen(plainText),
                                                  reinterpret_cast<const unsigned char *>(plainText),
                                                  encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_Array] = encryption_time;
        if (encrypted_length == -1) {
            LOGD("Public Encrypt failed ");
            exit(0);
        }

        //int decrypted_length = private_decrypt(encrypted, encrypted_length,
        //reinterpret_cast<unsigned char *>(privateKey), decrypted);

        RSA *rsa_priv = createRSA(reinterpret_cast<unsigned char *>(privateKey), 0);
        gettimeofday(&st, NULL);
        int decrypted_length = RSA_private_decrypt(encrypted_length, encrypted, decrypted, rsa_priv,
                                                   RSA_PKCS1_OAEP_PADDING);
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_Array + 1] = decryption_time;

        if (decrypted_length == -1) {
            LOGD("Private Decrypt failed ");
            exit(0);
        }
        index_Array +=2;
    }
    LOGD("We are good");

    env->SetIntArrayRegion(result, 0, array_len, fill);

    return result;

}

void print_data(const char *tittle, const void* data, int len);


extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESCBC(JNIEnv *env, jobject instance, jint blocksize,int rep_aes) {

    LOGD("AES/CBC");
    jintArray result;
    int array_len = rep_aes * 2;
    result = env->NewIntArray(array_len);
    jint fill[array_len];

    struct timeval st,et;
    unsigned char aes_key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    unsigned char iv_to_use[16];

    /* Input data to encrypt */
    unsigned char aes_input[blocksize];
    RAND_bytes(aes_input, sizeof(aes_input));

    /* Init vector */
    //unsigned char iv[AES_BLOCK_SIZE];

    memcpy(iv_to_use,iv,16);
    /* Buffers for Encryption and Decryption */
    unsigned char enc_out[sizeof(aes_input)];
    unsigned char dec_out[sizeof(aes_input)];

    /* AES-128 bit CBC Encryption */
    AES_KEY enc_key, dec_key;

    AES_set_encrypt_key(aes_key, sizeof(aes_key) * 8, &enc_key);
    AES_set_decrypt_key(aes_key, sizeof(aes_key) * 8, &dec_key); // Size of key is in bits

    int index_array = 0;
    for(int i = 0; i < rep_aes; i++) {
        gettimeofday(&st, NULL);

        AES_cbc_encrypt(aes_input, enc_out, sizeof(aes_input), &enc_key, iv_to_use, AES_ENCRYPT);
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_array] = encryption_time;

        /* AES-128 bit CBC Decryption */

        clock_t begin1 = clock();
        memcpy(iv_to_use, iv, 16);
        gettimeofday(&st, NULL);
        AES_cbc_encrypt(enc_out, dec_out, sizeof(aes_input), &dec_key, iv_to_use, AES_DECRYPT);
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fill[index_array + 1] = decryption_time;

        index_array +=2;
    }
    /* Printing and Verifying */
    //print_data("\n Original ",aes_input, sizeof(aes_input)); // you can not print data as a string, because after Encryption its not ASCII

    //print_data("\n Encrypted",enc_out, sizeof(enc_out));

    //print_data("\n Decrypted",dec_out, sizeof(dec_out));

    LOGD("Finished AES/CBC");

    env->SetIntArrayRegion(result, 0, array_len, fill);

    return result;

}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESCTR(JNIEnv *env, jobject instance,jint blocksize,jint rep_aes) {

    LOGD("AES/CTR");
    jintArray result;
    int array_len = rep_aes * 2;
    result = env->NewIntArray(array_len);
    jint fill[array_len];

    EVP_CIPHER_CTX *ctx, *ctx_dec;
    int len;

    int ciphertext_len;
    int plaintext_len;

    struct timeval st,et;
    unsigned char aes_key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    unsigned char iv_to_use[16];
    if(!(ctx = EVP_CIPHER_CTX_new())) LOGD("Error creating CTX");
    if(!(ctx_dec = EVP_CIPHER_CTX_new())) LOGD("Error creating CTX_DEC");

    /* Input data to encrypt */
    unsigned char aes_input[blocksize];
    RAND_bytes(aes_input, sizeof(aes_input));

    /* Init vector */
    //unsigned char iv[AES_BLOCK_SIZE];
    //memset(iv, 0x00, AES_BLOCK_SIZE);

    memcpy(iv_to_use,iv,16);
    /* Buffers for Encryption and Decryption */
    unsigned char enc_out[sizeof(aes_input)];
    unsigned char dec_out[sizeof(aes_input)];

    /* AES-128 bit CBC Encryption */
    AES_KEY enc_key, dec_key;


    AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, &enc_key);

    gettimeofday(&st,NULL);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, aes_key, iv))
        LOGD("Error encrypting");

    if (1 != EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_ctr(), NULL, aes_key, iv))
        LOGD("Error start decrypting");

    int index_array = 0;
    for (int i = 0; i < rep_aes; ++i) {



        if (1 != EVP_EncryptUpdate(ctx, enc_out, &len, aes_input, sizeof(aes_input))) {
            LOGD("Error updating encryption");
        }
        ciphertext_len = len;

        if (1 != EVP_EncryptFinal_ex(ctx, enc_out + len, &len)) LOGD("Error encrypt final");
        ciphertext_len += len;
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_array] = encryption_time;

        EVP_CIPHER_CTX_set_padding(ctx, 0);
        memcpy(iv_to_use, iv, 16);
        //memset(iv, 0x00, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly
        gettimeofday(&st, NULL);


        if (1 != EVP_DecryptUpdate(ctx_dec, dec_out, &len, enc_out, ciphertext_len))
            LOGD("Error updating Decryption");
        plaintext_len = len;

        if (1 != EVP_DecryptFinal_ex(ctx_dec, dec_out + len, &len))LOGD("Error final");
        plaintext_len += len;
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_array + 1] = decryption_time;

        index_array +=2;
    }

    EVP_CIPHER_CTX_free(ctx);

    /* *//* Printing and Verifying *//*
    print_data("\n Original ",aes_input, sizeof(aes_input)); // you can not print data as a string, because after Encryption its not ASCII

    print_data("\n Encrypted",enc_out, sizeof(enc_out));

    print_data("\n Decrypted",dec_out, sizeof(dec_out));*/

    env->SetIntArrayRegion(result, 0, array_len, fill);

    return result;

}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESGCM(JNIEnv *env, jobject instance,jint blocksize,jint rep_aes) {

    LOGD("AES/GCM");
    jintArray result;
    int array_len = rep_aes * 2;
    result = env->NewIntArray(array_len);
    jint fill[array_len];

    EVP_CIPHER_CTX *ctx;

    unsigned char aes_key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    unsigned char plaintext[blocksize];
    RAND_bytes(plaintext, sizeof(plaintext));

    unsigned char ciphertext[blocksize];
    unsigned char tag[16];

    unsigned char decrypted[blocksize];

    int len;

    int ciphertext_len;

    struct timeval st,et;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) LOGD("Error at ctx new");

    /* Initialise the encryption operation. */

    EVP_CIPHER_CTX *ctx_dec;
    int len_dec;
    int plaintext_len_dec;
    int ret_dec;

    if(!(ctx_dec = EVP_CIPHER_CTX_new())) LOGD("Error init new 2");

    int index_array = 0;
    for (int i = 0; i < rep_aes ; ++i) {

        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
            LOGD("Error at encryptInit");

        /* Set IV length if default 12 bytes (96 bits) is not appropriate */
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL))
            LOGD("Error at CTX Ctrl Encrypt");

        /* Initialise key and IV */
        if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv)) LOGD("Error initializasing");


        /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_gcm(), NULL, NULL, NULL))
        LOGD("Error at DecryptaInit");

    if(!EVP_CIPHER_CTX_ctrl(ctx_dec, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL))
        LOGD("Error at CTX control");

    LOGD("We are good");

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx_dec, NULL, NULL, aes_key, iv)) LOGD("Error at decryptinit");

        gettimeofday(&st, NULL);
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext)))
            LOGD("Error at encrypt updated");
        ciphertext_len = len;

        /* Finalise the encryption. Normally ciphertext bytes may be written at
         * this stage, but this does not occur in GCM mode
         */
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) LOGD("Error at encrypt final");

        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_array] = encryption_time;

        ciphertext_len += len;

        /* Get the tag */
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
            LOGD("Error getting tag");

        LOGD("Finished encryption");


        gettimeofday(&st, NULL);
        if (!EVP_DecryptUpdate(ctx_dec, decrypted, &len_dec, ciphertext, ciphertext_len))
            LOGD("Error decryptupdate");
        plaintext_len_dec = len_dec;

        if (!EVP_CIPHER_CTX_ctrl(ctx_dec, EVP_CTRL_GCM_SET_TAG, 16, tag))
            LOGD("Error at ctrl tag");

        int ret = EVP_DecryptFinal_ex(ctx_dec, decrypted + len_dec, &len_dec);
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_array + 1] = decryption_time;

        if (ret > 0) {
            /* Success */
            LOGD("Success");
        } else {
            /* Verify failed */
            LOGD("FAIL");
        }
        index_array +=2;
    }
    env->SetIntArrayRegion(result, 0, array_len, fill);

    return result;

}

void print_data(const char *tittle, const void* data, int len)
{
    LOGD("%s : ",tittle);
    const unsigned char * p = (const unsigned char*)data;
    int i = 0;

    for (; i<len; ++i)
        LOGD("%02X ", *p++);

    LOGD("\n");
}


extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_MD5(JNIEnv *env, jobject instance,jint blocksize,jint rep_hash) {

    jintArray result;
    result = env->NewIntArray(rep_hash);
    jint fill[rep_hash];

    struct timeval st,et;

    unsigned char c[MD5_DIGEST_LENGTH];

    MD5_CTX ctx;

    MD5_Init(&ctx);

    int ret;

    size_t bytes = blocksize;

    unsigned char data[blocksize];
    RAND_bytes(data, sizeof(data));

    for (int i = 0; i < rep_hash; ++i) {


        gettimeofday(&st, NULL);

        ret = MD5_Update(&ctx, data, blocksize);

        if (ret != 1) {
            LOGD("Error updating");
        }

        ret = MD5_Final(c, &ctx);
        if (ret != 1) {
            LOGD("Error final");
        }

        gettimeofday(&et, NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fill[i] = generation_time;
    }
    /*LOGD("Here starts:");
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
        LOGD("%x", c[i]);
    }*/

    LOGD("MD5 finished succesfully");


    env->SetIntArrayRegion(result, 0, rep_hash, fill);
    return result;

}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_DH(JNIEnv *env, jobject instance,jint rep_agree) {

    jintArray result;
    result = env->NewIntArray(rep_agree);
    jint fill[rep_agree];
    jintArray error;
    struct timeval st, et;

    LOGD("Starting");
    DH *privkey = DH_new();

    const char *p = "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F";

    const char *g = "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA";

    unsigned char *secret;

    DH *pubkey = DH_new();


    BIGNUM *prime = BN_new();
    BIGNUM *generator = BN_new();


    BN_hex2bn(&generator, g);

    BN_hex2bn(&prime, p);


    int ret = DH_set0_pqg(privkey, prime, NULL, generator);

    if (ret != 1) {

        LOGD("Error at setting");

        return error;

    }


    if (1 != DH_generate_key(privkey)) LOGD("Error at generating key");

    ret = DH_set0_pqg(pubkey, prime, NULL, generator);

    if (ret != 1) {
        LOGD("Error at setting");
        return error;
    }

    int secret_size;

    if (1 != DH_generate_key(pubkey)) LOGD("Error at generating key");

    if (NULL == (secret = static_cast<unsigned char *>(OPENSSL_malloc(
            sizeof(unsigned char) * (DH_size(privkey))))))
        LOGD("Error at malloc");

    BIGNUM *publico = pubkey->pub_key;

    int i = 0;
    for (i = 0; i < rep_agree; i++) {
    gettimeofday(&st, NULL);
    secret_size = DH_compute_key(secret, publico, privkey);
    gettimeofday(&et, NULL);

    int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[i] = encryption_time;
    if(0 > secret_size){ LOGD("Error computing first secret");}
}



    LOGD("We are fine");



    env->SetIntArrayRegion(result, 0, rep_agree, fill);

    return result;
}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESOFB(JNIEnv *env, jobject instance,jint blocksize,jint rep_aes) {
    LOGD("AES/OFB");
    jintArray result;
    int array_len = rep_aes * 2;
    result = env->NewIntArray(array_len);
    jint fill[array_len];


    EVP_CIPHER_CTX *ctx;


    unsigned char aes_key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    unsigned char plaintext[blocksize];
    RAND_bytes(plaintext, sizeof(plaintext));

    unsigned char ciphertext[blocksize];

    unsigned char decrypted[blocksize];

    int len;

    int ciphertext_len;

    struct timeval st,et;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) LOGD("Error at ctx new");

    EVP_CIPHER_CTX *ctx_dec;
    int len_dec;
    int plaintext_len_dec;
    int ret_dec;

    if(!(ctx_dec = EVP_CIPHER_CTX_new())) LOGD("Error init new 2");

    int index_array = 0;
    for (int i = 0; i < rep_aes; ++i) {


        /* Initialise the encryption operation. */
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, aes_key, iv))
            LOGD("Error at encryptInit");


        gettimeofday(&st, NULL);

        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext)))
            LOGD("Error at encrypt updated");
        ciphertext_len = len;

        /* Finalise the encryption. Normally ciphertext bytes may be written at
         * this stage, but this does not occur in GCM mode
         */
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) LOGD("Error at encrypt final");

        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_array] = encryption_time;

        ciphertext_len += len;

        LOGD("Finished encryption");


        /* Initialise the decryption operation. */
        LOGD("We are good");

        /* Initialise key and IV */
        if (!EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_ofb(), NULL, aes_key, iv))
            LOGD("Error at decryptinit");

        gettimeofday(&st, NULL);
        if (!EVP_DecryptUpdate(ctx_dec, decrypted, &len_dec, ciphertext, ciphertext_len))
            LOGD("Error decryptupdate");
        plaintext_len_dec = len_dec;


        int ret = EVP_DecryptFinal_ex(ctx_dec, decrypted + len_dec, &len_dec);
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index_array + 1] = decryption_time;

        if (ret > 0) {
            LOGD("Success");
        } else {
            LOGD("FAIL");
        }

        index_array += 2;
    }
    env->SetIntArrayRegion(result, 0, array_len, fill);

    return result;


}

/*Elliptic Curve Diffie-Hellman function*/
int EC_DH(unsigned char **secret, EC_KEY *key, const EC_POINT *pPub)
{
    int secretLen;

    secretLen = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    secretLen = (secretLen + 7) / 8;

    *secret = static_cast<unsigned char *>(malloc(secretLen));
    if (!(*secret))
        LOGD("Failed to allocate memory for secret.\n");
    secretLen = ECDH_compute_key(*secret, secretLen, pPub, key, NULL);

    return secretLen;
}

/*Key generation function for throwaway keys.*/
EC_KEY* gen_key(void)
{
    EC_KEY *key;

    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL)
        LOGD("Failed to create lKey object.\n");

    if (!EC_KEY_generate_key(key))
        LOGD("Failed to generate EC key.\n");

    return key;
}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_ECDH(JNIEnv *env, jobject instance,jint rep_agree) {

    jintArray result;
    result = env->NewIntArray(rep_agree);
    jint fill[rep_agree];

    struct timeval st,et;

    EC_KEY *lKey, *pKey;
    int lSecretLen, pSecretLen;
    unsigned char *lSecret, *pSecret;

    lKey = gen_key();
    pKey = gen_key();

    for(int i = 0; i < rep_agree; i++) {
        gettimeofday(&st, NULL);
        lSecretLen = EC_DH(&lSecret, lKey, EC_KEY_get0_public_key(pKey));
        gettimeofday(&et, NULL);
        pSecretLen = EC_DH(&pSecret, pKey, EC_KEY_get0_public_key(lKey));
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[i] = generation_time;

        if (lSecretLen != pSecretLen)
            LOGD("SecretLen mismatch.\n");

        if (memcmp(lSecret, pSecret, lSecretLen))
            LOGD("Secrets don't match.\n");
    }
    free(lSecret);
    free(pSecret);
    EC_KEY_free(lKey);
    EC_KEY_free(pKey);
    CRYPTO_cleanup_all_ex_data();

    LOGD("Elliptic Curve Diffie Hellman finished");

    env->SetIntArrayRegion(result, 0, rep_agree, fill);

    return result;


}


//Now we have the functions that will be used to perform the cryptographic algorithm in function of
//of the time provided

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_RSATime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_rsa) {


    struct timeval st,et;
    int repetitions_rsa = 0,repetitions_key = 0;

   FILE* report = create_file();
    if(report == NULL){
        LOGD("Error rediang the file");

    }

    fprintf(report,"************BoringSSL/RSA**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);

    char plainText[blocksize];

    for (int i = 0; i < blocksize ; ++i) {
        plainText[i] = rand();
    }

    unsigned char  encrypted[4098]={};
    unsigned char decrypted[4098]={};

    char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
"wQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

    char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
"-----END RSA PRIVATE KEY-----\n";


    RSA *rsa= NULL;


    fprintf(report,"************BoringSSL/RSA**************\n");

    time_t start_key = time(NULL);
    time_t now_key = time(NULL);

    while ((now_key - start_key) <= rep_key) {

        gettimeofday(&st, NULL);
    BIO *keybio ;
    keybio = BIO_new_mem_buf(publicKey, -1);
    if (keybio==NULL)
    {
        LOGD( "Failed to create key BIO");
        return;
    }

    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);

    if(rsa == NULL)
    {
        LOGD( "Failed to create RSA");
    }

    if(rsa == NULL)
    {
        LOGD( "Failed to create RSA_priv");
    }
        gettimeofday(&et, NULL);
        int setting_key_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to set key: %i ms\n", setting_key_time);
        repetitions_key += 1;
        now_key = time(NULL);
    }
    fprintf(report,"Key set: %i times\n", repetitions_key);
    time_t start = time(NULL);
    time_t now = time(NULL);

    while ((now - start) <= rep_rsa) {


        gettimeofday(&st, NULL);
        int encrypted_length = RSA_public_encrypt(strlen(plainText),
                                                  reinterpret_cast<const unsigned char *>(plainText),
                                                  encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fprintf(report,"Time to encrypt: %i ms\n", encryption_time);

        if (encrypted_length == -1) {
            LOGD("Public Encrypt failed ");
            exit(0);
        }

        //int decrypted_length = private_decrypt(encrypted, encrypted_length,
        //reinterpret_cast<unsigned char *>(privateKey), decrypted);

        RSA *rsa_priv = createRSA(reinterpret_cast<unsigned char *>(privateKey), 0);
        gettimeofday(&st, NULL);
        int decrypted_length = RSA_private_decrypt(encrypted_length, encrypted, decrypted, rsa_priv,
                                                   RSA_PKCS1_OAEP_PADDING);
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to decrypt: %i ms\n", decryption_time );

        if (decrypted_length == -1) {
            LOGD("Private Decrypt failed ");
            exit(0);
        }

        repetitions_rsa += 1;
        now = time(NULL);
    }

    LOGD("We are good");

    fprintf(report, "Times performed: %i \n",repetitions_rsa);
    fprintf(report,"*****************************");
    fclose (report);

    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_MD5Time(JNIEnv *env, jobject instance,
                                                         jint blocksize, jint rep_hash) {

    struct timeval st,et;

    FILE* report = create_file();

    fprintf(report,"************BoringSSL/MD5**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);
    unsigned char c[MD5_DIGEST_LENGTH];

    MD5_CTX ctx;

    MD5_Init(&ctx);

    int ret;

    size_t bytes = blocksize;

    unsigned char data[blocksize];
    RAND_bytes(data, sizeof(data));

    int repetitions = 0;

    time_t start = time(NULL);
    time_t now = time(NULL);

    while ((now - start) <= rep_hash) {

        gettimeofday(&st, NULL);

        ret = MD5_Update(&ctx, data, blocksize);

        if (ret != 1) {
            LOGD("Error updating");
        }

        ret = MD5_Final(c, &ctx);
        if (ret != 1) {
            LOGD("Error final");
        }

        gettimeofday(&et, NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fprintf(report,"Time to generate hash: %i ms\n", generation_time);

        now = time(NULL);
        repetitions +=1;

    }
    fprintf(report, "Times performed: %i \n",repetitions);
    fprintf(report,"*****************************");
    fclose(report);
    LOGD("MD5 finished succesfully");

    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_DHTime(JNIEnv *env, jobject instance,jint rep_key,
                                                        jint rep_agree) {

    FILE* report = create_file();
    struct timeval st, et;

    LOGD("Starting");

    fprintf(report,"************BoringSSL/DH**************\n");

    BIGNUM *publico;
    int secret_size;
    DH *privkey;
    DH *pubkey;

    const char *p = "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F";

    const char *g = "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA";

    unsigned char *secret;

    int repetitions = 0;


    time_t start_key = time(NULL);
    time_t now_key = time(NULL);

    while ((now_key - start_key) <= rep_key) {

        gettimeofday(&st,NULL);
        privkey = DH_new();
        pubkey = DH_new();

        BIGNUM *prime = BN_new();
        BIGNUM *generator = BN_new();


        BN_hex2bn(&generator, g);

        BN_hex2bn(&prime, p);


        int ret = DH_set0_pqg(privkey, prime, NULL, generator);

        if (ret != 1) {

            LOGD("Error at setting");

            return;

        }


        if (1 != DH_generate_key(privkey)) LOGD("Error at generating key");

        ret = DH_set0_pqg(pubkey, prime, NULL, generator);

        if (ret != 1) {
            LOGD("Error at setting");
            return;
        }



        if (1 != DH_generate_key(pubkey)) LOGD("Error at generating key");

        if (NULL == (secret = static_cast<unsigned char *>(OPENSSL_malloc(
                sizeof(unsigned char) * (DH_size(privkey))))))
            LOGD("Error at malloc");

        publico = pubkey->pub_key;
        gettimeofday(&st,NULL);


            now_key = time(NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fprintf(report, "Time to set key: %i \n",generation_time);
            repetitions +=1;
        }

        fprintf(report, "Times set key: %i \n",repetitions);

        time_t start = time(NULL);
        time_t now = time(NULL);

        repetitions = 0;
        while ((now - start) <= rep_agree) {

            gettimeofday(&st, NULL);
            secret_size = DH_compute_key(secret, publico, privkey);
            gettimeofday(&et, NULL);

            int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

            fprintf(report,"Time for key agreement: %i ms\n",generation_time);
            if(0 > secret_size){ LOGD("Error computing first secret");}
            now = time(NULL);
            repetitions +=1;
        }

        fprintf(report, "Times performed: %i \n",repetitions);
        fprintf(report,"*****************************");
        fclose(report);
        fclose(report);

        LOGD("We are fine");

    fprintf(report,"*****************************");
    fclose(report);

    return ;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_ECDHTime(JNIEnv *env, jobject instance,jint rep_key,jint rep_agree) {

    FILE* report = create_file();
    struct timeval st,et;
    int repetitions = 0;
    fprintf(report,"************BoringSSL/RSA**************\n");

    EC_KEY *lKey, *pKey;
    int lSecretLen, pSecretLen;
    unsigned char *lSecret, *pSecret;

    time_t start = time(NULL);
    time_t now = time(NULL);

    while ((now - start) <= rep_key) {
        gettimeofday(&st, NULL);
        lKey = gen_key();
        pKey = gen_key();
        gettimeofday(&et, NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fprintf(report, "Time to set keys: %i ms\n",generation_time);
        repetitions +=1;
        now = time(NULL);
    }
    fprintf(report, "Times set key : %i \n",repetitions);

    repetitions = 0;
    while ((now - start) <= rep_agree) {
        gettimeofday(&st, NULL);
        lSecretLen = EC_DH(&lSecret, lKey, EC_KEY_get0_public_key(pKey));
        gettimeofday(&et, NULL);
        pSecretLen = EC_DH(&pSecret, pKey, EC_KEY_get0_public_key(lKey));
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report, "Time to generate key agreement: %i ms\n",generation_time);

        if (lSecretLen != pSecretLen)
            LOGD("SecretLen mismatch.\n");

        if (memcmp(lSecret, pSecret, lSecretLen))
            LOGD("Secrets don't match.\n");
        now = time(NULL);
        repetitions +=1;
    }

    fprintf(report, "Times performed : %i \n",repetitions);
    free(lSecret);
    free(pSecret);
    EC_KEY_free(lKey);
    EC_KEY_free(pKey);
    CRYPTO_cleanup_all_ex_data();

    LOGD("Elliptic Curve Diffie Hellman finished");

    fprintf(report,"*****************************");
    fclose(report);

    return;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESCBCTime(JNIEnv *env, jobject instance,jint blocksize,int rep_key,int rep_aes) {

    LOGD("AES/CBC");


    FILE* report = create_file();
    fprintf(report,"************BoringSSL/AESCBC**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);
    struct timeval st,et;
    unsigned char aes_key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    unsigned char iv_to_use[16];

    /* Input data to encrypt */
    unsigned char aes_input[blocksize];
    RAND_bytes(aes_input, sizeof(aes_input));

    unsigned char enc_out[sizeof(aes_input)];
    unsigned char dec_out[sizeof(aes_input)];

    /* AES-128 bit CBC Encryption */
    AES_KEY enc_key, dec_key;


    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions = 0;
    while ((now - start) <= rep_key) {
        memcpy(iv_to_use, iv, 16);

        gettimeofday(&st,NULL);

        AES_set_encrypt_key(aes_key, sizeof(aes_key) * 8, &enc_key);
        AES_set_decrypt_key(aes_key, sizeof(aes_key) * 8, &dec_key); // Size of key is in bits
        gettimeofday(&et,NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);


        fprintf(report,"Time to set key: %i ms \n",generation_time);
        now = time(NULL);
        repetitions  += 1;
    }

    fprintf(report,"Times key set: %i ms \n",repetitions);
    start = time(NULL);
    now = time(NULL);
    repetitions = 0;
    while ((now - start) <= rep_aes) {
        gettimeofday(&st, NULL);

        AES_cbc_encrypt(aes_input, enc_out, sizeof(aes_input), &enc_key, iv_to_use, AES_ENCRYPT);
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to encrypt: %i ms\n", encryption_time);

        /* AES-128 bit CBC Decryption */

        clock_t begin1 = clock();
        memcpy(iv_to_use, iv, 16);
        gettimeofday(&st, NULL);
        AES_cbc_encrypt(enc_out, dec_out, sizeof(aes_input), &dec_key, iv_to_use, AES_DECRYPT);
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fprintf(report,"Time to decrypt: %i ms\n", decryption_time);

        now = time(NULL);
        repetitions  += 1;
    }

    fprintf(report,"Times performed: %i ms \n",repetitions);

    /* Printing and Verifying */
    //print_data("\n Original ",aes_input, sizeof(aes_input)); // you can not print data as a string, because after Encryption its not ASCII

    //print_data("\n Encrypted",enc_out, sizeof(enc_out));

    //print_data("\n Decrypted",dec_out, sizeof(dec_out));

    LOGD("Finished AES/CBC");

    fprintf(report,"*****************************");
    fclose(report);

    return;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESCTRTime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_aes) {

    FILE* report = create_file();
    fprintf(report,"************BoringSSL/AESCTR**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);


    EVP_CIPHER_CTX *ctx, *ctx_dec;
    int len;

    int ciphertext_len;
    int plaintext_len;

    struct timeval st,et;
    unsigned char aes_key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    unsigned char iv_to_use[16];


    if(!(ctx = EVP_CIPHER_CTX_new())) LOGD("Error creating CTX");
    if(!(ctx_dec = EVP_CIPHER_CTX_new())) LOGD("Error creating CTX_DEC");

    /* Input data to encrypt */
    unsigned char aes_input[blocksize];
    RAND_bytes(aes_input, sizeof(aes_input));

    /* Init vector */
    //unsigned char iv[AES_BLOCK_SIZE];
    //memset(iv, 0x00, AES_BLOCK_SIZE);

    memcpy(iv_to_use,iv,16);
    /* Buffers for Encryption and Decryption */
    unsigned char enc_out[sizeof(aes_input)];
    unsigned char dec_out[sizeof(aes_input)];

    /* AES-128 bit CBC Encryption */
    AES_KEY enc_key, dec_key;

    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions = 0;
    while ((now - start) <= rep_key) {

        gettimeofday(&st,NULL);
        AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, &enc_key);


        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, aes_key, iv))
            LOGD("Error encrypting");

        if (1 != EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_ctr(), NULL, aes_key, iv))
            LOGD("Error start decrypting");

        gettimeofday(&et,NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);


        fprintf(report,"Time to set key: %i ms \n",generation_time);
        now = time(NULL);
        repetitions  += 1;
    }
    fprintf(report,"Times key set: %i ms \n",repetitions);

    start = time(NULL);
    now = time(NULL);
    repetitions = 0;
    while ((now - start) <= rep_aes) {

        if (1 != EVP_EncryptUpdate(ctx, enc_out, &len, aes_input, sizeof(aes_input))) {
            LOGD("Error updating encryption");
        }
        ciphertext_len = len;

        if (1 != EVP_EncryptFinal_ex(ctx, enc_out + len, &len)) LOGD("Error encrypt final");
        ciphertext_len += len;
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to encrypt: %i ms\n", encryption_time);


        EVP_CIPHER_CTX_set_padding(ctx, 0);
        memcpy(iv_to_use, iv, 16);
        //memset(iv, 0x00, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly
        gettimeofday(&st, NULL);


        if (1 != EVP_DecryptUpdate(ctx_dec, dec_out, &len, enc_out, ciphertext_len))
            LOGD("Error updating Decryption");
        plaintext_len = len;

        if (1 != EVP_DecryptFinal_ex(ctx_dec, dec_out + len, &len))LOGD("Error final");
        plaintext_len += len;
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to decrypt: %i ms\n", decryption_time);
        now = time(NULL);
        repetitions  += 1;
    }

    fprintf(report,"Times performed: %i ms \n",repetitions);

    EVP_CIPHER_CTX_free(ctx);

    fprintf(report,"*****************************");
    fclose(report);

    /* *//* Printing and Verifying *//*
    print_data("\n Original ",aes_input, sizeof(aes_input)); // you can not print data as a string, because after Encryption its not ASCII

    print_data("\n Encrypted",enc_out, sizeof(enc_out));

    print_data("\n Decrypted",dec_out, sizeof(dec_out));*/



    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESGCMTime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_aes) {

    LOGD("AES/GCM");


    FILE* report = create_file();
    fprintf(report,"************BoringSSL/AESGCM**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);

    EVP_CIPHER_CTX *ctx;

    unsigned char aes_key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    unsigned char plaintext[blocksize];
    RAND_bytes(plaintext, sizeof(plaintext));

    unsigned char ciphertext[blocksize];
    unsigned char tag[16];

    unsigned char decrypted[blocksize];

    int len;

    int ciphertext_len;

    struct timeval st,et;

    EVP_CIPHER_CTX *ctx_dec;
    int len_dec;
    int plaintext_len_dec;
    int ret_dec;

    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions = 0;

    while ((now - start) <= rep_key) {

        gettimeofday(&st,NULL);
        /* Create and initialise the context */
        if(!(ctx = EVP_CIPHER_CTX_new())) LOGD("Error at ctx new");

        /* Initialise the encryption operation. */


        if(!(ctx_dec = EVP_CIPHER_CTX_new())) LOGD("Error init new 2");


        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
            LOGD("Error at encryptInit");

        /* Set IV length if default 12 bytes (96 bits) is not appropriate */
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL))
            LOGD("Error at CTX Ctrl Encrypt");

        /* Initialise key and IV */
        if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv)) LOGD("Error initializasing");


        /* Initialise the decryption operation. */
        if(!EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_gcm(), NULL, NULL, NULL))
            LOGD("Error at DecryptaInit");

        if(!EVP_CIPHER_CTX_ctrl(ctx_dec, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL))
            LOGD("Error at CTX control");

        LOGD("We are good");

        /* Initialise key and IV */
        if(!EVP_DecryptInit_ex(ctx_dec, NULL, NULL, aes_key, iv)) LOGD("Error at decryptinit");
        gettimeofday(&et,NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to set key: %i ms\n",generation_time);

        repetitions  += 1;

        now = time(NULL);
    }

    fprintf(report,"Times  key: %i ms\n",repetitions);


    start = time(NULL);
    now = time(NULL);
    repetitions = 0;
    while ((now - start) <= rep_aes) {


        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
            LOGD("Error at encryptInit");

        /* Set IV length if default 12 bytes (96 bits) is not appropriate */
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL))
            LOGD("Error at CTX Ctrl Encrypt");

        /* Initialise key and IV */
        if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv)) LOGD("Error initializasing");


        /* Initialise the decryption operation. */
        if(!EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_gcm(), NULL, NULL, NULL))
            LOGD("Error at DecryptaInit");

        if(!EVP_CIPHER_CTX_ctrl(ctx_dec, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL))
            LOGD("Error at CTX control");

        LOGD("We are good");

        /* Initialise key and IV */
        if(!EVP_DecryptInit_ex(ctx_dec, NULL, NULL, aes_key, iv)) LOGD("Error at decryptinit");


        gettimeofday(&st, NULL);
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext)))
            LOGD("Error at encrypt updated");
        ciphertext_len = len;

        /* Finalise the encryption. Normally ciphertext bytes may be written at
         * this stage, but this does not occur in GCM mode
         */
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) LOGD("Error at encrypt final");

        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to encrypt: %i ms\n", encryption_time);

        ciphertext_len += len;

        /* Get the tag */
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
            LOGD("Error getting tag");

        LOGD("Finished encryption");


        gettimeofday(&st, NULL);
        if (!EVP_DecryptUpdate(ctx_dec, decrypted, &len_dec, ciphertext, ciphertext_len))
            LOGD("Error decryptupdate");
        plaintext_len_dec = len_dec;

        if (!EVP_CIPHER_CTX_ctrl(ctx_dec, EVP_CTRL_GCM_SET_TAG, 16, tag))
            LOGD("Error at ctrl tag");

        int ret = EVP_DecryptFinal_ex(ctx_dec, decrypted + len_dec, &len_dec);
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to decrypt: %i ms\n", decryption_time);

        if (ret > 0) {
            /* Success */
            LOGD("Success");
        } else {
            /* Verify failed */
            LOGD("FAIL");
        }

        now = time(NULL);
        repetitions  += 1;
    }

    fprintf(report,"Times performed: %i ms\n",repetitions);
    fprintf(report,"*****************************");
    fclose(report);

    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESOFBTime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_aes) {

    LOGD("AES/OFB");

    FILE* report = create_file();
    fprintf(report,"************BoringSSL/AESOFB**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);

    int repetitions = 0;

    EVP_CIPHER_CTX *ctx;


    unsigned char aes_key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf, 0x15, 0x88, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0xae, 0x16, 0x28, 0xd2, 0xa6,
            0xab, 0xf7,

    };

    EVP_CIPHER_CTX *ctx_dec;
    int len_dec;
    int plaintext_len_dec;
    int ret_dec;

    unsigned char plaintext[blocksize];
    RAND_bytes(plaintext, sizeof(plaintext));

    unsigned char ciphertext[blocksize];

    unsigned char decrypted[blocksize];

    int len;

    int ciphertext_len;

    struct timeval st, et;

    time_t start = time(NULL);
    time_t now = time(NULL);


    while ((now - start) <= rep_key) {

        gettimeofday(&st, NULL);
        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new())) LOGD("Error at ctx new");



        if (!(ctx_dec = EVP_CIPHER_CTX_new())) LOGD("Error init new 2");

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, aes_key, iv))
            LOGD("Error at encryptInit");


        gettimeofday(&st, NULL);

        if (!EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_ofb(), NULL, aes_key, iv))
            LOGD("Error at decryptinit");

        gettimeofday(&et,NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fprintf(report,"Time to set key: %i ms\n",generation_time);

        repetitions  += 1;

        now = time(NULL);
    }

    fprintf(report,"Times set key: %i ms\n",repetitions);


    start = time(NULL);
    now = time(NULL);
    repetitions = 0;
    while ((now - start) <= rep_aes) {


        /* Initialise the encryption operation. */
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, aes_key, iv))
            LOGD("Error at encryptInit");


        gettimeofday(&st, NULL);

        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext)))
            LOGD("Error at encrypt updated");
        ciphertext_len = len;

        /* Finalise the encryption. Normally ciphertext bytes may be written at
         * this stage, but this does not occur in GCM mode
         */
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) LOGD("Error at encrypt final");

        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fprintf(report,"Time to encrypt: %i ms\n", encryption_time);


        ciphertext_len += len;

        LOGD("Finished encryption");


        /* Initialise the decryption operation. */
        LOGD("We are good");

        /* Initialise key and IV */
        if (!EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_ofb(), NULL, aes_key, iv))
            LOGD("Error at decryptinit");

        gettimeofday(&st, NULL);
        if (!EVP_DecryptUpdate(ctx_dec, decrypted, &len_dec, ciphertext, ciphertext_len))
            LOGD("Error decryptupdate");
        plaintext_len_dec = len_dec;


        int ret = EVP_DecryptFinal_ex(ctx_dec, decrypted + len_dec, &len_dec);
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to decrypt: %i ms\n", decryption_time);

        if (ret > 0) {
            LOGD("Success");
        } else {
            LOGD("FAIL");
        }

        repetitions  += 1;

        now = time(NULL);
    }

    fprintf(report,"Times performed: %i ms\n",repetitions);
    fprintf(report,"*****************************");
    fclose(report);

    return;
}
