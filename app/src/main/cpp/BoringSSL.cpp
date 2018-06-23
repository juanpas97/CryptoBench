
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
    report = fopen("/sdcard/CryptoBench/Report.txt", "ab+");
    if (report) {
        LOGD("Report created");
        return report;
    }
    return NULL; // error
}

FILE *create_file_text(const char *title)
{
    char title_location[100];
    strcpy(title_location,"/sdcard/CryptoBench/Special_test_");
    //char temp[6] ="abcd";
    //strcpy(temp,title);
    strcat(title_location, title);
    strcat(title_location,".txt");
    LOGD("title location is: %s",title_location);
    FILE *report = NULL;
    report = fopen(title_location, "ab+");
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
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_RSA(JNIEnv *env, jobject instance,jint blocksize,jint rep_rsa,jint rep_total) {

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

    FILE *report = create_file();
    int print_Res = fprintf(report, "************BoringSSL/RSA**************\n");

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

    int encrypted_length = 0;

    for(int j = 0; j < rep_total; j++){

        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int i = 0; i < rep_rsa; ++i) {

            encrypted_length = RSA_public_encrypt(strlen(plainText),
                                                  reinterpret_cast<const unsigned char *>(plainText),
                                                  encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
            if (encrypted_length == -1) {
                LOGD("Public Encrypt failed ");
                exit(0);
            }

            repetitions += 1;
        }
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to encrypt: %f bytes/second \n", result_agree);
    }

    //int decrypted_length = private_decrypt(encrypted, encrypted_length,
    //reinterpret_cast<unsigned char *>(privateKey), decrypted);
    for(int j = 0; j < rep_total; j++){
        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int i = 0; i < rep_rsa; ++i) {
            RSA *rsa_priv = createRSA(reinterpret_cast<unsigned char *>(privateKey), 0);
            gettimeofday(&st, NULL);
            int decrypted_length = RSA_private_decrypt(encrypted_length, encrypted, decrypted, rsa_priv,
                                                       RSA_PKCS1_OAEP_PADDING);

            if (decrypted_length == -1) {
                LOGD("Private Decrypt failed ");
                exit(0);
            }

            repetitions += 1;
        }
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to decrypt: %f bytes/second \n", result_agree);
    }

    LOGD("We are good");

    fprintf(report, "*****************************\n");
    fclose(report);

    return;

}



extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESCBC(JNIEnv *env, jobject instance, jint blocksize,jint rep_aes,jint rep_total) {

    LOGD("AES/CBC");

    FILE *report = create_file();
    int print_Res = fprintf(report, "************BoringSSL/AESCBC**************\n");
    fprintf(report, "Size of blocksize: %i \n", blocksize);

    jintArray result;
    int array_len = rep_aes * 2;
    result = env->NewIntArray(array_len);
    jint fill[array_len];

    struct timeval st, et;
    unsigned char aes_key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf, 0x15, 0x88, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0xae, 0x16, 0x28, 0xd2, 0xa6,
            0xab, 0xf7,

    };

    unsigned char iv_to_use[16];

    /* Input data to encrypt */
    unsigned char aes_input[blocksize];
    RAND_bytes(aes_input, sizeof(aes_input));

    /* Init vector */
    //unsigned char iv[AES_BLOCK_SIZE];

    memcpy(iv_to_use, iv, 16);
    /* Buffers for Encryption and Decryption */
    unsigned char enc_out[sizeof(aes_input)];
    unsigned char dec_out[sizeof(aes_input)];

    /* AES-128 bit CBC Encryption */
    AES_KEY enc_key, dec_key;

    AES_set_encrypt_key(aes_key, sizeof(aes_key) * 8, &enc_key);
    AES_set_decrypt_key(aes_key, sizeof(aes_key) * 8, &dec_key); // Size of key is in bits

    for (int j = 0; j < rep_total; j++) {

        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int i = 0; i < rep_aes; i++) {

            AES_cbc_encrypt(aes_input, enc_out, sizeof(aes_input), &enc_key, iv_to_use, AES_ENCRYPT);

            /* AES-128 bit CBC Decryption */
            repetitions += 1;
        }
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to encrypt: %f byte/seconds \n", result_agree);
    }

    for (int j = 0; j < rep_total; j++) {
        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int i = 0; i < rep_aes; i++) {
            //We have to copy the iv every time as in the process of encrypting the iv will be modified.
            memcpy(iv_to_use, iv, 16);
            AES_cbc_encrypt(enc_out, dec_out, sizeof(aes_input), &dec_key, iv_to_use, AES_DECRYPT);

            repetitions += 1;
        }
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
    }
    LOGD("Finished AES/CBC");

    fprintf(report, "*****************************\n");
    fclose(report);

    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESCTR(JNIEnv *env, jobject instance,jint blocksize,jint rep_aes,jint rep_total) {
    LOGD("AES/CTR");
    FILE *report = create_file();
    fprintf(report, "************BoringSSL/AESCTR**************\n");
    fprintf(report, "Size of blocksize: %i \n", blocksize);

    EVP_CIPHER_CTX *ctx, *ctx_dec;
    int len;

    int ciphertext_len = 0;
    int plaintext_len;

    struct timeval st, et;
    unsigned char aes_key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf, 0x15, 0x88, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0xae, 0x16, 0x28, 0xd2, 0xa6,
            0xab, 0xf7,

    };

    unsigned char iv_to_use[16];
    if (!(ctx = EVP_CIPHER_CTX_new())) LOGD("Error creating CTX");
    if (!(ctx_dec = EVP_CIPHER_CTX_new())) LOGD("Error creating CTX_DEC");

    /* Input data to encrypt */
    unsigned char aes_input[blocksize];
    RAND_bytes(aes_input, sizeof(aes_input));

    /* Init vector */
    //unsigned char iv[AES_BLOCK_SIZE];
    //memset(iv, 0x00, AES_BLOCK_SIZE);

    memcpy(iv_to_use, iv, 16);
    /* Buffers for Encryption and Decryption */
    unsigned char enc_out[sizeof(aes_input)];
    unsigned char dec_out[sizeof(aes_input)];

    /* AES-128 bit CBC Encryption */
    AES_KEY enc_key, dec_key;


    AES_set_encrypt_key(aes_key, sizeof(aes_key) * 8, &enc_key);


    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, aes_key, iv))
        LOGD("Error encrypting");

    if (1 != EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_ctr(), NULL, aes_key, iv))
        LOGD("Error start decrypting");

    for (int j = 0; j < rep_total; j++) {

        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int i = 0; i < rep_aes - 1; ++i) {

            if (1 != EVP_EncryptUpdate(ctx, enc_out, &len, aes_input, sizeof(aes_input))) {
                LOGD("Error updating encryption");
            }
            ciphertext_len = len;


            repetitions += 1;
        }
        if (1 != EVP_EncryptFinal_ex(ctx, enc_out + len, &len)) LOGD("Error encrypt final");
        ciphertext_len += len;
        repetitions +=1;
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to encrypt: %f byte/seconds \n", result_agree);
    }


    EVP_CIPHER_CTX_set_padding(ctx, 0);




    for (int j = 0; j < rep_total; j++) {
        memcpy(iv_to_use, iv, 16);
        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int i = 0; i < rep_aes - 1; ++i) {

            if (1 != EVP_DecryptUpdate(ctx_dec, dec_out, &len, enc_out, ciphertext_len))
                LOGD("Error updating Decryption");
            plaintext_len = len;

            repetitions += 1;
        }
        if (1 != EVP_DecryptFinal_ex(ctx_dec, dec_out + len, &len))LOGD("Error final");
        plaintext_len += len;
        repetitions += 1;
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
    }

    fprintf(report, "*****************************\n");
    fclose(report);



    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESGCM(JNIEnv *env, jobject instance,jint blocksize,jint rep_aes,jint rep_total) {
    LOGD("AES/GCM");

    FILE *report = create_file();
    fprintf(report, "************BoringSSL/AESGCM**************\n");
    fprintf(report, "Size of blocksize: %i \n", blocksize);


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

    int len = 0;

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


    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        LOGD("Error at encryptInit");

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL))
        LOGD("Error at CTX Ctrl Encrypt");

    /* Initialise key and IV */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv)) LOGD("Error initializasing");


    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_gcm(), NULL, NULL, NULL))
        LOGD("Error at DecryptaInit");

    if (!EVP_CIPHER_CTX_ctrl(ctx_dec, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL))
        LOGD("Error at CTX control");

    LOGD("We are good");

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx_dec, NULL, NULL, aes_key, iv)) LOGD("Error at decryptinit");


    for (int j = 0; j < rep_total; j++) {

        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int i = 0; i < rep_aes - 1; ++i) {
            if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext)))
                LOGD("Error at encrypt updated");
            ciphertext_len = len;

            repetitions += 1;
        }
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
            LOGD("Error at encrypt final");
        repetitions += 1;
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to encrypt: %f byte/seconds \n", result_agree);

    }


    ciphertext_len += len;

    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        LOGD("Error getting tag");

    LOGD("Finished encryption");

    for (int j = 0; j < rep_total; j++){
        int ret = 0;
        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int i = 0; i < rep_aes - 1 ; ++i) {

            if (!EVP_DecryptUpdate(ctx_dec, decrypted, &len_dec, ciphertext, ciphertext_len))
                LOGD("Error decryptupdate");
            plaintext_len_dec = len_dec;

            if (!EVP_CIPHER_CTX_ctrl(ctx_dec, EVP_CTRL_GCM_SET_TAG, 16, tag))
                LOGD("Error at ctrl tag");


            gettimeofday(&et, NULL);

            repetitions += 1;
        }
        ret = EVP_DecryptFinal_ex(ctx_dec, decrypted + len_dec, &len_dec);
        repetitions += 1;
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
    }

    fprintf(report, "*****************************\n");
    fclose(report);

    return;

}



extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_MD5(JNIEnv *env, jobject instance,jint blocksize,jint rep_hash,jint rep_total) {

    FILE *report = create_file();
    int print_Res = fprintf(report, "************BoringSSL/MD5**************\n");
    fprintf(report, "Size of blocksize: %i \n", blocksize);

    struct timeval st,et;

    unsigned char c[MD5_DIGEST_LENGTH];

    MD5_CTX ctx;

    MD5_Init(&ctx);

    int ret;

    size_t bytes = blocksize;

    unsigned char data[blocksize];
    RAND_bytes(data, sizeof(data));

    for (int j = 0; j < rep_total; ++j) {
        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int i = 0; i < rep_hash - 1 ; ++i) {

            ret = MD5_Update(&ctx, data, blocksize);

            if (ret != 1) {
                LOGD("Error updating");
            }

            repetitions += 1;
        }

        ret = MD5_Final(c, &ctx);
        if (ret != 1) {
            LOGD("Error final");
        }

        repetitions += 1;
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time hashing: %f bytes/second \n", result_agree);
    }

    LOGD("Hash finished");

    LOGD("MD5 finished succesfully");


    fprintf(report, "*****************************\n");
    fclose(report);
    return ;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_DH(JNIEnv *env, jobject instance,jint rep_agree,jint rep_total) {

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

    FILE *report = create_file();
    fprintf(report, "************BoringSSL/DH**************\n");

    BIGNUM *prime = BN_new();
    BIGNUM *generator = BN_new();


    BN_hex2bn(&generator, g);

    BN_hex2bn(&prime, p);


    int ret = DH_set0_pqg(privkey, prime, NULL, generator);

    if (ret != 1) {

        LOGD("Error at setting");

        return ;

    }


    if (1 != DH_generate_key(privkey)) LOGD("Error at generating key");

    ret = DH_set0_pqg(pubkey, prime, NULL, generator);

    if (ret != 1) {
        LOGD("Error at setting");
        return ;
    }

    int secret_size;

    if (1 != DH_generate_key(pubkey)) LOGD("Error at generating key");

    if (NULL == (secret = static_cast<unsigned char *>(OPENSSL_malloc(
            sizeof(unsigned char) * (DH_size(privkey))))))
        LOGD("Error at malloc");

    BIGNUM *publico = pubkey->pub_key;

    for (int j = 0; j < rep_total; j++) {
    int repetitions = 0;
        gettimeofday(&st, NULL);
    for (int i = 0; i < rep_agree; i++) {
    secret_size = DH_compute_key(secret, publico, privkey);
    if(0 > secret_size){ LOGD("Error computing first secret");}

        repetitions += 1;
    }

    gettimeofday(&et, NULL);
    double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = (repetitions) / time;

    fprintf(report, "Repetitions: %i \n", repetitions);
    fprintf(report, "Seconds: %f \n", time);
    fprintf(report, "Result: %f key agreements/second \n", result_agree);
}
fprintf(report, "*****************************\n");
fclose(report);



    LOGD("We are fine");

    return ;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESOFB(JNIEnv *env, jobject instance,jint blocksize,jint rep_aes,jint rep_total) {
    LOGD("AES/OFB");

    FILE *report = create_file();
    fprintf(report, "************BoringSSL/AESOFB**************\n");
    fprintf(report, "Size of blocksize: %i \n", blocksize);


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



    /* Initialise the encryption operation. */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, aes_key, iv))
        LOGD("Error at encryptInit");


    for (int j = 0; j < rep_total; j++) {

        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int i = 0; i < rep_aes - 1; ++i) {

            if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext)))
                LOGD("Error at encrypt updated");
            ciphertext_len = len;

            repetitions += 1;
        }
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
            LOGD("Error at encrypt final");
        repetitions += 1;
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
        ciphertext_len += len;
    }
    LOGD("Finished encryption");


    /* Initialise the decryption operation. */
    LOGD("We are good");

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_ofb(), NULL, aes_key, iv))
        LOGD("Error at decryptinit");

    for (int j = 0; j < rep_total; j++){

        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int i = 0; i < rep_aes - 1; ++i) {


            if (!EVP_DecryptUpdate(ctx_dec, decrypted, &len_dec, ciphertext, ciphertext_len))
                LOGD("Error decryptupdate");
            plaintext_len_dec = len_dec;
            repetitions += 1;
        }
        int ret = EVP_DecryptFinal_ex(ctx_dec, decrypted + len_dec, &len_dec);
        repetitions += 1;
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);

        if (ret > 0) {
            /* Success */
            LOGD("Success");
        } else {
            /* Verify failed */
            LOGD("FAIL");
        }
    }
    fprintf(report, "*****************************\n");
    fclose(report);

    return;


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
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_ECDH(JNIEnv *env, jobject instance,jint rep_agree,jint rep_total) {

    FILE *report = create_file();
    fprintf(report, "************BoringSSL/ECDH**************\n");

    struct timeval st,et;

    EC_KEY *lKey, *pKey;
    int lSecretLen, pSecretLen;
    unsigned char *lSecret, *pSecret;

    lKey = gen_key();
    pKey = gen_key();

    for (int j = 0; j < rep_total; j++) {

        int repetitions = 0;
        gettimeofday(&st, NULL);
        for(int i = 0; i < rep_agree; i++) {

            lSecretLen = EC_DH(&lSecret, lKey, EC_KEY_get0_public_key(pKey));
            repetitions += 1;
        }

        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions) / time;

        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Result: %f key agreements/second \n", result_agree);
    }
    fprintf(report, "*****************************\n");
    fclose(report);


    pSecretLen = EC_DH(&pSecret, pKey, EC_KEY_get0_public_key(lKey));


    if (lSecretLen != pSecretLen)
        LOGD("SecretLen mismatch.\n");

    if (memcmp(lSecret, pSecret, lSecretLen))
        LOGD("Secrets don't match.\n");

    free(lSecret);
    free(pSecret);
    EC_KEY_free(lKey);
    EC_KEY_free(pKey);
    CRYPTO_cleanup_all_ex_data();

    LOGD("Elliptic Curve Diffie Hellman finished");

    return;

}


//Now we have the functions that will be used to perform the cryptographic algorithm in function of
//of the time provided

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_RSATime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_rsa, jstring title_rand,jint rep_total) {

    const char *title = env->GetStringUTFChars(title_rand, 0);
    struct timeval st,et;
    int repetitions_rsa = 0,repetitions_key = 0;

    FILE* report = create_file_text(title);
    if(report == NULL){
        LOGD("Error rediang the file");

    }
    fprintf(report, "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
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

        now_key = time(NULL);
        repetitions_key +=1;

    }
    gettimeofday(&et, NULL);
    double time_key = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = repetitions_key / time_key;
    fprintf(report, "Repetitions: %i \n", repetitions_key);
    fprintf(report, "Seconds: %f \n", time_key);
    fprintf(report, "Result: %f Times set key/seconds \n", result_agree);

    int encrypted_length = 0;

    for (int i = 0; i < rep_total; i++) {

        time_t start = time(NULL);
        time_t now = time(NULL);
        repetitions_rsa = 0;

        gettimeofday(&st, NULL);
        while ((now - start) <= rep_rsa) {

            encrypted_length = RSA_public_encrypt(strlen(plainText),
                                                  reinterpret_cast<const unsigned char *>(plainText),
                                                  encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
            gettimeofday(&et, NULL);

            if (encrypted_length == -1) {
                LOGD("Public Encrypt failed ");
                exit(0);
            }
            repetitions_rsa +=1;
            now = time(NULL);
        }
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        result_agree = (repetitions_rsa * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions_rsa);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to encrypt: %f bytes/second \n", result_agree);
    }



    for (int i = 0; i < rep_total; i++) {

        time_t start = time(NULL);
        time_t now = time(NULL);
        repetitions_rsa = 0;
        RSA *rsa_priv = createRSA(reinterpret_cast<unsigned char *>(privateKey), 0);
        gettimeofday(&st, NULL);
        while ((now - start) <= rep_rsa) {
            int decrypted_length = RSA_private_decrypt(encrypted_length, encrypted, decrypted,
                                                       rsa_priv,
                                                       RSA_PKCS1_OAEP_PADDING);

            repetitions_rsa += 1;
            now = time(NULL);
            if (decrypted_length == -1) {
                LOGD("Private Decrypt failed ");
                exit(0);
            }
            repetitions_rsa += 1;
            now = time(NULL);
        }
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        result_agree = (repetitions_rsa * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions_rsa);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to decrypt: %f bytes/second \n", result_agree);
    }
    LOGD("Finish decryption");

    LOGD("We are good");

    fprintf(report,"*****************************");
    fclose (report);

    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_MD5Time(JNIEnv *env, jobject instance,
                                                         jint blocksize, jint rep_hash,jstring title_rand,jint rep_total) {

    struct timeval st,et;
    const char *title = env->GetStringUTFChars(title_rand, 0);
    FILE* report = create_file_text(title);

    if(report == NULL){
        LOGD("Error reading the file");
    }

    fprintf(report, "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    fprintf(report,"************BoringSSL/MD5**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);
    unsigned char c[MD5_DIGEST_LENGTH];

    MD5_CTX ctx;

    MD5_Init(&ctx);

    int ret;

    size_t bytes = blocksize;

    unsigned char data[blocksize];
    RAND_bytes(data, sizeof(data));

    for (int j = 0; j < rep_total ; j++) {
        int repetitions = 0;

        time_t start = time(NULL);
        time_t now = time(NULL);
        gettimeofday(&st, NULL);
        while ((now - start) < rep_hash) {

            ret = MD5_Update(&ctx, data, blocksize);

            if (ret != 1) {
                LOGD("Error updating");
            }

            repetitions += 1;
            now = time(NULL);
        }

        ret = MD5_Final(c, &ctx);
        if (ret != 1) {
            LOGD("Error final");
        }
        repetitions +=1;
        gettimeofday(&et, NULL);
        double time_key = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions * blocksize) / time_key;

        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time_key);
        fprintf(report, "Result: %f Bytes/second \n", result_agree);
    }
    fprintf(report,"*****************************");
    fclose(report);
    LOGD("We are good");
    LOGD("MD5 finished succesfully");

    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_DHTime(JNIEnv *env, jobject instance,jint rep_key,
                                                        jint rep_agree,jstring title_rand,jint rep_total) {

    const char *title = env->GetStringUTFChars(title_rand, 0);
    FILE* report = create_file_text(title);
    struct timeval st, et;

    LOGD("Starting");
    fprintf(report, "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");

    fprintf(report,"************BoringSSL/DH**************\n");

    BIGNUM *publico;
    int secret_size;
    DH *privkey;
    DH *pubkey;

    const char *p = "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F";

    const char *g = "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA";

    unsigned char *secret;

    LOGD("Value of rep_total is: %i",rep_total);
    int repetitions = 0;

    time_t start_key = time(NULL);
    time_t now_key = time(NULL);
    gettimeofday(&st,NULL);
    while ((now_key - start_key) < rep_key) {

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


        now_key = time(NULL);
        repetitions +=1;
    }

    gettimeofday(&et, NULL);
    double time_key = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = repetitions / time_key;
    fprintf(report, "Repetitions: %i \n", repetitions);
    fprintf(report, "Seconds: %f \n", time_key);
    fprintf(report, "Result: %f Times set key/seconds \n", result_agree);


    for (int i = 0; i < rep_total; ++i) {


        time_t start = time(NULL);
        time_t now = time(NULL);

        repetitions = 0;
        gettimeofday(&st, NULL);
        while ((now - start) <= rep_agree) {

            secret_size = DH_compute_key(secret, publico, privkey);
            if(0 > secret_size){ LOGD("Error computing first secret");}
            repetitions += 1;
            now = time(NULL);
        }
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = repetitions / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Key agreement: %f agreements/seconds \n", result_agree);
    }

    fprintf(report,"*****************************");
    fclose(report);

    return ;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_ECDHTime(JNIEnv *env, jobject instance,jint rep_key,jint rep_agree,jstring title_rand,jint rep_total) {

    const char *title = env->GetStringUTFChars(title_rand, 0);
    FILE* report = create_file_text(title);
    struct timeval st,et;
    int repetitions = 0;
    fprintf(report, "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");

    fprintf(report,"************BoringSSL/ECDH**************\n");

    EC_KEY *lKey, *pKey;
    int lSecretLen, pSecretLen;
    unsigned char *lSecret, *pSecret;

    time_t start = time(NULL);
    time_t now = time(NULL);
    gettimeofday(&st, NULL);
    while ((now - start) <= rep_key) {

        lKey = gen_key();
        pKey = gen_key();

        now = time(NULL);
        repetitions +=1;
    }

    gettimeofday(&et, NULL);

    double time_key = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = repetitions / time_key;
    fprintf(report, "Repetitions: %i \n", repetitions);
    fprintf(report, "Seconds: %f \n", time_key);
    fprintf(report, "Result: %f Times set key/seconds \n", result_agree);

    for (int i = 0; i < rep_total; ++i) {

        int repetitions_agree = 0;
        start = time(NULL);
        now = time(NULL);
        gettimeofday(&st, NULL);
        while ((now - start) < rep_agree) {

            lSecretLen = EC_DH(&lSecret, lKey, EC_KEY_get0_public_key(pKey));
            now = time(NULL);
            repetitions_agree += 1;
        }
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = repetitions_agree / time;
        fprintf(report, "Repetitions: %i \n", repetitions_agree);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Key agreement: %f agreements/seconds \n", result_agree);

        pSecretLen = EC_DH(&pSecret, pKey, EC_KEY_get0_public_key(lKey));

        if (memcmp(lSecret, pSecret, lSecretLen))
            LOGD("Secrets don't match.\n");
    }

    LOGD("Elliptic Curve Diffie Hellman finished");

    fprintf(report,"*****************************");
    fclose(report);

    return;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESCBCTime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_aes,jstring title_rand,jint rep_total) {

    LOGD("AES/CBC");

    const char *title = env->GetStringUTFChars(title_rand, 0);
    FILE* report = create_file_text(title);
    fprintf(report, "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
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
    gettimeofday(&st,NULL);

    while ((now - start) < rep_key) {
        memcpy(iv_to_use, iv, 16);

        AES_set_encrypt_key(aes_key, sizeof(aes_key) * 8, &enc_key);
        AES_set_decrypt_key(aes_key, sizeof(aes_key) * 8, &dec_key); // Size of key is in bits
        repetitions += 1;
        now = time(NULL);
    }
    gettimeofday(&et, NULL);
    LOGD("Finished setkey / RSA");
    double time_result = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = repetitions / time_result;
    fprintf(report, "Repetitions: %i \n", repetitions);
    fprintf(report, "Seconds: %f \n", time_result);
    fprintf(report, "Time to set key: %f setting key/seconds \n", result_agree);
    fprintf(report,"Times key set: %i ms \n",repetitions);


    for(int i = 0; i < rep_total; i++) {
        time_t start = time(NULL);
        time_t now = time(NULL);
        repetitions = 0;
        gettimeofday(&st, NULL);
        while ((now - start) < rep_aes) {

            AES_cbc_encrypt(aes_input, enc_out, sizeof(aes_input), &enc_key, iv_to_use, AES_ENCRYPT);

            repetitions += 1;
            now = time(NULL);
        }
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to encrypt: %f byte/seconds \n", result_agree);
    }



    for(int i = 0; i < rep_total; i++) {
        repetitions = 0;
        start = time(NULL);
        now = time(NULL);
        gettimeofday(&st, NULL);
        while ((now - start) < rep_aes) {
            memcpy(iv_to_use, iv, 16);
            AES_cbc_encrypt(enc_out, dec_out, sizeof(aes_input), &dec_key, iv_to_use, AES_DECRYPT);

            repetitions += 1;
            now = time(NULL);
        }
        gettimeofday(&et, NULL);
        double time_dec = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        result_agree = (repetitions * blocksize) / time_dec;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time_dec);
        fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
    }

    fclose(report);
    
    LOGD("Finished AES/CBC");

    fprintf(report,"*****************************");
    fclose(report);

    return;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESCTRTime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_aes,jstring title_rand,jint rep_total) {

    const char *title = env->GetStringUTFChars(title_rand, 0);
    FILE* report = create_file_text(title);
    fprintf(report, "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
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


        repetitions += 1;
        now= time(NULL);
    }
    gettimeofday(&et, NULL);
    LOGD("Finished setkey / RSA");
    double time_result = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = repetitions / time_result;
    fprintf(report, "Repetitions: %i \n", repetitions);
    fprintf(report, "Seconds: %f \n", time_result);
    fprintf(report, "Time to set key: %f setting key/seconds \n", result_agree);

    for (int i = 0; i < rep_total; i++) {

        start = time(NULL);
        now = time(NULL);
        repetitions = 0;
        gettimeofday(&st, NULL);

        while ((now - start) < rep_aes) {

            if (1 != EVP_EncryptUpdate(ctx, enc_out, &len, aes_input, sizeof(aes_input))) {
                LOGD("Error updating encryption");
            }
            ciphertext_len = len;

            now = time(NULL);
            repetitions  += 1;
        }
        if (1 != EVP_EncryptFinal_ex(ctx, enc_out + len, &len)) LOGD("Error encrypt final");
        ciphertext_len += len;
        repetitions +=1;
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to encrypt: %f byte/seconds \n", result_agree);
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);
    memcpy(iv_to_use, iv, 16);
    //memset(iv, 0x00, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly

    for (int i = 0; i < rep_total; i++) {

        start = time(NULL);
        now = time(NULL);
        repetitions = 0;
        gettimeofday(&st, NULL);

        while ((now - start) < rep_aes) {

            if (1 != EVP_DecryptUpdate(ctx_dec, dec_out, &len, enc_out, ciphertext_len))
                LOGD("Error updating Decryption");
            plaintext_len = len;

            plaintext_len += len;
            now = time(NULL);
            repetitions  += 1;
        }
        if (1 != EVP_DecryptFinal_ex(ctx_dec, dec_out + len, &len))LOGD("Error final");
        repetitions +=1;
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to encrypt: %f byte/seconds \n", result_agree);
    }


    EVP_CIPHER_CTX_free(ctx);

    fprintf(report,"*****************************");
    fclose(report);

    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESGCMTime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_aes,jstring title_rand,jint rep_total) {

    LOGD("AES/GCM");

    const char *title = env->GetStringUTFChars(title_rand, 0);

    FILE* report = create_file_text(title);
    fprintf(report, "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
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
    gettimeofday(&st,NULL);
    while ((now - start) < rep_key) {

        if(!(ctx = EVP_CIPHER_CTX_new())) LOGD("Error at ctx new");

        if(!(ctx_dec = EVP_CIPHER_CTX_new())) LOGD("Error init new 2");

        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
            LOGD("Error at encryptInit");

        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL))
            LOGD("Error at CTX Ctrl Encrypt");

        if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv)) LOGD("Error initializasing");

        if(!EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_gcm(), NULL, NULL, NULL))
            LOGD("Error at DecryptaInit");

        if(!EVP_CIPHER_CTX_ctrl(ctx_dec, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL))
            LOGD("Error at CTX control");

        if(!EVP_DecryptInit_ex(ctx_dec, NULL, NULL, aes_key, iv)) LOGD("Error at decryptinit");

        now = time(NULL);
        repetitions += 1;
        LOGD("Set key");
    }
    gettimeofday(&et, NULL);
    double time_key = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = repetitions / time_key;
    fprintf(report, "Repetitions: %i \n", repetitions);
    fprintf(report, "Seconds: %f \n", time_key);
    fprintf(report, "Result: %f Times set key/seconds \n", result_agree);

    if(!(ctx = EVP_CIPHER_CTX_new())) LOGD("Error at ctx new");

    if(!(ctx_dec = EVP_CIPHER_CTX_new())) LOGD("Error init new 2");

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        LOGD("Error at encryptInit");

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL))
        LOGD("Error at CTX Ctrl Encrypt");

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv)) LOGD("Error initializasing");


    if(!EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_gcm(), NULL, NULL, NULL))
        LOGD("Error at DecryptaInit");

    if(!EVP_CIPHER_CTX_ctrl(ctx_dec, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL))
        LOGD("Error at CTX control");

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx_dec, NULL, NULL, aes_key, iv)) LOGD("Error at decryptinit");


    for(int i = 0; i < rep_total; i++) {
        start = time(NULL);
        now = time(NULL);
        repetitions = 0;
        gettimeofday(&st, NULL);
        if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv)) LOGD("Error initializasing");
        while ((now - start) < rep_aes) {

            if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext))) {
                LOGD("Error at encrypt updated");
            }
            ciphertext_len = len;
            repetitions += 1;
            now = time(NULL);
        }
        LOGD("Success encrypting ");
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) LOGD("Error at encrypt final");
        repetitions +=1;
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to encrypt: %f byte/seconds \n", result_agree);
    }
    LOGD("Finished encryption");

    ciphertext_len += len;

    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        LOGD("Error getting tag");

    for(int i = 0; i <rep_total;i++){
        start = time(NULL);
        now = time(NULL);
        repetitions = 0;
        if(!EVP_DecryptInit_ex(ctx_dec, NULL, NULL, aes_key, iv)) LOGD("Error at decryptinit");
        gettimeofday(&st, NULL);
        while ((now - start) < rep_aes) {
            if(!EVP_DecryptInit_ex(ctx_dec, NULL, NULL, aes_key, iv)) LOGD("Error at decryptinit");

            if (!EVP_DecryptUpdate(ctx_dec, decrypted, &len_dec, ciphertext, ciphertext_len))
                LOGD("Error decryptupdate");
            plaintext_len_dec = len_dec;

            if (!EVP_CIPHER_CTX_ctrl(ctx_dec, EVP_CTRL_GCM_SET_TAG, 16, tag))
                LOGD("Error at ctrl tag");
            repetitions += 1;
            now = time(NULL);
        }
        EVP_DecryptFinal_ex(ctx_dec, decrypted + len_dec, &len_dec);
        repetitions +=1;
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
    }
    LOGD("Finished encryption");
    fprintf(report,"*****************************");
    fclose(report);

    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESOFBTime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_aes,jstring title_rand,jint rep_total) {

    LOGD("AES/OFB");
    const char *title = env->GetStringUTFChars(title_rand, 0);
    FILE* report = create_file_text(title);
    fprintf(report, "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");

    fprintf(report,"************BoringSSL/AESOFB**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);

    int repetitions = 0;

    EVP_CIPHER_CTX *ctx = nullptr;


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

    gettimeofday(&st, NULL);
    while ((now - start) <= rep_key) {

        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new())) LOGD("Error at ctx new");

        if (!(ctx_dec = EVP_CIPHER_CTX_new())) LOGD("Error init new 2");

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, aes_key, iv))
            LOGD("Error at encryptInit");

        if (!EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_ofb(), NULL, aes_key, iv))
            LOGD("Error at decryptinit");

        LOGD("Set key");
        repetitions  += 1;
        now = time(NULL);
    }
    gettimeofday(&et, NULL);
    double time_key = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = repetitions / time_key;
    fprintf(report, "Repetitions: %i \n", repetitions);
    fprintf(report, "Seconds: %f \n", time_key);
    fprintf(report, "Result: %f Times set key/seconds \n", result_agree);

    for(int i = 0; i <rep_total;i++){
        start = time(NULL);
        now = time(NULL);
        repetitions = 0;
        EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, aes_key, iv);
        gettimeofday(&st, NULL);
        while ((now - start) < rep_aes) {

            if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext)))
                LOGD("Error at encrypt updated");
            ciphertext_len = len;

            ciphertext_len += len;
            now = time(NULL);
            repetitions  += 1;
        }
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) LOGD("Error at encrypt final");
        repetitions += 1;
        LOGD("Success encrypting ");
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to encrypt: %f byte/seconds \n", result_agree);
    }

    for(int i = 0; i <rep_total;i++){
        EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_ofb(), NULL, aes_key, iv);
        start = time(NULL);
        now = time(NULL);
        repetitions = 0;
        gettimeofday(&st, NULL);
        while ((now - start) <= rep_aes) {

            if (!EVP_DecryptUpdate(ctx_dec, decrypted, &len_dec, ciphertext, ciphertext_len))
                LOGD("Error decryptupdate");
            plaintext_len_dec = len_dec;

            now = time(NULL);
            repetitions  += 1;
        }
        EVP_DecryptFinal_ex(ctx_dec, decrypted + len_dec, &len_dec);
        repetitions += 1;
        LOGD("Success decrypting ");
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
    }
    fprintf(report,"*****************************");
    fclose(report);

    return;
}
