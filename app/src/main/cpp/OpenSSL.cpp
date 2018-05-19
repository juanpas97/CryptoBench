//
// Created by Juan Pérez de Algaba on 17/5/18.
//
#include <jni.h>

#include <string>

#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <android/log.h>
#include "openssl/md5.h"
#include "openssl/evp.h"
#include "openssl/aes.h"
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>

#include <sys/time.h>

#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PRINT_KEYS

#define  LOG_TAG    "OpenSSL"

#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG ,__VA_ARGS__)


long diff_micro(struct timespec *start, struct timespec *end)
{
    /* us */
    return ((end->tv_sec * (1000000)) + (end->tv_nsec / 1000)) -
           ((start->tv_sec * 1000000) + (start->tv_nsec / 1000));
}


extern "C"
JNIEXPORT jlongArray JNICALL
Java_com_example_juanperezdealgaba_sac_OpenSSL_RSA(JNIEnv *env, jobject instance, jint size) {

    jlongArray result;
    result = env->NewLongArray(size);
    jlong fill[size];
    struct timespec start, end;
    struct timespec start1, end1;

    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char   *pri_key;           // Private key
    char   *pub_key;           // Public key
    char   msg[KEY_LENGTH/8];  // Message to encrypt
    char   *encrypt = NULL;    // Encrypted message
    char   *decrypt = NULL;    // Decrypted message
    char   *err;               // Buffer for any error messages

    // Generate key pair
    LOGD("Generating RSA (%d bits) keypair...", KEY_LENGTH);
    fflush(stdout);
    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = static_cast<char *>(malloc(pri_len + 1));
    pub_key = static_cast<char *>(malloc(pub_len + 1));

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

#ifdef PRINT_KEYS
    LOGD("\n%s\n\n\n%s\n", pri_key, pub_key);
#endif
    LOGD("done.\n");

    // Get the message to encrypt
    LOGD("Message to encrypt");

    char str1[]="This is a test";
    strcpy(msg, str1);

    // Encrypt the message
    encrypt = static_cast<char *>(malloc(RSA_size(keypair)));
    int encrypt_len;
    err = static_cast<char *>(malloc(130));

    clock_gettime(CLOCK_MONOTONIC_RAW, &start);
    if((encrypt_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)encrypt,
                                         keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &end);

        long delta_us = diff_micro(&start, &end);
        fill[0] = delta_us;
        ERR_error_string(ERR_get_error(), err);
        LOGD("Error");
        fprintf(stderr, "Error encrypting message: %s\n", err);
        RSA_free(keypair);
        BIO_free_all(pub);
        BIO_free_all(pri);
        free(pri_key);
        free(pub_key);
        free(encrypt);
        free(decrypt);
        free(err);
    }

    LOGD("Length of encrypted file:");
    LOGD("%d",encrypt_len);

    // Decrypt it
    decrypt = static_cast<char *>(malloc(encrypt_len));

    clock_gettime(CLOCK_MONOTONIC_RAW, &start1);
    if(RSA_private_decrypt(encrypt_len, (unsigned char*)encrypt, (unsigned char*)decrypt,
                           keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &end1);
        long delta_us = diff_micro(&start1, &end1);
        fill[1] = delta_us;
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
        goto free_stuff;
    }
    LOGD("Decrypted message: %s\n", decrypt);

    free_stuff:
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);
    free(pri_key);
    free(pub_key);
    free(encrypt);
    free(decrypt);
    free(err);

    env->SetLongArrayRegion(result, 0, size, fill);

    return result;
}

void print_data(const char *tittle, const void* data, int len);

extern "C"
JNIEXPORT jint JNICALL
Java_com_example_juanperezdealgaba_sac_OpenSSL_AES(JNIEnv *env, jobject instance) {

    unsigned char aes_key[16], iv[16];

    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(iv, sizeof(iv));

    /* Input data to encrypt */
    unsigned char aes_input[32];
    RAND_bytes(aes_input, sizeof(aes_input));

    /* Init vector */
    //unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);

    /* Buffers for Encryption and Decryption */
    unsigned char enc_out[sizeof(aes_input)];
    unsigned char dec_out[sizeof(aes_input)];

    /* AES-128 bit CBC Encryption */
    AES_KEY enc_key, dec_key;
    AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, &enc_key);
    AES_cbc_encrypt(aes_input, enc_out, sizeof(aes_input), &enc_key, iv, AES_ENCRYPT);
    /* AES-128 bit CBC Decryption */
    memset(iv, 0x00, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly
    AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key); // Size of key is in bits
    AES_cbc_encrypt(enc_out, dec_out, sizeof(aes_input), &dec_key, iv, AES_DECRYPT);

    /* Printing and Verifying */
    print_data("\n Original ",aes_input, sizeof(aes_input)); // you can not print data as a string, because after Encryption its not ASCII

    print_data("\n Encrypted",enc_out, sizeof(enc_out));

    print_data("\n Decrypted",dec_out, sizeof(dec_out));

    return 0;

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
JNIEXPORT jint JNICALL
Java_com_example_juanperezdealgaba_sac_OpenSSL_DH(JNIEnv *env, jobject instance) {

    EVP_PKEY *params;
    EVP_PKEY_CTX *kctx,*secretctx;
    EVP_PKEY *dhkey = NULL;

    EVP_PKEY *dhkey2 = NULL;
    size_t keylen;
    unsigned char *skey;


    LOGD("GO");
/* Use built-in parameters */
    if(NULL == (params = EVP_PKEY_new())) LOGD("Error at pkeynew");
    if(1 != EVP_PKEY_set1_DH(params,DH_get_2048_256())) LOGD("Error at setting key");

/* Create context for the key generation */
    if(!(kctx = EVP_PKEY_CTX_new(params, NULL))) LOGD("Error at pkeyctx");

    /* Generate a new key */
    if(1 != EVP_PKEY_keygen_init(kctx)) LOGD("Error at keygen init");
    if(1 != EVP_PKEY_keygen(kctx, &dhkey)) LOGD("Error at keygen");

    /* Generate the second key */
    if(1 != EVP_PKEY_keygen_init(kctx)) LOGD("Error at keygen init2");
    if(1 != EVP_PKEY_keygen(kctx, &dhkey2)) LOGD("Error at keygen2");

    secretctx = EVP_PKEY_CTX_new(dhkey,NULL);

    if (!secretctx){LOGD("Error with secret shared context");}
    if (EVP_PKEY_derive_init(secretctx) <= 0)
    {LOGD("Error at key derive of secret context");}
    if (EVP_PKEY_derive_set_peer(secretctx, dhkey2) <= 0)
    {LOGD("Error at derive set peer");}

    if (EVP_PKEY_derive(secretctx, NULL, &keylen) <= 0){LOGD("Error at derive");}


    //skey stores the shared secret
    skey = static_cast<unsigned char *>(OPENSSL_malloc(keylen));

    if (!skey)
    {
        LOGD("Error at freeing shared key");
    }

    if (EVP_PKEY_derive(secretctx, skey, &keylen) <= 0)
    {
        LOGD("Error at derive pkey");
    }

    LOGD("Diffie Hellman finished");

    return 0;

}extern "C"
JNIEXPORT jint JNICALL
Java_com_example_juanperezdealgaba_sac_OpenSSL_MD5(JNIEnv *env, jobject instance) {

    unsigned char c[MD5_DIGEST_LENGTH];

    MD5_CTX ctx;

    MD5_Init(&ctx);

    int bytes, ret;

    unsigned char data[1024] = "asdAFASDFASDFjyhdfcasdasdasd";

    ret = MD5_Update (&ctx, data, bytes);

    if(ret!=1){
        LOGD("Error updating");
    }

    ret = MD5_Final (c,&ctx);
    if(ret != 1){
        LOGD("Error final");
    }

    //LOGD("Here starts:");
    //for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
    //    LOGD("%x", c[i]);
    //}

    LOGD("MD5 finished succesfully");

    return 0;

}

