
// /
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
#include <openssl/crypto.h>

#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PRINT_KEYS

#define  LOG_TAG    "BoringSSL"

#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG ,__VA_ARGS__)

extern "C"
JNIEXPORT jdoubleArray JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_RSA(JNIEnv *env, jobject instance) {

    jdoubleArray result;
    result = env->NewDoubleArray(3);
    jdouble fill[3];

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

    clock_t begin = clock();
    if((encrypt_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)encrypt,
                                         keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {

        clock_t end = clock();

        double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

        fill[0] =time_spent;

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
    begin = clock();
    decrypt = static_cast<char *>(malloc(encrypt_len));
    if(RSA_private_decrypt(encrypt_len, (unsigned char*)encrypt, (unsigned char*)decrypt,
                           keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
        clock_t end = clock();

        double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

        fill[1] = time_spent;


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



    env->SetDoubleArrayRegion(result, 0, 3, fill);

    return result;

}

void print_data(const char *tittle, const void* data, int len);

extern "C"
JNIEXPORT jdoubleArray JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AES(JNIEnv *env, jobject instance) {

    jdoubleArray result;
    result = env->NewDoubleArray(3);
    jdouble fill[3];

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
    clock_t begin = clock();
    AES_cbc_encrypt(aes_input, enc_out, sizeof(aes_input), &enc_key, iv, AES_ENCRYPT);

    clock_t end = clock();
    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    fill[0] = time_spent;

    /* AES-128 bit CBC Decryption */
    memset(iv, 0x00, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly

    AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key); // Size of key is in bits
    clock_t begin1 = clock();
    AES_cbc_encrypt(enc_out, dec_out, sizeof(aes_input), &dec_key, iv, AES_DECRYPT);
    clock_t end1 = clock();

    double time_spent_decryption = (double)(end1 - begin1) / CLOCKS_PER_SEC;

    fill[1] = time_spent_decryption;

    /* Printing and Verifying */
    print_data("\n Original ",aes_input, sizeof(aes_input)); // you can not print data as a string, because after Encryption its not ASCII

    print_data("\n Encrypted",enc_out, sizeof(enc_out));

    print_data("\n Decrypted",dec_out, sizeof(dec_out));

    env->SetDoubleArrayRegion(result, 0, 3, fill);

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
JNIEXPORT jint JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_MD5(JNIEnv *env, jobject instance) {

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

extern "C"
JNIEXPORT jdoubleArray JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_DH(JNIEnv *env, jobject instance) {

    jdoubleArray result;
    result = env->NewDoubleArray(3);
    jdouble fill[3];

    LOGD("Starting");
    DH *privkey;
    int codes;
    int secret_size;

/* Generate the parameters to be used */
    if(NULL == (privkey = DH_new())) LOGD("Error at new");
    if(1 != DH_generate_parameters_ex(privkey, 2048, DH_GENERATOR_2, NULL)) LOGD("Error at generating params ex");

    if(1 != DH_check(privkey, &codes)) LOGD("Error at checking");
    if(codes != 0)
    {
        /* Problems have been found with the generated parameters */
        /* Handle these here - we'll just abort for this example */
        LOGD("DH_check failed\n");
        abort();
    }

/* Generate the public and private key pair */
    if(1 != DH_generate_key(privkey)) LOGD("Error generating key");

/* Send the public key to the peer.
 * How this occurs will be specific to your situation (see main text below) */


/* Receive the public key from the peer. In this example we're just hard coding a value */
    BIGNUM *pubkey = NULL;
    if(0 == (BN_dec2bn(&pubkey, "01234567890123456789012345678901234567890123456789"))) LOGD("Error at BIGNUM");

/* Compute the shared secret */
    unsigned char *secret;

    clock_t begin = clock();
    if(NULL == (secret = static_cast<unsigned char *>(malloc(sizeof(unsigned char) * (DH_size(privkey)))))) LOGD("Error at secret");

    clock_t end = clock();
    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    fill[1] = time_spent;

    if(0 > (secret_size = DH_compute_key(secret, pubkey, privkey))) LOGD("Error at checking number");

/* Do something with the shared secret */
/* Note secret_size may be less than DH_size(privkey) */
    LOGD("Finished");


/* Clean up */
    free(secret);
    BN_free(pubkey);
    DH_free(privkey);

    env->SetDoubleArrayRegion(result, 0, 3, fill);

    return result;
}