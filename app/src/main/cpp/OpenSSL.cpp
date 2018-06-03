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



extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_OpenSSL_RSA(JNIEnv *env, jobject instance, jint size) {

    jintArray result;
    result = env->NewIntArray(size);
    jint fill[size];
    struct timeval st,et;

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

    gettimeofday(&st,NULL);
    if((encrypt_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)encrypt,
                                         keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
        gettimeofday(&et,NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[0] = encryption_time;
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

     gettimeofday(&st,NULL);
    if(RSA_private_decrypt(encrypt_len, (unsigned char*)encrypt, (unsigned char*)decrypt,
                           keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
        gettimeofday(&et,NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[1] = encryption_time;
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

    env->SetIntArrayRegion(result, 0, size, fill);

    return result;
}

void print_data(const char *tittle, const void* data, int len);

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_OpenSSL_AESCBC(JNIEnv *env, jobject instance, jint size) {

    jintArray result;
    result = env->NewIntArray(size);
    jint fill[size];

    struct timeval st,et;
    unsigned char aes_key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

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

    gettimeofday(&st,NULL);
    AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, &enc_key);
    AES_cbc_encrypt(aes_input, enc_out, sizeof(aes_input), &enc_key, iv, AES_ENCRYPT);
    gettimeofday(&et,NULL);
    int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[0] = encryption_time;

    /* AES-128 bit CBC Decryption */
    clock_t begin1 = clock();
    memset(iv, 0x00, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly
    AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key); // Size of key is in bits
    gettimeofday(&st,NULL);
    AES_cbc_encrypt(enc_out, dec_out, sizeof(aes_input), &dec_key, iv, AES_DECRYPT);
    gettimeofday(&et,NULL);
    int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[1] = decryption_time;
    /* Printing and Verifying */
    print_data("\n Original ",aes_input, sizeof(aes_input)); // you can not print data as a string, because after Encryption its not ASCII

    print_data("\n Encrypted",enc_out, sizeof(enc_out));

    print_data("\n Decrypted",dec_out, sizeof(dec_out));

    env->SetIntArrayRegion(result, 0, size, fill);

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
Java_com_example_juanperezdealgaba_sac_OpenSSL_DH(JNIEnv *env, jobject instance) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];

    EVP_PKEY *params;
    EVP_PKEY_CTX *kctx,*secretctx;
    EVP_PKEY *dhkey = NULL;

    EVP_PKEY *dhkey2 = NULL;
    size_t keylen;
    unsigned char *skey;

    struct timeval st,et;

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

    gettimeofday(&st,NULL);
    if (EVP_PKEY_derive(secretctx, NULL, &keylen) <= 0){LOGD("Error at derive");}
    gettimeofday(&et,NULL);
    int key_agreement_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[1] = key_agreement_time;

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

    env->SetIntArrayRegion(result, 0, 3, fill);

    return result;

}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_OpenSSL_MD5(JNIEnv *env, jobject instance) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];

    struct timeval st,et;

        unsigned char c[MD5_DIGEST_LENGTH];

        MD5_CTX ctx;

        MD5_Init(&ctx);

        int ret;

        size_t bytes = 16;

        unsigned char data[1024] = "asdsdasd";

        gettimeofday(&st,NULL);

        ret = MD5_Update(&ctx, data, bytes);

        if (ret != 1) {
            LOGD("Error updating");
        }

        ret = MD5_Final(c, &ctx);
        if (ret != 1) {
            LOGD("Error final");
        }

        gettimeofday(&et,NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[0] = encryption_time;

        /*LOGD("Here starts:");
        for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
            LOGD("%x", c[i]);
        }*/

        LOGD("MD5 finished succesfully");


        env->SetIntArrayRegion(result, 0, 3, fill);
        return result;
}



extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_OpenSSL_AESCTR(JNIEnv *env, jobject instance) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];

    EVP_CIPHER_CTX *ctx;
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

    if(!(ctx = EVP_CIPHER_CTX_new())) LOGD("Error creating CTX");


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

    gettimeofday(&st,NULL);

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, aes_key, iv))
        LOGD("Error encrypting");
    if(1 != EVP_EncryptUpdate(ctx, enc_out, &len, aes_input, sizeof(aes_input))) {
        LOGD("Error updating encryption");
    }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, enc_out + len, &len)) LOGD("Error encrypt final");
    ciphertext_len += len;
    gettimeofday(&et,NULL);
    int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[0] = encryption_time;

    EVP_CIPHER_CTX_set_padding(ctx, 0);
    //memset(iv, 0x00, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly
    gettimeofday(&st,NULL);
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, aes_key, iv))
        LOGD("Error statr decrypting");

    if(1 != EVP_DecryptUpdate(ctx, dec_out, &len, enc_out, ciphertext_len))
        LOGD("Error updating Decryption");
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, dec_out + len, &len))LOGD("Error final");
    plaintext_len += len;
    gettimeofday(&et,NULL);
    int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[1] = decryption_time;

    EVP_CIPHER_CTX_free(ctx);

    /* Printing and Verifying */
    print_data("\n Original ",aes_input, sizeof(aes_input)); // you can not print data as a string, because after Encryption its not ASCII

    print_data("\n Encrypted",enc_out, sizeof(enc_out));

    print_data("\n Decrypted",dec_out, sizeof(dec_out));

    env->SetIntArrayRegion(result, 0, 3, fill);

    return result;

}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_OpenSSL_AESGCM(JNIEnv *env, jobject instance) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];

    EVP_CIPHER_CTX *ctx;

    unsigned char aes_key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    unsigned char plaintext[32];
    RAND_bytes(plaintext, sizeof(plaintext));

    unsigned char ciphertext[32];
    unsigned char tag[16];

    unsigned char decrypted[32];

    int len;

    int ciphertext_len;

    struct timeval st,et;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) LOGD("Error at ctx new");

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        LOGD("Error at encryptInit");

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL))
        LOGD("Error at CTX Ctrl Encrypt");

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv)) LOGD("Error initializasing");

    gettimeofday(&st,NULL);

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext)))
       LOGD("Error at encrypt updated");
    ciphertext_len = len;

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) LOGD("Error at encrypt final");

    gettimeofday(&et,NULL);
    int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[0] = encryption_time;

    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        LOGD("Error getting tag");

    LOGD("Finished encryption");

    EVP_CIPHER_CTX *ctx_dec;
    int len_dec;
    int plaintext_len_dec;
    int ret_dec;

    if(!(ctx_dec = EVP_CIPHER_CTX_new())) LOGD("Error init new 2");

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_gcm(), NULL, NULL, NULL))
        LOGD("Error at DecryptaInit");

    if(!EVP_CIPHER_CTX_ctrl(ctx_dec, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL))
        LOGD("Error at CTX control");

    LOGD("We are good");

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx_dec, NULL, NULL, aes_key, iv)) LOGD("Error at decryptinit");

    gettimeofday(&st,NULL);
    if(!EVP_DecryptUpdate(ctx_dec, decrypted, &len_dec, ciphertext, ciphertext_len))
        LOGD("Error decryptupdate");
    plaintext_len_dec = len_dec;

    if(!EVP_CIPHER_CTX_ctrl(ctx_dec, EVP_CTRL_GCM_SET_TAG, 16, tag))
        LOGD("Error at ctrl tag");

   int ret = EVP_DecryptFinal_ex(ctx_dec, decrypted + len_dec, &len_dec);
    gettimeofday(&et,NULL);
    int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[1] = decryption_time;

    if(ret > 0)
    {
        /* Success */
        LOGD("Success");
    }
    else
    {
        /* Verify failed */
        LOGD("FAIL");
    }

    env->SetIntArrayRegion(result, 0, 3, fill);

    return result;


}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_OpenSSL_AESOFB(JNIEnv *env, jobject instance) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];

    EVP_CIPHER_CTX *ctx;


    unsigned char aes_key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    unsigned char plaintext[32];
    RAND_bytes(plaintext, sizeof(plaintext));

    unsigned char ciphertext[32];

    unsigned char decrypted[32];

    int len;

    int ciphertext_len;

    struct timeval st,et;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) LOGD("Error at ctx new");

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, aes_key, iv))
        LOGD("Error at encryptInit");


    gettimeofday(&st,NULL);

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext)))
        LOGD("Error at encrypt updated");
    ciphertext_len = len;

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) LOGD("Error at encrypt final");

    gettimeofday(&et,NULL);
    int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[0] = encryption_time;

    ciphertext_len += len;

    LOGD("Finished encryption");

    EVP_CIPHER_CTX *ctx_dec;
    int len_dec;
    int plaintext_len_dec;
    int ret_dec;

    if(!(ctx_dec = EVP_CIPHER_CTX_new())) LOGD("Error init new 2");

    /* Initialise the decryption operation. */
    LOGD("We are good");

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx_dec, EVP_aes_128_ofb(), NULL, aes_key, iv)) LOGD("Error at decryptinit");

    gettimeofday(&st,NULL);
    if(!EVP_DecryptUpdate(ctx_dec, decrypted, &len_dec, ciphertext, ciphertext_len))
        LOGD("Error decryptupdate");
    plaintext_len_dec = len_dec;


    int ret = EVP_DecryptFinal_ex(ctx_dec, decrypted + len_dec, &len_dec);
    gettimeofday(&et,NULL);
    int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[1] = decryption_time;

    if(ret > 0)
    {
        LOGD("Success");
    }
    else
    {
        LOGD("FAIL");
    }

    env->SetIntArrayRegion(result, 0, 3, fill);

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
Java_com_example_juanperezdealgaba_sac_OpenSSL_ECDH(JNIEnv *env, jobject instance) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];

    struct timeval st,et;

    EC_KEY *lKey, *pKey;
    int lSecretLen, pSecretLen;
    unsigned char *lSecret, *pSecret;

    lKey = gen_key();
    pKey = gen_key();

    gettimeofday(&st,NULL);
    lSecretLen = EC_DH(&lSecret, lKey, EC_KEY_get0_public_key(pKey));
    pSecretLen = EC_DH(&pSecret, pKey, EC_KEY_get0_public_key(lKey));
    gettimeofday(&et,NULL);
    int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[1] = generation_time;

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

    env->SetIntArrayRegion(result, 0, 3, fill);

    return result;

}