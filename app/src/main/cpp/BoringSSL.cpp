
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
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESCBC(JNIEnv *env, jobject instance) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];

    struct timeval st,et;

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

    gettimeofday(&st,NULL);
    AES_cbc_encrypt(aes_input, enc_out, sizeof(aes_input), &enc_key, iv, AES_ENCRYPT);

    gettimeofday(&et,NULL);
    int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[1] = encryption_time;

    /* AES-128 bit CBC Decryption */
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

    env->SetIntArrayRegion(result, 0, 3, fill);

    return result;

}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESCTR(JNIEnv *env, jobject instance) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];

    EVP_CIPHER_CTX *ctx;
    int len;

    int ciphertext_len;
    int plaintext_len;

    struct timeval st,et;
    unsigned char aes_key[16], iv[16];

    if(!(ctx = EVP_CIPHER_CTX_new())) LOGD("Error creating CTX");

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
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESGCM(JNIEnv *env, jobject instance) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];

    EVP_CIPHER_CTX *ctx;

    unsigned char aes_key[16], iv[16];
    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(iv, sizeof(iv));

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
JNIEXPORT jdoubleArray JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_MD5(JNIEnv *env, jobject instance) {

    jdoubleArray result;
    result = env->NewDoubleArray(3);
    jdouble fill[3];

    unsigned char c[MD5_DIGEST_LENGTH];

    MD5_CTX ctx;

    MD5_Init(&ctx);

    int ret;

    size_t bytes = 16;

    unsigned char data[1024] = "asdsdasd";

    clock_t begin = clock();

    ret = MD5_Update(&ctx, data, bytes);

    if (ret != 1) {
        LOGD("Error updating");
    }

    ret = MD5_Final(c, &ctx);
    if (ret != 1) {
        LOGD("Error final");
    }

    clock_t end = clock();
    double time_spent_encryption = (double) (end - begin) / CLOCKS_PER_SEC;
    fill[1] = time_spent_encryption;

    /*LOGD("Here starts:");
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
        LOGD("%x", c[i]);
    }*/

    LOGD("MD5 finished succesfully");


    env->SetDoubleArrayRegion(result, 0, 3, fill);
    return result;

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

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_BoringSSL_AESOFB(JNIEnv *env, jobject instance) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];

    EVP_CIPHER_CTX *ctx;
    unsigned char aes_key[16], iv[16];
    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(iv, sizeof(iv));

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
Java_com_example_juanperezdealgaba_sac_BoringSSL_ECDH(JNIEnv *env, jobject instance) {

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