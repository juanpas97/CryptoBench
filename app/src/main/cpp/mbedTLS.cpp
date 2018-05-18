#include <jni.h>

#include <string>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <android/log.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md5.h"
#include "mbedtls/dhm.h"

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


#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG ,__VA_ARGS__)

#define  LOG_TAG    "mbedTLS"

#define KEY_SIZE 2048
#define EXPONENT 65537

#define DFL_BITS    2048
#define GENERATOR "4"


extern "C"
JNIEXPORT jint JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_RSA(JNIEnv *env, jobject instance) {

    int ret;
    int return_val;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_genkey";
    size_t i;

    char *argv[2];

    argv[1] = const_cast<char *>("Inputtt");

    unsigned char input[1024];
    unsigned char buf[512];
    unsigned char result[1024];

    mbedtls_ctr_drbg_init( &ctr_drbg );

    LOGD("Seeding the random number generator");
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        LOGD( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return 0;
    }

    LOGD( " ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE );
    fflush( stdout );

    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

    if( ( ret = mbedtls_rsa_gen_key( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                                     EXPONENT ) ) != 0 )
    {
        LOGD( " failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret );
        return 0;
    }

    memcpy( input, argv[1], strlen( argv[1] ) );

    LOGD( "\n  . Generating the RSA encrypted value" );

    return_val = mbedtls_rsa_pkcs1_encrypt( &rsa, mbedtls_ctr_drbg_random,
                                            &ctr_drbg, MBEDTLS_RSA_PUBLIC,
                                            strlen( argv[1] ), input, buf );

    if( return_val != 0 )
    {

        LOGD( " failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %d\n\n",
              return_val );
        return 0;
    }



    LOGD("Finished encryption");

    LOGD( "\n  . Decrypting the encrypted data" );

    return_val = mbedtls_rsa_pkcs1_decrypt( &rsa, mbedtls_ctr_drbg_random,
                                            &ctr_drbg, MBEDTLS_RSA_PRIVATE, &i,
                                            buf, result, 1024 );
    if( return_val != 0 )
    {
        LOGD( " failed\n  ! mbedtls_rsa_pkcs1_decrypt returned %d\n\n",
              return_val );
        return 0;
    }

    LOGD( "\n  . OK\n\n" );

    LOGD( "The decrypted result is: '%s'\n\n", result );

    mbedtls_rsa_free( &rsa );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );


    return 0;

}

extern "C"
JNIEXPORT jint JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_AES(JNIEnv *env, jobject instance) {

    const uint8_t Plaintext[64] =
            {
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
            };


    uint8_t key[32] =
            {
                    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
                    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
            };

    uint8_t iv[16] =
            {
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
            };


    const uint8_t Expected_Ciphertext[64] =
            {
                    0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d,
                    0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
                    0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4,
                    0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
                    0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0,
                    0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
                    0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81,
                    0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd,
            };


    uint8_t OutputMessage[64];
    uint8_t compare[64];
    uint32_t i=0,status = 0;
    //LOGD("Plain:");
    //for (int i = 0; i < 64; ++i) {
    //    LOGD("%x",Plaintext[i]);
    //}


    mbedtls_aes_context ctx;
    mbedtls_aes_init( &ctx );
    status = mbedtls_aes_setkey_enc( &ctx, key, 256 );
    if(status != 0)
    {
        LOGD("\n mbedtls Encrypt set key failed");
    }
    status = mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_ENCRYPT, 64, iv, Plaintext, OutputMessage );
    if(status != 0)
    {
        LOGD("\n mbedtls encryption failed");
    }


    uint8_t iv2[16] =
            {
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
            };

    mbedtls_aes_init( &ctx );
    status = mbedtls_aes_setkey_dec(&ctx, key, 256);
    if(status != 0)
    {
        LOGD("\n mbedtls decryption set key failed");
    }
    status = mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_DECRYPT, 64, iv2, OutputMessage,compare);
    if(status != 0)
    {
        LOGD("\n mbedtls encryption failed");
    }

    LOGD("AES finished");
    LOGD("Plain decrypted:");
    for (int i = 0; i < 64; ++i) {
        LOGD("%x", compare[i]);
    }
    mbedtls_aes_free( &ctx );

    return 0;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_MD5(JNIEnv *env, jobject instance) {

    int i, ret;
    unsigned char digest[16];
    char str[] = "Hello, world!";

    LOGD( "\n  MD5('%s') = ", str );

    if(  (ret = mbedtls_md5_ret( (unsigned char *) str, 13, digest ))  != 0 ) {
        return;
    }
    for( i = 0; i < 16; i++ )
        LOGD( "%02x", digest[i] );

    LOGD( "Finished!" );

}

