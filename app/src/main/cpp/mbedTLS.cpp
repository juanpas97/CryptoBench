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
#include "mbedtls/cipher.h"
#include <mbedtls/gcm.h>
#include "mbedtls/ecdh.h"
#include "mbedtls/pk.h"


#include <time.h>
#include <cstring>

#define HEAP_HINT NULL



#define BITS_TO_BYTES(b)                (b/8)
#define MIN_OAEP_PADDING                (2*BITS_TO_BYTES(160)+2)

#define RSA_LENGTH                      (BITS_TO_BYTES(2048))

#define RSA_OAEP_DECRYPTED_DATA_LENGTH  (RSA_LENGTH-MIN_OAEP_PADDING)
#define RSA_OAEP_ENCRYPTED_DATA_LENGTH  (RSA_LENGTH)

#define PRIVATE_KEY_LENGTH              (2048)
#define PUBLIC_KEY_LENGTH               (294)


#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG ,__VA_ARGS__)

#define  LOG_TAG    "mbedTLS"

#define KEY_SIZE 2048
#define EXPONENT 65537

#define DFL_BITS    2048
#define GENERATOR "4"


/*extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_RSA(JNIEnv *env, jobject instance) {

    jintArray resultArray;
    resultArray = env->NewIntArray(3);
    jint fill[3];
    struct timeval st,et;

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

    gettimeofday(&st,NULL);

    return_val = mbedtls_rsa_pkcs1_encrypt( &rsa, mbedtls_ctr_drbg_random,
                                            &ctr_drbg, MBEDTLS_RSA_PUBLIC,
                                            strlen( argv[1] ), input, buf );

    gettimeofday(&et,NULL);

    int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[0] = encryption_time;

    if( return_val != 0 )
    {

        LOGD( " failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %d\n\n",
              return_val );
        return 0;
    }



    LOGD("Finished encryption");

    LOGD( "\n  . Decrypting the encrypted data" );

    gettimeofday(&st,NULL);

    return_val = mbedtls_rsa_pkcs1_decrypt( &rsa, mbedtls_ctr_drbg_random,
                                            &ctr_drbg, MBEDTLS_RSA_PRIVATE, &i,
                                            buf, result, 1024 );
    gettimeofday(&et,NULL);

    int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[1] = decryption_time;

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


    env->SetIntArrayRegion(resultArray, 0, 3, fill);
    return resultArray;

}*/

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_AESCBC(JNIEnv *env, jobject instance,jint blocksize) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];



    uint8_t Plaintext[blocksize];

    for (int i = 0; i <= sizeof(Plaintext); ++i) {
        Plaintext[i] = rand();

    }

    uint8_t key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };


    struct timeval st,et;
    uint8_t OutputMessage[64];
    uint8_t compare[64];
    uint32_t i=0,status = 0;

    mbedtls_aes_context ctx;
    mbedtls_aes_init( &ctx );
    status = mbedtls_aes_setkey_enc( &ctx, key, 128 );
    if(status != 0)
    {
        LOGD("\n mbedtls Encrypt set key failed");
    }

    gettimeofday(&st,NULL);
    status = mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_ENCRYPT, 64, iv, Plaintext, OutputMessage );
    gettimeofday(&et,NULL);
    int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[0] = encryption_time;
    if(status != 0)
    {
        LOGD("\n mbedtls encryption failed");
    }


    uint8_t iv2[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    mbedtls_aes_init( &ctx );
    status = mbedtls_aes_setkey_dec(&ctx, key, 128);
    if(status != 0)
    {
        LOGD("\n mbedtls decryption set key failed");
    }

    gettimeofday(&st,NULL);
    status = mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_DECRYPT, 64, iv2, OutputMessage,compare);
    gettimeofday(&et,NULL);
    int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[1] = decryption_time;
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

    env->SetIntArrayRegion(result, 0, 3, fill);
    return result;
}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_MD5(JNIEnv *env, jobject instance) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];
    struct timeval st,et;

    jintArray error[1];

    int i, ret;
    unsigned char digest[16];
    char str[] = "Hello, world!";

    LOGD( "\n  MD5('%s') = ", str );

    gettimeofday(&st,NULL);
    if(  (ret = mbedtls_md5_ret( (unsigned char *) str, 13, digest ))  != 0 ) {
        return 0;
    }
    gettimeofday(&et,NULL);

    int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    fill[1] = generation_time;


    for( i = 0; i < 16; i++ )
        LOGD( "%02x", digest[i] );

    LOGD( "Finished!" );

    env->SetIntArrayRegion(result, 0, 3, fill);

    return result;

}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_DH(JNIEnv *env, jobject instance) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];

    struct timeval st,et;

    int ret;
    size_t n1, buflen;
    size_t n2;
    unsigned char buf1[2048];
    unsigned char buf2[2048];
    mbedtls_dhm_context dhm1;
    mbedtls_ctr_drbg_context ctr_drbg1;
    mbedtls_entropy_context entropy1;

    mbedtls_dhm_context dhm2;
    mbedtls_ctr_drbg_context ctr_drbg2;
    mbedtls_entropy_context entropy2;

    const char *pers = "dh_test";

    mbedtls_dhm_init( &dhm1 );
    mbedtls_ctr_drbg_init( &ctr_drbg1 );

    mbedtls_dhm_init( &dhm2 );
    mbedtls_ctr_drbg_init( &ctr_drbg2 );

    mbedtls_entropy_init( &entropy1 );
    mbedtls_entropy_init( &entropy2 );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg1, mbedtls_entropy_func, &entropy1,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        LOGD( " failed 1\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
    }

    ret= mbedtls_mpi_read_string(&dhm1.P,16,MBEDTLS_DHM_RFC5114_MODP_2048_P);
    if(ret != 0){
        LOGD("Error at reading P 1");
    }

    ret = mbedtls_mpi_read_string(&dhm1.G,16,MBEDTLS_DHM_RFC5114_MODP_2048_G);
    if(ret != 0){
        LOGD("Error at reading G 1");
    }

    ret = mbedtls_dhm_make_params( &dhm1, (int) mbedtls_mpi_size( &dhm1.P ), buf1, &n1,
                                         mbedtls_ctr_drbg_random, &ctr_drbg1 );

    if(ret != 0){
        LOGD("Error at make params 1");
    }

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg2, mbedtls_entropy_func, &entropy2,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        LOGD( " failed 1\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
    }

    ret= mbedtls_mpi_read_string(&dhm2.P,16,MBEDTLS_DHM_RFC5114_MODP_2048_P);
    if(ret != 0){
        LOGD("Error at reading P 2");
    }

    ret = mbedtls_mpi_read_string(&dhm2.G,16,MBEDTLS_DHM_RFC5114_MODP_2048_G);
    if(ret != 0){
        LOGD("Error at reading G 2");
    }

    mbedtls_dhm_make_params( &dhm2, (int) mbedtls_mpi_size( &dhm2.P ), buf2, &n2,
                             mbedtls_ctr_drbg_random, &ctr_drbg2 );

    n2 = dhm2.len;
    if( ( ret = mbedtls_dhm_make_public( &dhm2, (int) dhm2.len, buf2, n2,
                                         mbedtls_ctr_drbg_random, &ctr_drbg2 ) ) != 0 )
    {
        LOGD( " failed\n  ! mbedtls_dhm_make_public returned %d\n\n", ret );
    }

    n1 = dhm2.len;
    if( ( ret = mbedtls_dhm_make_public( &dhm1, (int) dhm1.len, buf1, n1,
                                         mbedtls_ctr_drbg_random, &ctr_drbg1 ) ) != 0 )
    {
        LOGD( " failed\n  ! mbedtls_dhm_make_public returned %d\n\n", ret );
    }

    if( ( ret = mbedtls_dhm_read_public( &dhm2, buf1, dhm1.len ) ) != 0 )
    {
        LOGD( " failed\n  ! mbedtls_dhm_read_public returned %d\n\n", ret );
    }

    if( ( ret = mbedtls_dhm_read_public( &dhm1, buf2, dhm2.len ) ) != 0 )
    {
        LOGD( " failed\n  ! mbedtls_dhm_read_public returned %d\n\n", ret );
    }

    gettimeofday(&st,NULL);
    if( ( ret = mbedtls_dhm_calc_secret( &dhm1, buf1, sizeof( buf1 ), &n1,
                                         mbedtls_ctr_drbg_random, &ctr_drbg1 ) ) != 0 )
    {
        LOGD( " failed\n  ! mbedtls_dhm_calc_secret returned %d\n\n", ret );
    }

    if( ( ret = mbedtls_dhm_calc_secret( &dhm2, buf2, sizeof( buf2 ), &n2,
                                         mbedtls_ctr_drbg_random, &ctr_drbg2 ) ) != 0 )
    {
        LOGD( " failed\n  ! mbedtls_dhm_calc_secret returned %d\n\n", ret );
    }

    gettimeofday(&et,NULL);
    int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
    fill[1] = generation_time;

    LOGD("BUF1");
    for( int i = 0; i < 16; i++ )
        LOGD( "%02x", buf1[i] );
    LOGD("BUF2");
    for( int i = 0; i < 16; i++ )
        LOGD( "%02x", buf2[i] );

    LOGD("DH finished");

    env->SetIntArrayRegion(result, 0, 3, fill);

    return result;

}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_AESCTR(JNIEnv *env, jobject instance, jint blocksize) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];

    struct timeval st, et;

    unsigned char key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    unsigned char plaintext[64];

    for (int i = 0; i <= sizeof(plaintext) ; ++i) {
        plaintext[i] = rand();
    }


    size_t nc_off = 0;
    unsigned char stream_block[16] = {0};
    uint8_t enc_out[64];
    memset(enc_out, 0, sizeof(enc_out));

    uint8_t plain_out[64];
    memset(plain_out, 0, sizeof(plain_out));

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc( &aes, key, 128);

    int ret;

    gettimeofday(&st,NULL);
    ret = mbedtls_aes_crypt_ctr(&aes, sizeof(plaintext), &nc_off, iv, stream_block, plaintext, enc_out);
    gettimeofday(&et,NULL);
    int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    if (ret == 0){
        LOGD("Success encrypting");
    }

    fill[0] = encryption_time;

    gettimeofday(&st,NULL);
    ret = mbedtls_aes_crypt_ctr(&aes, sizeof(enc_out), &nc_off, iv, stream_block, enc_out, plain_out);
    gettimeofday(&et,NULL);
    int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

    if (ret == 0){
        LOGD("Success decrypting");
    }

    fill[1] = decryption_time;


    mbedtls_aes_free(&aes);

    env->SetIntArrayRegion(result, 0, 3, fill);

    return result;
}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_AESGCM(JNIEnv *env, jobject instance,jint blocksize) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];

    struct timeval st,et;

    unsigned char key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };

    unsigned char plaintext[64];

    for (int i = 0; i <= sizeof(plaintext); ++i) {
        plaintext[i] = rand();
    }

    unsigned char encrypted[64];
    unsigned char decrypted[64];

    unsigned char tag[16];

    mbedtls_gcm_context ctx;

    mbedtls_gcm_init(&ctx);

    int ret = mbedtls_gcm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,key, 128);
    if(ret != 0){
        LOGD("%i",ret);
    }

    gettimeofday(&st,NULL);

    //I use the "high-level" interface as explained in this post : https://tls.mbed.org/discussions/generic/aes-gcm-authenticated-encryption-example

   ret = mbedtls_gcm_crypt_and_tag(&ctx,MBEDTLS_GCM_ENCRYPT, sizeof(plaintext),iv, sizeof(iv),NULL,0,plaintext,encrypted,
                              sizeof(tag),tag);
    gettimeofday(&et,NULL);
    int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
    fill[0]=encryption_time;
    if(ret != 0){
        LOGD("Error encrypting");
        LOGD("%i",ret);
    }

    gettimeofday(&st,NULL);

    ret=mbedtls_gcm_auth_decrypt(&ctx,sizeof(encrypted),iv, sizeof(iv),NULL,0,tag, sizeof(tag),encrypted,decrypted);

    gettimeofday(&et,NULL);
    int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
    fill[1]=decryption_time;

    if(ret != 0){
        LOGD("Error decrypting");
        LOGD("%i",ret);
    }

    LOGD("We are good");

    env->SetIntArrayRegion(result, 0, 3, fill);

    return result;

}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_ECDH(JNIEnv *env, jobject instance) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];

    struct timeval st,et;

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_context entropy;

    mbedtls_entropy_init( &entropy );
    const char *pers = "ecdh_genkey";


    mbedtls_ecp_group grp;
    mbedtls_ecp_point qA, qB;
    mbedtls_mpi dA, dB, zA, zB;

    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &qA ); mbedtls_ecp_point_init( &qB );
    mbedtls_mpi_init( &dA ); mbedtls_mpi_init( &dB );
    mbedtls_mpi_init( &zA ); mbedtls_mpi_init( &zB );

    int ret;
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        LOGD( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
    }

    ret = mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_SECP256R1);
    if(ret != 0){
        LOGD("Error group load");
    }

    mbedtls_ecdh_gen_public( &grp, &dA, &qA, mbedtls_ctr_drbg_random, &ctr_drbg);
    if(ret != 0){
        LOGD("Error generating public 1");
    }

    mbedtls_ecdh_gen_public( &grp, &dB, &qB, mbedtls_ctr_drbg_random, &ctr_drbg );
    if(ret != 0){
        LOGD("Error generating public 2");
    }

    ret = mbedtls_ecdh_compute_shared( &grp, &zA, &qB, &dA,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
    if(ret != 0){
        LOGD("Error generating secret 1");
    }

    gettimeofday(&st,NULL);
    ret = mbedtls_ecdh_compute_shared( &grp, &zB, &qA, &dB,
                                       NULL, NULL );
    gettimeofday(&et,NULL);
    int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
    fill[1]=generation_time;

    if(ret != 0){
        LOGD("Error generating secret 2");
    }

    ret = mbedtls_mpi_cmp_mpi( &zA, &zB );

    if(ret != 0){
        LOGD("Error comparing secrets");
    }
    LOGD("We are good");

    env->SetIntArrayRegion(result, 0, 3, fill);

    return result;

}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_RSA(JNIEnv *env, jobject instance) {

    jintArray result;
    result = env->NewIntArray(3);
    jint fill[3];


    struct timeval st,et;

    unsigned char plaintext[]= {0x8d, 0x4c, 0xa8, 0xf4, 0x47, 0x02, 0x9a, 0x92,
                                0x65, 0x27, 0xbd, 0x49, 0x12, 0xd2, 0xc6, 0xcc,
                                0xc7, 0x2b, 0x18, 0x02, 0x90, 0x4a, 0xd6, 0x65,
                                0x6f, 0x2a, 0x3c, 0x40, 0x68, 0xf5, 0x36, 0x70,
                                0xd4, 0x52, 0x82, 0xae, 0xa8, 0xa2, 0x38, 0xc0,
                                0x00, 0x13, 0x5f, 0x15, 0x45, 0x1a, 0x95, 0x17,
                                0xc1, 0x62, 0x9e, 0xc8, 0xe3, 0xe2, 0xc4, 0xf7,
                                0xbf, 0xaa, 0xef, 0xfb, 0x15, 0xde, 0xa8, 0xa9,
                                0x64, 0x3e, 0x0e, 0x5a, 0xa0, 0x12, 0x7d, 0x0d,
                                0x5b, 0xb1, 0xef, 0xf3, 0xaf, 0xed, 0x8f, 0x5b,
                                0xd8, 0xb3, 0xbc, 0xa1, 0x35, 0xd1};


    int ret = 0;
    mbedtls_pk_context pk;
    mbedtls_pk_context privk;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    size_t olen = 0;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_context ctr_drbg2;
    mbedtls_entropy_context entropy;
    const char *pers = "rsa_genkey";


    mbedtls_pk_init( &pk );
    mbedtls_pk_init( &privk );

    size_t olen_dec = 0;
    unsigned char output_decrypted[MBEDTLS_MPI_MAX_SIZE];

    ret = mbedtls_pk_parse_public_keyfile( &pk,"/sdcard/CryptoBench/public_key.txt");

    /*
     * Read the RSA public key
     */
    if( ret != 0 )
    {
        LOGD( " Error parsing public keyfile" );
        return result;
    }

    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        LOGD( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return result;
    }

    mbedtls_ctr_drbg_init( &ctr_drbg2 );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg2, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        LOGD( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return result;
    }

    gettimeofday(&st,NULL);
    ret = mbedtls_pk_encrypt( &pk, plaintext, sizeof(plaintext),
                              buf, &olen, sizeof(buf),
                              mbedtls_ctr_drbg_random, &ctr_drbg );
    gettimeofday(&et,NULL);
    int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
    fill[0]=encryption_time;



    if( ret != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -ret );
        return result;
    }

    mbedtls_pk_free(&pk);


    ret = mbedtls_pk_parse_keyfile( &privk, "/sdcard/CryptoBench/private_key.txt",NULL);

    if( ret != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_parsing private key, -ret" );
        return result;
    }

    gettimeofday(&st,NULL);
    ret =mbedtls_pk_decrypt( &privk, buf, olen, output_decrypted, &olen_dec, sizeof(output_decrypted),
                             mbedtls_ctr_drbg_random, &ctr_drbg2 );
    gettimeofday(&et,NULL);
    int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
    fill[1]=decryption_time;
    if(ret !=0){
        LOGD(" failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n", -ret);
    }


    LOGD( " ok\n" );

    LOGD("We are good");


    env->SetIntArrayRegion(result, 0, 3, fill);

    return result;

}
