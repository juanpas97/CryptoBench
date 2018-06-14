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

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_AESCBC(JNIEnv *env, jobject instance,jint blocksize,jint rep_aes) {

    jintArray result;
    int array_len = rep_aes * 2;
    result = env->NewIntArray(array_len);
    jint fill[array_len];



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

    uint8_t iv2[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };


    struct timeval st,et;
    uint8_t OutputMessage[blocksize];
    uint8_t compare[blocksize];
    uint32_t i=0,status = 0;

    mbedtls_aes_context ctx,ctx_dec;

    mbedtls_aes_init( &ctx );
    status = mbedtls_aes_setkey_enc( &ctx, key, 128 );
    if(status != 0)
    {
        LOGD("\n mbedtls Encrypt set key failed");
    }

    mbedtls_aes_init( &ctx_dec );
    status = mbedtls_aes_setkey_dec(&ctx_dec, key, 128);
    if(status != 0)
    {
        LOGD("\n mbedtls decryption set key failed");
    }

    int index = 0;

    for (int i = 0; i < rep_aes ; i++) {
        gettimeofday(&st, NULL);
        status = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, blocksize, iv, Plaintext, OutputMessage);
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index] = encryption_time;
        if (status != 0) {
            LOGD("\n mbedtls encryption failed");
        }


        gettimeofday(&st, NULL);
        status = mbedtls_aes_crypt_cbc(&ctx_dec, MBEDTLS_AES_DECRYPT, blocksize, iv2, OutputMessage,
                                       compare);
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[index + 1] = decryption_time;
        if (status != 0) {
            LOGD("\n mbedtls encryption failed");
        }

        index += 2;
    }

    LOGD("AES finished");
    //LOGD("Plain decrypted:");
    //for (int i = 0; i < 64; ++i) {
     //   LOGD("%x", compare[i]);
    //}
    mbedtls_aes_free( &ctx );

    env->SetIntArrayRegion(result, 0, array_len, fill);
    return result;
}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_MD5(JNIEnv *env, jobject instance,jint blocksize,jint rep_hash) {

    LOGD("rep_hash is: %i", rep_hash);

    jintArray result;
    result = env->NewIntArray(rep_hash);
    jint fill[rep_hash];
    struct timeval st,et;

    jintArray error[1];

    int i, ret;
    unsigned char digest[1024];
    uint8_t Plaintext[blocksize];

    for (int i = 0; i <= sizeof(Plaintext); ++i) {
        Plaintext[i] = rand();

    }

    for (int i = 0; i < rep_hash; ++i) {


        gettimeofday(&st, NULL);
        if ((ret = mbedtls_md5_ret(Plaintext, sizeof(Plaintext), digest)) != 0) {
            return 0;
        }
        gettimeofday(&et, NULL);

        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fill[i] = generation_time;


        //for( i = 0; i < 16; i++ )
        //    LOGD( "%02x", digest[i] );
    }
    LOGD( "Finished!" );

    env->SetIntArrayRegion(result, 0, rep_hash, fill);

    return result;

}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_DH(JNIEnv *env, jobject instance,jint rep_agree) {

    jintArray result;
    result = env->NewIntArray(rep_agree);
    jint fill[rep_agree];

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

    for (int i = 0; i < rep_agree; ++i) {


        gettimeofday(&et, NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fill[i] = generation_time;

        if ((ret = mbedtls_dhm_calc_secret(&dhm2, buf2, sizeof(buf2), &n2,
                                           mbedtls_ctr_drbg_random, &ctr_drbg2)) != 0) {
            LOGD(" failed\n  ! mbedtls_dhm_calc_secret returned %d\n\n", ret);
        }

    }
    //LOGD("BUF1");
    //for( int i = 0; i < 16; i++ )
    //    LOGD( "%02x", buf1[i] );
    //LOGD("BUF2");
    //for( int i = 0; i < 16; i++ )
     //   LOGD( "%02x", buf2[i] );

    LOGD("DH finished");

    env->SetIntArrayRegion(result, 0, rep_agree, fill);

    return result;

}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_AESCTR(JNIEnv *env, jobject instance, jint blocksize, jint rep_aes) {

    jintArray result;
    int array_len = rep_aes * 2;
    result = env->NewIntArray(array_len);
    jint fill[array_len];

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

    int index = 0;

    for (int i = 0; i < rep_aes ; i++) {
        gettimeofday(&st, NULL);
        ret = mbedtls_aes_crypt_ctr(&aes, sizeof(plaintext), &nc_off, iv, stream_block, plaintext,
                                    enc_out);
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        if (ret == 0) {
            LOGD("Success encrypting");
        }

        fill[index] = encryption_time;

        gettimeofday(&st, NULL);
        ret = mbedtls_aes_crypt_ctr(&aes, sizeof(enc_out), &nc_off, iv, stream_block, enc_out,
                                    plain_out);
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        if (ret == 0) {
            LOGD("Success decrypting");
        }

        fill[index + 1] = decryption_time;

        index += 2;

    }
    mbedtls_aes_free(&aes);

    env->SetIntArrayRegion(result, 0, array_len, fill);

    return result;
}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_AESGCM(JNIEnv *env, jobject instance,jint blocksize,jint rep_aes) {

    jintArray result;
    int array_len = rep_aes * 2;
    result = env->NewIntArray(rep_aes*2);
    jint fill[array_len];


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

    int index = 0;

    for (int i = 0; i < rep_aes ; i++) {
        gettimeofday(&st, NULL);

        //I use the "high-level" interface as explained in this post : https://tls.mbed.org/discussions/generic/aes-gcm-authenticated-encryption-example

        ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, sizeof(plaintext), iv,
                                        sizeof(iv), NULL, 0, plaintext, encrypted,
                                        sizeof(tag), tag);
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fill[index] = encryption_time;
        if (ret != 0) {
            LOGD("Error encrypting");
            LOGD("%i", ret);
        }

        gettimeofday(&st, NULL);

        ret = mbedtls_gcm_auth_decrypt(&ctx, sizeof(encrypted), iv, sizeof(iv), NULL, 0, tag,
                                       sizeof(tag), encrypted, decrypted);

        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fill[index + 1] = decryption_time;

        if (ret != 0) {
            LOGD("Error decrypting");
            LOGD("%i", ret);
        }
        index += 2;
    }

    LOGD("We are good");

    env->SetIntArrayRegion(result, 0, array_len, fill);

    return result;

}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_ECDH(JNIEnv *env, jobject instance, jint rep_agree) {

    jintArray result;
    result = env->NewIntArray(rep_agree);
    jint fill[rep_agree];

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

    for(int i = 0; i < rep_agree; i++) {
        gettimeofday(&st, NULL);
        ret = mbedtls_ecdh_compute_shared(&grp, &zB, &qA, &dB,
                                          NULL, NULL);
        gettimeofday(&et, NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fill[i] = generation_time;

        if (ret != 0) {
            LOGD("Error generating secret 2");
        }
    }
    ret = mbedtls_mpi_cmp_mpi( &zA, &zB );

    if(ret != 0){
        LOGD("Error comparing secrets");
    }
    LOGD("We are good");

    env->SetIntArrayRegion(result, 0, rep_agree, fill);

    return result;

}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_RSA(JNIEnv *env, jobject instance,jint blocksize,jint rep_aes) {

    jintArray result;
    int array_len = rep_aes * 2;
    result = env->NewIntArray(array_len);
    jint fill[array_len];


    struct timeval st,et;

    unsigned char plaintext[blocksize];

    for (int i = 0;  i <= sizeof(plaintext); i++) {
       plaintext[i] = rand();
    }


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
    mbedtls_rsa_set_padding( mbedtls_pk_rsa( pk ),  MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1 );
    unsigned char label[1024] = "label";

    ret = mbedtls_pk_parse_keyfile( &privk, "/sdcard/CryptoBench/private_key.txt",NULL);

    if( ret != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_parsing private key, -ret" );
        return result;
    }

    mbedtls_rsa_set_padding( mbedtls_pk_rsa( privk ),  MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1 );

    int index = 0;

    for (int i = 0; i < rep_aes ; i++) {

        gettimeofday(&st, NULL);

        ret = mbedtls_rsa_rsaes_oaep_encrypt(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctr_drbg,
                                             MBEDTLS_RSA_PUBLIC, label,
                                             sizeof(label),
                                             sizeof(plaintext), plaintext, buf);
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fill[index] = encryption_time;


        if (ret != 0) {
            printf(" failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -ret);
            return result;
        }

        LOGD("Encrypt was good");

        //mbedtls_pk_free(&pk);


        gettimeofday(&st, NULL);

        ret = mbedtls_rsa_rsaes_oaep_decrypt(mbedtls_pk_rsa(privk), mbedtls_ctr_drbg_random,
                                             &ctr_drbg2, MBEDTLS_RSA_PRIVATE, label,
                                             sizeof(label), &olen_dec, buf, output_decrypted, 1024);
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fill[index + 1] = decryption_time;
        if (ret != 0) {
            LOGD(" failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n", -ret);
        }

        index += 2;
    }

    LOGD( " ok\n" );

    LOGD("RSA good");


    env->SetIntArrayRegion(result, 0, array_len, fill);

    return result;

}


extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_RSATime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_rsa) {




    struct timeval st,et;

    unsigned char plaintext[blocksize];

    for (int i = 0;  i <= sizeof(plaintext); i++) {
        plaintext[i] = rand();
    }

    FILE* report = create_file();
    if(report == NULL){
        LOGD("Error rediang the file");

    }

    int ret = 0;
    mbedtls_pk_context pk;
    mbedtls_pk_context privk;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    size_t olen = 0;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_context ctr_drbg2;
    mbedtls_entropy_context entropy;
    unsigned char label[1024] = "label";
    const char *pers = "rsa_genkey";

    fprintf(report,"************mbedTLS/RSA**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);

    size_t olen_dec = 0;
    unsigned char output_decrypted[MBEDTLS_MPI_MAX_SIZE];

    time_t start_key = time(NULL);
    time_t now_key = time(NULL);
    int repetitions_key = 0;
    while ((now_key - start_key) <= rep_key) {
        gettimeofday(&st, NULL);


    mbedtls_pk_init( &pk );
    mbedtls_pk_init( &privk );



    ret = mbedtls_pk_parse_public_keyfile( &pk,"/sdcard/CryptoBench/public_key.txt");

    /*
     * Read the RSA public key
     */
    if( ret != 0 )
    {
        LOGD( " Error parsing public keyfile" );
        return ;
    }

    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        LOGD( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return ;
    }

    mbedtls_ctr_drbg_init( &ctr_drbg2 );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg2, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        LOGD( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return ;
    }
    mbedtls_rsa_set_padding( mbedtls_pk_rsa( pk ),  MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1 );


    ret = mbedtls_pk_parse_keyfile( &privk, "/sdcard/CryptoBench/private_key.txt",NULL);

    if( ret != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_parsing private key, -ret" );
        return;
    }

    mbedtls_rsa_set_padding( mbedtls_pk_rsa( privk ),  MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1 );

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

        ret = mbedtls_rsa_rsaes_oaep_encrypt(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctr_drbg,
                                             MBEDTLS_RSA_PUBLIC, label,
                                             sizeof(label),
                                             sizeof(plaintext), plaintext, buf);
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fprintf(report,"Time to encrypt: %i ms\n", encryption_time );


        if (ret != 0) {
            printf(" failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -ret);
            return ;
        }

        LOGD("Encrypt was good");

        //mbedtls_pk_free(&pk);


        gettimeofday(&st, NULL);
        ret = mbedtls_rsa_rsaes_oaep_decrypt(mbedtls_pk_rsa(privk), mbedtls_ctr_drbg_random,
                                             &ctr_drbg2, MBEDTLS_RSA_PRIVATE, label,
                                             sizeof(label), &olen_dec, buf, output_decrypted, 1024);
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fprintf(report,"Time to decrypt: %i ms\n", decryption_time );
        if (ret != 0) {
            LOGD(" failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n", -ret);
        }

        repetitions_rsa += 1;
        now = time(NULL);
    }

    LOGD("We are good");

    fprintf(report, "Times performed: %i \n",repetitions_rsa);
    fprintf(report,"*****************************");
    fclose (report);

    LOGD( " ok\n" );

    LOGD("RSA good");



    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_MD5Time(JNIEnv *env, jobject instance,jint blocksize,jint rep_hash) {

    LOGD("rep_hash is: %i", rep_hash);

    FILE* report = create_file();
    if(report == NULL){
        LOGD("Error rediang the file");

    }

    struct timeval st,et;

    fprintf(report,"************mbedTLS/MD5**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);

    int i, ret;
    unsigned char digest[1024];
    uint8_t Plaintext[blocksize];

    for (int i = 0; i <= sizeof(Plaintext); ++i) {
        Plaintext[i] = rand();

    }

    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions_rsa = 0;
    while ((now - start) <= rep_hash) {


        gettimeofday(&st, NULL);
        if ((ret = mbedtls_md5_ret(Plaintext, sizeof(Plaintext), digest)) != 0) {
            return ;
        }
        gettimeofday(&et, NULL);

        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fprintf(report,"Time to generate hash: %i ms\n", generation_time );

        repetitions_rsa += 1;
        now = time(NULL);
    }

    LOGD("We are good");

    fprintf(report, "Times performed: %i \n",repetitions_rsa);
    fprintf(report,"*****************************");
    fclose (report);
    LOGD( "Finished!" );

    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_DHTime(JNIEnv *env, jobject instance,jint rep_key,jint rep_agree) {

    jintArray result;
    result = env->NewIntArray(rep_agree);
    jint fill[rep_agree];

    FILE* report = create_file();
    if(report == NULL){
        LOGD("Error rediang the file");

    }

    struct timeval st,et;

    fprintf(report,"************mbedTLS/DH**************\n");

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

    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions = 0;
    while ((now - start) <= rep_key) {
        gettimeofday(&st,NULL);

    mbedtls_dhm_init(&dhm1);
    mbedtls_ctr_drbg_init(&ctr_drbg1);

    mbedtls_dhm_init(&dhm2);
    mbedtls_ctr_drbg_init(&ctr_drbg2);

    mbedtls_entropy_init(&entropy1);
    mbedtls_entropy_init(&entropy2);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg1, mbedtls_entropy_func, &entropy1,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        LOGD(" failed 1\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    }


    ret = mbedtls_mpi_read_string(&dhm1.P, 16, MBEDTLS_DHM_RFC5114_MODP_2048_P);
    if (ret != 0) {
        LOGD("Error at reading P 1");
    }

    ret = mbedtls_mpi_read_string(&dhm1.G, 16, MBEDTLS_DHM_RFC5114_MODP_2048_G);
    if (ret != 0) {
        LOGD("Error at reading G 1");
    }

    ret = mbedtls_dhm_make_params(&dhm1, (int) mbedtls_mpi_size(&dhm1.P), buf1, &n1,
                                  mbedtls_ctr_drbg_random, &ctr_drbg1);

    if (ret != 0) {
        LOGD("Error at make params 1");
    }

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg2, mbedtls_entropy_func, &entropy2,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        LOGD(" failed 1\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    }

    ret = mbedtls_mpi_read_string(&dhm2.P, 16, MBEDTLS_DHM_RFC5114_MODP_2048_P);
    if (ret != 0) {
        LOGD("Error at reading P 2");
    }

    ret = mbedtls_mpi_read_string(&dhm2.G, 16, MBEDTLS_DHM_RFC5114_MODP_2048_G);
    if (ret != 0) {
        LOGD("Error at reading G 2");
    }

    mbedtls_dhm_make_params(&dhm2, (int) mbedtls_mpi_size(&dhm2.P), buf2, &n2,
                            mbedtls_ctr_drbg_random, &ctr_drbg2);

    n2 = dhm2.len;
    if ((ret = mbedtls_dhm_make_public(&dhm2, (int) dhm2.len, buf2, n2,
                                       mbedtls_ctr_drbg_random, &ctr_drbg2)) != 0) {
        LOGD(" failed\n  ! mbedtls_dhm_make_public returned %d\n\n", ret);
    }

    n1 = dhm2.len;
    if ((ret = mbedtls_dhm_make_public(&dhm1, (int) dhm1.len, buf1, n1,
                                       mbedtls_ctr_drbg_random, &ctr_drbg1)) != 0) {
        LOGD(" failed\n  ! mbedtls_dhm_make_public returned %d\n\n", ret);
    }

    if ((ret = mbedtls_dhm_read_public(&dhm2, buf1, dhm1.len)) != 0) {
        LOGD(" failed\n  ! mbedtls_dhm_read_public returned %d\n\n", ret);
    }

    if ((ret = mbedtls_dhm_read_public(&dhm1, buf2, dhm2.len)) != 0) {
        LOGD(" failed\n  ! mbedtls_dhm_read_public returned %d\n\n", ret);
    }
        gettimeofday(&et,NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fprintf(report, "Time to set key: %i \n",generation_time);

        now = time(NULL);
        repetitions +=1;

    }
    fprintf(report,"Times key set: %i \n",repetitions);

    start = time(NULL);
    now = time(NULL);
    repetitions = 0;
    while ((now - start) <= rep_agree) {

    gettimeofday(&st, NULL);
    if ((ret = mbedtls_dhm_calc_secret(&dhm1, buf1, sizeof(buf1), &n1,
                                       mbedtls_ctr_drbg_random, &ctr_drbg1)) != 0) {
        LOGD(" failed\n  ! mbedtls_dhm_calc_secret returned %d\n\n", ret);
    }


        gettimeofday(&et, NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fprintf(report,"Times to generate key agreement: %i \n",generation_time);

        if ((ret = mbedtls_dhm_calc_secret(&dhm2, buf2, sizeof(buf2), &n2,
                                           mbedtls_ctr_drbg_random, &ctr_drbg2)) != 0) {
            LOGD(" failed\n  ! mbedtls_dhm_calc_secret returned %d\n\n", ret);
        }
        now = time(NULL);
        repetitions += 1;
    }

    fprintf(report, "Times performed: %i \n",repetitions);
    fprintf(report,"*****************************");
    fclose (report);

    LOGD("DH finished");

    return;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_ECDHTime(JNIEnv *env, jobject instance, jint rep_key,jint rep_agree) {



    FILE* report = create_file();
    if(report == NULL){
        LOGD("Error rediang the file");

    }

    struct timeval st,et;

    fprintf(report,"************mbedTLS/ECDH**************\n");

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_context entropy;

    mbedtls_entropy_init( &entropy );
    const char *pers = "ecdh_genkey";


    mbedtls_ecp_group grp;
    mbedtls_ecp_point qA, qB;
    mbedtls_mpi dA, dB, zA, zB;

    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions = 0;
    while ((now - start) <= rep_key) {
        gettimeofday(&st,NULL);

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

        gettimeofday(&et,NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        fprintf(report, "Time to set key: %i \n",generation_time);

        now = time(NULL);
        repetitions +=1;

    }
    fprintf(report,"Times key set: %i \n",repetitions);

    start = time(NULL);
    now = time(NULL);
    repetitions = 0;
    while ((now - start) <= rep_agree) {


        gettimeofday(&st, NULL);
        int ret = mbedtls_ecdh_compute_shared(&grp, &zB, &qA, &dB,
                                          NULL, NULL);
        gettimeofday(&et, NULL);
        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Times to generate key agreement: %i \n",generation_time);


        if (ret != 0) {
            LOGD("Error generating secret 2");
        }
        now = time(NULL);
        repetitions += 1;
    }

    fprintf(report, "Times performed: %i \n",repetitions);
    fprintf(report,"*****************************");
    fclose (report);

    LOGD("We are good");

    return ;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_AESCBCTime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_aes) {


    FILE* report = create_file();
    fprintf(report,"************mbedTLS/AESCBC**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);



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

    uint8_t iv2[16] = {
            0x09, 0xcf,0x15, 0x88, 0x4f, 0x3c,0x2b, 0x7e, 0x15,0xae,0x16, 0x28, 0xd2, 0xa6, 0xab, 0xf7,

    };


    struct timeval st,et;
    uint8_t OutputMessage[blocksize];
    uint8_t compare[blocksize];
    uint32_t i=0,status = 0;

    mbedtls_aes_context ctx,ctx_dec;

    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions = 0;

    while ((now - start) <= rep_key) {

        gettimeofday(&st,NULL);

    mbedtls_aes_init( &ctx );
    status = mbedtls_aes_setkey_enc( &ctx, key, 128 );
    if(status != 0)
    {
        LOGD("\n mbedtls Encrypt set key failed");
    }

    mbedtls_aes_init( &ctx_dec );
    status = mbedtls_aes_setkey_dec(&ctx_dec, key, 128);
    if(status != 0)
    {
        LOGD("\n mbedtls decryption set key failed");
    }
        gettimeofday(&et,NULL);gettimeofday(&et,NULL);
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
        gettimeofday(&st, NULL);
        status = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, blocksize, iv, Plaintext, OutputMessage);
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to encrypt: %i ms\n", encryption_time);
        if (status != 0) {
            LOGD("\n mbedtls encryption failed");
        }


        gettimeofday(&st, NULL);
        status = mbedtls_aes_crypt_cbc(&ctx_dec, MBEDTLS_AES_DECRYPT, blocksize, iv2, OutputMessage,
                                       compare);
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report,"Time to decrypt: %i ms\n", decryption_time);
        if (status != 0) {
            LOGD("\n mbedtls encryption failed");
        }

        now = time(NULL);
        repetitions  += 1;
    }

    fprintf(report,"Times performed: %i \n",repetitions);
    fprintf(report,"*****************************");
    fclose(report);

    LOGD("AES finished");
    //LOGD("Plain decrypted:");
    //for (int i = 0; i < 64; ++i) {
    //   LOGD("%x", compare[i]);
    //}
    mbedtls_aes_free( &ctx );

    return ;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_AESCTRTime(JNIEnv *env, jobject instance, jint blocksize, jint rep_key,jint rep_aes) {

    FILE *report = create_file();
    fprintf(report, "************mbedTLS/AESCTR**************\n");
    fprintf(report, "Blocksize is: %i  \n", blocksize);

    struct timeval st, et;

    unsigned char key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
            0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char iv[16] = {
            0x09, 0xcf, 0x15, 0x88, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0xae, 0x16, 0x28, 0xd2, 0xa6,
            0xab, 0xf7,

    };

    unsigned char plaintext[64];

    for (int i = 0; i <= sizeof(plaintext); ++i) {
        plaintext[i] = rand();
    }


    size_t nc_off = 0;
    unsigned char stream_block[16] = {0};
    uint8_t enc_out[64];
    memset(enc_out, 0, sizeof(enc_out));

    uint8_t plain_out[64];
    memset(plain_out, 0, sizeof(plain_out));

    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions = 0;
    mbedtls_aes_context aes;

    while ((now - start) <= rep_key) {

        gettimeofday(&st, NULL);


        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, key, 128);
        gettimeofday(&et, NULL);

        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report, "Time to set key: %i ms\n", generation_time);

        repetitions += 1;

        now = time(NULL);
    }

    fprintf(report, "Times set key: %i ms\n", repetitions);

    start = time(NULL);
    now = time(NULL);
    repetitions = 0;
    while ((now - start) <= rep_aes) {
        gettimeofday(&st, NULL);
        int ret = mbedtls_aes_crypt_ctr(&aes, sizeof(plaintext), &nc_off, iv, stream_block,
                                        plaintext,
                                        enc_out);
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        if (ret == 0) {
            LOGD("Success encrypting");
        }

        fprintf(report, "Time to encrypt: %i ms\n", encryption_time);

        gettimeofday(&st, NULL);
        ret = mbedtls_aes_crypt_ctr(&aes, sizeof(enc_out), &nc_off, iv, stream_block, enc_out,
                                    plain_out);
        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        if (ret == 0) {
            LOGD("Success decrypting");
        }

        fprintf(report, "Time to decrypt: %i ms\n", decryption_time);


        now = time(NULL);
        repetitions += 1;
    }

    fprintf(report, "Times performed: %i \n", repetitions);
    fprintf(report, "*****************************");
    fclose(report);
    mbedtls_aes_free(&aes);


    return;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_AESGCMTime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_aes) {

    FILE *report = create_file();
    fprintf(report, "************mbedTLS/AESGCM**************\n");
    fprintf(report, "Blocksize is: %i  \n", blocksize);

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

    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions = 0;

    while ((now - start) <= rep_key) {

        gettimeofday(&st, NULL);
        mbedtls_gcm_init(&ctx);

        int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
        if (ret != 0) {
            LOGD("%i", ret);
        }
        LOGD("Setting key finished");
        gettimeofday(&et, NULL);

        int generation_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        fprintf(report, "Time to set key: %i ms\n", generation_time);

        repetitions += 1;

        now = time(NULL);
    }
    LOGD("Before printing");
    fprintf(report, "Times set key: %i ms\n", repetitions);

    start = time(NULL);
    now = time(NULL);
    repetitions = 0;
    LOGD("Finish set key");
    while ((now - start) <= rep_aes) {
        gettimeofday(&st, NULL);

        //I use the "high-level" interface as explained in this post : https://tls.mbed.org/discussions/generic/aes-gcm-authenticated-encryption-example

        int ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, sizeof(plaintext), iv,
                                        sizeof(iv), NULL, 0, plaintext, encrypted,
                                        sizeof(tag), tag);
        gettimeofday(&et, NULL);
        int encryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
        if (ret != 0) {
            LOGD("Error encrypting");
            LOGD("%i", ret);
        }

        fprintf(report, "Time to encrypt: %i ms\n", encryption_time);

        gettimeofday(&st, NULL);

        ret = mbedtls_gcm_auth_decrypt(&ctx, sizeof(encrypted), iv, sizeof(iv), NULL, 0, tag,
                                       sizeof(tag), encrypted, decrypted);

        gettimeofday(&et, NULL);
        int decryption_time = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);

        if (ret != 0) {
            LOGD("Error decrypting");
            LOGD("%i", ret);
        }

        fprintf(report, "Time to decrypt: %i ms\n", decryption_time);
        now = time(NULL);
        repetitions += 1;
    }

    fprintf(report, "Times performed: %i \n", repetitions);
    fprintf(report, "*****************************");
    fclose(report);

    LOGD("We are good");


    return;

}
