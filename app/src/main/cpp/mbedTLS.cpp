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

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_AESCBC(JNIEnv *env, jobject instance,jint blocksize,jint rep_aes,jint rep_total) {

    FILE *report = create_file();
    fprintf(report, "************mbedTLS/AESCBC**************\n");
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
            0x09, 0xcf, 0x15, 0x88, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0xae, 0x16, 0x28, 0xd2, 0xa6,
            0xab, 0xf7,

    };

    uint8_t iv2[16] = {
            0x09, 0xcf, 0x15, 0x88, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0xae, 0x16, 0x28, 0xd2, 0xa6,
            0xab, 0xf7,

    };


    struct timeval st, et;
    uint8_t OutputMessage[blocksize];
    uint8_t compare[blocksize];
    uint32_t i = 0, status = 0;

    mbedtls_aes_context ctx, ctx_dec;

    mbedtls_aes_init(&ctx);
    status = mbedtls_aes_setkey_enc(&ctx, key, 128);
    if (status != 0) {
        LOGD("\n mbedtls Encrypt set key failed");
    }

    mbedtls_aes_init(&ctx_dec);
    status = mbedtls_aes_setkey_dec(&ctx_dec, key, 128);
    if (status != 0) {
        LOGD("\n mbedtls decryption set key failed");
    }
    for (int j = 0; j < rep_total; j++) {
    int repetitions = 0;
        gettimeofday(&st, NULL);
    for (int i = 0; i < rep_aes; i++) {

        status = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, blocksize, iv, Plaintext,
                                       OutputMessage);

        if (status != 0) {
            LOGD("\n mbedtls encryption failed");
        }


        repetitions += 1;
    }
    gettimeofday(&et, NULL);
    double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = (repetitions * blocksize) / time;
    fprintf(report, "Repetitions: %i \n", repetitions);
    fprintf(report, "Seconds: %f \n", time);
    fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
}
        for (int j = 0; j < rep_total; j++) {
            int repetitions = 0;
            gettimeofday(&st, NULL);
        for (int x = 0; x <rep_aes ;x++) {

        status = mbedtls_aes_crypt_cbc(&ctx_dec, MBEDTLS_AES_DECRYPT, blocksize, iv2, OutputMessage,
                                       compare);
        if (status != 0) {
            LOGD("\n mbedtls encryption failed");
        }

        repetitions += 1;
    }
    gettimeofday(&et, NULL);
    double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = (repetitions * blocksize) / time;
    fprintf(report, "Repetitions: %i \n", repetitions);
    fprintf(report, "Seconds: %f \n", time);
    fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
}

    LOGD("AES finished");
    //LOGD("Plain decrypted:");
    //for (int i = 0; i < 64; ++i) {
     //   LOGD("%x", compare[i]);
    //}
    mbedtls_aes_free( &ctx );
    fclose(report);
    return ;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_MD5(JNIEnv *env, jobject instance,jint blocksize,jint rep_hash,jint rep_total) {

    FILE *report = create_file();
    fprintf(report, "************mbedTLS/MD5**************\n");

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

    for (int j = 0; j < rep_total; j++) {

        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int x = 0; x < rep_hash; x++) {

            if ((ret = mbedtls_md5_ret(Plaintext, sizeof(Plaintext), digest)) != 0) {
                return;
            }
            repetitions += 1;
        }
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time hashing: %f bytes/second \n", result_agree);
    }
    LOGD( "Finished!" );

    fprintf(report,"********************");
    fclose(report);
    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_DH(JNIEnv *env, jobject instance,jint rep_agree,jint rep_total) {

    jintArray result;
    result = env->NewIntArray(rep_agree);
    jint fill[rep_agree];

    FILE *report = create_file();
    fprintf(report, "************mbedTLS/DH**************\n");

    struct timeval st, et;

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


    if ((ret = mbedtls_dhm_calc_secret(&dhm1, buf1, sizeof(buf1), &n1,
                                       mbedtls_ctr_drbg_random, &ctr_drbg1)) != 0) {
        LOGD(" failed\n  ! mbedtls_dhm_calc_secret returned %d\n\n", ret);
    }

    for (int i = 0; i < rep_total; i++) {
        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int j = 0; j < rep_agree; j++) {

            if ((ret = mbedtls_dhm_calc_secret(&dhm2, buf2, sizeof(buf2), &n2,
                                               mbedtls_ctr_drbg_random, &ctr_drbg2)) != 0) {
                LOGD(" failed\n  ! mbedtls_dhm_calc_secret returned %d\n\n", ret);
            }

            repetitions += 1;
        }

        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions) / time;

        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Result: %f key agreements/second \n", result_agree);
    }
    fclose(report);

    LOGD("DH finished");


    return ;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_AESCTR(JNIEnv *env, jobject instance, jint blocksize, jint rep_aes,jint rep_total) {


    FILE *report = create_file();
    fprintf(report, "************mbedTLS/AESCTR**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);

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

    for(int j = 0; j < rep_total; j++) {
        int ret;
        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int i = 0; i < rep_aes; i++) {

            ret = mbedtls_aes_crypt_ctr(&aes, sizeof(plaintext), &nc_off, iv, stream_block,
                                        plaintext,
                                        enc_out);
            gettimeofday(&et, NULL);

            if (ret == 0) {
                LOGD("Success encrypting");
            }
            repetitions += 1;
        }
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
    }

    for(int j = 0; j < rep_total; j++) {
    int repetitions = 0;
    int ret = 0;
        gettimeofday(&st, NULL);
    for (int i = 0; i < rep_aes ; i++) {
        ret = mbedtls_aes_crypt_ctr(&aes, sizeof(enc_out), &nc_off, iv, stream_block, enc_out,
                                    plain_out);

        if (ret == 0) {
            LOGD("Success decrypting");
        }

        repetitions += 1;
    }
    gettimeofday(&et, NULL);
    double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = (repetitions * blocksize) / time;
    fprintf(report, "Repetitions: %i \n", repetitions);
    fprintf(report, "Seconds: %f \n", time);
    fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
    }
    mbedtls_aes_free(&aes);

    fclose(report);

    return;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_AESGCM(JNIEnv *env, jobject instance,jint blocksize,jint rep_aes,jint rep_total) {

    FILE *report = create_file();
    fprintf(report, "************mbedTLS/AESGCM**************\n");
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

    unsigned char encrypted[64];
    unsigned char decrypted[64];

    unsigned char tag[16];

    mbedtls_gcm_context ctx;

    mbedtls_gcm_init(&ctx);

    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (ret != 0) {
        LOGD("%i", ret);
    }

    for (int j = 0; j < rep_total; j++) {
        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int i = 0; i < rep_aes; i++) {

            //I use the "high-level" interface as explained in this post : https://tls.mbed.org/discussions/generic/aes-gcm-authenticated-encryption-example

            ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, sizeof(plaintext), iv,
                                            sizeof(iv), NULL, 0, plaintext, encrypted,
                                            sizeof(tag), tag);

            repetitions += 1;
        }
        if (ret != 0) {
            LOGD("Error encrypting");
            LOGD("%i", ret);
        }
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
    }

        for ( int j = 0; j < rep_total; j++) {
            int repetitions = 0;
            gettimeofday(&st, NULL);
            for (int x = 0; x < rep_aes; x++) {


                ret = mbedtls_gcm_auth_decrypt(&ctx, sizeof(encrypted), iv, sizeof(iv), NULL, 0,
                                               tag,
                                               sizeof(tag), encrypted, decrypted);
                repetitions += 1;
            }

            gettimeofday(&et, NULL);
            if (ret != 0) {
                LOGD("Error decrypting");
                LOGD("%i", ret);
            }
            gettimeofday(&et, NULL);
            double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
            double result_agree = (repetitions * blocksize) / time;
            fprintf(report, "Repetitions: %i \n", repetitions);
            fprintf(report, "Seconds: %f \n", time);
            fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
        }

    fprintf(report,"********************");

    fclose(report);
        return ;


}
extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_ECDH(JNIEnv *env, jobject instance, jint rep_agree,jint rep_total) {


    FILE *report = create_file();
    int print_Res = fprintf(report, "************mbedTLS/ECDH**************\n");



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

    for(int i = 0; i < rep_total; i++) {
        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int j = 0; j < rep_agree; j++) {

            ret = mbedtls_ecdh_compute_shared(&grp, &zB, &qA, &dB,
                                              NULL, NULL);

            if (ret != 0) {
                LOGD("Error generating secret 2");
            }
            repetitions += 1;
        }
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        double result_agree = repetitions / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Key agreement: %f agreements/seconds \n", result_agree);
    }
    ret = mbedtls_mpi_cmp_mpi( &zA, &zB );

    if(ret != 0){
        LOGD("Error comparing secrets");
    }
    LOGD("We are good");
    fprintf(report,"********************");
    fclose(report);

    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_RSA(JNIEnv *env, jobject instance,jint blocksize,jint rep_aes,jint rep_total) {


    FILE *report = create_file();
    int print_Res = fprintf(report, "************mbedTLS/RSA**************\n");

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
    unsigned char label[1024] = "label";

    ret = mbedtls_pk_parse_keyfile( &privk, "/sdcard/CryptoBench/private_key.txt",NULL);

    if( ret != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_parsing private key, -ret" );
        return ;
    }

    mbedtls_rsa_set_padding( mbedtls_pk_rsa( privk ),  MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1 );

    for (int i = 0; i < rep_total ; i++) {

        int repetitions = 0;
        gettimeofday(&st, NULL);
        for (int j = 0; j < rep_aes; j++) {

            ret = mbedtls_rsa_rsaes_oaep_encrypt(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random,
                                                 &ctr_drbg,
                                                 MBEDTLS_RSA_PUBLIC, label,
                                                 sizeof(label),
                                                 sizeof(plaintext), plaintext, buf);

            if (ret != 0) {
                printf(" failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -ret);


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
        LOGD("Encrypt was good");

        //mbedtls_pk_free(&pk);

        for (int i = 0; i < rep_total ; i++) {
            int repetitions = 0;
            gettimeofday(&st, NULL);
            for (int j = 0; j < rep_aes; j++) {
                ret = mbedtls_rsa_rsaes_oaep_decrypt(mbedtls_pk_rsa(privk), mbedtls_ctr_drbg_random,
                                                     &ctr_drbg2, MBEDTLS_RSA_PRIVATE, label,
                                                     sizeof(label), &olen_dec, buf,
                                                     output_decrypted,
                                                     1024);

                if (ret != 0) {
                    LOGD(" failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n", -ret);
                }

                repetitions += 1;
            }
            gettimeofday(&et, NULL);
            double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
            double result_agree = (repetitions * blocksize) / time;
            fprintf(report, "Repetitions: %i \n", repetitions);
            fprintf(report, "Seconds: %f \n", time);
            fprintf(report, "Time to encrypt: %f bytes/seconds \n", result_agree);
        }

    LOGD( " ok\n" );

    LOGD("RSA good");
    fprintf(report,"********************");

    fclose(report);

    return;

}


extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_RSATime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_rsa,jstring title_rand,jint rep_total) {

    const char *title = env->GetStringUTFChars(title_rand, 0);


    struct timeval st, et;

    unsigned char plaintext[blocksize];

    for (int i = 0; i <= sizeof(plaintext); i++) {
        plaintext[i] = rand();
    }

    FILE *report = create_file_text(title);
    if (report == NULL) {
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

    fprintf(report,
            "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    fprintf(report, "************mbedTLS/RSA**************\n");
    fprintf(report, "Blocksize is: %i  \n", blocksize);

    size_t olen_dec = 0;
    unsigned char output_decrypted[MBEDTLS_MPI_MAX_SIZE];

    time_t start_key = time(NULL);
    time_t now_key = time(NULL);
    int repetitions_key = 0;
    gettimeofday(&st, NULL);
    while ((now_key - start_key) <= rep_key) {

        mbedtls_pk_init(&pk);
        mbedtls_pk_init(&privk);


        ret = mbedtls_pk_parse_public_keyfile(&pk, "/sdcard/CryptoBench/public_key.txt");

        /*
         * Read the RSA public key
         */
        if (ret != 0) {
            LOGD(" Error parsing public keyfile");
            return;
        }

        mbedtls_ctr_drbg_init(&ctr_drbg);

        mbedtls_entropy_init(&entropy);
        if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                         (const unsigned char *) pers,
                                         strlen(pers))) != 0) {
            LOGD(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
            return;
        }

        mbedtls_ctr_drbg_init(&ctr_drbg2);

        mbedtls_entropy_init(&entropy);
        if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg2, mbedtls_entropy_func, &entropy,
                                         (const unsigned char *) pers,
                                         strlen(pers))) != 0) {
            LOGD(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
            return;
        }
        mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);


        ret = mbedtls_pk_parse_keyfile(&privk, "/sdcard/CryptoBench/private_key.txt", NULL);

        if (ret != 0) {
            printf(" failed\n  ! mbedtls_pk_parsing private key, -ret");
            return;
        }

        mbedtls_rsa_set_padding(mbedtls_pk_rsa(privk), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);

        now_key = time(NULL);
        repetitions_key +=1;

    }
    gettimeofday(&et, NULL);
    double time_key = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = repetitions_key / time_key;
    fprintf(report, "Repetitions: %i \n", repetitions_key);
    fprintf(report, "Seconds: %f \n", time_key);
    fprintf(report, "Result: %f Times set key/seconds \n", result_agree);

    for (int i = 0; i < rep_total ; i++) {

    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions_rsa = 0;
        gettimeofday(&st, NULL);
    while ((now - start) <= rep_rsa) {

        ret = mbedtls_rsa_rsaes_oaep_encrypt(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctr_drbg,
                                             MBEDTLS_RSA_PUBLIC, label,
                                             sizeof(label),
                                             sizeof(plaintext), plaintext, buf);

        if (ret != 0) {
            printf(" failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -ret);
            return;
        }

        repetitions_rsa += 1;
        now = time(NULL);
    }
    gettimeofday(&et, NULL);
    double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    result_agree = (repetitions_rsa * blocksize) / time;
    fprintf(report, "Repetitions: %i \n", repetitions_rsa);
    fprintf(report, "Seconds: %f \n", time);
    fprintf(report, "Time to encrypt: %f agreements/seconds \n", result_agree);

}
    LOGD("Finished encryption");

    /* Initialise the decryption operation. */
    for (int i = 0; i < rep_total; i++) {

        time_t start = time(NULL);
        time_t now = time(NULL);
        int repetitions_rsa = 0;

        gettimeofday(&st, NULL);
        while ((now - start) <= rep_rsa) {


            ret = mbedtls_rsa_rsaes_oaep_decrypt(mbedtls_pk_rsa(privk), mbedtls_ctr_drbg_random,
                                                 &ctr_drbg2, MBEDTLS_RSA_PRIVATE, label,
                                                 sizeof(label), &olen_dec, buf, output_decrypted,
                                                 1024);
            if (ret != 0) {
                LOGD(" failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n", -ret);
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
    LOGD("We are good");
    fprintf(report,"********************");

    fclose (report);

    LOGD( " ok\n" );

    LOGD("RSA good");



    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_MD5Time(JNIEnv *env, jobject instance,jint blocksize,jint rep_hash,jstring title_rand,jint total_rep) {

    const char *title = env->GetStringUTFChars(title_rand, 0);
    LOGD("rep_hash is: %i", rep_hash);

    FILE* report = create_file_text(title);
    if(report == NULL){
        LOGD("Error rediang the file");

    }

    struct timeval st,et;

    fprintf(report,
            "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    fprintf(report,"************mbedTLS/MD5**************\n");
    fprintf(report,"Blocksize is: %i  \n",blocksize);

    int i, ret;
    unsigned char digest[1024];
    uint8_t Plaintext[blocksize];

    for (int i = 0; i <= sizeof(Plaintext); ++i) {
        Plaintext[i] = rand();

    }

    for (int j = 0; j < total_rep; ++j) {

    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions_rsa = 0;
        gettimeofday(&st, NULL);
    while ((now - start) <= rep_hash) {



        if ((ret = mbedtls_md5_ret(Plaintext, sizeof(Plaintext), digest)) != 0) {
            return ;
        }


        repetitions_rsa += 1;
        now = time(NULL);
    }

    gettimeofday(&et, NULL);
    double time_key = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = (repetitions_rsa * blocksize) / time_key;

    fprintf(report, "Repetitions: %i \n", repetitions_rsa);
    fprintf(report, "Seconds: %f \n", time_key);
    fprintf(report, "Result: %f Bytes/second \n", result_agree);
    }
    LOGD("We are good");

    fprintf(report,"*****************************");
    fclose (report);
    LOGD( "Finished!" );

    return;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_DHTime(JNIEnv *env, jobject instance,jint rep_key,jint rep_agree,jstring title_rand,jint rep_total) {


    const char *title = env->GetStringUTFChars(title_rand, 0);
    FILE* report = create_file_text(title);
    if(report == NULL){
        LOGD("Error reading the file");
    }

    struct timeval st,et;

    //Temporary solution, there must be a buffer somewhere that avoid the code write the file.
    fprintf(report,
            "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    fprintf(report, "************mbedTLS/DH**************\n");

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
    gettimeofday(&st,NULL);
    while ((now - start) <= rep_key) {

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

        now = time(NULL);
        repetitions +=1;

    }
    gettimeofday(&et, NULL);
    double time_key = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = repetitions / time_key;
    fprintf(report, "Repetitions: %i \n", repetitions);
    fprintf(report, "Seconds: %f \n", time_key);
    fprintf(report, "Result: %f Times set key/seconds \n", result_agree);

    for (int i = 0; i <rep_total ; ++i) {

        start = time(NULL);
        now = time(NULL);
        repetitions = 0;
        gettimeofday(&st, NULL);
        while ((now - start) <= rep_agree) {

            if ((ret = mbedtls_dhm_calc_secret(&dhm1, buf1, sizeof(buf1), &n1,
                                               mbedtls_ctr_drbg_random, &ctr_drbg1)) != 0) {
                LOGD(" failed\n  ! mbedtls_dhm_calc_secret returned %d\n\n", ret);
            }

            repetitions += 1;
            now = time(NULL);
        }
        gettimeofday(&et, NULL);
        if ((ret = mbedtls_dhm_calc_secret(&dhm2, buf2, sizeof(buf2), &n2,
                                           mbedtls_ctr_drbg_random, &ctr_drbg2)) != 0) {
            LOGD(" failed\n  ! mbedtls_dhm_calc_secret returned %d\n\n", ret);
        }
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        result_agree = repetitions / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Key agreement: %f agreements/seconds \n", result_agree);
    }
    fprintf(report,"********************");

    fclose (report);

    LOGD("DH finished");

    return;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_ECDHTime(JNIEnv *env, jobject instance, jint rep_key,jint rep_agree,jstring title_rand,jint rep_total) {

    const char *title = env->GetStringUTFChars(title_rand, 0);

    FILE *report = create_file_text(title);
    if (report == NULL) {
        LOGD("Error rediang the file");

    }

    struct timeval st, et;

    fprintf(report,
            "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    fprintf(report, "************mbedTLS/ECDH**************\n");

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_context entropy;

    mbedtls_entropy_init(&entropy);
    const char *pers = "ecdh_genkey";


    mbedtls_ecp_group grp;
    mbedtls_ecp_point qA, qB;
    mbedtls_mpi dA, dB, zA, zB;

    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions = 0;
    while ((now - start) <= rep_key) {
        gettimeofday(&st, NULL);

        mbedtls_ecp_group_init(&grp);
        mbedtls_ecp_point_init(&qA);
        mbedtls_ecp_point_init(&qB);
        mbedtls_mpi_init(&dA);
        mbedtls_mpi_init(&dB);
        mbedtls_mpi_init(&zA);
        mbedtls_mpi_init(&zB);

        int ret;
        if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                         (const unsigned char *) pers,
                                         strlen(pers))) != 0) {
            LOGD(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        }

        ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
        if (ret != 0) {
            LOGD("Error group load");
        }

        mbedtls_ecdh_gen_public(&grp, &dA, &qA, mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            LOGD("Error generating public 1");
        }

        mbedtls_ecdh_gen_public(&grp, &dB, &qB, mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            LOGD("Error generating public 2");
        }

        gettimeofday(&et, NULL);

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
        start = time(NULL);
        now = time(NULL);
        repetitions = 0;
        gettimeofday(&st,NULL);
        while ((now - start) <= rep_agree) {

            int ret = mbedtls_ecdh_compute_shared(&grp, &zB, &qA, &dB,
                                                  NULL, NULL);

            if (ret != 0) {
                LOGD("Error generating secret 2");
            }
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
    fprintf(report,"********************");

    fclose (report);

    LOGD("We are good");

    return ;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_AESCBCTime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_aes,jstring title_rand,jint total_rep) {

    const char *title = env->GetStringUTFChars(title_rand, 0);
    FILE *report = create_file_text(title);
    fprintf(report,
            "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    fprintf(report, "************mbedTLS/AESCBC**************\n");
    fprintf(report, "Blocksize is: %i  \n", blocksize);


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
            0x09, 0xcf, 0x15, 0x88, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0xae, 0x16, 0x28, 0xd2, 0xa6,
            0xab, 0xf7,

    };

    uint8_t iv2[16] = {
            0x09, 0xcf, 0x15, 0x88, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0xae, 0x16, 0x28, 0xd2, 0xa6,
            0xab, 0xf7,

    };


    struct timeval st, et;
    uint8_t OutputMessage[blocksize];
    uint8_t compare[blocksize];
    uint32_t i = 0, status = 0;

    mbedtls_aes_context ctx, ctx_dec;

    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions_key = 0;
    gettimeofday(&st, NULL);
    while ((now - start) <= rep_key) {


        mbedtls_aes_init(&ctx);
        status = mbedtls_aes_setkey_enc(&ctx, key, 128);
        if (status != 0) {
            LOGD("\n mbedtls Encrypt set key failed");
        }

        mbedtls_aes_init(&ctx_dec);
        status = mbedtls_aes_setkey_dec(&ctx_dec, key, 128);
        if (status != 0) {
            LOGD("\n mbedtls decryption set key failed");
        }


        repetitions_key += 1;
        now = time(NULL);
    }
    gettimeofday(&et, NULL);
    LOGD("Finished setkey / RSA");
    double time_result = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = repetitions_key / time_result;
    fprintf(report, "Repetitions: %i \n", repetitions_key);
    fprintf(report, "Seconds: %f \n", time_result);
    fprintf(report, "Time to set key: %f setting key/seconds \n", result_agree);

    for (int i = 0; i < total_rep; ++i) {
        start = time(NULL);
        now = time(NULL);
        int repetitions = 0;
        gettimeofday(&st,NULL);
        while ((now - start) <= rep_aes) {
            status = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, blocksize, iv, Plaintext,
                                           OutputMessage);

            if (status != 0) {
                LOGD("\n mbedtls encryption failed");
            }

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


        for (int j = 0; j < total_rep; j++) {
                start = time(NULL);
                now = time(NULL);
                int repetitions = 0;
                /* Initialise the decryption operation. */
                gettimeofday(&st,NULL);
                while ((now - start) <= rep_aes) {

                status = mbedtls_aes_crypt_cbc(&ctx_dec, MBEDTLS_AES_DECRYPT, blocksize, iv2, OutputMessage,
                                               compare);

                if (status != 0) {
                LOGD("\n mbedtls encryption failed");
                }
                    repetitions += 1;
                    now = time(NULL);
                }
            gettimeofday(&et, NULL);
            double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
            result_agree = (repetitions * blocksize) / time;
            fprintf(report, "Repetitions: %i \n", repetitions);
            fprintf(report, "Seconds: %f \n", time);
            fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
        }

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
Java_com_example_juanperezdealgaba_sac_mbedTLS_AESCTRTime(JNIEnv *env, jobject instance, jint blocksize, jint rep_key,jint rep_aes,jstring title_rand,jint rep_total) {

    const char *title = env->GetStringUTFChars(title_rand, 0);

    FILE *report = create_file_text(title);
    fprintf(report,
            "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");

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
    time_t now_key= time(NULL);
    int repetitions_key = 0;
    mbedtls_aes_context aes;

    gettimeofday(&st, NULL);
    while ((now_key - start) <= rep_key) {

        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, key, 128);


        repetitions_key += 1;
        now_key = time(NULL);
    }
    gettimeofday(&et, NULL);
    double time_key = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = repetitions_key / time_key;
    fprintf(report, "Repetitions: %i \n", repetitions_key);
    fprintf(report, "Seconds: %f \n", time_key);
    fprintf(report, "Time set key: %f keys set/second \n", result_agree);



    for (int i = 0; i <rep_total ; ++i) {

    time_t start = time(NULL);
    time_t now = time(NULL);
    int repetitions = 0;
    int ret = 0;
        gettimeofday(&st, NULL);
    while ((now - start) <= rep_aes) {
        ret = mbedtls_aes_crypt_ctr(&aes, sizeof(plaintext), &nc_off, iv, stream_block,
                                        plaintext,
                                        enc_out);

        if (ret == 0) {
            LOGD("Success encrypting");
        }

        repetitions += 1;
        now = time(NULL);
    }
    gettimeofday(&et, NULL);
    double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = (repetitions * blocksize) / time;
    fprintf(report, "Repetitions: %i \n", repetitions);
    fprintf(report, "Seconds: %f \n", time);
    fprintf(report, "Time to encrypt: %f byte/seconds \n", result_agree);
}


    for (int i = 0; i <rep_total ; ++i) {
    start = time(NULL);
    time_t now = time(NULL);
    int repetitions = 0;
        gettimeofday(&st, NULL);
    /* Initialise the decryption operation. */
    while ((now - start) <= rep_aes) {

        int ret = mbedtls_aes_crypt_ctr(&aes, sizeof(enc_out), &nc_off, iv, stream_block, enc_out,
                                    plain_out);

        if (ret != 0) {
            LOGD("Error decrypting");
        }

        repetitions += 1;
        now = time(NULL);
    }
    gettimeofday(&et, NULL);
    double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    result_agree = (repetitions * blocksize) / time;
    fprintf(report, "Repetitions: %i \n", repetitions);
    fprintf(report, "Seconds: %f \n", time);
    fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
}
    fprintf(report, "*****************************");
    fclose(report);
    mbedtls_aes_free(&aes);


    return;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_juanperezdealgaba_sac_mbedTLS_AESGCMTime(JNIEnv *env, jobject instance,jint blocksize,jint rep_key,jint rep_aes,jstring title_rand,jint total_rep) {

    const char *title = env->GetStringUTFChars(title_rand, 0);

    FILE *report = create_file_text(title);
    fprintf(report,
            "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
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
    int repetitions_key = 0;

    gettimeofday(&st, NULL);
   while ((now - start) <= rep_key) {

        mbedtls_gcm_init(&ctx);

        int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
        if (ret != 0) {
            LOGD("%i", ret);
        }
       //The structure is freed only for research, as initializing the structure a lot of times
       //without freeing it it will crash the app.
       mbedtls_gcm_free(&ctx);

        repetitions_key += 1;
        now = time(NULL);

    }
    gettimeofday(&et, NULL);
    double time_key = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
    double result_agree = repetitions_key / time_key;
    fprintf(report, "Repetitions: %i \n", repetitions_key);
    fprintf(report, "Seconds: %f \n", time_key);
    fprintf(report, "Time set key: %f keys set/second \n", result_agree);

    mbedtls_gcm_init(&ctx);
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
    LOGD("Finish set key");

    for (int i = 0; i < total_rep; ++i) {

        start = time(NULL);
        now = time(NULL);
        int repetitions = 0;
        gettimeofday(&st, NULL);
        while ((now - start) <= rep_aes) {


            //I use the "high-level" interface as explained in this post : https://tls.mbed.org/discussions/generic/aes-gcm-authenticated-encryption-example

            int ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, sizeof(plaintext), iv,
                                                sizeof(iv), NULL, 0, plaintext, encrypted,
                                                sizeof(tag), tag);

            if (ret != 0) {
                LOGD("Error encrypting");
                LOGD("%i", ret);
            }

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
    LOGD("Finished encryption");


    for (int i = 0; i < total_rep; ++i) {
        start = time(NULL);
        now = time(NULL);
        int repetitions = 0;
        int ret = 0;
        /* Initialise the decryption operation. */
        gettimeofday(&st,NULL);
        while ((now - start) <= rep_aes) {


            ret = mbedtls_gcm_auth_decrypt(&ctx, sizeof(encrypted), iv, sizeof(iv), NULL, 0, tag,
                                           sizeof(tag), encrypted, decrypted);

            if (ret != 0) {
                LOGD("Error decrypting");
                LOGD("%i", ret);
            }

            repetitions += 1;
            now = time(NULL);
        }
        gettimeofday(&et, NULL);
        double time = (et.tv_sec - st.tv_sec) + ((et.tv_usec - st.tv_usec) / 1000000);
        result_agree = (repetitions * blocksize) / time;
        fprintf(report, "Repetitions: %i \n", repetitions);
        fprintf(report, "Seconds: %f \n", time);
        fprintf(report, "Time to decrypt: %f byte/seconds \n", result_agree);
    }

    fprintf(report, "*****************************");
    fclose(report);

    LOGD("We are good");


    return;

}
