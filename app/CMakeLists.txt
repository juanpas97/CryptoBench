# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.


# Add preprocessor defines to CFLAGS
add_definitions(-DWOLFSSL_JNI -DWOLFSSL_DTLS -DOPENSSL_EXTRA -DHAVE_CRL -DHAVE_CRL_MONITOR
                -DHAVE_OCSP -DPERSIST_SESSION_CACHE -DPERSIST_CERT_CACHE -DATOMIC_USER
                -DHAVE_ECC -DTFM_ECC256 -DHAVE_PK_CALLBACKS -DHAVE_DH -DUSE_FAST_MATH
                -DTFM_TIMING_RESISTANT -DECC_TIMING_RESISTANT -DWC_RSA_BLINDING -DTFM_NO_ASM
                )

# set wolfSSL JNI location as environment variable, change if needed
set(wolfssljni_DIR ${CMAKE_SOURCE_DIR}/../wolfssljni)
set(wolfssl_DIR    ${CMAKE_SOURCE_DIR}/../wolfssl)

# Add header directories to include paths
include_directories(
            ${wolfssl_DIR}
            ${wolfssljni_DIR}/native
            )

# Add wolfSSL library source files, to be compiled as SHARED library
add_library(wolfssl SHARED
            ${wolfssl_DIR}/wolfcrypt/src/aes.c
            ${wolfssl_DIR}/wolfcrypt/src/arc4.c
            ${wolfssl_DIR}/wolfcrypt/src/asm.c
            ${wolfssl_DIR}/wolfcrypt/src/asn.c
            ${wolfssl_DIR}/wolfcrypt/src/blake2b.c
            ${wolfssl_DIR}/wolfcrypt/src/camellia.c
            ${wolfssl_DIR}/wolfcrypt/src/chacha.c
            ${wolfssl_DIR}/wolfcrypt/src/chacha20_poly1305.c
            ${wolfssl_DIR}/wolfcrypt/src/cmac.c
            ${wolfssl_DIR}/wolfcrypt/src/coding.c
            ${wolfssl_DIR}/wolfcrypt/src/compress.c
            ${wolfssl_DIR}/wolfcrypt/src/cpuid.c
            ${wolfssl_DIR}/wolfcrypt/src/curve25519.c
            ${wolfssl_DIR}/wolfcrypt/src/des3.c
            ${wolfssl_DIR}/wolfcrypt/src/dh.c
            ${wolfssl_DIR}/wolfcrypt/src/dsa.c
            ${wolfssl_DIR}/wolfcrypt/src/ecc.c
            ${wolfssl_DIR}/wolfcrypt/src/ecc_fp.c
            ${wolfssl_DIR}/wolfcrypt/src/ed25519.c
            ${wolfssl_DIR}/wolfcrypt/src/error.c
            ${wolfssl_DIR}/wolfcrypt/src/fe_low_mem.c
            ${wolfssl_DIR}/wolfcrypt/src/fe_operations.c
            ${wolfssl_DIR}/wolfcrypt/src/ge_low_mem.c
            ${wolfssl_DIR}/wolfcrypt/src/ge_operations.c
            ${wolfssl_DIR}/wolfcrypt/src/hash.c
            ${wolfssl_DIR}/wolfcrypt/src/hc128.c
            ${wolfssl_DIR}/wolfcrypt/src/hmac.c
            ${wolfssl_DIR}/wolfcrypt/src/idea.c
            ${wolfssl_DIR}/wolfcrypt/src/integer.c
            ${wolfssl_DIR}/wolfcrypt/src/logging.c
            ${wolfssl_DIR}/wolfcrypt/src/md2.c
            ${wolfssl_DIR}/wolfcrypt/src/md4.c
            ${wolfssl_DIR}/wolfcrypt/src/md5.c
            ${wolfssl_DIR}/wolfcrypt/src/memory.c
            ${wolfssl_DIR}/wolfcrypt/src/pkcs12.c
            ${wolfssl_DIR}/wolfcrypt/src/pkcs7.c
            ${wolfssl_DIR}/wolfcrypt/src/poly1305.c
            ${wolfssl_DIR}/wolfcrypt/src/pwdbased.c
            ${wolfssl_DIR}/wolfcrypt/src/rabbit.c
            ${wolfssl_DIR}/wolfcrypt/src/random.c
            ${wolfssl_DIR}/wolfcrypt/src/ripemd.c
            ${wolfssl_DIR}/wolfcrypt/src/rsa.c
            ${wolfssl_DIR}/wolfcrypt/src/sha.c
            ${wolfssl_DIR}/wolfcrypt/src/sha256.c
            ${wolfssl_DIR}/wolfcrypt/src/sha3.c
            ${wolfssl_DIR}/wolfcrypt/src/sha512.c
            ${wolfssl_DIR}/wolfcrypt/src/signature.c
            ${wolfssl_DIR}/wolfcrypt/src/srp.c
            ${wolfssl_DIR}/wolfcrypt/src/tfm.c
            ${wolfssl_DIR}/wolfcrypt/src/wc_encrypt.c
            ${wolfssl_DIR}/wolfcrypt/src/wc_port.c
            ${wolfssl_DIR}/wolfcrypt/src/wolfevent.c
            ${wolfssl_DIR}/wolfcrypt/src/wolfmath.c
            ${wolfssl_DIR}/src/crl.c
            ${wolfssl_DIR}/src/internal.c
            ${wolfssl_DIR}/src/io.c
            ${wolfssl_DIR}/src/keys.c
            ${wolfssl_DIR}/src/ocsp.c
            ${wolfssl_DIR}/src/sniffer.c
            ${wolfssl_DIR}/src/ssl.c
            ${wolfssl_DIR}/src/tls.c
            ${wolfssl_DIR}/src/tls13.c
           )

# Add wolfSSL JNI library native source files, to be compiled as SHARED library
# wolfSSL JNI Java files are tied into build in Module build.gradle file
add_library(wolfssljni SHARED
            ${wolfssljni_DIR}/native/com_wolfssl_wolfcrypt_ECC.c
            ${wolfssljni_DIR}/native/com_wolfssl_wolfcrypt_RSA.c
            ${wolfssljni_DIR}/native/com_wolfssl_WolfSSL.c
            ${wolfssljni_DIR}/native/com_wolfssl_WolfSSLContext.c
            ${wolfssljni_DIR}/native/com_wolfssl_WolfSSLSession.c
            ${wolfssljni_DIR}/native/WolfCrypt.c
           )




# Include libraries needed for wolfSSL and wolfSSL JNI libs
target_link_libraries(wolfssljni
                      wolfssl
                      android
                      log)



add_library( # Sets the name of the library.
             native-lib

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             src/main/cpp/native-lib.cpp )


add_library( # Sets the name of the library.
             OpenSSL

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             src/main/cpp/OpenSSL.cpp )


add_library( # Sets the name of the library.
             BoringSSL

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             src/main/cpp/BoringSSL.cpp )

 add_library( # Sets the name of the library.
              mbedTLS

              # Sets the library as a shared library.
              SHARED

              # Provides a relative path to your source file(s).
              src/main/cpp/mbedTLS.cpp )


include_directories(OpenSSL/openssl-armeabi-v7a/include/)
include_directories(OpenSSL/x86/include/)

include_directories(BoringSSL/boringssl-armeabi-v7a/include/)
include_directories(BoringSSL/x86/include/)

include_directories(mbedTLS/mbedtls-armeabi-v7a/include/)
include_directories(mbedTLS/x86/include/)

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.


if (${ANDROID_ABI} STREQUAL "armeabi-v7a")
target_link_libraries( # Specifies the target library.
                       OpenSSL

                       ${CMAKE_CURRENT_SOURCE_DIR}/OpenSSL/openssl-${ANDROID_ABI}/lib/libcrypto.a
                       ${CMAKE_CURRENT_SOURCE_DIR}/OpenSSL/openssl-${ANDROID_ABI}/lib/libssl.a

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )

target_link_libraries( # Specifies the target library.
                       native-lib

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )

target_link_libraries( # Specifies the target library.
                       BoringSSL

                       ${CMAKE_CURRENT_SOURCE_DIR}/BoringSSL/boringssl-${ANDROID_ABI}/lib/libcrypto.a
                       ${CMAKE_CURRENT_SOURCE_DIR}/BoringSSL/boringssl-${ANDROID_ABI}/lib/libssl.a
                       ${CMAKE_CURRENT_SOURCE_DIR}/BoringSSL/boringssl-${ANDROID_ABI}/lib/libdecrepit.a
                        ${CMAKE_CURRENT_SOURCE_DIR}/BoringSSL/boringssl-${ANDROID_ABI}/lib/libboringssl_gtest.a

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )

target_link_libraries( # Specifies the target library.
                       mbedTLS

                       ${CMAKE_CURRENT_SOURCE_DIR}/mbedTLS/mbedtls-${ANDROID_ABI}/lib/libmbedcrypto.a
                       ${CMAKE_CURRENT_SOURCE_DIR}/mbedTLS/mbedtls-${ANDROID_ABI}/lib/libmbedtls.a
                       ${CMAKE_CURRENT_SOURCE_DIR}/mbedTLS/mbedtls-${ANDROID_ABI}/lib/libmbedx509.a


                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )


endif()

if (${ANDROID_ABI} STREQUAL "x86")
target_link_libraries( # Specifies the target library.
                       OpenSSL


                       ${CMAKE_CURRENT_SOURCE_DIR}/OpenSSL/x86/lib/libcrypto.a
                       ${CMAKE_CURRENT_SOURCE_DIR}/OpenSSL/x86/lib/libssl.a
                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )

 target_link_libraries( # Specifies the target library.
                        native-lib

                        # Links the target library to the log library
                        # included in the NDK.
                        ${log-lib} )

target_link_libraries( # Specifies the target library.
                       BoringSSL

                       ${CMAKE_CURRENT_SOURCE_DIR}/BoringSSL/x86/lib/libcrypto.a
                       ${CMAKE_CURRENT_SOURCE_DIR}/BoringSSL/x86/lib/libssl.a
                       ${CMAKE_CURRENT_SOURCE_DIR}/BoringSSL/x86/lib/libdecrepit.a
                       ${CMAKE_CURRENT_SOURCE_DIR}/BoringSSL/x86/lib/libboringssl_gtest.a
                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )

target_link_libraries( # Specifies the target library.
                       mbedTLS

                       ${CMAKE_CURRENT_SOURCE_DIR}/mbedTLS/x86/lib/libmbedcrypto.a
                       ${CMAKE_CURRENT_SOURCE_DIR}/mbedTLS/x86/lib/libmbedtls.a
                       ${CMAKE_CURRENT_SOURCE_DIR}/mbedTLS/x86/lib/libmbedx509.a

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )

endif()
