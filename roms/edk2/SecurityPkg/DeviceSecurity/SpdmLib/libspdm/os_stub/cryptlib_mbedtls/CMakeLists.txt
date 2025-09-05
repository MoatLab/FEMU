cmake_minimum_required(VERSION 2.8.12)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    ADD_COMPILE_OPTIONS(-Wno-incompatible-pointer-types -Wno-pointer-sign)
endif()

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub
                    ${LIBSPDM_DIR}/os_stub/cryptlib_mbedtls
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/include
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/include/mbedtls
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls/include
                    ${LIBSPDM_DIR}/os_stub/mbedtlslib/mbedtls/include/mbedtls
)

SET(src_cryptlib_mbedtls
    cipher/aead_aes_gcm.c
    cipher/aead_chacha20_poly1305.c
    cipher/aead_sm4_gcm.c
    der/der.c
    hash/sha.c
    hash/sha3.c
    hash/sm3.c
    hmac/hmac_sha.c
    hmac/hmac_sha3.c
    hmac/hmac_sm3.c
    kdf/hkdf_sha.c
    kdf/hkdf_sha3.c
    kdf/hkdf_sm3.c
    pem/pem.c
    pk/ec.c
    pk/ecd.c
    pk/dh.c
    pk/sm2.c
    pk/rsa_basic.c
    pk/rsa_ext.c
    pk/x509.c
    rand/rand.c
    sys_call/mem_allocation.c
    sys_call/crt_wrapper_host.c
)

ADD_LIBRARY(cryptlib_mbedtls STATIC ${src_cryptlib_mbedtls})
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "CBMC") OR (TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        TARGET_COMPILE_OPTIONS(cryptlib_mbedtls PRIVATE /wd4090)
    endif()
endif()