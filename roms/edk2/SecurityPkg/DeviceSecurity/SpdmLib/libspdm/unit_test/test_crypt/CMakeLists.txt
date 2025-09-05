cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/unit_test/test_crypt
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub
)

SET(src_test_crypt
    test_crypt.c
    hash_verify.c
    hmac_verify.c
    hkdf_verify.c
    aead_verify.c
    rsa_verify.c
    rsa_verify2.c
    dh_verify.c
    ec_verify.c
    ec_verify2.c
    ecd_verify.c
    ecd_verify2.c
    sm2_verify.c
    sm2_verify2.c
    rand_verify.c
    x509_verify.c
    os_support.c
)

SET(test_crypt_LIBRARY
    memlib
    debuglib
    ${CRYPTO_LIB_PATHS}
    rnglib
    cryptlib_${CRYPTO}
    malloclib
    spdm_crypt_lib
    spdm_crypt_ext_lib
)

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    SET(test_crypt_LIBRARY ${test_crypt_LIBRARY} armbuild_lib)
endif()

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(test_crypt
                   ${src_test_crypt}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib>
                   $<TARGET_OBJECTS:${CRYPTO_LIB_PATHS}>
                   $<TARGET_OBJECTS:rnglib>
                   $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
                   $<TARGET_OBJECTS:malloclib>
    )
else()
    ADD_EXECUTABLE(test_crypt ${src_test_crypt})
    TARGET_LINK_LIBRARIES(test_crypt ${test_crypt_LIBRARY})
endif()

