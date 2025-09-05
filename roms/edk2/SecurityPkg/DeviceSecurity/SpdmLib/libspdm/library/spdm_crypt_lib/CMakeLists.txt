cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include)
INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/os_stub)

SET(src_spdm_crypt_lib
    libspdm_crypt_hash.c
    libspdm_crypt_hmac.c
    libspdm_crypt_hkdf.c
    libspdm_crypt_asym.c
    libspdm_crypt_cert.c
    libspdm_crypt_aead.c
    libspdm_crypt_dhe.c
    libspdm_crypt_rng.c
    fips/libspdm_selftest.c
    fips/libspdm_selftest_hmac.c
    fips/libspdm_selftest_aes_gcm.c
    fips/libspdm_selftest_rsa_ssa.c
    fips/libspdm_selftest_rsa_pss.c
    fips/libspdm_selftest_hkdf.c
    fips/libspdm_selftest_ecdh.c
    fips/libspdm_selftest_sha2.c
    fips/libspdm_selftest_sha3.c
    fips/libspdm_selftest_ffdh.c
    fips/libspdm_selftest_ecdsa.c
    fips/libspdm_selftest_eddsa.c
)

ADD_LIBRARY(spdm_crypt_lib STATIC ${src_spdm_crypt_lib})
