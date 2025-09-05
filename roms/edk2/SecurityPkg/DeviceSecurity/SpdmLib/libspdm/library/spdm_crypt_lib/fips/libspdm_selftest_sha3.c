/**
 *  Copyright Notice:
 *  Copyright 2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_fips_lib.h"

#if LIBSPDM_FIPS_MODE

/**
 * SHA3_256 KAT
 **/
bool libspdm_fips_selftest_sha3_256(void *fips_selftest_context)
{
    bool result = true;

#if LIBSPDM_SHA3_256_SUPPORT
    libspdm_fips_selftest_context *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return false;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_SHA3_256) != 0) {
        return true;
    }

    const uint8_t msg[] = {0x7f, 0x94};
    /*Test Vectors: https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#sha3vsha3vss */
    uint8_t sha3_256_result[32];
    const uint8_t sha3_256_answer[] = {
        0xde, 0x01, 0x6a, 0xcf, 0xc1, 0xa2, 0xe2, 0x2e,
        0x39, 0x52, 0x6c, 0x60, 0x9d, 0x9c, 0x69, 0xd8,
        0x56, 0xa5, 0x43, 0xfe, 0xbb, 0x3c, 0xb4, 0x26,
        0xee, 0x1f, 0x13, 0x18, 0xd7, 0x80, 0xea, 0x88
    };
    libspdm_zero_mem(sha3_256_result, sizeof(sha3_256_result));
    result = libspdm_sha3_256_hash_all(msg, sizeof(msg), sha3_256_result);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "gen sha3_256 failed \n"));
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(sha3_256_result, sha3_256_answer,
                                        sizeof(sha3_256_answer))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "sha3_256 KAT failed \n"));
        result = false;
        goto update;
    }

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_SHA3_256;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_SHA3_256;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_SHA3_256;
    }

#endif/* LIBSPDM_SHA3_256_SUPPORT */

    return result;
}

/**
 * SHA3_384 KAT
 **/
bool libspdm_fips_selftest_sha3_384(void *fips_selftest_context)
{
    bool result = true;

#if LIBSPDM_SHA3_384_SUPPORT
    libspdm_fips_selftest_context *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return false;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_SHA3_384) != 0) {
        return true;
    }

    uint8_t sha3_384_result[48];
    /*Test Vectors: https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#sha3vsha3vss */
    const uint8_t msg[] = {0x89, 0xcc};
    const uint8_t sha3_384_answer[] = {
        0xcf, 0x9b, 0xe5, 0x91, 0x0e, 0x2c, 0x4f, 0x89,
        0x5b, 0x9e, 0x92, 0x08, 0x02, 0x26, 0x52, 0xbb,
        0x4d, 0x6a, 0x7e, 0x85, 0x84, 0x5b, 0x2a, 0x6c,
        0x22, 0x1c, 0x22, 0x84, 0x1e, 0xc0, 0x74, 0x64,
        0xae, 0xe9, 0xfb, 0x5f, 0x89, 0x38, 0xb2, 0xda,
        0xa8, 0x7b, 0xe3, 0x37, 0xf0, 0x38, 0xcb, 0xcf
    };
    libspdm_zero_mem(sha3_384_result, sizeof(sha3_384_result));
    result = libspdm_sha3_384_hash_all(msg, sizeof(msg), sha3_384_result);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "gen sha3_384 failed \n"));
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(sha3_384_result, sha3_384_answer,
                                        sizeof(sha3_384_answer))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "sha3_384 KAT failed \n"));
        result = false;
        goto update;
    }

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_SHA3_384;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_SHA3_384;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_SHA3_384;
    }

#endif/* LIBSPDM_SHA3_384_SUPPORT */

    return result;
}

/**
 * SHA3_512 KAT
 **/
bool libspdm_fips_selftest_sha3_512(void *fips_selftest_context)
{
    bool result = true;

#if LIBSPDM_SHA3_512_SUPPORT
    libspdm_fips_selftest_context *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return false;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_SHA3_512) != 0) {
        return true;
    }

    uint8_t sha3_512_result[64];
    /*Test Vectors: https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#sha3vsha3vss */
    const uint8_t msg[] = {0xb1, 0x39};
    const uint8_t sha3_512_answer[] = {
        0xd3, 0xe5, 0xc0, 0x26, 0x47, 0x05, 0xe8, 0x1d,
        0x0c, 0x90, 0xf9, 0x9d, 0xae, 0xff, 0x00, 0x89,
        0xfa, 0x3e, 0x91, 0x77, 0xd3, 0xd5, 0xbc, 0x74,
        0x9c, 0xde, 0x10, 0xf0, 0x35, 0xf4, 0x95, 0x65,
        0x55, 0x44, 0xf8, 0x57, 0x79, 0x91, 0x71, 0x2e,
        0xb5, 0x18, 0x01, 0x5b, 0xe2, 0x9d, 0x19, 0x5b,
        0x7e, 0xbf, 0x61, 0xe8, 0xd2, 0x93, 0x90, 0xea,
        0xf1, 0x47, 0x88, 0x08, 0x2b, 0x11, 0x97, 0x6d
    };
    libspdm_zero_mem(sha3_512_result, sizeof(sha3_512_result));
    result = libspdm_sha3_512_hash_all(msg, sizeof(msg), sha3_512_result);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "gen sha3_512 failed \n"));
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(sha3_512_result, sha3_512_answer,
                                        sizeof(sha3_512_answer))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "sha3_512 KAT failed \n"));
        result = false;
        goto update;
    }

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_SHA3_512;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_SHA3_512;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_SHA3_512;
    }

#endif/* LIBSPDM_SHA3_512_SUPPORT */

    return result;
}

#endif/*LIBSPDM_FIPS_MODE*/
