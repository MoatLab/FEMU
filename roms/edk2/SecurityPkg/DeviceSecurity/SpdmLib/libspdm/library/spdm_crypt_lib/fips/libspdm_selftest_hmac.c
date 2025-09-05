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
 * HMAC-SHA256 KAT covers SHA256 KAT.
 **/
bool libspdm_fips_selftest_hmac_sha256(void *fips_selftest_context)
{
    bool result = true;

#if LIBSPDM_SHA256_SUPPORT
    libspdm_fips_selftest_context *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return false;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_HMAC_SHA256) != 0) {
        return true;
    }

    const uint8_t key[32] = {0};
    const uint8_t msg[32] = {0};

    uint8_t hmac_256_result[32];
    const uint8_t hmac_sha256_answer[] = {
        0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b,
        0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
        0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
        0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a
    };
    libspdm_zero_mem(hmac_256_result, sizeof(hmac_256_result));
    result = libspdm_hmac_sha256_all(msg, sizeof(msg), key, sizeof(key), hmac_256_result);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "gen hmac_sha256 failed \n"));
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(hmac_256_result, hmac_sha256_answer,
                                        sizeof(hmac_sha256_answer))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "hmac_sha256 KAT failed \n"));
        result = false;
        goto update;
    }

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_HMAC_SHA256;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_HMAC_SHA256;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_HMAC_SHA256;
    }

#endif/*LIBSPDM_SHA256_SUPPORT*/

    return result;
}

/**
 * HMAC-SHA384 KAT covers SHA384 KAT.
 **/
bool libspdm_fips_selftest_hmac_sha384(void *fips_selftest_context)
{
    bool result = true;

#if LIBSPDM_SHA384_SUPPORT
    libspdm_fips_selftest_context *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return false;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_HMAC_SHA384) != 0) {
        return true;
    }

    const uint8_t key[32] = {0};
    const uint8_t msg[32] = {0};

    uint8_t hmac_384_result[48];
    const uint8_t hmac_sha384_answer[] = {
        0xe6, 0x65, 0xec, 0x75, 0xdc, 0xa3, 0x23, 0xdf,
        0x31, 0x80, 0x40, 0x60, 0xe1, 0xb0, 0xd8, 0x28,
        0xb5, 0x0a, 0x6a, 0x8a, 0x53, 0x9c, 0xfe, 0xdd,
        0x9a, 0xa0, 0x07, 0x4b, 0x5b, 0x36, 0x44, 0x5d,
        0xef, 0xbc, 0x47, 0x45, 0x3d, 0xf8, 0xd0, 0xc1,
        0x4b, 0x7a, 0xd2, 0x06, 0x2e, 0x7b, 0xbd, 0xb1
    };
    libspdm_zero_mem(hmac_384_result, sizeof(hmac_384_result));
    result = libspdm_hmac_sha384_all(msg, sizeof(msg), key, sizeof(key), hmac_384_result);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "gen hmac_sha384 failed \n"));
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(hmac_384_result, hmac_sha384_answer,
                                        sizeof(hmac_sha384_answer))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "hmac_sha384 KAT failed \n"));
        result = false;
        goto update;
    }

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_HMAC_SHA384;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_HMAC_SHA384;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_HMAC_SHA384;
    }

#endif/*LIBSPDM_SHA384_SUPPORT*/

    return result;
}

/**
 * HMAC-SHA512 KAT covers SHA512 KAT.
 **/
bool libspdm_fips_selftest_hmac_sha512(void *fips_selftest_context)
{
    bool result = true;

#if LIBSPDM_SHA512_SUPPORT
    libspdm_fips_selftest_context *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return false;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_HMAC_SHA512) != 0) {
        return true;
    }

    const uint8_t key[32] = {0};
    const uint8_t msg[32] = {0};

    uint8_t hmac_512_result[64];
    const uint8_t hmac_sha512_answer[] = {
        0xba, 0xe4, 0x6c, 0xeb, 0xeb, 0xbb, 0x90, 0x40,
        0x9a, 0xbc, 0x5a, 0xcf, 0x7a, 0xc2, 0x1f, 0xdb,
        0x33, 0x9c, 0x01, 0xce, 0x15, 0x19, 0x2c, 0x52,
        0xfb, 0x9e, 0x8a, 0xa1, 0x1a, 0x8d, 0xe9, 0xa4,
        0xea, 0x15, 0xa0, 0x45, 0xf2, 0xbe, 0x24, 0x5f,
        0xbb, 0x98, 0x91, 0x6a, 0x9a, 0xe8, 0x1b, 0x35,
        0x3e, 0x33, 0xb9, 0xc4, 0x2a, 0x55, 0x38, 0x0c,
        0x51, 0x58, 0x24, 0x1d, 0xae, 0xb3, 0xc6, 0xdd
    };
    libspdm_zero_mem(hmac_512_result, sizeof(hmac_512_result));
    result = libspdm_hmac_sha512_all(msg, sizeof(msg), key, sizeof(key), hmac_512_result);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "gen hmac_sha512 failed \n"));
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(hmac_512_result, hmac_sha512_answer,
                                        sizeof(hmac_sha512_answer))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "hmac_sha512 KAT failed \n"));
        result = false;
        goto update;
    }
update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_HMAC_SHA512;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_HMAC_SHA512;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_HMAC_SHA512;
    }

#endif/*LIBSPDM_SHA512_SUPPORT*/

    return result;
}

#endif/*LIBSPDM_FIPS_MODE*/
