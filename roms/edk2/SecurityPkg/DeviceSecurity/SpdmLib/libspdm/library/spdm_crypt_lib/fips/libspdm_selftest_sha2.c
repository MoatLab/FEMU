/**
 *  Copyright Notice:
 *  Copyright 2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"
#include "internal/libspdm_fips_lib.h"
#include "internal/libspdm_common_lib.h"

#if LIBSPDM_FIPS_MODE

/**
 * SHA256 KAT: HMAC-SHA256 KAT covers SHA256 KAT.
 **/
bool libspdm_fips_selftest_sha256(void *fips_selftest_context)
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
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_SHA256) != 0) {
        return true;
    }

    result = libspdm_fips_selftest_hmac_sha256(context);

    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_SHA256;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_SHA256;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_SHA256;
    }
#endif /*LIBSPDM_SHA256_SUPPORT*/

    return result;
}

/**
 * SHA384 KAT: HMAC-SHA384 KAT covers SHA384 KAT.
 **/
bool libspdm_fips_selftest_sha384(void *fips_selftest_context)
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
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_SHA384) != 0) {
        return true;
    }

    result = libspdm_fips_selftest_hmac_sha384(context);

    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_SHA384;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_SHA384;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_SHA384;
    }
#endif /*LIBSPDM_SHA384_SUPPORT*/

    return result;
}

/**
 * SHA512 KAT: HMAC-SHA512 KAT covers SHA512 KAT.
 **/
bool libspdm_fips_selftest_sha512(void *fips_selftest_context)
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
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_SHA512) != 0) {
        return true;
    }

    result = libspdm_fips_selftest_hmac_sha512(context);

    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_SHA512;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_SHA512;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_SHA512;
    }
#endif /*LIBSPDM_SHA512_SUPPORT*/

    return result;
}

#endif/*LIBSPDM_FIPS_MODE*/
