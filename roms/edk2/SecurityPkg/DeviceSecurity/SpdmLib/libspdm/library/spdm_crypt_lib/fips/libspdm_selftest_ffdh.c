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
 * FFDH self_test
 **/
bool libspdm_fips_selftest_ffdh(void *fips_selftest_context)
{
    bool result = true;

#if LIBSPDM_FFDHE_SUPPORT
    libspdm_fips_selftest_context *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return false;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_FFDH) != 0) {
        return true;
    }

    void *dh1;
    void *dh2;
    uint8_t ff_public_key1[256];
    size_t ff_public_key1_length;
    uint8_t ff_public_key2[256];
    size_t ff_public_key2_length;
    uint8_t ff_key1[256];
    size_t ff_key1_length;
    uint8_t ff_key2[256];
    size_t ff_key2_length;

    ff_public_key1_length = sizeof(ff_public_key1);
    ff_public_key2_length = sizeof(ff_public_key2);
    ff_key1_length = sizeof(ff_key1);
    ff_key2_length = sizeof(ff_key2);

    dh1 = libspdm_dh_new_by_nid(LIBSPDM_CRYPTO_NID_FFDHE2048);
    if (dh1 == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "FFDH gen dh1 failed \n"));
        result = false;
        goto update;
    }

    dh2 = libspdm_dh_new_by_nid(LIBSPDM_CRYPTO_NID_FFDHE2048);
    if (dh2 == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "FFDH gen dh2 failed \n"));
        libspdm_dh_free(dh1);
        result = false;
        goto update;
    }

    result = libspdm_dh_generate_key(dh1, ff_public_key1, &ff_public_key1_length);
    if (!result || ff_public_key1_length != 256) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "FFDH generate key1 failed \n"));
        libspdm_dh_free(dh1);
        libspdm_dh_free(dh2);
        result = false;
        goto update;
    }

    result = libspdm_dh_generate_key(dh2, ff_public_key2, &ff_public_key2_length);
    if (!result || ff_public_key2_length != 256) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "FFDH generate key2 failed \n"));
        libspdm_dh_free(dh1);
        libspdm_dh_free(dh2);
        result = false;
        goto update;
    }

    result = libspdm_dh_compute_key(dh1, ff_public_key2, ff_public_key2_length,
                                    ff_key1, &ff_key1_length);
    if (!result || ff_key1_length != 256) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "FFDH compute key failed \n"));
        libspdm_dh_free(dh1);
        libspdm_dh_free(dh2);
        result = false;
        goto update;
    }

    result = libspdm_dh_compute_key(dh2, ff_public_key1, ff_public_key1_length,
                                    ff_key2, &ff_key2_length);
    if (!result || ff_key2_length != 256) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "FFDH compute key failed \n"));
        libspdm_dh_free(dh1);
        libspdm_dh_free(dh2);
        result = false;
        goto update;
    }

    /*self_test*/
    if (ff_key1_length != ff_key2_length) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "FFDH self_test failed \n"));
        libspdm_dh_free(dh1);
        libspdm_dh_free(dh2);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(ff_key1, ff_key2, ff_key1_length)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "FFDH self_test failed \n"));
        libspdm_dh_free(dh1);
        libspdm_dh_free(dh2);
        result = false;
        goto update;
    }

    libspdm_dh_free(dh1);
    libspdm_dh_free(dh2);

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_FFDH;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_FFDH;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_FFDH;
    }

#endif/*LIBSPDM_FFDHE_SUPPORT*/

    return result;
}

#endif/*LIBSPDM_FIPS_MODE*/
