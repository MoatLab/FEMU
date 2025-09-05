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
 * ECDH self_test
 **/
bool libspdm_fips_selftest_ecdh(void *fips_selftest_context)
{
    bool result = true;

#if LIBSPDM_ECDHE_SUPPORT
    libspdm_fips_selftest_context *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return false;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_ECDH) != 0) {
        return true;
    }

    void *ec_context;
    uint8_t common_key[66];
    size_t common_key_length;

    common_key_length = sizeof(common_key);
    libspdm_zero_mem(common_key, common_key_length);
    /* self private Key*/
    const uint8_t self_privkey[] = {
        0xd6, 0x84, 0xd1, 0x7c, 0xe3, 0x6b, 0xe7, 0x08,
        0xbc, 0xd9, 0x89, 0x3f, 0xbb, 0xf4, 0xf2, 0xcf,
        0x8d, 0x7f, 0xd4, 0x72, 0xbc, 0xfb, 0x54, 0x29,
        0xd9, 0x86, 0xe2, 0x86, 0xc2, 0x38, 0xe5, 0x88
    };

    /* peer public Key*/
    const uint8_t peer_public[] = {
        0x54, 0xbc, 0x5f, 0x6b, 0x70, 0x9b, 0x29, 0x5c,
        0xa9, 0x43, 0xd0, 0xb7, 0xf3, 0xa2, 0x4b, 0xf0,
        0x76, 0xb1, 0xd1, 0x9f, 0x55, 0x6a, 0x4e, 0xa0,
        0x40, 0x54, 0xd2, 0xb1, 0x2f, 0x0f, 0xc1, 0x6d,
        0xe7, 0x53, 0xe1, 0x3a, 0xd9, 0xb9, 0x2d, 0xd6,
        0x3a, 0xda, 0x9d, 0xa9, 0xa9, 0x4e, 0xdd, 0x30,
        0x60, 0x24, 0x9f, 0x9d, 0xcb, 0xfc, 0x1a, 0x56,
        0x35, 0x63, 0x64, 0xe2, 0x64, 0xcf, 0x00, 0xed
    };

    /* expected ecdh common secret*/
    const uint8_t expected_ecdh_secret[] = {
        0x05, 0xd5, 0xc8, 0x66, 0x83, 0x59, 0xe8, 0x33,
        0x1d, 0xb7, 0x68, 0x2f, 0x98, 0x71, 0x2f, 0xfe,
        0x2d, 0xfa, 0x10, 0xe6, 0x67, 0x89, 0x81, 0xd8,
        0x51, 0xd9, 0x72, 0x47, 0x17, 0x7b, 0xa3, 0x5e
    };

    ec_context = libspdm_ec_new_by_nid(LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256);
    if (ec_context == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDH new failed \n"));
        result = false;
        goto update;
    }

    result = libspdm_ec_set_priv_key(ec_context, self_privkey, sizeof(self_privkey));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDH set private key failed \n"));
        libspdm_ec_free(ec_context);
        result = false;
        goto update;
    }

    result = libspdm_ec_compute_key(ec_context, peer_public, sizeof(peer_public), common_key,
                                    &common_key_length);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDH compute key failed \n"));
        libspdm_ec_free(ec_context);
        result = false;
        goto update;
    }

    /*KAT test*/
    if (common_key_length != sizeof(expected_ecdh_secret)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDH KAT failed \n"));
        libspdm_ec_free(ec_context);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(common_key, expected_ecdh_secret,
                                        sizeof(expected_ecdh_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDH KAT failed \n"));
        result = false;
        goto update;
    }

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_ECDH;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_ECDH;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_ECDH;
    }

#endif/*LIBSPDM_ECDHE_SUPPORT*/

    return result;
}

#endif/*LIBSPDM_FIPS_MODE*/
