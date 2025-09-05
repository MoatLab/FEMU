/**
 *  Copyright Notice:
 *  Copyright 2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_fips_lib.h"

#if LIBSPDM_FIPS_MODE

/*hardcode random for ecdsa*/
int libspdm_hardcode_random_number_ecdsa(void *rng_state, unsigned char *output, size_t len)
{
    /*Random number*/
    const uint8_t random[] = {
        0x01, 0x5b, 0x92, 0x22, 0xfc, 0x35, 0xc5, 0x2b,
        0x79, 0x1c, 0xcd, 0x37, 0x07, 0x7d, 0xae, 0x6a,
        0x88, 0x1f, 0x7d, 0x03, 0x30, 0x92, 0x67, 0x47,
        0x0b, 0xce, 0x31, 0x7c, 0x46, 0xdd, 0x90, 0xbf
    };
    libspdm_copy_mem(output, len, random, sizeof(random));

    return 0;
}

/**
 * ECDSA self_test
 **/
bool libspdm_fips_selftest_ecdsa(void *fips_selftest_context)
{
    bool result = true;

#if LIBSPDM_ECDSA_SUPPORT
    libspdm_fips_selftest_context *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return false;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_ECDSA) != 0) {
        return true;
    }

    uint8_t signature[32 * 2];
    size_t sig_size;
    void *ec_context;

    sig_size = sizeof(signature);
    libspdm_zero_mem(signature, sig_size);

    /* Message hash */
    const uint8_t message_hash[] = {
        0x9a, 0x1b, 0x6d, 0xe3, 0xff, 0xd0, 0x7e, 0x77,
        0xe2, 0x54, 0xc6, 0x27, 0x9a, 0xc3, 0x28, 0x07,
        0x42, 0x43, 0x1a, 0x32, 0xc8, 0xaf, 0x0c, 0x87,
        0x94, 0xff, 0x40, 0x75, 0x09, 0xfe, 0x40, 0xd8
    };

    /* Private Key */
    const uint8_t priv_key[] = {
        0xd6, 0x84, 0xd1, 0x7c, 0xe3, 0x6b, 0xe7, 0x08,
        0xbc, 0xd9, 0x89, 0x3f, 0xbb, 0xf4, 0xf2, 0xcf,
        0x8d, 0x7f, 0xd4, 0x72, 0xbc, 0xfb, 0x54, 0x29,
        0xd9, 0x86, 0xe2, 0x86, 0xc2, 0x38, 0xe5, 0xed
    };

    /* Public Key */
    const uint8_t public_key[] = {
        0x54, 0xbc, 0x5f, 0x6b, 0x70, 0x9b, 0x29, 0x5c,
        0xa9, 0x43, 0xd0, 0xb7, 0xf3, 0xa2, 0x4b, 0xf0,
        0x76, 0xb1, 0xd1, 0x9f, 0x55, 0x6a, 0x4e, 0xa0,
        0x40, 0x54, 0xd2, 0xb1, 0x2f, 0x0f, 0xc1, 0x6d,
        0xe7, 0x53, 0xe1, 0x3a, 0xd9, 0xb9, 0x2d, 0xd6,
        0x3a, 0xda, 0x9d, 0xa9, 0xa9, 0x4e, 0xdd, 0x30,
        0x60, 0x24, 0x9f, 0x9d, 0xcb, 0xfc, 0x1a, 0x56,
        0x35, 0x63, 0x64, 0xe2, 0x64, 0xcf, 0x00, 0xed
    };

    /* Expected signature*/
    const uint8_t expected_signature[] = {
        0xe1, 0x6a, 0xe9, 0x76, 0x61, 0x97, 0x8e, 0xe9,
        0xc7, 0x0f, 0xe0, 0x20, 0xc0, 0x65, 0xe1, 0x6c,
        0x89, 0x6f, 0x24, 0x6b, 0x4e, 0x88, 0x10, 0xcd,
        0xb4, 0x9a, 0xcc, 0x20, 0xcf, 0xa5, 0xb0, 0xc9,
        0xc1, 0x02, 0x4b, 0xa7, 0x41, 0xef, 0x51, 0x8f,
        0xe3, 0x11, 0xec, 0x95, 0xe2, 0xf4, 0x83, 0x97,
        0x3d, 0x32, 0x72, 0xf6, 0x4b, 0x34, 0xd3, 0x9f,
        0x25, 0x6a, 0x12, 0x3b, 0x7c, 0x87, 0xc4, 0x4d
    };

    ec_context = libspdm_ec_new_by_nid(LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256);
    if (ec_context == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ec_context new failed \n"));
        result = false;
        goto update;
    }

    result = libspdm_ec_set_pub_key(ec_context, public_key, sizeof(public_key));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ec_context set pub_key failed \n"));
        libspdm_ec_free(ec_context);
        result = false;
        goto update;
    }

    result = libspdm_ec_set_priv_key(ec_context, priv_key, sizeof(priv_key));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ec_context set priv_key failed \n"));
        libspdm_ec_free(ec_context);
        result = false;
        goto update;
    }

    /*ECDSA KAT test*/
    result = libspdm_ecdsa_sign_ex(ec_context, LIBSPDM_CRYPTO_NID_SHA256,
                                   message_hash, sizeof(message_hash),
                                   signature, &sig_size,
                                   libspdm_hardcode_random_number_ecdsa);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDSA sign failed \n"));
        libspdm_ec_free(ec_context);
        result = false;
        goto update;
    }

    if (sig_size != sizeof(expected_signature)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDSA KAT failed \n"));
        libspdm_ec_free(ec_context);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(signature, expected_signature,
                                        sizeof(expected_signature))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDSA KAT failed \n"));
        libspdm_ec_free(ec_context);
        result = false;
        goto update;
    }

    result = libspdm_ecdsa_verify(ec_context, LIBSPDM_CRYPTO_NID_SHA256,
                                  message_hash, sizeof(message_hash),
                                  signature, sig_size);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDSA selftest failed \n"));
        libspdm_ec_free(ec_context);
        result = false;
        goto update;
    }

    libspdm_ec_free(ec_context);

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_ECDSA;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_ECDSA;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_ECDSA;
    }

#endif/*LIBSPDM_ECDSA_SUPPORT*/

    return result;
}

#endif/*LIBSPDM_FIPS_MODE*/
