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
 * AES_GCM self_test
 **/
bool libspdm_fips_selftest_aes_gcm(void *fips_selftest_context)
{
    bool result = true;

#if LIBSPDM_AEAD_GCM_SUPPORT
    libspdm_fips_selftest_context *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return false;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_AES_GCM) != 0) {
        return true;
    }

    uint8_t output_ciphertext[1024];
    uint8_t output_plaintext[1024];
    uint8_t output_tag[1024];
    size_t output_ciphertext_size;
    size_t output_plaintext_size;

    output_ciphertext_size = sizeof(output_ciphertext);
    output_plaintext_size = sizeof(output_plaintext);

    /*Key to use crypto operation*/
    const uint8_t key[] = {
        0x01, 0xd1, 0xa6, 0x9e, 0x73, 0x7f, 0xf2, 0xea,
        0x53, 0x56, 0x6f, 0xa2, 0xd7, 0xc0, 0x80, 0xd6
    };

    /*IV to perform the crypto operation upon*/
    const uint8_t iv[] = {
        0x0f, 0x3e, 0xd5, 0x9c, 0xa5, 0xb3, 0x0f, 0xb5,
        0xea, 0x4e, 0x13, 0x60
    };

    /*Data to perform the crypto operation upon*/
    const uint8_t input[] = {
        0xf6, 0x28, 0xc8, 0x61, 0xe5, 0x97, 0x04, 0xd9,
        0xba, 0xc8, 0x00, 0xc0, 0x4c, 0x1a, 0x2d, 0x7e,
        0x6c, 0x44, 0x61, 0x3f, 0xa4, 0x64, 0xb0, 0xe1,
        0x17, 0x3d, 0x8d, 0xba, 0xc0, 0x14, 0x72, 0xd3,
        0xc6, 0x8a, 0x5e, 0xb4, 0xf3, 0x16, 0x7f, 0xd0,
        0x21, 0x29, 0x76, 0x85, 0x86, 0x4d, 0x78, 0x86,
        0x14, 0x98, 0x32, 0x5e, 0xa6, 0xda, 0x6f, 0xce,
        0x98, 0x2c, 0xe9, 0x6e, 0xaa, 0x77, 0x18, 0xb8,
        0x89, 0xb7, 0x2d, 0x13, 0xc5, 0x61, 0xb3, 0xaf,
        0xe7, 0x13, 0xa7, 0x38, 0x45, 0xd4, 0x4c, 0x4a,
        0xc6, 0xdc, 0xe5, 0x29, 0x6c, 0xd5, 0xd9, 0xc6,
        0xde, 0xe2, 0x5d, 0x78, 0xfd, 0xa7, 0x3a, 0x45,
        0x7e, 0xdf, 0x00, 0xd0, 0x6a, 0xb0, 0xe8, 0x3a,
        0x86, 0x48, 0xa7, 0xaf, 0x7e, 0x6f, 0x33, 0xb2
    };

    /*Additional auth data*/
    const uint8_t aad[] = {
        0x66, 0x2a, 0x0a, 0x62, 0xe2, 0xb5, 0xa5, 0xa9,
        0xae, 0x46, 0x19, 0x16, 0x46, 0xf5, 0x26, 0xd8,
        0x8b, 0xf1, 0xac, 0xe1, 0x11, 0xee, 0xcf, 0x66,
        0x8c, 0x3b, 0xde, 0x57, 0x42, 0x2b, 0xa8, 0x02,
        0xc4, 0x60, 0x24, 0xb3, 0xa3, 0x84, 0xb5, 0x52,
        0x12, 0x98, 0xfe, 0x1e
    };

    /*Expected ciphertext*/
    const uint8_t expected_ciphertext[] = {
        0x2d, 0x4a, 0x0b, 0x34, 0x20, 0xcd, 0x7a, 0xe7,
        0x91, 0x1e, 0x5a, 0x53, 0x5e, 0x2b, 0x7b, 0x8e,
        0x42, 0x37, 0xf0, 0xeb, 0x5a, 0x84, 0xc5, 0xea,
        0x95, 0xd3, 0xe7, 0xe2, 0xb4, 0xb8, 0x88, 0xe0,
        0x4f, 0x28, 0xe3, 0x41, 0x7f, 0x05, 0x8d, 0x7c,
        0x4d, 0xae, 0x05, 0x92, 0xfc, 0x27, 0xfc, 0x67,
        0x94, 0x9f, 0x24, 0xa5, 0x5e, 0x70, 0xd9, 0xa7,
        0xb3, 0xd2, 0x78, 0xf0, 0xcd, 0x75, 0x4e, 0x43,
        0xe8, 0xad, 0xd4, 0x54, 0x57, 0xf8, 0x67, 0x1d,
        0x31, 0xbf, 0x45, 0xef, 0x1f, 0xaf, 0xec, 0x3b,
        0x4b, 0x3c, 0x90, 0x65, 0x83, 0x32, 0x6c, 0x9b,
        0x5c, 0xc2, 0x30, 0xc4, 0x5a, 0x6e, 0xec, 0x74,
        0xe3, 0x51, 0x11, 0xb5, 0x51, 0x04, 0xc5, 0xc0,
        0x68, 0x50, 0xc4, 0xb8, 0xd1, 0x9a, 0x8e, 0x37
    };

    /*Expected Auth Tag*/
    const uint8_t expected_tag[] = {
        0xc1, 0x37, 0xee, 0x11, 0x32, 0xf3, 0x75, 0x0a,
        0xd6, 0x57, 0x78, 0x77, 0x40, 0x05, 0x91, 0x41
    };

    /*KAT test*/
    libspdm_zero_mem(output_ciphertext, sizeof(output_ciphertext));
    libspdm_zero_mem(output_tag, sizeof(output_tag));
    result = libspdm_aead_aes_gcm_encrypt(key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad),
                                          input, sizeof(input), output_tag, sizeof(expected_tag),
                                          output_ciphertext, &output_ciphertext_size);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aes_gcm encrypt failed \n"));
        goto update;
    }

    if (output_ciphertext_size != sizeof(expected_ciphertext)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aes_gcm KAT failed \n"));
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(output_ciphertext, expected_ciphertext,
                                        sizeof(expected_ciphertext))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aes_gcm KAT failed \n"));
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(output_tag, expected_tag, sizeof(expected_tag))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aes_gcm KAT failed \n"));
        result = false;
        goto update;
    }

    libspdm_zero_mem(output_plaintext, sizeof(output_plaintext));
    result = libspdm_aead_aes_gcm_decrypt(key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad),
                                          expected_ciphertext, sizeof(expected_ciphertext),
                                          expected_tag, sizeof(expected_tag),
                                          output_plaintext, &output_plaintext_size);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aes_gcm decrypt failed \n"));
        result = false;
        goto update;
    }

    if (output_plaintext_size != sizeof(input)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aes_gcm selftest failed \n"));
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(output_plaintext, input, sizeof(input))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aes_gcm selftest failed \n"));
        result = false;
        goto update;
    }

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_AES_GCM;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_AES_GCM;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_AES_GCM;
    }

#endif/*LIBSPDM_AEAD_GCM_SUPPORT*/

    return result;
}

#endif
