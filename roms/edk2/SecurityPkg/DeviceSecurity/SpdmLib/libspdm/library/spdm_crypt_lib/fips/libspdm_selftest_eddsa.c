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
 * EDDSA self_test
 **/
bool libspdm_fips_selftest_eddsa(void *fips_selftest_context)
{
    bool result = true;

#if LIBSPDM_EDDSA_SUPPORT
    libspdm_fips_selftest_context *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return false;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_EDDSA) != 0) {
        return true;
    }

#if LIBSPDM_EDDSA_ED25519_SUPPORT

    void *ecd_25519;
    uint8_t signature_25519[32 * 2];
    size_t sig25519_size;
    uint8_t get_pub_key_25519[32];
    size_t get_pub_key_25519_size = sizeof(get_pub_key_25519);

    /*test vectors from https://www.rfc-editor.org/rfc/rfc8032 */
    uint8_t message_25519[] = {
        0x72
    };

    const uint8_t public_key_25519[] = {
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e,
        0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4,
        0x66, 0x0c
    };

    const uint8_t private_key_25519[] = {
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb
    };

    /* Expected signature*/
    const uint8_t expected_signature_25519[] = {
        0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25,
        0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb,
        0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0,
        0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16,
        0x12, 0xbb, 0x0c, 0x00
    };

    ecd_25519 = libspdm_ecd_new_by_nid(LIBSPDM_CRYPTO_NID_EDDSA_ED25519);
    if (ecd_25519 == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 25519 gen failed \n"));
        result = false;
        goto update;
    }

    result = libspdm_ecd_set_pub_key(ecd_25519, public_key_25519, sizeof(public_key_25519));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 25519 set public key failed \n"));
        libspdm_ecd_free(ecd_25519);
        result = false;
        goto update;
    }

    result =  libspdm_ecd_get_pub_key(ecd_25519, get_pub_key_25519, &get_pub_key_25519_size);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 25519 get pub key failed \n"));
        libspdm_ecd_free(ecd_25519);
        result = false;
        goto update;
    }

    if (get_pub_key_25519_size != sizeof(public_key_25519)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 25519 get key size compare failed \n"));
        libspdm_ecd_free(ecd_25519);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(get_pub_key_25519, public_key_25519,
                                        sizeof(public_key_25519))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 25519 get key content compare failed \n"));
        libspdm_ecd_free(ecd_25519);
        result = false;
        goto update;
    }

    result = libspdm_ecd_set_pri_key(ecd_25519, private_key_25519, sizeof(private_key_25519));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 25519 set private key failed \n"));
        libspdm_ecd_free(ecd_25519);
        result = false;
        goto update;
    }

    /* Verify Ed-DSA*/
    sig25519_size = sizeof(signature_25519);
    result = libspdm_eddsa_sign(ecd_25519, LIBSPDM_CRYPTO_NID_NULL, NULL, 0, message_25519,
                                sizeof(message_25519), signature_25519, &sig25519_size);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 25519 sign failed \n"));
        libspdm_ecd_free(ecd_25519);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(signature_25519, expected_signature_25519,
                                        sizeof(expected_signature_25519))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 25519 KAT failed \n"));
        libspdm_ecd_free(ecd_25519);
        result = false;
        goto update;
    }

    result = libspdm_eddsa_verify(ecd_25519, LIBSPDM_CRYPTO_NID_NULL, NULL, 0, message_25519,
                                  sizeof(message_25519), signature_25519, sig25519_size);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 25519 verify failed \n"));
        libspdm_ecd_free(ecd_25519);
        result = false;
        goto update;
    }

    libspdm_ecd_free(ecd_25519);

#endif/*LIBSPDM_EDDSA_ED25519_SUPPORT */

#if LIBSPDM_EDDSA_ED448_SUPPORT
    void *ecd_448;
    uint8_t signature_448[57 * 2];
    size_t sig448_size;
    uint8_t get_edd48_key[57];
    size_t get_pub_key_448_size = sizeof(get_edd48_key);

    /*test vectors from https://www.rfc-editor.org/rfc/rfc8032 */
    uint8_t message_448[] = {
        0x03
    };

    const uint8_t public_key_448[] = {
        0x43, 0xba, 0x28, 0xf4, 0x30, 0xcd, 0xff, 0x45, 0x6a, 0xe5, 0x31, 0x54, 0x5f, 0x7e, 0xcd,
        0x0a, 0xc8, 0x34, 0xa5, 0x5d, 0x93, 0x58, 0xc0, 0x37, 0x2b, 0xfa, 0x0c, 0x6c, 0x67, 0x98,
        0xc0, 0x86, 0x6a, 0xea, 0x01, 0xeb, 0x00, 0x74, 0x28, 0x02, 0xb8, 0x43, 0x8e, 0xa4, 0xcb,
        0x82, 0x16, 0x9c, 0x23, 0x51, 0x60, 0x62, 0x7b, 0x4c, 0x3a, 0x94, 0x80
    };

    const uint8_t private_key_448[] = {
        0xc4, 0xea, 0xb0, 0x5d, 0x35, 0x70, 0x07, 0xc6, 0x32, 0xf3, 0xdb, 0xb4, 0x84, 0x89, 0x92,
        0x4d, 0x55, 0x2b, 0x08, 0xfe, 0x0c, 0x35, 0x3a, 0x0d, 0x4a, 0x1f, 0x00, 0xac, 0xda, 0x2c,
        0x46, 0x3a, 0xfb, 0xea, 0x67, 0xc5, 0xe8, 0xd2, 0x87, 0x7c, 0x5e, 0x3b, 0xc3, 0x97, 0xa6,
        0x59, 0x94, 0x9e, 0xf8, 0x02, 0x1e, 0x95, 0x4e, 0x0a, 0x12, 0x27, 0x4e
    };

    /* Expected signature*/
    const uint8_t expected_signature_448[] = {
        0x26, 0xb8, 0xf9, 0x17, 0x27, 0xbd, 0x62, 0x89, 0x7a, 0xf1, 0x5e, 0x41, 0xeb, 0x43, 0xc3,
        0x77, 0xef, 0xb9, 0xc6, 0x10, 0xd4, 0x8f, 0x23, 0x35, 0xcb, 0x0b, 0xd0, 0x08, 0x78, 0x10,
        0xf4, 0x35, 0x25, 0x41, 0xb1, 0x43, 0xc4, 0xb9, 0x81, 0xb7, 0xe1, 0x8f, 0x62, 0xde, 0x8c,
        0xcd, 0xf6, 0x33, 0xfc, 0x1b, 0xf0, 0x37, 0xab, 0x7c, 0xd7, 0x79, 0x80, 0x5e, 0x0d, 0xbc,
        0xc0, 0xaa, 0xe1, 0xcb, 0xce, 0xe1, 0xaf, 0xb2, 0xe0, 0x27, 0xdf, 0x36, 0xbc, 0x04, 0xdc,
        0xec, 0xbf, 0x15, 0x43, 0x36, 0xc1, 0x9f, 0x0a, 0xf7, 0xe0, 0xa6, 0x47, 0x29, 0x05, 0xe7,
        0x99, 0xf1, 0x95, 0x3d, 0x2a, 0x0f, 0xf3, 0x34, 0x8a, 0xb2, 0x1a, 0xa4, 0xad, 0xaf, 0xd1,
        0xd2, 0x34, 0x44, 0x1c, 0xf8, 0x07, 0xc0, 0x3a
    };

    ecd_448 = libspdm_ecd_new_by_nid(LIBSPDM_CRYPTO_NID_EDDSA_ED448);
    if (ecd_448 == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 448 gen failed \n"));
        result = false;
        goto update;
    }

    result = libspdm_ecd_set_pub_key(ecd_448, public_key_448, sizeof(public_key_448));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 448 set public key failed \n"));
        libspdm_ecd_free(ecd_448);
        result = false;
        goto update;
    }

    result =  libspdm_ecd_get_pub_key(ecd_448, get_edd48_key, &get_pub_key_448_size);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 448 get pub key failed \n"));
        libspdm_ecd_free(ecd_448);
        result = false;
        goto update;
    }

    if (get_pub_key_448_size != sizeof(public_key_448)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 448 get key compare failed \n"));
        libspdm_ecd_free(ecd_448);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(get_edd48_key, public_key_448,
                                        sizeof(public_key_448))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 448 get key compare failed \n"));
        libspdm_ecd_free(ecd_448);
        result = false;
        goto update;
    }

    result = libspdm_ecd_set_pri_key(ecd_448, private_key_448, sizeof(private_key_448));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 448 set private key failed \n"));
        libspdm_ecd_free(ecd_448);
        result = false;
        goto update;
    }

    /* Verify Ed-DSA*/
    sig448_size = sizeof(signature_448);
    result = libspdm_eddsa_sign(ecd_448, LIBSPDM_CRYPTO_NID_NULL, NULL, 0, message_448,
                                sizeof(message_448), signature_448, &sig448_size);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 448 sign failed \n"));
        libspdm_ecd_free(ecd_448);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(signature_448, expected_signature_448,
                                        sizeof(expected_signature_448))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 448 KAT failed \n"));
        libspdm_ecd_free(ecd_448);
        result = false;
        goto update;
    }

    result = libspdm_eddsa_verify(ecd_448, LIBSPDM_CRYPTO_NID_NULL, NULL, 0, message_448,
                                  sizeof(message_448), signature_448, sig448_size);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "EDDSA 448 verify failed \n"));
        libspdm_ecd_free(ecd_448);
        result = false;
        goto update;
    }

    libspdm_ecd_free(ecd_448);
#endif/*LIBSPDM_EDDSA_ED448_SUPPORT*/

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_EDDSA;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_EDDSA;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_EDDSA;
    }

#endif /* LIBSPDM_EDDSA_SUPPORT */
    return result;
}

#endif/*LIBSPDM_FIPS_MODE*/
