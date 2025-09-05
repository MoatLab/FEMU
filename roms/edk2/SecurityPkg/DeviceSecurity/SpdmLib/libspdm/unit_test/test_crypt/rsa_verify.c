/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)

#define LIBSPDM_RSA_MODULUS_LENGTH 512

/* RSA2048 PKCS#1 Validation data */

/* Public modulus of RSA2048 key. */
uint8_t m_libspdm_rsa_n[] = {
    0xDB, 0x10, 0x1A, 0xC2, 0xA3, 0xF1, 0xDC, 0xFF, 0x13, 0x6B, 0xED, 0x44,
    0xDF, 0xF0, 0x02, 0x6D, 0x13, 0xC7, 0x88, 0xDA, 0x70, 0x6B, 0x54, 0xF1,
    0xE8, 0x27, 0xDC, 0xC3, 0x0F, 0x99, 0x6A, 0xFA, 0xC6, 0x67, 0xFF, 0x1D,
    0x1E, 0x3C, 0x1D, 0xC1, 0xB5, 0x5F, 0x6C, 0xC0, 0xB2, 0x07, 0x3A, 0x6D,
    0x41, 0xE4, 0x25, 0x99, 0xAC, 0xFC, 0xD2, 0x0F, 0x02, 0xD3, 0xD1, 0x54,
    0x06, 0x1A, 0x51, 0x77, 0xBD, 0xB6, 0xBF, 0xEA, 0xA7, 0x5C, 0x06, 0xA9,
    0x5D, 0x69, 0x84, 0x45, 0xD7, 0xF5, 0x05, 0xBA, 0x47, 0xF0, 0x1B, 0xD7,
    0x2B, 0x24, 0xEC, 0xCB, 0x9B, 0x1B, 0x10, 0x8D, 0x81, 0xA0, 0xBE, 0xB1,
    0x8C, 0x33, 0xE4, 0x36, 0xB8, 0x43, 0xEB, 0x19, 0x2A, 0x81, 0x8D, 0xDE,
    0x81, 0x0A, 0x99, 0x48, 0xB6, 0xF6, 0xBC, 0xCD, 0x49, 0x34, 0x3A, 0x8F,
    0x26, 0x94, 0xE3, 0x28, 0x82, 0x1A, 0x7C, 0x8F, 0x59, 0x9F, 0x45, 0xE8,
    0x5D, 0x1A, 0x45, 0x76, 0x04, 0x56, 0x05, 0xA1, 0xD0, 0x1B, 0x8C, 0x77,
    0x6D, 0xAF, 0x53, 0xFA, 0x71, 0xE2, 0x67, 0xE0, 0x9A, 0xFE, 0x03, 0xA9,
    0x85, 0xD2, 0xC9, 0xAA, 0xBA, 0x2A, 0xBC, 0xF4, 0xA0, 0x08, 0xF5, 0x13,
    0x98, 0x13, 0x5D, 0xF0, 0xD9, 0x33, 0x34, 0x2A, 0x61, 0xC3, 0x89, 0x55,
    0xF0, 0xAE, 0x1A, 0x9C, 0x22, 0xEE, 0x19, 0x05, 0x8D, 0x32, 0xFE, 0xEC,
    0x9C, 0x84, 0xBA, 0xB7, 0xF9, 0x6C, 0x3A, 0x4F, 0x07, 0xFC, 0x45, 0xEB,
    0x12, 0xE5, 0x7B, 0xFD, 0x55, 0xE6, 0x29, 0x69, 0xD1, 0xC2, 0xE8, 0xB9,
    0x78, 0x59, 0xF6, 0x79, 0x10, 0xC6, 0x4E, 0xEB, 0x6A, 0x5E, 0xB9, 0x9A,
    0xC7, 0xC4, 0x5B, 0x63, 0xDA, 0xA3, 0x3F, 0x5E, 0x92, 0x7A, 0x81, 0x5E,
    0xD6, 0xB0, 0xE2, 0x62, 0x8F, 0x74, 0x26, 0xC2, 0x0C, 0xD3, 0x9A, 0x17,
    0x47, 0xE6, 0x8E, 0xAB
};

/* Public exponent of RSA2048 key. */
uint8_t m_libspdm_rsa_e[] = { 0x01, 0x00, 0x01 };

/* Private exponent of RSA2048 key. */
uint8_t m_libspdm_rsa_d[] = {
    0x52, 0x41, 0xF4, 0xDA, 0x7B, 0xB7, 0x59, 0x55, 0xCA, 0xD4, 0x2F, 0x0F,
    0x3A, 0xCB, 0xA4, 0x0D, 0x93, 0x6C, 0xCC, 0x9D, 0xC1, 0xB2, 0xFB, 0xFD,
    0xAE, 0x40, 0x31, 0xAC, 0x69, 0x52, 0x21, 0x92, 0xB3, 0x27, 0xDF, 0xEA,
    0xEE, 0x2C, 0x82, 0xBB, 0xF7, 0x40, 0x32, 0xD5, 0x14, 0xC4, 0x94, 0x12,
    0xEC, 0xB8, 0x1F, 0xCA, 0x59, 0xE3, 0xC1, 0x78, 0xF3, 0x85, 0xD8, 0x47,
    0xA5, 0xD7, 0x02, 0x1A, 0x65, 0x79, 0x97, 0x0D, 0x24, 0xF4, 0xF0, 0x67,
    0x6E, 0x75, 0x2D, 0xBF, 0x10, 0x3D, 0xA8, 0x7D, 0xEF, 0x7F, 0x60, 0xE4,
    0xE6, 0x05, 0x82, 0x89, 0x5D, 0xDF, 0xC6, 0xD2, 0x6C, 0x07, 0x91, 0x33,
    0x98, 0x42, 0xF0, 0x02, 0x00, 0x25, 0x38, 0xC5, 0x85, 0x69, 0x8A, 0x7D,
    0x2F, 0x95, 0x6C, 0x43, 0x9A, 0xB8, 0x81, 0xE2, 0xD0, 0x07, 0x35, 0xAA,
    0x05, 0x41, 0xC9, 0x1E, 0xAF, 0xE4, 0x04, 0x3B, 0x19, 0xB8, 0x73, 0xA2,
    0xAC, 0x4B, 0x1E, 0x66, 0x48, 0xD8, 0x72, 0x1F, 0xAC, 0xF6, 0xCB, 0xBC,
    0x90, 0x09, 0xCA, 0xEC, 0x0C, 0xDC, 0xF9, 0x2C, 0xD7, 0xEB, 0xAE, 0xA3,
    0xA4, 0x47, 0xD7, 0x33, 0x2F, 0x8A, 0xCA, 0xBC, 0x5E, 0xF0, 0x77, 0xE4,
    0x97, 0x98, 0x97, 0xC7, 0x10, 0x91, 0x7D, 0x2A, 0xA6, 0xFF, 0x46, 0x83,
    0x97, 0xDE, 0xE9, 0xE2, 0x17, 0x03, 0x06, 0x14, 0xE2, 0xD7, 0xB1, 0x1D,
    0x77, 0xAF, 0x51, 0x27, 0x5B, 0x5E, 0x69, 0xB8, 0x81, 0xE6, 0x11, 0xC5,
    0x43, 0x23, 0x81, 0x04, 0x62, 0xFF, 0xE9, 0x46, 0xB8, 0xD8, 0x44, 0xDB,
    0xA5, 0xCC, 0x31, 0x54, 0x34, 0xCE, 0x3E, 0x82, 0xD6, 0xBF, 0x7A, 0x0B,
    0x64, 0x21, 0x6D, 0x88, 0x7E, 0x5B, 0x45, 0x12, 0x1E, 0x63, 0x8D, 0x49,
    0xA7, 0x1D, 0xD9, 0x1E, 0x06, 0xCD, 0xE8, 0xBA, 0x2C, 0x8C, 0x69, 0x32,
    0xEA, 0xBE, 0x60, 0x71
};

/* signature input message */
const char m_libspdm_rsa_sign_data[] = "OpenSSL FIPS 140-2 Public Key RSA KAT";

/**
 * RSA2048 SHA-256 PAD_PKCS1 signature for the above message.
 * This is libspdm self_test, not FIPS 140-2 KAT.
 * Because the padding way is different.
 **/
uint8_t m_libspdm_rsa_pkcs1_signature[] = {
    0x6e, 0x5f, 0xb3, 0x06, 0x47, 0x20, 0xe7, 0x94, 0xce, 0xc1, 0x82, 0xd1,
    0xc4, 0x8a, 0x05, 0x8f, 0xed, 0xe7, 0x81, 0x04, 0xe6, 0x1c, 0x42, 0xe1,
    0x58, 0x14, 0x5e, 0xc1, 0xe2, 0x9f, 0xbb, 0x30, 0x43, 0xf5, 0x00, 0x54,
    0x73, 0x8f, 0xf7, 0xbf, 0xe5, 0x1c, 0x18, 0xf8, 0xfb, 0xf0, 0x44, 0x0a,
    0x9e, 0xc9, 0x94, 0xf7, 0x41, 0xef, 0x5a, 0xa7, 0x66, 0x8b, 0xb3, 0x59,
    0xd7, 0xad, 0x07, 0x81, 0x57, 0x67, 0x6e, 0x71, 0xd9, 0xdc, 0xd6, 0x06,
    0x70, 0x19, 0x49, 0xb9, 0xf4, 0x1e, 0x1e, 0x77, 0x7c, 0xb1, 0xe9, 0xa7,
    0x8d, 0xe2, 0x99, 0x9a, 0x06, 0x5e, 0xb8, 0xb0, 0x6a, 0x00, 0x9b, 0x95,
    0x11, 0xf3, 0x80, 0x89, 0x56, 0xce, 0xe0, 0x21, 0xf2, 0xb5, 0x7a, 0x22,
    0x47, 0x0e, 0xd2, 0xb8, 0x90, 0x0a, 0x3c, 0x0f, 0x00, 0xb5, 0x7d, 0xc1,
    0xb0, 0x9d, 0x7a, 0x2d, 0x6d, 0x7d, 0x34, 0x8b, 0xf5, 0xcb, 0xcf, 0x7a,
    0xeb, 0x4a, 0xdd, 0x75, 0x1c, 0x34, 0x74, 0xe7, 0x4c, 0x2a, 0x51, 0xd6,
    0x8b, 0x48, 0xca, 0x99, 0x9f, 0x73, 0x18, 0xb6, 0x19, 0x03, 0x8a, 0x22,
    0xb9, 0x8f, 0x08, 0x6c, 0xd6, 0x6b, 0x6f, 0xbe, 0x56, 0xd2, 0x50, 0x75,
    0xa9, 0x1c, 0x66, 0x47, 0x4b, 0x4f, 0x75, 0xcd, 0x02, 0x82, 0xc3, 0xf4,
    0x29, 0xaf, 0x8f, 0x31, 0xd1, 0xbe, 0x4b, 0x93, 0x31, 0x04, 0x8a, 0xd0,
    0x09, 0xc7, 0x3c, 0x20, 0xd5, 0xcc, 0xdc, 0xf6, 0xea, 0xa8, 0x16, 0x1a,
    0x3c, 0x63, 0x3c, 0xef, 0x63, 0xd4, 0xc1, 0xc0, 0x23, 0xe9, 0x95, 0xcf,
    0x96, 0xc3, 0x6b, 0xca, 0x61, 0xda, 0x8f, 0xc2, 0x2a, 0xe4, 0xef, 0x80,
    0xf1, 0x9b, 0x31, 0xfe, 0xe6, 0x58, 0x3f, 0xa9, 0x49, 0x7b, 0xdc, 0xae,
    0x1b, 0x6d, 0x68, 0x98, 0x55, 0x9d, 0x73, 0xf0, 0xcc, 0x23, 0xc0, 0x84,
    0x46, 0x67, 0x35, 0x54
};

/* Default public key 0x10001. */
uint8_t m_libspdm_default_public_key[] = { 0x01, 0x00, 0x01 };

/* input public key test. */
uint8_t m_libspdm_test_rsa_public_exponent1[] = { 0x03 };
uint8_t m_libspdm_test_rsa_public_exponent2[] = { 0x01, 0x01 };
uint8_t m_libspdm_test_rsa_public_exponent3[] = { 0x01, 0x00, 0x01};

uint8_t * m_libspdm_test_rsa_public_exponent[] = {
    m_libspdm_test_rsa_public_exponent1,
    m_libspdm_test_rsa_public_exponent2,
    m_libspdm_test_rsa_public_exponent3
};

/**
 * Validate Crypto RSA Interfaces.
 *
 * @retval  true   Validation succeeded.
 * @retval  false  Validation failed.
 **/
bool libspdm_validate_crypt_rsa(void)
{
    void *rsa;
    #if LIBSPDM_SHA256_SUPPORT
    uint8_t hash_value[LIBSPDM_SHA256_DIGEST_SIZE];
    size_t hash_size;
    void *sha256_ctx;
    uint8_t *signature;
    size_t sig_size;
    #endif
    bool status;
    size_t key_size;
    uint8_t *KeyBuffer;
    uint8_t index;

    libspdm_my_print("\nCrypto RSA Engine Testing: ");

    /* Generate & Initialize RSA context*/
    rsa = libspdm_rsa_new();
    libspdm_my_print("\n- Generate RSA context ... ");
    if (rsa == NULL) {
        libspdm_my_print("[Fail]");
        return false;
    }

    /* Set/Get RSA key Components*/
    libspdm_my_print("Set/Get RSA key Components ... ");

    /* Set/Get RSA key N*/
    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_N, m_libspdm_rsa_n, sizeof(m_libspdm_rsa_n));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    key_size = 0;
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_N, NULL, &key_size);
    if (status || key_size != sizeof(m_libspdm_rsa_n)) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    KeyBuffer = allocate_pool(key_size);
    if (KeyBuffer == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_N, KeyBuffer, &key_size);
    if (!status || key_size != sizeof(m_libspdm_rsa_n)) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return false;
    }

    if (memcmp(KeyBuffer, m_libspdm_rsa_n, key_size) != 0) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return false;
    }

    free_pool(KeyBuffer);

    /* Set/Get RSA key E*/
    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_E, m_libspdm_rsa_e, sizeof(m_libspdm_rsa_e));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    key_size = 0;
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_E, NULL, &key_size);
    if (status || key_size != sizeof(m_libspdm_rsa_e)) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    KeyBuffer = allocate_pool(key_size);
    if (KeyBuffer == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_E, KeyBuffer, &key_size);
    if (!status || key_size != sizeof(m_libspdm_rsa_e)) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return false;
    }

    if (memcmp(KeyBuffer, m_libspdm_rsa_e, key_size) != 0) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return false;
    }

    free_pool(KeyBuffer);

    /* Clear/Get RSA key Components*/
    libspdm_my_print("Clear/Get RSA key Components ... ");

    /* Clear/Get RSA key N*/
    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_N, NULL, 0);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    key_size = 1;
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_N, NULL, &key_size);
    if (!status || key_size != 0) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    /* Clear/Get RSA key E*/
    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_E, NULL, 0);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    key_size = 1;
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_E, NULL, &key_size);
    if (!status || key_size != 0) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    /* Generate RSA key Components without default RSA public exponent*/
    libspdm_my_print("Generate RSA key Components without default RSA public exponent... ");

    for (index = 0; index < 3; index++) {
        libspdm_rsa_free(rsa);
        rsa = libspdm_rsa_new();
        status = libspdm_rsa_generate_key(rsa, LIBSPDM_RSA_MODULUS_LENGTH,
                                          m_libspdm_test_rsa_public_exponent[index],
                                          (index + 1));
        if (!status) {
            libspdm_my_print("[Fail]");
            libspdm_rsa_free(rsa);
            return false;
        }

        key_size = LIBSPDM_RSA_MODULUS_LENGTH / 8;
        KeyBuffer = allocate_pool(key_size);
        if (KeyBuffer == NULL) {
            libspdm_my_print("[Fail]");
            libspdm_rsa_free(rsa);
            return false;
        }
        status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_E, KeyBuffer, &key_size);
        if (!status) {
            libspdm_my_print("[Fail]");
            free_pool(KeyBuffer);
            libspdm_rsa_free(rsa);
            return false;
        }

        if ((key_size != (size_t)(index + 1)) ||
            memcmp(KeyBuffer, m_libspdm_test_rsa_public_exponent[index],
                   (index + 1)) != 0) {
            libspdm_my_print("[Fail]");
            free_pool(KeyBuffer);
            libspdm_rsa_free(rsa);
            return false;
        }

        key_size = LIBSPDM_RSA_MODULUS_LENGTH / 8;
        status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_N, KeyBuffer, &key_size);
        if (!status) {
            libspdm_my_print("[Fail]");
            free_pool(KeyBuffer);
            libspdm_rsa_free(rsa);
            return false;
        }

        if (key_size != LIBSPDM_RSA_MODULUS_LENGTH / 8) {
            libspdm_my_print("[Fail]");
            free_pool(KeyBuffer);
            libspdm_rsa_free(rsa);
            return false;
        }

        if (!libspdm_rsa_check_key(rsa)) {
            libspdm_my_print("[Fail]");
            free_pool(KeyBuffer);
            libspdm_rsa_free(rsa);
            return false;
        }
        free_pool(KeyBuffer);
    }

    /* Generate RSA key Components with default RSA public exponent*/
    libspdm_my_print("Generate RSA key Components with default RSA public exponent... ");

    status = libspdm_rsa_generate_key(rsa, LIBSPDM_RSA_MODULUS_LENGTH, NULL, 0);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    key_size = LIBSPDM_RSA_MODULUS_LENGTH / 8;
    KeyBuffer = allocate_pool(key_size);
    if (KeyBuffer == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_E, KeyBuffer, &key_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return false;
    }

    if (key_size != 3 ||
        memcmp(KeyBuffer, m_libspdm_default_public_key, 3) != 0) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return false;
    }

    key_size = LIBSPDM_RSA_MODULUS_LENGTH / 8;
    status = libspdm_rsa_get_key(rsa, LIBSPDM_RSA_KEY_N, KeyBuffer, &key_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return false;
    }

    if (key_size != LIBSPDM_RSA_MODULUS_LENGTH / 8) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return false;
    }

    if (!libspdm_rsa_check_key(rsa)) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return false;
    }

    /* Check invalid RSA key components*/
    libspdm_my_print("Check Invalid RSA key Components ... ");

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_N, m_libspdm_rsa_n, sizeof(m_libspdm_rsa_n));
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return false;
    }

    if (libspdm_rsa_check_key(rsa)) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return false;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_N, KeyBuffer, key_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return false;
    }

    if (!libspdm_rsa_check_key(rsa)) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return false;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_E, m_libspdm_rsa_e, sizeof(m_libspdm_rsa_e));
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return false;
    }

    if (!libspdm_rsa_check_key(rsa)) {
        libspdm_my_print("[Fail]");
        free_pool(KeyBuffer);
        libspdm_rsa_free(rsa);
        return false;
    }

    free_pool(KeyBuffer);

    #if LIBSPDM_SHA256_SUPPORT
    /* SHA-256 digest message for PKCS#1 signature*/
    libspdm_my_print("hash Original message ... ");
    hash_size = LIBSPDM_SHA256_DIGEST_SIZE;
    libspdm_zero_mem(hash_value, hash_size);
    sha256_ctx = libspdm_sha256_new();
    if (sha256_ctx == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    status = libspdm_sha256_init(sha256_ctx);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_sha256_free(sha256_ctx);
        libspdm_rsa_free(rsa);
        return false;
    }

    status = libspdm_sha256_update(sha256_ctx, m_libspdm_rsa_sign_data,
                                   libspdm_ascii_str_len(m_libspdm_rsa_sign_data));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_sha256_free(sha256_ctx);
        libspdm_rsa_free(rsa);
        return false;
    }

    status = libspdm_sha256_final(sha256_ctx, hash_value);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_sha256_free(sha256_ctx);
        libspdm_rsa_free(rsa);
        return false;
    }

    libspdm_sha256_free(sha256_ctx);

    #if LIBSPDM_RSA_SSA_SUPPORT
    /* Sign RSA PKCS#1-encoded signature*/
    libspdm_my_print("PKCS#1 signature ... ");

    libspdm_rsa_free(rsa);

    rsa = libspdm_rsa_new();
    if (rsa == NULL) {
        libspdm_my_print("[Fail]");
        return false;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_N, m_libspdm_rsa_n, sizeof(m_libspdm_rsa_n));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_E, m_libspdm_rsa_e, sizeof(m_libspdm_rsa_e));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_D, m_libspdm_rsa_d, sizeof(m_libspdm_rsa_d));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    sig_size = 0;
    status = libspdm_rsa_pkcs1_sign_with_nid(rsa, LIBSPDM_CRYPTO_NID_SHA256, hash_value,
                                             hash_size, NULL, &sig_size);
    if (status || sig_size == 0) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    signature = allocate_pool(sig_size);
    if (signature == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }
    status = libspdm_rsa_pkcs1_sign_with_nid(rsa, LIBSPDM_CRYPTO_NID_SHA256, hash_value,
                                             hash_size, signature, &sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(signature);
        libspdm_rsa_free(rsa);
        return false;
    }

    if (sig_size != sizeof(m_libspdm_rsa_pkcs1_signature) ||
        memcmp(m_libspdm_rsa_pkcs1_signature, signature, sig_size)) {
        libspdm_my_print("[Fail]");
        free_pool(signature);
        libspdm_rsa_free(rsa);
        return false;
    }

    /* Verify RSA PKCS#1-encoded signature*/
    libspdm_my_print("PKCS#1 signature Verification ... ");

    status = libspdm_rsa_pkcs1_verify_with_nid(rsa, LIBSPDM_CRYPTO_NID_SHA256, hash_value,
                                               hash_size, signature, sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        free_pool(signature);
        return false;
    }

    free_pool(signature);
    #endif /* LIBSPDM_RSA_SSA_SUPPORT */

    #if LIBSPDM_RSA_PSS_SUPPORT
    /* Sign RSA PSS-encoded signature*/
    libspdm_my_print("PSS signature ... ");

    libspdm_rsa_free(rsa);

    rsa = libspdm_rsa_new();
    if (rsa == NULL) {
        libspdm_my_print("[Fail]");
        return false;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_N, m_libspdm_rsa_n, sizeof(m_libspdm_rsa_n));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_E, m_libspdm_rsa_e, sizeof(m_libspdm_rsa_e));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    status = libspdm_rsa_set_key(rsa, LIBSPDM_RSA_KEY_D, m_libspdm_rsa_d, sizeof(m_libspdm_rsa_d));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    sig_size = 0;
    status = libspdm_rsa_pss_sign(rsa, LIBSPDM_CRYPTO_NID_SHA256, hash_value, hash_size,
                                  NULL, &sig_size);
    if (status || sig_size == 0) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }

    signature = allocate_pool(sig_size);
    if (signature == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_rsa_free(rsa);
        return false;
    }
    status = libspdm_rsa_pss_sign(rsa, LIBSPDM_CRYPTO_NID_SHA256, hash_value, hash_size,
                                  signature, &sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(signature);
        libspdm_rsa_free(rsa);
        return false;
    }

    /* Verify RSA PSS-encoded signature*/
    libspdm_my_print("PSS signature Verification ... ");

    status = libspdm_rsa_pss_verify(rsa, LIBSPDM_CRYPTO_NID_SHA256, hash_value, hash_size,
                                    signature, sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(signature);
        libspdm_rsa_free(rsa);
        return false;
    }

    free_pool(signature);
    #endif /* LIBSPDM_RSA_PSS_SUPPORT */

    /* Release Resources*/
    libspdm_rsa_free(rsa);
    libspdm_my_print("Release RSA context ... [Pass]");

    libspdm_my_print("\n");
    #endif /* LIBSPDM_SHA256_SUPPORT */

    return true;
}

#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */
