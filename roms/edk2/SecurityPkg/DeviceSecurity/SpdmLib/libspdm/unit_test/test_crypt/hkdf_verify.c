/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

uint8_t m_libspdm_hkdf_sha256_ikm[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b
};

uint8_t m_libspdm_hkdf_sha256_salt[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c,
};

uint8_t m_libspdm_hkdf_sha256_info[] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
};

uint8_t m_libspdm_hkdf_sha256_prk[] = {
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc,
    0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b,
    0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
    0xb3, 0xe5,
};

uint8_t m_libspdm_hkdf_sha256_okm[] = {
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43,
    0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90,
    0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
    0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
    0x58, 0x65,
};

/**
 * This Hkdf-Sha384 test vector is form Project Wycheproof
 * developed and maintained by members of Google Security Team.
 * https://github.com/google/wycheproof/blob/master/testvectors/hkdf_sha384_test.json
 **/
uint8_t m_libspdm_hkdf_sha384_ikm[] = {
    0x86, 0x77, 0xdc, 0x79, 0x23, 0x3e, 0xf3, 0x48, 0x07, 0x77,
    0xc4, 0xc6, 0x01, 0xef, 0x4f, 0x0b,
};

uint8_t m_libspdm_hkdf_sha384_salt[] = {
    0xad, 0x88, 0xdb, 0x71, 0x82, 0x44, 0xe2, 0xcb, 0x60, 0xe3,
    0x5f, 0x87, 0x4d, 0x7a, 0xd8, 0x1f,
};

uint8_t m_libspdm_hkdf_sha384_info[] = {
    0xa3, 0x8f, 0x63, 0x4d, 0x94, 0x78, 0x19, 0xa9, 0xbf, 0xa7,
    0x92, 0x17, 0x4b, 0x42, 0xba, 0xa2, 0x0c, 0x9f, 0xce, 0x15,
};

uint8_t m_libspdm_hkdf_sha384_prk[] = {
    0x60, 0xae, 0xa0, 0xde, 0xca, 0x97, 0x62, 0xaa, 0x43, 0xaf,
    0x0e, 0x77, 0xa8, 0x0f, 0xb7, 0x76, 0xd0, 0x08, 0x19, 0x62,
    0xf8, 0x30, 0xb5, 0x0d, 0x92, 0x08, 0x92, 0x7a, 0x8a, 0xd5,
    0x6a, 0x3d, 0xc4, 0x4a, 0x5d, 0xfe, 0xb6, 0xb4, 0x79, 0x2f,
    0x97, 0x92, 0x71, 0xe6, 0xcb, 0x08, 0x86, 0x52,
};

uint8_t m_libspdm_hkdf_sha384_okm[] = {
    0x75, 0x85, 0x46, 0x36, 0x2a, 0x07, 0x0c, 0x0f, 0x13, 0xcb,
    0xfb, 0xf1, 0x75, 0x6e, 0x8f, 0x29, 0xb7, 0x81, 0x9f, 0xb9,
    0x03, 0xc7, 0xed, 0x4f, 0x97, 0xa5, 0x6b, 0xe3, 0xc8, 0xf8,
    0x1e, 0x8c, 0x37, 0xae, 0xf5, 0xc0, 0xf8, 0xe5, 0xd2, 0xb1,
    0x7e, 0xb1, 0xaa, 0x02, 0xec, 0x04, 0xc3, 0x3f, 0x54, 0x6c,
    0xb2, 0xf3, 0xd1, 0x93, 0xe9, 0x30, 0xa9, 0xf8, 0x9e, 0xc9,
    0xce, 0x3a, 0x82, 0xb5
};

/**
 * Validate Crypto HMAC Key Derivation Function Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 **/
bool libspdm_validate_crypt_hkdf(void)
{
    #if LIBSPDM_SHA256_SUPPORT || LIBSPDM_SHA3_256_SUPPORT || \
    LIBSPDM_SM3_256_SUPPORT || LIBSPDM_SHA384_SUPPORT

    #if LIBSPDM_SHA256_SUPPORT || LIBSPDM_SHA3_256_SUPPORT || \
    LIBSPDM_SM3_256_SUPPORT
    uint8_t prk_out[32];
    uint8_t out[42];
    #endif

    #if LIBSPDM_SHA384_SUPPORT
    uint8_t prk_out48[48];
    uint8_t out64[64];
    #endif
    bool status;

    libspdm_my_print(" \nCrypto HKDF Engine Testing:\n");

    #if LIBSPDM_SHA256_SUPPORT
    /* HKDF-SHA-256 digest validation. */
    libspdm_my_print("- HKDF-SHA256: ");

    libspdm_my_print("extract... ");
    libspdm_zero_mem(prk_out, sizeof(prk_out));
    status = libspdm_hkdf_sha256_extract (
        m_libspdm_hkdf_sha256_ikm, sizeof(m_libspdm_hkdf_sha256_ikm),
        m_libspdm_hkdf_sha256_salt, sizeof(m_libspdm_hkdf_sha256_salt),
        prk_out, sizeof(prk_out)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Check value... ");
    if (memcmp(prk_out, m_libspdm_hkdf_sha256_prk, sizeof(m_libspdm_hkdf_sha256_prk)) != 0) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_zero_mem(out, sizeof(out));
    libspdm_my_print("expand... ");
    status = libspdm_hkdf_sha256_expand (
        m_libspdm_hkdf_sha256_prk, sizeof(m_libspdm_hkdf_sha256_prk),
        m_libspdm_hkdf_sha256_info, sizeof(m_libspdm_hkdf_sha256_info),
        out, sizeof(out)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Check value... ");
    if (memcmp(out, m_libspdm_hkdf_sha256_okm, sizeof(m_libspdm_hkdf_sha256_okm)) != 0) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_zero_mem(out, sizeof(out));
    libspdm_my_print("extract_and_expand... ");
    status = libspdm_hkdf_sha256_extract_and_expand (
        m_libspdm_hkdf_sha256_ikm, sizeof(m_libspdm_hkdf_sha256_ikm),
        m_libspdm_hkdf_sha256_salt, sizeof(m_libspdm_hkdf_sha256_salt),
        m_libspdm_hkdf_sha256_info, sizeof(m_libspdm_hkdf_sha256_info),
        out, sizeof(out)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Check value... ");
    if (memcmp(out, m_libspdm_hkdf_sha256_okm, sizeof(m_libspdm_hkdf_sha256_okm)) != 0) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("[Pass]\n");
    #endif /* LIBSPDM_SHA256_SUPPORT */

    #if LIBSPDM_SHA3_256_SUPPORT
    /* HKDF-SHA3-256 digest validation. */
    libspdm_my_print("- HKDF-SHA3_256: ");

    libspdm_my_print("extract... ");
    libspdm_zero_mem(prk_out, sizeof(prk_out));
    status = libspdm_hkdf_sha3_256_extract (
        m_libspdm_hkdf_sha256_ikm, sizeof(m_libspdm_hkdf_sha256_ikm),
        m_libspdm_hkdf_sha256_salt, sizeof(m_libspdm_hkdf_sha256_salt),
        prk_out, sizeof(prk_out)
        );
    if (!status) {
        libspdm_my_print("[Fail]\n");
        return true;
    }

    libspdm_zero_mem(out, sizeof(out));
    libspdm_my_print("expand... ");
    status = libspdm_hkdf_sha3_256_expand (
        m_libspdm_hkdf_sha256_prk, sizeof(m_libspdm_hkdf_sha256_prk),
        m_libspdm_hkdf_sha256_info, sizeof(m_libspdm_hkdf_sha256_info),
        out, sizeof(out)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_zero_mem(out, sizeof(out));
    libspdm_my_print("extract_and_expand... ");
    status = libspdm_hkdf_sha3_256_extract_and_expand (
        m_libspdm_hkdf_sha256_ikm, sizeof(m_libspdm_hkdf_sha256_ikm),
        m_libspdm_hkdf_sha256_salt, sizeof(m_libspdm_hkdf_sha256_salt),
        m_libspdm_hkdf_sha256_info, sizeof(m_libspdm_hkdf_sha256_info),
        out, sizeof(out)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("[Pass]\n");
    #endif /* LIBSPDM_SHA3_256_SUPPORT */

    #if LIBSPDM_SM3_256_SUPPORT
    /* HKDF-SM3-256 digest validation. */
    libspdm_my_print("- HKDF-SM3_256: ");

    libspdm_my_print("extract... ");
    libspdm_zero_mem(prk_out, sizeof(prk_out));
    status = libspdm_hkdf_sm3_256_extract (
        m_libspdm_hkdf_sha256_ikm, sizeof(m_libspdm_hkdf_sha256_ikm),
        m_libspdm_hkdf_sha256_salt, sizeof(m_libspdm_hkdf_sha256_salt),
        prk_out, sizeof(prk_out)
        );
    if (!status) {
        libspdm_my_print("[Fail]\n");
        return false;
    }

    libspdm_zero_mem(out, sizeof(out));
    libspdm_my_print("expand... ");
    status = libspdm_hkdf_sm3_256_expand (
        m_libspdm_hkdf_sha256_prk, sizeof(m_libspdm_hkdf_sha256_prk),
        m_libspdm_hkdf_sha256_info, sizeof(m_libspdm_hkdf_sha256_info),
        out, sizeof(out)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_zero_mem(out, sizeof(out));
    libspdm_my_print("extract_and_expand... ");
    status = libspdm_hkdf_sm3_256_extract_and_expand (
        m_libspdm_hkdf_sha256_ikm, sizeof(m_libspdm_hkdf_sha256_ikm),
        m_libspdm_hkdf_sha256_salt, sizeof(m_libspdm_hkdf_sha256_salt),
        m_libspdm_hkdf_sha256_info, sizeof(m_libspdm_hkdf_sha256_info),
        out, sizeof(out)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("[Pass]\n");
    #endif /* LIBSPDM_SM3_256_SUPPORT */

    #if LIBSPDM_SHA384_SUPPORT
    /* HKDF-SHA-384 digest validation. */
    libspdm_my_print("- HKDF-SHA384: ");

    libspdm_my_print("extract... ");
    libspdm_zero_mem(prk_out48, sizeof(prk_out48));
    status = libspdm_hkdf_sha384_extract (
        m_libspdm_hkdf_sha384_ikm, sizeof(m_libspdm_hkdf_sha384_ikm),
        m_libspdm_hkdf_sha384_salt, sizeof(m_libspdm_hkdf_sha384_salt),
        prk_out48, sizeof(prk_out48)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Check value... ");
    if (memcmp(prk_out48, m_libspdm_hkdf_sha384_prk, sizeof(m_libspdm_hkdf_sha384_prk)) != 0) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_zero_mem(out64, sizeof(out64));
    libspdm_my_print("expand... ");
    status = libspdm_hkdf_sha384_expand (
        m_libspdm_hkdf_sha384_prk, sizeof(m_libspdm_hkdf_sha384_prk),
        m_libspdm_hkdf_sha384_info, sizeof(m_libspdm_hkdf_sha384_info),
        out64, sizeof(out64)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Check value... ");
    if (memcmp(out64, m_libspdm_hkdf_sha384_okm, sizeof(m_libspdm_hkdf_sha384_okm)) != 0) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_zero_mem(out64, sizeof(out64));
    libspdm_my_print("extract_and_expand... ");
    status = libspdm_hkdf_sha384_extract_and_expand (
        m_libspdm_hkdf_sha384_ikm, sizeof(m_libspdm_hkdf_sha384_ikm),
        m_libspdm_hkdf_sha384_salt, sizeof(m_libspdm_hkdf_sha384_salt),
        m_libspdm_hkdf_sha384_info, sizeof(m_libspdm_hkdf_sha384_info),
        out64, sizeof(out64)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Check value... ");
    if (memcmp(out64, m_libspdm_hkdf_sha384_okm, sizeof(m_libspdm_hkdf_sha384_okm)) != 0) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("[Pass]\n");
    #endif /* LIBSPDM_SHA384_SUPPORT */
    #endif /* LIBSPDM_SHA256_SUPPORT ||  LIBSPDM_SHA3_256_SUPPORT ... */

    return true;
}
