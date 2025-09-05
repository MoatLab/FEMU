/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

/* Max known digest size is SHA-512 output (64 bytes). */
#define MAX_DIGEST_SIZE (LIBSPDM_SHA512_DIGEST_SIZE)

/* Data string for HMAC validation. */
const char *m_libspdm_hmac_data = "Hi There";

/* Key value for HMAC-SHA-256 validation. (from "4. Test Vectors" of IETF RFC4231) */
uint8_t m_libspdm_hmac_sha256_key[20] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

/* Result for HMAC-SHA-256 ("Hi There"). (from "4. Test Vectors" of IETF RFC4231) */
uint8_t m_libspdm_hmac_sha256_digest[] = {
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
    0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
    0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
};

/**
 * Validate message authentication code interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 **/
bool libspdm_validate_crypt_hmac(void)
{
    #if (LIBSPDM_SHA256_SUPPORT) || (LIBSPDM_SHA3_256_SUPPORT) || \
    (LIBSPDM_SM3_256_SUPPORT)
    void *hmac_ctx;
    uint8_t digest[MAX_DIGEST_SIZE];
    bool status;

    libspdm_my_print(" \nCrypto HMAC Engine Testing:\n");
    #endif /* (LIBSPDM_SHA256_SUPPORT) || (LIBSPDM_SHA3_256_SUPPORT) || (LIBSPDM_SM3_256_SUPPORT) */

    #if LIBSPDM_SHA256_SUPPORT
    /* HMAC-SHA-256 validation. */
    libspdm_my_print("- HMAC-SHA-256: ");

    libspdm_zero_mem(digest, MAX_DIGEST_SIZE);
    hmac_ctx = libspdm_hmac_sha256_new();
    if (hmac_ctx == NULL) {
        libspdm_my_print("[Fail]");
        return false;
    }

    status = libspdm_hmac_sha256_set_key(hmac_ctx, m_libspdm_hmac_sha256_key, 20);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(hmac_ctx);
        return false;
    }

    libspdm_my_print("Update... ");
    status = libspdm_hmac_sha256_update(hmac_ctx, m_libspdm_hmac_data, 8);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(hmac_ctx);
        return false;
    }

    libspdm_my_print("Finalize... ");
    status = libspdm_hmac_sha256_final(hmac_ctx, digest);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(hmac_ctx);
        return false;
    }

    free_pool(hmac_ctx);

    libspdm_my_print("Check value... ");
    if (memcmp(digest, m_libspdm_hmac_sha256_digest, LIBSPDM_SHA256_DIGEST_SIZE) != 0) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("[Pass]\n");
    #endif /* LIBSPDM_SHA256_SUPPORT */

    #if LIBSPDM_SHA3_256_SUPPORT
    /* HMAC-SHA3-256 digest Validation*/
    libspdm_my_print("- HMAC-SHA3-256: ");

    libspdm_zero_mem(digest, MAX_DIGEST_SIZE);
    hmac_ctx = libspdm_hmac_sha3_256_new();
    if (hmac_ctx == NULL) {
        libspdm_my_print("[Fail]\n");
        return true;
    }

    status = libspdm_hmac_sha3_256_set_key(hmac_ctx, m_libspdm_hmac_sha256_key, 20);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(hmac_ctx);
        return false;
    }

    libspdm_my_print("Update... ");
    status = libspdm_hmac_sha3_256_update(hmac_ctx, m_libspdm_hmac_data, 8);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(hmac_ctx);
        return false;
    }

    libspdm_my_print("Finalize... ");
    status = libspdm_hmac_sha3_256_final(hmac_ctx, digest);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(hmac_ctx);
        return false;
    }

    free_pool(hmac_ctx);
    libspdm_my_print("[Pass]\n");
    #endif /* LIBSPDM_SHA3_256_SUPPORT */

    #if LIBSPDM_SM3_256_SUPPORT
    /* HMAC-SM3-256 digest Validation*/
    libspdm_my_print("- HMAC-SM3-256: ");

    libspdm_zero_mem(digest, MAX_DIGEST_SIZE);
    hmac_ctx = libspdm_hmac_sm3_256_new();
    if (hmac_ctx == NULL) {
        libspdm_my_print("[Fail]\n");
        return false;
    }

    status = libspdm_hmac_sm3_256_set_key(hmac_ctx, m_libspdm_hmac_sha256_key, 20);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(hmac_ctx);
        return false;
    }

    libspdm_my_print("Update... ");
    status = libspdm_hmac_sm3_256_update(hmac_ctx, m_libspdm_hmac_data, 8);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(hmac_ctx);
        return false;
    }

    libspdm_my_print("Finalize... ");
    status = libspdm_hmac_sm3_256_final(hmac_ctx, digest);
    if (!status) {
        libspdm_my_print("[Fail]");
        free_pool(hmac_ctx);
        return false;
    }

    free_pool(hmac_ctx);
    libspdm_my_print("[Pass]\n");
    #endif /* LIBSPDM_SM3_256_SUPPORT */

    return true;
}
