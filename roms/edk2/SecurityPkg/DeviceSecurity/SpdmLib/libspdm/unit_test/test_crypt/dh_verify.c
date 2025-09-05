/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

#if LIBSPDM_FFDHE_SUPPORT

/**
 * Validate Crypto DH Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_dh(void)
{
    void *dh1;
    void *dh2;
    bool status;
    uint8_t ff_public_key1[256];
    size_t ff_public_key1_length;
    uint8_t ff_public_key2[256];
    size_t ff_public_key2_length;
    uint8_t ff_key1[256];
    size_t ff_key1_length;
    uint8_t ff_key2[256];
    size_t ff_key2_length;

    libspdm_my_print("\nCrypto DH Engine Testing:\n");

    ff_public_key1_length = sizeof(ff_public_key1);
    ff_public_key2_length = sizeof(ff_public_key2);
    ff_key1_length = sizeof(ff_key1);
    ff_key2_length = sizeof(ff_key2);
    libspdm_my_print("- Context1 ... ");
    dh1 = libspdm_dh_new_by_nid(LIBSPDM_CRYPTO_NID_FFDHE2048);
    if (dh1 == NULL) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Context2 ... ");
    dh2 = libspdm_dh_new_by_nid(LIBSPDM_CRYPTO_NID_FFDHE2048);
    if (dh2 == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_dh_free(dh1);
        return false;
    }

    libspdm_my_print("Generate key1 ... ");
    status = libspdm_dh_generate_key(dh1, ff_public_key1, &ff_public_key1_length);
    if (!status || ff_public_key1_length != 256) {
        libspdm_my_print("[Fail]");
        libspdm_dh_free(dh1);
        libspdm_dh_free(dh2);
        return false;
    }

    libspdm_my_print("Generate key2 ... ");
    status = libspdm_dh_generate_key(dh2, ff_public_key2, &ff_public_key2_length);
    if (!status || ff_public_key2_length != 256) {
        libspdm_my_print("[Fail]");
        libspdm_dh_free(dh1);
        libspdm_dh_free(dh2);
        return false;
    }

    libspdm_my_print("Compute key1 ... ");
    status = libspdm_dh_compute_key(dh1, ff_public_key2, ff_public_key2_length,
                                    ff_key1, &ff_key1_length);
    if (!status || ff_key1_length != 256) {
        libspdm_my_print("[Fail]");
        libspdm_dh_free(dh1);
        libspdm_dh_free(dh2);
        return false;
    }

    libspdm_my_print("Compute key2 ... ");
    status = libspdm_dh_compute_key(dh2, ff_public_key1, ff_public_key1_length,
                                    ff_key2, &ff_key2_length);
    if (!status || ff_key2_length != 256) {
        libspdm_my_print("[Fail]");
        libspdm_dh_free(dh1);
        libspdm_dh_free(dh2);
        return false;
    }

    libspdm_my_print("Compare Keys ... ");
    if (ff_key1_length != ff_key2_length) {
        libspdm_my_print("[Fail]");
        libspdm_dh_free(dh1);
        libspdm_dh_free(dh2);
        return false;
    }

    if (memcmp(ff_key1, ff_key2, ff_key1_length) != 0) {
        libspdm_my_print("[Fail]");
        libspdm_dh_free(dh1);
        libspdm_dh_free(dh2);
        return false;
    }

    libspdm_my_print("[Pass]\n");
    libspdm_dh_free(dh1);
    libspdm_dh_free(dh2);

    return true;
}

#endif /* LIBSPDM_FFDHE_SUPPORT */
