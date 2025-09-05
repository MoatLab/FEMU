/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)

/**
 * Validate Crypto Ed Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_ecd(void)
{
    void *ecd1;
    void *ecd2;
    uint8_t message[] = "EdDsaTest";
    uint8_t signature1[32 * 2];
    uint8_t signature2[57 * 2];
    size_t sig1_size;
    size_t sig2_size;
    bool status;

    libspdm_my_print("\nCrypto Ed-DSA Signing Verification Testing:\n");

    libspdm_my_print("- Context1 ... ");
    ecd1 = libspdm_ecd_new_by_nid(LIBSPDM_CRYPTO_NID_EDDSA_ED25519);
    if (ecd1 == NULL) {
        libspdm_my_print("[Fail]");
        return false;
    }

    /* Verify Ed-DSA*/
    sig1_size = sizeof(signature1);
    libspdm_my_print("\n- Ed-DSA Signing ... ");
    status = libspdm_eddsa_sign(ecd1, LIBSPDM_CRYPTO_NID_NULL, NULL, 0, message, sizeof(message),
                                signature1, &sig1_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ecd_free(ecd1);
        return false;
    }

    libspdm_my_print("Ed-DSA Verification ... ");
    status = libspdm_eddsa_verify(ecd1, LIBSPDM_CRYPTO_NID_NULL, NULL, 0, message, sizeof(message),
                                  signature1, sig1_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ecd_free(ecd1);
        return false;
    } else {
        libspdm_my_print("[Pass]\n");
    }
    libspdm_ecd_free(ecd1);

    libspdm_my_print("Context2 ... ");
    ecd2 = libspdm_ecd_new_by_nid(LIBSPDM_CRYPTO_NID_EDDSA_ED448);
    if (ecd2 == NULL) {
        libspdm_my_print("[Fail]");
        return false;
    }

    sig2_size = sizeof(signature2);
    libspdm_my_print("\n- Ed-DSA Signing ... ");
    status = libspdm_eddsa_sign(ecd2, LIBSPDM_CRYPTO_NID_NULL, NULL, 0, message, sizeof(message),
                                signature2, &sig2_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ecd_free(ecd2);
        return false;
    }

    libspdm_my_print("Ed-DSA Verification ... ");
    status = libspdm_eddsa_verify(ecd2, LIBSPDM_CRYPTO_NID_NULL, NULL, 0, message, sizeof(message),
                                  signature2, sig2_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ecd_free(ecd2);
        return false;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    libspdm_ecd_free(ecd2);

    return true;
}

#endif /* (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT) */
