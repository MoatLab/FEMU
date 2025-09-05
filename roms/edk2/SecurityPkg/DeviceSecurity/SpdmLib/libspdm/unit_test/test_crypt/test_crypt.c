/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

size_t libspdm_ascii_str_len(const char *string)
{
    size_t length;

    LIBSPDM_ASSERT(string != NULL);
    if (string == NULL) {
        return 0;
    }

    for (length = 0; *string != '\0'; string++, length++) {
        ;
    }
    return length;
}

void libspdm_my_print(const char *message)
{
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "%s", message));
}

/**
 * entrypoint of Cryptographic Validation Utility.
 **/
bool libspdm_cryptest_main(void)
{
    bool status;

    libspdm_my_print("\nCrypto Wrapper Cryptosystem Testing: \n");
    libspdm_my_print("-------------------------------------------- \n");

    status = libspdm_validate_crypt_digest();
    if (!status) {
        return status;
    }

    status = libspdm_validate_crypt_hmac();
    if (!status) {
        return status;
    }

    status = libspdm_validate_crypt_hkdf();
    if (!status) {
        return status;
    }

#if (LIBSPDM_AEAD_GCM_SUPPORT) || (LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT) || \
    (LIBSPDM_AEAD_SM4_SUPPORT)
    status = libspdm_validate_crypt_aead_cipher();
    if (!status) {
        return status;
    }
#endif

    #if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
    status = libspdm_validate_crypt_rsa();
    if (!status) {
        return status;
    }
    #endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

    #if LIBSPDM_RSA_SSA_SUPPORT
    status = libspdm_validate_crypt_rsa_2();
    if (!status) {
        return status;
    }
    #endif /* LIBSPDM_RSA_SSA_SUPPORT */

    status = libspdm_validate_crypt_x509("ecp256", sizeof("ecp256"));
    if (!status) {
        return status;
    }

    status = libspdm_validate_crypt_x509("ecp384", sizeof("ecp384"));
    if (!status) {
        return status;
    }

    status = libspdm_validate_crypt_x509("rsa2048", sizeof("rsa2048"));
    if (!status) {
        return status;
    }

    status = libspdm_validate_crypt_x509("rsa3072", sizeof("rsa3072"));
    if (!status) {
        return status;
    }

    #if LIBSPDM_FFDHE_SUPPORT
    status = libspdm_validate_crypt_dh();
    if (!status) {
        return status;
    }
    #endif /* LIBSPDM_FFDHE_SUPPORT */

    #if (LIBSPDM_ECDHE_SUPPORT) && (LIBSPDM_ECDSA_SUPPORT)
    status = libspdm_validate_crypt_ec();
    if (!status) {
        return status;
    }

    status = libspdm_validate_crypt_ec_2();
    if (!status) {
        return status;
    }
    #endif /* (LIBSPDM_ECDHE_SUPPORT) && (LIBSPDM_ECDSA_SUPPORT) */

    #if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
    status = libspdm_validate_crypt_ecd();
    if (!status) {
        return status;
    }

    status = libspdm_validate_crypt_ecd_2();
    if (!status) {
        return status;
    }
    #endif /* (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT) */

    #if (LIBSPDM_SM2_DSA_SUPPORT) || (LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT)
    status = libspdm_validate_crypt_sm2();
    if (!status) {
        return status;
    }
    #endif /* (LIBSPDM_SM2_DSA_SUPPORT) || (LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT) */

    #if LIBSPDM_SM2_DSA_SUPPORT
    status = libspdm_validate_crypt_sm2_2();
    if (!status) {
        return status;
    }
    #endif /* LIBSPDM_SM2_DSA_SUPPORT */

    status = libspdm_validate_crypt_prng();
    if (!status) {
        return status;
    }

    return status;
}

int main(void)
{
    int return_value = 0;

    if (!libspdm_cryptest_main()) {
        return_value = 1;
    }

    return return_value;
}
