/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

#if (LIBSPDM_ECDHE_SUPPORT) && (LIBSPDM_ECDSA_SUPPORT)

/*ecp256 key: https://lapo.it/asn1js/#MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjqRWI_stNQKCZwHIIL9pQLqos_cTSZ2Q3L5XaPaE-hGhRANCAAR-X9hTLdaMSJxS9gNglcAxjLCocVJ5I6msv8D7iLloQfRC_RsnQFl5UkTDAKfkavduNdy0AM2VR4XMmD6I9E1D*/
uint8_t m_libspdm_ec_public_key[] = {
    0x7E, 0x5F, 0xD8, 0x53, 0x2D, 0xD6, 0x8C, 0x48, 0x9C, 0x52, 0xF6, 0x03, 0x60, 0x95, 0xC0, 0x31,
    0x8C, 0xB0, 0xA8, 0x71, 0x52, 0x79, 0x23, 0xA9, 0xAC, 0xBF, 0xC0, 0xFB, 0x88, 0xB9, 0x68, 0x41,
    0xF4, 0x42, 0xFD, 0x1B, 0x27, 0x40, 0x59, 0x79, 0x52, 0x44, 0xC3, 0x00, 0xA7, 0xE4, 0x6A, 0xF7,
    0x6E, 0x35, 0xDC, 0xB4, 0x00, 0xCD, 0x95, 0x47, 0x85, 0xCC, 0x98, 0x3E, 0x88, 0xF4, 0x4D, 0x43,
};

uint8_t m_libspdm_ec_private_key[] = {
    0x8E, 0xA4, 0x56, 0x23, 0xFB, 0x2D, 0x35, 0x02, 0x82, 0x67, 0x01, 0xC8, 0x20, 0xBF, 0x69, 0x40,
    0xBA, 0xA8, 0xB3, 0xF7, 0x13, 0x49, 0x9D, 0x90, 0xDC, 0xBE, 0x57, 0x68, 0xF6, 0x84, 0xFA, 0x11,
};

/**
 * Validate Crypto EC Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_ec(void)
{
    void *ec1;
    void *ec2;
    uint8_t public1[66 * 2];
    size_t public1_length;
    uint8_t public2[66 * 2];
    size_t public2_length;
    uint8_t key1[66];
    size_t key1_length;
    uint8_t key2[66];
    size_t key2_length;
    uint8_t hash_value[LIBSPDM_SHA256_DIGEST_SIZE];
    size_t hash_size;
    uint8_t signature[66 * 2];
    size_t sig_size;
    bool status;

    libspdm_my_print("\nCrypto EC-DH key Exchange Testing:\n");

    /* Initialize key length*/
    public1_length = sizeof(public1);
    public2_length = sizeof(public2);
    key1_length = sizeof(key1);
    key2_length = sizeof(key2);

    /* Generate & Initialize EC context*/
    libspdm_my_print("- Context1 ... ");
    ec1 = libspdm_ec_new_by_nid(LIBSPDM_CRYPTO_NID_SECP384R1);
    if (ec1 == NULL) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Context2 ... ");
    ec2 = libspdm_ec_new_by_nid(LIBSPDM_CRYPTO_NID_SECP384R1);
    if (ec2 == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        return false;
    }

    /* Verify EC-DH */
    libspdm_my_print("Generate key1 ... ");
    status = libspdm_ec_generate_key(ec1, public1, &public1_length);
    if (!status || public1_length != 48 * 2) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    libspdm_my_print("Generate key2 ... ");
    status = libspdm_ec_generate_key(ec2, public2, &public2_length);
    if (!status || public2_length != 48 * 2) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    libspdm_my_print("Compute key1 ... ");
    status = libspdm_ec_compute_key(ec1, public2, public2_length, key1,
                                    &key1_length);
    if (!status || key1_length != 48) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    libspdm_my_print("Compute key2 ... ");
    status = libspdm_ec_compute_key(ec2, public1, public1_length, key2,
                                    &key2_length);
    if (!status || key2_length != 48) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    libspdm_my_print("Compare Keys ... ");
    if (key1_length != key2_length) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    if (memcmp(key1, key2, key1_length) != 0) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    libspdm_ec_free(ec1);
    libspdm_ec_free(ec2);

    /* Initialize key length*/
    public1_length = sizeof(public1);
    public2_length = sizeof(public2);
    key1_length = sizeof(key1);
    key2_length = sizeof(key2);

    /* Generate & Initialize EC context*/
    libspdm_my_print("- Context1 ... ");
    ec1 = libspdm_ec_new_by_nid(LIBSPDM_CRYPTO_NID_SECP521R1);
    if (ec1 == NULL) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Context2 ... ");
    ec2 = libspdm_ec_new_by_nid(LIBSPDM_CRYPTO_NID_SECP521R1);
    if (ec2 == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        return false;
    }

    /* Verify EC-DH*/
    libspdm_my_print("Generate key1 ... ");
    status = libspdm_ec_generate_key(ec1, public1, &public1_length);
    if (!status || public1_length != 66 * 2) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    libspdm_my_print("Generate key2 ... ");
    status = libspdm_ec_generate_key(ec2, public2, &public2_length);
    if (!status || public2_length != 66 * 2) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    libspdm_my_print("Compute key1 ... ");
    status = libspdm_ec_compute_key(ec1, public2, public2_length, key1,
                                    &key1_length);
    if (!status || key1_length != 66) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    libspdm_my_print("Compute key2 ... ");
    status = libspdm_ec_compute_key(ec2, public1, public1_length, key2,
                                    &key2_length);
    if (!status || key2_length != 66) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    libspdm_my_print("Compare Keys ... ");
    if (key1_length != key2_length) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    if (memcmp(key1, key2, key1_length) != 0) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    libspdm_ec_free(ec1);
    libspdm_ec_free(ec2);

    libspdm_my_print("\nCrypto EC-DSA Signing Verification Testing:\n");

    public1_length = sizeof(public1);
    public2_length = sizeof(public2);

    libspdm_my_print("- Context1 ... ");
    ec1 = libspdm_ec_new_by_nid(LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256);
    if (ec1 == NULL) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Context2 ... ");
    ec2 = libspdm_ec_new_by_nid(LIBSPDM_CRYPTO_NID_ECDSA_NIST_P521);
    if (ec2 == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        return false;
    }

    libspdm_my_print("Compute key1 ... ");
    status = libspdm_ec_generate_key(ec1, public1, &public1_length);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    libspdm_my_print("Compute key2 ... ");
    status = libspdm_ec_generate_key(ec2, public2, &public2_length);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    /* Verify EC-DSA */
    hash_size = sizeof(hash_value);
    sig_size = sizeof(signature);
    libspdm_my_print("\n- EC-DSA Signing ... ");
    status = libspdm_ecdsa_sign(ec1, LIBSPDM_CRYPTO_NID_SHA256, hash_value, hash_size,
                                signature, &sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    libspdm_my_print("EC-DSA Verification ... ");
    status = libspdm_ecdsa_verify(ec1, LIBSPDM_CRYPTO_NID_SHA256, hash_value, hash_size,
                                  signature, sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    hash_size = sizeof(hash_value);
    sig_size = sizeof(signature);
    libspdm_my_print("- EC-DSA Signing ... ");
    status = libspdm_ecdsa_sign(ec2, LIBSPDM_CRYPTO_NID_SHA256, hash_value, hash_size,
                                signature, &sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    libspdm_my_print("EC-DSA Verification ... ");
    status = libspdm_ecdsa_verify(ec2, LIBSPDM_CRYPTO_NID_SHA256, hash_value, hash_size,
                                  signature, sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    libspdm_ec_free(ec1);
    libspdm_ec_free(ec2);

    libspdm_my_print(
        "\nCrypto EC-DSA Signing Verification Testing with SetPubKey:\n");

    public1_length = sizeof(public1);
    public2_length = sizeof(public2);

    libspdm_my_print("- Context1 ... ");
    ec1 = libspdm_ec_new_by_nid(LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256);
    if (ec1 == NULL) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Context2 ... ");
    ec2 = libspdm_ec_new_by_nid(LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256);
    if (ec2 == NULL) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        return false;
    }

    libspdm_my_print("Compute key in Context1 ... ");
    status = libspdm_ec_generate_key(ec1, public1, &public1_length);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    libspdm_my_print("Export key in Context1 ... ");
    status = libspdm_ec_get_pub_key(ec1, public2, &public2_length);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    libspdm_my_print("Import key in Context2 ... ");
    status = libspdm_ec_set_pub_key(ec2, public2, public2_length);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    /* Verify EC-DSA*/
    hash_size = sizeof(hash_value);
    sig_size = sizeof(signature);
    libspdm_my_print("\n- EC-DSA Signing in Context1 ... ");
    status = libspdm_ecdsa_sign(ec1, LIBSPDM_CRYPTO_NID_SHA256, hash_value, hash_size,
                                signature, &sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    }

    libspdm_my_print("EC-DSA Verification in Context2 ... ");
    status = libspdm_ecdsa_verify(ec2, LIBSPDM_CRYPTO_NID_SHA256, hash_value, hash_size,
                                  signature, sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        libspdm_ec_free(ec2);
        return false;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    libspdm_ec_free(ec1);
    libspdm_ec_free(ec2);

    libspdm_my_print("\nSet public and private key Testing:\n");
    libspdm_my_print("- Context1 ... ");
    ec1 = libspdm_ec_new_by_nid(LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256);
    if (ec1 == NULL) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Import public key in Context1 ... ");
    status = libspdm_ec_set_pub_key(ec1, m_libspdm_ec_public_key, sizeof(m_libspdm_ec_public_key));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        return false;
    }

    libspdm_my_print("Import private key in Context1 ... ");
    status =
        libspdm_ec_set_priv_key(ec1, m_libspdm_ec_private_key, sizeof(m_libspdm_ec_private_key));
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        return false;
    }

    /* Use the set key to verify EC-DSA */
    hash_size = sizeof(hash_value);
    sig_size = sizeof(signature);
    libspdm_my_print("\n- EC-DSA Signing in Context1 ... ");
    status = libspdm_ecdsa_sign(ec1, LIBSPDM_CRYPTO_NID_SHA256, hash_value, hash_size,
                                signature, &sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        return false;
    }

    libspdm_my_print("EC-DSA Verification in Context1 ... ");
    status = libspdm_ecdsa_verify(ec1, LIBSPDM_CRYPTO_NID_SHA256, hash_value, hash_size,
                                  signature, sig_size);
    if (!status) {
        libspdm_my_print("[Fail]");
        libspdm_ec_free(ec1);
        return false;
    } else {
        libspdm_my_print("[Pass]\n");
    }

    libspdm_ec_free(ec1);

    return true;
}
#endif /* (LIBSPDM_ECDHE_SUPPORT) && (LIBSPDM_ECDSA_SUPPORT) */
