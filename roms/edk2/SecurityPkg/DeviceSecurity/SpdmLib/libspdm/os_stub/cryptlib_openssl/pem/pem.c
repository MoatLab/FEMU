/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * PEM (Privacy Enhanced Mail) format Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <openssl/pem.h>
#include <openssl/evp.h>

static size_t ascii_str_len(const char *string)
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

/**
 * Callback function for password phrase conversion used for retrieving the encrypted PEM.
 *
 * @param[out]  buf      Pointer to the buffer to write the passphrase to.
 * @param[in]   size     Maximum length of the passphrase (i.e. the size of buf).
 * @param[in]   flag     A flag which is set to 0 when reading and 1 when writing.
 * @param[in]   key      key data to be passed to the callback routine.
 *
 * @retval  The number of characters in the passphrase or 0 if an error occurred.
 *
 **/
int PasswordCallback(char *buf, const int size, const int flag, const void *key)
{
    int key_length;

    libspdm_zero_mem((void *)buf, (size_t)size);
    if (key != NULL) {

        /* Duplicate key phrase directly.*/

        key_length = (int)ascii_str_len((char *)key);
        key_length = (key_length > size) ? size : key_length;
        libspdm_copy_mem(buf, size, key, (size_t)key_length);
        return key_length;
    } else {
        return 0;
    }
}

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
/**
 * Retrieve the RSA Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] rsa_context   Pointer to newly generated RSA context which contain the retrieved
 *                         RSA private key component. Use libspdm_rsa_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If rsa_context is NULL, then return false.
 *
 * @retval  true   RSA Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool libspdm_rsa_get_private_key_from_pem(const uint8_t *pem_data,
                                          size_t pem_size,
                                          const char *password,
                                          void **rsa_context)
{
    bool status;
    BIO *pem_bio;

    /* Check input parameters.*/

    if (pem_data == NULL || rsa_context == NULL || pem_size > INT_MAX) {
        return false;
    }

    /* Add possible block-cipher descriptor for PEM data decryption.
     * NOTE: Only support most popular ciphers AES for the encrypted PEM.*/

    if (EVP_add_cipher(EVP_aes_128_cbc()) == 0) {
        return false;
    }
    if (EVP_add_cipher(EVP_aes_192_cbc()) == 0) {
        return false;
    }
    if (EVP_add_cipher(EVP_aes_256_cbc()) == 0) {
        return false;
    }

    status = false;

    /* Read encrypted PEM data.*/

    pem_bio = BIO_new(BIO_s_mem());
    if (pem_bio == NULL) {
        return status;
    }

    if (BIO_write(pem_bio, pem_data, (int)pem_size) <= 0) {
        goto done;
    }

    /* Retrieve RSA Private key from encrypted PEM data.*/

    *rsa_context =
        PEM_read_bio_RSAPrivateKey(pem_bio, NULL,
                                   (pem_password_cb *)&PasswordCallback,
                                   (void *)password);
    if (*rsa_context != NULL) {
        status = true;
    }

done:

    /* Release Resources.*/

    BIO_free(pem_bio);

    return status;
}
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

/**
 * Retrieve the EC Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] ec_context    Pointer to newly generated EC DSA context which contain the retrieved
 *                         EC private key component. Use libspdm_ec_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If ec_context is NULL, then return false.
 *
 * @retval  true   EC Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool libspdm_ec_get_private_key_from_pem(const uint8_t *pem_data, size_t pem_size,
                                         const char *password,
                                         void **ec_context)
{
    bool status;
    BIO *pem_bio;

    /* Check input parameters.*/

    if (pem_data == NULL || ec_context == NULL || pem_size > INT_MAX) {
        return false;
    }

    /* Add possible block-cipher descriptor for PEM data decryption.
     * NOTE: Only support most popular ciphers AES for the encrypted PEM.*/

    if (EVP_add_cipher(EVP_aes_128_cbc()) == 0) {
        return false;
    }
    if (EVP_add_cipher(EVP_aes_192_cbc()) == 0) {
        return false;
    }
    if (EVP_add_cipher(EVP_aes_256_cbc()) == 0) {
        return false;
    }

    status = false;

    /* Read encrypted PEM data.*/

    pem_bio = BIO_new(BIO_s_mem());
    if (pem_bio == NULL) {
        return status;
    }

    if (BIO_write(pem_bio, pem_data, (int)pem_size) <= 0) {
        goto done;
    }


    /* Retrieve EC Private key from encrypted PEM data.*/

    *ec_context =
        PEM_read_bio_ECPrivateKey(pem_bio, NULL,
                                  (pem_password_cb *)&PasswordCallback,
                                  (void *)password);
    if (*ec_context != NULL) {
        status = true;
    }

done:

    /* Release Resources.*/

    BIO_free(pem_bio);

    return status;
}

/**
 * Retrieve the Ed Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] ecd_context    Pointer to newly generated Ed DSA context which contain the retrieved
 *                         Ed private key component. Use libspdm_ecd_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If ecd_context is NULL, then return false.
 *
 * @retval  true   Ed Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool libspdm_ecd_get_private_key_from_pem(const uint8_t *pem_data,
                                          size_t pem_size,
                                          const char *password,
                                          void **ecd_context)
{
    bool status;
    BIO *pem_bio;
    EVP_PKEY *pkey;
    int32_t type;

    /* Check input parameters.*/

    if (pem_data == NULL || ecd_context == NULL || pem_size > INT_MAX) {
        return false;
    }

    /* Add possible block-cipher descriptor for PEM data decryption.
     * NOTE: Only support most popular ciphers AES for the encrypted PEM.*/

    if (EVP_add_cipher(EVP_aes_128_cbc()) == 0) {
        return false;
    }
    if (EVP_add_cipher(EVP_aes_192_cbc()) == 0) {
        return false;
    }
    if (EVP_add_cipher(EVP_aes_256_cbc()) == 0) {
        return false;
    }

    status = false;

    /* Read encrypted PEM data.*/

    pem_bio = BIO_new(BIO_s_mem());
    if (pem_bio == NULL) {
        return status;
    }

    if (BIO_write(pem_bio, pem_data, (int)pem_size) <= 0) {
        goto done;
    }


    /* Retrieve Ed Private key from encrypted PEM data.*/

    pkey = PEM_read_bio_PrivateKey(pem_bio, NULL,
                                   (pem_password_cb *)&PasswordCallback,
                                   (void *)password);
    if (pkey == NULL) {
        goto done;
    }
    type = EVP_PKEY_id(pkey);
    if ((type != EVP_PKEY_ED25519) && (type != EVP_PKEY_ED448)) {
        goto done;
    }
    *ecd_context = pkey;
    status = true;

done:

    /* Release Resources.*/

    BIO_free(pem_bio);

    return status;
}

/**
 * Retrieve the sm2 Private key from the password-protected PEM key data.
 *
 * @param[in]  pem_data      Pointer to the PEM-encoded key data to be retrieved.
 * @param[in]  pem_size      size of the PEM key data in bytes.
 * @param[in]  password     NULL-terminated passphrase used for encrypted PEM key data.
 * @param[out] sm2_context   Pointer to newly generated sm2 context which contain the retrieved
 *                         sm2 private key component. Use sm2_free() function to free the
 *                         resource.
 *
 * If pem_data is NULL, then return false.
 * If sm2_context is NULL, then return false.
 *
 * @retval  true   sm2 Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 *
 **/
bool libspdm_sm2_get_private_key_from_pem(const uint8_t *pem_data,
                                          size_t pem_size,
                                          const char *password,
                                          void **sm2_context)
{
    bool status;
    BIO *pem_bio;
    EVP_PKEY *pkey;
    EC_KEY *ec_key;
    int32_t openssl_nid;

    /* Check input parameters.*/

    if (pem_data == NULL || sm2_context == NULL || pem_size > INT_MAX) {
        return false;
    }

    /* Add possible block-cipher descriptor for PEM data decryption.
     * NOTE: Only support SM4 for the encrypted PEM.*/

    /*if (EVP_add_cipher (EVP_sm4_cbc ()) == 0) {
     *  return false;
     *}*/

    status = false;

    /* Read encrypted PEM data.*/

    pem_bio = BIO_new(BIO_s_mem());
    if (pem_bio == NULL) {
        return status;
    }

    if (BIO_write(pem_bio, pem_data, (int)pem_size) <= 0) {
        goto done;
    }

    /* Retrieve sm2 Private key from encrypted PEM data.*/

    pkey = PEM_read_bio_PrivateKey(pem_bio, NULL,
                                   (pem_password_cb *)&PasswordCallback,
                                   (void *)password);
    if (pkey == NULL) {
        goto done;
    }
    ec_key = (void *)EVP_PKEY_get0_EC_KEY(pkey);
    openssl_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
    if (openssl_nid != NID_sm2) {
        goto done;
    }

    *sm2_context = pkey;
    status = true;

done:

    /* Release Resources.*/

    BIO_free(pem_bio);

    return status;
}
