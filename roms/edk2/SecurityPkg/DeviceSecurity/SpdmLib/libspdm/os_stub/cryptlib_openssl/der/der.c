/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * DER (Distinguished Encoding Rules) format Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <openssl/x509.h>
#include <openssl/evp.h>

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
/**
 * Retrieve the RSA Public key from the DER key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * @param[in]  der_data     Pointer to the DER-encoded key data to be retrieved.
 * @param[in]  der_size     size of the DER key data in bytes.
 * @param[out] rsa_context  Pointer to newly generated RSA context which contain the retrieved
 *                          RSA public key component. Use libspdm_rsa_free() function to free the
 *                          resource.
 *
 * If der_data is NULL, then return false.
 * If rsa_context is NULL, then return false.
 *
 * @retval  true   RSA Public key was retrieved successfully.
 * @retval  false  Invalid DER key data.
 *
 **/
bool libspdm_rsa_get_public_key_from_der(const uint8_t *der_data,
                                         size_t der_size,
                                         void **rsa_context)
{
    bool status;
    BIO *der_bio;

    /* Check input parameters.*/

    if (der_data == NULL || rsa_context == NULL || der_size > INT_MAX) {
        return false;
    }

    status = false;

    /* Read DER data.*/

    der_bio = BIO_new(BIO_s_mem());
    if (der_bio == NULL) {
        return status;
    }

    if (BIO_write(der_bio, der_data, (int)der_size) <= 0) {
        goto done;
    }

    /* Retrieve RSA Public key from DER data.*/

    *rsa_context = d2i_RSA_PUBKEY_bio(der_bio, NULL);
    if (*rsa_context != NULL) {
        status = true;
    }

done:

    /* Release Resources.*/

    BIO_free(der_bio);

    return status;
}
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_ECDSA_SUPPORT
/**
 * Retrieve the EC Public key from the DER key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * @param[in]  der_data    Pointer to the DER-encoded key data to be retrieved.
 * @param[in]  der_size    size of the DER key data in bytes.
 * @param[out] ec_context  Pointer to newly generated EC DSA context which contain the retrieved
 *                         EC public key component. Use libspdm_ec_free() function to free the
 *                         resource.
 *
 * If der_data is NULL, then return false.
 * If ec_context is NULL, then return false.
 *
 * @retval  true   EC Public key was retrieved successfully.
 * @retval  false  Invalid DER key data.
 *
 **/
bool libspdm_ec_get_public_key_from_der(const uint8_t *der_data,
                                        size_t der_size,
                                        void **ec_context)
{
    bool status;
    BIO *der_bio;

    /* Check input parameters.*/

    if (der_data == NULL || ec_context == NULL || der_size > INT_MAX) {
        return false;
    }

    status = false;

    /* Read DER data.*/

    der_bio = BIO_new(BIO_s_mem());
    if (der_bio == NULL) {
        return status;
    }

    if (BIO_write(der_bio, der_data, (int)der_size) <= 0) {
        goto done;
    }


    /* Retrieve EC Public key from DER data.*/

    *ec_context = d2i_EC_PUBKEY_bio(der_bio, NULL);
    if (*ec_context != NULL) {
        status = true;
    }

done:

    /* Release Resources.*/

    BIO_free(der_bio);

    return status;
}
#endif /* LIBSPDM_ECDSA_SUPPORT */

#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
/**
 * Retrieve the Ed Public key from the DER key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * @param[in]  der_data     Pointer to the DER-encoded key data to be retrieved.
 * @param[in]  der_size     size of the DER key data in bytes.
 * @param[out] ecd_context  Pointer to newly generated Ed DSA context which contain the retrieved
 *                          Ed public key component. Use libspdm_ecd_free() function to free the
 *                          resource.
 *
 * If der_data is NULL, then return false.
 * If ecd_context is NULL, then return false.
 *
 * @retval  true   Ed Public key was retrieved successfully.
 * @retval  false  Invalid DER key data.
 *
 **/
bool libspdm_ecd_get_public_key_from_der(const uint8_t *der_data,
                                         size_t der_size,
                                         void **ecd_context)
{
    bool status;
    BIO *der_bio;
    EVP_PKEY *pkey;
    int32_t type;

    /* Check input parameters.*/

    if (der_data == NULL || ecd_context == NULL || der_size > INT_MAX) {
        return false;
    }

    status = false;

    /* Read DER data.*/

    der_bio = BIO_new(BIO_s_mem());
    if (der_bio == NULL) {
        return status;
    }

    if (BIO_write(der_bio, der_data, (int)der_size) <= 0) {
        goto done;
    }


    /* Retrieve Ed Public key from DER data.*/

    pkey = d2i_PUBKEY_bio(der_bio, NULL);
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

    BIO_free(der_bio);

    return status;
}
#endif /* (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT) */

#if LIBSPDM_SM2_DSA_SUPPORT
/**
 * Retrieve the sm2 Public key from the DER key data.
 *
 * The public key is ASN.1 DER-encoded as RFC7250 describes,
 * namely, the SubjectPublicKeyInfo structure of a X.509 certificate.
 *
 * @param[in]  der_data     Pointer to the DER-encoded key data to be retrieved.
 * @param[in]  der_size     size of the DER key data in bytes.
 * @param[out] sm2_context  Pointer to newly generated sm2 context which contain the retrieved
 *                          sm2 public key component. Use sm2_free() function to free the
 *                          resource.
 *
 * If der_data is NULL, then return false.
 * If sm2_context is NULL, then return false.
 *
 * @retval  true   sm2 Public key was retrieved successfully.
 * @retval  false  Invalid DER key data.
 *
 **/
bool libspdm_sm2_get_public_key_from_der(const uint8_t *der_data,
                                         size_t der_size,
                                         void **sm2_context)
{
    bool status;
    BIO *der_bio;
    EVP_PKEY *pkey;
    int result;

    /* Check input parameters.*/

    if (der_data == NULL || sm2_context == NULL || der_size > INT_MAX) {
        return false;
    }

    status = false;

    /* Read DER data.*/

    der_bio = BIO_new(BIO_s_mem());
    if (der_bio == NULL) {
        return status;
    }

    if (BIO_write(der_bio, der_data, (int)der_size) <= 0) {
        goto done;
    }

    /* Retrieve sm2 Public key from DER data.*/

    pkey = d2i_PUBKEY_bio(der_bio, NULL);
    if (pkey == NULL) {
        goto done;
    }
    result = EVP_PKEY_is_a(pkey,"SM2");
    if (result == 0) {
        goto done;
    }

    *sm2_context = pkey;
    status = true;

done:

    /* Release Resources.*/

    BIO_free(der_bio);

    return status;
}
#endif /* LIBSPDM_SM2_DSA_SUPPORT */
