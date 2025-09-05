/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * DER (Distinguished Encoding Rules) format Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>

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
    int ret;
    mbedtls_pk_context pk;
    mbedtls_rsa_context *rsa;

    if (der_data == NULL || rsa_context == NULL || der_size > INT_MAX) {
        return false;
    }

    mbedtls_pk_init(&pk);

    ret = mbedtls_pk_parse_public_key(&pk, der_data, der_size);
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return false;
    }

    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA) {
        mbedtls_pk_free(&pk);
        return false;
    }

    rsa = libspdm_rsa_new();
    if (rsa == NULL) {
        return false;
    }
    ret = mbedtls_rsa_copy(rsa, mbedtls_pk_rsa(pk));
    if (ret != 0) {
        libspdm_rsa_free(rsa);
        mbedtls_pk_free(&pk);
        return false;
    }
    mbedtls_pk_free(&pk);

    *rsa_context = rsa;
    return true;
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
    int ret;
    mbedtls_pk_context pk;
    mbedtls_ecdh_context *ecdh;

    if (der_data == NULL || ec_context == NULL || der_size > INT_MAX) {
        return false;
    }

    mbedtls_pk_init(&pk);

    ret = mbedtls_pk_parse_public_key(&pk, der_data, der_size);
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return false;
    }

    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_ECKEY) {
        mbedtls_pk_free(&pk);
        return false;
    }

    ecdh = allocate_zero_pool(sizeof(mbedtls_ecdh_context));
    if (ecdh == NULL) {
        mbedtls_pk_free(&pk);
        return false;
    }
    mbedtls_ecdh_init(ecdh);

    ret = mbedtls_ecdh_get_params(ecdh, mbedtls_pk_ec(pk),
                                  MBEDTLS_ECDH_OURS);
    if (ret != 0) {
        mbedtls_ecdh_free(ecdh);
        free_pool(ecdh);
        mbedtls_pk_free(&pk);
        return false;
    }
    mbedtls_pk_free(&pk);

    *ec_context = ecdh;
    return true;
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
    return false;
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
    return false;
}
#endif /* LIBSPDM_SM2_DSA_SUPPORT */
