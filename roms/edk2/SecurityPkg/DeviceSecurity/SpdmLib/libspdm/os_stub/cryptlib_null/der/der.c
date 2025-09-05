/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * DER (Distinguished Encoding Rules) format Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"

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
    LIBSPDM_ASSERT(false);
    return false;
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
    LIBSPDM_ASSERT(false);
    return false;
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
    LIBSPDM_ASSERT(false);
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
    LIBSPDM_ASSERT(false);
    return false;
}
#endif /* LIBSPDM_SM2_DSA_SUPPORT */
