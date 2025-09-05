/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * X.509 Certificate Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"

/**
 * Construct a X509 object from DER-encoded certificate data.
 *
 * If cert is NULL, then return false.
 * If single_x509_cert is NULL, then return false.
 *
 * @param[in]  cert            Pointer to the DER-encoded certificate data.
 * @param[in]  cert_size        The size of certificate data in bytes.
 * @param[out] single_x509_cert  The generated X509 object.
 *
 * @retval     true            The X509 object generation succeeded.
 * @retval     false           The operation failed.
 *
 **/
bool libspdm_x509_construct_certificate(const uint8_t *cert, size_t cert_size,
                                        uint8_t **single_x509_cert)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Construct a X509 stack object from a list of DER-encoded certificate data.
 *
 * If x509_stack is NULL, then return false.
 *
 * @param[in, out]  x509_stack  On input, pointer to an existing or NULL X509 stack object.
 *                            On output, pointer to the X509 stack object with new
 *                            inserted X509 certificate.
 * @param           ...        A list of DER-encoded single certificate data followed
 *                            by certificate size. A NULL terminates the list. The
 *                            pairs are the arguments to libspdm_x509_construct_certificate().
 *
 * @retval     true            The X509 stack construction succeeded.
 * @retval     false           The construction operation failed.
 *
 **/
bool libspdm_x509_construct_certificate_stack(uint8_t **x509_stack, ...)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Release the specified X509 object.
 *
 * If x509_cert is NULL, then return false.
 *
 * @param[in]  x509_cert  Pointer to the X509 object to be released.
 *
 **/
void libspdm_x509_free(void *x509_cert)
{
    LIBSPDM_ASSERT(false);
}

/**
 * Release the specified X509 stack object.
 *
 * If x509_stack is NULL, then return false.
 *
 * @param[in]  x509_stack  Pointer to the X509 stack object to be released.
 *
 **/
void libspdm_x509_stack_free(void *x509_stack)
{
    LIBSPDM_ASSERT(false);
}

/**
 * Retrieve the tag and length of the tag.
 *
 * @param ptr      The position in the ASN.1 data
 * @param end      end of data
 * @param length   The variable that will receive the length
 * @param tag      The expected tag
 *
 * @retval      true   Get tag successful
 * @retval      FALSe  Failed to get tag or tag not match
 **/
bool libspdm_asn1_get_tag(uint8_t **ptr, const uint8_t *end, size_t *length,
                          uint32_t tag)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the subject bytes from one X.509 certificate.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     cert_subject  Pointer to the retrieved certificate subject bytes.
 * @param[in, out] subject_size  The size in bytes of the cert_subject buffer on input,
 *                             and the size of buffer returned cert_subject on output.
 *
 * If cert is NULL, then return false.
 * If subject_size is NULL, then return false.
 *
 * @retval  true   The certificate subject retrieved successfully.
 * @retval  false  Invalid certificate, or the subject_size is too small for the result.
 *                The subject_size will be updated with the required size.
 *
 **/
bool libspdm_x509_get_subject_name(const uint8_t *cert, size_t cert_size,
                                   uint8_t *cert_subject,
                                   size_t *subject_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the common name (CN) string from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     common_name       buffer to contain the retrieved certificate common
 *                                 name string. At most common_name_size bytes will be
 *                                 written and the string will be null terminated. May be
 *                                 NULL in order to determine the size buffer needed.
 * @param[in,out]  common_name_size   The size in bytes of the common_name buffer on input,
 *                                 and the size of buffer returned common_name on output.
 *                                 If common_name is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 *
 * @retval RETURN_SUCCESS           The certificate common_name retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If common_name_size is NULL.
 *                                 If common_name is not NULL and *common_name_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no common_name entry exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 common_name_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool libspdm_x509_get_common_name(const uint8_t *cert, size_t cert_size,
                                  char *common_name,
                                  size_t *common_name_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the organization name (O) string from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     name_buffer       buffer to contain the retrieved certificate organization
 *                                 name string. At most name_buffer_size bytes will be
 *                                 written and the string will be null terminated. May be
 *                                 NULL in order to determine the size buffer needed.
 * @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
 *                                 and the size of buffer returned name on output.
 *                                 If name_buffer is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 *
 * @retval RETURN_SUCCESS           The certificate Organization name retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If name_buffer_size is NULL.
 *                                 If name_buffer is not NULL and *common_name_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no Organization name entry exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 common_name_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool
libspdm_x509_get_organization_name(const uint8_t *cert, size_t cert_size,
                                   char *name_buffer,
                                   size_t *name_buffer_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
/**
 * Retrieve the RSA public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size     size of the X509 certificate in bytes.
 * @param[out] rsa_context   Pointer to newly generated RSA context which contain the retrieved
 *                         RSA public key component. Use libspdm_rsa_free() function to free the
 *                         resource.
 *
 * If cert is NULL, then return false.
 * If rsa_context is NULL, then return false.
 *
 * @retval  true   RSA public key was retrieved successfully.
 * @retval  false  Fail to retrieve RSA public key from X509 certificate.
 *
 **/
bool libspdm_rsa_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                          void **rsa_context)
{
    LIBSPDM_ASSERT(false);
    return false;
}
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

/**
 * Retrieve the EC public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size     size of the X509 certificate in bytes.
 * @param[out] ec_context    Pointer to newly generated EC DSA context which contain the retrieved
 *                         EC public key component. Use libspdm_ec_free() function to free the
 *                         resource.
 *
 * If cert is NULL, then return false.
 * If ec_context is NULL, then return false.
 *
 * @retval  true   EC public key was retrieved successfully.
 * @retval  false  Fail to retrieve EC public key from X509 certificate.
 *
 **/
bool libspdm_ec_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                         void **ec_context)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the Ed public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size     size of the X509 certificate in bytes.
 * @param[out] ecd_context    Pointer to newly generated Ed DSA context which contain the retrieved
 *                         Ed public key component. Use libspdm_ecd_free() function to free the
 *                         resource.
 *
 * If cert is NULL, then return false.
 * If ecd_context is NULL, then return false.
 *
 * @retval  true   Ed public key was retrieved successfully.
 * @retval  false  Fail to retrieve Ed public key from X509 certificate.
 *
 **/
bool libspdm_ecd_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                          void **ecd_context)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the sm2 public key from one DER-encoded X509 certificate.
 *
 * @param[in]  cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]  cert_size     size of the X509 certificate in bytes.
 * @param[out] sm2_context   Pointer to newly generated sm2 context which contain the retrieved
 *                         sm2 public key component. Use sm2_free() function to free the
 *                         resource.
 *
 * If cert is NULL, then return false.
 * If ecd_context is NULL, then return false.
 *
 * @retval  true   sm2 public key was retrieved successfully.
 * @retval  false  Fail to retrieve sm2 public key from X509 certificate.
 *
 **/
bool libspdm_sm2_get_public_key_from_x509(const uint8_t *cert, size_t cert_size,
                                          void **sm2_context)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Verify one X509 certificate was issued by the trusted CA.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate to be verified.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[in]      ca_cert       Pointer to the DER-encoded trusted CA certificate.
 * @param[in]      ca_cert_size   size of the CA Certificate in bytes.
 *
 * If cert is NULL, then return false.
 * If ca_cert is NULL, then return false.
 *
 * @retval  true   The certificate was issued by the trusted CA.
 * @retval  false  Invalid certificate or the certificate was not issued by the given
 *                trusted CA.
 *
 **/
bool libspdm_x509_verify_cert(const uint8_t *cert, size_t cert_size,
                              const uint8_t *ca_cert, size_t ca_cert_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Verify one X509 certificate was issued by the trusted CA.
 *
 * @param[in]      cert_chain         One or more ASN.1 DER-encoded X.509 certificates
 *                                  where the first certificate is signed by the Root
 *                                  Certificate or is the Root Cerificate itself. and
 *                                  subsequent cerificate is signed by the preceding
 *                                  cerificate.
 * @param[in]      cert_chain_length   Total length of the certificate chain, in bytes.
 *
 * @param[in]      root_cert          Trusted Root Certificate buffer
 *
 * @param[in]      root_cert_length    Trusted Root Certificate buffer length
 *
 * @retval  true   All cerificates was issued by the first certificate in X509Certchain.
 * @retval  false  Invalid certificate or the certificate was not issued by the given
 *                trusted CA.
 **/
bool libspdm_x509_verify_cert_chain(const uint8_t *root_cert, size_t root_cert_length,
                                    const uint8_t *cert_chain, size_t cert_chain_length)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Get one X509 certificate from cert_chain.
 *
 * @param[in]      cert_chain         One or more ASN.1 DER-encoded X.509 certificates
 *                                  where the first certificate is signed by the Root
 *                                  Certificate or is the Root Cerificate itself. and
 *                                  subsequent cerificate is signed by the preceding
 *                                  cerificate.
 * @param[in]      cert_chain_length   Total length of the certificate chain, in bytes.
 *
 * @param[in]      cert_index         index of certificate.
 *
 * @param[out]     cert              The certificate at the index of cert_chain.
 * @param[out]     cert_length        The length certificate at the index of cert_chain.
 *
 * @retval  true   Success.
 * @retval  false  Failed to get certificate from certificate chain.
 **/
bool libspdm_x509_get_cert_from_cert_chain(const uint8_t *cert_chain,
                                           size_t cert_chain_length,
                                           const int32_t cert_index, const uint8_t **cert,
                                           size_t *cert_length)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the TBSCertificate from one given X.509 certificate.
 *
 * @param[in]      cert         Pointer to the given DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     tbs_cert      DER-Encoded to-Be-Signed certificate.
 * @param[out]     tbs_cert_size  size of the TBS certificate in bytes.
 *
 * If cert is NULL, then return false.
 * If tbs_cert is NULL, then return false.
 * If tbs_cert_size is NULL, then return false.
 *
 * @retval  true   The TBSCertificate was retrieved successfully.
 * @retval  false  Invalid X.509 certificate.
 *
 **/
bool libspdm_x509_get_tbs_cert(const uint8_t *cert, size_t cert_size,
                               uint8_t **tbs_cert, size_t *tbs_cert_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the version from one X.509 certificate.
 *
 * If cert is NULL, then return false.
 * If cert_size is 0, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     version      Pointer to the retrieved version integer.
 *
 * @retval RETURN_SUCCESS           The certificate version retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If  cert is NULL or cert_size is Zero.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool libspdm_x509_get_version(const uint8_t *cert, size_t cert_size,
                              size_t *version)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the serialNumber from one X.509 certificate.
 *
 * If cert is NULL, then return false.
 * If cert_size is 0, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     serial_number  Pointer to the retrieved certificate serial_number bytes.
 * @param[in, out] serial_number_size  The size in bytes of the serial_number buffer on input,
 *                             and the size of buffer returned serial_number on output.
 *
 * @retval RETURN_SUCCESS           The certificate serialNumber retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL or cert_size is Zero.
 *                                 If serial_number_size is NULL.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no serial_number exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the serial_number is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 serial_number_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 **/
bool libspdm_x509_get_serial_number(const uint8_t *cert, size_t cert_size,
                                    uint8_t *serial_number,
                                    size_t *serial_number_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the issuer bytes from one X.509 certificate.
 *
 * If cert is NULL, then return false.
 * If issuer_size is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     cert_issuer  Pointer to the retrieved certificate subject bytes.
 * @param[in, out] issuer_size  The size in bytes of the cert_issuer buffer on input,
 *                             and the size of buffer returned cert_issuer on output.
 *
 * @retval  true   The certificate issuer retrieved successfully.
 * @retval  false  Invalid certificate, or the issuer_size is too small for the result.
 *                The issuer_size will be updated with the required size.
 * @retval  false  This interface is not supported.
 *
 **/
bool libspdm_x509_get_issuer_name(const uint8_t *cert, size_t cert_size,
                                  uint8_t *cert_issuer,
                                  size_t *issuer_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the issuer common name (CN) string from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     common_name       buffer to contain the retrieved certificate issuer common
 *                                 name string. At most common_name_size bytes will be
 *                                 written and the string will be null terminated. May be
 *                                 NULL in order to determine the size buffer needed.
 * @param[in,out]  common_name_size   The size in bytes of the common_name buffer on input,
 *                                 and the size of buffer returned common_name on output.
 *                                 If common_name is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 *
 * @retval RETURN_SUCCESS           The certificate Issuer common_name retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If common_name_size is NULL.
 *                                 If common_name is not NULL and *common_name_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no common_name entry exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 common_name_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool
libspdm_x509_get_issuer_common_name(const uint8_t *cert, size_t cert_size,
                                    char *common_name,
                                    size_t *common_name_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the issuer organization name (O) string from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     name_buffer       buffer to contain the retrieved certificate issuer organization
 *                                 name string. At most name_buffer_size bytes will be
 *                                 written and the string will be null terminated. May be
 *                                 NULL in order to determine the size buffer needed.
 * @param[in,out]  name_buffer_size   The size in bytes of the name buffer on input,
 *                                 and the size of buffer returned name on output.
 *                                 If name_buffer is NULL then the amount of space needed
 *                                 in buffer (including the final null) is returned.
 *
 * @retval RETURN_SUCCESS           The certificate issuer Organization name retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If name_buffer_size is NULL.
 *                                 If name_buffer is not NULL and *common_name_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no Organization name entry exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the name_buffer is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 common_name_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool
libspdm_x509_get_issuer_orgnization_name(const uint8_t *cert, size_t cert_size,
                                         char *name_buffer,
                                         size_t *name_buffer_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the signature algorithm from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     oid              signature algorithm Object identifier buffer.
 * @param[in,out]  oid_size          signature algorithm Object identifier buffer size
 *
 * @retval RETURN_SUCCESS           The certificate Extension data retrieved successfully.
 * @retval RETURN_INVALID_PARAMETER If cert is NULL.
 *                                 If oid_size is NULL.
 *                                 If oid is not NULL and *oid_size is 0.
 *                                 If Certificate is invalid.
 * @retval RETURN_NOT_FOUND         If no SignatureType.
 * @retval RETURN_BUFFER_TOO_SMALL  If the oid is NULL. The required buffer size
 *                                 is returned in the oid_size.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 **/
bool libspdm_x509_get_signature_algorithm(const uint8_t *cert,
                                          size_t cert_size, uint8_t *oid,
                                          size_t *oid_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve Extension data from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[in]      oid              Object identifier buffer
 * @param[in]      oid_size          Object identifier buffer size
 * @param[out]     extension_data    Extension bytes.
 * @param[in, out] extension_data_size Extension bytes size.
 *
 * @retval true   If the returned extension_data_size == 0, it means that cert and oid are valid, but the oid extension is not found;
 *                If the returned extension_data_size != 0, it means that cert and oid are valid, and the oid extension is found;
 * @retval false  If the returned extension_data_size == 0, it means that cert or oid are invalid;
 *                If the returned extension_data_size != 0, it means that cert and oid are valid, and the oid extension is found,
 *                                                          but the store buffer is too small.
 **/
bool libspdm_x509_get_extension_data(const uint8_t *cert, size_t cert_size,
                                     const uint8_t *oid, size_t oid_size,
                                     uint8_t *extension_data,
                                     size_t *extension_data_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the Validity from one X.509 certificate
 *
 * If cert is NULL, then return false.
 * If CertIssuerSize is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      cert         Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size     size of the X509 certificate in bytes.
 * @param[out]     from         notBefore Pointer to date_time object.
 * @param[in,out]  from_size     notBefore date_time object size.
 * @param[out]     to           notAfter Pointer to date_time object.
 * @param[in,out]  to_size       notAfter date_time object size.
 *
 * Note: libspdm_x509_compare_date_time to compare date_time oject
 *      x509SetDateTime to get a date_time object from a date_time_str
 *
 * @retval  true   The certificate Validity retrieved successfully.
 * @retval  false  Invalid certificate, or Validity retrieve failed.
 * @retval  false  This interface is not supported.
 **/
bool libspdm_x509_get_validity(const uint8_t *cert, size_t cert_size,
                               uint8_t *from, size_t *from_size, uint8_t *to,
                               size_t *to_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the key usage from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     usage            key usage (LIBSPDM_CRYPTO_X509_KU_*)
 *
 * @retval  true   The certificate key usage retrieved successfully.
 * @retval  false  Invalid certificate, or usage is NULL
 * @retval  false  This interface is not supported.
 **/
bool libspdm_x509_get_key_usage(const uint8_t *cert, size_t cert_size,
                                size_t *usage)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the Extended key usage from one X.509 certificate.
 *
 * @param[in]      cert             Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size         size of the X509 certificate in bytes.
 * @param[out]     usage            key usage bytes.
 * @param[in, out] usage_size        key usage buffer sizs in bytes.
 *
 * @retval true   If the returned usage_size == 0, it means that cert and oid are valid, but the Extended key usage is not found;
 *                If the returned usage_size != 0, it means that cert and oid are valid, and the Extended key usage is found;
 * @retval false  If the returned usage_size == 0, it means that cert or oid are invalid;
 *                If the returned usage_size != 0, it means that cert and oid are valid, and the Extended key usage is found,
 *                                                 but the store buffer is too small.
 **/
bool libspdm_x509_get_extended_key_usage(const uint8_t *cert,
                                         size_t cert_size, uint8_t *usage,
                                         size_t *usage_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Retrieve the basic constraints from one X.509 certificate.
 *
 * @param[in]      cert                     Pointer to the DER-encoded X509 certificate.
 * @param[in]      cert_size                size of the X509 certificate in bytes.
 * @param[out]     basic_constraints        basic constraints bytes.
 * @param[in, out] basic_constraints_size   basic constraints buffer sizs in bytes.
 *
 * @retval true   If the returned basic_constraints_size == 0, it means that cert and oid are valid, but the basic_constraints is not found;
 *                If the returned basic_constraints_size != 0, it means that cert and oid are valid, and the basic_constraints is found;
 * @retval false  If the returned basic_constraints_size == 0, it means that cert or oid are invalid;
 *                If the returned basic_constraints_size != 0, it means that cert and oid are valid, and the basic_constraints is found,
 *                                                             but the store buffer is too small.
 **/
bool libspdm_x509_get_extended_basic_constraints(const uint8_t *cert,
                                                 size_t cert_size,
                                                 uint8_t *basic_constraints,
                                                 size_t *basic_constraints_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * format a date_time object into DataTime buffer
 *
 * If date_time_str is NULL, then return false.
 * If date_time_size is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      date_time_str      date_time string like YYYYMMDDhhmmssZ
 *                                 Ref: https://www.w3.org/TR/NOTE-datetime
 *                                 Z stand for UTC time
 * @param[out]     date_time         Pointer to a date_time object.
 * @param[in,out]  date_time_size     date_time object buffer size.
 *
 * @retval RETURN_SUCCESS           The date_time object create successfully.
 * @retval RETURN_INVALID_PARAMETER If date_time_str is NULL.
 *                                 If date_time_size is NULL.
 *                                 If date_time is not NULL and *date_time_size is 0.
 *                                 If year month day hour minute second combination is invalid datetime.
 * @retval RETURN_BUFFER_TOO_SMALL  If the date_time is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 date_time_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 **/
bool libspdm_x509_set_date_time(const char *date_time_str, void *date_time, size_t *date_time_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Compare date_time1 object and date_time2 object.
 *
 * If date_time1 is NULL, then return -2.
 * If date_time2 is NULL, then return -2.
 * If date_time1 == date_time2, then return 0
 * If date_time1 > date_time2, then return 1
 * If date_time1 < date_time2, then return -1
 *
 * @param[in]      date_time1         Pointer to a date_time Ojbect
 * @param[in]      date_time2         Pointer to a date_time Object
 *
 * @retval  0      If date_time1 == date_time2
 * @retval  1      If date_time1 > date_time2
 * @retval  -1     If date_time1 < date_time2
 **/
int32_t libspdm_x509_compare_date_time(const void *date_time1, const void *date_time2)
{
    LIBSPDM_ASSERT(false);
    return -3;
}

/**
 * Gen CSR
 *
 * @param[in]      hash_nid              hash algo for sign
 * @param[in]      asym_nid              asym algo for sign
 *
 * @param[in]      requester_info        requester info to gen CSR
 * @param[in]      requester_info_length The len of requester info
 *
 * @param[in]       is_ca                if true, set basic_constraints: CA:true; Otherwise, set to false.
 *
 * @param[in]      context               Pointer to asymmetric context
 * @param[in]      subject_name          Subject name: should be break with ',' in the middle
 *                                       example: "C=AA,CN=BB"
 * Subject names should contain a comma-separated list of OID types and values:
 * The valid OID type name is in:
 * {"CN", "commonName", "C", "countryName", "O", "organizationName","L",
 * "OU", "organizationalUnitName", "ST", "stateOrProvinceName", "emailAddress",
 * "serialNumber", "postalAddress", "postalCode", "dnQualifier", "title",
 * "SN","givenName","GN", "initials", "pseudonym", "generationQualifier", "domainComponent", "DC"}.
 * Note: The object of C and countryName should be CSR Supported Country Codes
 *
 * @param[in, out]      csr_len               For input, csr_len is the size of store CSR buffer.
 *                                            For output, csr_len is CSR len for DER format
 * @param[in, out]      csr_pointer           For input, csr_pointer is buffer address to store CSR.
 *                                            For output, csr_pointer is address for stored CSR.
 *                                            The csr_pointer address will be changed.
 * @param[in]           base_cert             An optional leaf certificate whose
 *                                            extensions should be copied to the CSR
 *
 * @retval  true   Success.
 * @retval  false  Failed to gen CSR.
 **/
bool libspdm_gen_x509_csr(size_t hash_nid, size_t asym_nid,
                          uint8_t *requester_info, size_t requester_info_length,
                          bool is_ca,
                          void *context, char *subject_name,
                          size_t *csr_len, uint8_t *csr_pointer,
                          void *base_cert)
{
    LIBSPDM_ASSERT(false);
    return false;
}
