/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * X.509 Certificate Handler Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/rsa.h>

#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#if LIBSPDM_CERT_PARSE_SUPPORT

/*buffer size to store subject object*/
#define MAX_SBUJECT_NAME_LEN 0x100

/*see link:"https://man.openbsd.org/ASN1_get_object.3" */
#define OPENSSL_ASN1_ERROR_MASK 0x80

/* OID*/
#define OID_EXT_KEY_USAGE     { 0x55, 0x1D, 0x25 }
#define OID_BASIC_CONSTRAINTS { 0x55, 0x1D, 0x13 }

static const uint8_t m_libspdm_oid_ext_key_usage[] = OID_EXT_KEY_USAGE;
static const uint8_t m_libspdm_oid_basic_constraints[] = OID_BASIC_CONSTRAINTS;

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
    X509 *x509_cert;
    const uint8_t *temp;


    /* Check input parameters.*/

    if (cert == NULL || single_x509_cert == NULL || cert_size > INT_MAX) {
        return false;
    }


    /* Read DER-encoded X509 Certificate and Construct X509 object.*/

    temp = cert;
    x509_cert = d2i_X509(NULL, &temp, (long)cert_size);
    if (x509_cert == NULL) {
        return false;
    }

    *single_x509_cert = (uint8_t *)x509_cert;

    return true;
}

/**
 * Construct a X509 stack object from a list of DER-encoded certificate data.
 *
 * If x509_stack is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in, out]  x509_stack  On input, pointer to an existing or NULL X509 stack object.
 *                            On output, pointer to the X509 stack object with new
 *                            inserted X509 certificate.
 * @param[in]       args       LIBSPDM_VA_LIST marker for the variable argument list.
 *                            A list of DER-encoded single certificate data followed
 *                            by certificate size. A NULL terminates the list. The
 *                            pairs are the arguments to libspdm_x509_construct_certificate().
 *
 * @retval     true            The X509 stack construction succeeded.
 * @retval     false           The construction operation failed.
 * @retval     false           This interface is not supported.
 *
 **/
bool libspdm_x509_construct_certificate_stack_v(uint8_t **x509_stack,
                                                LIBSPDM_VA_LIST args)
{
    uint8_t *cert;
    size_t cert_size;
    X509 *x509_cert;
    STACK_OF(X509) * cert_stack;
    bool res;

    /* Check input parameters.*/

    if (x509_stack == NULL) {
        return false;
    }

    res = false;


    /* Initialize X509 stack object.*/

    cert_stack = (STACK_OF(X509) *)(*x509_stack);
    if (cert_stack == NULL) {
        cert_stack = sk_X509_new_null();
        if (cert_stack == NULL) {
            return res;
        }
    }

    for (;;) {

        /* If cert is NULL, then it is the end of the list.*/

        cert = LIBSPDM_VA_ARG(args, uint8_t *);
        if (cert == NULL) {
            break;
        }

        cert_size = LIBSPDM_VA_ARG(args, size_t);
        if (cert_size == 0) {
            break;
        }


        /* Construct X509 Object from the given DER-encoded certificate data.*/

        x509_cert = NULL;
        res = libspdm_x509_construct_certificate((const uint8_t *)cert, cert_size,
                                                 (uint8_t **)&x509_cert);
        if (!res) {
            if (x509_cert != NULL) {
                X509_free(x509_cert);
            }
            break;
        }


        /* Insert the new X509 object into X509 stack object.*/

        res = sk_X509_push(cert_stack, x509_cert);
        if (!res) {
            X509_free(x509_cert);
            break;
        }
    }

    if (!res) {
        sk_X509_pop_free(cert_stack, X509_free);
    } else {
        *x509_stack = (uint8_t *)cert_stack;
    }

    return res;
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
    LIBSPDM_VA_LIST args;
    bool result;

    LIBSPDM_VA_START(args, x509_stack);
    result = libspdm_x509_construct_certificate_stack_v(x509_stack, args);
    LIBSPDM_VA_END(args);
    return result;
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

    /* Check input parameters.*/

    if (x509_cert == NULL) {
        return;
    }


    /* Free OpenSSL X509 object.*/

    X509_free((X509 *)x509_cert);
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

    /* Check input parameters.*/

    if (x509_stack == NULL) {
        return;
    }


    /* Free OpenSSL X509 stack object.*/

    sk_X509_pop_free((STACK_OF(X509) *)x509_stack, X509_free);
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
    const uint8_t *ptr_old;
    int32_t obj_tag;
    int32_t obj_class;
    long obj_length;
    int32_t ret;

    /* Save ptr position*/

    ptr_old = *ptr;

    /*when there is no object, return false*/
    if ((*ptr) == end) {
        return false;
    }

    ret = ASN1_get_object((const uint8_t **)ptr, &obj_length, &obj_tag, &obj_class,
                          (int32_t)(end - (*ptr)));
    /* Either a primitive encoding with a valid tag and definite length, but the content octets won't fit into omax, or parsing failed. */
    if (ret & OPENSSL_ASN1_ERROR_MASK) {
        return false;
    }

    if (obj_tag == (int32_t)(tag & LIBSPDM_CRYPTO_ASN1_TAG_VALUE_MASK) &&
        obj_class == (int32_t)(tag & LIBSPDM_CRYPTO_ASN1_TAG_CLASS_MASK)) {
        *length = (size_t)obj_length;
        return true;
    } else {

        /* if doesn't match tag, restore ptr to origin ptr*/

        *ptr = (uint8_t *)ptr_old;
        return false;
    }
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
    bool res;
    X509 *x509_cert;
    X509_NAME *x509_name;
    size_t x509_name_size;


    /* Check input parameters.*/

    if (cert == NULL || subject_size == NULL) {
        return false;
    }

    x509_cert = NULL;


    /* Read DER-encoded X509 Certificate and Construct X509 object.*/

    res = libspdm_x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if ((x509_cert == NULL) || (!res)) {
        res = false;
        goto done;
    }

    res = false;


    /* Retrieve subject name from certificate object.*/

    x509_name = X509_get_subject_name(x509_cert);
    if (x509_name == NULL) {
        goto done;
    }

    x509_name_size = i2d_X509_NAME(x509_name, NULL);
    if (*subject_size < x509_name_size) {
        *subject_size = x509_name_size;
        goto done;
    }
    *subject_size = x509_name_size;
    if (cert_subject != NULL) {
        i2d_X509_NAME(x509_name, &cert_subject);
        res = true;
    }

done:

    /* Release Resources.*/

    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }

    return res;
}

/**
 * Retrieve a string from one X.509 certificate base on the request_nid.
 *
 * @param[in]      x509_name         X509 name
 * @param[in]      request_nid      NID of string to obtain
 * @param[out]     common_name       buffer to contain the retrieved certificate common
 *                                 name string (UTF8). At most common_name_size bytes will be
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
 * @retval RETURN_NOT_FOUND         If no NID name entry exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 common_name_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool
libspdm_internal_x509_get_nid_name(X509_NAME *x509_name, const int32_t request_nid,
                                   char *common_name,
                                   size_t *common_name_size)
{
    bool status;
    int32_t index;
    int length;
    X509_NAME_ENTRY *entry;
    ASN1_STRING *entry_data;
    uint8_t *utf8_name;
    size_t common_name_capacity;

    status = false;
    utf8_name = NULL;


    /* Check input parameters.*/

    if (x509_name == NULL || (common_name_size == NULL)) {
        return false;
    }
    if ((common_name != NULL) && (*common_name_size == 0)) {
        return false;
    }


    /* Retrive the string from X.509 Subject base on the request_nid*/

    index = X509_NAME_get_index_by_NID(x509_name, request_nid, -1);
    if (index < 0) {

        /* No request_nid name entry exists in X509_NAME object*/

        *common_name_size = 0;
        status = false;
        goto done;
    }

    entry = X509_NAME_get_entry(x509_name, index);
    if (entry == NULL) {

        /* Fail to retrieve name entry data*/

        *common_name_size = 0;
        status = false;
        goto done;
    }

    entry_data = X509_NAME_ENTRY_get_data(entry);

    length = ASN1_STRING_to_UTF8(&utf8_name, entry_data);
    if (length < 0) {

        /* Fail to convert the name string*/

        *common_name_size = 0;
        status = false;
        goto done;
    }

    if (common_name == NULL) {
        *common_name_size = length + 1;
        status = false;
    } else {
        common_name_capacity = *common_name_size;
        *common_name_size =
            LIBSPDM_MIN((size_t)length, *common_name_size - 1) + 1;
        libspdm_copy_mem(common_name, common_name_capacity,
                         utf8_name, *common_name_size - 1);
        common_name[*common_name_size - 1] = '\0';
        status = true;
    }

done:

    /* Release Resources.*/

    if (utf8_name != NULL) {
        OPENSSL_free(utf8_name);
    }

    return status;
}

/**
 * Retrieve a string from one X.509 certificate base on the request_nid.
 *
 * @param[in]      x509_name         x509_name Struct
 * @param[in]      request_nid      NID of string to obtain
 * @param[out]     common_name       buffer to contain the retrieved certificate common
 *                                 name string (UTF8). At most common_name_size bytes will be
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
 * @retval RETURN_NOT_FOUND         If no NID name entry exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 common_name_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool
libspdm_internal_x509_get_subject_nid_name(const uint8_t *cert, size_t cert_size,
                                           const int32_t request_nid, char *common_name,
                                           size_t *common_name_size)
{
    bool status;
    X509 *x509_cert;
    X509_NAME *x509_name;

    status = false;
    x509_cert = NULL;

    if (cert == NULL || cert_size == 0) {
        goto done;
    }


    /* Read DER-encoded X509 Certificate and Construct X509 object.*/

    status = libspdm_x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if ((x509_cert == NULL) || (!status)) {

        /* Invalid X.509 Certificate*/

        status = false;
        goto done;
    }

    status = false;


    /* Retrieve subject name from certificate object.*/

    x509_name = X509_get_subject_name(x509_cert);
    if (x509_name == NULL) {

        /* Fail to retrieve subject name content*/

        goto done;
    }

    status = libspdm_internal_x509_get_nid_name(x509_name, request_nid, common_name,
                                                common_name_size);

done:

    /* Release Resources.*/

    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }
    return status;
}

/**
 * Retrieve a string from one X.509 certificate base on the request_nid.
 *
 * @param[in]      x509_name         X509 Struct
 * @param[in]      request_nid      NID of string to obtain
 * @param[out]     common_name       buffer to contain the retrieved certificate common
 *                                 name string (UTF8). At most common_name_size bytes will be
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
 * @retval RETURN_NOT_FOUND         If no NID name entry exists.
 * @retval RETURN_BUFFER_TOO_SMALL  If the common_name is NULL. The required buffer size
 *                                 (including the final null) is returned in the
 *                                 common_name_size parameter.
 * @retval RETURN_UNSUPPORTED       The operation is not supported.
 *
 **/
bool
libspdm_internal_x509_get_issuer_nid_name(const uint8_t *cert, size_t cert_size,
                                          const int32_t request_nid, char *common_name,
                                          size_t *common_name_size)
{
    bool status;
    X509 *x509_cert;
    X509_NAME *x509_name;

    status = false;
    x509_cert = NULL;

    if (cert == NULL || cert_size == 0) {
        goto done;
    }


    /* Read DER-encoded X509 Certificate and Construct X509 object.*/

    status = libspdm_x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if ((x509_cert == NULL) || (!status)) {

        /* Invalid X.509 Certificate*/

        status = false;
        goto done;
    }

    status = false;


    /* Retrieve subject name from certificate object.*/

    x509_name = X509_get_issuer_name(x509_cert);
    if (x509_name == NULL) {

        /* Fail to retrieve subject name content*/

        goto done;
    }

    status = libspdm_internal_x509_get_nid_name(x509_name, request_nid, common_name,
                                                common_name_size);

done:

    /* Release Resources.*/

    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }
    return status;
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
    return libspdm_internal_x509_get_subject_nid_name(
        cert, cert_size, NID_commonName, common_name, common_name_size);
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
    return libspdm_internal_x509_get_subject_nid_name(cert, cert_size,
                                                      NID_organizationName,
                                                      name_buffer,
                                                      name_buffer_size);
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
    bool status;
    X509 *x509_cert;

    x509_cert = NULL;
    status = libspdm_x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if ((x509_cert == NULL) || (!status)) {

        /* Invalid X.509 Certificate*/

        status = false;
    }

    if (status) {
        *version = X509_get_version(x509_cert);
    }

    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }
    return status;
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
    X509 *x509_cert;
    ASN1_INTEGER *asn1_integer;
    bool status;

    status = false;


    /* Check input parameters.*/

    if (cert == NULL || serial_number_size == NULL) {
        return status;
    }

    x509_cert = NULL;


    /* Read DER-encoded X509 Certificate and Construct X509 object.*/

    status = libspdm_x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if ((x509_cert == NULL) || (!status)) {
        *serial_number_size = 0;
        status = false;
        goto done;
    }


    /* Retrieve subject name from certificate object.*/

    asn1_integer = X509_get_serialNumber(x509_cert);
    if (asn1_integer == NULL) {
        *serial_number_size = 0;
        status = false;
        goto done;
    }

    if (*serial_number_size < (size_t)asn1_integer->length) {
        *serial_number_size = (size_t)asn1_integer->length;
        status = false;
        goto done;
    }

    if (serial_number != NULL) {
        libspdm_copy_mem(serial_number, *serial_number_size,
                         asn1_integer->data, (size_t)asn1_integer->length);
        status = true;
    }
    *serial_number_size = (size_t)asn1_integer->length;

done:

    /* Release Resources.*/

    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }

    return status;
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
    bool res;
    X509 *x509_cert;
    X509_NAME *x509_name;
    size_t x509_name_size;


    /* Check input parameters.*/

    if (cert == NULL || issuer_size == NULL) {
        return false;
    }

    x509_cert = NULL;


    /* Read DER-encoded X509 Certificate and Construct X509 object.*/

    res = libspdm_x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if ((x509_cert == NULL) || (!res)) {
        res = false;
        goto done;
    }

    res = false;


    /* Retrieve issuer name from certificate object.*/

    x509_name = X509_get_issuer_name(x509_cert);
    if (x509_name == NULL) {
        goto done;
    }

    x509_name_size = i2d_X509_NAME(x509_name, NULL);
    if (*issuer_size < x509_name_size) {
        *issuer_size = x509_name_size;
        goto done;
    }
    *issuer_size = x509_name_size;
    if (cert_issuer != NULL) {
        i2d_X509_NAME(x509_name, &cert_issuer);
        res = true;
    }

done:

    /* Release Resources.*/

    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }

    return res;
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
    return libspdm_internal_x509_get_issuer_nid_name(
        cert, cert_size, NID_commonName, common_name, common_name_size);
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
    return libspdm_internal_x509_get_issuer_nid_name(cert, cert_size,
                                                     NID_organizationName,
                                                     name_buffer, name_buffer_size);
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
    bool status;
    X509 *x509_cert;
    int nid;
    ASN1_OBJECT *asn1_obj;
    size_t obj_length;


    /* Check input parameters.*/

    if (cert == NULL || oid_size == NULL || cert_size == 0) {
        return false;
    }

    x509_cert = NULL;
    status = false;


    /* Read DER-encoded X509 Certificate and Construct X509 object.*/

    status = libspdm_x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if ((x509_cert == NULL) || (!status)) {
        status = false;
        goto done;
    }


    /* Retrieve subject name from certificate object.*/

    nid = X509_get_signature_nid(x509_cert);
    if (nid == NID_undef) {
        *oid_size = 0;
        status = false;
        goto done;
    }
    asn1_obj = OBJ_nid2obj(nid);
    if (asn1_obj == NULL) {
        *oid_size = 0;
        status = false;
        goto done;
    }

    obj_length = OBJ_length(asn1_obj);
    if (*oid_size < obj_length) {
        *oid_size = obj_length;
        status = false;
        goto done;
    }
    if (oid != NULL) {
        libspdm_copy_mem(oid, *oid_size, OBJ_get0_data(asn1_obj), obj_length);
    }
    *oid_size = obj_length;
    status = true;

done:

    /* Release Resources.*/

    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }

    return status;
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
    bool res;
    X509 *x509_cert;
    const ASN1_TIME *f_time;
    const ASN1_TIME *t_time;
    size_t t_size;
    size_t f_size;


    /* Check input parameters.*/

    if (cert == NULL || from_size == NULL || to_size == NULL ||
        cert_size == 0) {
        return false;
    }

    x509_cert = NULL;
    res = false;


    /* Read DER-encoded X509 Certificate and Construct X509 object.*/

    res = libspdm_x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if ((x509_cert == NULL) || (!res)) {
        goto done;
    }


    /* Retrieve Validity from/to from certificate object.*/

    f_time = X509_get0_notBefore(x509_cert);
    t_time = X509_get0_notAfter(x509_cert);

    if (f_time == NULL || t_time == NULL) {
        goto done;
    }

    f_size = sizeof(ASN1_TIME) + f_time->length;
    if (*from_size < f_size) {
        *from_size = f_size;
        goto done;
    }
    if (from != NULL) {
        libspdm_copy_mem(from, *from_size, f_time, sizeof(ASN1_TIME));
        ((ASN1_TIME *)from)->data = from + sizeof(ASN1_TIME);
        libspdm_copy_mem(from + sizeof(ASN1_TIME),
                         *from_size - sizeof(ASN1_TIME),
                         f_time->data, f_time->length);
    }
    *from_size = f_size;

    t_size = sizeof(ASN1_TIME) + t_time->length;
    if (*to_size < t_size) {
        *to_size = t_size;
        goto done;
    }
    if (to != NULL) {
        libspdm_copy_mem(to, *to_size, t_time, sizeof(ASN1_TIME));
        ((ASN1_TIME *)to)->data = to + sizeof(ASN1_TIME);
        libspdm_copy_mem(to + sizeof(ASN1_TIME),
                         *to_size - sizeof(ASN1_TIME),
                         t_time->data, t_time->length);
    }
    *to_size = t_size;

    res = true;

done:

    /* Release Resources.*/

    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }

    return res;
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
 * @param[in,out]  date_time         Pointer to a date_time object.
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
    bool status;
    int32_t ret;
    ASN1_TIME *dt;
    size_t d_size;

    dt = NULL;
    status = false;

    dt = ASN1_TIME_new();
    if (dt == NULL) {
        status = false;
        goto cleanup;
    }

    ret = ASN1_TIME_set_string_X509(dt, date_time_str);
    if (ret != 1) {
        status = false;
        goto cleanup;
    }

    d_size = sizeof(ASN1_TIME) + dt->length;
    if (*date_time_size < d_size) {
        *date_time_size = d_size;
        status = false;
        goto cleanup;
    }
    if (date_time != NULL) {
        libspdm_copy_mem(date_time, *date_time_size, dt, sizeof(ASN1_TIME));
        ((ASN1_TIME *)date_time)->data =
            (uint8_t *)date_time + sizeof(ASN1_TIME);
        libspdm_copy_mem((uint8_t *)date_time + sizeof(ASN1_TIME),
                         *date_time_size - sizeof(ASN1_TIME),
                         dt->data, dt->length);
    }
    *date_time_size = d_size;
    status = true;

cleanup:
    if (dt != NULL) {
        ASN1_TIME_free(dt);
    }
    return status;
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
    return (int32_t)ASN1_TIME_compare(date_time1, date_time2);
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
    bool res;
    X509 *x509_cert;


    /* Check input parameters.*/

    if (cert == NULL || usage == NULL) {
        return false;
    }

    x509_cert = NULL;
    res = false;


    /* Read DER-encoded X509 Certificate and Construct X509 object.*/

    res = libspdm_x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if ((x509_cert == NULL) || (!res)) {
        goto done;
    }


    /* Retrieve subject name from certificate object.*/

    *usage = X509_get_key_usage(x509_cert);
    if (*usage == NID_undef) {
        goto done;
    }
    res = true;

done:

    /* Release Resources.*/

    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }

    return res;
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
    bool status;
    int i;
    X509 *x509_cert;
    const STACK_OF(X509_EXTENSION) * extensions;
    ASN1_OBJECT *asn1_obj;
    ASN1_OCTET_STRING *asn1_oct;
    X509_EXTENSION *ext;
    size_t obj_length;
    size_t oct_length;

    /* Check input parameters.*/

    if (cert == NULL || cert_size == 0 || oid == NULL || oid_size == 0 ||
        extension_data_size == NULL) {
        if (extension_data_size != NULL) {
            *extension_data_size = 0;
        }
        return false;
    }

    x509_cert = NULL;
    status = false;

    /* Read DER-encoded X509 Certificate and Construct X509 object.*/

    status = libspdm_x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if (!status) {
        *extension_data_size = 0;
        goto cleanup;
    }

    /* Retrieve extensions from certificate object.*/

    extensions = X509_get0_extensions(x509_cert);
    if (sk_X509_EXTENSION_num(extensions) <= 0) {
        *extension_data_size = 0;
        goto cleanup;
    }

    /* Traverse extensions*/

    status = false;
    asn1_oct = NULL;
    oct_length = 0;
    for (i = 0; i < sk_X509_EXTENSION_num(extensions); i++) {
        ext = sk_X509_EXTENSION_value(extensions, (int)i);
        if (ext == NULL) {
            continue;
        }
        asn1_obj = X509_EXTENSION_get_object(ext);
        if (asn1_obj == NULL) {
            continue;
        }
        asn1_oct = X509_EXTENSION_get_data(ext);
        if (asn1_oct == NULL) {
            continue;
        }

        obj_length = OBJ_length(asn1_obj);
        oct_length = ASN1_STRING_length(asn1_oct);

        if ((oid_size == obj_length) &&
            libspdm_consttime_is_mem_equal(OBJ_get0_data(asn1_obj), oid, oid_size)) {

            /* Extension Found*/

            status = true;
            break;
        }

        /* reset to 0 if not found */
        oct_length = 0;
    }

    if (status) {
        if (*extension_data_size < oct_length) {
            *extension_data_size = oct_length;
            status = false;
            goto cleanup;
        }
        if (asn1_oct != NULL) {
            libspdm_copy_mem(extension_data, *extension_data_size,
                             ASN1_STRING_get0_data(asn1_oct), oct_length);
        }
        *extension_data_size = oct_length;
    } else {
        /* the cert extension is found, but the oid extension is not found; */
        status = true;
        *extension_data_size = 0;
    }

cleanup:

    /* Release Resources.*/

    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }

    return status;
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
    bool status;
    status = libspdm_x509_get_extension_data(cert, cert_size,
                                             m_libspdm_oid_ext_key_usage,
                                             sizeof(m_libspdm_oid_ext_key_usage), usage,
                                             usage_size);
    return status;
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
    bool status;

    if (cert == NULL || cert_size == 0 || basic_constraints_size == NULL) {
        return false;
    }
    status = libspdm_x509_get_extension_data((uint8_t *)cert, cert_size,
                                             (uint8_t *)m_libspdm_oid_basic_constraints,
                                             sizeof(m_libspdm_oid_basic_constraints),
                                             basic_constraints,
                                             basic_constraints_size);
    return status;
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
    bool res;
    EVP_PKEY *pkey;
    X509 *x509_cert;


    /* Check input parameters.*/

    if (cert == NULL || rsa_context == NULL) {
        return false;
    }

    pkey = NULL;
    x509_cert = NULL;


    /* Read DER-encoded X509 Certificate and Construct X509 object.*/

    res = libspdm_x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if ((x509_cert == NULL) || (!res)) {
        res = false;
        goto done;
    }

    res = false;


    /* Retrieve and check EVP_PKEY data from X509 Certificate.*/

    pkey = X509_get_pubkey(x509_cert);
    if ((pkey == NULL) || (EVP_PKEY_id(pkey) != EVP_PKEY_RSA)) {
        goto done;
    }


    /* Duplicate RSA context from the retrieved EVP_PKEY.*/

    if ((*rsa_context = RSAPublicKey_dup(EVP_PKEY_get0_RSA(pkey))) !=
        NULL) {
        res = true;
    }

done:

    /* Release Resources.*/

    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }

    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }

    return res;
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
    bool res;
    EVP_PKEY *pkey;
    X509 *x509_cert;


    /* Check input parameters.*/

    if (cert == NULL || ec_context == NULL) {
        return false;
    }

    pkey = NULL;
    x509_cert = NULL;


    /* Read DER-encoded X509 Certificate and Construct X509 object.*/

    res = libspdm_x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if ((x509_cert == NULL) || (!res)) {
        res = false;
        goto done;
    }

    res = false;


    /* Retrieve and check EVP_PKEY data from X509 Certificate.*/

    pkey = X509_get_pubkey(x509_cert);
    if ((pkey == NULL) || (EVP_PKEY_id(pkey) != EVP_PKEY_EC)) {
        goto done;
    }


    /* Duplicate EC context from the retrieved EVP_PKEY.*/

    if ((*ec_context = EC_KEY_dup(EVP_PKEY_get0_EC_KEY(pkey))) != NULL) {
        res = true;
    }

done:

    /* Release Resources.*/

    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }

    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }

    return res;
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
    bool res;
    EVP_PKEY *pkey;
    X509 *x509_cert;
    int32_t type;


    /* Check input parameters.*/

    if (cert == NULL || ecd_context == NULL) {
        return false;
    }

    pkey = NULL;
    x509_cert = NULL;


    /* Read DER-encoded X509 Certificate and Construct X509 object.*/

    res = libspdm_x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if ((x509_cert == NULL) || (!res)) {
        res = false;
        goto done;
    }

    res = false;


    /* Retrieve and check EVP_PKEY data from X509 Certificate.*/

    pkey = X509_get_pubkey(x509_cert);
    if (pkey == NULL) {
        goto done;
    }
    type = EVP_PKEY_id(pkey);
    if ((type != EVP_PKEY_ED25519) && (type != EVP_PKEY_ED448)) {
        goto done;
    }

    *ecd_context = pkey;
    res = true;

done:

    /* Release Resources.*/

    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }

    return res;
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
    bool res;
    EVP_PKEY *pkey;
    X509 *x509_cert;
    int result;

    /* Check input parameters.*/

    if (cert == NULL || sm2_context == NULL) {
        return false;
    }

    pkey = NULL;
    x509_cert = NULL;


    /* Read DER-encoded X509 Certificate and Construct X509 object.*/

    res = libspdm_x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if ((x509_cert == NULL) || (!res)) {
        res = false;
        goto done;
    }

    res = false;


    /* Retrieve and check EVP_PKEY data from X509 Certificate.*/

    pkey = X509_get_pubkey(x509_cert);
    if (pkey == NULL) {
        goto done;
    }

    result = EVP_PKEY_is_a(pkey,"SM2");
    if (result == 0) {
        goto done;
    }

    *sm2_context = pkey;
    res = true;

done:

    /* Release Resources.*/

    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }

    return res;
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
    bool res;
    X509 *x509_cert;
    X509 *x509_ca_cert;
    X509_STORE *cert_store;
    X509_STORE_CTX *cert_ctx;


    /* Check input parameters.*/

    if (cert == NULL || ca_cert == NULL) {
        return false;
    }

    res = false;
    x509_cert = NULL;
    x509_ca_cert = NULL;
    cert_store = NULL;
    cert_ctx = NULL;


    /* Register & Initialize necessary digest algorithms for certificate verification.*/

    if (EVP_add_digest(EVP_sha256()) == 0) {
        goto done;
    }
    if (EVP_add_digest(EVP_sha384()) == 0) {
        goto done;
    }
    if (EVP_add_digest(EVP_sha512()) == 0) {
        goto done;
    }


    /* Read DER-encoded certificate to be verified and Construct X509 object.*/

    res = libspdm_x509_construct_certificate(cert, cert_size, (uint8_t **)&x509_cert);
    if ((x509_cert == NULL) || (!res)) {
        res = false;
        goto done;
    }


    /* Read DER-encoded root certificate and Construct X509 object.*/

    res = libspdm_x509_construct_certificate(ca_cert, ca_cert_size,
                                             (uint8_t **)&x509_ca_cert);
    if ((x509_ca_cert == NULL) || (!res)) {
        res = false;
        goto done;
    }

    res = false;


    /* Set up X509 Store for trusted certificate.*/

    cert_store = X509_STORE_new();
    if (cert_store == NULL) {
        goto done;
    }
    if (!(X509_STORE_add_cert(cert_store, x509_ca_cert))) {
        goto done;
    }

    /* Allow partial certificate chains, terminated by a non-self-signed but
     * still trusted intermediate certificate.
     */

    X509_STORE_set_flags(cert_store, X509_V_FLAG_PARTIAL_CHAIN);

#if OPENSSL_IGNORE_CRITICAL
    X509_STORE_set_flags(cert_store, X509_V_FLAG_IGNORE_CRITICAL);
#endif

#ifndef OPENSSL_CHECK_TIME
    X509_STORE_set_flags(cert_store, X509_V_FLAG_NO_CHECK_TIME);
#endif

    /* Set up X509_STORE_CTX for the subsequent verification operation.*/

    cert_ctx = X509_STORE_CTX_new();
    if (cert_ctx == NULL) {
        goto done;
    }
    if (!X509_STORE_CTX_init(cert_ctx, cert_store, x509_cert, NULL)) {
        goto done;
    }


    /* X509 Certificate Verification.*/
    res = (X509_verify_cert(cert_ctx) <= 0) ? false : true;
    X509_STORE_CTX_cleanup(cert_ctx);

done:

    /* Release Resources.*/

    if (x509_cert != NULL) {
        X509_free(x509_cert);
    }

    if (x509_ca_cert != NULL) {
        X509_free(x509_ca_cert);
    }

    if (cert_store != NULL) {
        X509_STORE_free(cert_store);
    }

    X509_STORE_CTX_free(cert_ctx);

    return res;
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
    const uint8_t *temp;
    uint32_t asn1_tag;
    uint32_t obj_class;
    size_t length;


    /* Check input parameters.*/

    if ((cert == NULL) || (tbs_cert == NULL) || (tbs_cert_size == NULL) ||
        (cert_size > INT_MAX)) {
        return false;
    }


    /* An X.509 Certificate is: (defined in RFC3280)
     *   Certificate  ::=  SEQUENCE  {
     *     tbsCertificate       TBSCertificate,
     *     signatureAlgorithm   AlgorithmIdentifier,
     *     signature            BIT STRING }*/

    /* and*/

    /*  TBSCertificate  ::=  SEQUENCE  {
     *    version         [0]  version DEFAULT v1,
     *    ...
     *    }*/

    /* So we can just ASN1-parse the x.509 DER-encoded data. If we strip
     * the first SEQUENCE, the second SEQUENCE is the TBSCertificate.*/

    temp = cert;
    length = 0;
    ASN1_get_object(&temp, (long *)&length, (int *)&asn1_tag,
                    (int *)&obj_class, (long)cert_size);

    if (asn1_tag != V_ASN1_SEQUENCE) {
        return false;
    }

    *tbs_cert = (uint8_t *)temp;

    ASN1_get_object(&temp, (long *)&length, (int *)&asn1_tag,
                    (int *)&obj_class, (long)length);

    /* Verify the parsed TBSCertificate is one correct SEQUENCE data.*/

    if (asn1_tag != V_ASN1_SEQUENCE) {
        return false;
    }

    *tbs_cert_size = length + (temp - *tbs_cert);

    return true;
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
    const uint8_t *tmp_ptr;
    size_t length;
    uint32_t asn1_tag;
    uint32_t obj_class;
    const uint8_t *current_cert;
    size_t current_cert_len;
    const uint8_t *preceding_cert;
    size_t preceding_cert_len;
    bool verify_flag;
    int32_t ret;
    uint8_t *root_ptr;
    uint8_t *chain_ptr;
    size_t root_obj_len;
    size_t chain_obj_len;
    uint8_t *end;

    preceding_cert = root_cert;
    preceding_cert_len = root_cert_length;

    current_cert = cert_chain;
    length = 0;
    current_cert_len = 0;

    root_ptr = (uint8_t*)(size_t)root_cert;
    end = root_ptr + root_cert_length;
    verify_flag = libspdm_asn1_get_tag(
        &root_ptr, end, &root_obj_len,
        LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!verify_flag) {
        return false;
    }

    chain_ptr = (uint8_t*)(size_t)cert_chain;
    end = chain_ptr + cert_chain_length;
    verify_flag = libspdm_asn1_get_tag(
        &chain_ptr, end, &chain_obj_len,
        LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!verify_flag) {
        return false;
    }

    /*only self_signed cert is accepted when these two cert are same*/
    if ((chain_obj_len == root_obj_len) &&
        (libspdm_consttime_is_mem_equal(root_ptr, chain_ptr, root_obj_len)) &&
        (!libspdm_is_root_certificate(root_cert, root_cert_length))) {
        return false;
    }

    verify_flag = false;
    while (true) {
        tmp_ptr = current_cert;
        ret = ASN1_get_object(
            (const uint8_t **)&tmp_ptr, (long *)&length,
            (int *)&asn1_tag, (int *)&obj_class,
            (long)(cert_chain_length + cert_chain - tmp_ptr));
        if (asn1_tag != V_ASN1_SEQUENCE || ret & OPENSSL_ASN1_ERROR_MASK) {
            break;
        }


        /* Calculate current_cert length;*/

        current_cert_len = tmp_ptr - current_cert + length;


        /* Verify current_cert with preceding cert;*/

        verify_flag =
            libspdm_x509_verify_cert(current_cert, current_cert_len,
                                     preceding_cert, preceding_cert_len);
        if (verify_flag == false) {
            break;
        }


        /* move Current cert to Preceding cert*/

        preceding_cert_len = current_cert_len;
        preceding_cert = current_cert;


        /* Move to next*/

        current_cert = current_cert + current_cert_len;
    }

    return verify_flag;
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
    size_t asn1_len;
    int32_t current_index;
    size_t current_cert_len;
    const uint8_t *current_cert;
    const uint8_t *tmp_ptr;
    int32_t ret;
    uint32_t asn1_tag;
    uint32_t obj_class;


    /* Check input parameters.*/

    if ((cert_chain == NULL) || (cert == NULL) || (cert_index < -1) ||
        (cert_length == NULL)) {
        return false;
    }

    asn1_len = 0;
    current_cert_len = 0;
    current_cert = cert_chain;
    current_index = -1;


    /* Traverse the certificate chain*/

    while (true) {
        tmp_ptr = current_cert;

        /* Get asn1 object and taglen*/
        ret = ASN1_get_object(
            (const uint8_t **)&tmp_ptr, (long *)&asn1_len,
            (int *)&asn1_tag, (int *)&obj_class,
            (long)(cert_chain_length + cert_chain - tmp_ptr));
        if (asn1_tag != V_ASN1_SEQUENCE || ret & OPENSSL_ASN1_ERROR_MASK) {
            break;
        }

        /* Calculate current_cert length;*/

        current_cert_len = tmp_ptr - current_cert + asn1_len;
        current_index++;

        if (current_index == cert_index) {
            *cert = current_cert;
            *cert_length = current_cert_len;
            return true;
        }


        /* Move to next*/

        current_cert = current_cert + current_cert_len;
    }


    /* If cert_index is -1, Return the last certificate*/

    if (cert_index == -1 && current_index >= 0) {
        *cert = current_cert - current_cert_len;
        *cert_length = current_cert_len;
        return true;
    }

    return false;
}

size_t libspdm_get_str_len(char *dst)
{
    char *p = dst;

    if (dst == NULL) {
        return 0;
    }

    while (*p != '\0')
    {
        p++;
    }

    return p - dst;
}

char *libspdm_strstr(char *src, char *dst)
{
    size_t index;

    if ((src == NULL) || (dst == NULL)) {
        return NULL;
    }

    if (libspdm_get_str_len(src) < libspdm_get_str_len(dst)) {
        return NULL;
    }

    for (index = 0; index < libspdm_get_str_len(src) - libspdm_get_str_len(dst); index++) {
        if ((*(src + index) == *dst) &&
            libspdm_consttime_is_mem_equal(src + index, dst, libspdm_get_str_len(dst))) {
            return (src + index);
        }
    }

    return NULL;
}

bool libspdm_set_subject_name(X509_NAME *x509_name, char *subject_name)
{
    int ret;
    uint8_t index;
    char *char_start;
    char *char_end;
    char temp[MAX_SBUJECT_NAME_LEN];
    char *end_case = ",";

    ret = 0;
    char_start = NULL;
    char_end = NULL;

    /* X.509 DN attributes from RFC 5280, Appendix A.1. */
    char *subject_set[] = {
        "CN", "commonName", "C", "countryName", "O", "organizationName","L", "OU",
        "organizationalUnitName", "ST", "stateOrProvinceName", "emailAddress", "serialNumber",
        "postalAddress", "postalCode", "dnQualifier", "title", "SN","givenName","GN",
        "initials", "pseudonym", "generationQualifier", "domainComponent", "DC"
    };


    for (index = 0; index < sizeof(subject_set)/sizeof(subject_set[0]); index++)
    {

        char_start = libspdm_strstr(subject_name, subject_set[index]);

        /* find object in subject_set and the next is '=' */
        if ((char_start != NULL) &&
            (*(char_start + libspdm_get_str_len(subject_set[index])) == '=')) {

            char_start += (libspdm_get_str_len(subject_set[index]) + 1);
            /*end with ','*/
            char_end = libspdm_strstr(char_start, end_case);
            if (char_end != NULL) {
                libspdm_copy_mem(temp, MAX_SBUJECT_NAME_LEN, char_start, char_end - char_start);
                temp[char_end - char_start] = '\0';
            } else {
                /*end with '\0'*/
                char_end = subject_name + libspdm_get_str_len(subject_name);
                libspdm_copy_mem(temp, MAX_SBUJECT_NAME_LEN, char_start, char_end - char_start);
                temp[char_end - char_start] = '\0';
            }

            ret = X509_NAME_add_entry_by_txt(x509_name, subject_set[index], MBSTRING_ASC,
                                             (const unsigned char*)temp, -1, -1, 0);
            if (ret != 1) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"set subject error\n"));
                return false;
            }
        }
        char_start = NULL;
    }

    return true;
}

/**
 * Set all attributes object form req_info to CSR
 *
 * @param[in]      req                   CSR to set attributes
 * @param[in]      req_info              requester info to gen CSR
 * @param[in]      req_info_len          The len of requester info
 *
 * @retval  true   Success Set.
 * @retval  false  Set failed.
 **/
bool libspdm_set_attribute_for_req(X509_REQ *req, uint8_t *req_info, size_t req_info_len,
                                   EVP_PKEY *public_key)
{
    uint8_t *ptr;
    int32_t length;
    size_t obj_len;
    bool ret;
    uint8_t *end;
    uint8_t *ptr_old;

    uint8_t *oid;
    size_t oid_len;
    uint8_t *val;
    size_t val_len;
    size_t nid;
    ASN1_OBJECT *oid_asn1_obj;
    const unsigned char *oid_for_d2i;

    uint8_t *pubkey_info;
    size_t pubkey_info_len;
    uint8_t *der_data;
    int32_t der_len;
    X509_REQ_INFO *x509_req_info;

    x509_req_info = NULL;
    der_data = NULL;
    der_len = 0;
    length = (int32_t)req_info_len;
    ptr = req_info;
    obj_len = 0;
    end = ptr + length;
    ret = false;

    if (req_info == NULL) {
        return false;
    }

    /*get subject name from req_info and set it to CSR*/
    x509_req_info = d2i_X509_REQ_INFO(NULL, (const unsigned char **)(&req_info), req_info_len);
    if (x509_req_info) {
        X509_REQ_set_subject_name(req, X509_REQ_get_subject_name((X509_REQ *)x509_req_info));
        X509_REQ_INFO_free(x509_req_info);
    } else {
        return false;
    }

    /*req_info sequence, all req_info format is ok because the req_info has been verified before*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);

    /*integer:version*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_INTEGER);
    /*check req_info verson. spec PKCS#10: It shall be 0 for this version of the standard.*/
    if ((obj_len != 1) || (*ptr != 0)) {
        return false;
    }
    ptr += obj_len;

    /*sequence:subject name*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    ptr += obj_len;

    /*sequence:subject pkinfo*/
    pubkey_info = ptr;
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);

    pubkey_info_len = obj_len + (ptr - pubkey_info);
    der_len = i2d_PUBKEY(public_key, &der_data);
    /*check the public key info*/
    if (!((der_len > 0) && (der_len == pubkey_info_len) &&
          (libspdm_consttime_is_mem_equal(pubkey_info, der_data, der_len)))) {
        if (der_data != NULL) {
            OPENSSL_free(der_data);
        }
        return false;
    }
    OPENSSL_free(der_data);
    ptr += obj_len;

    /*get attributes from req_info and set them to CSR*/

    /*[0]: attributes*/
    ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                               LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC |
                               LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    /*there is no attributes*/
    if (ptr == end) {
        return true;
    }

    /*there is some attributes object: 1,2 ...*/
    while (ret)
    {
        ret = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                   LIBSPDM_CRYPTO_ASN1_SEQUENCE |
                                   LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
        if (ret) {
            /*save old positon*/
            ptr_old = ptr;

            /*move to the next sequence*/
            ptr += obj_len;

            /*get attributes oid*/
            ret = libspdm_asn1_get_tag(&ptr_old, end, &obj_len, LIBSPDM_CRYPTO_ASN1_OID);
            if (!ret) {
                return false;
            }

            /*the whole oid include: LIBSPDM_CRYPTO_ASN1_OID and obj_len*/
            oid = ptr_old - 2;
            oid_len = obj_len + 2;

            ptr_old += obj_len;
            /*get attributes val*/
            ret = libspdm_asn1_get_tag(&ptr_old, end, &obj_len,
                                       LIBSPDM_CRYPTO_ASN1_SET |
                                       LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
            if (!ret) {
                return false;
            }
            ret = libspdm_asn1_get_tag(&ptr_old, end, &obj_len, LIBSPDM_CRYPTO_ASN1_UTF8_STRING);
            if (!ret) {
                return false;
            }
            val = ptr_old;
            val_len = obj_len;

            /*transfer oid to nid*/
            oid_for_d2i = oid;
            oid_asn1_obj = d2i_ASN1_OBJECT(NULL, &oid_for_d2i, oid_len);
            nid = OBJ_obj2nid(oid_asn1_obj);
            ASN1_OBJECT_free(oid_asn1_obj);

            /*set attributes*/
            ret = X509_REQ_add1_attr_by_NID(req, nid,
                                            V_ASN1_UTF8STRING,
                                            (const unsigned char *)val,
                                            val_len);
            if (ret == 0) {
                return false;
            }

        } else {
            break;
        }
    }

    if (ptr == end) {
        return true;
    } else {
        return false;
    }
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
    int ret;
    int version;

    X509_REQ *x509_req;
    X509_NAME *x509_name;
    EVP_PKEY *private_key;
    EVP_PKEY *public_key;
    RSA *rsa_public_key;
    EC_KEY *ec_public_key;
    const EVP_MD *md;
    uint8_t *csr_p;
    STACK_OF(X509_EXTENSION) *exts;
    X509_EXTENSION *basic_constraints_ext;
    int num_exts;

    exts = NULL;
    basic_constraints_ext = NULL;
    ret = 0;
    version = 0;

    x509_req = NULL;
    x509_name = NULL;
    private_key = NULL;
    public_key = NULL;
    rsa_public_key = NULL;
    ec_public_key = NULL;
    md = NULL;
    csr_p = csr_pointer;
    num_exts = 0;

    x509_req = X509_REQ_new();
    if (x509_req == NULL) {
        return false;
    }

    private_key = EVP_PKEY_new();
    if (private_key == NULL) {
        X509_REQ_free(x509_req);
        return false;
    }

    public_key = EVP_PKEY_new();
    if (public_key == NULL) {
        X509_REQ_free(x509_req);
        EVP_PKEY_free(private_key);
        return false;
    }

    switch (asym_nid)
    {
    case LIBSPDM_CRYPTO_NID_RSASSA2048:
    case LIBSPDM_CRYPTO_NID_RSAPSS2048:
    case LIBSPDM_CRYPTO_NID_RSASSA3072:
    case LIBSPDM_CRYPTO_NID_RSAPSS3072:
    case LIBSPDM_CRYPTO_NID_RSASSA4096:
    case LIBSPDM_CRYPTO_NID_RSAPSS4096:
        ret = EVP_PKEY_set1_RSA(private_key, (RSA *)context);
        if (ret != 1) {
            goto free_all;
        }

        rsa_public_key = RSAPublicKey_dup((RSA *)context);
        EVP_PKEY_assign_RSA(public_key, rsa_public_key);
        break;
    case LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256:
    case LIBSPDM_CRYPTO_NID_ECDSA_NIST_P384:
    case LIBSPDM_CRYPTO_NID_ECDSA_NIST_P521:
        ret = EVP_PKEY_set1_EC_KEY(private_key, (EC_KEY *)context);
        if (ret != 1) {
            goto free_all;
        }

        ec_public_key = EC_KEY_dup((EC_KEY *)context);
        EVP_PKEY_assign_EC_KEY(public_key, ec_public_key);
        break;
    default:
        goto free_all;
    }

    /*set version of x509 req*/
    ret = X509_REQ_set_version(x509_req, version);
    if (ret != 1) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"set version error\n"));
        goto free_all;
    }

    /*set subject of x509 req*/
    x509_name = X509_REQ_get_subject_name(x509_req);

    if (subject_name != NULL) {
        ret = libspdm_set_subject_name(x509_name, subject_name);
        if (ret != 1) {
            goto free_all;
        }
    }

    /* requester info parse
     * check the req_info version and subjectPKInfo;
     * get attribute and subject from req_info and set them to CSR;
     **/
    if (requester_info_length != 0) {
        ret = libspdm_set_attribute_for_req(x509_req, requester_info, requester_info_length,
                                            public_key);
        if (ret == 0) {
            goto free_all;
        }
    }

    /*set public key for x509 req: the public key is from private key*/
    ret = X509_REQ_set_pubkey(x509_req, private_key);
    if (ret != 1) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"set public key error\n"));
        goto free_all;
    }

    /*get hash algo*/
    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        md = EVP_sha256();
        break;
    case LIBSPDM_CRYPTO_NID_SHA384:
        md = EVP_sha384();
        break;
    case LIBSPDM_CRYPTO_NID_SHA512:
        md = EVP_sha512();
        break;
    case LIBSPDM_CRYPTO_NID_SHA3_256:
        md = EVP_sha3_256();
        break;
    case LIBSPDM_CRYPTO_NID_SHA3_384:
        md = EVP_sha3_384();
        break;
    case LIBSPDM_CRYPTO_NID_SHA3_512:
        md = EVP_sha3_512();
        break;
    case LIBSPDM_CRYPTO_NID_SM3_256:
        md = EVP_sm3();
        break;
    default:
        ret = 0;
        goto free_all;
    }

    /*gen basicConstraints*/
    exts = sk_X509_EXTENSION_new_null();
    if (!exts) {
        ret = 0;
        goto free_all;
    }

    /*set basicConstraints*/
    basic_constraints_ext = X509V3_EXT_conf_nid(
        NULL, NULL, NID_basic_constraints,
        is_ca ? "CA:TRUE" : "CA:FALSE");
    if (!basic_constraints_ext) {
        sk_X509_EXTENSION_free(exts);
        ret = 0;
        goto free_all;
    }
    sk_X509_EXTENSION_push(exts, basic_constraints_ext);

    if (base_cert != NULL) {
        const ASN1_OBJECT *basic_constraints_obj = OBJ_nid2obj(NID_basic_constraints);
        const ASN1_OBJECT *authority_key_identifier_obj = OBJ_nid2obj(NID_authority_key_identifier);

        num_exts = X509_get_ext_count(base_cert);

        for (int i = 0; i < num_exts; i++) {
            X509_EXTENSION *extension = X509_get_ext(base_cert, i);
            ASN1_OBJECT *obj = X509_EXTENSION_get_object(extension);

            if (OBJ_cmp(basic_constraints_obj, obj) == 0) {
                continue;
            }

            if (OBJ_cmp(authority_key_identifier_obj, obj) == 0) {
                continue;
            }

            sk_X509_EXTENSION_push(exts, extension);
        }
    }

    X509_REQ_add_extensions(x509_req, exts);
    sk_X509_EXTENSION_free(exts);

    /*sign for x509 req*/
    ret = X509_REQ_sign(x509_req, private_key, md);
    if (ret <= 0) {
        ret = 0;
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"sign csr error\n"));
        goto free_all;
    }

    ret = i2d_X509_REQ(x509_req, &csr_p);
    if (ret <= 0) {
        ret = 0;
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,"i2d_X509_REQ error\n"));
        goto free_all;
    } else {
        *csr_len = ret;
    }

    /*free*/
free_all:
    X509_REQ_free(x509_req);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);

    return (ret != 0);
}

#endif
