/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * RSA Asymmetric Cipher Wrapper Implementation.
 *
 * This file implements following APIs which provide basic capabilities for RSA:
 * 1) libspdm_rsa_new
 * 2) libspdm_rsa_free
 * 3) libspdm_rsa_set_key
 * 4) rsa_pkcs1_verify
 *
 * RFC 8017 - PKCS #1: RSA Cryptography Specifications version 2.2
 **/

#include "internal_crypt_lib.h"

#include <mbedtls/rsa.h>

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
/**
 * Allocates and initializes one RSA context for subsequent use.
 *
 * @return  Pointer to the RSA context that has been initialized.
 *         If the allocations fails, libspdm_rsa_new() returns NULL.
 *
 **/
void *libspdm_rsa_new(void)
{
    void *rsa_context;

    rsa_context = allocate_zero_pool(sizeof(mbedtls_rsa_context));
    if (rsa_context == NULL) {
        return rsa_context;
    }

    mbedtls_rsa_init(rsa_context, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
    return rsa_context;
}

/**
 * Release the specified RSA context.
 *
 * @param[in]  rsa_context  Pointer to the RSA context to be released.
 *
 **/
void libspdm_rsa_free(void *rsa_context)
{
    mbedtls_rsa_free(rsa_context);
    free_pool(rsa_context);
}

/**
 * Sets the tag-designated key component into the established RSA context.
 *
 * This function sets the tag-designated RSA key component into the established
 * RSA context from the user-specified non-negative integer (octet string format
 * represented in RSA PKCS#1).
 * If big_number is NULL, then the specified key component in RSA context is cleared.
 *
 * If rsa_context is NULL, then return false.
 *
 * @param[in, out]  rsa_context  Pointer to RSA context being set.
 * @param[in]       key_tag      tag of RSA key component being set.
 * @param[in]       big_number   Pointer to octet integer buffer.
 *                             If NULL, then the specified key component in RSA
 *                             context is cleared.
 * @param[in]       bn_size      size of big number buffer in bytes.
 *                             If big_number is NULL, then it is ignored.
 *
 * @retval  true   RSA key component was set successfully.
 * @retval  false  Invalid RSA key component tag.
 *
 **/
bool libspdm_rsa_set_key(void *rsa_context, const libspdm_rsa_key_tag_t key_tag,
                         const uint8_t *big_number, size_t bn_size)
{
    mbedtls_rsa_context *rsa_key;
    int ret;
    mbedtls_mpi value;


    /* Check input parameters.*/

    if (rsa_context == NULL || bn_size > INT_MAX) {
        return false;
    }

    mbedtls_mpi_init(&value);

    rsa_key = (mbedtls_rsa_context *)rsa_context;

    /* if big_number is Null clear*/
    if (big_number) {
        ret = mbedtls_mpi_read_binary(&value, big_number, bn_size);
        if (ret != 0) {
            mbedtls_mpi_free(&value);
            return false;
        }
    }

    switch (key_tag) {
    case LIBSPDM_RSA_KEY_N:
        ret = mbedtls_rsa_import(rsa_key, &value, NULL, NULL, NULL,
                                 NULL);
        break;
    case LIBSPDM_RSA_KEY_E:
        ret = mbedtls_rsa_import(rsa_key, NULL, NULL, NULL, NULL,
                                 &value);
        break;
    case LIBSPDM_RSA_KEY_D:
        ret = mbedtls_rsa_import(rsa_key, NULL, NULL, NULL, &value,
                                 NULL);
        break;
    case LIBSPDM_RSA_KEY_Q:
        ret = mbedtls_rsa_import(rsa_key, NULL, NULL, &value, NULL,
                                 NULL);
        break;
    case LIBSPDM_RSA_KEY_P:
        ret = mbedtls_rsa_import(rsa_key, NULL, &value, NULL, NULL,
                                 NULL);
        break;
    case LIBSPDM_RSA_KEY_DP:
    case LIBSPDM_RSA_KEY_DQ:
    case LIBSPDM_RSA_KEY_Q_INV:
    default:
        ret = -1;
        break;
    }

    mbedtls_mpi_free(&value);
    return ret == 0;
}
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_RSA_SSA_SUPPORT
/**
 * Verifies the RSA-SSA signature with EMSA-PKCS1-v1_5 encoding scheme defined in
 * RSA PKCS#1.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature    Pointer to RSA PKCS1-v1_5 signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in PKCS1-v1_5.
 * @retval  false  Invalid signature or invalid RSA context.
 *
 **/
bool libspdm_rsa_pkcs1_verify_with_nid(void *rsa_context, size_t hash_nid,
                                       const uint8_t *message_hash,
                                       size_t hash_size, const uint8_t *signature,
                                       size_t sig_size)
{
    int ret;
    mbedtls_md_type_t md_alg;
    mbedtls_rsa_context *rsa_key;

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    rsa_key = (mbedtls_rsa_context *)rsa_context;
    if (mbedtls_rsa_complete(rsa_key) != 0) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        md_alg = MBEDTLS_MD_SHA256;
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        md_alg = MBEDTLS_MD_SHA384;
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        md_alg = MBEDTLS_MD_SHA512;
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        break;

    default:
        return false;
    }

    if (mbedtls_rsa_get_len(rsa_context) != sig_size) {
        return false;
    }

    mbedtls_rsa_set_padding(rsa_context, MBEDTLS_RSA_PKCS_V15, md_alg);

    ret = mbedtls_rsa_pkcs1_verify(rsa_context, NULL, NULL,
                                   MBEDTLS_RSA_PUBLIC, md_alg,
                                   (uint32_t)hash_size, message_hash,
                                   signature);
    if (ret != 0) {
        return false;
    }
    return true;
}
#endif /* LIBSPDM_RSA_SSA_SUPPORT */

#if LIBSPDM_RSA_PSS_SUPPORT
/**
 * Verifies the RSA-SSA signature with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2.
 *
 * The salt length is same as digest length.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature    Pointer to RSA-SSA PSS signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in RSA-SSA PSS.
 * @retval  false  Invalid signature or invalid RSA context.
 *
 **/
bool libspdm_rsa_pss_verify(void *rsa_context, size_t hash_nid,
                            const uint8_t *message_hash, size_t hash_size,
                            const uint8_t *signature, size_t sig_size)
{
    int ret;
    mbedtls_md_type_t md_alg;
    mbedtls_rsa_context *rsa_key;

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    rsa_key = (mbedtls_rsa_context *)rsa_context;
    if (mbedtls_rsa_complete(rsa_key) != 0) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        md_alg = MBEDTLS_MD_SHA256;
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        md_alg = MBEDTLS_MD_SHA384;
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        md_alg = MBEDTLS_MD_SHA512;
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        break;

    default:
        return false;
    }

    if (mbedtls_rsa_get_len(rsa_context) != sig_size) {
        return false;
    }

    mbedtls_rsa_set_padding(rsa_context, MBEDTLS_RSA_PKCS_V21, md_alg);

    ret = mbedtls_rsa_rsassa_pss_verify(rsa_context, NULL, NULL,
                                        MBEDTLS_RSA_PUBLIC, md_alg,
                                        (uint32_t)hash_size, message_hash,
                                        signature);
    if (ret != 0) {
        return false;
    }
    return true;
}

#if LIBSPDM_FIPS_MODE
/**
 * Verifies the RSA-SSA signature with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2 for FIPS test.
 *
 * The salt length is zero.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If signature is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 *
 * @param[in]  rsa_context   Pointer to RSA context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  message_hash  Pointer to octet message hash to be checked.
 * @param[in]  hash_size     size of the message hash in bytes.
 * @param[in]  signature    Pointer to RSA-SSA PSS signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in RSA-SSA PSS.
 * @retval  false  Invalid signature or invalid RSA context.
 *
 **/
bool libspdm_rsa_pss_verify_fips(void *rsa_context, size_t hash_nid,
                                 const uint8_t *message_hash, size_t hash_size,
                                 const uint8_t *signature, size_t sig_size)
{
    int ret;
    mbedtls_md_type_t md_alg;
    mbedtls_rsa_context *rsa_key;
    mbedtls_md_type_t mgf1_hash_id;

    if (rsa_context == NULL || message_hash == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    rsa_key = (mbedtls_rsa_context *)rsa_context;
    if (mbedtls_rsa_complete(rsa_key) != 0) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        md_alg = MBEDTLS_MD_SHA256;
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        md_alg = MBEDTLS_MD_SHA384;
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        md_alg = MBEDTLS_MD_SHA512;
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        break;

    default:
        return false;
    }

    if (mbedtls_rsa_get_len(rsa_context) != sig_size) {
        return false;
    }

    mbedtls_rsa_set_padding(rsa_context, MBEDTLS_RSA_PKCS_V21, md_alg);

    mgf1_hash_id = (rsa_key->hash_id != MBEDTLS_MD_NONE) ?
                   (mbedtls_md_type_t) rsa_key->hash_id : md_alg;

    /*salt len is 0*/
    ret = mbedtls_rsa_rsassa_pss_verify_ext(rsa_context, NULL, NULL,
                                            MBEDTLS_RSA_PUBLIC, md_alg,
                                            (uint32_t)hash_size, message_hash,
                                            mgf1_hash_id,
                                            0,
                                            signature);
    if (ret != 0) {
        return false;
    }
    return true;
}
#endif /*LIBSPDM_FIPS_MODE*/

#endif /* LIBSPDM_RSA_PSS_SUPPORT */
