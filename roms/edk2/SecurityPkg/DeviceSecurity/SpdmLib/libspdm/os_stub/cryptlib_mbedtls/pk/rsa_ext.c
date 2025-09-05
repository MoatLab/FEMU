/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * RSA Asymmetric Cipher Wrapper Implementation.
 *
 * This file implements following APIs which provide more capabilities for RSA:
 * 1) libspdm_rsa_get_key
 * 2) libspdm_rsa_generate_key
 * 3) libspdm_rsa_check_key
 * 4) rsa_pkcs1_sign
 *
 * RFC 8017 - PKCS #1: RSA Cryptography Specifications version 2.2
 **/

#include "internal_crypt_lib.h"
#include <mbedtls/rsa.h>

#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
/**
 * Gets the tag-designated RSA key component from the established RSA context.
 *
 * This function retrieves the tag-designated RSA key component from the
 * established RSA context as a non-negative integer (octet string format
 * represented in RSA PKCS#1).
 * If specified key component has not been set or has been cleared, then returned
 * bn_size is set to 0.
 * If the big_number buffer is too small to hold the contents of the key, false
 * is returned and bn_size is set to the required buffer size to obtain the key.
 *
 * If rsa_context is NULL, then return false.
 * If bn_size is NULL, then return false.
 * If bn_size is large enough but big_number is NULL, then return false.
 *
 * @param[in, out]  rsa_context  Pointer to RSA context being set.
 * @param[in]       key_tag      tag of RSA key component being set.
 * @param[out]      big_number   Pointer to octet integer buffer.
 * @param[in, out]  bn_size      On input, the size of big number buffer in bytes.
 *                             On output, the size of data returned in big number buffer in bytes.
 *
 * @retval  true   RSA key component was retrieved successfully.
 * @retval  false  Invalid RSA key component tag.
 * @retval  false  bn_size is too small.
 *
 **/
bool libspdm_rsa_get_key(void *rsa_context, const libspdm_rsa_key_tag_t key_tag,
                         uint8_t *big_number, size_t *bn_size)
{
    mbedtls_rsa_context *rsa_key;
    int ret;
    mbedtls_mpi value;
    size_t size;


    /* Check input parameters.*/

    if (rsa_context == NULL || *bn_size > INT_MAX) {
        return false;
    }

    /* Init mbedtls_mpi*/

    mbedtls_mpi_init(&value);
    size = *bn_size;
    *bn_size = 0;

    rsa_key = (mbedtls_rsa_context *)rsa_context;

    switch (key_tag) {
    case LIBSPDM_RSA_KEY_N:
        ret = mbedtls_rsa_export(rsa_key, &value, NULL, NULL, NULL,
                                 NULL);
        break;
    case LIBSPDM_RSA_KEY_E:
        ret = mbedtls_rsa_export(rsa_key, NULL, NULL, NULL, NULL,
                                 &value);
        break;
    case LIBSPDM_RSA_KEY_D:
        ret = mbedtls_rsa_export(rsa_key, NULL, NULL, NULL, &value,
                                 NULL);
        break;
    case LIBSPDM_RSA_KEY_Q:
        ret = mbedtls_rsa_export(rsa_key, NULL, NULL, &value, NULL,
                                 NULL);
        break;
    case LIBSPDM_RSA_KEY_P:
        ret = mbedtls_rsa_export(rsa_key, NULL, &value, NULL, NULL,
                                 NULL);
        break;
    case LIBSPDM_RSA_KEY_DP:
    case LIBSPDM_RSA_KEY_DQ:
    case LIBSPDM_RSA_KEY_Q_INV:
    default:
        ret = -1;
        break;
    }

    if (ret != 0) {
        return false;
    }

    if (!mbedtls_mpi_size(&value)) {
        ret = 0;
        goto end;
    }

    *bn_size = size;

    if (ret == 0) {
        size = mbedtls_mpi_size(&value);
    }
    if (size == 0) {
        ret = 1;
        goto end;
    }

    if (*bn_size < size) {
        ret = 1;
        *bn_size = size;
        goto end;
    }

    if (big_number == NULL) {
        ret = 0;
        *bn_size = size;
        goto end;
    }

    if (big_number != NULL && ret == 0) {
        ret = mbedtls_mpi_write_binary(&value, big_number, size);
        *bn_size = size;
    }
end:
    mbedtls_mpi_free(&value);
    return ret == 0;
}

/**
 * Generates RSA key components.
 *
 * This function generates RSA key components. It takes RSA public exponent E and
 * length in bits of RSA modulus N as input, and generates all key components.
 * If public_exponent is NULL, the default RSA public exponent (0x10001) will be used.
 *
 * If rsa_context is NULL, then return false.
 *
 * @param[in, out]  rsa_context           Pointer to RSA context being set.
 * @param[in]       modulus_length        length of RSA modulus N in bits.
 * @param[in]       public_exponent       Pointer to RSA public exponent.
 * @param[in]       public_exponent_size   size of RSA public exponent buffer in bytes.
 *
 * @retval  true   RSA key component was generated successfully.
 * @retval  false  Invalid RSA key component tag.
 *
 **/
bool libspdm_rsa_generate_key(void *rsa_context, size_t modulus_length,
                              const uint8_t *public_exponent,
                              size_t public_exponent_size)
{
    int32_t ret = 0;
    mbedtls_rsa_context *rsa;
    uint32_t e;


    /* Check input parameters.*/
    if (rsa_context == NULL || modulus_length > INT_MAX ||
        public_exponent_size > INT_MAX) {
        return false;
    }

    rsa = (mbedtls_rsa_context *)rsa_context;

    if (public_exponent == NULL) {
        e = 0x10001;
    } else {
        if (public_exponent_size == 0) {
            return false;
        }

        switch (public_exponent_size) {
        case 1:
            e = public_exponent[0];
            break;
        case 2:
            e = public_exponent[0] << 8 | public_exponent[1];
            break;
        case 3:
            e = public_exponent[0] << 16 | public_exponent[1] << 8 |
                public_exponent[2];
            break;
        case 4:
            e = public_exponent[0] << 24 | public_exponent[1] << 16 |
                public_exponent[2] << 8 | public_exponent[3];
            break;
        default:
            return false;
        }
    }

    if (ret == 0) {
        ret = mbedtls_rsa_gen_key(rsa, libspdm_myrand, NULL,
                                  (uint32_t)modulus_length, e);
    }

    return ret == 0;
}

/**
 * Validates key components of RSA context.
 * NOTE: This function performs integrity checks on all the RSA key material, so
 *      the RSA key structure must contain all the private key data.
 *
 * This function validates key components of RSA context in following aspects:
 * - Whether p is a prime
 * - Whether q is a prime
 * - Whether n = p * q
 * - Whether d*e = 1  mod lcm(p-1,q-1)
 *
 * If rsa_context is NULL, then return false.
 *
 * @param[in]  rsa_context  Pointer to RSA context to check.
 *
 * @retval  true   RSA key components are valid.
 * @retval  false  RSA key components are not valid.
 *
 **/
bool libspdm_rsa_check_key(void *rsa_context)
{
    int ret;

    if (rsa_context == NULL) {
        return false;
    }

    ret = mbedtls_rsa_complete(rsa_context);
    if (ret == 0) {
        ret = mbedtls_rsa_check_privkey(rsa_context);
    }
    return ret == 0;
}
#endif /* (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT) */

#if LIBSPDM_RSA_SSA_SUPPORT
/**
 * Carries out the RSA-SSA signature generation with EMSA-PKCS1-v1_5 encoding scheme.
 *
 * This function carries out the RSA-SSA signature generation with EMSA-PKCS1-v1_5 encoding scheme defined in
 * RSA PKCS#1.
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If hash_size need match the hash_nid. hash_nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 * If sig_size is large enough but signature is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]      rsa_context   Pointer to RSA context for signature generation.
 * @param[in]      hash_nid      hash NID
 * @param[in]      message_hash  Pointer to octet message hash to be signed.
 * @param[in]      hash_size     size of the message hash in bytes.
 * @param[out]     signature    Pointer to buffer to receive RSA PKCS1-v1_5 signature.
 * @param[in, out] sig_size      On input, the size of signature buffer in bytes.
 *                             On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in PKCS1-v1_5.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 * @retval  false  This interface is not supported.
 *
 **/
bool libspdm_rsa_pkcs1_sign_with_nid(void *rsa_context, size_t hash_nid,
                                     const uint8_t *message_hash,
                                     size_t hash_size, uint8_t *signature,
                                     size_t *sig_size)
{
    int ret;
    mbedtls_md_type_t md_alg;
    mbedtls_rsa_context *rsa_key;

    if (rsa_context == NULL || message_hash == NULL) {
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

    if (mbedtls_rsa_get_len(rsa_context) > *sig_size) {
        *sig_size = mbedtls_rsa_get_len(rsa_context);
        return false;
    }

    mbedtls_rsa_set_padding(rsa_context, MBEDTLS_RSA_PKCS_V15, md_alg);

    ret = mbedtls_rsa_pkcs1_sign(rsa_context, libspdm_myrand, NULL,
                                 MBEDTLS_RSA_PRIVATE, md_alg,
                                 (uint32_t)hash_size, message_hash,
                                 signature);
    if (ret != 0) {
        return false;
    }
    *sig_size = mbedtls_rsa_get_len(rsa_context);
    return true;
}
#endif /* LIBSPDM_RSA_SSA_SUPPORT */

#if LIBSPDM_RSA_PSS_SUPPORT
/**
 * Carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme.
 *
 * This function carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2.
 *
 * The salt length is same as digest length.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 * If sig_size is large enough but signature is NULL, then return false.
 *
 * @param[in]       rsa_context   Pointer to RSA context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       message_hash  Pointer to octet message hash to be signed.
 * @param[in]       hash_size     size of the message hash in bytes.
 * @param[out]      signature    Pointer to buffer to receive RSA-SSA PSS signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                              On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in RSA-SSA PSS.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 *
 **/
bool libspdm_rsa_pss_sign(void *rsa_context, size_t hash_nid,
                          const uint8_t *message_hash, size_t hash_size,
                          uint8_t *signature, size_t *sig_size)
{
    int ret;
    mbedtls_md_type_t md_alg;
    mbedtls_rsa_context *rsa_key;

    if (rsa_context == NULL || message_hash == NULL) {
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

    if (signature == NULL) {

        /* If signature is NULL, return safe signature_size*/

        *sig_size = MBEDTLS_MPI_MAX_SIZE;
        return false;
    }

    mbedtls_rsa_set_padding(rsa_context, MBEDTLS_RSA_PKCS_V21, md_alg);

    ret = mbedtls_rsa_rsassa_pss_sign(rsa_context, libspdm_myrand, NULL,
                                      MBEDTLS_RSA_PRIVATE, md_alg,
                                      (uint32_t)hash_size, message_hash,
                                      signature);
    if (ret != 0) {
        return false;
    }
    *sig_size = ((mbedtls_rsa_context *)rsa_context)->len;
    return true;
}

#if LIBSPDM_FIPS_MODE

/*random function() for RSA_PSS*/
int libspdm_myrand_rsapss_fips(void *rng_state, unsigned char *output, size_t len)
{

    bool result;

    if (len == 0) {
        return 0;
    } else {
        result = libspdm_random_bytes(output, len);
        /* The MbedTLS function f_rng, which myrand implements, is not
         * documented well. From looking at code: zero is considered success,
         * while non-zero return value is considered failure.*/

        return result ? 0 : -1;
    }
}

/**
 * Carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme for FIPS test.
 *
 * This function carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme defined in
 * RSA PKCS#1 v2.2 for FIPS test.
 *
 * The salt length is zero.
 *
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If rsa_context is NULL, then return false.
 * If message_hash is NULL, then return false.
 * If hash_size need match the hash_nid. nid could be SHA256, SHA384, SHA512, SHA3_256, SHA3_384, SHA3_512.
 * If sig_size is large enough but signature is NULL, then return false.
 *
 * @param[in]       rsa_context   Pointer to RSA context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       message_hash  Pointer to octet message hash to be signed.
 * @param[in]       hash_size     size of the message hash in bytes.
 * @param[out]      signature    Pointer to buffer to receive RSA-SSA PSS signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                              On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in RSA-SSA PSS.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 *
 **/
bool libspdm_rsa_pss_sign_fips(void *rsa_context, size_t hash_nid,
                               const uint8_t *message_hash, size_t hash_size,
                               uint8_t *signature, size_t *sig_size)
{
    int ret;
    mbedtls_md_type_t md_alg;
    mbedtls_rsa_context *rsa_key;

    if (rsa_context == NULL || message_hash == NULL) {
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

    if (signature == NULL) {

        /* If signature is NULL, return safe signature_size*/

        *sig_size = MBEDTLS_MPI_MAX_SIZE;
        return false;
    }

    mbedtls_rsa_set_padding(rsa_context, MBEDTLS_RSA_PKCS_V21, md_alg);

    /*salt len is 0*/
    ret = mbedtls_rsa_rsassa_pss_sign_ext(rsa_context, libspdm_myrand_rsapss_fips, NULL,
                                          md_alg, (uint32_t)hash_size, message_hash,
                                          0, signature);
    if (ret != 0) {
        return false;
    }
    *sig_size = ((mbedtls_rsa_context *)rsa_context)->len;
    return true;
}
#endif /*LIBSPDM_FIPS_MODE*/

#endif /* LIBSPDM_RSA_PSS_SUPPORT */
