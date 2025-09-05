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

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>

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
    RSA *rsa_key;
    BIGNUM *bn_key;
    size_t size;


    /* Check input parameters.*/

    if (rsa_context == NULL || bn_size == NULL) {
        return false;
    }

    rsa_key = (RSA *)rsa_context;
    size = *bn_size;
    *bn_size = 0;
    bn_key = NULL;

    switch (key_tag) {

    /* RSA public Modulus (N)*/

    case LIBSPDM_RSA_KEY_N:
        RSA_get0_key(rsa_key, (const BIGNUM **)&bn_key, NULL, NULL);
        break;


    /* RSA public Exponent (e)*/

    case LIBSPDM_RSA_KEY_E:
        RSA_get0_key(rsa_key, NULL, (const BIGNUM **)&bn_key, NULL);
        break;


    /* RSA Private Exponent (d)*/

    case LIBSPDM_RSA_KEY_D:
        RSA_get0_key(rsa_key, NULL, NULL, (const BIGNUM **)&bn_key);
        break;


    /* RSA Secret prime Factor of Modulus (p)*/

    case LIBSPDM_RSA_KEY_P:
        RSA_get0_factors(rsa_key, (const BIGNUM **)&bn_key, NULL);
        break;


    /* RSA Secret prime Factor of Modules (q)*/

    case LIBSPDM_RSA_KEY_Q:
        RSA_get0_factors(rsa_key, NULL, (const BIGNUM **)&bn_key);
        break;


    /* p's CRT Exponent (== d mod (p - 1))*/

    case LIBSPDM_RSA_KEY_DP:
        RSA_get0_crt_params(rsa_key, (const BIGNUM **)&bn_key, NULL,
                            NULL);
        break;


    /* q's CRT Exponent (== d mod (q - 1))*/

    case LIBSPDM_RSA_KEY_DQ:
        RSA_get0_crt_params(rsa_key, NULL, (const BIGNUM **)&bn_key,
                            NULL);
        break;


    /* The CRT Coefficient (== 1/q mod p)*/

    case LIBSPDM_RSA_KEY_Q_INV:
        RSA_get0_crt_params(rsa_key, NULL, NULL,
                            (const BIGNUM **)&bn_key);
        break;

    default:
        return false;
    }

    if (bn_key == NULL) {
        return false;
    }

    *bn_size = size;
    size = BN_num_bytes(bn_key);

    if (*bn_size < size) {
        *bn_size = size;
        return false;
    }

    if (big_number == NULL) {
        *bn_size = size;
        return true;
    }
    *bn_size = BN_bn2bin(bn_key, big_number);

    return true;
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
    BIGNUM *bn_e;
    bool ret_val;


    /* Check input parameters.*/

    if (rsa_context == NULL || modulus_length > INT_MAX ||
        public_exponent_size > INT_MAX) {
        return false;
    }

    bn_e = BN_new();
    if (bn_e == NULL) {
        return false;
    }

    ret_val = false;

    if (public_exponent == NULL) {
        if (BN_set_word(bn_e, 0x10001) == 0) {
            goto done;
        }
    } else {
        if (BN_bin2bn(public_exponent, (uint32_t)public_exponent_size,
                      bn_e) == NULL) {
            goto done;
        }
    }

    if (RSA_generate_key_ex((RSA *)rsa_context, (uint32_t)modulus_length,
                            bn_e, NULL) == 1) {
        ret_val = true;
    }

done:
    BN_free(bn_e);
    return ret_val;
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
    size_t reason;


    /* Check input parameters.*/

    if (rsa_context == NULL) {
        return false;
    }

    if (RSA_check_key((RSA *)rsa_context) != 1) {
        reason = ERR_GET_REASON(ERR_peek_last_error());
        if (reason == RSA_R_P_NOT_PRIME ||
            reason == RSA_R_Q_NOT_PRIME ||
            reason == RSA_R_N_DOES_NOT_EQUAL_P_Q ||
            reason == RSA_R_D_E_NOT_CONGRUENT_TO_1) {
            return false;
        }
    }

    return true;
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
    RSA *rsa;
    size_t size;
    int32_t digest_type;


    /* Check input parameters.*/

    if (rsa_context == NULL || message_hash == NULL) {
        return false;
    }

    rsa = (RSA *)rsa_context;
    size = RSA_size(rsa);

    if (*sig_size < size) {
        *sig_size = size;
        return false;
    }

    if (signature == NULL) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        digest_type = NID_sha256;
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        digest_type = NID_sha384;
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        digest_type = NID_sha512;
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_256:
        digest_type = NID_sha3_256;
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_384:
        digest_type = NID_sha3_384;
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_512:
        digest_type = NID_sha3_512;
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        break;

    default:
        return false;
    }

    return (bool)RSA_sign(digest_type, message_hash, (uint32_t)hash_size,
                          signature, (uint32_t *)sig_size,
                          (RSA *)rsa_context);
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
    RSA *rsa;
    bool result;
    int32_t size;
    const EVP_MD *evp_md;
    void *buffer;

    if (rsa_context == NULL || message_hash == NULL) {
        return false;
    }

    rsa = (RSA *)rsa_context;
    size = RSA_size(rsa);

    if (*sig_size < (size_t)size) {
        *sig_size = size;
        return false;
    }
    *sig_size = size;

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        evp_md = EVP_sha256();
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        evp_md = EVP_sha384();
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        evp_md = EVP_sha512();
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_256:
        evp_md = EVP_sha3_256();
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_384:
        evp_md = EVP_sha3_384();
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_512:
        evp_md = EVP_sha3_512();
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        break;

    default:
        return false;
    }

    buffer = allocate_pool(size);
    if (buffer == NULL) {
        return false;
    }

    result = (bool)RSA_padding_add_PKCS1_PSS(
        rsa, buffer, message_hash, evp_md, RSA_PSS_SALTLEN_DIGEST);
    if (!result) {
        free_pool(buffer);
        return false;
    }

    size = RSA_private_encrypt(size, buffer, signature, rsa,
                               RSA_NO_PADDING);
    free_pool(buffer);
    if (size <= 0) {
        return false;
    } else {
        LIBSPDM_ASSERT(*sig_size == (size_t)size);
        return true;
    }
}

#if LIBSPDM_FIPS_MODE
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
    RSA *rsa;
    bool result;
    int32_t size;
    const EVP_MD *evp_md;
    void *buffer;

    if (rsa_context == NULL || message_hash == NULL) {
        return false;
    }

    rsa = (RSA *)rsa_context;
    size = RSA_size(rsa);

    if (*sig_size < (size_t)size) {
        *sig_size = size;
        return false;
    }
    *sig_size = size;

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SHA256:
        evp_md = EVP_sha256();
        if (hash_size != LIBSPDM_SHA256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA384:
        evp_md = EVP_sha384();
        if (hash_size != LIBSPDM_SHA384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA512:
        evp_md = EVP_sha512();
        if (hash_size != LIBSPDM_SHA512_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_256:
        evp_md = EVP_sha3_256();
        if (hash_size != LIBSPDM_SHA3_256_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_384:
        evp_md = EVP_sha3_384();
        if (hash_size != LIBSPDM_SHA3_384_DIGEST_SIZE) {
            return false;
        }
        break;

    case LIBSPDM_CRYPTO_NID_SHA3_512:
        evp_md = EVP_sha3_512();
        if (hash_size != LIBSPDM_SHA3_512_DIGEST_SIZE) {
            return false;
        }
        break;

    default:
        return false;
    }

    buffer = allocate_pool(size);
    if (buffer == NULL) {
        return false;
    }

    /*salt len is 0*/
    result = (bool)RSA_padding_add_PKCS1_PSS(
        rsa, buffer, message_hash, evp_md, 0);
    if (!result) {
        free_pool(buffer);
        return false;
    }

    size = RSA_private_encrypt(size, buffer, signature, rsa,
                               RSA_NO_PADDING);
    free_pool(buffer);
    if (size <= 0) {
        return false;
    } else {
        LIBSPDM_ASSERT(*sig_size == (size_t)size);
        return true;
    }
}
#endif /*LIBSPDM_FIPS_MODE*/

#endif /* LIBSPDM_RSA_PSS_SUPPORT */
