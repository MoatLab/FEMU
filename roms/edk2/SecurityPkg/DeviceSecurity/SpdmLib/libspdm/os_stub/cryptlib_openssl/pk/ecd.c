/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Edwards-Curve Wrapper Implementation.
 *
 * RFC 8032 - Edwards-Curve Digital signature algorithm (EdDSA)
 * FIPS 186-4 - Digital signature Standard (DSS)
 **/

#include "internal_crypt_lib.h"

#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)

#include <openssl/evp.h>
#include <crypto/evp.h>

/**
 * Allocates and Initializes one Edwards-Curve context for subsequent use
 * with the NID.
 *
 * The key is generated before the function returns.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Edwards-Curve context that has been initialized.
 *         If the allocations fails, libspdm_ecd_new_by_nid() returns NULL.
 *
 **/
void *libspdm_ecd_new_by_nid(size_t nid)
{
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey;
    int32_t result;
    int32_t openssl_pkey_type;

    switch (nid) {
    case LIBSPDM_CRYPTO_NID_EDDSA_ED25519:
        openssl_pkey_type = EVP_PKEY_ED25519;
        break;
    case LIBSPDM_CRYPTO_NID_EDDSA_ED448:
        openssl_pkey_type = EVP_PKEY_ED448;
        break;
    default:
        return NULL;
    }

    pkey_ctx = EVP_PKEY_CTX_new_id(openssl_pkey_type, NULL);
    if (pkey_ctx == NULL) {
        return NULL;
    }
    result = EVP_PKEY_keygen_init(pkey_ctx);
    if (result <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }
    pkey = NULL;
    result = EVP_PKEY_keygen(pkey_ctx, &pkey);
    if (result <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pkey_ctx);

    return (void *)pkey;
}

/**
 * Release the specified Ed context.
 *
 * @param[in]  ecd_context  Pointer to the Ed context to be released.
 *
 **/
void libspdm_ecd_free(void *ecd_context)
{
    EVP_PKEY_free((EVP_PKEY *)ecd_context);
}

/**
 * Sets the public key component into the established Ed context.
 *
 * For ed25519, the public_size is 32.
 * For ed448, the public_size is 57.
 *
 * @param[in, out]  ecd_context      Pointer to Ed context being set.
 * @param[in]       public         Pointer to the buffer to receive generated public X,Y.
 * @param[in]       public_size     The size of public buffer in bytes.
 *
 * @retval  true   Ed public key component was set successfully.
 * @retval  false  Invalid EC public key component.
 *
 **/
bool libspdm_ecd_set_pub_key(void *ecd_context, const uint8_t *public_key,
                             size_t public_key_size)
{
    uint32_t final_pub_key_size;
    EVP_PKEY *evp_key;
    EVP_PKEY *new_evp_key;

    if ((ecd_context == NULL) || (public_key == NULL)) {
        return false;
    }

    evp_key = (EVP_PKEY *)ecd_context;

    switch (EVP_PKEY_id(evp_key)) {
    case EVP_PKEY_ED25519:
        final_pub_key_size = 32;
        break;
    case EVP_PKEY_ED448:
        final_pub_key_size = 57;
        break;
    default:
        return false;
    }

    if (final_pub_key_size != public_key_size) {
        return false;
    }

    new_evp_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_id(evp_key), NULL,
                                              public_key, public_key_size);

    if (new_evp_key == NULL) {
        return false;
    }

    if (evp_pkey_copy_downgraded(&evp_key, new_evp_key) != 1) {
        EVP_PKEY_free(new_evp_key);
        return false;
    }

    EVP_PKEY_free(new_evp_key);
    return true;
}

/**
 * Sets the private key component into the established Ed context.
 *
 * For ed25519, the private_size is 32.
 * For ed448, the private_size is 57.
 *
 * @param[in, out]  ecd_context      Pointer to Ed context being set.
 * @param[in]       private         Pointer to the buffer to receive generated private X,Y.
 * @param[in]       private_size     The size of private buffer in bytes.
 *
 * @retval  true   Ed private key component was set successfully.
 * @retval  false  Invalid EC private key component.
 *
 **/
bool libspdm_ecd_set_pri_key(void *ecd_context, const uint8_t *private_key,
                             size_t private_key_size)
{
    uint32_t final_pri_key_size;
    EVP_PKEY *evp_key;
    EVP_PKEY *new_evp_key;

    if ((ecd_context == NULL) || (private_key == NULL)) {
        return false;
    }

    evp_key = (EVP_PKEY *)ecd_context;

    switch (EVP_PKEY_id(evp_key)) {
    case EVP_PKEY_ED25519:
        final_pri_key_size = 32;
        break;
    case EVP_PKEY_ED448:
        final_pri_key_size = 57;
        break;
    default:
        return false;
    }

    if (final_pri_key_size != private_key_size) {
        return false;
    }

    new_evp_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_id(evp_key), NULL,
                                               private_key, private_key_size);
    if (new_evp_key == NULL) {
        return false;
    }

    if (evp_pkey_copy_downgraded(&evp_key, new_evp_key) != 1) {
        EVP_PKEY_free(new_evp_key);
        return false;
    }

    EVP_PKEY_free(new_evp_key);
    return true;
}

/**
 * Gets the public key component from the established Ed context.
 *
 * For ed25519, the public_size is 32.
 * For ed448, the public_size is 57.
 *
 * @param[in, out]  ecd_context      Pointer to Ed context being set.
 * @param[out]      public         Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval  true   Ed key component was retrieved successfully.
 * @retval  false  Invalid EC public key component.
 *
 **/
bool libspdm_ecd_get_pub_key(void *ecd_context, uint8_t *public_key,
                             size_t *public_key_size)
{
    EVP_PKEY *pkey;
    int32_t result;
    uint32_t final_pub_key_size;

    if (ecd_context == NULL || public_key == NULL ||
        public_key_size == NULL) {
        return false;
    }

    pkey = (EVP_PKEY *)ecd_context;
    switch (EVP_PKEY_id(pkey)) {
    case EVP_PKEY_ED25519:
        final_pub_key_size = 32;
        break;
    case EVP_PKEY_ED448:
        final_pub_key_size = 57;
        break;
    default:
        return false;
    }
    if (*public_key_size < final_pub_key_size) {
        *public_key_size = final_pub_key_size;
        return false;
    }
    *public_key_size = final_pub_key_size;
    libspdm_zero_mem(public_key, *public_key_size);
    result = EVP_PKEY_get_raw_public_key(pkey, public_key, public_key_size);
    if (result == 0) {
        return false;
    }

    return true;
}

/**
 * Validates key components of Ed context.
 * NOTE: This function performs integrity checks on all the Ed key material, so
 *      the Ed key structure must contain all the private key data.
 *
 * If ecd_context is NULL, then return false.
 *
 * @param[in]  ecd_context  Pointer to Ed context to check.
 *
 * @retval  true   Ed key components are valid.
 * @retval  false  Ed key components are not valid.
 *
 **/
bool libspdm_ecd_check_key(const void *ecd_context)
{
    /* TBD*/
    return false;
}

/**
 * Generates Ed key and returns Ed public key.
 *
 * For ed25519, the public_size is 32.
 * For ed448, the public_size is 57.
 *
 * If ecd_context is NULL, then return false.
 * If public_size is NULL, then return false.
 * If public_size is large enough but public is NULL, then return false.
 *
 * @param[in, out]  ecd_context      Pointer to the Ed context.
 * @param[out]      public         Pointer to the buffer to receive generated public key.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   Ed public key generation succeeded.
 * @retval false  Ed public key generation failed.
 * @retval false  public_size is not large enough.
 *
 **/
bool libspdm_ecd_generate_key(void *ecd_context, uint8_t *public_key,
                              size_t *public_key_size)
{
    /* TBD*/
    return true;
}

/**
 * Carries out the Ed-DSA signature.
 *
 * This function carries out the Ed-DSA signature.
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If ecd_context is NULL, then return false.
 * If message is NULL, then return false.
 * hash_nid must be NULL.
 * If sig_size is large enough but signature is NULL, then return false.
 *
 * For ed25519, context must be NULL and context_size must be 0.
 * For ed448, context must be maximum of 255 octets.
 *
 * For ed25519, the sig_size is 64. first 32-byte is R, second 32-byte is S.
 * For ed448, the sig_size is 114. first 57-byte is R, second 57-byte is S.
 *
 * @param[in]       ecd_context    Pointer to Ed context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       context      the EDDSA signing context.
 * @param[in]       context_size size of EDDSA signing context.
 * @param[in]       message      Pointer to octet message to be signed (before hash).
 * @param[in]       size         size of the message in bytes.
 * @param[out]      signature    Pointer to buffer to receive Ed-DSA signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                              On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in Ed-DSA.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 *
 **/
bool libspdm_eddsa_sign(const void *ecd_context, size_t hash_nid,
                        const uint8_t *context, size_t context_size,
                        const uint8_t *message, size_t size, uint8_t *signature,
                        size_t *sig_size)
{
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    size_t half_size;
    int32_t result;

    if (ecd_context == NULL || message == NULL) {
        return false;
    }

    if (signature == NULL || sig_size == NULL) {
        return false;
    }

    pkey = (EVP_PKEY *)ecd_context;
    switch (EVP_PKEY_id(pkey)) {
    case EVP_PKEY_ED25519:
        half_size = 32;
        break;
    case EVP_PKEY_ED448:
        half_size = 57;
        break;
    default:
        return false;
    }
    if (*sig_size < (size_t)(half_size * 2)) {
        *sig_size = half_size * 2;
        return false;
    }
    *sig_size = half_size * 2;
    libspdm_zero_mem(signature, *sig_size);

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_NULL:
        break;

    default:
        return false;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return false;
    }
    result = EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    result = EVP_DigestSign(ctx, signature, sig_size, message, size);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    return true;
}

/**
 * Verifies the Ed-DSA signature.
 *
 * If ecd_context is NULL, then return false.
 * If message is NULL, then return false.
 * If signature is NULL, then return false.
 * hash_nid must be NULL.
 *
 * For ed25519, context must be NULL and context_size must be 0.
 * For ed448, context must be maximum of 255 octets.
 *
 * For ed25519, the sig_size is 64. first 32-byte is R, second 32-byte is S.
 * For ed448, the sig_size is 114. first 57-byte is R, second 57-byte is S.
 *
 * @param[in]  ecd_context    Pointer to Ed context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  context      the EDDSA signing context.
 * @param[in]  context_size size of EDDSA signing context.
 * @param[in]  message      Pointer to octet message to be checked (before hash).
 * @param[in]  size         size of the message in bytes.
 * @param[in]  signature    Pointer to Ed-DSA signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in Ed-DSA.
 * @retval  false  Invalid signature or invalid Ed context.
 *
 **/
bool libspdm_eddsa_verify(const void *ecd_context, size_t hash_nid,
                          const uint8_t *context, size_t context_size,
                          const uint8_t *message, size_t size,
                          const uint8_t *signature, size_t sig_size)
{
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    size_t half_size;
    int32_t result;

    if (ecd_context == NULL || message == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    pkey = (EVP_PKEY *)ecd_context;
    switch (EVP_PKEY_id(pkey)) {
    case EVP_PKEY_ED25519:
        half_size = 32;
        break;
    case EVP_PKEY_ED448:
        half_size = 57;
        break;
    default:
        return false;
    }
    if (sig_size != (size_t)(half_size * 2)) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_NULL:
        break;

    default:
        return false;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return false;
    }
    result = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
    result = EVP_DigestVerify(ctx, signature, sig_size, message, size);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    return true;
}
#endif /* (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT) */
