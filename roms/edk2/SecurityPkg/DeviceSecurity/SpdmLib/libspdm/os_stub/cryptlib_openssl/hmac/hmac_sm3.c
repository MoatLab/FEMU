/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * HMAC-SM3 Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <openssl/hmac.h>

void *hmac_md_new(void);
void hmac_md_free(void *hmac_md_ctx);
bool hmac_md_set_key(const EVP_MD *md, void *hmac_md_ctx,
                     const uint8_t *key, size_t key_size);
bool hmac_md_duplicate(const void *hmac_md_ctx, void *new_hmac_md_ctx);
bool hmac_md_update(void *hmac_md_ctx, const void *data,
                    size_t data_size);
bool hmac_md_final(void *hmac_md_ctx, uint8_t *hmac_value);
bool hmac_md_all(const EVP_MD *md, const void *data,
                 size_t data_size, const uint8_t *key, size_t key_size,
                 uint8_t *hmac_value);

/**
 * Allocates and initializes one HMAC_CTX context for subsequent HMAC-SM3_256 use.
 *
 * @return  Pointer to the HMAC_CTX context that has been initialized.
 *         If the allocations fails, libspdm_hmac_sm3_256_new() returns NULL.
 *
 **/
void *libspdm_hmac_sm3_256_new(void)
{
    return hmac_md_new();
}

/**
 * Release the specified HMAC_CTX context.
 *
 * @param[in]  hmac_sm3_256_ctx  Pointer to the HMAC_CTX context to be released.
 *
 **/
void libspdm_hmac_sm3_256_free(void *hmac_sm3_256_ctx)
{
    hmac_md_free(hmac_sm3_256_ctx);
}

/**
 * Set user-supplied key for subsequent use. It must be done before any
 * calling to libspdm_hmac_sm3_256_update().
 *
 * If hmac_sm3_256_ctx is NULL, then return false.
 *
 * @param[out]  hmac_sm3_256_ctx  Pointer to HMAC-SM3_256 context.
 * @param[in]   key                Pointer to the user-supplied key.
 * @param[in]   key_size            key size in bytes.
 *
 * @retval true   The key is set successfully.
 * @retval false  The key is set unsuccessfully.
 *
 **/
bool libspdm_hmac_sm3_256_set_key(void *hmac_sm3_256_ctx, const uint8_t *key,
                                  size_t key_size)
{
    return hmac_md_set_key(EVP_sm3(), hmac_sm3_256_ctx, key, key_size);
}

/**
 * Makes a copy of an existing HMAC-SM3_256 context.
 *
 * If hmac_sm3_256_ctx is NULL, then return false.
 * If new_hmac_sm3_256_ctx is NULL, then return false.
 *
 * @param[in]  hmac_sm3_256_ctx     Pointer to HMAC-SM3_256 context being copied.
 * @param[out] new_hmac_sm3_256_ctx  Pointer to new HMAC-SM3_256 context.
 *
 * @retval true   HMAC-SM3_256 context copy succeeded.
 * @retval false  HMAC-SM3_256 context copy failed.
 *
 **/
bool libspdm_hmac_sm3_256_duplicate(const void *hmac_sm3_256_ctx,
                                    void *new_hmac_sm3_256_ctx)
{
    return hmac_md_duplicate(hmac_sm3_256_ctx, new_hmac_sm3_256_ctx);
}

/**
 * Digests the input data and updates HMAC-SM3_256 context.
 *
 * This function performs HMAC-SM3_256 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * HMAC-SM3_256 context should be initialized by libspdm_hmac_sm3_256_new(), and should not be finalized
 * by libspdm_hmac_sm3_256_final(). Behavior with invalid context is undefined.
 *
 * If hmac_sm3_256_ctx is NULL, then return false.
 *
 * @param[in, out]  hmac_sm3_256_ctx Pointer to the HMAC-SM3_256 context.
 * @param[in]       data              Pointer to the buffer containing the data to be digested.
 * @param[in]       data_size          size of data buffer in bytes.
 *
 * @retval true   HMAC-SM3_256 data digest succeeded.
 * @retval false  HMAC-SM3_256 data digest failed.
 *
 **/
bool libspdm_hmac_sm3_256_update(void *hmac_sm3_256_ctx, const void *data,
                                 size_t data_size)
{
    return hmac_md_update(hmac_sm3_256_ctx, data, data_size);
}

/**
 * Completes computation of the HMAC-SM3_256 digest value.
 *
 * This function completes HMAC-SM3_256 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the HMAC-SM3_256 context cannot
 * be used again.
 * HMAC-SM3_256 context should be initialized by libspdm_hmac_sm3_256_new(), and should not be finalized
 * by libspdm_hmac_sm3_256_final(). Behavior with invalid HMAC-SM3_256 context is undefined.
 *
 * If hmac_sm3_256_ctx is NULL, then return false.
 * If hmac_value is NULL, then return false.
 *
 * @param[in, out]  hmac_sm3_256_ctx  Pointer to the HMAC-SM3_256 context.
 * @param[out]      hmac_value          Pointer to a buffer that receives the HMAC-SM3_256 digest
 *                                    value (32 bytes).
 *
 * @retval true   HMAC-SM3_256 digest computation succeeded.
 * @retval false  HMAC-SM3_256 digest computation failed.
 *
 **/
bool libspdm_hmac_sm3_256_final(void *hmac_sm3_256_ctx, uint8_t *hmac_value)
{
    return hmac_md_final(hmac_sm3_256_ctx, hmac_value);
}

/**
 * Computes the HMAC-SM3_256 digest of a input data buffer.
 *
 * This function performs the HMAC-SM3_256 digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be digested.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[in]   key         Pointer to the user-supplied key.
 * @param[in]   key_size     key size in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the HMAC-SM3_256 digest
 *                         value (32 bytes).
 *
 * @retval true   HMAC-SM3_256 digest computation succeeded.
 * @retval false  HMAC-SM3_256 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_hmac_sm3_256_all(const void *data, size_t data_size,
                              const uint8_t *key, size_t key_size,
                              uint8_t *hmac_value)
{
    return hmac_md_all(EVP_sm3(), data, data_size, key, key_size,
                       hmac_value);
}
