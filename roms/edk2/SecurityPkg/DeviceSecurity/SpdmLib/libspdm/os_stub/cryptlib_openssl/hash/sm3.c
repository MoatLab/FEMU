/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SM3 digest Wrapper Implementations.
 **/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>

void *hash_md_new(void);
void hash_md_free(const void *md_ctx);
bool hash_md_init(const EVP_MD *md, void *md_ctx);
bool hash_md_duplicate(const void *md_ctx, void *new_md_ctx);
bool hash_md_update(const void *md_ctx, const void *data, size_t data_size);
bool hash_md_final(const void *md_ctx, void *hash_value);
bool hash_md_hash_all(const EVP_MD *md, const void *data, size_t data_size,
                      uint8_t *hash_value);

/**
 * Allocates and initializes one HASH_CTX context for subsequent SM3-256 use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, libspdm_sm3_256_new() returns NULL.
 *
 **/
void *libspdm_sm3_256_new(void)
{
    return hash_md_new();
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sm3_256_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void libspdm_sm3_256_free(void *sm3_256_ctx)
{
    hash_md_free(sm3_256_ctx);
}

/**
 * Initializes user-supplied memory pointed by sm3_context as SM3 hash context for
 * subsequent use.
 *
 * If sm3_context is NULL, then return false.
 *
 * @param[out]  sm3_context  Pointer to SM3 context being initialized.
 *
 * @retval true   SM3 context initialization succeeded.
 * @retval false  SM3 context initialization failed.
 *
 **/
bool libspdm_sm3_256_init(void *sm3_context)
{
    return hash_md_init (EVP_sm3(), sm3_context);
}

/**
 * Makes a copy of an existing SM3 context.
 *
 * If sm3_context is NULL, then return false.
 * If new_sm3_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  sm3_context     Pointer to SM3 context being copied.
 * @param[out] new_sm3_context  Pointer to new SM3 context.
 *
 * @retval true   SM3 context copy succeeded.
 * @retval false  SM3 context copy failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sm3_256_duplicate(const void *sm3_context, void *new_sm3_context)
{
    return hash_md_duplicate (sm3_context, new_sm3_context);
}

/**
 * Digests the input data and updates SM3 context.
 *
 * This function performs SM3 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SM3 context should be already correctly initialized by sm3_init(), and should not be finalized
 * by sm3_final(). Behavior with invalid context is undefined.
 *
 * If sm3_context is NULL, then return false.
 *
 * @param[in, out]  sm3_context     Pointer to the SM3 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval true   SM3 data digest succeeded.
 * @retval false  SM3 data digest failed.
 *
 **/
bool libspdm_sm3_256_update(void *sm3_context, const void *data,
                            size_t data_size)
{
    return hash_md_update (sm3_context, data, data_size);
}

/**
 * Completes computation of the SM3 digest value.
 *
 * This function completes SM3 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the SM3 context cannot
 * be used again.
 * SM3 context should be already correctly initialized by sm3_init(), and should not be
 * finalized by sm3_final(). Behavior with invalid SM3 context is undefined.
 *
 * If sm3_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sm3_context     Pointer to the SM3 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SM3 digest
 *                                value (32 bytes).
 *
 * @retval true   SM3 digest computation succeeded.
 * @retval false  SM3 digest computation failed.
 *
 **/
bool libspdm_sm3_256_final(void *sm3_context, uint8_t *hash_value)
{
    return hash_md_final (sm3_context, hash_value);
}

/**
 * Computes the SM3 message digest of a input data buffer.
 *
 * This function performs the SM3 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SM3 digest
 *                         value (32 bytes).
 *
 * @retval true   SM3 digest computation succeeded.
 * @retval false  SM3 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sm3_256_hash_all(const void *data, size_t data_size,
                              uint8_t *hash_value)
{
    return hash_md_hash_all (EVP_sm3(), data, data_size, hash_value);
}
