/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SHA3-256/384/512 and Shake-256 digest Wrapper Implementation
 **/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>

void *hash_md_new(void);
void hash_md_free(void *md_ctx);
bool hash_md_init(const EVP_MD *md, void *md_ctx);
bool hash_md_duplicate(const void *md_ctx, void *new_md_ctx);
bool hash_md_update(void *md_ctx, const void *data, size_t data_size);
bool hash_md_final(void *md_ctx, void *hash_value);
bool hash_md_hash_all(const EVP_MD *md, const void *data, size_t data_size,
                      uint8_t *hash_value);

/**
 * Allocates and initializes one HASH_CTX context for subsequent SHA3-256 use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, libspdm_sha3_256_new() returns NULL.
 *
 **/
void *libspdm_sha3_256_new(void)
{
    return hash_md_new();
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sha3_256_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void libspdm_sha3_256_free(void *sha3_256_ctx)
{
    hash_md_free(sha3_256_ctx);
}

/**
 * Initializes user-supplied memory pointed by sha3_256_context as SHA3-256 hash context for
 * subsequent use.
 *
 * If sha3_256_context is NULL, then return false.
 *
 * @param[out]  sha3_256_context  Pointer to SHA3-256 context being initialized.
 *
 * @retval true   SHA3-256 context initialization succeeded.
 * @retval false  SHA3-256 context initialization failed.
 *
 **/
bool libspdm_sha3_256_init(void *sha3_256_context)
{
    return hash_md_init (EVP_sha3_256(), sha3_256_context);
}

/**
 * Makes a copy of an existing SHA3-256 context.
 *
 * If sha3_256_context is NULL, then return false.
 * If new_sha3_256_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  sha3_256_context     Pointer to SHA3-256 context being copied.
 * @param[out] new_sha3_256_context  Pointer to new SHA3-256 context.
 *
 * @retval true   SHA3-256 context copy succeeded.
 * @retval false  SHA3-256 context copy failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha3_256_duplicate(const void *sha3_256_context,
                                void *new_sha3_256_context)
{
    return hash_md_duplicate (sha3_256_context, new_sha3_256_context);
}

/**
 * Digests the input data and updates SHA3-256 context.
 *
 * This function performs SHA3-256 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SHA3-256 context should be already correctly initialized by libspdm_sha3_256_init(), and should not be finalized
 * by libspdm_sha3_256_final(). Behavior with invalid context is undefined.
 *
 * If sha3_256_context is NULL, then return false.
 *
 * @param[in, out]  sha3_256_context  Pointer to the SHA3-256 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval true   SHA3-256 data digest succeeded.
 * @retval false  SHA3-256 data digest failed.
 *
 **/
bool libspdm_sha3_256_update(void *sha3_256_context, const void *data,
                             size_t data_size)
{
    return hash_md_update (sha3_256_context, data, data_size);
}

/**
 * Completes computation of the SHA3-256 digest value.
 *
 * This function completes SHA3-256 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the SHA3-256 context cannot
 * be used again.
 * SHA3-256 context should be already correctly initialized by libspdm_sha3_256_init(), and should not be
 * finalized by libspdm_sha3_256_final(). Behavior with invalid SHA3-256 context is undefined.
 *
 * If sha3_256_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha3_256_context  Pointer to the SHA3-256 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA3-256 digest
 *                                value (256 / 8 bytes).
 *
 * @retval true   SHA3-256 digest computation succeeded.
 * @retval false  SHA3-256 digest computation failed.
 *
 **/
bool libspdm_sha3_256_final(void *sha3_256_context, uint8_t *hash_value)
{
    return hash_md_final (sha3_256_context, hash_value);
}

/**
 * Computes the SHA3-256 message digest of a input data buffer.
 *
 * This function performs the SHA3-256 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SHA3-256 digest
 *                         value (256 / 8 bytes).
 *
 * @retval true   SHA3-256 digest computation succeeded.
 * @retval false  SHA3-256 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha3_256_hash_all(const void *data, size_t data_size,
                               uint8_t *hash_value)
{
    return hash_md_hash_all (EVP_sha3_256(), data, data_size, hash_value);
}

/**
 * Allocates and initializes one HASH_CTX context for subsequent SHA3-384 use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, libspdm_sha3_384_new() returns NULL.
 *
 **/
void *libspdm_sha3_384_new(void)
{
    return hash_md_new();
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sha3_384_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void libspdm_sha3_384_free(void *sha3_384_ctx)
{
    hash_md_free(sha3_384_ctx);
}

/**
 * Initializes user-supplied memory pointed by sha3_384_context as SHA3-384 hash context for
 * subsequent use.
 *
 * If sha3_384_context is NULL, then return false.
 *
 * @param[out]  sha3_384_context  Pointer to SHA3-384 context being initialized.
 *
 * @retval true   SHA3-384 context initialization succeeded.
 * @retval false  SHA3-384 context initialization failed.
 *
 **/
bool libspdm_sha3_384_init(void *sha3_384_context)
{
    return hash_md_init (EVP_sha3_384(), sha3_384_context);
}

/**
 * Makes a copy of an existing SHA3-384 context.
 *
 * If sha3_384_context is NULL, then return false.
 * If new_sha3_384_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  sha3_384_context     Pointer to SHA3-384 context being copied.
 * @param[out] new_sha3_384_context  Pointer to new SHA3-384 context.
 *
 * @retval true   SHA3-384 context copy succeeded.
 * @retval false  SHA3-384 context copy failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha3_384_duplicate(const void *sha3_384_context,
                                void *new_sha3_384_context)
{
    return hash_md_duplicate (sha3_384_context, new_sha3_384_context);
}

/**
 * Digests the input data and updates SHA3-384 context.
 *
 * This function performs SHA3-384 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SHA3-384 context should be already correctly initialized by libspdm_sha3_384_init(), and should not be finalized
 * by libspdm_sha3_384_final(). Behavior with invalid context is undefined.
 *
 * If sha3_384_context is NULL, then return false.
 *
 * @param[in, out]  sha3_384_context  Pointer to the SHA3-384 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval true   SHA3-384 data digest succeeded.
 * @retval false  SHA3-384 data digest failed.
 *
 **/
bool libspdm_sha3_384_update(void *sha3_384_context, const void *data,
                             size_t data_size)
{
    return hash_md_update (sha3_384_context, data, data_size);
}

/**
 * Completes computation of the SHA3-384 digest value.
 *
 * This function completes SHA3-384 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the SHA3-384 context cannot
 * be used again.
 * SHA3-384 context should be already correctly initialized by libspdm_sha3_384_init(), and should not be
 * finalized by libspdm_sha3_384_final(). Behavior with invalid SHA3-384 context is undefined.
 *
 * If sha3_384_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha3_384_context  Pointer to the SHA3-384 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA3-384 digest
 *                                value (384 / 8 bytes).
 *
 * @retval true   SHA3-384 digest computation succeeded.
 * @retval false  SHA3-384 digest computation failed.
 *
 **/
bool libspdm_sha3_384_final(void *sha3_384_context, uint8_t *hash_value)
{
    return hash_md_final (sha3_384_context, hash_value);
}

/**
 * Computes the SHA3-384 message digest of a input data buffer.
 *
 * This function performs the SHA3-384 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SHA3-384 digest
 *                         value (384 / 8 bytes).
 *
 * @retval true   SHA3-384 digest computation succeeded.
 * @retval false  SHA3-384 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha3_384_hash_all(const void *data, size_t data_size,
                               uint8_t *hash_value)
{
    return hash_md_hash_all (EVP_sha3_384(), data, data_size, hash_value);
}

/**
 * Allocates and initializes one HASH_CTX context for subsequent SHA3-512 use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, libspdm_sha3_512_new() returns NULL.
 *
 **/
void *libspdm_sha3_512_new(void)
{
    return hash_md_new();
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sha3_512_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void libspdm_sha3_512_free(void *sha3_512_ctx)
{
    hash_md_free(sha3_512_ctx);
}

/**
 * Initializes user-supplied memory pointed by sha3_512_context as SHA3-512 hash context for
 * subsequent use.
 *
 * If sha3_512_context is NULL, then return false.
 *
 * @param[out]  sha3_512_context  Pointer to SHA3-512 context being initialized.
 *
 * @retval true   SHA3-512 context initialization succeeded.
 * @retval false  SHA3-512 context initialization failed.
 *
 **/
bool libspdm_sha3_512_init(void *sha3_512_context)
{
    return hash_md_init (EVP_sha3_512(), sha3_512_context);
}

/**
 * Makes a copy of an existing SHA3-512 context.
 *
 * If sha3_512_context is NULL, then return false.
 * If new_sha3_512_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  sha3_512_context     Pointer to SHA3-512 context being copied.
 * @param[out] new_sha3_512_context  Pointer to new SHA3-512 context.
 *
 * @retval true   SHA3-512 context copy succeeded.
 * @retval false  SHA3-512 context copy failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha3_512_duplicate(const void *sha3_512_context,
                                void *new_sha3_512_context)
{
    return hash_md_duplicate (sha3_512_context, new_sha3_512_context);
}

/**
 * Digests the input data and updates SHA3-512 context.
 *
 * This function performs SHA3-512 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SHA3-512 context should be already correctly initialized by libspdm_sha3_512_init(), and should not be finalized
 * by libspdm_sha3_512_final(). Behavior with invalid context is undefined.
 *
 * If sha3_512_context is NULL, then return false.
 *
 * @param[in, out]  sha3_512_context  Pointer to the SHA3-512 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval true   SHA3-512 data digest succeeded.
 * @retval false  SHA3-512 data digest failed.
 *
 **/
bool libspdm_sha3_512_update(void *sha3_512_context, const void *data,
                             size_t data_size)
{
    return hash_md_update (sha3_512_context, data, data_size);
}

/**
 * Completes computation of the SHA3-512 digest value.
 *
 * This function completes SHA3-512 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the SHA3-512 context cannot
 * be used again.
 * SHA3-512 context should be already correctly initialized by libspdm_sha3_512_init(), and should not be
 * finalized by libspdm_sha3_512_final(). Behavior with invalid SHA3-512 context is undefined.
 *
 * If sha3_512_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha3_512_context  Pointer to the SHA3-512 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA3-512 digest
 *                                value (512 / 8 bytes).
 *
 * @retval true   SHA3-512 digest computation succeeded.
 * @retval false  SHA3-512 digest computation failed.
 *
 **/
bool libspdm_sha3_512_final(void *sha3_512_context, uint8_t *hash_value)
{
    return hash_md_final (sha3_512_context, hash_value);
}

/**
 * Computes the SHA3-512 message digest of a input data buffer.
 *
 * This function performs the SHA3-512 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SHA3-512 digest
 *                         value (512 / 8 bytes).
 *
 * @retval true   SHA3-512 digest computation succeeded.
 * @retval false  SHA3-512 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha3_512_hash_all(const void *data, size_t data_size,
                               uint8_t *hash_value)
{
    return hash_md_hash_all (EVP_sha3_512(), data, data_size, hash_value);
}
