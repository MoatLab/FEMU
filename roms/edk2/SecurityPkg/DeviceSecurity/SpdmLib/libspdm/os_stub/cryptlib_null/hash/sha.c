/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SHA-256/384/512 digest Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"

/**
 * Allocates and initializes one HASH_CTX context for subsequent SHA256 use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, libspdm_sha256_hash_all() returns NULL.
 *
 **/
void *libspdm_sha256_new(void)
{
    LIBSPDM_ASSERT(false);
    return NULL;
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sha256_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void libspdm_sha256_free(void *sha256_ctx)
{
    LIBSPDM_ASSERT(false);
}

/**
 * Initializes user-supplied memory pointed by sha256_context as SHA-256 hash context for
 * subsequent use.
 *
 * If sha256_context is NULL, then return false.
 *
 * @param[out]  sha256_context  Pointer to SHA-256 context being initialized.
 *
 * @retval true   SHA-256 context initialization succeeded.
 * @retval false  SHA-256 context initialization failed.
 *
 **/
bool libspdm_sha256_init(void *sha256_context)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Makes a copy of an existing SHA-256 context.
 *
 * If sha256_context is NULL, then return false.
 * If new_sha256_context is NULL, then return false.
 *
 * @param[in]  sha256_context     Pointer to SHA-256 context being copied.
 * @param[out] new_sha256_context  Pointer to new SHA-256 context.
 *
 * @retval true   SHA-256 context copy succeeded.
 * @retval false  SHA-256 context copy failed.
 *
 **/
bool libspdm_sha256_duplicate(const void *sha256_context,
                              void *new_sha256_context)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Digests the input data and updates SHA-256 context.
 *
 * This function performs SHA-256 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SHA-256 context should be already correctly initialized by libspdm_sha256_init(), and should not be finalized
 * by libspdm_sha256_final(). Behavior with invalid context is undefined.
 *
 * If sha256_context is NULL, then return false.
 *
 * @param[in, out]  sha256_context  Pointer to the SHA-256 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval true   SHA-256 data digest succeeded.
 * @retval false  SHA-256 data digest failed.
 *
 **/
bool libspdm_sha256_update(void *sha256_context, const void *data,
                           size_t data_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Completes computation of the SHA-256 digest value.
 *
 * This function completes SHA-256 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the SHA-256 context cannot
 * be used again.
 * SHA-256 context should be already correctly initialized by libspdm_sha256_init(), and should not be
 * finalized by libspdm_sha256_final(). Behavior with invalid SHA-256 context is undefined.
 *
 * If sha256_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha256_context  Pointer to the SHA-256 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA-256 digest
 *                                value (32 bytes).
 *
 * @retval true   SHA-256 digest computation succeeded.
 * @retval false  SHA-256 digest computation failed.
 *
 **/
bool libspdm_sha256_final(void *sha256_context, uint8_t *hash_value)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Computes the SHA-256 message digest of a input data buffer.
 *
 * This function performs the SHA-256 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SHA-256 digest
 *                         value (32 bytes).
 *
 * @retval true   SHA-256 digest computation succeeded.
 * @retval false  SHA-256 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha256_hash_all(const void *data, size_t data_size,
                             uint8_t *hash_value)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Allocates and initializes one HASH_CTX context for subsequent SHA384 use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, libspdm_sha384_new() returns NULL.
 *
 **/
void *libspdm_sha384_new(void)
{
    LIBSPDM_ASSERT(false);
    return NULL;
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sha384_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void libspdm_sha384_free(void *sha384_ctx)
{
    LIBSPDM_ASSERT(false);
}

/**
 * Initializes user-supplied memory pointed by sha384_context as SHA-384 hash context for
 * subsequent use.
 *
 * If sha384_context is NULL, then return false.
 *
 * @param[out]  sha384_context  Pointer to SHA-384 context being initialized.
 *
 * @retval true   SHA-384 context initialization succeeded.
 * @retval false  SHA-384 context initialization failed.
 *
 **/
bool libspdm_sha384_init(void *sha384_context)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Makes a copy of an existing SHA-384 context.
 *
 * If sha384_context is NULL, then return false.
 * If new_sha384_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  sha384_context     Pointer to SHA-384 context being copied.
 * @param[out] new_sha384_context  Pointer to new SHA-384 context.
 *
 * @retval true   SHA-384 context copy succeeded.
 * @retval false  SHA-384 context copy failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha384_duplicate(const void *sha384_context,
                              void *new_sha384_context)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Digests the input data and updates SHA-384 context.
 *
 * This function performs SHA-384 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SHA-384 context should be already correctly initialized by libspdm_sha384_init(), and should not be finalized
 * by libspdm_sha384_final(). Behavior with invalid context is undefined.
 *
 * If sha384_context is NULL, then return false.
 *
 * @param[in, out]  sha384_context  Pointer to the SHA-384 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval true   SHA-384 data digest succeeded.
 * @retval false  SHA-384 data digest failed.
 *
 **/
bool libspdm_sha384_update(void *sha384_context, const void *data,
                           size_t data_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Completes computation of the SHA-384 digest value.
 *
 * This function completes SHA-384 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the SHA-384 context cannot
 * be used again.
 * SHA-384 context should be already correctly initialized by libspdm_sha384_init(), and should not be
 * finalized by libspdm_sha384_final(). Behavior with invalid SHA-384 context is undefined.
 *
 * If sha384_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha384_context  Pointer to the SHA-384 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA-384 digest
 *                                value (48 bytes).
 *
 * @retval true   SHA-384 digest computation succeeded.
 * @retval false  SHA-384 digest computation failed.
 *
 **/
bool libspdm_sha384_final(void *sha384_context, uint8_t *hash_value)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Computes the SHA-384 message digest of a input data buffer.
 *
 * This function performs the SHA-384 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SHA-384 digest
 *                         value (48 bytes).
 *
 * @retval true   SHA-384 digest computation succeeded.
 * @retval false  SHA-384 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha384_hash_all(const void *data, size_t data_size,
                             uint8_t *hash_value)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Allocates and initializes one HASH_CTX context for subsequent SHA512 use.
 *
 * @return  Pointer to the HASH_CTX context that has been initialized.
 *         If the allocations fails, libspdm_sha512_new() returns NULL.
 *
 **/
void *libspdm_sha512_new(void)
{
    LIBSPDM_ASSERT(false);
    return NULL;
}

/**
 * Release the specified HASH_CTX context.
 *
 * @param[in]  sha512_ctx  Pointer to the HASH_CTX context to be released.
 *
 **/
void libspdm_sha512_free(void *sha512_ctx)
{
    LIBSPDM_ASSERT(false);
}

/**
 * Initializes user-supplied memory pointed by sha512_context as SHA-512 hash context for
 * subsequent use.
 *
 * If sha512_context is NULL, then return false.
 *
 * @param[out]  sha512_context  Pointer to SHA-512 context being initialized.
 *
 * @retval true   SHA-512 context initialization succeeded.
 * @retval false  SHA-512 context initialization failed.
 *
 **/
bool libspdm_sha512_init(void *sha512_context)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Makes a copy of an existing SHA-512 context.
 *
 * If sha512_context is NULL, then return false.
 * If new_sha512_context is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[in]  sha512_context     Pointer to SHA-512 context being copied.
 * @param[out] new_sha512_context  Pointer to new SHA-512 context.
 *
 * @retval true   SHA-512 context copy succeeded.
 * @retval false  SHA-512 context copy failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha512_duplicate(const void *sha512_context,
                              void *new_sha512_context)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Digests the input data and updates SHA-512 context.
 *
 * This function performs SHA-512 digest on a data buffer of the specified size.
 * It can be called multiple times to compute the digest of long or discontinuous data streams.
 * SHA-512 context should be already correctly initialized by libspdm_sha512_init(), and should not be finalized
 * by libspdm_sha512_final(). Behavior with invalid context is undefined.
 *
 * If sha512_context is NULL, then return false.
 *
 * @param[in, out]  sha512_context  Pointer to the SHA-512 context.
 * @param[in]       data           Pointer to the buffer containing the data to be hashed.
 * @param[in]       data_size       size of data buffer in bytes.
 *
 * @retval true   SHA-512 data digest succeeded.
 * @retval false  SHA-512 data digest failed.
 *
 **/
bool libspdm_sha512_update(void *sha512_context, const void *data,
                           size_t data_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Completes computation of the SHA-512 digest value.
 *
 * This function completes SHA-512 hash computation and retrieves the digest value into
 * the specified memory. After this function has been called, the SHA-512 context cannot
 * be used again.
 * SHA-512 context should be already correctly initialized by libspdm_sha512_init(), and should not be
 * finalized by libspdm_sha512_final(). Behavior with invalid SHA-512 context is undefined.
 *
 * If sha512_context is NULL, then return false.
 * If hash_value is NULL, then return false.
 *
 * @param[in, out]  sha512_context  Pointer to the SHA-512 context.
 * @param[out]      hash_value      Pointer to a buffer that receives the SHA-512 digest
 *                                value (64 bytes).
 *
 * @retval true   SHA-512 digest computation succeeded.
 * @retval false  SHA-512 digest computation failed.
 *
 **/
bool libspdm_sha512_final(void *sha512_context, uint8_t *hash_value)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Computes the SHA-512 message digest of a input data buffer.
 *
 * This function performs the SHA-512 message digest of a given data buffer, and places
 * the digest value into the specified memory.
 *
 * If this interface is not supported, then return false.
 *
 * @param[in]   data        Pointer to the buffer containing the data to be hashed.
 * @param[in]   data_size    size of data buffer in bytes.
 * @param[out]  hash_value   Pointer to a buffer that receives the SHA-512 digest
 *                         value (64 bytes).
 *
 * @retval true   SHA-512 digest computation succeeded.
 * @retval false  SHA-512 digest computation failed.
 * @retval false  This interface is not supported.
 *
 **/
bool libspdm_sha512_hash_all(const void *data, size_t data_size,
                             uint8_t *hash_value)
{
    LIBSPDM_ASSERT(false);
    return false;
}
