/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * HMAC-SHA3_256/384/512 KDF Wrapper Implementation.
 *
 * RFC 5869: HMAC-based Extract-and-Expand key Derivation Function (HKDF)
 **/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>

bool hkdf_md_extract_and_expand(const EVP_MD *md, const uint8_t *key,
                                size_t key_size, const uint8_t *salt,
                                size_t salt_size, const uint8_t *info,
                                size_t info_size, uint8_t *out,
                                size_t out_size);
bool hkdf_md_extract(const EVP_MD *md, const uint8_t *key,
                     size_t key_size, const uint8_t *salt,
                     size_t salt_size, uint8_t *prk_out,
                     size_t prk_out_size);
bool hkdf_md_expand(const EVP_MD *md, const uint8_t *prk,
                    size_t prk_size, const uint8_t *info,
                    size_t info_size, uint8_t *out, size_t out_size);

/**
 * Derive SHA3_256 HMAC-based Extract-and-Expand key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_256_extract_and_expand(const uint8_t *key, size_t key_size,
                                              const uint8_t *salt, size_t salt_size,
                                              const uint8_t *info, size_t info_size,
                                              uint8_t *out, size_t out_size)
{
    return hkdf_md_extract_and_expand(EVP_sha3_256(), key, key_size, salt,
                                      salt_size, info, info_size, out,
                                      out_size);
}

/**
 * Derive SHA3_256 HMAC-based Extract key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[out]  prk_out           Pointer to buffer to receive hkdf value.
 * @param[in]   prk_out_size       size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_256_extract(const uint8_t *key, size_t key_size,
                                   const uint8_t *salt, size_t salt_size,
                                   uint8_t *prk_out, size_t prk_out_size)
{
    return hkdf_md_extract(EVP_sha3_256(), key, key_size, salt, salt_size,
                           prk_out, prk_out_size);
}

/**
 * Derive SHA3_256 HMAC-based Expand key Derivation Function (HKDF).
 *
 * @param[in]   prk              Pointer to the user-supplied key.
 * @param[in]   prk_size          key size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_256_expand(const uint8_t *prk, size_t prk_size,
                                  const uint8_t *info, size_t info_size,
                                  uint8_t *out, size_t out_size)
{
    return hkdf_md_expand(EVP_sha3_256(), prk, prk_size, info, info_size, out,
                          out_size);
}

/**
 * Derive SHA3_384 HMAC-based Extract-and-Expand key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_384_extract_and_expand(const uint8_t *key, size_t key_size,
                                              const uint8_t *salt, size_t salt_size,
                                              const uint8_t *info, size_t info_size,
                                              uint8_t *out, size_t out_size)
{
    return hkdf_md_extract_and_expand(EVP_sha3_384(), key, key_size, salt,
                                      salt_size, info, info_size, out,
                                      out_size);
}

/**
 * Derive SHA3_384 HMAC-based Extract key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[out]  prk_out           Pointer to buffer to receive hkdf value.
 * @param[in]   prk_out_size       size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_384_extract(const uint8_t *key, size_t key_size,
                                   const uint8_t *salt, size_t salt_size,
                                   uint8_t *prk_out, size_t prk_out_size)
{
    return hkdf_md_extract(EVP_sha3_384(), key, key_size, salt, salt_size,
                           prk_out, prk_out_size);
}

/**
 * Derive SHA3_384 HMAC-based Expand key Derivation Function (HKDF).
 *
 * @param[in]   prk              Pointer to the user-supplied key.
 * @param[in]   prk_size          key size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_384_expand(const uint8_t *prk, size_t prk_size,
                                  const uint8_t *info, size_t info_size,
                                  uint8_t *out, size_t out_size)
{
    return hkdf_md_expand(EVP_sha3_384(), prk, prk_size, info, info_size, out,
                          out_size);
}

/**
 * Derive SHA3_512 HMAC-based Extract-and-Expand key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_512_extract_and_expand(const uint8_t *key, size_t key_size,
                                              const uint8_t *salt, size_t salt_size,
                                              const uint8_t *info, size_t info_size,
                                              uint8_t *out, size_t out_size)
{
    return hkdf_md_extract_and_expand(EVP_sha3_512(), key, key_size, salt,
                                      salt_size, info, info_size, out,
                                      out_size);
}

/**
 * Derive SHA3_512 HMAC-based Extract key Derivation Function (HKDF).
 *
 * @param[in]   key              Pointer to the user-supplied key.
 * @param[in]   key_size          key size in bytes.
 * @param[in]   salt             Pointer to the salt(non-secret) value.
 * @param[in]   salt_size         salt size in bytes.
 * @param[out]  prk_out           Pointer to buffer to receive hkdf value.
 * @param[in]   prk_out_size       size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_512_extract(const uint8_t *key, size_t key_size,
                                   const uint8_t *salt, size_t salt_size,
                                   uint8_t *prk_out, size_t prk_out_size)
{
    return hkdf_md_extract(EVP_sha3_512(), key, key_size, salt, salt_size,
                           prk_out, prk_out_size);
}

/**
 * Derive SHA3_512 HMAC-based Expand key Derivation Function (HKDF).
 *
 * @param[in]   prk              Pointer to the user-supplied key.
 * @param[in]   prk_size          key size in bytes.
 * @param[in]   info             Pointer to the application specific info.
 * @param[in]   info_size         info size in bytes.
 * @param[out]  out              Pointer to buffer to receive hkdf value.
 * @param[in]   out_size          size of hkdf bytes to generate.
 *
 * @retval true   Hkdf generated successfully.
 * @retval false  Hkdf generation failed.
 *
 **/
bool libspdm_hkdf_sha3_512_expand(const uint8_t *prk, size_t prk_size,
                                  const uint8_t *info, size_t info_size,
                                  uint8_t *out, size_t out_size)
{
    return hkdf_md_expand(EVP_sha3_512(), prk, prk_size, info, info_size, out,
                          out_size);
}
