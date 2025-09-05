/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Diffie-Hellman Wrapper Implementation over.
 *
 * RFC 7919 - Negotiated Finite Field Diffie-Hellman Ephemeral (FFDHE) Parameters
 **/

#include "internal_crypt_lib.h"

/**
 * Allocates and Initializes one Diffie-Hellman context for subsequent use
 * with the NID.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Diffie-Hellman context that has been initialized.
 *         If the allocations fails, dh_new() returns NULL.
 *
 **/
void *libspdm_dh_new_by_nid(size_t nid)
{
    LIBSPDM_ASSERT(false);
    return NULL;
}

/**
 * Release the specified DH context.
 *
 * If dh_context is NULL, then return false.
 *
 * @param[in]  dh_context  Pointer to the DH context to be released.
 *
 **/
void libspdm_dh_free(void *dh_context)
{
    LIBSPDM_ASSERT(false);
}

/**
 * Generates DH parameter.
 *
 * Given generator g, and length of prime number p in bits, this function generates p,
 * and sets DH context according to value of g and p.
 *
 * If dh_context is NULL, then return false.
 * If prime is NULL, then return false.
 *
 * @param[in, out]  dh_context    Pointer to the DH context.
 * @param[in]       generator    value of generator.
 * @param[in]       prime_length  length in bits of prime to be generated.
 * @param[out]      prime        Pointer to the buffer to receive the generated prime number.
 *
 * @retval true   DH parameter generation succeeded.
 * @retval false  value of generator is not supported.
 * @retval false  PRNG fails to generate random prime number with prime_length.
 *
 **/
bool libspdm_dh_generate_parameter(void *dh_context, size_t generator,
                                   size_t prime_length, uint8_t *prime)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Sets generator and prime parameters for DH.
 *
 * Given generator g, and prime number p, this function and sets DH
 * context accordingly.
 *
 * If dh_context is NULL, then return false.
 * If prime is NULL, then return false.
 *
 * @param[in, out]  dh_context    Pointer to the DH context.
 * @param[in]       generator    value of generator.
 * @param[in]       prime_length  length in bits of prime to be generated.
 * @param[in]       prime        Pointer to the prime number.
 *
 * @retval true   DH parameter setting succeeded.
 * @retval false  value of generator is not supported.
 * @retval false  value of generator is not suitable for the prime.
 * @retval false  value of prime is not a prime number.
 * @retval false  value of prime is not a safe prime number.
 *
 **/
bool libspdm_dh_set_parameter(void *dh_context, size_t generator,
                              size_t prime_length, const uint8_t *prime)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Generates DH public key.
 *
 * This function generates random secret exponent, and computes the public key, which is
 * returned via parameter public_key and public_key_size. DH context is updated accordingly.
 * If the public_key buffer is too small to hold the public key, false is returned and
 * public_key_size is set to the required buffer size to obtain the public key.
 *
 * If dh_context is NULL, then return false.
 * If public_key_size is NULL, then return false.
 * If public_key_size is large enough but public_key is NULL, then return false.
 *
 * @param[in, out]  dh_context      Pointer to the DH context.
 * @param[out]      public_key      Pointer to the buffer to receive generated public key.
 * @param[in, out]  public_key_size  On input, the size of public_key buffer in bytes.
 *                                On output, the size of data returned in public_key buffer in bytes.
 *
 * @retval true   DH public key generation succeeded.
 * @retval false  DH public key generation failed.
 * @retval false  public_key_size is not large enough.
 *
 **/
bool libspdm_dh_generate_key(void *dh_context, uint8_t *public_key,
                             size_t *public_key_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}

/**
 * Computes exchanged common key.
 *
 * Given peer's public key, this function computes the exchanged common key, based on its own
 * context including value of prime modulus and random secret exponent.
 *
 * If dh_context is NULL, then return false.
 * If peer_public_key is NULL, then return false.
 * If key_size is NULL, then return false.
 * If key is NULL, then return false.
 * If key_size is not large enough, then return false.
 *
 * @param[in, out]  dh_context          Pointer to the DH context.
 * @param[in]       peer_public_key      Pointer to the peer's public key.
 * @param[in]       peer_public_key_size  size of peer's public key in bytes.
 * @param[out]      key                Pointer to the buffer to receive generated key.
 * @param[in, out]  key_size            On input, the size of key buffer in bytes.
 *                                    On output, the size of data returned in key buffer in bytes.
 *
 * @retval true   DH exchanged key generation succeeded.
 * @retval false  DH exchanged key generation failed.
 * @retval false  key_size is not large enough.
 *
 **/
bool libspdm_dh_compute_key(void *dh_context, const uint8_t *peer_public_key,
                            size_t peer_public_key_size, uint8_t *key,
                            size_t *key_size)
{
    LIBSPDM_ASSERT(false);
    return false;
}
