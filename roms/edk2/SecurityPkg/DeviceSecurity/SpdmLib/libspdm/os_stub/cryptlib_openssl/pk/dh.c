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
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/objects.h>

#if LIBSPDM_FFDHE_SUPPORT

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
    switch (nid) {
    case LIBSPDM_CRYPTO_NID_FFDHE2048:
        return DH_new_by_nid(NID_ffdhe2048);
    case LIBSPDM_CRYPTO_NID_FFDHE3072:
        return DH_new_by_nid(NID_ffdhe3072);
    case LIBSPDM_CRYPTO_NID_FFDHE4096:
        return DH_new_by_nid(NID_ffdhe4096);
    default:
        return NULL;
    }
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

    /* Free OpenSSL DH context*/

    DH_free((DH *)dh_context);
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
    bool ret_val;
    BIGNUM *bn_p;


    /* Check input parameters.*/

    if (dh_context == NULL || prime == NULL || prime_length > INT_MAX) {
        return false;
    }

    if (generator != DH_GENERATOR_2 && generator != DH_GENERATOR_5) {
        return false;
    }

    ret_val = (bool)DH_generate_parameters_ex(
        dh_context, (uint32_t)prime_length, (uint32_t)generator, NULL);
    if (!ret_val) {
        return false;
    }

    DH_get0_pqg(dh_context, (const BIGNUM **)&bn_p, NULL, NULL);
    BN_bn2bin(bn_p, prime);

    return true;
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
    DH *dh;
    BIGNUM *bn_p;
    BIGNUM *bn_g;


    /* Check input parameters.*/

    if (dh_context == NULL || prime == NULL || prime_length > INT_MAX) {
        return false;
    }

    if (generator != DH_GENERATOR_2 && generator != DH_GENERATOR_5) {
        return false;
    }


    /* Set the generator and prime parameters for DH object.*/

    dh = (DH *)dh_context;
    bn_p = BN_bin2bn((const unsigned char *)prime, (int)(prime_length / 8),
                     NULL);
    bn_g = BN_bin2bn((const unsigned char *)&generator, 1, NULL);
    if ((bn_p == NULL) || (bn_g == NULL) ||
        !DH_set0_pqg(dh, bn_p, NULL, bn_g)) {
        goto error;
    }

    return true;

error:
    BN_free(bn_p);
    BN_free(bn_g);

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
 * For FFDHE2048, the public_size is 256.
 * For FFDHE3072, the public_size is 384.
 * For FFDHE4096, the public_size is 512.
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
    bool ret_val;
    DH *dh;
    BIGNUM *dh_pub_key;
    int size;
    size_t final_pub_key_size;


    /* Check input parameters.*/

    if (dh_context == NULL || public_key_size == NULL) {
        return false;
    }

    if (public_key == NULL && *public_key_size != 0) {
        return false;
    }

    dh = (DH *)dh_context;
    switch (DH_size(dh)) {
    case 256:
        final_pub_key_size = 256;
        break;
    case 384:
        final_pub_key_size = 384;
        break;
    case 512:
        final_pub_key_size = 512;
        break;
    default:
        return false;
    }

    if (*public_key_size < final_pub_key_size) {
        *public_key_size = final_pub_key_size;
        return false;
    }
    *public_key_size = final_pub_key_size;

    ret_val = (bool)DH_generate_key(dh_context);
    if (ret_val) {
        DH_get0_key(dh, (const BIGNUM **)&dh_pub_key, NULL);
        size = BN_num_bytes(dh_pub_key);
        if (size <= 0) {
            return false;
        }
        LIBSPDM_ASSERT((size_t)size <= final_pub_key_size);

        if (public_key != NULL) {
            libspdm_zero_mem(public_key, *public_key_size);
            BN_bn2bin(dh_pub_key,
                      &public_key[0 + final_pub_key_size - size]);
        }
    }

    return ret_val;
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
 * For FFDHE2048, the peer_public_size and key_size is 256.
 * For FFDHE3072, the peer_public_size and key_size is 384.
 * For FFDHE4096, the peer_public_size and key_size is 512.
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
    BIGNUM *bn;
    int size;
    DH *dh;
    size_t final_key_size;


    /* Check input parameters.*/

    if (dh_context == NULL || peer_public_key == NULL || key_size == NULL ||
        key == NULL) {
        return false;
    }

    if (peer_public_key_size > INT_MAX) {
        return false;
    }

    bn = BN_bin2bn(peer_public_key, (uint32_t)peer_public_key_size, NULL);
    if (bn == NULL) {
        return false;
    }

    dh = (DH *)dh_context;
    switch (DH_size(dh)) {
    case 256:
        final_key_size = 256;
        break;
    case 384:
        final_key_size = 384;
        break;
    case 512:
        final_key_size = 512;
        break;
    default:
        BN_free(bn);
        return false;
    }
    if (*key_size < final_key_size) {
        *key_size = final_key_size;
        BN_free(bn);
        return false;
    }

    size = DH_compute_key_padded(key, bn, dh_context);
    BN_free(bn);
    if (size < 0) {
        return false;
    }
    if ((size_t)size != final_key_size) {
        return false;
    }

    *key_size = size;
    return true;
}

#endif /* LIBSPDM_FFDHE_SUPPORT */
