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
#include <mbedtls/dhm.h>
#include <mbedtls/bignum.h>
#include <string.h>

#if LIBSPDM_FFDHE_SUPPORT

static const unsigned char m_ffehde2048_p[] =
    MBEDTLS_DHM_RFC7919_FFDHE2048_P_BIN;
static const unsigned char m_ffehde3072_p[] =
    MBEDTLS_DHM_RFC7919_FFDHE3072_P_BIN;
static const unsigned char m_ffehde4096_p[] =
    MBEDTLS_DHM_RFC7919_FFDHE4096_P_BIN;
static const unsigned char m_ffehde2048_g[] =
    MBEDTLS_DHM_RFC7919_FFDHE2048_G_BIN;
static const unsigned char m_ffehde3072_g[] =
    MBEDTLS_DHM_RFC7919_FFDHE3072_G_BIN;
static const unsigned char m_ffehde4096_g[] =
    MBEDTLS_DHM_RFC7919_FFDHE4096_G_BIN;

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
    mbedtls_dhm_context *ctx;
    int ret;

    ctx = allocate_zero_pool(sizeof(mbedtls_dhm_context));
    if (ctx == NULL) {
        return NULL;
    }

    mbedtls_dhm_init(ctx);

    switch (nid) {
    case LIBSPDM_CRYPTO_NID_FFDHE2048:
        ret = mbedtls_mpi_read_binary(&ctx->P, m_ffehde2048_p,
                                      sizeof(m_ffehde2048_p));
        if (ret != 0) {
            goto error;
        }
        ret = mbedtls_mpi_read_binary(&ctx->G, m_ffehde2048_g,
                                      sizeof(m_ffehde2048_g));
        if (ret != 0) {
            goto error;
        }
        break;
    case LIBSPDM_CRYPTO_NID_FFDHE3072:
        ret = mbedtls_mpi_read_binary(&ctx->P, m_ffehde3072_p,
                                      sizeof(m_ffehde3072_p));
        if (ret != 0) {
            goto error;
        }
        ret = mbedtls_mpi_read_binary(&ctx->G, m_ffehde3072_g,
                                      sizeof(m_ffehde3072_g));
        if (ret != 0) {
            goto error;
        }
        break;
    case LIBSPDM_CRYPTO_NID_FFDHE4096:
        ret = mbedtls_mpi_read_binary(&ctx->P, m_ffehde4096_p,
                                      sizeof(m_ffehde4096_p));
        if (ret != 0) {
            goto error;
        }
        ret = mbedtls_mpi_read_binary(&ctx->G, m_ffehde4096_g,
                                      sizeof(m_ffehde4096_g));
        if (ret != 0) {
            goto error;
        }
        break;
    default:
        goto error;
    }
    ctx->len = mbedtls_mpi_size(&ctx->P);
    return ctx;
error:
    free_pool(ctx);
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
    mbedtls_dhm_free(dh_context);
    free_pool(dh_context);
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
    int ret;
    mbedtls_dhm_context *ctx;
    size_t final_pub_key_size;


    /* Check input parameters.*/

    if (dh_context == NULL || public_key_size == NULL) {
        return false;
    }

    if (public_key == NULL && *public_key_size != 0) {
        return false;
    }

    ctx = dh_context;
    switch (mbedtls_mpi_size(&ctx->P)) {
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
    libspdm_zero_mem(public_key, *public_key_size);

    ret = mbedtls_dhm_make_public(dh_context, (uint32_t)*public_key_size,
                                  public_key, (uint32_t)*public_key_size,
                                  libspdm_myrand, NULL);
    if (ret != 0) {
        return false;
    }

    return true;
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
 * For FFDHE2048, the peer_public_size is 256.
 * For FFDHE3072, the peer_public_size is 384.
 * For FFDHE4096, the peer_public_size is 512.
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
    int ret;
    mbedtls_dhm_context *ctx;
    size_t return_size;
    size_t dh_key_size;

    /* Check input parameters.*/

    if (dh_context == NULL || peer_public_key == NULL || key_size == NULL ||
        key == NULL) {
        return false;
    }

    if (peer_public_key_size > INT_MAX) {
        return false;
    }

    ctx = dh_context;
    switch (mbedtls_mpi_size(&ctx->P)) {
    case 256:
        dh_key_size = 256;
        break;
    case 384:
        dh_key_size = 384;
        break;
    case 512:
        dh_key_size = 512;
        break;
    default:
        return false;
    }
    if (peer_public_key_size != dh_key_size) {
        return false;
    }
    if (*key_size < dh_key_size) {
        return false;
    }
    *key_size = dh_key_size;

    ret = mbedtls_dhm_read_public(dh_context, peer_public_key,
                                  peer_public_key_size);
    if (ret != 0) {
        return false;
    }

    return_size = 0;
    ret = mbedtls_dhm_calc_secret(dh_context, key, *key_size, &return_size,
                                  libspdm_myrand, NULL);
    if (ret != 0) {
        return false;
    }

    /*change the key, for example: from 0x123400 to 0x001234*/
    if (return_size < dh_key_size) {
        memmove(key + dh_key_size - return_size, key, return_size);
        libspdm_zero_mem(key, dh_key_size - return_size);
    }

    return true;
}

#endif /* LIBSPDM_FFDHE_SUPPORT */
