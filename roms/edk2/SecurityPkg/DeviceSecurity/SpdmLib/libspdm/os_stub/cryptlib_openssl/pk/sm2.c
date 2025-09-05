/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Shang-Mi2 Asymmetric Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/objects.h>

/**
 * Allocates and Initializes one Shang-Mi2 context for subsequent use.
 *
 * The key is generated before the function returns.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Shang-Mi2 context that has been initialized.
 *         If the allocations fails, sm2_new_by_nid() returns NULL.
 *
 **/
void *libspdm_sm2_dsa_new_by_nid(size_t nid)
{
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY_CTX *key_ctx;
    EVP_PKEY *pkey;
    int32_t result;
    EVP_PKEY *params;

    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    if (pkey_ctx == NULL) {
        return NULL;
    }
    result = EVP_PKEY_paramgen_init(pkey_ctx);
    if (result != 1) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }
    result = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, NID_sm2);
    if (result == 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }

    params = NULL;
    result = EVP_PKEY_paramgen(pkey_ctx, &params);
    if (result == 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pkey_ctx);

    key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, params, NULL);
    if (key_ctx == NULL) {
        EVP_PKEY_free(params);
        return NULL;
    }
    EVP_PKEY_free(params);

    result = EVP_PKEY_keygen_init(key_ctx);
    if (result == 0) {
        EVP_PKEY_CTX_free(key_ctx);
        return NULL;
    }
    pkey = NULL;
    result = EVP_PKEY_keygen(key_ctx, &pkey);
    if (result == 0 || pkey == NULL) {
        EVP_PKEY_CTX_free(key_ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(key_ctx);

    result = EVP_PKEY_is_a(pkey, "SM2");
    if (result != 1) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    return (void *)pkey;
}

/**
 * Release the specified sm2 context.
 *
 * @param[in]  sm2_context  Pointer to the sm2 context to be released.
 *
 **/
void libspdm_sm2_dsa_free(void *sm2_context)
{
    EVP_PKEY_free((EVP_PKEY *)sm2_context);
}

/**
 * Sets the public key component into the established sm2 context.
 *
 * The public_size is 64. first 32-byte is X, second 32-byte is Y.
 *
 * @param[in, out]  ec_context      Pointer to sm2 context being set.
 * @param[in]       public         Pointer to the buffer to receive generated public X,Y.
 * @param[in]       public_size     The size of public buffer in bytes.
 *
 * @retval  true   sm2 public key component was set successfully.
 * @retval  false  Invalid sm2 public key component.
 *
 **/
bool libspdm_sm2_dsa_set_pub_key(void *sm2_context, const uint8_t *public_key,
                                 size_t public_key_size)
{
    EVP_PKEY *pkey;
    EC_KEY *ec_key;
    const EC_GROUP *ec_group;
    bool ret_val;
    BIGNUM *bn_x;
    BIGNUM *bn_y;
    EC_POINT *ec_point;
    int32_t openssl_nid;
    size_t half_size;

    if (sm2_context == NULL || public_key == NULL) {
        return false;
    }

    pkey = (EVP_PKEY *)sm2_context;
    if (EVP_PKEY_id(pkey) != EVP_PKEY_SM2) {
        return false;
    }
    ec_key = (void *)EVP_PKEY_get0_EC_KEY(pkey);

    openssl_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
    switch (openssl_nid) {
    case NID_sm2:
        half_size = 32;
        break;
    default:
        return false;
    }
    if (public_key_size != half_size * 2) {
        return false;
    }

    ec_group = EC_KEY_get0_group(ec_key);
    ec_point = NULL;

    bn_x = BN_bin2bn(public_key, (uint32_t)half_size, NULL);
    bn_y = BN_bin2bn(public_key + half_size, (uint32_t)half_size, NULL);
    if (bn_x == NULL || bn_y == NULL) {
        ret_val = false;
        goto done;
    }
    ec_point = EC_POINT_new(ec_group);
    if (ec_point == NULL) {
        ret_val = false;
        goto done;
    }

    ret_val = (bool)EC_POINT_set_affine_coordinates(ec_group, ec_point,
                                                    bn_x, bn_y, NULL);
    if (!ret_val) {
        goto done;
    }

    ret_val = (bool)EC_KEY_set_public_key(ec_key, ec_point);
    if (!ret_val) {
        goto done;
    }

    ret_val = true;

done:
    if (bn_x != NULL) {
        BN_free(bn_x);
    }
    if (bn_y != NULL) {
        BN_free(bn_y);
    }
    if (ec_point != NULL) {
        EC_POINT_free(ec_point);
    }
    return ret_val;
}

/**
 * Gets the public key component from the established sm2 context.
 *
 * The public_size is 64. first 32-byte is X, second 32-byte is Y.
 *
 * @param[in, out]  sm2_context     Pointer to sm2 context being set.
 * @param[out]      public         Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval  true   sm2 key component was retrieved successfully.
 * @retval  false  Invalid sm2 key component.
 *
 **/
bool libspdm_sm2_dsa_get_pub_key(void *sm2_context, uint8_t *public_key,
                                 size_t *public_key_size)
{
    EVP_PKEY *pkey;
    EC_KEY *ec_key;
    const EC_GROUP *ec_group;
    bool ret_val;
    const EC_POINT *ec_point;
    BIGNUM *bn_x;
    BIGNUM *bn_y;
    int32_t openssl_nid;
    size_t half_size;
    int x_size;
    int y_size;

    if (sm2_context == NULL || public_key_size == NULL) {
        return false;
    }

    if (public_key == NULL && *public_key_size != 0) {
        return false;
    }

    pkey = (EVP_PKEY *)sm2_context;
    if (EVP_PKEY_id(pkey) != EVP_PKEY_SM2) {
        return false;
    }
    ec_key = (void *)EVP_PKEY_get0_EC_KEY(pkey);

    openssl_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
    switch (openssl_nid) {
    case NID_sm2:
        half_size = 32;
        break;
    default:
        return false;
    }
    if (*public_key_size < half_size * 2) {
        *public_key_size = half_size * 2;
        return false;
    }
    *public_key_size = half_size * 2;

    ec_group = EC_KEY_get0_group(ec_key);
    ec_point = EC_KEY_get0_public_key(ec_key);
    if (ec_point == NULL) {
        return false;
    }

    bn_x = BN_new();
    bn_y = BN_new();
    if (bn_x == NULL || bn_y == NULL) {
        ret_val = false;
        goto done;
    }

    ret_val = (bool)EC_POINT_get_affine_coordinates(ec_group, ec_point,
                                                    bn_x, bn_y, NULL);
    if (!ret_val) {
        goto done;
    }

    x_size = BN_num_bytes(bn_x);
    y_size = BN_num_bytes(bn_y);
    if (x_size <= 0 || y_size <= 0) {
        ret_val = false;
        goto done;
    }
    LIBSPDM_ASSERT((size_t)x_size <= half_size && (size_t)y_size <= half_size);

    if (public_key != NULL) {
        libspdm_zero_mem(public_key, *public_key_size);
        BN_bn2bin(bn_x, &public_key[0 + half_size - x_size]);
        BN_bn2bin(bn_y, &public_key[half_size + half_size - y_size]);
    }
    ret_val = true;

done:
    if (bn_x != NULL) {
        BN_free(bn_x);
    }
    if (bn_y != NULL) {
        BN_free(bn_y);
    }
    return ret_val;
}

/**
 * Validates key components of sm2 context.
 * NOTE: This function performs integrity checks on all the sm2 key material, so
 *      the sm2 key structure must contain all the private key data.
 *
 * If sm2_context is NULL, then return false.
 *
 * @param[in]  sm2_context  Pointer to sm2 context to check.
 *
 * @retval  true   sm2 key components are valid.
 * @retval  false  sm2 key components are not valid.
 *
 **/
bool libspdm_sm2_dsa_check_key(const void *sm2_context)
{
    EVP_PKEY *pkey;
    EC_KEY *ec_key;
    bool ret_val;

    if (sm2_context == NULL) {
        return false;
    }

    pkey = (EVP_PKEY *)sm2_context;
    if (EVP_PKEY_id(pkey) != EVP_PKEY_SM2) {
        return false;
    }
    ec_key = (void *)EVP_PKEY_get0_EC_KEY(pkey);

    ret_val = (bool)EC_KEY_check_key(ec_key);
    if (!ret_val) {
        return false;
    }

    return true;
}

/**
 * Generates sm2 key and returns sm2 public key (X, Y), based upon GB/T 32918.3-2016: SM2 - Part3.
 *
 * This function generates random secret, and computes the public key (X, Y), which is
 * returned via parameter public, public_size.
 * X is the first half of public with size being public_size / 2,
 * Y is the second half of public with size being public_size / 2.
 * sm2 context is updated accordingly.
 * If the public buffer is too small to hold the public X, Y, false is returned and
 * public_size is set to the required buffer size to obtain the public X, Y.
 *
 * The public_size is 64. first 32-byte is X, second 32-byte is Y.
 *
 * If sm2_context is NULL, then return false.
 * If public_size is NULL, then return false.
 * If public_size is large enough but public is NULL, then return false.
 *
 * @param[in, out]  sm2_context     Pointer to the sm2 context.
 * @param[out]      public_data     Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   sm2 public X,Y generation succeeded.
 * @retval false  sm2 public X,Y generation failed.
 * @retval false  public_size is not large enough.
 *
 **/
bool libspdm_sm2_dsa_generate_key(void *sm2_context, uint8_t *public_data,
                                  size_t *public_size)
{
    EVP_PKEY *pkey;
    EC_KEY *ec_key;
    const EC_GROUP *ec_group;
    bool ret_val;
    const EC_POINT *ec_point;
    BIGNUM *bn_x;
    BIGNUM *bn_y;
    int32_t openssl_nid;
    size_t half_size;
    int x_size;
    int y_size;

    if (sm2_context == NULL || public_size == NULL) {
        return false;
    }

    if (public_data == NULL && *public_size != 0) {
        return false;
    }

    pkey = (EVP_PKEY *)sm2_context;
    if (EVP_PKEY_id(pkey) != EVP_PKEY_SM2) {
        return false;
    }
    ec_key = (void *)EVP_PKEY_get0_EC_KEY(pkey);

    ret_val = (bool)EC_KEY_generate_key(ec_key);
    if (!ret_val) {
        return false;
    }
    openssl_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
    switch (openssl_nid) {
    case NID_sm2:
        half_size = 32;
        break;
    default:
        return false;
    }
    if (*public_size < half_size * 2) {
        *public_size = half_size * 2;
        return false;
    }
    *public_size = half_size * 2;

    ec_group = EC_KEY_get0_group(ec_key);
    ec_point = EC_KEY_get0_public_key(ec_key);
    if (ec_point == NULL) {
        return false;
    }

    bn_x = BN_new();
    bn_y = BN_new();
    if (bn_x == NULL || bn_y == NULL) {
        ret_val = false;
        goto done;
    }

    ret_val = (bool)EC_POINT_get_affine_coordinates(ec_group, ec_point,
                                                    bn_x, bn_y, NULL);
    if (!ret_val) {
        goto done;
    }

    x_size = BN_num_bytes(bn_x);
    y_size = BN_num_bytes(bn_y);
    if (x_size <= 0 || y_size <= 0) {
        ret_val = false;
        goto done;
    }
    LIBSPDM_ASSERT((size_t)x_size <= half_size && (size_t)y_size <= half_size);

    if (public_data != NULL) {
        libspdm_zero_mem(public_data, *public_size);
        BN_bn2bin(bn_x, &public_data[0 + half_size - x_size]);
        BN_bn2bin(bn_y, &public_data[half_size + half_size - y_size]);
    }
    ret_val = true;

done:
    if (bn_x != NULL) {
        BN_free(bn_x);
    }
    if (bn_y != NULL) {
        BN_free(bn_y);
    }
    return ret_val;
}

/**
 * Allocates and Initializes one Shang-Mi2 context for subsequent use.
 *
 * The key is generated before the function returns.
 *
 * @param nid cipher NID
 *
 * @return  Pointer to the Shang-Mi2 context that has been initialized.
 *         If the allocations fails, sm2_new_by_nid() returns NULL.
 *
 **/
void *libspdm_sm2_key_exchange_new_by_nid(size_t nid)
{
    /* current openssl only supports ECDH with SM2 curve, but does not support SM2-key-exchange.*/
    return NULL;
}

/**
 * Release the specified sm2 context.
 *
 * @param[in]  sm2_context  Pointer to the sm2 context to be released.
 *
 **/
void libspdm_sm2_key_exchange_free(void *sm2_context)
{
    /* current openssl only supports ECDH with SM2 curve, but does not support SM2-key-exchange.*/
}

/**
 * Initialize the specified sm2 context.
 *
 * @param[in]  sm2_context  Pointer to the sm2 context to be released.
 * @param[in]  hash_nid            hash NID, only SM3 is valid.
 * @param[in]  id_a                the ID-A of the key exchange context.
 * @param[in]  id_a_size           size of ID-A key exchange context.
 * @param[in]  id_b                the ID-B of the key exchange context.
 * @param[in]  id_b_size           size of ID-B key exchange context.
 * @param[in]  is_initiator        if the caller is initiator.
 *                                true: initiator
 *                                false: not an initiator
 *
 * @retval true   sm2 context is initialized.
 * @retval false  sm2 context is not initialized.
 **/
bool libspdm_sm2_key_exchange_init(const void *sm2_context, size_t hash_nid,
                                   const uint8_t *id_a, size_t id_a_size,
                                   const uint8_t *id_b, size_t id_b_size,
                                   bool is_initiator)
{
    /* current openssl only supports ECDH with SM2 curve, but does not support SM2-key-exchange.*/
    return false;
}

/**
 * Generates sm2 key and returns sm2 public key (X, Y), based upon GB/T 32918.3-2016: SM2 - Part3.
 *
 * This function generates random secret, and computes the public key (X, Y), which is
 * returned via parameter public, public_size.
 * X is the first half of public with size being public_size / 2,
 * Y is the second half of public with size being public_size / 2.
 * sm2 context is updated accordingly.
 * If the public buffer is too small to hold the public X, Y, false is returned and
 * public_size is set to the required buffer size to obtain the public X, Y.
 *
 * The public_size is 64. first 32-byte is X, second 32-byte is Y.
 *
 * If sm2_context is NULL, then return false.
 * If public_size is NULL, then return false.
 * If public_size is large enough but public is NULL, then return false.
 *
 * @param[in, out]  sm2_context     Pointer to the sm2 context.
 * @param[out]      public_data     Pointer to the buffer to receive generated public X,Y.
 * @param[in, out]  public_size     On input, the size of public buffer in bytes.
 *                                On output, the size of data returned in public buffer in bytes.
 *
 * @retval true   sm2 public X,Y generation succeeded.
 * @retval false  sm2 public X,Y generation failed.
 * @retval false  public_size is not large enough.
 *
 **/
bool libspdm_sm2_key_exchange_generate_key(void *sm2_context, uint8_t *public_data,
                                           size_t *public_size)
{
    /* current openssl only supports ECDH with SM2 curve, but does not support SM2-key-exchange.*/
    return false;
}

/**
 * Computes exchanged common key, based upon GB/T 32918.3-2016: SM2 - Part3.
 *
 * Given peer's public key (X, Y), this function computes the exchanged common key,
 * based on its own context including value of curve parameter and random secret.
 * X is the first half of peer_public with size being peer_public_size / 2,
 * Y is the second half of peer_public with size being peer_public_size / 2.
 *
 * If sm2_context is NULL, then return false.
 * If peer_public is NULL, then return false.
 * If peer_public_size is 0, then return false.
 * If key is NULL, then return false.
 *
 * The id_a_size and id_b_size must be smaller than 2^16-1.
 * The peer_public_size is 64. first 32-byte is X, second 32-byte is Y.
 * The key_size must be smaller than 2^32-1, limited by KDF function.
 *
 * @param[in, out]  sm2_context         Pointer to the sm2 context.
 * @param[in]       peer_public         Pointer to the peer's public X,Y.
 * @param[in]       peer_public_size     size of peer's public X,Y in bytes.
 * @param[out]      key                Pointer to the buffer to receive generated key.
 * @param[in]       key_size            On input, the size of key buffer in bytes.
 *
 * @retval true   sm2 exchanged key generation succeeded.
 * @retval false  sm2 exchanged key generation failed.
 *
 **/
bool libspdm_sm2_key_exchange_compute_key(void *sm2_context,
                                          const uint8_t *peer_public,
                                          size_t peer_public_size, uint8_t *key,
                                          size_t *key_size)
{
    /* current openssl only supports ECDH with SM2 curve, but does not support SM2-key-exchange.*/
    return false;
}

static void ecc_signature_der_to_bin(uint8_t *der_signature,
                                     size_t der_sig_size,
                                     uint8_t *signature, size_t sig_size)
{
    uint8_t der_r_size;
    uint8_t der_s_size;
    uint8_t *bn_r;
    uint8_t *bn_s;
    uint8_t r_size;
    uint8_t s_size;
    uint8_t half_size;

    half_size = (uint8_t)(sig_size / 2);

    LIBSPDM_ASSERT(der_signature[0] == 0x30);
    LIBSPDM_ASSERT((size_t)(der_signature[1] + 2) == der_sig_size);
    LIBSPDM_ASSERT(der_signature[2] == 0x02);
    der_r_size = der_signature[3];
    LIBSPDM_ASSERT(der_signature[4 + der_r_size] == 0x02);
    der_s_size = der_signature[5 + der_r_size];
    LIBSPDM_ASSERT(der_sig_size == (size_t)(der_r_size + der_s_size + 6));

    if (der_signature[4] != 0) {
        r_size = der_r_size;
        bn_r = &der_signature[4];
    } else {
        r_size = der_r_size - 1;
        bn_r = &der_signature[5];
    }
    if (der_signature[6 + der_r_size] != 0) {
        s_size = der_s_size;
        bn_s = &der_signature[6 + der_r_size];
    } else {
        s_size = der_s_size - 1;
        bn_s = &der_signature[7 + der_r_size];
    }
    LIBSPDM_ASSERT(r_size <= half_size && s_size <= half_size);
    libspdm_zero_mem(signature, sig_size);
    libspdm_copy_mem(&signature[0 + half_size - r_size],
                     sig_size - (0 + half_size - r_size),
                     bn_r, r_size);
    libspdm_copy_mem(&signature[half_size + half_size - s_size],
                     sig_size - (half_size + half_size - s_size),
                     bn_s, s_size);
}

static void ecc_signature_bin_to_der(uint8_t *signature, size_t sig_size,
                                     uint8_t *der_signature,
                                     size_t *der_sig_size_in_out)
{
    size_t der_sig_size;
    uint8_t der_r_size;
    uint8_t der_s_size;
    uint8_t *bn_r;
    uint8_t *bn_s;
    uint8_t r_size;
    uint8_t s_size;
    uint8_t half_size;
    uint8_t index;

    half_size = (uint8_t)(sig_size / 2);

    for (index = 0; index < half_size; index++) {
        if (signature[index] != 0) {
            break;
        }
    }
    r_size = (uint8_t)(half_size - index);
    bn_r = &signature[index];
    for (index = 0; index < half_size; index++) {
        if (signature[half_size + index] != 0) {
            break;
        }
    }
    s_size = (uint8_t)(half_size - index);
    bn_s = &signature[half_size + index];
    if (r_size == 0 || s_size == 0) {
        *der_sig_size_in_out = 0;
        return;
    }
    if (bn_r[0] < 0x80) {
        der_r_size = r_size;
    } else {
        der_r_size = r_size + 1;
    }
    if (bn_s[0] < 0x80) {
        der_s_size = s_size;
    } else {
        der_s_size = s_size + 1;
    }
    der_sig_size = der_r_size + der_s_size + 6;
    LIBSPDM_ASSERT(der_sig_size <= *der_sig_size_in_out);
    *der_sig_size_in_out = der_sig_size;
    libspdm_zero_mem(der_signature, der_sig_size);
    der_signature[0] = 0x30;
    der_signature[1] = (uint8_t)(der_sig_size - 2);
    der_signature[2] = 0x02;
    der_signature[3] = der_r_size;
    if (bn_r[0] < 0x80) {
        libspdm_copy_mem(&der_signature[4],
                         der_sig_size - (&der_signature[4] - der_signature),
                         bn_r, r_size);
    } else {
        libspdm_copy_mem(&der_signature[5],
                         der_sig_size - (&der_signature[5] - der_signature),
                         bn_r, r_size);
    }
    der_signature[4 + der_r_size] = 0x02;
    der_signature[5 + der_r_size] = der_s_size;
    if (bn_s[0] < 0x80) {
        libspdm_copy_mem(&der_signature[6 + der_r_size],
                         der_sig_size - (&der_signature[6 + der_r_size] - der_signature),
                         bn_s, s_size);
    } else {
        libspdm_copy_mem(&der_signature[7 + der_r_size],
                         der_sig_size - (&der_signature[7 + der_r_size] - der_signature),
                         bn_s, s_size);
    }
}

/**
 * Carries out the SM2 signature, based upon GB/T 32918.2-2016: SM2 - Part2.
 *
 * This function carries out the SM2 signature.
 * If the signature buffer is too small to hold the contents of signature, false
 * is returned and sig_size is set to the required buffer size to obtain the signature.
 *
 * If sm2_context is NULL, then return false.
 * If message is NULL, then return false.
 * hash_nid must be SM3_256.
 * If sig_size is large enough but signature is NULL, then return false.
 *
 * The id_a_size must be smaller than 2^16-1.
 * The sig_size is 64. first 32-byte is R, second 32-byte is S.
 *
 * @param[in]       sm2_context   Pointer to sm2 context for signature generation.
 * @param[in]       hash_nid      hash NID
 * @param[in]       id_a          the ID-A of the signing context.
 * @param[in]       id_a_size     size of ID-A signing context.
 * @param[in]       message      Pointer to octet message to be signed (before hash).
 * @param[in]       size         size of the message in bytes.
 * @param[out]      signature    Pointer to buffer to receive SM2 signature.
 * @param[in, out]  sig_size      On input, the size of signature buffer in bytes.
 *                              On output, the size of data returned in signature buffer in bytes.
 *
 * @retval  true   signature successfully generated in SM2.
 * @retval  false  signature generation failed.
 * @retval  false  sig_size is too small.
 *
 **/
bool libspdm_sm2_dsa_sign(const void *sm2_context, size_t hash_nid,
                          const uint8_t *id_a, size_t id_a_size,
                          const uint8_t *message, size_t size,
                          uint8_t *signature, size_t *sig_size)
{
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    size_t half_size;
    int32_t result;
    uint8_t der_signature[32 * 2 + 8];
    size_t der_sig_size;

    if (sm2_context == NULL || message == NULL) {
        return false;
    }

    if (signature == NULL || sig_size == NULL) {
        return false;
    }

    pkey = (EVP_PKEY *)sm2_context;
    switch (EVP_PKEY_id(pkey)) {
    case EVP_PKEY_SM2:
        half_size = 32;
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
    case LIBSPDM_CRYPTO_NID_SM3_256:
        break;

    default:
        return false;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return false;
    }
    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (id_a_size != 0) {
        result = EVP_PKEY_CTX_set1_id(pkey_ctx, id_a,
                                      id_a_size);
        if (result <= 0) {
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_CTX_free(pkey_ctx);
            return false;
        }
    }

    EVP_MD_CTX_set_pkey_ctx(ctx, pkey_ctx);

    result = EVP_DigestSignInit(ctx, NULL, EVP_sm3(), NULL, pkey);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }
    der_sig_size = sizeof(der_signature);
    result = EVP_DigestSign(ctx, der_signature, &der_sig_size, message,
                            size);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_CTX_free(pkey_ctx);

    ecc_signature_der_to_bin(der_signature, der_sig_size, signature,
                             *sig_size);

    return true;
}

/**
 * Verifies the SM2 signature, based upon GB/T 32918.2-2016: SM2 - Part2.
 *
 * If sm2_context is NULL, then return false.
 * If message is NULL, then return false.
 * If signature is NULL, then return false.
 * hash_nid must be SM3_256.
 *
 * The id_a_size must be smaller than 2^16-1.
 * The sig_size is 64. first 32-byte is R, second 32-byte is S.
 *
 * @param[in]  sm2_context   Pointer to SM2 context for signature verification.
 * @param[in]  hash_nid      hash NID
 * @param[in]  id_a          the ID-A of the signing context.
 * @param[in]  id_a_size     size of ID-A signing context.
 * @param[in]  message      Pointer to octet message to be checked (before hash).
 * @param[in]  size         size of the message in bytes.
 * @param[in]  signature    Pointer to SM2 signature to be verified.
 * @param[in]  sig_size      size of signature in bytes.
 *
 * @retval  true   Valid signature encoded in SM2.
 * @retval  false  Invalid signature or invalid sm2 context.
 *
 **/
bool libspdm_sm2_dsa_verify(const void *sm2_context, size_t hash_nid,
                            const uint8_t *id_a, size_t id_a_size,
                            const uint8_t *message, size_t size,
                            const uint8_t *signature, size_t sig_size)
{
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    size_t half_size;
    int32_t result;
    uint8_t der_signature[32 * 2 + 8];
    size_t der_sig_size;

    if (sm2_context == NULL || message == NULL || signature == NULL) {
        return false;
    }

    if (sig_size > INT_MAX || sig_size == 0) {
        return false;
    }

    pkey = (EVP_PKEY *)sm2_context;
    switch (EVP_PKEY_id(pkey)) {
    case EVP_PKEY_SM2:
        half_size = 32;
        break;
    default:
        return false;
    }

    if (sig_size != (size_t)(half_size * 2)) {
        return false;
    }

    switch (hash_nid) {
    case LIBSPDM_CRYPTO_NID_SM3_256:
        break;

    default:
        return false;
    }

    der_sig_size = sizeof(der_signature);
    ecc_signature_bin_to_der((uint8_t *)signature, sig_size, der_signature,
                             &der_sig_size);

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return false;
    }
    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ctx == NULL) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (id_a_size != 0) {
        result = EVP_PKEY_CTX_set1_id(pkey_ctx, id_a,
                                      id_a_size);
        if (result <= 0) {
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_CTX_free(pkey_ctx);
            return false;
        }
    }
    EVP_MD_CTX_set_pkey_ctx(ctx, pkey_ctx);

    result = EVP_DigestVerifyInit(ctx, NULL, EVP_sm3(), NULL, pkey);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }
    result = EVP_DigestVerify(ctx, der_signature, (uint32_t)der_sig_size,
                              message, size);
    if (result != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_CTX_free(pkey_ctx);
    return true;
}
