/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * AEAD (AES-GCM) Wrapper Implementation.
 *
 * RFC 5116 - An Interface and Algorithms for Authenticated Encryption
 * NIST SP800-38d - Cipher Modes of Operation: Galois / Counter Mode(GCM) and GMAC
 **/

#include "internal_crypt_lib.h"
#include <openssl/aes.h>
#include <openssl/evp.h>

/**
 * Performs AEAD AES-GCM authenticated encryption on a data buffer and additional authenticated data (AAD).
 *
 * iv_size must be 12, otherwise false is returned.
 * key_size must be 16, 24 or 32, otherwise false is returned.
 * tag_size must be 12, 13, 14, 15, 16, otherwise false is returned.
 *
 * @param[in]   key         Pointer to the encryption key.
 * @param[in]   key_size     size of the encryption key in bytes.
 * @param[in]   iv          Pointer to the IV value.
 * @param[in]   iv_size      size of the IV value in bytes.
 * @param[in]   a_data       Pointer to the additional authenticated data (AAD).
 * @param[in]   a_data_size   size of the additional authenticated data (AAD) in bytes.
 * @param[in]   data_in      Pointer to the input data buffer to be encrypted.
 * @param[in]   data_in_size  size of the input data buffer in bytes.
 * @param[out]  tag_out      Pointer to a buffer that receives the authentication tag output.
 * @param[in]   tag_size     size of the authentication tag in bytes.
 * @param[out]  data_out     Pointer to a buffer that receives the encryption output.
 * @param[out]  data_out_size size of the output data buffer in bytes.
 *
 * @retval true   AEAD AES-GCM authenticated encryption succeeded.
 * @retval false  AEAD AES-GCM authenticated encryption failed.
 *
 **/
bool libspdm_aead_aes_gcm_encrypt(const uint8_t *key, size_t key_size,
                                  const uint8_t *iv, size_t iv_size,
                                  const uint8_t *a_data, size_t a_data_size,
                                  const uint8_t *data_in, size_t data_in_size,
                                  uint8_t *tag_out, size_t tag_size,
                                  uint8_t *data_out, size_t *data_out_size)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    size_t temp_out_size;
    bool ret_value;

    if (data_in_size > INT_MAX) {
        return false;
    }
    if (a_data_size > INT_MAX) {
        return false;
    }
    if (iv_size != 12) {
        return false;
    }
    switch (key_size) {
    case 16:
        cipher = EVP_aes_128_gcm();
        break;
    case 24:
        cipher = EVP_aes_192_gcm();
        break;
    case 32:
        cipher = EVP_aes_256_gcm();
        break;
    default:
        return false;
    }
    if ((tag_size != 12) && (tag_size != 13) && (tag_size != 14) &&
        (tag_size != 15) && (tag_size != 16)) {
        return false;
    }
    if (data_out_size != NULL) {
        if ((*data_out_size > INT_MAX) ||
            (*data_out_size < data_in_size)) {
            return false;
        }
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return false;
    }

    ret_value = (bool)EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
    if (!ret_value) {
        goto done;
    }

    ret_value = (bool)EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                          (int32_t)iv_size, NULL);
    if (!ret_value) {
        goto done;
    }

    ret_value = (bool)EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    if (!ret_value) {
        goto done;
    }

    ret_value = (bool)EVP_EncryptUpdate(
        ctx, NULL, (int32_t *)&temp_out_size, a_data, (int32_t)a_data_size);
    if (!ret_value) {
        goto done;
    }

    ret_value = (bool)EVP_EncryptUpdate(ctx, data_out,
                                        (int32_t *)&temp_out_size, data_in,
                                        (int32_t)data_in_size);
    if (!ret_value) {
        goto done;
    }

    ret_value = (bool)EVP_EncryptFinal_ex(ctx, data_out,
                                          (int32_t *)&temp_out_size);
    if (!ret_value) {
        goto done;
    }

    ret_value = (bool)EVP_CIPHER_CTX_ctrl(
        ctx, EVP_CTRL_GCM_GET_TAG, (int32_t)tag_size, (void *)tag_out);

done:
    EVP_CIPHER_CTX_free(ctx);
    if (!ret_value) {
        return ret_value;
    }

    if (data_out_size != NULL) {
        *data_out_size = data_in_size;
    }

    return ret_value;
}

/**
 * Performs AEAD AES-GCM authenticated decryption on a data buffer and additional authenticated data (AAD).
 *
 * iv_size must be 12, otherwise false is returned.
 * key_size must be 16, 24 or 32, otherwise false is returned.
 * tag_size must be 12, 13, 14, 15, 16, otherwise false is returned.
 * If additional authenticated data verification fails, false is returned.
 *
 * @param[in]   key         Pointer to the encryption key.
 * @param[in]   key_size     size of the encryption key in bytes.
 * @param[in]   iv          Pointer to the IV value.
 * @param[in]   iv_size      size of the IV value in bytes.
 * @param[in]   a_data       Pointer to the additional authenticated data (AAD).
 * @param[in]   a_data_size   size of the additional authenticated data (AAD) in bytes.
 * @param[in]   data_in      Pointer to the input data buffer to be decrypted.
 * @param[in]   data_in_size  size of the input data buffer in bytes.
 * @param[in]   tag         Pointer to a buffer that contains the authentication tag.
 * @param[in]   tag_size     size of the authentication tag in bytes.
 * @param[out]  data_out     Pointer to a buffer that receives the decryption output.
 * @param[out]  data_out_size size of the output data buffer in bytes.
 *
 * @retval true   AEAD AES-GCM authenticated decryption succeeded.
 * @retval false  AEAD AES-GCM authenticated decryption failed.
 *
 **/
bool libspdm_aead_aes_gcm_decrypt(const uint8_t *key, size_t key_size,
                                  const uint8_t *iv, size_t iv_size,
                                  const uint8_t *a_data, size_t a_data_size,
                                  const uint8_t *data_in, size_t data_in_size,
                                  const uint8_t *tag, size_t tag_size,
                                  uint8_t *data_out, size_t *data_out_size)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    size_t temp_out_size;
    bool ret_value;

    if (data_in_size > INT_MAX) {
        return false;
    }
    if (a_data_size > INT_MAX) {
        return false;
    }
    if (iv_size != 12) {
        return false;
    }
    switch (key_size) {
    case 16:
        cipher = EVP_aes_128_gcm();
        break;
    case 24:
        cipher = EVP_aes_192_gcm();
        break;
    case 32:
        cipher = EVP_aes_256_gcm();
        break;
    default:
        return false;
    }
    if ((tag_size != 12) && (tag_size != 13) && (tag_size != 14) &&
        (tag_size != 15) && (tag_size != 16)) {
        return false;
    }
    if (data_out_size != NULL) {
        if ((*data_out_size > INT_MAX) ||
            (*data_out_size < data_in_size)) {
            return false;
        }
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return false;
    }

    ret_value = (bool)EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
    if (!ret_value) {
        goto done;
    }

    ret_value = (bool)EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                          (int32_t)iv_size, NULL);
    if (!ret_value) {
        goto done;
    }

    ret_value = (bool)EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    if (!ret_value) {
        goto done;
    }

    ret_value = (bool)EVP_DecryptUpdate(
        ctx, NULL, (int32_t *)&temp_out_size, a_data, (int32_t)a_data_size);
    if (!ret_value) {
        goto done;
    }

    ret_value = (bool)EVP_DecryptUpdate(ctx, data_out,
                                        (int32_t *)&temp_out_size, data_in,
                                        (int32_t)data_in_size);
    if (!ret_value) {
        goto done;
    }

    ret_value = (bool)EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                          (int32_t)tag_size, (void *)tag);
    if (!ret_value) {
        goto done;
    }

    ret_value = (bool)EVP_DecryptFinal_ex(ctx, data_out,
                                          (int32_t *)&temp_out_size);

done:
    EVP_CIPHER_CTX_free(ctx);
    if (!ret_value) {
        return ret_value;
    }

    if (data_out_size != NULL) {
        *data_out_size = data_in_size;
    }

    return ret_value;
}
