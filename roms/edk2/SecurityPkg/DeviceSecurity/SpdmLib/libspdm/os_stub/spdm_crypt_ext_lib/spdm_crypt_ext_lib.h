/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SPDM_CRYPT_EXT_LIB_H
#define SPDM_CRYPT_EXT_LIB_H

#include "hal/base.h"

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  pem_data  Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size  Size of the PEM key data in bytes.
 * @param  password  NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context   Pointer to newly generated asymmetric context which contain the retrieved private
 *                   key component. Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
typedef bool (*libspdm_asym_get_private_key_from_pem_func)(const uint8_t *pem_data,
                                                           size_t pem_size,
                                                           const char *password,
                                                           void **context);

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  base_asym_algo  SPDM base_asym_algo
 * @param  pem_data        Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size        Size of the PEM key data in bytes.
 * @param  password        NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context         Pointer to newly generated asymmetric context which contain the retrieved
 *                         private key component.
 *                         Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_asym_get_private_key_from_pem(uint32_t base_asym_algo,
                                           const uint8_t *pem_data,
                                           size_t pem_size,
                                           const char *password,
                                           void **context);

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  req_base_asym_alg  SPDM req_base_asym_alg
 * @param  pem_data           Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size           Size of the PEM key data in bytes.
 * @param  password           NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context            Pointer to newly generated asymmetric context which contain the
 *                            retrieved private key component. Use libspdm_asym_free() function to
 *                            free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_req_asym_get_private_key_from_pem(uint16_t req_base_asym_alg,
                                               const uint8_t *pem_data,
                                               size_t pem_size,
                                               const char *password,
                                               void **context);

/**
 * Return asym NID, based upon the negotiated asym algorithm.
 *
 * @param  base_asym_algo  SPDM base_asym_algo
 *
 * @return asym NID
 **/
size_t libspdm_get_aysm_nid(uint32_t base_asym_algo);

/**
 * Computes the hash of a input data buffer, based upon the negotiated measurement hash algorithm.
 *
 * This function performs the hash of a given data buffer, and return the hash value.
 *
 * @param  measurement_hash_algo  SPDM measurement_hash_algo
 * @param  data                   Pointer to the buffer containing the data to be hashed.
 * @param  data_size              Size of data buffer in bytes.
 * @param  hash_value             Pointer to a buffer that receives the hash value.
 *
 * @retval true   Hash computation succeeded.
 * @retval false  Hash computation failed.
 **/
bool libspdm_measurement_hash_all(uint32_t measurement_hash_algo,
                                  const void *data, size_t data_size,
                                  uint8_t *hash_value);

#endif /* SPDM_CRYPT_EXT_LIB_H */
