/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_lib_config.h"
#include "spdm_crypt_ext_lib/spdm_crypt_ext_lib.h"
#include "hal/library/cryptlib.h"
#include "spdm_crypt_ext_lib/cryptlib_ext.h"
#include "industry_standard/spdm.h"
#include "hal/library/debuglib.h"

/**
 * Return asymmetric GET_PRIVATE_KEY_FROM_PEM function, based upon the asymmetric algorithm.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 *
 * @return asymmetric GET_PRIVATE_KEY_FROM_PEM function
 **/
libspdm_asym_get_private_key_from_pem_func
libspdm_get_asym_get_private_key_from_pem(uint32_t base_asym_algo)
{
    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (LIBSPDM_RSA_SSA_SUPPORT) || (LIBSPDM_RSA_PSS_SUPPORT)
        return libspdm_rsa_get_private_key_from_pem;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if LIBSPDM_ECDSA_SUPPORT
        return libspdm_ec_get_private_key_from_pem;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
#if (LIBSPDM_EDDSA_ED25519_SUPPORT) || (LIBSPDM_EDDSA_ED448_SUPPORT)
        return libspdm_ecd_get_private_key_from_pem;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
#if LIBSPDM_SM2_DSA_SUPPORT
        return libspdm_sm2_get_private_key_from_pem;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  base_asym_algo                 SPDM base_asym_algo
 * @param  pem_data                      Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size                      size of the PEM key data in bytes.
 * @param  password                     NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context                      Pointer to newly generated asymmetric context which contain the retrieved private key component.
 *                                     Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_asym_get_private_key_from_pem(uint32_t base_asym_algo,
                                           const uint8_t *pem_data,
                                           size_t pem_size,
                                           const char *password,
                                           void **context)
{
    libspdm_asym_get_private_key_from_pem_func asym_get_private_key_from_pem;
    asym_get_private_key_from_pem = libspdm_get_asym_get_private_key_from_pem(base_asym_algo);
    if (asym_get_private_key_from_pem == NULL) {
        return false;
    }
    return asym_get_private_key_from_pem(pem_data, pem_size, password, context);
}

/**
 * Return asymmetric GET_PRIVATE_KEY_FROM_PEM function, based upon the asymmetric algorithm.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 *
 * @return asymmetric GET_PRIVATE_KEY_FROM_PEM function
 **/
static libspdm_asym_get_private_key_from_pem_func
libspdm_get_req_asym_get_private_key_from_pem(uint16_t req_base_asym_alg)
{
    return libspdm_get_asym_get_private_key_from_pem(req_base_asym_alg);
}

/**
 * Retrieve the Private key from the password-protected PEM key data.
 *
 * @param  req_base_asym_alg               SPDM req_base_asym_alg
 * @param  pem_data                      Pointer to the PEM-encoded key data to be retrieved.
 * @param  pem_size                      size of the PEM key data in bytes.
 * @param  password                     NULL-terminated passphrase used for encrypted PEM key data.
 * @param  context                      Pointer to newly generated asymmetric context which contain the retrieved private key component.
 *                                     Use libspdm_asym_free() function to free the resource.
 *
 * @retval  true   Private key was retrieved successfully.
 * @retval  false  Invalid PEM key data or incorrect password.
 **/
bool libspdm_req_asym_get_private_key_from_pem(uint16_t req_base_asym_alg,
                                               const uint8_t *pem_data,
                                               size_t pem_size,
                                               const char *password,
                                               void **context)
{
    libspdm_asym_get_private_key_from_pem_func asym_get_private_key_from_pem;
    asym_get_private_key_from_pem =
        libspdm_get_req_asym_get_private_key_from_pem(req_base_asym_alg);
    if (asym_get_private_key_from_pem == NULL) {
        return false;
    }
    return asym_get_private_key_from_pem(pem_data, pem_size, password,
                                         context);
}

/**
 * Computes the hash of a input data buffer.
 *
 * This function performs the hash of a given data buffer, and return the hash value.
 *
 * @param  data        Pointer to the buffer containing the data to be hashed.
 * @param  data_size   Size of data buffer in bytes.
 * @param  hash_value  Pointer to a buffer that receives the hash value.
 *
 * @retval true   hash computation succeeded.
 * @retval false  hash computation failed.
 **/
typedef bool (*libspdm_hash_all_func)(const void *data, size_t data_size, uint8_t *hash_value);

/**
 * Return hash function, based upon the negotiated measurement hash algorithm.
 *
 * @param  measurement_hash_algo          SPDM measurement_hash_algo
 *
 * @return hash function
 **/
static libspdm_hash_all_func libspdm_spdm_measurement_hash_func(uint32_t measurement_hash_algo)
{
    switch (measurement_hash_algo) {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
#if LIBSPDM_SHA256_SUPPORT
        return libspdm_sha256_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
#if LIBSPDM_SHA384_SUPPORT
        return libspdm_sha384_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
#if LIBSPDM_SHA512_SUPPORT
        return libspdm_sha512_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
#if LIBSPDM_SHA3_256_SUPPORT
        return libspdm_sha3_256_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
#if LIBSPDM_SHA3_384_SUPPORT
        return libspdm_sha3_384_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
#if LIBSPDM_SHA3_512_SUPPORT
        return libspdm_sha3_512_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256:
#if LIBSPDM_SM3_256_SUPPORT
        return libspdm_sm3_256_hash_all;
#else
        LIBSPDM_ASSERT(false);
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        break;
    }

    return NULL;
}

bool libspdm_measurement_hash_all(uint32_t measurement_hash_algo,
                                  const void *data, size_t data_size,
                                  uint8_t *hash_value)
{
    libspdm_hash_all_func hash_function;
    hash_function = libspdm_spdm_measurement_hash_func(measurement_hash_algo);
    if (hash_function == NULL) {
        return false;
    }
    return hash_function(data, data_size, hash_value);
}

size_t libspdm_get_aysm_nid(uint32_t base_asym_algo)
{
    switch (base_asym_algo)
    {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
        return LIBSPDM_CRYPTO_NID_RSASSA2048;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
        return LIBSPDM_CRYPTO_NID_RSASSA3072;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
        return LIBSPDM_CRYPTO_NID_RSASSA4096;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        return LIBSPDM_CRYPTO_NID_RSAPSS2048;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        return LIBSPDM_CRYPTO_NID_RSAPSS3072;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        return LIBSPDM_CRYPTO_NID_RSAPSS4096;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        return LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        return LIBSPDM_CRYPTO_NID_ECDSA_NIST_P384;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        return LIBSPDM_CRYPTO_NID_ECDSA_NIST_P521;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
        return LIBSPDM_CRYPTO_NID_EDDSA_ED25519;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        return LIBSPDM_CRYPTO_NID_EDDSA_ED448;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        return LIBSPDM_CRYPTO_NID_SM2_DSA_P256;
    default:
        return LIBSPDM_CRYPTO_NID_NULL;
    }
}
