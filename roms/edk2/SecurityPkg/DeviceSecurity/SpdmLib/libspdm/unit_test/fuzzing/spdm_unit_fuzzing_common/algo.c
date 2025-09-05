/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_fuzzing.h"

uint8_t m_libspdm_use_measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
uint32_t m_libspdm_use_measurement_hash_algo =
    SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
uint32_t m_libspdm_use_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
uint32_t m_libspdm_use_asym_algo =
    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
uint16_t m_libspdm_use_req_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
uint16_t m_libspdm_use_dhe_algo = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;
uint16_t m_libspdm_use_aead_algo = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
uint16_t m_libspdm_use_key_schedule_algo = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
