/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

void libspdm_test_responder_algorithms_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);
}

void libspdm_test_responder_algorithms_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);
}

void libspdm_test_responder_algorithms_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);
}

void libspdm_test_responder_algorithms_case4(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);
}
void libspdm_test_responder_algorithms_case5(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);
}

void libspdm_test_responder_algorithms_case6(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);
}

void libspdm_test_responder_algorithms_case7(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
                                                   SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);
}

void libspdm_test_responder_algorithms_case8(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);
}

void libspdm_test_responder_algorithms_case9(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    libspdm_reset_message_a(spdm_context);

    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);
}

void libspdm_test_responder_algorithms_case10(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    response_size = sizeof(response);

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512;
    libspdm_reset_message_a(spdm_context);

    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);
}

void libspdm_test_responder_algorithms_case11(void **State)
{
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    response_size = sizeof(response);
    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);
}

void libspdm_test_responder_algorithms_case12(void **State)
{
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_hash_algo = 0;
    spdm_context->local_context.algorithm.measurement_spec = 0;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.algorithm.other_params_support = 0;
    spdm_context->local_context.algorithm.mel_spec = SPDM_MEL_SPECIFICATION_DMTF;
    libspdm_reset_message_a(spdm_context);

    spdm_context->connection_info.algorithm.other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;

    /* Sub Case 1: MEL_CAP set 1*/
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;

    response_size = sizeof(response);
    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);

    /* Sub Case 2: MEL_CAP set 0*/
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    response_size = sizeof(response);
    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.algorithm.other_params_support = 0;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY;

    response_size = sizeof(response);
    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.algorithm.other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY;

    response_size = sizeof(response);
    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.algorithm.other_params_support = 0;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_NEG;

    response_size = sizeof(response);
    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);


    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.algorithm.other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_NEG;

    response_size = sizeof(response);
    libspdm_get_response_algorithms(spdm_context, spdm_test_context->test_buffer_size,
                                    spdm_test_context->test_buffer, &response_size, response);

}

libspdm_test_context_t libspdm_test_responder_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;
    spdm_message_header_t *spdm_request_header;
    libspdm_setup_test_context(&libspdm_test_responder_context);

    spdm_request_header = (spdm_message_header_t*)test_buffer;

    if (spdm_request_header->request_response_code != SPDM_NEGOTIATE_ALGORITHMS) {
        spdm_request_header->request_response_code = SPDM_NEGOTIATE_ALGORITHMS;
    }

    libspdm_test_responder_context.test_buffer = test_buffer;
    libspdm_test_responder_context.test_buffer_size = test_buffer_size;

    /* Success Case*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_algorithms_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /* connection_state Check */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_algorithms_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Support capablities flag: SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_algorithms_case3(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Support capablities flag */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_algorithms_case4(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Support capablities flag: SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_algorithms_case5(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Support capablities flag: SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_algorithms_case6(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Support capablities flag: SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_algorithms_case7(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Support capablities flag: SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_algorithms_case8(&State);
    libspdm_unit_test_group_teardown(&State);

    /* response_state: LIBSPDM_RESPONSE_STATE_BUSY */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_algorithms_case9(&State);
    libspdm_unit_test_group_teardown(&State);

    /* capablities: SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_algorithms_case10(&State);
    libspdm_unit_test_group_teardown(&State);

    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_algorithms_case11(&State);
    libspdm_unit_test_group_teardown(&State);

    /* V1.3 requester*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_algorithms_case12(&State);
    libspdm_unit_test_group_teardown(&State);
}
