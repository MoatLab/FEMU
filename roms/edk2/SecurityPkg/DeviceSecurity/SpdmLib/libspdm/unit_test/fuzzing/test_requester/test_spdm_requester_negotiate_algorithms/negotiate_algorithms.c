/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

uint8_t temp_buf[LIBSPDM_RECEIVER_BUFFER_SIZE];

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

libspdm_return_t libspdm_device_send_message(void *spdm_context, size_t request_size,
                                             const void *request, uint64_t timeout)
{
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_device_receive_message(void *spdm_context, size_t *response_size,
                                                void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    uint8_t *spdm_response;
    size_t spdm_response_size;
    size_t test_message_header_size;

    spdm_test_context = libspdm_get_test_context();
    test_message_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    spdm_response = (void *)((uint8_t *)temp_buf + test_message_header_size);
    spdm_response_size = spdm_test_context->test_buffer_size;
    if (spdm_response_size > sizeof(temp_buf) - test_message_header_size - LIBSPDM_TEST_ALIGNMENT) {
        spdm_response_size = sizeof(temp_buf) - test_message_header_size - LIBSPDM_TEST_ALIGNMENT;
    }
    libspdm_copy_mem((uint8_t *)temp_buf + test_message_header_size,
                     sizeof(temp_buf) - test_message_header_size,
                     spdm_test_context->test_buffer,
                     spdm_response_size);

    libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                          spdm_response_size,
                                          spdm_response, response_size, response);

    return LIBSPDM_STATUS_SUCCESS;
}

void libspdm_test_requester_negotiate_algorithms_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    libspdm_reset_message_a(spdm_context);

    libspdm_negotiate_algorithms(spdm_context);
}

void libspdm_test_requester_negotiate_algorithms_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    libspdm_reset_message_a(spdm_context);

    libspdm_negotiate_algorithms(spdm_context);
}

void libspdm_test_requester_negotiate_algorithms_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

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

    libspdm_negotiate_algorithms(spdm_context);
}

void libspdm_test_requester_negotiate_algorithms_case4(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
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

    libspdm_negotiate_algorithms(spdm_context);
}

void libspdm_test_requester_negotiate_algorithms_case5(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_test_context = *State;
    uint32_t connection_capability_flags;

    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.algorithm.other_params_support = 0;

    spdm_context->local_context.capability.flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
                                                   SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP|
                                                   SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP|
                                                   SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP|
                                                   SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    connection_capability_flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    spdm_context->connection_info.capability.flags = connection_capability_flags;

    /* Sub Case 0: Initially*/
    libspdm_negotiate_algorithms(spdm_context);

    /* Sub Case 1: MEL_CAP set 1,mel_specification set SPDM_MEL_SPECIFICATION_DMTF*/
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.mel_spec = SPDM_MEL_SPECIFICATION_DMTF;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_negotiate_algorithms(spdm_context);

    /* Sub Case 2: MEL_CAP set 1, mel_specification set 0*/
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.mel_spec = 0;
    libspdm_negotiate_algorithms(spdm_context);

    /* Sub Case 3:MEL_CAP set 0, mel_specification set SPDM_MEL_SPECIFICATION_DMTF*/
    spdm_context->connection_info.capability.flags = connection_capability_flags;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.mel_spec = SPDM_MEL_SPECIFICATION_DMTF;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_negotiate_algorithms(spdm_context);

    /* Sub Case 4: MEL_CAP set 0, mel_specification set 0*/
    spdm_context->connection_info.capability.flags = connection_capability_flags;
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.mel_spec = 0;
    libspdm_negotiate_algorithms(spdm_context);

    /* Sub Case 5: MULTI_KEY_CAP set 01b*/
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_ONLY;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY;
    spdm_context->local_context.algorithm.other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    libspdm_negotiate_algorithms(spdm_context);

    /* Sub Case 6: MULTI_KEY_CAP set 10b*/
    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_NEG;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_NEG;
    spdm_context->local_context.algorithm.other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    libspdm_negotiate_algorithms(spdm_context);
}

libspdm_test_context_t m_libspdm_test_requester_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_test_requester_context);

    m_libspdm_test_requester_context.test_buffer = test_buffer;
    m_libspdm_test_requester_context.test_buffer_size = test_buffer_size;

    /* Successful V1.0 response*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_negotiate_algorithms_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Successful V1.1 response*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_negotiate_algorithms_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_negotiate_algorithms_case3(&State);
    libspdm_unit_test_group_teardown(&State);

    /* V1.2 response*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_negotiate_algorithms_case4(&State);
    libspdm_unit_test_group_teardown(&State);

    /* V1.3 response*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_negotiate_algorithms_case5(&State);
    libspdm_unit_test_group_teardown(&State);
}
