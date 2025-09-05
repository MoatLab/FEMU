/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

libspdm_test_context_t m_libspdm_responder_psk_exchange_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

typedef struct
{
    spdm_message_header_t header;
    uint16_t req_session_id;
    uint16_t psk_hint_length;
    uint16_t context_length;
    uint16_t opaque_length;
    uint8_t psk_hint[LIBSPDM_PSK_MAX_HINT_LENGTH];
    uint8_t context[LIBSPDM_PSK_CONTEXT_LENGTH];
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
} libspdm_psk_exchange_request_mine_t;

void libspdm_test_responder_psk_exchange_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void *data;
    size_t data_size;
    libspdm_psk_exchange_request_mine_t *spdm_test_psk_exchange_request;
    size_t spdm_test_psk_exchange_request_size;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_psk_exchange_request =
        (libspdm_psk_exchange_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_psk_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->connection_info.local_used_cert_chain_buffer = data;
    spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size;

    libspdm_reset_message_a(spdm_context);

    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    ptr = spdm_test_psk_exchange_request->psk_hint;
    libspdm_copy_mem(ptr, sizeof(spdm_test_psk_exchange_request->psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    if (spdm_test_psk_exchange_request->psk_hint_length <= LIBSPDM_PSK_MAX_HINT_LENGTH) {
        ptr += spdm_test_psk_exchange_request->psk_hint_length;
    } else {
        ptr += LIBSPDM_PSK_MAX_HINT_LENGTH;
    }
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    if (spdm_test_psk_exchange_request->context_length <= LIBSPDM_PSK_CONTEXT_LENGTH) {
        ptr += spdm_test_psk_exchange_request->context_length;
    } else {
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
    }
    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_psk_exchange_req_size,
                                                     ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);

    libspdm_get_response_psk_exchange(
        spdm_context, spdm_test_psk_exchange_request_size,
        spdm_test_psk_exchange_request, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}

void libspdm_test_responder_psk_exchange_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void *data;
    size_t data_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->connection_info.local_used_cert_chain_buffer = data;
    spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size;

    libspdm_reset_message_a(spdm_context);

    response_size = sizeof(response);
    libspdm_get_response_psk_exchange(
        spdm_context,  spdm_test_context->test_buffer_size,
        spdm_test_context->test_buffer, &response_size, response);

    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
void libspdm_test_responder_psk_exchange_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void *data;
    size_t data_size;
    libspdm_psk_exchange_request_mine_t *spdm_test_psk_exchange_request;
    size_t spdm_test_psk_exchange_request_size;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_psk_exchange_request =
        (libspdm_psk_exchange_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_psk_exchange_request_size = spdm_test_context->test_buffer_size;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->connection_info.local_used_cert_chain_buffer = data;
    spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size;

    libspdm_reset_message_a(spdm_context);

    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    ptr = spdm_test_psk_exchange_request->psk_hint;
    libspdm_copy_mem(ptr, sizeof(spdm_test_psk_exchange_request->psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    if (spdm_test_psk_exchange_request->psk_hint_length <= LIBSPDM_PSK_MAX_HINT_LENGTH) {
        ptr += spdm_test_psk_exchange_request->psk_hint_length;
    } else {
        ptr += LIBSPDM_PSK_MAX_HINT_LENGTH;
    }
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    if (spdm_test_psk_exchange_request->context_length <= LIBSPDM_PSK_CONTEXT_LENGTH) {
        ptr += spdm_test_psk_exchange_request->context_length;
    } else {
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
    }
    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_psk_exchange_req_size,
                                                     ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);

    libspdm_get_response_psk_exchange(spdm_context, spdm_test_psk_exchange_request_size,
                                      spdm_test_psk_exchange_request, &response_size,
                                      response);
    free(data);
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

void libspdm_test_responder_psk_exchange_case4(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void *data;
    size_t data_size;
    libspdm_psk_exchange_request_mine_t *spdm_test_psk_exchange_request;
    size_t spdm_test_psk_exchange_request_size;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_psk_exchange_request =
        (libspdm_psk_exchange_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_psk_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->connection_info.local_used_cert_chain_buffer = data;
    spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size;

    libspdm_reset_message_a(spdm_context);

    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    ptr = spdm_test_psk_exchange_request->psk_hint;
    libspdm_copy_mem(ptr, sizeof(spdm_test_psk_exchange_request->psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    if (spdm_test_psk_exchange_request->psk_hint_length <= LIBSPDM_PSK_MAX_HINT_LENGTH) {
        ptr += spdm_test_psk_exchange_request->psk_hint_length;
    } else {
        ptr += LIBSPDM_PSK_MAX_HINT_LENGTH;
    }
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    if (spdm_test_psk_exchange_request->context_length <= LIBSPDM_PSK_CONTEXT_LENGTH) {
        ptr += spdm_test_psk_exchange_request->context_length;
    } else {
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
    }
    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_psk_exchange_req_size,
                                                     ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);

    libspdm_get_response_psk_exchange(spdm_context, spdm_test_psk_exchange_request_size,
                                      spdm_test_psk_exchange_request, &response_size,
                                      response);

    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}

void libspdm_test_responder_psk_exchange_case5(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void *data;
    size_t data_size;
    libspdm_psk_exchange_request_mine_t *spdm_test_psk_exchange_request;
    size_t spdm_test_psk_exchange_request_size;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_psk_exchange_request =
        (libspdm_psk_exchange_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_psk_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->connection_info.local_used_cert_chain_buffer = data;
    spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size;


    libspdm_reset_message_a(spdm_context);

    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    ptr = spdm_test_psk_exchange_request->psk_hint;
    libspdm_copy_mem(ptr, sizeof(spdm_test_psk_exchange_request->psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    if (spdm_test_psk_exchange_request->psk_hint_length <= LIBSPDM_PSK_MAX_HINT_LENGTH) {
        ptr += spdm_test_psk_exchange_request->psk_hint_length;
    } else {
        ptr += LIBSPDM_PSK_MAX_HINT_LENGTH;
    }
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    if (spdm_test_psk_exchange_request->context_length <= LIBSPDM_PSK_CONTEXT_LENGTH) {
        ptr += spdm_test_psk_exchange_request->context_length;
    } else {
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
    }
    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_psk_exchange_req_size,
                                                     ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);

    libspdm_get_response_psk_exchange(spdm_context, spdm_test_psk_exchange_request_size,
                                      spdm_test_psk_exchange_request, &response_size,
                                      response);

    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}

void libspdm_test_responder_psk_exchange_case6(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void *data;
    size_t data_size;
    libspdm_psk_exchange_request_mine_t *spdm_test_psk_exchange_request;
    size_t spdm_test_psk_exchange_request_size;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_psk_exchange_request =
        (libspdm_psk_exchange_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_psk_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->connection_info.local_used_cert_chain_buffer = data;
    spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size;

    libspdm_reset_message_a(spdm_context);

    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    ptr = spdm_test_psk_exchange_request->psk_hint;
    libspdm_copy_mem(ptr, sizeof(spdm_test_psk_exchange_request->psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    if (spdm_test_psk_exchange_request->psk_hint_length <= LIBSPDM_PSK_MAX_HINT_LENGTH) {
        ptr += spdm_test_psk_exchange_request->psk_hint_length;
    } else {
        ptr += LIBSPDM_PSK_MAX_HINT_LENGTH;
    }
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    if (spdm_test_psk_exchange_request->context_length <= LIBSPDM_PSK_CONTEXT_LENGTH) {
        ptr += spdm_test_psk_exchange_request->context_length;
    } else {
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
    }
    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_psk_exchange_req_size,
                                                     ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);

    libspdm_get_response_psk_exchange(
        spdm_context, spdm_test_psk_exchange_request_size,
        spdm_test_psk_exchange_request, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}

void libspdm_test_responder_psk_exchange_case7(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void *data;
    size_t data_size;
    libspdm_psk_exchange_request_mine_t *spdm_test_psk_exchange_request;
    size_t spdm_test_psk_exchange_request_size;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_psk_exchange_request =
        (libspdm_psk_exchange_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_psk_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->connection_info.local_used_cert_chain_buffer = data;
    spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size;

    libspdm_reset_message_a(spdm_context);

    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    ptr = spdm_test_psk_exchange_request->psk_hint;
    libspdm_copy_mem(ptr, sizeof(spdm_test_psk_exchange_request->psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    if (spdm_test_psk_exchange_request->psk_hint_length <= LIBSPDM_PSK_MAX_HINT_LENGTH) {
        ptr += spdm_test_psk_exchange_request->psk_hint_length;
    } else {
        ptr += LIBSPDM_PSK_MAX_HINT_LENGTH;
    }
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    if (spdm_test_psk_exchange_request->context_length <= LIBSPDM_PSK_CONTEXT_LENGTH) {
        ptr += spdm_test_psk_exchange_request->context_length;
    } else {
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
    }
    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_psk_exchange_req_size,
                                                     ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);

    libspdm_get_response_psk_exchange(spdm_context, spdm_test_psk_exchange_request_size,
                                      spdm_test_psk_exchange_request, &response_size,
                                      response);

    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;
    spdm_message_header_t *spdm_request_header;
    libspdm_setup_test_context(&m_libspdm_responder_psk_exchange_test_context);

    spdm_request_header = (spdm_message_header_t*)test_buffer;

    if (spdm_request_header->request_response_code != SPDM_PSK_EXCHANGE) {
        spdm_request_header->request_response_code = SPDM_PSK_EXCHANGE;
    }

    m_libspdm_responder_psk_exchange_test_context.test_buffer = (void *)test_buffer;
    m_libspdm_responder_psk_exchange_test_context.test_buffer_size = test_buffer_size;

    /* Success Case*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_psk_exchange_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Use the original seed, without changing request as input */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_psk_exchange_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    #if LIBSPDM_RESPOND_IF_READY_SUPPORT
    /* response_state: SPDM_RESPONSE_STATE_NOT_READY*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_psk_exchange_case3(&State);
    libspdm_unit_test_group_teardown(&State);
    #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

    /* capability.flags: SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_psk_exchange_case4(&State);
    libspdm_unit_test_group_teardown(&State);

    /* capability.flags: SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_psk_exchange_case5(&State);
    libspdm_unit_test_group_teardown(&State);

    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_psk_exchange_case6(&State);
    libspdm_unit_test_group_teardown(&State);

    /* capability.flags: SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_psk_exchange_case7(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/
