/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

uint8_t m_cert_chain_buffer[SPDM_MAX_CERTIFICATE_CHAIN_SIZE];

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

libspdm_test_context_t m_libspdm_responder_key_exchange_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

typedef struct {
    spdm_message_header_t header;
    uint16_t req_session_id;
    uint16_t reserved;
    uint8_t random_data[SPDM_RANDOM_DATA_SIZE];
    uint8_t exchange_data[LIBSPDM_MAX_DHE_KEY_SIZE];
    uint16_t opaque_length;
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
} libspdm_key_exchange_request_mine_t;

void libspdm_test_responder_key_exchange_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_key_exchange_request_mine_t *spdm_test_key_exchange_request;
    size_t spdm_test_key_exchange_request_size;
    void *data;
    size_t data_size;

    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_key_exchange_request =
        (libspdm_key_exchange_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_key_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    ptr = spdm_test_key_exchange_request->exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_key_exchange_req_size,
                                                     ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);

    libspdm_get_response_key_exchange(spdm_context, spdm_test_key_exchange_request_size,
                                      spdm_test_key_exchange_request, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}

void libspdm_test_responder_key_exchange_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_key_exchange_request_mine_t *spdm_test_key_exchange_request;
    size_t spdm_test_key_exchange_request_size;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void *data;
    size_t data_size;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_key_exchange_request =
        (libspdm_key_exchange_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_key_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;
    ptr = spdm_test_key_exchange_request->exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_key_exchange_req_size,
                                                     ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);

    libspdm_get_response_key_exchange(spdm_context, spdm_test_key_exchange_request_size,
                                      spdm_test_key_exchange_request, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}

void libspdm_test_responder_key_exchange_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    const libspdm_key_exchange_request_mine_t *spdm_test_key_exchange_request;
    size_t spdm_test_key_exchange_request_size;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void *data;
    size_t data_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_key_exchange_request =
        (const libspdm_key_exchange_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_key_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_MAX;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    response_size = sizeof(response);

    libspdm_get_response_key_exchange(spdm_context, spdm_test_key_exchange_request_size,
                                      spdm_test_key_exchange_request, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && \
    (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)
void libspdm_test_responder_key_exchange_case4(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_key_exchange_request_mine_t *spdm_test_key_exchange_request;
    size_t spdm_test_key_exchange_request_size;
    void *data;
    size_t data_size;

    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_key_exchange_request =
        (libspdm_key_exchange_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_key_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    libspdm_register_cert_chain_buffer(spdm_context, m_cert_chain_buffer,
                                       sizeof(m_cert_chain_buffer));

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 1;

    ptr = spdm_test_key_exchange_request->exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_key_exchange_req_size,
                                                     ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);

    libspdm_get_response_key_exchange(spdm_context, spdm_test_key_exchange_request_size,
                                      spdm_test_key_exchange_request, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}
#endif

void libspdm_test_responder_key_exchange_case5(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_key_exchange_request_mine_t *spdm_test_key_exchange_request;
    size_t spdm_test_key_exchange_request_size;
    void *data;
    size_t data_size;

    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_key_exchange_request =
        (libspdm_key_exchange_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_key_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    ptr = spdm_test_key_exchange_request->exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_key_exchange_req_size,
                                                     ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);

    libspdm_get_response_key_exchange(spdm_context, spdm_test_key_exchange_request_size,
                                      spdm_test_key_exchange_request, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}

void libspdm_test_responder_key_exchange_case6(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_key_exchange_request_mine_t *spdm_test_key_exchange_request;
    size_t spdm_test_key_exchange_request_size;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void *data;
    size_t data_size;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_key_exchange_request =
        (libspdm_key_exchange_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_key_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    ptr = spdm_test_key_exchange_request->exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_key_exchange_req_size,
                                                     ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);

    libspdm_get_response_key_exchange(spdm_context, spdm_test_key_exchange_request_size,
                                      spdm_test_key_exchange_request, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}

void libspdm_test_responder_key_exchange_case7(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_key_exchange_request_mine_t *spdm_test_key_exchange_request;
    size_t spdm_test_key_exchange_request_size;
    void *data;
    size_t data_size;

    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_key_exchange_request =
        (libspdm_key_exchange_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_key_exchange_request_size = spdm_test_context->test_buffer_size;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= 0xFFFFFFFF;
    spdm_context->local_context.capability.flags |= 0xFFFFFFFF;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    ptr = spdm_test_key_exchange_request->exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_key_exchange_req_size,
                                                     ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);

    libspdm_get_response_key_exchange(spdm_context, spdm_test_key_exchange_request_size,
                                      spdm_test_key_exchange_request, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}

void libspdm_test_responder_key_exchange_case8(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_key_exchange_request_mine_t *spdm_test_key_exchange_request;
    size_t spdm_test_key_exchange_request_size;
    void *data1;
    size_t data_size1;
    void *data2;
    size_t data_size2;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_key_exchange_request =
        (libspdm_key_exchange_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_key_exchange_request_size = spdm_test_context->test_buffer_size;
    spdm_test_key_exchange_request->header.param2 = 0xFF;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_key(m_libspdm_use_asym_algo, &data1, &data_size1);
    spdm_context->local_context.local_public_key_provision = data1;
    spdm_context->local_context.local_public_key_provision_size = data_size1;
    libspdm_read_requester_public_key(m_libspdm_use_req_asym_algo, &data2, &data_size2);
    spdm_context->local_context.peer_public_key_provision = data2;
    spdm_context->local_context.peer_public_key_provision_size = data_size2;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    ptr = spdm_test_key_exchange_request->exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data(spdm_context, &opaque_key_exchange_req_size,
                                                     ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);

    libspdm_get_response_key_exchange(spdm_context, spdm_test_key_exchange_request_size,
                                      spdm_test_key_exchange_request, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data1);
    free(data2);
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;
    spdm_message_header_t *spdm_request_header;
    libspdm_setup_test_context(&m_libspdm_responder_key_exchange_test_context);

    spdm_request_header = (spdm_message_header_t*)test_buffer;

    if (spdm_request_header->request_response_code != SPDM_KEY_EXCHANGE) {
        spdm_request_header->request_response_code = SPDM_KEY_EXCHANGE;
    }

    m_libspdm_responder_key_exchange_test_context.test_buffer = test_buffer;
    m_libspdm_responder_key_exchange_test_context.test_buffer_size = test_buffer_size;

    /* Success Case*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_key_exchange_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /* capability.flags: SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_key_exchange_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    /* response_state: SPDM_RESPONSE_STATE_BUSY*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_key_exchange_case3(&State);
    libspdm_unit_test_group_teardown(&State);

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && \
    (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)
    /* return response mut_auth_requested  */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_key_exchange_case4(&State);
    libspdm_unit_test_group_teardown(&State);
#endif

    /*capability.flags: SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_key_exchange_case5(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Buffer reset */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_key_exchange_case6(&State);
    libspdm_unit_test_group_teardown(&State);

    /* All capabilities flags are supported in the current SPDM connection */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_key_exchange_case7(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Request previously provisioned public key, slot 0xFF */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_key_exchange_case8(&State);
    libspdm_unit_test_group_teardown(&State);
}


#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
