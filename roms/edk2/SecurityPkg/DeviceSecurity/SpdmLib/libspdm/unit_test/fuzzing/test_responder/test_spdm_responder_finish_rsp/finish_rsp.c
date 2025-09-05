/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

static libspdm_th_managed_buffer_t th_curr;

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

libspdm_test_context_t m_libspdm_responder_finish_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_secured_message_set_request_finished_key(void *spdm_secured_message_context,
                                                      const void *key, size_t key_size)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    LIBSPDM_ASSERT(key_size == secured_message_context->hash_size);
    libspdm_copy_mem(secured_message_context->handshake_secret.request_finished_key,
                     sizeof(secured_message_context->handshake_secret.request_finished_key),
                     key, secured_message_context->hash_size);
}

typedef struct
{
    spdm_message_header_t header;
    uint8_t signature[LIBSPDM_MAX_ASYM_KEY_SIZE];
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} libspdm_finish_request_mine_t;

void libspdm_test_responder_finish_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    libspdm_finish_request_mine_t *spdm_test_finish_request;
    size_t spdm_test_finish_request_size;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t dummy_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *State;

    spdm_test_finish_request = (libspdm_finish_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_finish_request_size = spdm_test_context->test_buffer_size;

    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo,
                                                    &data1, &data_size1,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(session_info->secured_message_context,
                                                     dummy_buffer, hash_size);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);

    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = spdm_test_finish_request->signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size, cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, spdm_test_finish_request,
                                  sizeof(spdm_finish_request_t));
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    spdm_test_finish_request_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    libspdm_get_response_finish(spdm_context, spdm_test_finish_request_size,
                                spdm_test_finish_request,
                                &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_f(spdm_context, spdm_context->session_info);
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data1);
}

void libspdm_test_responder_finish_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;

    response_size = sizeof(response);
    libspdm_get_response_finish(spdm_context, spdm_test_context->test_buffer_size,
                                spdm_test_context->test_buffer, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_f(spdm_context, spdm_context->session_info);
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
}

void libspdm_test_responder_finish_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;

    response_size = sizeof(response);
    libspdm_get_response_finish(spdm_context, spdm_test_context->test_buffer_size,
                                spdm_test_context->test_buffer, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_f(spdm_context, spdm_context->session_info);
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
}

void libspdm_test_responder_finish_case4(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    response_size = sizeof(response);
    libspdm_get_response_finish(spdm_context, spdm_test_context->test_buffer_size,
                                spdm_test_context->test_buffer, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_f(spdm_context, spdm_context->session_info);
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
}

void libspdm_test_responder_finish_case5(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context = *State;

    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    response_size = sizeof(response);
    libspdm_get_response_finish(spdm_context, spdm_test_context->test_buffer_size,
                                spdm_test_context->test_buffer, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_f(spdm_context, spdm_context->session_info);
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
}

void libspdm_test_responder_finish_case6(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context = *State;

    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->last_spdm_request_session_id_valid = !false;
    response_size = sizeof(response);
    libspdm_get_response_finish(spdm_context, spdm_test_context->test_buffer_size,
                                spdm_test_context->test_buffer, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_f(spdm_context, spdm_context->session_info);
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
}

void libspdm_test_responder_finish_case7(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void *data1;
    size_t data_size1;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;

    uint8_t dummy_buffer[LIBSPDM_MAX_HASH_SIZE];
    spdm_test_context = *State;

    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo,
                                                    &data1, &data_size1,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(session_info->secured_message_context,
                                                     dummy_buffer, hash_size);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_NOT_STARTED);
    libspdm_secured_message_set_request_finished_key(session_info->secured_message_context,
                                                     dummy_buffer, hash_size);

    response_size = sizeof(response);
    libspdm_get_response_finish(spdm_context, spdm_test_context->test_buffer_size,
                                spdm_test_context->test_buffer, &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_f(spdm_context, spdm_context->session_info);
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data1);
}

void libspdm_test_responder_finish_case8(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void *data1;
    size_t data_size1;
    void *data2;
    size_t data_size2;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    size_t req_asym_signature_size;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t dummy_buffer[LIBSPDM_MAX_HASH_SIZE];
    libspdm_finish_request_mine_t *spdm_test_finish_request;
    size_t spdm_test_finish_request_size;

    spdm_test_context = *State;

    spdm_test_finish_request = (libspdm_finish_request_mine_t *)spdm_test_context->test_buffer;
    spdm_test_finish_request_size = spdm_test_context->test_buffer_size;

    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo,
                                                    &data1, &data_size1,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 1;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo,
                                                    &data2,
                                                    &data_size2, NULL, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = data_size2;
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data2, data_size2,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        data2,
        data_size2,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
    session_id = 0xFFFFFEE;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(session_info->secured_message_context,
                                                     dummy_buffer, hash_size);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 1;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;

    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    req_asym_signature_size = libspdm_get_req_asym_signature_size(m_libspdm_use_req_asym_algo);
    ptr = spdm_test_finish_request->signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size, cert_buffer_hash);
    cert_buffer = (uint8_t *)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size, req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    libspdm_append_managed_buffer(&th_curr, spdm_test_finish_request,
                                  sizeof(spdm_finish_request_t));
    /* The caller need guarantee the version is correct, both of MajorVersion and MinorVersion should be less than 10.*/
    if (((spdm_test_finish_request->header.spdm_version & 0xF) >= 10) ||
        (((spdm_test_finish_request->header.spdm_version >> 4) & 0xF) >= 10)) {
        spdm_test_finish_request->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    }

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        spdm_test_finish_request->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo, false,
            libspdm_get_managed_buffer(&th_curr),
            libspdm_get_managed_buffer_size(&th_curr), ptr, &req_asym_signature_size);
#endif
    libspdm_append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    spdm_test_finish_request_size =
        sizeof(spdm_finish_request_t) + req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    libspdm_get_response_finish(spdm_context, spdm_test_finish_request_size,
                                spdm_test_finish_request,
                                &response_size, response);
    if (spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_reset_message_f(spdm_context, spdm_context->session_info);
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data1);
    free(data2);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = 0;
#else
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size = 0;
    libspdm_req_asym_free(
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;
    spdm_message_header_t *spdm_request_header;
    libspdm_setup_test_context(&m_libspdm_responder_finish_test_context);

    spdm_request_header = (spdm_message_header_t*)test_buffer;

    if (spdm_request_header->request_response_code != SPDM_FINISH) {
        spdm_request_header->request_response_code = SPDM_FINISH;
    }

    m_libspdm_responder_finish_test_context.test_buffer = (void *)test_buffer;
    m_libspdm_responder_finish_test_context.test_buffer_size = test_buffer_size;

    /* Success Case*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_finish_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /*response_state: LIBSPDM_RESPONSE_STATE_BUSY */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_finish_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    /*not supported capabilities_flag */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_finish_case3(&State);
    libspdm_unit_test_group_teardown(&State);
    /* connection_state Check */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_finish_case4(&State);
    libspdm_unit_test_group_teardown(&State);
    /* No handshake in clear, then it must be in a session.*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_finish_case5(&State);
    libspdm_unit_test_group_teardown(&State);
    /* handshake in clear, then it must not be in a session.*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_finish_case6(&State);
    libspdm_unit_test_group_teardown(&State);
    /* secured_message_context:= LIBSPDM_SESSION_STATE_NOT_STARTED */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_finish_case7(&State);
    libspdm_unit_test_group_teardown(&State);
    /* Success Case */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_finish_case8(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
