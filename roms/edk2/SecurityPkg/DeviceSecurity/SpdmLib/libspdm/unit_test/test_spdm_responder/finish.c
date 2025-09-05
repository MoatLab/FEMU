/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#pragma pack(1)

typedef struct {
    spdm_message_header_t header;
    uint8_t signature[LIBSPDM_MAX_ASYM_KEY_SIZE];
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} libspdm_finish_request_mine_t;

#pragma pack()

libspdm_finish_request_mine_t m_libspdm_finish_request1 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_FINISH, 0, 0 },
};
size_t m_libspdm_finish_request1_size = sizeof(m_libspdm_finish_request1);

libspdm_finish_request_mine_t m_libspdm_finish_request3 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_FINISH, 1, 0 },
};
size_t m_libspdm_finish_request3_size = sizeof(m_libspdm_finish_request3);

libspdm_finish_request_mine_t m_libspdm_finish_request4 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_FINISH, 1, 0xFF },
};
size_t m_libspdm_finish_request4_size = sizeof(m_libspdm_finish_request4);

libspdm_finish_request_mine_t m_libspdm_finish_request5 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_FINISH, 1, 10 },
};
size_t m_libspdm_finish_request5_size = sizeof(m_libspdm_finish_request5);

libspdm_finish_request_mine_t m_libspdm_finish_request6 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_FINISH, 6, 10 },
};
size_t m_libspdm_finish_request6_size = sizeof(m_libspdm_finish_request6);

libspdm_finish_request_mine_t m_libspdm_finish_request7 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_FINISH, 1, 3 },
};
size_t m_libspdm_finish_request7_size = sizeof(m_libspdm_finish_request7);

uint8_t m_dummy_buffer[LIBSPDM_MAX_HASH_SIZE];

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

static libspdm_th_managed_buffer_t th_curr;

void libspdm_secured_message_set_request_finished_key(
    void *spdm_secured_message_context, const void *key, size_t key_size)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    LIBSPDM_ASSERT(key_size == secured_message_context->hash_size);
    libspdm_copy_mem(secured_message_context->handshake_secret.request_finished_key,
                     sizeof(secured_message_context->handshake_secret.request_finished_key),
                     key, secured_message_context->hash_size);
}

/**
 * Test 1: receiving a correct FINISH message from the requester with a
 * correct MAC, no signature (no mutual authentication), and 'handshake in
 * the clear'.
 * Expected behavior: the responder accepts the request and produces a valid
 * FINISH_RSP response message.
 **/
void libspdm_test_responder_finish_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_libspdm_finish_request1.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request1,
                                  sizeof(spdm_finish_request_t));
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request1_size,
                                         &m_libspdm_finish_request1,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_finish_response_t) + hmac_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_FINISH_RSP);
    free(data1);
}

/**
 * Test 2:
 * Expected behavior:
 **/
void libspdm_test_responder_finish_case2(void **state)
{
}

/**
 * Test 3: receiving a correct FINISH from the requester, but the
 * responder is in a Busy state.
 * Expected behavior: the responder accepts the request, but produces an
 * ERROR message indicating the Busy state.
 **/
void libspdm_test_responder_finish_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_libspdm_finish_request1.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request1,
                                  sizeof(spdm_finish_request_t));
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request1_size,
                                         &m_libspdm_finish_request1,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_BUSY);
    free(data1);
}

/**
 * Test 4: receiving a correct FINISH from the requester, but the responder
 * requires resynchronization with the requester.
 * Expected behavior: the responder accepts the request, but produces an
 * ERROR message indicating the NeedResynch state.
 **/
void libspdm_test_responder_finish_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_libspdm_finish_request1.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request1,
                                  sizeof(spdm_finish_request_t));
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request1_size,
                                         &m_libspdm_finish_request1,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_REQUEST_RESYNCH);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_NEED_RESYNC);
    free(data1);
}

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
/**
 * Test 5: receiving a correct FINISH from the requester, but the responder
 * could not produce the response in time.
 * Expected behavior: the responder accepts the request, but produces an
 * ERROR message indicating the ResponseNotReady state.
 **/
void libspdm_test_responder_finish_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    spdm_error_data_response_not_ready_t *error_data;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_libspdm_finish_request1.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request1,
                                  sizeof(spdm_finish_request_t));
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request1_size,
                                         &m_libspdm_finish_request1,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_error_response_t) +
                     sizeof(spdm_error_data_response_not_ready_t));
    spdm_response = (void *)response;
    error_data =
        (spdm_error_data_response_not_ready_t *)(spdm_response + 1);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESPONSE_NOT_READY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_NOT_READY);
    assert_int_equal(error_data->request_code, SPDM_FINISH);
    free(data1);
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

/**
 * Test 6: receiving a correct FINISH from the requester, but the responder
 * is not set no receive a FINISH message because previous messages (namely,
 * GET_CAPABILITIES, NEGOTIATE_ALGORITHMS or GET_DIGESTS) have not been
 * received.
 * Expected behavior: the responder rejects the request, and produces an
 * ERROR message indicating the UnexpectedRequest.
 **/
void libspdm_test_responder_finish_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_libspdm_finish_request1.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request1,
                                  sizeof(spdm_finish_request_t));
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request1_size,
                                         &m_libspdm_finish_request1,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

void libspdm_test_responder_finish_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_libspdm_finish_request1.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    session_info->session_transcript.message_m.buffer_size =
        session_info->session_transcript.message_m.max_buffer_size;
    spdm_context->transcript.message_b.buffer_size =
        spdm_context->transcript.message_b.max_buffer_size;
    spdm_context->transcript.message_c.buffer_size =
        spdm_context->transcript.message_c.max_buffer_size;
    spdm_context->transcript.message_mut_b.buffer_size =
        spdm_context->transcript.message_mut_b.max_buffer_size;
    spdm_context->transcript.message_mut_c.buffer_size =
        spdm_context->transcript.message_mut_c.max_buffer_size;
#endif

    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request1,
                                  sizeof(spdm_finish_request_t));
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request1_size,
                                         &m_libspdm_finish_request1,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_finish_response_t) + hmac_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_FINISH_RSP);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(session_info->session_transcript.message_m.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#endif

    free(data1);
}

/**
 * Test 8: receiving a correct FINISH message from the requester with
 * correct MAC and signature (with mutual authentication), and 'handshake in
 * the clear'.
 * Expected behavior: the responder accepts the request and produces a valid
 * FINISH_RSP response message.
 **/
void libspdm_test_responder_finish_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    void *data2;
    size_t data_size2;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    size_t req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
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
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 1;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data2,
                                                    &data_size2, NULL, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size2;
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
    spdm_context->connection_info.peer_used_cert_chain_slot_id = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 1;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_libspdm_use_req_asym_algo);
    ptr = m_libspdm_finish_request3.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t *)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request3,
                                  sizeof(spdm_finish_request_t));
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        m_libspdm_finish_request3.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, libspdm_get_managed_buffer(&th_curr),
            libspdm_get_managed_buffer_size(&th_curr),
            ptr, &req_asym_signature_size);
#endif
    libspdm_append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request3_size = sizeof(spdm_finish_request_t) +
                                     req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request3_size,
                                         &m_libspdm_finish_request3,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_finish_response_t) + hmac_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_FINISH_RSP);
    free(data1);
    free(data2);
}

/**
 * Test 9: receiving a correct FINISH message from the requester, but the
 * responder has no capabilities for key exchange.
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the UnsupportedRequest.
 **/
void libspdm_test_responder_finish_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    /* no key exchange capabilities (responder)*/
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_libspdm_finish_request1.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request1,
                                  sizeof(spdm_finish_request_t));
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request1_size,
                                         &m_libspdm_finish_request1,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_FINISH);
    free(data1);
}

/**
 * Test 10: receiving a correct FINISH message from the requester, but the
 * responder is not correctly setup by not initializing a session during
 * KEY_EXCHANGE.
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the UnsupportedRequest.
 **/
void libspdm_test_responder_finish_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_NOT_STARTED);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_libspdm_finish_request1.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request1,
                                  sizeof(spdm_finish_request_t));
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request1_size,
                                         &m_libspdm_finish_request1,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

/**
 * Test 11: receiving a FINISH message from the requester with an incorrect
 * MAC (all-zero).
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the DecryptError.
 **/
void libspdm_test_responder_finish_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_libspdm_finish_request1.signature;
    libspdm_set_mem(ptr, hmac_size, (uint8_t)(0x00)); /*all-zero MAC*/
    m_libspdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request1_size,
                                         &m_libspdm_finish_request1,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_DECRYPT_ERROR);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

/**
 * Test 12: receiving a FINISH message from the requester with an incorrect
 * MAC (arbitrary).
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the DecryptError.
 **/
void libspdm_test_responder_finish_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    uint8_t zero_data[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_libspdm_finish_request1.signature;
    /*arbitrary MAC*/
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_set_mem(zero_data, hash_size, (uint8_t)(0x00));
    libspdm_hmac_all(m_libspdm_use_hash_algo, zero_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request1_size,
                                         &m_libspdm_finish_request1,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_DECRYPT_ERROR);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

/**
 * Test 13:
 * Expected behavior:
 **/
void libspdm_test_responder_finish_case13(void **state)
{
}

/**
 * Test 14: receiving a FINISH message from the requester with an incorrect
 * MAC size (only the correct first half of the MAC).
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the InvalidRequest.
 **/
void libspdm_test_responder_finish_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_libspdm_finish_request1.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request1,
                                  sizeof(spdm_finish_request_t));
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    libspdm_set_mem(ptr + hmac_size/2, hmac_size/2, (uint8_t) 0x00); /* half HMAC size*/
    m_libspdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size/2;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request1_size,
                                         &m_libspdm_finish_request1,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
}

/**
 * Test 15: receiving a FINISH message from the requester with an incorrect
 * signature (all-zero), but a correct MAC.
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the DecryptError.
 **/
void libspdm_test_responder_finish_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    void *data2;
    size_t data_size2;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    size_t req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
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
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 1;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data2,
                                                    &data_size2, NULL, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size2;
#endif

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 1;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_libspdm_use_req_asym_algo);
    ptr = m_libspdm_finish_request3.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t *)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request3,
                                  sizeof(spdm_finish_request_t));
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        m_libspdm_finish_request3.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, libspdm_get_managed_buffer(&th_curr),
            libspdm_get_managed_buffer_size(&th_curr),
            ptr, &req_asym_signature_size);
#endif
    libspdm_append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    libspdm_set_mem(m_libspdm_finish_request3.signature,
                    req_asym_signature_size, (uint8_t) 0x00); /*zero signature*/
    m_libspdm_finish_request3_size = sizeof(spdm_finish_request_t) +
                                     req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request3_size,
                                         &m_libspdm_finish_request3,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_DECRYPT_ERROR);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
    free(data2);
}

/**
 * Test 16: receiving a FINISH message from the requester with an incorrect
 * signature (arbitrary), but a correct MAC.
 * Expected behavior: the responder refuses the FINISH message and produces
 * an ERROR message indicating the DecryptError.
 **/
void libspdm_test_responder_finish_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    void *data2;
    size_t data_size2;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t random_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    size_t req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
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
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 1;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data2,
                                                    &data_size2, NULL, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size2;
#endif

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 1;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_libspdm_use_req_asym_algo);
    ptr = m_libspdm_finish_request3.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t *)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request3,
                                  sizeof(spdm_finish_request_t));
    /*randomize signature*/
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), random_buffer);
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        m_libspdm_finish_request3.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, random_buffer, hash_size, ptr, &req_asym_signature_size);
#endif
    libspdm_append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request3_size = sizeof(spdm_finish_request_t) +
                                     req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request3_size,
                                         &m_libspdm_finish_request3,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_DECRYPT_ERROR);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
    free(data2);
}

/**
 * Test 17: receiving a correct FINISH from the requester.
 * Expected behavior: the responder accepts the request and produces a valid FINISH
 * response message, and buffer F receives the exchanged FINISH and FINISH_RSP messages.
 **/
void libspdm_test_responder_finish_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
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
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer, hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context, LIBSPDM_SESSION_STATE_HANDSHAKING);

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_libspdm_finish_request1.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size, cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request1,
                                  sizeof(spdm_finish_request_t));
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request1_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(
        spdm_context, m_libspdm_finish_request1_size, &m_libspdm_finish_request1,
        &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_finish_response_t) + hmac_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_FINISH_RSP);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->session_info[0].session_transcript.message_f.buffer_size,
                     m_libspdm_finish_request1_size + response_size);
    assert_memory_equal(spdm_context->session_info[0].session_transcript.message_f.buffer,
                        &m_libspdm_finish_request1, m_libspdm_finish_request1_size);
    assert_memory_equal(spdm_context->session_info[0].session_transcript.message_f.buffer +
                        m_libspdm_finish_request1_size,
                        response, response_size);
#endif

    free(data1);
}

/**
 * Test 18: receiving a correct FINISH message from the requester with
 * correct MAC and signature (with mutual authentication), and 'handshake in
 * the clear'. The slot_id for requester mutual authentication is 0xFF.
 * Expected behavior: the responder accepts the request and produces a valid
 * FINISH_RSP response message.
 **/
void libspdm_test_responder_finish_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    void *data2;
    size_t data_size2;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    size_t req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_key(m_libspdm_use_asym_algo, &data1, &data_size1);
    spdm_context->local_context.local_public_key_provision = data1;
    spdm_context->local_context.local_public_key_provision_size = data_size1;
    spdm_context->local_context.mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    libspdm_read_requester_public_key(m_libspdm_use_req_asym_algo, &data2, &data_size2);
    spdm_context->local_context.peer_public_key_provision = data2;
    spdm_context->local_context.peer_public_key_provision_size = data_size2;

    spdm_context->encap_context.req_slot_id = 0xFF;
    spdm_context->connection_info.peer_used_cert_chain_slot_id = 0xFF;
    spdm_context->connection_info.local_used_cert_chain_slot_id = 0xFF;

    libspdm_reset_message_a(spdm_context);

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 1;

    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_libspdm_use_req_asym_algo);
    ptr = m_libspdm_finish_request4.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t *)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request4,
                                  sizeof(spdm_finish_request_t));
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        m_libspdm_finish_request4.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, libspdm_get_managed_buffer(&th_curr),
            libspdm_get_managed_buffer_size(&th_curr),
            ptr, &req_asym_signature_size);
#endif
    libspdm_append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;

    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request4_size = sizeof(spdm_finish_request_t) +
                                     req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request4_size,
                                         &m_libspdm_finish_request4,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_finish_response_t) + hmac_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_FINISH_RSP);
    free(data1);
    free(data2);
}

/**
 * Test 19: receiving a invalid FINISH request message, enable mutual authentication without using the encapsulated request flow,
 * that is KEY_EXCHANGE_RSP.MutAuthRequested equals 0x01.
 * SlotID in FINISH request message is 10, but it shall be 0xFF or between 0 and 7 inclusive.
 * Expected behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST.
 **/
void libspdm_test_responder_finish_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    void *data2;
    size_t data_size2;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    size_t req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
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
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data2,
                                                    &data_size2, NULL, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size2;
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
    spdm_context->connection_info.peer_used_cert_chain_slot_id = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_libspdm_use_req_asym_algo);
    ptr = m_libspdm_finish_request5.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t *)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request5,
                                  sizeof(spdm_finish_request_t));
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        m_libspdm_finish_request5.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, libspdm_get_managed_buffer(&th_curr),
            libspdm_get_managed_buffer_size(&th_curr),
            ptr, &req_asym_signature_size);
#endif
    libspdm_append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request5_size = sizeof(spdm_finish_request_t) +
                                     req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request5_size,
                                         &m_libspdm_finish_request5,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
    free(data2);
}

/**
 * Test 20: receiving a invalid FINISH request message, enable mutual authentication with using the encapsulated request flow,
 * that is KEY_EXCHANGE_RSP.MutAuthRequested equals 0x02.
 * SlotID in FINISH request message is 3, but it shall match the value 0 in final ENCAPSULATED_RESPONSE_ACK.EncapsulatedRequest.
 * Expected behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST.
 **/
void libspdm_test_responder_finish_case20(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    void *data2;
    size_t data_size2;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    size_t req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
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
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested =
        SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data2,
                                                    &data_size2, NULL, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size2;
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
    spdm_context->connection_info.peer_used_cert_chain_slot_id = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested =
        SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_libspdm_use_req_asym_algo);
    ptr = m_libspdm_finish_request7.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t *)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request7,
                                  sizeof(spdm_finish_request_t));
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        m_libspdm_finish_request7.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, libspdm_get_managed_buffer(&th_curr),
            libspdm_get_managed_buffer_size(&th_curr),
            ptr, &req_asym_signature_size);
#endif
    libspdm_append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request7_size = sizeof(spdm_finish_request_t) +
                                     req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request7_size,
                                         &m_libspdm_finish_request7,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(data1);
    free(data2);
}

/**
 * Test 21: receiving a valid FINISH request message, due to disable mutual authentication,
 * although SlotID in FINISH request message is 10, it shall be ignored when read.
 * Expected behavior: the responder accepts the request and produces a valid
 * FINISH_RSP response message.
 **/
void libspdm_test_responder_finish_case21(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = 0;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    ptr = m_libspdm_finish_request6.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request6,
                                  sizeof(spdm_finish_request_t));
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request6_size = sizeof(spdm_finish_request_t) + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request6_size,
                                         &m_libspdm_finish_request6,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_FINISH_RSP);
    assert_int_equal(response_size,
                     sizeof(spdm_finish_response_t) + hmac_size);
    free(data1);
}

/**
 * Test 22: receiving a valid FINISH request message, enable mutual authentication without using the encapsulated request flow,
 * that is KEY_EXCHANGE_RSP.MutAuthRequested equals 0x01.
 * although SlotID in FINISH request message is 3, it no need match the value 0 in final ENCAPSULATED_RESPONSE_ACK.EncapsulatedRequest.
 * Expected behavior: the responder accepts the request and produces a valid
 * FINISH_RSP response message.
 **/
void libspdm_test_responder_finish_case22(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    void *data2;
    size_t data_size2;
    uint8_t *ptr;
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    size_t req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
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
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data2,
                                                    &data_size2, NULL, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size2;
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
    spdm_context->connection_info.peer_used_cert_chain_slot_id = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_libspdm_use_req_asym_algo);
    ptr = m_libspdm_finish_request7.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t *)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    libspdm_append_managed_buffer(&th_curr, (uint8_t *)&m_libspdm_finish_request7,
                                  sizeof(spdm_finish_request_t));
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        m_libspdm_finish_request7.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, libspdm_get_managed_buffer(&th_curr),
            libspdm_get_managed_buffer_size(&th_curr),
            ptr, &req_asym_signature_size);
#endif
    libspdm_append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request7_size = sizeof(spdm_finish_request_t) +
                                     req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request7_size,
                                         &m_libspdm_finish_request7,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_FINISH_RSP);
    assert_int_equal(response_size,
                     sizeof(spdm_finish_response_t) + hmac_size);
    free(data1);
    free(data2);
}

/**
 * Test 23: Same as test case 22 but test signature endianness.
 * Big-Endian Sign. Little-Endian Verify.
 * Expecting signature to fail.
 **/
void libspdm_test_responder_finish_case23(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t* spdm_response;
    void* data1;
    size_t data_size1;
    void* data2;
    size_t data_size2;
    uint8_t* ptr;
    uint8_t* cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t* session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    size_t req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 23;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
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
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->spdm_10_11_verify_signature_endian =
        LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data2,
                                                    &data_size2, NULL, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size2;
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
    spdm_context->connection_info.peer_used_cert_chain_slot_id = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_libspdm_use_req_asym_algo);
    ptr = m_libspdm_finish_request7.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t*)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t*)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    libspdm_append_managed_buffer(&th_curr, (uint8_t*)&m_libspdm_finish_request7,
                                  sizeof(spdm_finish_request_t));
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        m_libspdm_finish_request7.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, libspdm_get_managed_buffer(&th_curr),
            libspdm_get_managed_buffer_size(&th_curr),
            ptr, &req_asym_signature_size);
#endif
    libspdm_append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request7_size = sizeof(spdm_finish_request_t) +
                                     req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request7_size,
                                         &m_libspdm_finish_request7,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void*)response;

    /* Expecting failure on little-endian signature */
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    free(data1);
    free(data2);
}

/**
 * Test 24: Same as test case 22 but test signature endianness.
 * Big-Endian Sign. Big-Endian Verify.
 * Expecting signature to PASS.
 **/
void libspdm_test_responder_finish_case24(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t* spdm_response;
    void* data1;
    size_t data_size1;
    void* data2;
    size_t data_size2;
    uint8_t* ptr;
    uint8_t* cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t* session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    size_t req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 24;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
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
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->spdm_10_11_verify_signature_endian =
        LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data2,
                                                    &data_size2, NULL, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size2;
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
    spdm_context->connection_info.peer_used_cert_chain_slot_id = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_libspdm_use_req_asym_algo);
    ptr = m_libspdm_finish_request7.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t*)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t*)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    libspdm_append_managed_buffer(&th_curr, (uint8_t*)&m_libspdm_finish_request7,
                                  sizeof(spdm_finish_request_t));
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        m_libspdm_finish_request7.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, libspdm_get_managed_buffer(&th_curr),
            libspdm_get_managed_buffer_size(&th_curr),
            ptr, &req_asym_signature_size);
#endif
    libspdm_append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request7_size = sizeof(spdm_finish_request_t) +
                                     req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request7_size,
                                         &m_libspdm_finish_request7,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void*)response;

    /* Expecting pass on big-endian signature */
    assert_int_equal(spdm_response->header.request_response_code, SPDM_FINISH_RSP);
    assert_int_equal(response_size, sizeof(spdm_finish_response_t) + hmac_size);
    free(data1);
    free(data2);
}

/**
 * Test 25: Same as test case 22, but test signature endianness.
 * Big Endian Sign. Big or Little Endian Verify.
 * Expecting signature to PASS.
 **/
void libspdm_test_responder_finish_case25(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t* spdm_response;
    void* data1;
    size_t data_size1;
    void* data2;
    size_t data_size2;
    uint8_t* ptr;
    uint8_t* cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t* session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    size_t req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 25;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
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
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->spdm_10_11_verify_signature_endian =
        LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data2,
                                                    &data_size2, NULL, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size2;
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
    spdm_context->connection_info.peer_used_cert_chain_slot_id = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_libspdm_use_req_asym_algo);
    ptr = m_libspdm_finish_request7.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t*)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t*)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    libspdm_append_managed_buffer(&th_curr, (uint8_t*)&m_libspdm_finish_request7,
                                  sizeof(spdm_finish_request_t));
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        m_libspdm_finish_request7.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, libspdm_get_managed_buffer(&th_curr),
            libspdm_get_managed_buffer_size(&th_curr),
            ptr, &req_asym_signature_size);
#endif
    libspdm_append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request7_size = sizeof(spdm_finish_request_t) +
                                     req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request7_size,
                                         &m_libspdm_finish_request7,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void*)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_FINISH_RSP);
    assert_int_equal(response_size, sizeof(spdm_finish_response_t) + hmac_size);
    free(data1);
    free(data2);
}

/**
 * Test 26: Same as test case 22, but test endian verification.
 * Sign as Little Endian, Verify as Little.
 * Expecting signature to PASS.
 **/
void libspdm_test_responder_finish_case26(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t* spdm_response;
    void* data1;
    size_t data_size1;
    void* data2;
    size_t data_size2;
    uint8_t* ptr;
    uint8_t* cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t* session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    size_t req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 26;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
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
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->spdm_10_11_verify_signature_endian =
        LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data2,
                                                    &data_size2, NULL, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size2;
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
    spdm_context->connection_info.peer_used_cert_chain_slot_id = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_libspdm_use_req_asym_algo);
    ptr = m_libspdm_finish_request7.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t*)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t*)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    libspdm_append_managed_buffer(&th_curr, (uint8_t*)&m_libspdm_finish_request7,
                                  sizeof(spdm_finish_request_t));
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        m_libspdm_finish_request7.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, libspdm_get_managed_buffer(&th_curr),
            libspdm_get_managed_buffer_size(&th_curr),
            ptr, &req_asym_signature_size);

    /* Switch signature to little endian */
    libspdm_copy_signature_swap_endian(
        m_libspdm_use_req_asym_algo,
        ptr, req_asym_signature_size,
        ptr, req_asym_signature_size);
#endif
    libspdm_append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request7_size = sizeof(spdm_finish_request_t) +
                                     req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request7_size,
                                         &m_libspdm_finish_request7,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void*)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_FINISH_RSP);
    assert_int_equal(response_size, sizeof(spdm_finish_response_t) + hmac_size);
    free(data1);
    free(data2);
}

/**
 * Test 27: Same as test case 22, but test endian verification.
 * Sign as Little Endian, Verify as Big.
 * Expecting signature to FAIL.
 **/
void libspdm_test_responder_finish_case27(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t* spdm_response;
    void* data1;
    size_t data_size1;
    void* data2;
    size_t data_size2;
    uint8_t* ptr;
    uint8_t* cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t* session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    size_t req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 27;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
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
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->spdm_10_11_verify_signature_endian =
        LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data2,
                                                    &data_size2, NULL, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size2;
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
    spdm_context->connection_info.peer_used_cert_chain_slot_id = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_libspdm_use_req_asym_algo);
    ptr = m_libspdm_finish_request7.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t*)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t*)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    libspdm_append_managed_buffer(&th_curr, (uint8_t*)&m_libspdm_finish_request7,
                                  sizeof(spdm_finish_request_t));
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        m_libspdm_finish_request7.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, libspdm_get_managed_buffer(&th_curr),
            libspdm_get_managed_buffer_size(&th_curr),
            ptr, &req_asym_signature_size);

    /* Switch signature to little endian */
    libspdm_copy_signature_swap_endian(
        m_libspdm_use_req_asym_algo,
        ptr, req_asym_signature_size,
        ptr, req_asym_signature_size);
#endif
    libspdm_append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request7_size = sizeof(spdm_finish_request_t) +
                                     req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request7_size,
                                         &m_libspdm_finish_request7,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void*)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    free(data1);
    free(data2);
}

/**
 * Test 28: Same as test case 22, but test endian verification.
 * Sign as Little Endian, Verify as Big Or Little.
 * Expecting signature to PASS.
 **/
void libspdm_test_responder_finish_case28(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t* spdm_response;
    void* data1;
    size_t data_size1;
    void* data2;
    size_t data_size2;
    uint8_t* ptr;
    uint8_t* cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t req_cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t* session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;
    size_t req_asym_signature_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 28;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
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
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size =
        data_size1;
    spdm_context->spdm_10_11_verify_signature_endian =
        LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data2,
                                                    &data_size2, NULL, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data2, data_size2);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size2;
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
    spdm_context->connection_info.peer_used_cert_chain_slot_id = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_set_mem(m_dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key(
        session_info->secured_message_context, m_dummy_buffer,
        hash_size);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    session_info->mut_auth_requested = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    req_asym_signature_size =
        libspdm_get_req_asym_signature_size(m_libspdm_use_req_asym_algo);
    ptr = m_libspdm_finish_request7.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t*)data1;
    cert_buffer_size = data_size1;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     cert_buffer_hash);
    cert_buffer = (uint8_t*)data2;
    cert_buffer_size = data_size2;
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                     req_cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
    /* session_transcript.message_k is 0*/
    libspdm_append_managed_buffer(&th_curr, req_cert_buffer_hash, hash_size);
    libspdm_append_managed_buffer(&th_curr, (uint8_t*)&m_libspdm_finish_request7,
                                  sizeof(spdm_finish_request_t));
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        m_libspdm_finish_request7.header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT, SPDM_FINISH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, libspdm_get_managed_buffer(&th_curr),
            libspdm_get_managed_buffer_size(&th_curr),
            ptr, &req_asym_signature_size);

    /* Switch signature to little endian */
    libspdm_copy_signature_swap_endian(
        m_libspdm_use_req_asym_algo,
        ptr, req_asym_signature_size,
        ptr, req_asym_signature_size);
#endif
    libspdm_append_managed_buffer(&th_curr, ptr, req_asym_signature_size);
    ptr += req_asym_signature_size;
    libspdm_set_mem(request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);
    m_libspdm_finish_request7_size = sizeof(spdm_finish_request_t) +
                                     req_asym_signature_size + hmac_size;
    response_size = sizeof(response);
    status = libspdm_get_response_finish(spdm_context,
                                         m_libspdm_finish_request7_size,
                                         &m_libspdm_finish_request7,
                                         &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    spdm_response = (void*)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_FINISH_RSP);
    assert_int_equal(response_size, sizeof(spdm_finish_response_t) + hmac_size);
    free(data1);
    free(data2);
}


libspdm_test_context_t m_libspdm_responder_finish_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_finish_test_main(void)
{
    const struct CMUnitTest spdm_responder_finish_tests[] = {
        /* Success Case*/
        cmocka_unit_test(libspdm_test_responder_finish_case1),
        /* Can be populated with new test.*/
        cmocka_unit_test(libspdm_test_responder_finish_case2),
        /* response_state: SPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(libspdm_test_responder_finish_case3),
        /* response_state: SPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(libspdm_test_responder_finish_case4),
        #if LIBSPDM_RESPOND_IF_READY_SUPPORT
        /* response_state: LIBSPDM_RESPONSE_STATE_NOT_READY*/
        cmocka_unit_test(libspdm_test_responder_finish_case5),
        #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
        /* connection_state Check*/
        cmocka_unit_test(libspdm_test_responder_finish_case6),
        /* Buffer reset*/
        cmocka_unit_test(libspdm_test_responder_finish_case7),
        /* Success Case*/
        cmocka_unit_test(libspdm_test_responder_finish_case8),
        /* Unsupported KEY_EX capabilities*/
        cmocka_unit_test(libspdm_test_responder_finish_case9),
        /* Uninitialized session*/
        cmocka_unit_test(libspdm_test_responder_finish_case10),
        /* Incorrect MAC*/
        cmocka_unit_test(libspdm_test_responder_finish_case11),
        cmocka_unit_test(libspdm_test_responder_finish_case12),
        /* Can be populated with new test.*/
        cmocka_unit_test(libspdm_test_responder_finish_case13),
        cmocka_unit_test(libspdm_test_responder_finish_case14),
        /* Incorrect signature*/
        cmocka_unit_test(libspdm_test_responder_finish_case15),
        cmocka_unit_test(libspdm_test_responder_finish_case16),
        /* Buffer verification*/
        cmocka_unit_test(libspdm_test_responder_finish_case17),
        /* Success Case, enable mutual authentication and use slot_id 0xFF */
        cmocka_unit_test(libspdm_test_responder_finish_case18),
        /* Invalid SlotID in FINISH request message when mutual authentication */
        cmocka_unit_test_setup(libspdm_test_responder_finish_case19, libspdm_unit_test_group_setup),
        cmocka_unit_test_setup(libspdm_test_responder_finish_case20, libspdm_unit_test_group_setup),
        /* If FINISH.Param1 != 0x01, then FINISH.Param2 is reserved, shall be ignored when read */
        cmocka_unit_test_setup(libspdm_test_responder_finish_case21, libspdm_unit_test_group_setup),
        /* If KEY_EXCHANGE_RSP.MutAuthRequested equals neither 0x02 nor 0x04, FINISH.Param2 no need match ENCAPSULATED_RESPONSE_ACK.EncapsulatedRequest */
        cmocka_unit_test_setup(libspdm_test_responder_finish_case22, libspdm_unit_test_group_setup),
        /* Big Endian Sign - Little Endian Verify */
        cmocka_unit_test_setup(libspdm_test_responder_finish_case23, libspdm_unit_test_group_setup),
        /* Big Endian Sign - Big Endian Verify */
        cmocka_unit_test_setup(libspdm_test_responder_finish_case24, libspdm_unit_test_group_setup),
        /* Big Endian Sign - Big or Little Endian Verify */
        cmocka_unit_test_setup(libspdm_test_responder_finish_case25, libspdm_unit_test_group_setup),
        /* Little Endian Sign - Little Endian Verify*/
        cmocka_unit_test_setup(libspdm_test_responder_finish_case26, libspdm_unit_test_group_setup),
        /* Little Endian Sign - Big Endian Verify */
        cmocka_unit_test_setup(libspdm_test_responder_finish_case27, libspdm_unit_test_group_setup),
        /* Little Endian Sign - Big or Little Endian Verify */
        cmocka_unit_test_setup(libspdm_test_responder_finish_case28, libspdm_unit_test_group_setup),
    };

    libspdm_setup_test_context(&m_libspdm_responder_finish_test_context);

    return cmocka_run_group_tests(spdm_responder_finish_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
