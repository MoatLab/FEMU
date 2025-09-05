/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP

spdm_key_update_request_t m_spdm_key_update_request1 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_KEY_UPDATE,
     SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY, 0x3}
};
size_t m_spdm_key_update_request1_size = sizeof(m_spdm_key_update_request1);

spdm_key_update_request_t m_spdm_key_update_request2 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_KEY_UPDATE,
     SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY, 0x3}
};
size_t m_spdm_key_update_request2_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

spdm_key_update_request_t m_spdm_key_update_request3 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_KEY_UPDATE,
     SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS, 0x71}
};
size_t m_spdm_key_update_request3_size = sizeof(m_spdm_key_update_request3);

spdm_key_update_request_t m_spdm_key_update_request4 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_KEY_UPDATE,
     SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS, 0x71}
};
size_t m_spdm_key_update_request4_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

spdm_key_update_request_t m_spdm_key_update_request5 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_KEY_UPDATE,
     SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY, 0x4A}
};
size_t m_spdm_key_update_request5_size = sizeof(m_spdm_key_update_request5);

spdm_key_update_request_t m_spdm_key_update_request6 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_KEY_UPDATE,
     SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY, 0x4A}
};
size_t m_spdm_key_update_request6_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

spdm_key_update_request_t m_spdm_key_update_request7 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_KEY_UPDATE,
     SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY, 0x92}
};
size_t m_spdm_key_update_request7_size = sizeof(m_spdm_key_update_request7);

spdm_key_update_request_t m_spdm_key_update_request8 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_KEY_UPDATE,
     SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS, 0x13}
};
size_t m_spdm_key_update_request8_size = sizeof(m_spdm_key_update_request8);

spdm_key_update_request_t m_spdm_key_update_request9 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_KEY_UPDATE,
     SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY, 0x22}
};
size_t m_spdm_key_update_request9_size = sizeof(m_spdm_key_update_request9);

spdm_key_update_request_t m_spdm_key_update_request10 = {
    {SPDM_MESSAGE_VERSION_11, SPDM_KEY_UPDATE, 0xFF, 0x12}
};
size_t m_spdm_key_update_request10_size = sizeof(m_spdm_key_update_request10);

static void spdm_set_standard_key_update_test_state(
    libspdm_context_t *spdm_context,  uint32_t *session_id)
{
    libspdm_session_info_t *session_info;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;

    spdm_context->transcript.message_a.buffer_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;

    *session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = *session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = *session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, *session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
}

static void libspdm_set_standard_key_update_test_secrets(
    libspdm_secured_message_context_t *secured_message_context,
    uint8_t *m_rsp_secret_buffer,  uint8_t rsp_secret_fill,
    uint8_t *m_req_secret_buffer,  uint8_t req_secret_fill)
{
    libspdm_set_mem(m_rsp_secret_buffer, secured_message_context->hash_size, rsp_secret_fill);
    libspdm_set_mem(m_req_secret_buffer, secured_message_context->hash_size, req_secret_fill);

    libspdm_copy_mem(secured_message_context->application_secret.response_data_secret,
                     sizeof(secured_message_context->application_secret.response_data_secret),
                     m_rsp_secret_buffer, secured_message_context->aead_key_size);
    libspdm_copy_mem(secured_message_context->application_secret.request_data_secret,
                     sizeof(secured_message_context->application_secret.request_data_secret),
                     m_req_secret_buffer, secured_message_context->aead_key_size);

    libspdm_set_mem(secured_message_context->application_secret
                    .response_data_encryption_key,
                    secured_message_context->aead_key_size, rsp_secret_fill);
    libspdm_set_mem(secured_message_context->application_secret
                    .response_data_salt,
                    secured_message_context->aead_iv_size, rsp_secret_fill);

    libspdm_set_mem(secured_message_context->application_secret
                    .request_data_encryption_key,
                    secured_message_context->aead_key_size, req_secret_fill);
    libspdm_set_mem(secured_message_context->application_secret
                    .request_data_salt,
                    secured_message_context->aead_iv_size, req_secret_fill);

    secured_message_context->application_secret.response_data_sequence_number = 0;
    secured_message_context->application_secret.request_data_sequence_number = 0;
}

static void libspdm_compute_secret_update(spdm_version_number_t spdm_version,
                                          size_t hash_size,
                                          const uint8_t *in_secret,  uint8_t *out_secret,
                                          size_t out_secret_size)
{
    uint8_t bin_str9[128];
    size_t bin_str9_size;

    bin_str9_size = sizeof(bin_str9);
    libspdm_bin_concat(spdm_version,
                       SPDM_BIN_STR_9_LABEL, sizeof(SPDM_BIN_STR_9_LABEL) - 1,
                       NULL, (uint16_t)hash_size, hash_size, bin_str9,
                       &bin_str9_size);

    libspdm_hkdf_expand(m_libspdm_use_hash_algo, in_secret, hash_size, bin_str9,
                        bin_str9_size, out_secret, out_secret_size);
}

/**
 * Test 1: receiving a correct KEY_UPDATE message from the requester with
 * the UpdateKey operation.
 * Expected behavior: the encap requester accepts the request, produces a valid
 * KEY_UPDATE_ACK response message, and the request data key is updated.
 **/
void test_libspdm_requester_encap_key_update_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;

    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_update_response_t *spdm_response;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x01;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side *not* updated*/

    /*response side updated */
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  secured_message_context->hash_size,
                                  m_rsp_secret_buffer, m_rsp_secret_buffer,
                                  secured_message_context->hash_size);

    response_size = sizeof(response);
    status = libspdm_get_encap_response_key_update(spdm_context,
                                                   m_spdm_key_update_request1_size,
                                                   &m_spdm_key_update_request1,
                                                   &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_key_update_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_KEY_UPDATE_ACK);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY);
    assert_int_equal(spdm_response->header.param2,
                     m_spdm_key_update_request1.header.param2);
    assert_memory_equal(secured_message_context
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, secured_message_context->hash_size);
    assert_memory_equal(secured_message_context
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, secured_message_context->hash_size);
}

/**
 * Test 2: receiving a KEY_UPDATE message larger than specified, with the
 * UpdateKey operation.
 * Expected behavior: the encap requester refuses the KEY_UPDATE message and
 * produces an ERROR message indicating the InvalidRequest. No keys
 * are updated.
 **/
void test_libspdm_requester_encap_key_update_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;

    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_update_response_t *spdm_response;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x02;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    response_size = sizeof(response);
    status = libspdm_get_encap_response_key_update(spdm_context,
                                                   m_spdm_key_update_request2_size,
                                                   &m_spdm_key_update_request2,
                                                   &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_memory_equal(secured_message_context
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, secured_message_context->hash_size);
    assert_memory_equal(secured_message_context
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, secured_message_context->hash_size);
}

void test_libspdm_requester_encap_key_update_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;

    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_update_response_t *spdm_response;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x03;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /*"filling" buffers*/
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
    spdm_context->transcript.message_b.buffer_size =
        spdm_context->transcript.message_b.max_buffer_size;
    spdm_context->transcript.message_c.buffer_size =
        spdm_context->transcript.message_c.max_buffer_size;
    spdm_context->transcript.message_mut_b.buffer_size =
        spdm_context->transcript.message_mut_b.max_buffer_size;
    spdm_context->transcript.message_mut_c.buffer_size =
        spdm_context->transcript.message_mut_c.max_buffer_size;
#endif

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side *not* updated*/

    /*response side updated */
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  secured_message_context->hash_size,
                                  m_rsp_secret_buffer, m_rsp_secret_buffer,
                                  secured_message_context->hash_size);

    response_size = sizeof(response);
    status = libspdm_get_encap_response_key_update(spdm_context,
                                                   m_spdm_key_update_request1_size,
                                                   &m_spdm_key_update_request1,
                                                   &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_key_update_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_KEY_UPDATE_ACK);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY);
    assert_int_equal(spdm_response->header.param2,
                     m_spdm_key_update_request1.header.param2);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(session_info->session_transcript.message_m.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#endif
    assert_memory_equal(secured_message_context
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, secured_message_context->hash_size);
    assert_memory_equal(secured_message_context
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, secured_message_context->hash_size);
}

/**
 * Test 4: receiving a correct KEY_UPDATE message from the requester, but the
 * responder has no capabilities for key update.
 * Expected behavior: the encap requester refuses the KEY_UPDATE message and
 * produces an ERROR message indicating the UnsupportedRequest. No keys are
 * updated.
 **/
void test_libspdm_requester_encap_key_update_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;

    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_update_response_t *spdm_response;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x04;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    /*no capabilities*/
    spdm_context->connection_info.capability.flags &=
        !SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags &=
        !SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    response_size = sizeof(response);
    status = libspdm_get_encap_response_key_update(spdm_context,
                                                   m_spdm_key_update_request1_size,
                                                   &m_spdm_key_update_request1,
                                                   &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_KEY_UPDATE);
    assert_memory_equal(secured_message_context
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, secured_message_context->hash_size);
    assert_memory_equal(secured_message_context
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, secured_message_context->hash_size);
}

/**
 * Test 5: receiving a correct KEY_UPDATE message from the requester, but the
 * responder is not correctly setup by not initializing a session during
 * KEY_EXCHANGE.
 * Expected behavior: the encap requester refuses the KEY_UPDATE message and produces
 * an ERROR message indicating the UnsupportedRequest. No keys are updated.
 **/
void test_libspdm_requester_encap_key_update_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;

    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_update_response_t *spdm_response;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x04;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    /*uninitialized session*/
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_NOT_STARTED);

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    response_size = sizeof(response);
    status = libspdm_get_encap_response_key_update(spdm_context,
                                                   m_spdm_key_update_request1_size,
                                                   &m_spdm_key_update_request1,
                                                   &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_memory_equal(secured_message_context
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, secured_message_context->hash_size);
    assert_memory_equal(secured_message_context
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, secured_message_context->hash_size);
}

/**
 * Test 6: receiving a correct KEY_UPDATE message from the requester with
 * the UpdateAllKeys operation.
 * Expected behavior: the encap requester refuses the KEY_UPDATE message and produces
 * an ERROR message indicating the UnsupportedRequest. No keys are updated.
 **/
void test_libspdm_requester_encap_key_update_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;

    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_update_response_t *spdm_response;


    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x06;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    response_size = sizeof(response);
    status = libspdm_get_encap_response_key_update(spdm_context,
                                                   m_spdm_key_update_request3_size,
                                                   &m_spdm_key_update_request3,
                                                   &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2,
                     0);
}

/**
 * Test 7: receiving a KEY_UPDATE message larger than specified, with the
 * UpdateAllKeys operation.
 * Expected behavior: the encap requester refuses the KEY_UPDATE message and
 * produces an ERROR message indicating the InvalidRequest. No keys
 * are updated.
 **/
void test_libspdm_requester_encap_key_update_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;

    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_update_response_t *spdm_response;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x07;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    response_size = sizeof(response);
    status = libspdm_get_encap_response_key_update(spdm_context,
                                                   m_spdm_key_update_request4_size,
                                                   &m_spdm_key_update_request4,
                                                   &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_memory_equal(secured_message_context
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, secured_message_context->hash_size);
    assert_memory_equal(secured_message_context
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, secured_message_context->hash_size);
}

/**
 * Test 8: receiving a invalid KEY_UPDATE message from the requester with
 * the VerifyNewKey operation. The responder is setup as if no valid
 * KEY_UPDATE request with either the UpdateKey or UpdateAllKeys has been
 * previously received.
 * Expected behavior: the encap requester refuses the KEY_UPDATE message and
 * produces an ERROR message indicating the InvalidRequest. No keys are
 * updated.
 **/
void test_libspdm_requester_encap_key_update_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_update_response_t *spdm_response;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x08;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*no mocked major secret update*/

    /*no keys are updated*/

    response_size = sizeof(response);
    status = libspdm_get_encap_response_key_update(spdm_context,
                                                   m_spdm_key_update_request5_size,
                                                   &m_spdm_key_update_request5,
                                                   &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2,
                     0);
}

/**
 * Test 9: receiving a KEY_UPDATE message with a reserved operation code.
 * Expected behavior: the encap requester refuses the KEY_UPDATE message and
 * produces an ERROR message indicating the InvalidRequest. No keys
 * are updated.
 **/
void test_libspdm_requester_encap_key_update_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;

    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_update_response_t *spdm_response;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x09;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    response_size = sizeof(response);
    status = libspdm_get_encap_response_key_update(spdm_context,
                                                   m_spdm_key_update_request10_size,
                                                   &m_spdm_key_update_request10,
                                                   &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_memory_equal(secured_message_context
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, secured_message_context->hash_size);
    assert_memory_equal(secured_message_context
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, secured_message_context->hash_size);
}

/* UpdateKey + UpdateKey: failed*/
void test_libspdm_requester_encap_key_update_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;

    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_update_response_t *spdm_response;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0A;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side *not* updated*/

    /*last request: UpdateKey*/
    session_info->last_key_update_request = m_spdm_key_update_request1;

    /*response side updated */
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  secured_message_context->hash_size,
                                  m_rsp_secret_buffer, m_rsp_secret_buffer,
                                  secured_message_context->hash_size);

    response_size = sizeof(response);
    status = libspdm_get_encap_response_key_update(spdm_context,
                                                   m_spdm_key_update_request1_size,
                                                   &m_spdm_key_update_request1,
                                                   &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2,
                     0);
}

/* VerifyNewKey + UpdateKey: success*/
void test_libspdm_requester_encap_key_update_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;

    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_update_response_t *spdm_response;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0B;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side *not* updated*/

    /*last request: verify new key*/
    session_info->last_key_update_request = m_spdm_key_update_request5;
    /*verify new key clear last_key_update_request*/
    libspdm_zero_mem (&(session_info->last_key_update_request), sizeof(spdm_key_update_request_t));

    /*response side updated */
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  secured_message_context->hash_size,
                                  m_rsp_secret_buffer, m_rsp_secret_buffer,
                                  secured_message_context->hash_size);

    response_size = sizeof(response);
    status = libspdm_get_encap_response_key_update(spdm_context,
                                                   m_spdm_key_update_request1_size,
                                                   &m_spdm_key_update_request1,
                                                   &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_key_update_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_KEY_UPDATE_ACK);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY);
    assert_int_equal(spdm_response->header.param2,
                     m_spdm_key_update_request1.header.param2);
    assert_memory_equal(secured_message_context
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, secured_message_context->hash_size);
    assert_memory_equal(secured_message_context
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, secured_message_context->hash_size);
}

/* VerifyNewKey + VerifyNewKey: failed*/
void test_libspdm_requester_encap_key_update_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;

    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_update_response_t *spdm_response;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0C;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side *not* updated*/

    /*last request: verify new key*/
    session_info->last_key_update_request = m_spdm_key_update_request5;
    /*verify new key clear last_key_update_request*/
    libspdm_zero_mem (&(session_info->last_key_update_request), sizeof(spdm_key_update_request_t));

    /*response side updated */
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  secured_message_context->hash_size,
                                  m_rsp_secret_buffer, m_rsp_secret_buffer,
                                  secured_message_context->hash_size);

    response_size = sizeof(response);
    status = libspdm_get_encap_response_key_update(spdm_context,
                                                   m_spdm_key_update_request5_size,
                                                   &m_spdm_key_update_request5,
                                                   &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2,
                     0);
}


/* ohter command + UpdateKey: success*/
void test_libspdm_requester_encap_key_update_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;

    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_update_response_t *spdm_response;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0D;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side *not* updated*/

    /*ohter command with cleared last_key_update_request*/
    libspdm_zero_mem (&(session_info->last_key_update_request), sizeof(spdm_key_update_request_t));

    /*response side updated */
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  secured_message_context->hash_size,
                                  m_rsp_secret_buffer, m_rsp_secret_buffer,
                                  secured_message_context->hash_size);

    response_size = sizeof(response);
    status = libspdm_get_encap_response_key_update(spdm_context,
                                                   m_spdm_key_update_request1_size,
                                                   &m_spdm_key_update_request1,
                                                   &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_key_update_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_KEY_UPDATE_ACK);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY);
    assert_int_equal(spdm_response->header.param2,
                     m_spdm_key_update_request1.header.param2);
    assert_memory_equal(secured_message_context
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, secured_message_context->hash_size);
    assert_memory_equal(secured_message_context
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, secured_message_context->hash_size);
}


/* ohter command + VerifyNewKey: failed*/
void test_libspdm_requester_encap_key_update_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;

    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_update_response_t *spdm_response;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0E;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side *not* updated*/

    /*ohter command with cleared last_key_update_request*/
    libspdm_zero_mem (&(session_info->last_key_update_request), sizeof(spdm_key_update_request_t));

    /*response side updated */
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  secured_message_context->hash_size,
                                  m_rsp_secret_buffer, m_rsp_secret_buffer,
                                  secured_message_context->hash_size);

    response_size = sizeof(response);
    status = libspdm_get_encap_response_key_update(spdm_context,
                                                   m_spdm_key_update_request5_size,
                                                   &m_spdm_key_update_request5,
                                                   &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2,
                     0);
}



libspdm_test_context_t m_libspdm_requester_encap_key_update_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_requester_encap_key_update_test_main(void)
{
    const struct CMUnitTest spdm_requester_key_update_tests[] = {
        /* Success Case -- UpdateKey*/
        cmocka_unit_test(test_libspdm_requester_encap_key_update_case1),
        /* Bad request size*/
        cmocka_unit_test(test_libspdm_requester_encap_key_update_case2),
        /* Buffer reset*/
        cmocka_unit_test(test_libspdm_requester_encap_key_update_case3),
        /* Unsupported KEY_UPD capabilities*/
        cmocka_unit_test(test_libspdm_requester_encap_key_update_case4),
        /* Uninitialized session*/
        cmocka_unit_test(test_libspdm_requester_encap_key_update_case5),
        /* ruquster RETURN_UNSUPPORTED*/
        cmocka_unit_test(test_libspdm_requester_encap_key_update_case6),
        /* Bad request size*/
        cmocka_unit_test(test_libspdm_requester_encap_key_update_case7),
        /* Uninitialized key update*/
        cmocka_unit_test(test_libspdm_requester_encap_key_update_case8),
        /* Invalid operation*/
        cmocka_unit_test(test_libspdm_requester_encap_key_update_case9),
        /* UpdateKey + UpdateKey: failed*/
        cmocka_unit_test(test_libspdm_requester_encap_key_update_case10),
        /* VerifyNewKey + UpdateKey: success*/
        cmocka_unit_test(test_libspdm_requester_encap_key_update_case11),
        /* VerifyNewKey + VerifyNewKey: failed*/
        cmocka_unit_test(test_libspdm_requester_encap_key_update_case12),
        /* ohter command + UpdateKey: success*/
        cmocka_unit_test(test_libspdm_requester_encap_key_update_case13),
        /* ohter command + VerifyNewKey: failed*/
        cmocka_unit_test(test_libspdm_requester_encap_key_update_case14),
    };

    libspdm_setup_test_context(&m_libspdm_requester_encap_key_update_test_context);

    return cmocka_run_group_tests(spdm_requester_key_update_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP*/
