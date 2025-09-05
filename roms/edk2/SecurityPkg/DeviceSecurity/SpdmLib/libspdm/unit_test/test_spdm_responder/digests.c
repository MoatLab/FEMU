/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

spdm_get_digest_request_t m_libspdm_get_digests_request1 = {
    {
        SPDM_MESSAGE_VERSION_10,
        SPDM_GET_DIGESTS,
    },
};
size_t m_libspdm_get_digests_request1_size = sizeof(m_libspdm_get_digests_request1);

spdm_get_digest_request_t m_libspdm_get_digests_request2 = {
    {
        SPDM_MESSAGE_VERSION_13,
        SPDM_GET_DIGESTS,
    },
};
size_t m_libspdm_get_digests_request2_size = sizeof(m_libspdm_get_digests_request2);

static uint8_t m_libspdm_local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

/**
 * Test 1: receives a valid GET_DIGESTS request message from Requester
 * Expected Behavior: produces a valid DIGESTS response message
 **/
void libspdm_test_responder_digests_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] =
        m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request1_size,
                                          &m_libspdm_get_digests_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        response_size,
        sizeof(spdm_digest_response_t) +
        libspdm_get_hash_size(spdm_context->connection_info
                              .algorithm.base_hash_algo));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_DIGESTS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     0);
#endif
}

/**
 * Test 2:
 * Expected Behavior:
 **/
void libspdm_test_responder_digests_case2(void **state)
{
}

/**
 * Test 3: receives a valid GET_DIGESTS request message from Requester, but Responder is not ready to accept the new
 * request message (is busy) and may be able to process the request message if it is sent again in the future
 * Expected Behavior: produces an ERROR response message with error code = Busy
 **/
void libspdm_test_responder_digests_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] =
        m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request1_size,
                                          &m_libspdm_get_digests_request1,
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
}

/**
 * Test 4: receives a valid GET_DIGESTS request message from Requester, but Responder needs the Requester to reissue GET_VERSION to resynchronize
 * Expected Behavior: produces an ERROR response message with error code = RequestResynch
 **/
void libspdm_test_responder_digests_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] =
        m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request1_size,
                                          &m_libspdm_get_digests_request1,
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
}

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
/**
 * Test 5: receives a valid GET_DIGESTS request message from Requester, but Responder cannot produce the response message in time
 * Expected Behavior: produces an ERROR response message with error code = ResponseNotReady
 **/
void libspdm_test_responder_digests_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;
    spdm_error_data_response_not_ready_t *error_data;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] =
        m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request1_size,
                                          &m_libspdm_get_digests_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_error_response_t) +
                     sizeof(spdm_error_data_response_not_ready_t));
    spdm_response = (void *)response;
    error_data = (spdm_error_data_response_not_ready_t *)(spdm_response + 1);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESPONSE_NOT_READY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_NOT_READY);
    assert_int_equal(error_data->request_code, SPDM_GET_DIGESTS);
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

/**
 * Test 6: receives a valid GET_DIGESTS request message from Requester, but connection_state equals to zero and makes the check fail,
 * meaning that steps GET_CAPABILITIES-CAPABILITIES and NEGOTIATE_ALGORITHMS-ALGORITHMS of the protocol were not previously completed
 * Expected Behavior: produces an ERROR response message with error code = UnexpectedRequest
 **/
void libspdm_test_responder_digests_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] =
        m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request1_size,
                                          &m_libspdm_get_digests_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 7: receives a valid GET_DIGESTS request message from Requester, but there is no local certificate chain, i.e. there is no digest to send
 * Expected Behavior: produces an ERROR response message with error code = Unspecified
 **/
void libspdm_test_responder_digests_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;
    size_t index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        spdm_context->local_context.local_cert_chain_provision[index] =
            NULL;
        spdm_context->local_context
        .local_cert_chain_provision_size[index] = 0;
    }

    response_size = sizeof(response);
    libspdm_reset_message_b(spdm_context);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request1_size,
                                          &m_libspdm_get_digests_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNSPECIFIED);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 08: receives a valid GET_DIGESTS request message from Requester in a session
 * Expected Behavior: produces a valid DIGESTS response message
 **/
void libspdm_test_responder_digests_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;
    libspdm_session_info_t *session_info;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] =
        m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    session_info->session_transcript.message_m.buffer_size =
        session_info->session_transcript.message_m.max_buffer_size;
#endif

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request1_size,
                                          &m_libspdm_get_digests_request1,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        response_size,
        sizeof(spdm_digest_response_t) +
        libspdm_get_hash_size(spdm_context->connection_info
                              .algorithm.base_hash_algo));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_DIGESTS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(session_info->session_transcript.message_m.buffer_size,
                     0);
#endif
}

/**
 * Test 9: receives a valid GET_DIGESTS request message from Requester , set multi_key_conn_rsp to check if it responds correctly
 * Expected Behavior: produces a valid DIGESTS response message
 **/
void libspdm_test_responder_digests_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] =
        m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif
    /* Sub Case 1: Set multi_key_conn_rsp to true*/
    spdm_context->connection_info.multi_key_conn_rsp = true;
    libspdm_reset_message_d(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request2_size,
                                          &m_libspdm_get_digests_request2,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        response_size,
        sizeof(spdm_digest_response_t) + sizeof(spdm_key_pair_id_t) +
        sizeof(spdm_certificate_info_t) +
        sizeof(spdm_key_usage_bit_mask_t) +
        libspdm_get_hash_size(spdm_context->connection_info
                              .algorithm.base_hash_algo));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_DIGESTS);
    assert_int_equal(spdm_context->transcript.message_d.buffer_size,
                     sizeof(spdm_digest_response_t) +
                     sizeof(spdm_key_pair_id_t) +
                     sizeof(spdm_certificate_info_t) +
                     sizeof(spdm_key_usage_bit_mask_t) +
                     libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo));

    /* Sub Case 2: Set multi_key_conn_rsp to false*/
    spdm_context->connection_info.multi_key_conn_rsp = false;
    libspdm_reset_message_d(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request2_size,
                                          &m_libspdm_get_digests_request2,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        response_size,
        sizeof(spdm_digest_response_t) +
        libspdm_get_hash_size(spdm_context->connection_info
                              .algorithm.base_hash_algo));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_DIGESTS);
    assert_int_equal(spdm_context->transcript.message_d.buffer_size, 0);
}

/**
 * Test10: a response message is successfully sent ,
 * Check KeyPairID CertificateInfo and KeyUsageMask
 * Expected Behavior: requester returns the status LIBSPDM_STATUS_SUCCESS
 **/
void libspdm_test_responder_digests_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response;
    uint8_t *digest;
    spdm_key_pair_id_t *key_pair_id;
    spdm_certificate_info_t *cert_info;
    spdm_key_usage_bit_mask_t *key_usage_bit_mask;
    uint32_t hash_size;
    uint8_t slot_count;
    size_t additional_size;

    slot_count = SPDM_MAX_SLOT_COUNT;
    additional_size = sizeof(spdm_key_pair_id_t) + sizeof(spdm_certificate_info_t) +
                      sizeof(spdm_key_usage_bit_mask_t);
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x0A;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    for (uint8_t index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        spdm_context->local_context.local_cert_chain_provision[index] =
            &m_libspdm_local_certificate_chain[hash_size *index];
        spdm_context->local_context.local_cert_chain_provision_size[index] = hash_size;
    }

    libspdm_set_mem(m_libspdm_local_certificate_chain,
                    sizeof(m_libspdm_local_certificate_chain),
                    (uint8_t)(0xFF));

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif
    spdm_context->connection_info.multi_key_conn_rsp = true;
    libspdm_reset_message_d(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_digests(spdm_context,
                                          m_libspdm_get_digests_request2_size,
                                          &m_libspdm_get_digests_request2,
                                          &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_digest_response_t) +
                     (hash_size + additional_size) *
                     slot_count);

    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_DIGESTS);
    assert_int_equal(spdm_context->transcript.message_d.buffer_size,
                     sizeof(spdm_digest_response_t) + (hash_size + additional_size) * slot_count);

    digest = (void *)(spdm_response + 1);
    libspdm_zero_mem (digest, hash_size * slot_count);
    key_pair_id = (spdm_key_pair_id_t *)((uint8_t *)digest + (hash_size * slot_count));
    cert_info = (spdm_certificate_info_t *)((uint8_t *)key_pair_id +
                                            sizeof(spdm_key_pair_id_t) * slot_count);
    key_usage_bit_mask = (spdm_key_usage_bit_mask_t *)((uint8_t *)cert_info +
                                                       sizeof(spdm_certificate_info_t) *
                                                       slot_count);
    for (uint8_t index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        assert_memory_equal((void *)&key_pair_id[index],
                            (void *)&spdm_context->local_context.local_key_pair_id[index],
                            sizeof(spdm_key_pair_id_t));
        assert_memory_equal((void *)&cert_info[index],
                            (void *)&spdm_context->local_context.local_cert_info[index],
                            sizeof(spdm_certificate_info_t));
        assert_memory_equal((void *)&key_usage_bit_mask[index],
                            (void *)&spdm_context->local_context.local_key_usage_bit_mask[index],
                            sizeof(spdm_key_usage_bit_mask_t));
    }
}

libspdm_test_context_t m_libspdm_responder_digests_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_digests_test_main(void)
{
    const struct CMUnitTest spdm_responder_digests_tests[] = {
        /* Success Case*/
        cmocka_unit_test(libspdm_test_responder_digests_case1),
        /* Can be populated with new test.*/
        cmocka_unit_test(libspdm_test_responder_digests_case2),
        /* response_state: SPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(libspdm_test_responder_digests_case3),
        /* response_state: LIBSPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(libspdm_test_responder_digests_case4),
        #if LIBSPDM_RESPOND_IF_READY_SUPPORT
        /* response_state: LIBSPDM_RESPONSE_STATE_NOT_READY*/
        cmocka_unit_test(libspdm_test_responder_digests_case5),
        #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
        /* connection_state Check*/
        cmocka_unit_test(libspdm_test_responder_digests_case6),
        /* No digest to send*/
        cmocka_unit_test(libspdm_test_responder_digests_case7),
        /* Success Case in a session*/
        cmocka_unit_test(libspdm_test_responder_digests_case8),
        /* Set multi_key_conn_rsp to check if it responds correctly */
        cmocka_unit_test(libspdm_test_responder_digests_case9),
        /* Check KeyPairID CertificateInfo and KeyUsageMask*/
        cmocka_unit_test(libspdm_test_responder_digests_case10),
    };

    libspdm_setup_test_context(&m_libspdm_responder_digests_test_context);

    return cmocka_run_group_tests(spdm_responder_digests_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
