/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP

#pragma pack(1)

typedef struct {
    spdm_message_header_t header;
    uint16_t req_session_id;
    uint16_t psk_hint_length;
    uint16_t context_length;
    uint16_t opaque_length;
    uint8_t psk_hint[LIBSPDM_PSK_MAX_HINT_LENGTH];
    uint8_t context[LIBSPDM_PSK_CONTEXT_LENGTH];
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
} libspdm_psk_exchange_request_mine_t;

typedef struct {
    spdm_message_header_t header;
    uint16_t req_session_id;
    uint16_t psk_hint_length;
    uint16_t context_length;
    uint16_t opaque_length;
    uint8_t context[LIBSPDM_PSK_CONTEXT_LENGTH];
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
} libspdm_psk_exchange_request_mine_t_noPSKHINT;

typedef struct {
    spdm_message_header_t header;
    uint16_t req_session_id;
    uint16_t psk_hint_length;
    uint16_t context_length;
    uint16_t opaque_length;
    uint8_t psk_hint[LIBSPDM_PSK_MAX_HINT_LENGTH];
    uint8_t context[LIBSPDM_PSK_CONTEXT_LENGTH];
} libspdm_psk_exchange_request_mine_t_noOPAQUE;

typedef struct {
    spdm_message_header_t header;
    uint16_t req_session_id;
    uint16_t psk_hint_length;
    uint16_t context_length;
    uint16_t opaque_length;
    uint8_t context[LIBSPDM_PSK_CONTEXT_LENGTH];
} libspdm_psk_exchange_request_mine_t_noPSKHINT_noOPAQUE;

#pragma pack()


libspdm_psk_exchange_request_mine_t m_libspdm_psk_exchange_request1 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_PSK_EXCHANGE,
      SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
size_t m_libspdm_psk_exchange_request1_size = sizeof(m_libspdm_psk_exchange_request1);

libspdm_psk_exchange_request_mine_t m_libspdm_psk_exchange_request2 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_PSK_EXCHANGE,
      SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
size_t m_libspdm_psk_exchange_request2_size = sizeof(spdm_psk_exchange_request_t);

libspdm_psk_exchange_request_mine_t m_libspdm_psk_exchange_request3 = {
    { SPDM_MESSAGE_VERSION_12, SPDM_PSK_EXCHANGE,
      SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
size_t m_libspdm_psk_exchange_request3_size = sizeof(m_libspdm_psk_exchange_request3);

/* Request TCB measurement hash */
libspdm_psk_exchange_request_mine_t m_libspdm_psk_exchange_request4 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_PSK_EXCHANGE,
      SPDM_PSK_EXCHANGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, 0 },
};
size_t m_libspdm_psk_exchange_request4_size = sizeof(m_libspdm_psk_exchange_request4);

/* Request all measurement hash */
libspdm_psk_exchange_request_mine_t m_libspdm_psk_exchange_request5 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_PSK_EXCHANGE,
      SPDM_PSK_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH, 0 },
};
size_t m_libspdm_psk_exchange_request5_size = sizeof(m_libspdm_psk_exchange_request5);

/* Uses a reserved value in measurement hash */
libspdm_psk_exchange_request_mine_t m_libspdm_psk_exchange_request6 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_PSK_EXCHANGE,
      0x50, 0 },
};
size_t m_libspdm_psk_exchange_request6_size = sizeof(m_libspdm_psk_exchange_request6);

libspdm_psk_exchange_request_mine_t_noPSKHINT m_libspdm_psk_exchange_request7 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_PSK_EXCHANGE,
      SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
size_t m_libspdm_psk_exchange_request7_size = sizeof(m_libspdm_psk_exchange_request7);

libspdm_psk_exchange_request_mine_t_noOPAQUE m_libspdm_psk_exchange_request8 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_PSK_EXCHANGE,
      SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
size_t m_libspdm_psk_exchange_request8_size = sizeof(m_libspdm_psk_exchange_request8);

libspdm_psk_exchange_request_mine_t_noPSKHINT_noOPAQUE m_libspdm_psk_exchange_request9 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_PSK_EXCHANGE,
      SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
size_t m_libspdm_psk_exchange_request9_size = sizeof(m_libspdm_psk_exchange_request9);

void libspdm_test_responder_psk_exchange_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
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

    m_libspdm_psk_exchange_request1.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request1.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    m_libspdm_psk_exchange_request1.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request1.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request1.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request1.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request1.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request1.context_length;
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request1_size,
        &m_libspdm_psk_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_PSK_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     0);
#endif
    free(data1);
}

void libspdm_test_responder_psk_exchange_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
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

    m_libspdm_psk_exchange_request2.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request2.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    m_libspdm_psk_exchange_request2.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request2.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request2.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request2.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request2.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request2.context_length;
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request2_size,
        &m_libspdm_psk_exchange_request2, &response_size, response);
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

void libspdm_test_responder_psk_exchange_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
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

    m_libspdm_psk_exchange_request1.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request1.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    m_libspdm_psk_exchange_request1.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request1.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request1.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request1.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request1.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request1.context_length;
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request1_size,
        &m_libspdm_psk_exchange_request1, &response_size, response);
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

void libspdm_test_responder_psk_exchange_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
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

    m_libspdm_psk_exchange_request1.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request1.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    m_libspdm_psk_exchange_request1.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request1.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request1.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request1.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request1.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request1.context_length;
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request1_size,
        &m_libspdm_psk_exchange_request1, &response_size, response);
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
void libspdm_test_responder_psk_exchange_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;
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
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
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

    m_libspdm_psk_exchange_request1.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request1.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    m_libspdm_psk_exchange_request1.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request1.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request1.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request1.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request1.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request1.context_length;
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request1_size,
        &m_libspdm_psk_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_error_response_t) +
                     sizeof(spdm_error_data_response_not_ready_t));
    spdm_response = (void *)response;
    error_data = (spdm_error_data_response_not_ready_t
                  *)(&spdm_response->rsp_session_id);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESPONSE_NOT_READY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_NOT_READY);
    assert_int_equal(error_data->request_code, SPDM_PSK_EXCHANGE);
    free(data1);
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

void libspdm_test_responder_psk_exchange_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
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

    m_libspdm_psk_exchange_request1.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request1.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    m_libspdm_psk_exchange_request1.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request1.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request1.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request1.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request1.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request1.context_length;
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request1_size,
        &m_libspdm_psk_exchange_request1, &response_size, response);
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

void libspdm_test_responder_psk_exchange_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
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

    m_libspdm_psk_exchange_request1.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request1.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    m_libspdm_psk_exchange_request1.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request1.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request1.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request1.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request1.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request1.context_length;
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
    ptr += opaque_psk_exchange_req_size;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
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

    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request1_size,
        &m_libspdm_psk_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_PSK_EXCHANGE_RSP);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#endif

    free(data1);
}

void libspdm_test_responder_psk_exchange_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t current_request_size;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size1;

    libspdm_reset_message_a(spdm_context);

    m_libspdm_psk_exchange_request1.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request1.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    m_libspdm_psk_exchange_request1.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request1.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request1.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request1.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request1.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request1.context_length;
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
    ptr += opaque_psk_exchange_req_size;

    current_request_size = sizeof(spdm_psk_exchange_request_t) +
                           m_libspdm_psk_exchange_request1.psk_hint_length +
                           m_libspdm_psk_exchange_request1.context_length +
                           opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, current_request_size, &m_libspdm_psk_exchange_request1,
        &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(libspdm_secured_message_get_session_state(
                         spdm_context->session_info[0].secured_message_context),
                     LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_PSK_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->session_info[0].session_transcript.message_k.buffer_size,
                     current_request_size + response_size);
    assert_memory_equal(spdm_context->session_info[0].session_transcript.message_k.buffer,
                        &m_libspdm_psk_exchange_request1, current_request_size);
    assert_memory_equal(spdm_context->session_info[0].session_transcript.message_k.buffer +
                        current_request_size, response, response_size);
#endif
    free(data1);
}

void libspdm_test_responder_psk_exchange_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_session_info_init(spdm_context,
                              spdm_context->session_info,
                              INVALID_SESSION_ID, false);
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;
    spdm_context->connection_info.local_used_cert_chain_buffer = data1;
    spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size1;

    libspdm_reset_message_a(spdm_context);

    m_libspdm_psk_exchange_request3.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request3.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    m_libspdm_psk_exchange_request3.opaque_length = (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request3.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request3.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request3.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request3.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request3.context_length;
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request3_size,
        &m_libspdm_psk_exchange_request3, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    assert_int_equal(spdm_context->session_info[0].session_policy, 0);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_PSK_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    free(data1);
}

void libspdm_test_responder_psk_exchange_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uint32_t measurement_summary_hash_size;
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
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

    m_libspdm_psk_exchange_request4.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request4.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    m_libspdm_psk_exchange_request4.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request4.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request4.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request4.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request4.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request4.context_length;
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request4_size,
        &m_libspdm_psk_exchange_request4, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_PSK_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);

    measurement_summary_hash_size = libspdm_get_measurement_summary_hash_size(
        spdm_context, false, m_libspdm_psk_exchange_request4.header.param1);
    libspdm_generate_measurement_summary_hash(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        spdm_context->connection_info.version,
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.measurement_spec,
        spdm_context->connection_info.algorithm.measurement_hash_algo,
        m_libspdm_psk_exchange_request4.header.param1,
        measurement_hash,
        measurement_summary_hash_size);
    assert_memory_equal(
        (uint8_t *)response +
        sizeof(spdm_psk_exchange_response_t),
        measurement_hash,
        measurement_summary_hash_size);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     0);
#endif
    free(data1);
}

void libspdm_test_responder_psk_exchange_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uint32_t measurement_summary_hash_size;
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
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

    m_libspdm_psk_exchange_request5.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request5.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    m_libspdm_psk_exchange_request5.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request5.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request5.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request5.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request5.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request5.context_length;
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request5_size,
        &m_libspdm_psk_exchange_request5, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_PSK_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);

    measurement_summary_hash_size = libspdm_get_measurement_summary_hash_size(
        spdm_context, false, m_libspdm_psk_exchange_request5.header.param1);
    libspdm_generate_measurement_summary_hash(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        spdm_context->connection_info.version,
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.measurement_spec,
        spdm_context->connection_info.algorithm.measurement_hash_algo,
        m_libspdm_psk_exchange_request5.header.param1,
        measurement_hash,
        measurement_summary_hash_size);
    assert_memory_equal(
        (uint8_t *)response +
        sizeof(spdm_psk_exchange_response_t),
        measurement_hash,
        measurement_summary_hash_size);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     0);
#endif
    free(data1);
}

void libspdm_test_responder_psk_exchange_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
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

    m_libspdm_psk_exchange_request6.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request6.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    m_libspdm_psk_exchange_request6.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request6.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request6.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request6.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request6.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request6.context_length;
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request6_size,
        &m_libspdm_psk_exchange_request6, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /* Error before libspdm_reset_message_buffer_via_request_code, so will not libspdm_reset_message_m */
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     spdm_context->transcript.message_m.max_buffer_size);
#endif
    free(data1);
}

void libspdm_test_responder_psk_exchange_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    spdm_context->local_context.capability.flags &=
        !SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
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

    m_libspdm_psk_exchange_request4.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request4.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    m_libspdm_psk_exchange_request4.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request4.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request4.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request4.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request4.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request4.context_length;
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request4_size,
        &m_libspdm_psk_exchange_request4, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);

    free(data1);
}

void libspdm_test_responder_psk_exchange_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
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

    m_libspdm_psk_exchange_request7.psk_hint_length = 0;
    m_libspdm_psk_exchange_request7.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    m_libspdm_psk_exchange_request7.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request7.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request7.context;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request7.context_length;
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request7_size,
        &m_libspdm_psk_exchange_request7, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_PSK_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     0);
#endif
    free(data1);
}

void libspdm_test_responder_psk_exchange_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
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

    m_libspdm_psk_exchange_request8.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request8.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size = 0;
    m_libspdm_psk_exchange_request8.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request8.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request8.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request8.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request8.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request8.context_length;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request8_size,
        &m_libspdm_psk_exchange_request8, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_PSK_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     0);
#endif
    free(data1);
}

void libspdm_test_responder_psk_exchange_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
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

    m_libspdm_psk_exchange_request9.psk_hint_length = 0;
    m_libspdm_psk_exchange_request9.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size = 0;
    m_libspdm_psk_exchange_request9.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request9.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request9.context;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request9.context_length;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request9_size,
        &m_libspdm_psk_exchange_request9, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_PSK_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     0);
#endif
    free(data1);
}

void libspdm_test_responder_psk_exchange_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_session_info_init(spdm_context,
                              spdm_context->session_info,
                              INVALID_SESSION_ID, false);
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

    m_libspdm_psk_exchange_request3.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request3.context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size(spdm_context);
    m_libspdm_psk_exchange_request3.opaque_length =
        (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request3.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request3.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request3.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request3.psk_hint_length;
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request3.context_length;
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_psk_exchange_req_size, ptr);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif
    ptr += opaque_psk_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_psk_exchange(
        spdm_context, m_libspdm_psk_exchange_request3_size,
        &m_libspdm_psk_exchange_request3, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    assert_int_equal(spdm_context->session_info[0].session_policy, 0);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version,
                     SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_PSK_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     0);
#endif
    free(data1);
}

libspdm_test_context_t m_libspdm_responder_psk_exchange_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_psk_exchange_test_main(void)
{
    const struct CMUnitTest spdm_responder_psk_exchange_tests[] = {
        /* Success Case*/
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case1),
        /* Bad request size*/
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case2),
        /* response_state: SPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case3),
        /* response_state: SPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case4),
        #if LIBSPDM_RESPOND_IF_READY_SUPPORT
        /* response_state: SPDM_RESPONSE_STATE_NOT_READY*/
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case5),
        #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
        /* connection_state Check*/
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case6),
        /* Buffer reset*/
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case7),
        /* Buffer verification*/
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case8),
        /* Successful response V1.2*/
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case9),
        /* TCB measurement hash requested */
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case10),
        /* All measurement hash requested */
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case11),
        /* Reserved value in Measurement summary. Error + Invalid */
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case12),
        /* TCB measurement hash requested, measurement flag not set */
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case13),
        /* No PSKHint*/
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case14),
        /* No OpaqueData*/
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case15),
        /* No PSKHint and no OpaqueData*/
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case16),
        /* OpaqueData only supports OpaqueDataFmt1, Success Case */
        cmocka_unit_test(libspdm_test_responder_psk_exchange_case17),
    };

    libspdm_setup_test_context(&m_libspdm_responder_psk_exchange_test_context);

    return cmocka_run_group_tests(spdm_responder_psk_exchange_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/
