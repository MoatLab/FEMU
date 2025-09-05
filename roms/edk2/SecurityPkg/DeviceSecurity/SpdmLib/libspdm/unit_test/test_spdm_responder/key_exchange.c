/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint16_t req_session_id;
    uint8_t session_policy;
    uint8_t reserved;
    uint8_t random_data[SPDM_RANDOM_DATA_SIZE];
    uint8_t exchange_data[LIBSPDM_MAX_DHE_KEY_SIZE];
    uint16_t opaque_length;
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
} libspdm_key_exchange_request_mine_t;
#pragma pack()

libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request1 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
size_t m_libspdm_key_exchange_request1_size = sizeof(m_libspdm_key_exchange_request1);

libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request2 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
size_t m_libspdm_key_exchange_request2_size = sizeof(spdm_key_exchange_request_t);

/* Request TCB measurement hash */
libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request3 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, 0 },
};
size_t m_libspdm_key_exchange_request3_size = sizeof(m_libspdm_key_exchange_request3);

/* Request all measurement hash */
libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request4 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH, 0 },
};
size_t m_libspdm_key_exchange_request4_size = sizeof(m_libspdm_key_exchange_request4);

/* Uses a reserved value in measurement hash */
libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request5 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      0x50, 0 },
};
size_t m_libspdm_key_exchange_request5_size = sizeof(m_libspdm_key_exchange_request5);

/* Asks for certificate in slot 1 */
libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request6 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 1 },
};
size_t m_libspdm_key_exchange_request6_size = sizeof(m_libspdm_key_exchange_request6);

/* Asks for previously provisioned raw public key */
libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request7 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0xFF },
};
size_t m_libspdm_key_exchange_request7_size = sizeof(m_libspdm_key_exchange_request7);

libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request8 = {
    { SPDM_MESSAGE_VERSION_12, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
size_t m_libspdm_key_exchange_request8_size = sizeof(m_libspdm_key_exchange_request8);

libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request9 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 9 },
};
size_t m_libspdm_key_exchange_request9_size = sizeof(m_libspdm_key_exchange_request9);

libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request10 = {
    { SPDM_MESSAGE_VERSION_13, SPDM_KEY_EXCHANGE,
      SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0 },
};
size_t m_libspdm_key_exchange_request10_size = sizeof(m_libspdm_key_exchange_request10);

void libspdm_test_responder_key_exchange_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);

    session_id = (m_libspdm_key_exchange_request1.req_session_id << 16) |
                 spdm_response->rsp_session_id;
    libspdm_free_session_id(spdm_context, session_id);
    free(data1);
}

void libspdm_test_responder_key_exchange_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request2.random_data);
    m_libspdm_key_exchange_request2.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request2.reserved = 0;
    ptr = m_libspdm_key_exchange_request2.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request2_size,
        &m_libspdm_key_exchange_request2, &response_size, response);
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

void libspdm_test_responder_key_exchange_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
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

void libspdm_test_responder_key_exchange_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
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
void libspdm_test_responder_key_exchange_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    spdm_error_data_response_not_ready_t *error_data;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
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
    assert_int_equal(error_data->request_code, SPDM_KEY_EXCHANGE);
    free(data1);
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

void libspdm_test_responder_key_exchange_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
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

void libspdm_test_responder_key_exchange_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;
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

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_KEY_EXCHANGE_RSP);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#endif

    free(data1);
}

void libspdm_test_responder_key_exchange_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uint32_t measurement_summary_hash_size;
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request3.random_data);
    m_libspdm_key_exchange_request3.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request3.reserved = 0;
    ptr = m_libspdm_key_exchange_request3.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request3_size,
        &m_libspdm_key_exchange_request3, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);

    measurement_summary_hash_size = libspdm_get_measurement_summary_hash_size(
        spdm_context, false, m_libspdm_key_exchange_request3.header.param1);
    libspdm_generate_measurement_summary_hash(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        spdm_context->connection_info.version,
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.measurement_spec,
        spdm_context->connection_info.algorithm.measurement_hash_algo,
        m_libspdm_key_exchange_request3.header.param1,
        measurement_hash,
        measurement_summary_hash_size);

    assert_memory_equal(
        (uint8_t *)response +
        sizeof(spdm_key_exchange_response_t) +
        dhe_key_size,
        measurement_hash,
        measurement_summary_hash_size);
    free(data1);
}

void libspdm_test_responder_key_exchange_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uint32_t measurement_summary_hash_size;
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request4.random_data);
    m_libspdm_key_exchange_request4.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request4.reserved = 0;
    ptr = m_libspdm_key_exchange_request4.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request4_size,
        &m_libspdm_key_exchange_request4, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);

    measurement_summary_hash_size = libspdm_get_measurement_summary_hash_size(
        spdm_context, false, m_libspdm_key_exchange_request4.header.param1);
    libspdm_generate_measurement_summary_hash(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        spdm_context->connection_info.version,
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.measurement_spec,
        spdm_context->connection_info.algorithm.measurement_hash_algo,
        m_libspdm_key_exchange_request4.header.param1,
        measurement_hash,
        measurement_summary_hash_size);

    assert_memory_equal(
        (uint8_t *)response +
        sizeof(spdm_key_exchange_response_t) +
        dhe_key_size,
        measurement_hash,
        measurement_summary_hash_size);

    session_id = (m_libspdm_key_exchange_request4.req_session_id << 16) |
                 spdm_response->rsp_session_id;
    libspdm_free_session_id(spdm_context, session_id);

    free(data1);
}

void libspdm_test_responder_key_exchange_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request5.random_data);
    m_libspdm_key_exchange_request5.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request5.reserved = 0;
    ptr = m_libspdm_key_exchange_request5.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request5_size,
        &m_libspdm_key_exchange_request5, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);

    free(data1);
}

void libspdm_test_responder_key_exchange_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    /* Clear capabilities flag */
    spdm_context->local_context.capability.flags &=
        !SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;

    /*set capabilities flags */
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request3.random_data);
    m_libspdm_key_exchange_request3.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request3.reserved = 0;
    ptr = m_libspdm_key_exchange_request3.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request3_size,
        &m_libspdm_key_exchange_request3, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);

    free(data1);
}

void libspdm_test_responder_key_exchange_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    void *data2;
    size_t data_size2;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

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

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request7.random_data);
    m_libspdm_key_exchange_request7.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request7.reserved = 0;
    ptr = m_libspdm_key_exchange_request7.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request7_size,
        &m_libspdm_key_exchange_request7, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
    free(data1);
    free(data2);
}

void libspdm_test_responder_key_exchange_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;
    size_t opaque_key_exchange_rsp_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;

    /* Clear previous sessions */
    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;

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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);

    /* Required to compute response size independently */
    opaque_key_exchange_rsp_size =
        libspdm_get_opaque_data_version_selection_data_size(spdm_context);

    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request1_size,
        &m_libspdm_key_exchange_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
    assert_int_equal(response_size,
                     sizeof(spdm_key_exchange_response_t) +
                     dhe_key_size +
                     sizeof(uint16_t) +
                     opaque_key_exchange_rsp_size +
                     libspdm_get_asym_signature_size(
                         spdm_context->connection_info.algorithm.base_asym_algo)
                     );

    free(data1);
}

void libspdm_test_responder_key_exchange_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t current_request_size;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

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

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request1.random_data);
    m_libspdm_key_exchange_request1.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request1.reserved = 0;
    ptr = m_libspdm_key_exchange_request1.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;

    current_request_size = sizeof(spdm_key_exchange_request_t) + dhe_key_size +
                           sizeof(uint16_t) + opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, current_request_size, &m_libspdm_key_exchange_request1,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->session_info[0].session_transcript.message_k.buffer_size,
                     current_request_size + response_size);
    assert_memory_equal(spdm_context->session_info[0].session_transcript.message_k.buffer,
                        &m_libspdm_key_exchange_request1, current_request_size);
    assert_memory_equal(spdm_context->session_info[0].session_transcript.message_k.buffer +
                        current_request_size,
                        response, response_size);
#endif
    free(data1);
}

void libspdm_test_responder_key_exchange_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;

    libspdm_session_info_init(spdm_context,
                              spdm_context->session_info,
                              INVALID_SESSION_ID, false);
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request8.random_data);
    m_libspdm_key_exchange_request8.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request8.reserved = 0;
    m_libspdm_key_exchange_request8.session_policy = 0xFF;
    ptr = m_libspdm_key_exchange_request8.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request8_size,
        &m_libspdm_key_exchange_request8, &response_size, response);
    assert_int_equal(spdm_context->session_info[0].session_policy,
                     m_libspdm_key_exchange_request8.session_policy);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
    free(data1);
}

/**
 * Test 18: SlotID in KEY_EXCHANGE request message is 9, but it should be 0xFF or between 0 and 7 inclusive.
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST.
 **/
void libspdm_test_responder_key_exchange_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request9.random_data);
    m_libspdm_key_exchange_request9.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request9.reserved = 0;
    ptr = m_libspdm_key_exchange_request9.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request9_size,
        &m_libspdm_key_exchange_request9, &response_size, response);
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

void libspdm_test_responder_key_exchange_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;
    spdm_context->response_state = 0;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags = 0;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request8.random_data);
    m_libspdm_key_exchange_request8.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request8.reserved = 0;
    ptr = m_libspdm_key_exchange_request8.exchange_data;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new(spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                  false);
    libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);

    size_t opaque_data_size;
    spdm_general_opaque_data_table_header_t
    *spdm_general_opaque_data_table_header;
    secured_message_opaque_element_table_header_t
    *opaque_element_table_header;
    secured_message_opaque_element_header_t
    * secured_message_element_header;
    uint8_t element_num;
    uint8_t element_index;
    size_t current_element_len;

    spdm_general_opaque_data_table_header =
        (spdm_general_opaque_data_table_header_t *)(ptr + sizeof(uint16_t));
    spdm_general_opaque_data_table_header->total_elements = 2;
    opaque_element_table_header = (void *)(spdm_general_opaque_data_table_header + 1);

    element_num = spdm_general_opaque_data_table_header->total_elements;
    opaque_data_size = sizeof(spdm_general_opaque_data_table_header_t);


    for (element_index = 0; element_index < element_num; element_index++) {
        opaque_element_table_header->id = SPDM_REGISTRY_ID_DMTF;
        opaque_element_table_header->vendor_len = 0;
        /* When opaque_element_data_len is not four byte aligned*/
        opaque_element_table_header->opaque_element_data_len = 0xF;

        secured_message_element_header = (void *)(opaque_element_table_header + 1);
        secured_message_element_header->sm_data_id =
            SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION;
        secured_message_element_header->sm_data_version =
            SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;

        current_element_len = sizeof(secured_message_opaque_element_table_header_t) +
                              opaque_element_table_header->vendor_len +
                              sizeof(opaque_element_table_header->opaque_element_data_len) +
                              opaque_element_table_header->opaque_element_data_len;

        /*move to next element*/
        opaque_element_table_header =
            (secured_message_opaque_element_table_header_t *)
            ((uint8_t *)opaque_element_table_header +
             current_element_len);

        opaque_data_size += current_element_len;
    }

    *(uint16_t *)ptr = (uint16_t)opaque_data_size;

    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request8_size,
        &m_libspdm_key_exchange_request8, &response_size, response);
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

void libspdm_test_responder_key_exchange_case20(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;
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
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;

    libspdm_session_info_init(spdm_context,
                              spdm_context->session_info,
                              INVALID_SESSION_ID, false);
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                              m_libspdm_key_exchange_request8.random_data);
    m_libspdm_key_exchange_request8.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request8.reserved = 0;
    m_libspdm_key_exchange_request8.session_policy = 0xFF;
    ptr = m_libspdm_key_exchange_request8.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request8_size,
        &m_libspdm_key_exchange_request8, &response_size, response);
    assert_int_equal(spdm_context->session_info[0].session_policy,
                     m_libspdm_key_exchange_request8.session_policy);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version,
                     SPDM_MESSAGE_VERSION_12);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal(spdm_response->rsp_session_id, 0xFFFF);
    free(data1);
}

/**
 * Test 36: The key usage bit mask is not set, the SlotID fields in KEY_EXCHANGE and KEY_EXCHANGE_RSP shall not specify this certificate slot
 * Expected Behavior: get a SPDM_ERROR_CODE_INVALID_REQUEST return code
 **/
void libspdm_test_responder_key_exchange_case21(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response;
    void *data1;
    size_t data_size1;
    uint8_t *ptr;
    size_t dhe_key_size;
    void *dhe_context;
    size_t opaque_key_exchange_req_size;
    uint8_t slot_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;
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
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->connection_info.multi_key_conn_rsp = true;

    libspdm_session_info_init(spdm_context,
                              spdm_context->session_info,
                              INVALID_SESSION_ID, false);
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data1,
                                                    &data_size1, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data1;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size1;

    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.mut_auth_requested = 0;

    /* If set, the SlotID fields in KEY_EXCHANGE and KEY_EXCHANGE_RSP can specify this certificate slot. If not set,
     * the SlotID fields in KEY_EXCHANGE and KEY_EXCHANGE_RSP shall not specify this certificate slot */
    slot_id = 0;
    m_libspdm_key_exchange_request10.header.param2 = slot_id;
    spdm_context->local_context.local_key_usage_bit_mask[slot_id] =
        SPDM_KEY_USAGE_BIT_MASK_CHALLENGE_USE |
        SPDM_KEY_USAGE_BIT_MASK_MEASUREMENT_USE;

    libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, m_libspdm_key_exchange_request10.random_data);
    m_libspdm_key_exchange_request10.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request10.reserved = 0;
    m_libspdm_key_exchange_request10.session_policy = 0xFF;
    ptr = m_libspdm_key_exchange_request10.exchange_data;
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
    libspdm_build_opaque_data_supported_version_data(
        spdm_context, &opaque_key_exchange_req_size, ptr);
    ptr += opaque_key_exchange_req_size;
    response_size = sizeof(response);
    status = libspdm_get_response_key_exchange(
        spdm_context, m_libspdm_key_exchange_request10_size,
        &m_libspdm_key_exchange_request10, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);

    free(data1);
}

libspdm_test_context_t m_libspdm_responder_key_exchange_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_key_exchange_test_main(void)
{
    const struct CMUnitTest spdm_responder_key_exchange_tests[] = {
        /* Success Case*/
        cmocka_unit_test(libspdm_test_responder_key_exchange_case1),
        /* Bad request size*/
        cmocka_unit_test(libspdm_test_responder_key_exchange_case2),
        /* response_state: SPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(libspdm_test_responder_key_exchange_case3),
        /* response_state: SPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(libspdm_test_responder_key_exchange_case4),
        #if LIBSPDM_RESPOND_IF_READY_SUPPORT
        /* response_state: SPDM_RESPONSE_STATE_NOT_READY*/
        cmocka_unit_test(libspdm_test_responder_key_exchange_case5),
        #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
        /* connection_state Check*/
        cmocka_unit_test(libspdm_test_responder_key_exchange_case6),
        /* Buffer reset*/
        cmocka_unit_test(libspdm_test_responder_key_exchange_case7),
        /* TCB measurement hash requested */
        cmocka_unit_test(libspdm_test_responder_key_exchange_case8),
        /* All measurement hash requested */
        cmocka_unit_test(libspdm_test_responder_key_exchange_case9),
        /* Reserved value in Measurement summary. Error + Invalid */
        cmocka_unit_test(libspdm_test_responder_key_exchange_case10),
        /* TCB measurement hash requested, measurement flag not set */
        cmocka_unit_test(libspdm_test_responder_key_exchange_case11),
        /* Request previously provisioned public key, slot 0xFF */
        cmocka_unit_test(libspdm_test_responder_key_exchange_case14),
        /* HANDSHAKE_IN_THE_CLEAR set for requester and responder */
        cmocka_unit_test(libspdm_test_responder_key_exchange_case15),
        /* Buffer verification*/
        cmocka_unit_test(libspdm_test_responder_key_exchange_case16),
        /* Successful response V1.2*/
        cmocka_unit_test(libspdm_test_responder_key_exchange_case17),
        /* Invalid SlotID in KEY_EXCHANGE request message*/
        cmocka_unit_test(libspdm_test_responder_key_exchange_case18),
        /* Only OpaqueDataFmt1 is supported, Bytes not aligned*/
        cmocka_unit_test(libspdm_test_responder_key_exchange_case19),
        /* OpaqueData only supports OpaqueDataFmt1, Success Case */
        cmocka_unit_test(libspdm_test_responder_key_exchange_case20),
        /* The key usage bit mask is not set, failed Case*/
        cmocka_unit_test(libspdm_test_responder_key_exchange_case21),
    };

    libspdm_setup_test_context(&m_libspdm_responder_key_exchange_test_context);

    return cmocka_run_group_tests(spdm_responder_key_exchange_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
