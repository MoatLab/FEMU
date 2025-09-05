/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP

#define CHUNK_SEND_ACK_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE (42)

typedef struct {
    spdm_negotiate_algorithms_request_t spdm_request_version10;
    spdm_negotiate_algorithms_common_struct_table_t struct_table[4];
} libspdm_negotiate_algorithms_request_spdm_tables_t;

libspdm_negotiate_algorithms_request_spdm_tables_t
    m_libspdm_chunk_send_negotiate_algorithm_request1 =
{
    {
        {
            SPDM_MESSAGE_VERSION_12,
            SPDM_NEGOTIATE_ALGORITHMS,
            4,
            0
        },
        sizeof(libspdm_negotiate_algorithms_request_spdm_tables_t),
        SPDM_MEASUREMENT_SPECIFICATION_DMTF,
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1,
    },
    {
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE,
            0x20,
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD,
            0x20,
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG,
            0x20,
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
        },
        {
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE,
            0x20,
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH
        }
    }
};

size_t m_libspdm_chunk_send_negotiate_algorithm_request1_size =
    sizeof(m_libspdm_chunk_send_negotiate_algorithm_request1);

void libspdm_test_responder_chunk_send_ack_setup_algo_state(libspdm_context_t* spdm_context)
{
    /* This state is copied form Algorithms test case 22 */
    m_libspdm_chunk_send_negotiate_algorithm_request1.spdm_request_version10.base_hash_algo =
        m_libspdm_use_hash_algo;
    m_libspdm_chunk_send_negotiate_algorithm_request1.spdm_request_version10.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

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
    /* spdm_context->connection_info.algorithm.other_params_support = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1; */
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

    spdm_context->local_context.capability.data_transfer_size =
        CHUNK_SEND_ACK_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
}

/* Test sending large NegAlg Request in multiple chunks. */
void libspdm_test_responder_chunk_send_ack_rsp_case0(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t *chunk_send_request;
    spdm_chunk_send_ack_response_t* chunk_send_ack_response;
    spdm_algorithms_response_t *algorithms_response;
    size_t algorithms_response_size;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;
    uint16_t chunk_num;
    uint32_t bytes_sent;
    uint32_t bytes_total;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);

    chunk_num = 0;
    bytes_sent = 0;
    bytes_total = sizeof(m_libspdm_chunk_send_negotiate_algorithm_request1);
    chunk_src = (const uint8_t *)&m_libspdm_chunk_send_negotiate_algorithm_request1;

    do {
        libspdm_zero_mem(request, sizeof(request));
        chunk_send_request = (spdm_chunk_send_request_t*)request;

        chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
        chunk_send_request->header.param1 = 0;
        chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
        chunk_send_request->chunk_seq_no = chunk_num;

        if (chunk_num == 0) {
            *((uint32_t*) (chunk_send_request + 1)) = bytes_total;
            chunk_send_request->chunk_size =
                spdm_context->local_context.capability.data_transfer_size
                - sizeof(spdm_chunk_send_request_t) - sizeof(uint32_t);

            chunk_dst = ((uint8_t*) (chunk_send_request + 1)) + sizeof(uint32_t);

            request_size = sizeof(spdm_chunk_send_request_t)
                           + sizeof(uint32_t)
                           + chunk_send_request->chunk_size;
        } else {
            chunk_send_request->chunk_size =
                LIBSPDM_MIN(
                    spdm_context->local_context.capability.data_transfer_size
                    - sizeof(spdm_chunk_send_request_t),
                    bytes_total - bytes_sent);

            chunk_dst = ((uint8_t*) (chunk_send_request + 1));

            request_size = sizeof(spdm_chunk_send_request_t)
                           + chunk_send_request->chunk_size;

            if (bytes_total - bytes_sent == chunk_send_request->chunk_size) {
                chunk_send_request->header.param1 = SPDM_CHUNK_SEND_REQUEST_ATTRIBUTE_LAST_CHUNK;
            }
        }

        libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                         chunk_src, chunk_send_request->chunk_size);

        chunk_src += chunk_send_request->chunk_size;
        bytes_sent += chunk_send_request->chunk_size;
        chunk_num++;

        response_size = sizeof(response);
        status = libspdm_get_response_chunk_send(
            spdm_context,
            request_size, request,
            &response_size, response);

        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        assert_true(response_size >= sizeof(spdm_chunk_send_ack_response_t));

        chunk_send_ack_response = (spdm_chunk_send_ack_response_t*) response;
        assert_int_equal(chunk_send_ack_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
        assert_int_equal(chunk_send_ack_response->header.request_response_code,
                         SPDM_CHUNK_SEND_ACK);
        assert_int_equal(chunk_send_ack_response->header.param1, 0);
        assert_int_equal(chunk_send_ack_response->header.param2, spdm_test_context->case_id);
        assert_int_equal(chunk_send_ack_response->chunk_seq_no, chunk_send_request->chunk_seq_no);

    } while (bytes_sent < bytes_total);

    algorithms_response = (spdm_algorithms_response_t*) (chunk_send_ack_response + 1);
    algorithms_response_size = response_size - sizeof(spdm_chunk_send_ack_response_t);
    assert_int_equal(algorithms_response->header.request_response_code, SPDM_ALGORITHMS);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(algorithms_response_size,
                     sizeof(spdm_algorithms_response_t) + 4 *
                     sizeof(spdm_negotiate_algorithms_common_struct_table_t));
    assert_int_equal(algorithms_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(algorithms_response->header.request_response_code, SPDM_ALGORITHMS);
    assert_int_equal(algorithms_response->header.param1, 4);
}

/**
 * Test 1: Responder receives a CHUNK_SEND request without chunk capabilities.
 * Expected Behavior: Returns ERROR response message with an error code.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case1(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;
    uint16_t chunk_num;
    uint32_t bytes_total;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 1;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);

    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    chunk_num = 0;
    bytes_total = sizeof(m_libspdm_chunk_send_negotiate_algorithm_request1);
    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = chunk_num;

    *((uint32_t*) (chunk_send_request + 1)) = bytes_total;
    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t) - sizeof(uint32_t);

    chunk_dst = ((uint8_t*) (chunk_send_request + 1)) + sizeof(uint32_t);

    request_size = sizeof(spdm_chunk_send_request_t)
                   + sizeof(uint32_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_true(response_size == sizeof(spdm_error_response_t));

    error_response = (spdm_error_response_t*) response;
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(error_response->header.param2, 0);
}

/**
 * Test 2: Responder receives a CHUNK_SEND request with bad response state.
 * Expected Behavior: Returns ERROR response message
 * with request_response_code as error code.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case2(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;
    uint16_t chunk_num;
    uint32_t bytes_total;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 2;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;

    chunk_num = 0;
    bytes_total = sizeof(m_libspdm_chunk_send_negotiate_algorithm_request1);
    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t)spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = chunk_num;

    *((uint32_t*) (chunk_send_request + 1)) = bytes_total;
    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t) - sizeof(uint32_t);

    chunk_dst = ((uint8_t*) (chunk_send_request + 1)) + sizeof(uint32_t);

    request_size = sizeof(spdm_chunk_send_request_t)
                   + sizeof(uint32_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_true(response_size == sizeof(spdm_error_response_t));

    error_response = (spdm_error_response_t*) response;
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_BUSY);
    assert_int_equal(error_response->header.param2, 0);
}

/**
 * Test 3: Responder receives a CHUNK_SEND request with bad connection state.
 * Expected Behavior: Returns ERROR response message
 * with SPDM_ERROR_CODE_UNEXPECTED_REQUEST error code.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case3(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;
    uint16_t chunk_num;
    uint32_t bytes_total;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 3;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);

    spdm_context->connection_info.connection_state
        = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES - 1;

    chunk_num = 0;
    bytes_total = sizeof(m_libspdm_chunk_send_negotiate_algorithm_request1);
    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = chunk_num;

    *((uint32_t*) (chunk_send_request + 1)) = bytes_total;
    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t) - sizeof(uint32_t);

    chunk_dst = ((uint8_t*) (chunk_send_request + 1)) + sizeof(uint32_t);

    request_size = sizeof(spdm_chunk_send_request_t)
                   + sizeof(uint32_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_true(response_size == sizeof(spdm_error_response_t));

    error_response = (spdm_error_response_t*) response;
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(error_response->header.param2, 0);
}


/**
 * Test 4: Responder receives a CHUNK_SEND request with bad size.
 * Expected Behavior: Returns ERROR response message
 * with SPDM_ERROR_CODE_INVALID_REQUEST error code.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case4(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;
    uint16_t chunk_num;
    uint32_t bytes_total;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 4;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);

    chunk_num = 0;
    bytes_total = sizeof(m_libspdm_chunk_send_negotiate_algorithm_request1);
    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = chunk_num;

    *((uint32_t*) (chunk_send_request + 1)) = bytes_total;
    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t) - sizeof(uint32_t);

    chunk_dst = ((uint8_t*) (chunk_send_request + 1)) + sizeof(uint32_t);

    request_size = sizeof(spdm_chunk_send_request_t)
                   + sizeof(uint32_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    request_size = sizeof(spdm_chunk_send_request_t) - 1;
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_true(response_size == sizeof(spdm_error_response_t));

    error_response = (spdm_error_response_t*) response;
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(error_response->header.param2, 0);
}
/**
 * Test 5: Responder receives a CHUNK_SEND request SPDM version less than 1.2.
 * Expected Behavior: Returns ERROR response message
 * with SPDM_ERROR_CODE_UNSUPPORTED_REQUEST error code.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case5(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;
    uint16_t chunk_num;
    uint32_t bytes_total;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 5;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);

    chunk_num = 0;
    bytes_total = sizeof(m_libspdm_chunk_send_negotiate_algorithm_request1);
    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = chunk_num;

    *((uint32_t*) (chunk_send_request + 1)) = bytes_total;
    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t) - sizeof(uint32_t);

    chunk_dst = ((uint8_t*) (chunk_send_request + 1)) + sizeof(uint32_t);

    request_size = sizeof(spdm_chunk_send_request_t)
                   + sizeof(uint32_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_true(response_size == sizeof(spdm_error_response_t));

    error_response = (spdm_error_response_t*) response;
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(error_response->header.param2, SPDM_CHUNK_SEND);
}
/**
 * Test 6: Responder receives a CHUNK_SEND request with wrong SPDM version.
 * Expected Behavior: Returns ERROR response message
 * with SPDM_ERROR_CODE_VERSION_MISMATCH error code.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case6(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;
    uint16_t chunk_num;
    uint32_t bytes_total;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 6;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);

    chunk_num = 0;
    bytes_total = sizeof(m_libspdm_chunk_send_negotiate_algorithm_request1);
    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = 0x13;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = chunk_num;

    *((uint32_t*) (chunk_send_request + 1)) = bytes_total;
    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t) - sizeof(uint32_t);

    chunk_dst = ((uint8_t*) (chunk_send_request + 1)) + sizeof(uint32_t);

    request_size = sizeof(spdm_chunk_send_request_t)
                   + sizeof(uint32_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_true(response_size == sizeof(spdm_error_response_t));

    error_response = (spdm_error_response_t*) response;
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_VERSION_MISMATCH);
    assert_int_equal(error_response->header.param2, 0);
}

/**
 * Test 7: Responder gets chunk send when chunk get already in use.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case7(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;
    uint16_t chunk_num;
    uint32_t bytes_total;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 7;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);
    spdm_context->chunk_context.get.chunk_in_use = true;

    chunk_num = 0;
    bytes_total = sizeof(m_libspdm_chunk_send_negotiate_algorithm_request1);
    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = chunk_num;

    *((uint32_t*) (chunk_send_request + 1)) = bytes_total;
    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t) - sizeof(uint32_t);

    chunk_dst = ((uint8_t*) (chunk_send_request + 1)) + sizeof(uint32_t);

    request_size = sizeof(spdm_chunk_send_request_t)
                   + sizeof(uint32_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_true(response_size == sizeof(spdm_error_response_t));

    error_response = (spdm_error_response_t*) response;
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(error_response->header.param2, 0);

    spdm_context->chunk_context.get.chunk_in_use = false;
}

/**
 * Test 8: First request has bad sequence number.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case8(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t *chunk_send_request;
    spdm_chunk_send_ack_response_t *chunk_send_ack_response;
    spdm_error_response_t *error_response;

    const uint8_t *chunk_src;
    uint8_t *chunk_dst;
    uint32_t bytes_total;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 8;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);

    bytes_total = sizeof(m_libspdm_chunk_send_negotiate_algorithm_request1);
    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = 1; /* Bad seq num */

    *((uint32_t*) (chunk_send_request + 1)) = bytes_total;
    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t) - sizeof(uint32_t);

    chunk_dst = ((uint8_t*) (chunk_send_request + 1)) + sizeof(uint32_t);

    request_size = sizeof(spdm_chunk_send_request_t)
                   + sizeof(uint32_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_true(response_size == sizeof(spdm_chunk_send_ack_response_t)
                + sizeof(spdm_error_response_t));

    chunk_send_ack_response = (spdm_chunk_send_ack_response_t*) response;
    assert_int_equal(chunk_send_ack_response->header.param1,
                     SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED);

    error_response = (spdm_error_response_t*) (chunk_send_ack_response + 1);
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(error_response->header.param2, 0);
}

/**
 * Test 9: First request has chunk size too large.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case9(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_chunk_send_ack_response_t* chunk_send_ack_response;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;
    uint32_t bytes_total;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 9;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);

    bytes_total = sizeof(m_libspdm_chunk_send_negotiate_algorithm_request1);
    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = 0;

    *((uint32_t*) (chunk_send_request + 1)) = bytes_total;
    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t) - sizeof(uint32_t);

    chunk_dst = ((uint8_t*) (chunk_send_request + 1)) + sizeof(uint32_t);

    request_size = sizeof(spdm_chunk_send_request_t)
                   + sizeof(uint32_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    chunk_send_request->chunk_size += 1; /* chunk size too large */

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_true(response_size == sizeof(spdm_chunk_send_ack_response_t)
                + sizeof(spdm_error_response_t));

    chunk_send_ack_response = (spdm_chunk_send_ack_response_t*) response;
    assert_int_equal(chunk_send_ack_response->header.param1,
                     SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED);

    error_response = (spdm_error_response_t*) (chunk_send_ack_response + 1);
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(error_response->header.param2, 0);
}

/**
 * Test 10: First request has size larger than data transfer size.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case10(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_chunk_send_ack_response_t* chunk_send_ack_response;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;
    uint32_t bytes_total;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 10;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);

    bytes_total = sizeof(m_libspdm_chunk_send_negotiate_algorithm_request1);
    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = 0;

    *((uint32_t*) (chunk_send_request + 1)) = bytes_total;
    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t) - sizeof(uint32_t);

    chunk_dst = ((uint8_t*) (chunk_send_request + 1)) + sizeof(uint32_t);

    request_size = sizeof(spdm_chunk_send_request_t)
                   + sizeof(uint32_t)
                   + chunk_send_request->chunk_size
                   + 1; /* Request size too large */

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_true(response_size == sizeof(spdm_chunk_send_ack_response_t)
                + sizeof(spdm_error_response_t));

    chunk_send_ack_response = (spdm_chunk_send_ack_response_t*) response;
    assert_int_equal(chunk_send_ack_response->header.param1,
                     SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED);

    error_response = (spdm_error_response_t*) (chunk_send_ack_response + 1);
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(error_response->header.param2, 0);
}

/**
 * Test 11: First request has LAST CHUNK bit set.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case11(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_chunk_send_ack_response_t* chunk_send_ack_response;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 11;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);

    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = 0;

    *((uint32_t*) (chunk_send_request + 1)) = LIBSPDM_MAX_SPDM_MSG_SIZE + 1;

    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t) - sizeof(uint32_t);

    chunk_dst = ((uint8_t*) (chunk_send_request + 1)) + sizeof(uint32_t);

    request_size = sizeof(spdm_chunk_send_request_t)
                   + sizeof(uint32_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_true(response_size == sizeof(spdm_chunk_send_ack_response_t)
                + sizeof(spdm_error_response_t));

    chunk_send_ack_response = (spdm_chunk_send_ack_response_t*) response;
    assert_int_equal(chunk_send_ack_response->header.param1,
                     SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED);

    error_response = (spdm_error_response_t*) (chunk_send_ack_response + 1);
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(error_response->header.param2, 0);
}

/**
 * Test 12: First request has LAST CHUNK bit set.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case12(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_chunk_send_ack_response_t* chunk_send_ack_response;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;
    uint32_t bytes_total;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 12;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);

    bytes_total = sizeof(m_libspdm_chunk_send_negotiate_algorithm_request1);
    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = SPDM_CHUNK_SEND_REQUEST_ATTRIBUTE_LAST_CHUNK;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = 0;

    *((uint32_t*) (chunk_send_request + 1)) = bytes_total;

    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t) - sizeof(uint32_t);

    chunk_dst = ((uint8_t*) (chunk_send_request + 1)) + sizeof(uint32_t);

    request_size = sizeof(spdm_chunk_send_request_t)
                   + sizeof(uint32_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_true(response_size == sizeof(spdm_chunk_send_ack_response_t)
                + sizeof(spdm_error_response_t));

    chunk_send_ack_response = (spdm_chunk_send_ack_response_t*) response;
    assert_int_equal(chunk_send_ack_response->header.param1,
                     SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED);

    error_response = (spdm_error_response_t*) (chunk_send_ack_response + 1);
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(error_response->header.param2, 0);
}

void libspdm_test_responder_chunk_send_ack_reset_send_state(libspdm_context_t* spdm_context)
{
    libspdm_chunk_info_t* send_info;

    send_info = &spdm_context->chunk_context.send;
    send_info->chunk_in_use = false;
    send_info->chunk_handle = 0;
    send_info->chunk_seq_no = 0;
    send_info->chunk_bytes_transferred = 0;
    send_info->large_message = NULL;
    send_info->large_message_size = 0;
}

/**
 * Test 13: Request has bad sequence number.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case13(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_chunk_send_ack_response_t* chunk_send_ack_response;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 13;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);
    spdm_context->chunk_context.send.chunk_in_use = true;
    spdm_context->chunk_context.send.chunk_handle = (uint8_t) spdm_test_context->case_id;
    spdm_context->chunk_context.send.chunk_seq_no = 0;

    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = 2; /* Bad seq num */

    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t);

    chunk_dst = ((uint8_t*) (chunk_send_request + 1));

    request_size = sizeof(spdm_chunk_send_request_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_true(response_size == sizeof(spdm_chunk_send_ack_response_t)
                + sizeof(spdm_error_response_t));

    chunk_send_ack_response = (spdm_chunk_send_ack_response_t*) response;
    assert_int_equal(chunk_send_ack_response->header.param1,
                     SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED);

    error_response = (spdm_error_response_t*) (chunk_send_ack_response + 1);
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(error_response->header.param2, 0);

    libspdm_test_responder_chunk_send_ack_reset_send_state(spdm_context);
}

/**
 * Test 14: Request has bad chunk handle.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case14(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_chunk_send_ack_response_t* chunk_send_ack_response;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 14;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);
    spdm_context->chunk_context.send.chunk_in_use = true;
    spdm_context->chunk_context.send.chunk_handle = (uint8_t) spdm_test_context->case_id;
    spdm_context->chunk_context.send.chunk_seq_no = 0;

    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id + 1; /* bad chunk_handle */
    chunk_send_request->chunk_seq_no = 1;
    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t);

    chunk_dst = ((uint8_t*) (chunk_send_request + 1));

    request_size = sizeof(spdm_chunk_send_request_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_true(response_size == sizeof(spdm_chunk_send_ack_response_t)
                + sizeof(spdm_error_response_t));

    chunk_send_ack_response = (spdm_chunk_send_ack_response_t*) response;
    assert_int_equal(chunk_send_ack_response->header.param1,
                     SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED);

    error_response = (spdm_error_response_t*) (chunk_send_ack_response + 1);
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(error_response->header.param2, 0);

    libspdm_test_responder_chunk_send_ack_reset_send_state(spdm_context);
}

/**
 * Test 15: Request has size larger than data transfer size.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case15(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_chunk_send_ack_response_t* chunk_send_ack_response;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 15;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);
    spdm_context->chunk_context.send.chunk_in_use = true;
    spdm_context->chunk_context.send.chunk_handle = (uint8_t) spdm_test_context->case_id;
    spdm_context->chunk_context.send.chunk_seq_no = 0;

    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = 1;

    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t);

    chunk_dst = ((uint8_t*) (chunk_send_request + 1));

    request_size = sizeof(spdm_chunk_send_request_t)
                   + chunk_send_request->chunk_size
                   + 1; /* Request size too large */

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_true(response_size == sizeof(spdm_chunk_send_ack_response_t)
                + sizeof(spdm_error_response_t));

    chunk_send_ack_response = (spdm_chunk_send_ack_response_t*) response;
    assert_int_equal(chunk_send_ack_response->header.param1,
                     SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED);

    error_response = (spdm_error_response_t*) (chunk_send_ack_response + 1);
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(error_response->header.param2, 0);

    libspdm_test_responder_chunk_send_ack_reset_send_state(spdm_context);
}

/**
 * Test 16: Request has chunk size + transferred size > large message size
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case16(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_chunk_send_ack_response_t* chunk_send_ack_response;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 16;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);
    spdm_context->chunk_context.send.chunk_in_use = true;
    spdm_context->chunk_context.send.chunk_handle = (uint8_t) spdm_test_context->case_id;
    spdm_context->chunk_context.send.chunk_seq_no = 0;
    spdm_context->chunk_context.send.large_message_size = 1024;
    spdm_context->chunk_context.send.chunk_bytes_transferred = 1023;

    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = 1;
    chunk_send_request->chunk_size = 2; /* Bad size. Over large message size */

    chunk_dst = ((uint8_t*) (chunk_send_request + 1));

    request_size = sizeof(spdm_chunk_send_request_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_true(response_size == sizeof(spdm_chunk_send_ack_response_t)
                + sizeof(spdm_error_response_t));

    chunk_send_ack_response = (spdm_chunk_send_ack_response_t*) response;
    assert_int_equal(chunk_send_ack_response->header.param1,
                     SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED);

    error_response = (spdm_error_response_t*) (chunk_send_ack_response + 1);
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(error_response->header.param2, 0);

    libspdm_test_responder_chunk_send_ack_reset_send_state(spdm_context);
}

/**
 * Test 17: Request has LAST_CHUNK indicated before all bytes transferred.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case17(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_chunk_send_ack_response_t* chunk_send_ack_response;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 17;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);
    spdm_context->chunk_context.send.chunk_in_use = true;
    spdm_context->chunk_context.send.chunk_handle = (uint8_t) spdm_test_context->case_id;
    spdm_context->chunk_context.send.chunk_seq_no = 0;
    spdm_context->chunk_context.send.large_message_size = 1024;
    spdm_context->chunk_context.send.chunk_bytes_transferred = 1023;

    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = 0;
    chunk_send_request->chunk_size = 1;

    chunk_dst = ((uint8_t*) (chunk_send_request + 1));

    request_size = sizeof(spdm_chunk_send_request_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_true(response_size == sizeof(spdm_chunk_send_ack_response_t)
                + sizeof(spdm_error_response_t));

    chunk_send_ack_response = (spdm_chunk_send_ack_response_t*) response;
    assert_int_equal(chunk_send_ack_response->header.param1,
                     SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED);

    error_response = (spdm_error_response_t*) (chunk_send_ack_response + 1);
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(error_response->header.param2, 0);

    libspdm_test_responder_chunk_send_ack_reset_send_state(spdm_context);
}

/**
 * Test 18: Request missing LAST_CHUNK after all bytes transferred.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case18(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_chunk_send_ack_response_t* chunk_send_ack_response;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 18;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);
    spdm_context->chunk_context.send.chunk_in_use = true;
    spdm_context->chunk_context.send.chunk_handle = (uint8_t) spdm_test_context->case_id;
    spdm_context->chunk_context.send.chunk_seq_no = 0;
    spdm_context->chunk_context.send.large_message_size = 1024;
    spdm_context->chunk_context.send.chunk_bytes_transferred = 1022;

    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = 0;
    chunk_send_request->chunk_size = 2;

    chunk_dst = ((uint8_t*) (chunk_send_request + 1));

    request_size = sizeof(spdm_chunk_send_request_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_true(response_size == sizeof(spdm_chunk_send_ack_response_t)
                + sizeof(spdm_error_response_t));

    chunk_send_ack_response = (spdm_chunk_send_ack_response_t*) response;
    assert_int_equal(chunk_send_ack_response->header.param1,
                     SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED);

    error_response = (spdm_error_response_t*) (chunk_send_ack_response + 1);
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(error_response->header.param2, 0);

    libspdm_test_responder_chunk_send_ack_reset_send_state(spdm_context);
}

/**
 *  Test 19: Request missing LAST_CHUNK when request size != data transfer size.
 **/
void libspdm_test_responder_chunk_send_ack_rsp_case19(void** state)
{
    libspdm_return_t status;

    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t request[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t* chunk_send_request;
    spdm_chunk_send_ack_response_t* chunk_send_ack_response;
    spdm_error_response_t* error_response;

    const uint8_t* chunk_src;
    uint8_t* chunk_dst;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 19;

    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);
    spdm_context->chunk_context.send.chunk_in_use = true;
    spdm_context->chunk_context.send.chunk_handle = (uint8_t) spdm_test_context->case_id;
    spdm_context->chunk_context.send.chunk_seq_no = 0;
    spdm_context->chunk_context.send.large_message_size = 1024;
    spdm_context->chunk_context.send.chunk_bytes_transferred = 0;

    chunk_src = (const uint8_t*) &m_libspdm_chunk_send_negotiate_algorithm_request1;

    libspdm_zero_mem(request, sizeof(request));
    chunk_send_request = (spdm_chunk_send_request_t*) request;

    chunk_send_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    chunk_send_request->header.request_response_code = SPDM_CHUNK_SEND;
    chunk_send_request->header.param1 = 0;
    chunk_send_request->header.param2 = (uint8_t) spdm_test_context->case_id; /* chunk_handle */
    chunk_send_request->chunk_seq_no = 0;
    chunk_send_request->chunk_size =
        spdm_context->local_context.capability.data_transfer_size
        - sizeof(spdm_chunk_send_request_t)
        - 1; /* Chunk size too small. */

    chunk_dst = ((uint8_t*) (chunk_send_request + 1));

    request_size = sizeof(spdm_chunk_send_request_t)
                   + chunk_send_request->chunk_size;

    libspdm_copy_mem(chunk_dst, chunk_send_request->chunk_size,
                     chunk_src, chunk_send_request->chunk_size);

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_send(
        spdm_context,
        request_size, request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_true(response_size == sizeof(spdm_chunk_send_ack_response_t)
                + sizeof(spdm_error_response_t));

    chunk_send_ack_response = (spdm_chunk_send_ack_response_t*) response;
    assert_int_equal(chunk_send_ack_response->header.param1,
                     SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED);

    error_response = (spdm_error_response_t*) (chunk_send_ack_response + 1);
    assert_int_equal(error_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(error_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(error_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(error_response->header.param2, 0);

    libspdm_test_responder_chunk_send_ack_reset_send_state(spdm_context);
}

libspdm_test_context_t m_libspdm_responder_chunk_send_ack_rsp_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_chunk_send_ack_test_main(void)
{
    const struct CMUnitTest spdm_responder_chunk_send_ack_tests[] = {
        /* Responder sent multiple chunks and processed correctly */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case0),
        /* Responder has no response flag chunk cap */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case1),
        /* Responder has bad response state */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case2),
        /* Responder has connection state <= NOT_START */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case3),
        /* Request has wrong size */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case4),
        /* Request has SPDM version less than 1.2*/
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case5),
        /* Request has SPDM version not matching connection */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case6),
        /* Responder is already in chunking mode */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case7),

        /* First request has bad sequence number */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case8),
        /* First request has chunk size too large */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case9),
        /* First request has size larger than data transfer size */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case10),
        /* Large message size larger than max SPDM message size. */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case11),
        /* First request has LAST CHUNK bit set. */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case12),

        /* Request has bad sequence number */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case13),
        /* Request has bad chunk handle */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case14),
        /* Request has chunk size too large for request*/
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case15),
        /* Request has chunk size + transferred size > large message size */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case16),
        /* Request has LAST_CHUNK indicated before all bytes transferred. */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case17),
        /* Request missing LAST_CHUNK after all bytes transferred. */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case18),
        /* Request missing LAST_CHUNK when request size != data transfer size. */
        cmocka_unit_test(libspdm_test_responder_chunk_send_ack_rsp_case19),
    };

    libspdm_setup_test_context(&m_libspdm_responder_chunk_send_ack_rsp_test_context);

    return cmocka_run_group_tests(spdm_responder_chunk_send_ack_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP*/
