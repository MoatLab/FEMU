/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP

#define CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE (44)

/**
 * Test 1: Responder receives a CHUNK_GET request when it is not expecting it.
 * Responder does not have response CHUNK cap set.
 * Expected Behavior: Returns ERROR response message
 * with SPDM_ERROR_CODE_UNEXPECTED_REQUEST error code.
 **/
void libspdm_test_responder_chunk_get_rsp_case1(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t* spdm_response;
    spdm_chunk_get_request_t spdm_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->connection_info.capability.data_transfer_size =
        CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_CHUNK_GET;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;
    spdm_request.chunk_seq_no = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_get(
        spdm_context,
        sizeof(spdm_request), &spdm_request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));

    spdm_response = (spdm_error_response_t*) response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 2: Responder receives a CHUNK_GET request with bad response state.
 * Expected Behavior: Returns ERROR response message with an error code.
 **/
void libspdm_test_responder_chunk_get_rsp_case2(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t* spdm_response;
    spdm_chunk_get_request_t spdm_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->local_context.capability.data_transfer_size =
        CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    /* Set bad response state */
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_CHUNK_GET;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;
    spdm_request.chunk_seq_no = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_get(
        spdm_context,
        sizeof(spdm_request), &spdm_request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));

    spdm_response = (spdm_error_response_t*) response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 3: Responder receives a CHUNK_GET request with bad connection state.
 * Expected Behavior: Returns ERROR response message
 * with SPDM_ERROR_CODE_UNEXPECTED_REQUEST error code.
 **/
void libspdm_test_responder_chunk_get_rsp_case3(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t* spdm_response;
    spdm_chunk_get_request_t spdm_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    /* Set bad connection_state */
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES - 1;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->local_context.capability.data_transfer_size =
        CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_CHUNK_GET;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0; /* Handle */
    spdm_request.chunk_seq_no = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_get(
        spdm_context,
        sizeof(spdm_request), &spdm_request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));

    spdm_response = (spdm_error_response_t*) response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 4: Responder receives a CHUNK_GET request with bad size.
 * Expected Behavior: Returns ERROR response message
 * with SPDM_ERROR_CODE_INVALID_REQUEST error code.
 **/
void libspdm_test_responder_chunk_get_rsp_case4(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t* spdm_response;
    spdm_chunk_get_request_t spdm_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->local_context.capability.data_transfer_size =
        CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_CHUNK_GET;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;
    spdm_request.chunk_seq_no = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_get(
        spdm_context,
        sizeof(spdm_request) - 1, &spdm_request, /* Bad request size */
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));

    spdm_response = (spdm_error_response_t*) response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 5: Responder receives a CHUNK_GET request with wrong SPDM version.
 * Expected Behavior: Returns ERROR response message
 * with SPDM_ERROR_CODE_VERSION_MISMATCH error code.
 **/
void libspdm_test_responder_chunk_get_rsp_case5(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t* spdm_response;
    spdm_chunk_get_request_t spdm_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->local_context.capability.data_transfer_size =
        CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_11; /* Mismatching SPDM version */
    spdm_request.header.request_response_code = SPDM_CHUNK_GET;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;
    spdm_request.chunk_seq_no = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_get(
        spdm_context,
        sizeof(spdm_request), &spdm_request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));

    spdm_response = (spdm_error_response_t*) response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_CHUNK_GET);
}

/**
 * Test 6: Responder has no chunk saved to get.
 **/
void libspdm_test_responder_chunk_get_rsp_case6(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t* spdm_response;
    spdm_chunk_get_request_t spdm_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->local_context.capability.data_transfer_size =
        CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    /* Set no chunk saved */
    spdm_context->chunk_context.get.chunk_in_use = false;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_CHUNK_GET;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;
    spdm_request.chunk_seq_no = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_get(
        spdm_context,
        sizeof(spdm_request), &spdm_request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));

    spdm_response = (spdm_error_response_t*) response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 7: Responder has handle that does not match request.
 **/
void libspdm_test_responder_chunk_get_rsp_case7(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t* spdm_response;
    spdm_chunk_get_request_t spdm_request;
    void* scratch_buffer;
    size_t scratch_buffer_size;

    uint8_t chunk_handle;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->local_context.capability.data_transfer_size =
        CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);

    scratch_buffer = (uint8_t*)scratch_buffer +
                     libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    scratch_buffer_size = scratch_buffer_size -
                          libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    libspdm_zero_mem(scratch_buffer, scratch_buffer_size);

    chunk_handle = (uint8_t) spdm_test_context->case_id;
    spdm_context->chunk_context.get.chunk_in_use = true;
    spdm_context->chunk_context.get.chunk_handle = (uint8_t) spdm_test_context->case_id;
    spdm_context->chunk_context.get.chunk_seq_no = chunk_handle;
    spdm_context->chunk_context.get.large_message = scratch_buffer;
    spdm_context->chunk_context.get.large_message_size = scratch_buffer_size;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_CHUNK_GET;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = chunk_handle - 1; /* Bad chunk handle */
    spdm_request.chunk_seq_no = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_get(
        spdm_context,
        sizeof(spdm_request), &spdm_request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));

    spdm_response = (spdm_error_response_t*) response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 8: Responder has earlier sequence number than request .
 **/
void libspdm_test_responder_chunk_get_rsp_case8(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t* spdm_response;
    spdm_chunk_get_request_t spdm_request;
    void* scratch_buffer;
    size_t scratch_buffer_size;
    uint8_t chunk_handle;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->local_context.capability.data_transfer_size =
        CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);

    scratch_buffer = (uint8_t*)scratch_buffer +
                     libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    scratch_buffer_size = scratch_buffer_size -
                          libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    libspdm_zero_mem(scratch_buffer, scratch_buffer_size);

    chunk_handle = (uint8_t) spdm_test_context->case_id;
    spdm_context->chunk_context.get.chunk_in_use = true;
    spdm_context->chunk_context.get.chunk_handle = chunk_handle;
    spdm_context->chunk_context.get.chunk_seq_no = 0;
    spdm_context->chunk_context.get.large_message = scratch_buffer;
    spdm_context->chunk_context.get.large_message_size = scratch_buffer_size;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_CHUNK_GET;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = chunk_handle;
    spdm_request.chunk_seq_no = 1; /* Bad chunk seq no */

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_get(
        spdm_context,
        sizeof(spdm_request), &spdm_request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));

    spdm_response = (spdm_error_response_t*) response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 9: Responder has later sequence number than request.
 **/
void libspdm_test_responder_chunk_get_rsp_case9(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_error_response_t* spdm_response;
    spdm_chunk_get_request_t spdm_request;
    void* scratch_buffer;
    size_t scratch_buffer_size;
    uint8_t chunk_handle;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->local_context.capability.data_transfer_size =
        CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);

    scratch_buffer = (uint8_t*)scratch_buffer +
                     libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    scratch_buffer_size = scratch_buffer_size -
                          libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    libspdm_zero_mem(scratch_buffer, scratch_buffer_size);

    chunk_handle = (uint8_t) spdm_test_context->case_id;
    spdm_context->chunk_context.get.chunk_in_use = true;
    spdm_context->chunk_context.get.chunk_handle = chunk_handle;
    spdm_context->chunk_context.get.chunk_seq_no = 0;
    spdm_context->chunk_context.get.large_message = scratch_buffer;
    spdm_context->chunk_context.get.large_message_size = scratch_buffer_size;
    spdm_context->chunk_context.get.chunk_bytes_transferred = 0;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_CHUNK_GET;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = chunk_handle;
    spdm_request.chunk_seq_no = 1; /* Bad chunk seq no */

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_get(
        spdm_context,
        sizeof(spdm_request), &spdm_request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));

    spdm_response = (spdm_error_response_t*) response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 10: Successful request of first chunk.
 **/
void libspdm_test_responder_chunk_get_rsp_case10(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_chunk_response_response_t* spdm_response;
    spdm_chunk_get_request_t spdm_request;
    void* scratch_buffer;
    size_t scratch_buffer_size;

    uint8_t chunk_handle;
    uint32_t data_transfer_size;
    uint32_t first_chunk_size;
    uint32_t second_chunk_size;
    uint32_t third_chunk_size;
    uint32_t total_chunk_size;
    uint32_t large_response;
    uint8_t* chunk_ptr;
    uint32_t i;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 10;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    data_transfer_size = CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.capability.data_transfer_size = data_transfer_size;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);

    scratch_buffer = (uint8_t*)scratch_buffer +
                     libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    scratch_buffer_size = scratch_buffer_size -
                          libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    libspdm_zero_mem(scratch_buffer, scratch_buffer_size);

    /* Fill 1st chunk with 1, 2nd chunk with 2, 3rd chunk with 3 */
    first_chunk_size = data_transfer_size -
                       (sizeof(spdm_chunk_response_response_t) + sizeof(uint32_t));
    second_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    third_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    total_chunk_size = first_chunk_size + second_chunk_size + third_chunk_size;
    LIBSPDM_ASSERT(total_chunk_size <= scratch_buffer_size);

    libspdm_set_mem(scratch_buffer, first_chunk_size, 1);
    libspdm_set_mem((uint8_t*)scratch_buffer + first_chunk_size, second_chunk_size, 2);
    libspdm_set_mem((uint8_t*) scratch_buffer + first_chunk_size + second_chunk_size,
                    third_chunk_size, 3);

    chunk_handle = (uint8_t) spdm_test_context->case_id; /* Any number is fine */
    spdm_context->chunk_context.get.chunk_in_use = true;
    spdm_context->chunk_context.get.chunk_handle = chunk_handle;
    spdm_context->chunk_context.get.chunk_seq_no = 0;
    spdm_context->chunk_context.get.large_message = scratch_buffer;
    spdm_context->chunk_context.get.large_message_size = total_chunk_size;
    spdm_context->chunk_context.get.chunk_bytes_transferred = 0;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_CHUNK_GET;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = chunk_handle;
    spdm_request.chunk_seq_no = 0;

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_get(
        spdm_context,
        sizeof(spdm_request), &spdm_request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, data_transfer_size);

    spdm_response = (spdm_chunk_response_response_t*) response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CHUNK_RESPONSE);
    assert_int_equal(spdm_response->header.param1, 0);
    assert_int_equal(spdm_response->header.param2, chunk_handle);
    assert_int_equal(spdm_response->chunk_seq_no, 0);
    assert_int_equal(spdm_response->chunk_size, first_chunk_size);

    large_response = *(uint32_t*) (spdm_response + 1);
    assert_int_equal(large_response, total_chunk_size);

    /* Verify the 1st chunk is filled with 1 */
    chunk_ptr = (uint8_t*)(((uint32_t*) (spdm_response + 1)) + 1);
    for (i = 0; i < spdm_response->chunk_size; i++) {
        assert_int_equal(chunk_ptr[i], 1);
    }
}

/**
 * Test 11: Successful request of middle chunk.
 **/
void libspdm_test_responder_chunk_get_rsp_case11(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_chunk_response_response_t* spdm_response;
    spdm_chunk_get_request_t spdm_request;
    void* scratch_buffer;
    size_t scratch_buffer_size;

    uint8_t chunk_handle;
    uint16_t chunk_seq_no;
    uint32_t data_transfer_size;
    uint32_t first_chunk_size;
    uint32_t second_chunk_size;
    uint32_t third_chunk_size;
    uint32_t total_chunk_size;
    uint8_t* chunk_ptr;
    uint32_t i;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 11;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    data_transfer_size = CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.capability.data_transfer_size = data_transfer_size;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);

    scratch_buffer = (uint8_t*)scratch_buffer +
                     libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    scratch_buffer_size = scratch_buffer_size -
                          libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    libspdm_zero_mem(scratch_buffer, scratch_buffer_size);

    /* Fill 1st chunk with 1, 2nd chunk with 2, 3rd chunk with 3 */
    first_chunk_size = data_transfer_size -
                       (sizeof(spdm_chunk_response_response_t) + sizeof(uint32_t));
    second_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    third_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    total_chunk_size = first_chunk_size + second_chunk_size + third_chunk_size;
    LIBSPDM_ASSERT(total_chunk_size <= scratch_buffer_size);

    libspdm_set_mem(scratch_buffer, first_chunk_size, 1);
    libspdm_set_mem((uint8_t*) scratch_buffer + first_chunk_size, second_chunk_size, 2);
    libspdm_set_mem((uint8_t*) scratch_buffer + first_chunk_size + second_chunk_size,
                    third_chunk_size, 3);

    chunk_handle = (uint8_t) spdm_test_context->case_id; /* Any number is fine */
    chunk_seq_no = 1; /* 1 == 2nd chunk */
    spdm_context->chunk_context.get.chunk_in_use = true;
    spdm_context->chunk_context.get.chunk_handle = chunk_handle;
    spdm_context->chunk_context.get.chunk_seq_no = chunk_seq_no;
    spdm_context->chunk_context.get.large_message = scratch_buffer;
    spdm_context->chunk_context.get.large_message_size = total_chunk_size;
    spdm_context->chunk_context.get.chunk_bytes_transferred = first_chunk_size;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_CHUNK_GET;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = chunk_handle;
    spdm_request.chunk_seq_no = chunk_seq_no;

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_get(
        spdm_context,
        sizeof(spdm_request), &spdm_request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, data_transfer_size);

    spdm_response = (spdm_chunk_response_response_t*) response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CHUNK_RESPONSE);
    assert_int_equal(spdm_response->header.param1, 0);
    assert_int_equal(spdm_response->header.param2, chunk_handle);
    assert_int_equal(spdm_response->chunk_seq_no, chunk_seq_no);
    assert_int_equal(spdm_response->chunk_size, second_chunk_size);

    /* Verify the 2nd chunk is filled with 2 */
    chunk_ptr = (uint8_t*) (spdm_response + 1);
    for (i = 0; i < spdm_response->chunk_size; i++) {
        assert_int_equal(chunk_ptr[i], 2);
    }
}

/**
 * Test 12: Succesful request of last chunk where size is exactly max chunk size
 **/
void libspdm_test_responder_chunk_get_rsp_case12(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_chunk_response_response_t* spdm_response;
    spdm_chunk_get_request_t spdm_request;
    void* scratch_buffer;
    size_t scratch_buffer_size;

    uint8_t chunk_handle;
    uint16_t chunk_seq_no;
    uint32_t data_transfer_size;
    uint32_t first_chunk_size;
    uint32_t second_chunk_size;
    uint32_t third_chunk_size;
    uint32_t total_chunk_size;
    uint8_t* chunk_ptr;
    uint32_t i;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 12;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    data_transfer_size = CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.capability.data_transfer_size = data_transfer_size;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);

    scratch_buffer = (uint8_t*)scratch_buffer +
                     libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    scratch_buffer_size = scratch_buffer_size -
                          libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    libspdm_zero_mem(scratch_buffer, scratch_buffer_size);

    /* Fill 1st chunk with 1, 2nd chunk with 2, 3rd chunk with 3 */
    first_chunk_size = data_transfer_size -
                       (sizeof(spdm_chunk_response_response_t) + sizeof(uint32_t));
    second_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    third_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    total_chunk_size = first_chunk_size + second_chunk_size + third_chunk_size;
    LIBSPDM_ASSERT(total_chunk_size <= scratch_buffer_size);

    libspdm_set_mem(scratch_buffer, first_chunk_size, 1);
    libspdm_set_mem((uint8_t*) scratch_buffer + first_chunk_size, second_chunk_size, 2);
    libspdm_set_mem((uint8_t*) scratch_buffer + first_chunk_size + second_chunk_size,
                    third_chunk_size, 3);

    chunk_handle = (uint8_t) spdm_test_context->case_id; /* Any number is fine */
    chunk_seq_no = 2; /* 2 == 3rd chunk */
    spdm_context->chunk_context.get.chunk_in_use = true;
    spdm_context->chunk_context.get.chunk_handle = chunk_handle;
    spdm_context->chunk_context.get.chunk_seq_no = chunk_seq_no;
    spdm_context->chunk_context.get.large_message = scratch_buffer;
    spdm_context->chunk_context.get.large_message_size = total_chunk_size;
    spdm_context->chunk_context.get.chunk_bytes_transferred = first_chunk_size + second_chunk_size;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_CHUNK_GET;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = chunk_handle;
    spdm_request.chunk_seq_no = chunk_seq_no;

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_get(
        spdm_context,
        sizeof(spdm_request), &spdm_request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, data_transfer_size);

    spdm_response = (spdm_chunk_response_response_t*) response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CHUNK_RESPONSE);
    assert_int_equal(spdm_response->header.param1, SPDM_CHUNK_GET_RESPONSE_ATTRIBUTE_LAST_CHUNK);
    assert_int_equal(spdm_response->header.param2, chunk_handle);
    assert_int_equal(spdm_response->chunk_seq_no, chunk_seq_no);
    assert_int_equal(spdm_response->chunk_size, third_chunk_size);

    /* Verify the 3nd chunk is filled with 3 */
    chunk_ptr = (uint8_t*) (spdm_response + 1);
    for (i = 0; i < spdm_response->chunk_size; i++) {
        assert_int_equal(chunk_ptr[i], 3);
    }
}

/**
 * Test 13: Succesful request of last chunk where size is exactly 1.
 **/
void libspdm_test_responder_chunk_get_rsp_case13(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_chunk_response_response_t* spdm_response;
    spdm_chunk_get_request_t spdm_request;
    void* scratch_buffer;
    size_t scratch_buffer_size;

    uint8_t chunk_handle;
    uint16_t chunk_seq_no;
    uint32_t data_transfer_size;
    uint32_t first_chunk_size;
    uint32_t second_chunk_size;
    uint32_t third_chunk_size;
    uint32_t total_chunk_size;
    uint32_t fourth_chunk_size;
    uint32_t expected_response_size;
    uint8_t* chunk_ptr;
    uint32_t i;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 12;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    data_transfer_size = CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.capability.data_transfer_size = data_transfer_size;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);

    scratch_buffer = (uint8_t*)scratch_buffer +
                     libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    scratch_buffer_size = scratch_buffer_size -
                          libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    libspdm_zero_mem(scratch_buffer, scratch_buffer_size);

    /* Fill 1st chunk with 1, 2nd chunk with 2, 3rd chunk with 3, 4th chunk with 4 */
    first_chunk_size = data_transfer_size -
                       (sizeof(spdm_chunk_response_response_t) + sizeof(uint32_t));
    second_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    third_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    fourth_chunk_size = 1;

    total_chunk_size = first_chunk_size + second_chunk_size + third_chunk_size + fourth_chunk_size;
    expected_response_size = sizeof(spdm_chunk_response_response_t) + fourth_chunk_size;
    LIBSPDM_ASSERT(total_chunk_size <= scratch_buffer_size);

    libspdm_set_mem(scratch_buffer, first_chunk_size, 1);
    libspdm_set_mem((uint8_t*) scratch_buffer + first_chunk_size, second_chunk_size, 2);
    libspdm_set_mem((uint8_t*) scratch_buffer + first_chunk_size + second_chunk_size,
                    third_chunk_size, 3);
    libspdm_set_mem((uint8_t*) scratch_buffer + first_chunk_size
                    + second_chunk_size + third_chunk_size,
                    fourth_chunk_size, 4);

    chunk_handle = (uint8_t) spdm_test_context->case_id; /* Any number is fine */
    chunk_seq_no = 3; /* 3 == 4th chunk */
    spdm_context->chunk_context.get.chunk_in_use = true;
    spdm_context->chunk_context.get.chunk_handle = chunk_handle;
    spdm_context->chunk_context.get.chunk_seq_no = chunk_seq_no;
    spdm_context->chunk_context.get.large_message = scratch_buffer;
    spdm_context->chunk_context.get.large_message_size = total_chunk_size;
    spdm_context->chunk_context.get.chunk_bytes_transferred =
        first_chunk_size + second_chunk_size + third_chunk_size;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_request.header.request_response_code = SPDM_CHUNK_GET;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = chunk_handle;
    spdm_request.chunk_seq_no = chunk_seq_no;

    response_size = sizeof(response);
    status = libspdm_get_response_chunk_get(
        spdm_context,
        sizeof(spdm_request), &spdm_request,
        &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, expected_response_size);

    spdm_response = (spdm_chunk_response_response_t*) response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CHUNK_RESPONSE);
    assert_int_equal(spdm_response->header.param1, SPDM_CHUNK_GET_RESPONSE_ATTRIBUTE_LAST_CHUNK);
    assert_int_equal(spdm_response->header.param2, chunk_handle);
    assert_int_equal(spdm_response->chunk_seq_no, chunk_seq_no);
    assert_int_equal(spdm_response->chunk_size, fourth_chunk_size);

    /* Verify the 4th chunk is filled with 4 */
    chunk_ptr = (uint8_t*)(spdm_response + 1);
    for (i = 0; i < spdm_response->chunk_size; i++) {
        assert_int_equal(chunk_ptr[i], 4);
    }
}


libspdm_test_context_t m_libspdm_responder_chunk_get_rsp_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_chunk_get_rsp_test_main(void)
{
    const struct CMUnitTest spdm_responder_chunk_get_tests[] = {
        /* Responder has no response flag chunk cap */
        cmocka_unit_test(libspdm_test_responder_chunk_get_rsp_case1),
        /* Responder has response state != NORMAL */
        cmocka_unit_test(libspdm_test_responder_chunk_get_rsp_case2),
        /* Responder has connection state <= NOT_START */
        cmocka_unit_test(libspdm_test_responder_chunk_get_rsp_case3),
        /* Request has wrong size */
        cmocka_unit_test(libspdm_test_responder_chunk_get_rsp_case4),
        /* Request has wrong SPDM version */
        cmocka_unit_test(libspdm_test_responder_chunk_get_rsp_case5),
        /* Responder has no chunk saved to get */
        cmocka_unit_test(libspdm_test_responder_chunk_get_rsp_case6),
        /* Responder has handle that does not match request */
        cmocka_unit_test(libspdm_test_responder_chunk_get_rsp_case7),
        /* Responder has earlier sequence number than request */
        cmocka_unit_test(libspdm_test_responder_chunk_get_rsp_case8),
        /* Responder has later sequence number than request*/
        cmocka_unit_test(libspdm_test_responder_chunk_get_rsp_case9),
        /* Successful request of first chunk */
        cmocka_unit_test(libspdm_test_responder_chunk_get_rsp_case10),
        /* Successful request of middle chunk */
        cmocka_unit_test(libspdm_test_responder_chunk_get_rsp_case11),
        /* Succesful request of last chunk, where size is exactly max chunk size */
        cmocka_unit_test(libspdm_test_responder_chunk_get_rsp_case12),
        /* Successful request of last chunk where chunk size is exactly 1 byte */
        cmocka_unit_test(libspdm_test_responder_chunk_get_rsp_case13),
    };

    libspdm_setup_test_context(&m_libspdm_responder_chunk_get_rsp_test_context);

    return cmocka_run_group_tests(spdm_responder_chunk_get_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP*/
