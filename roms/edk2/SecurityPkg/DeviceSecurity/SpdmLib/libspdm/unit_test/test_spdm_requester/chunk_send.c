/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP

static bool m_libspdm_chunk_send_last_chunk = false;
static uint8_t m_libspdm_chunk_send_chunk_handle = 0;
static uint16_t m_libspdm_chunk_send_chunk_seq_no = 0;

/* Override the LIBSPDM_DATA_TRANSFER_SIZE just for the unit tests in this file.
 * All other unit tests have the default data transfer size due to the specific
 * unit tests requests and responses hardcode for each test case. */
#define CHUNK_SEND_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE (42)

void libspdm_requester_chunk_send_test_case1_build_algorithms_response(
    void* context, void* response, size_t* response_size)
{
    spdm_algorithms_response_t* spdm_response;

    *response_size = sizeof(spdm_algorithms_response_t);
    spdm_response = (spdm_algorithms_response_t*) response;

    libspdm_zero_mem(spdm_response, *response_size);
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_response->header.request_response_code = SPDM_ALGORITHMS;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->length = sizeof(spdm_algorithms_response_t);
    spdm_response->measurement_specification_sel =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_response->measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
    spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
    spdm_response->ext_asym_sel_count = 0;
    spdm_response->ext_hash_sel_count = 0;
}


libspdm_return_t libspdm_requester_chunk_send_test_send_message(
    void* spdm_context, size_t request_size, const void* request,
    uint64_t timeout)
{
    libspdm_test_context_t* spdm_test_context;
    const spdm_chunk_send_request_t* chunk_send;

    spdm_test_context = libspdm_get_test_context();

    chunk_send = (const spdm_chunk_send_request_t*)
                 ((const uint8_t*) request + sizeof(libspdm_test_message_header_t));

    m_libspdm_chunk_send_chunk_handle = chunk_send->header.param2;
    m_libspdm_chunk_send_chunk_seq_no = chunk_send->chunk_seq_no;

    if (chunk_send->header.param1 & SPDM_CHUNK_SEND_REQUEST_ATTRIBUTE_LAST_CHUNK) {
        m_libspdm_chunk_send_last_chunk = true;
    }

    if (spdm_test_context->case_id == 1) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 2) {
        return LIBSPDM_STATUS_SEND_FAIL;
    }
    if (spdm_test_context->case_id == 3) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 4) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 5) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 6) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 7) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 8) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 9) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 10) {
        if (chunk_send->header.request_response_code == SPDM_CHUNK_SEND) {
            return LIBSPDM_STATUS_SUCCESS;
        }
        return LIBSPDM_STATUS_SEND_FAIL;
    }
    if (spdm_test_context->case_id == 11) {
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 12) {
        /* Here the send request message should always be SPDM_CHUNK_SEND,
         * if not then something is wrong. */
        LIBSPDM_ASSERT(chunk_send->header.request_response_code == SPDM_CHUNK_SEND);
        return LIBSPDM_STATUS_SUCCESS;
    }
    return LIBSPDM_STATUS_SEND_FAIL;
}

libspdm_return_t libspdm_requester_chunk_send_test_receive_message(
    void *context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_chunk_send_ack_response_t *chunk_send_ack_rsp;
    spdm_error_response_t *error_response;
    size_t chunk_rsp_size;
    uint8_t *chunk_copy_to;
    size_t chunk_size;

    spdm_test_context = libspdm_get_test_context();
    spdm_context = context;

    if ((spdm_test_context->case_id == 1) || (spdm_test_context->case_id == 10) ||
        (spdm_test_context->case_id == 11)) {
        /* Successful chunk send of algorithms request */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_ack_rsp->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp->header.param1 = 0;
        chunk_send_ack_rsp->header.param2 = m_libspdm_chunk_send_chunk_handle;
        chunk_send_ack_rsp->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no;

        if (m_libspdm_chunk_send_last_chunk) {

            chunk_copy_to = (uint8_t*) (chunk_send_ack_rsp + 1);
            chunk_size = *response_size - (chunk_copy_to - (uint8_t*) *response);

            libspdm_requester_chunk_send_test_case1_build_algorithms_response(
                spdm_context, chunk_copy_to, &chunk_size);
            chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t) + chunk_size;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                chunk_rsp_size, chunk_send_ack_rsp,
                response_size, response);
        } else {
            chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t);
            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                chunk_rsp_size, chunk_send_ack_rsp,
                response_size, response);
        }
        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 2) {
        /* Request fail send
         * Should never reach here since the test case is meant to fail at send */
        LIBSPDM_ASSERT(0);
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    if (spdm_test_context->case_id == 3) {
        /* Response fail receive */
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    if (spdm_test_context->case_id == 4) {
        /* Response has bad SPDM version */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_11; /* Bad SPDM version */
        chunk_send_ack_rsp->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp->header.param1 = 0;
        chunk_send_ack_rsp->header.param2 = m_libspdm_chunk_send_chunk_handle;
        chunk_send_ack_rsp->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no;

        chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t);
        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_send_ack_rsp,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 5) {
        /* Response has bad request response code */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_ack_rsp->header.request_response_code = SPDM_ERROR; /* Bad response code */
        chunk_send_ack_rsp->header.param1 = 0;
        chunk_send_ack_rsp->header.param2 = 0;

        chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t);
        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_send_ack_rsp,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 6) {
        /* Response has bad response size */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_ack_rsp->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp->header.param1 = 0;
        chunk_send_ack_rsp->header.param2 = m_libspdm_chunk_send_chunk_handle;
        chunk_send_ack_rsp->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no;

        chunk_rsp_size = 4; /* Bad response size */

        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_send_ack_rsp,
            response_size, response);


        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 7) {
        /* Response has early error detected */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_ack_rsp->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp->header.param1
            = SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED;
        chunk_send_ack_rsp->header.param2 = m_libspdm_chunk_send_chunk_handle;
        chunk_send_ack_rsp->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no;

        error_response = (void*) (chunk_send_ack_rsp + 1);
        error_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        error_response->header.request_response_code = SPDM_ERROR;
        error_response->header.param1 = SPDM_ERROR_CODE_UNSPECIFIED;
        error_response->header.param2 = 0;

        chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t) + sizeof(spdm_error_response_t);
        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_send_ack_rsp,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 8) {
        /* Response has bad chunk handle */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_ack_rsp->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp->header.param1 = 0;

        /* Bad chunk handle */
        chunk_send_ack_rsp->header.param2 = m_libspdm_chunk_send_chunk_handle - 1;
        chunk_send_ack_rsp->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no;

        chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t);
        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_send_ack_rsp,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 9) {
        /* Response has bad chunk seq no */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_ack_rsp->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp->header.param1 = 0;
        chunk_send_ack_rsp->header.param2 = m_libspdm_chunk_send_chunk_handle;

        /* Bad Chunk Seq No */
        chunk_send_ack_rsp->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no - 1;

        chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t);
        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_send_ack_rsp,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }
    if (spdm_test_context->case_id == 12) {
        /* ErrorCode == LargeResponse shall not be allowed in ResponseToLargeRequest */
        chunk_send_ack_rsp
            = (void*) ((uint8_t*) *response + sizeof(libspdm_test_message_header_t));

        chunk_send_ack_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_send_ack_rsp->header.request_response_code = SPDM_CHUNK_SEND_ACK;
        chunk_send_ack_rsp->header.param1
            = SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED;
        chunk_send_ack_rsp->header.param2 = m_libspdm_chunk_send_chunk_handle;
        chunk_send_ack_rsp->chunk_seq_no = m_libspdm_chunk_send_chunk_seq_no;

        error_response = (void*) (chunk_send_ack_rsp + 1);
        error_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        error_response->header.request_response_code = SPDM_ERROR;

        /* ErrorCode == LargeResponse in ResponseToLargeRequest */
        error_response->header.param1 = SPDM_ERROR_CODE_LARGE_RESPONSE;
        error_response->header.param2 = 0;
        *((uint8_t*) (error_response + 1)) = 0;

        chunk_rsp_size = sizeof(spdm_chunk_send_ack_response_t) + sizeof(spdm_error_response_t) +
                         sizeof(uint8_t);
        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_send_ack_rsp,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }
    return LIBSPDM_STATUS_RECEIVE_FAIL;
}

libspdm_return_t libspdm_test_requester_chunk_send_generic_test_case(
    void** state, uint32_t case_id)
{
    /* Copied from Neg. Algorithms test case 2 */
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = case_id;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);
    if (case_id != 10) {
        spdm_context->connection_info.capability.data_transfer_size
            = CHUNK_SEND_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE;
        spdm_context->local_context.capability.sender_data_transfer_size
            = LIBSPDM_DATA_TRANSFER_SIZE;
    } else {
        spdm_context->connection_info.capability.data_transfer_size
            = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_context->local_context.capability.sender_data_transfer_size
            = CHUNK_SEND_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE;
    }

    if (case_id == 11) {
        spdm_context->connection_info.capability.max_spdm_msg_size = 42;
    }

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    return status;
}

void libspdm_test_requester_chunk_send_case1(void** state)
{
    libspdm_return_t status;

    status = libspdm_test_requester_chunk_send_generic_test_case(state, 1);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

void libspdm_test_requester_chunk_send_case2(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 2);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
}

void libspdm_test_requester_chunk_send_case3(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 3);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

void libspdm_test_requester_chunk_send_case4(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 4);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

void libspdm_test_requester_chunk_send_case5(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 5);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

void libspdm_test_requester_chunk_send_case6(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 6);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

void libspdm_test_requester_chunk_send_case7(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 7);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
}

void libspdm_test_requester_chunk_send_case8(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 8);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

void libspdm_test_requester_chunk_send_case9(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 9);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

void libspdm_test_requester_chunk_send_case10(void** state)
{
    libspdm_return_t status;
    status = libspdm_test_requester_chunk_send_generic_test_case(state, 10);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

void libspdm_test_requester_chunk_send_case11(void** state)
{
    libspdm_return_t status;

    status = libspdm_test_requester_chunk_send_generic_test_case(state, 11);
    assert_int_equal(status, LIBSPDM_STATUS_PEER_BUFFER_TOO_SMALL);
}

/**
 * Test 12: ErrorCode == LargeResponse shall not be allowed in ResponseToLargeRequest.
 * Expected behavior: returns a status of LIBSPDM_STATUS_ERROR_PEER,
 * Received an unexpected error message.
 **/
void libspdm_test_requester_chunk_send_case12(void** state)
{
    libspdm_return_t status;

    status = libspdm_test_requester_chunk_send_generic_test_case(state, 12);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
}

libspdm_test_context_t m_libspdm_requester_chunk_send_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_chunk_send_test_send_message,
    libspdm_requester_chunk_send_test_receive_message,
};

int libspdm_requester_chunk_send_test_main(void)
{
    /* Test the CHUNK_SEND handlers in various requester handlers */
    const struct CMUnitTest spdm_requester_chunk_send_tests[] = {
        /* Request Algorithms successfully sent in chunks. */
        cmocka_unit_test(libspdm_test_requester_chunk_send_case1),
        /* Chunk Request fail send */
        cmocka_unit_test(libspdm_test_requester_chunk_send_case2),
        /* Chunk Response fail receive */
        cmocka_unit_test(libspdm_test_requester_chunk_send_case3),
        /* Chunk Response has bad SPDM version */
        cmocka_unit_test(libspdm_test_requester_chunk_send_case4),
        /* Chunk Response has bad request response code */
        cmocka_unit_test(libspdm_test_requester_chunk_send_case5),
        /* Chunk Response has bad response size */
        cmocka_unit_test(libspdm_test_requester_chunk_send_case6),
        /* Chunk Response has early error detected */
        cmocka_unit_test(libspdm_test_requester_chunk_send_case7),
        /* Chunk Response has bad chunk handle */
        cmocka_unit_test(libspdm_test_requester_chunk_send_case8),
        /* Chunk Response has bad chunk seq no */
        cmocka_unit_test(libspdm_test_requester_chunk_send_case9),
        /* sent in chunks due to greater than the sending transmit buffer size. */
        cmocka_unit_test(libspdm_test_requester_chunk_send_case10),
        /* requester message size greater than the responder max_spdm_msg_size, return LIBSPDM_STATUS_PEER_BUFFER_TOO_SMALL */
        cmocka_unit_test(libspdm_test_requester_chunk_send_case11),
        /* ErrorCode == LargeResponse shall not be allowed in ResponseToLargeRequest */
        cmocka_unit_test(libspdm_test_requester_chunk_send_case12),
    };

    libspdm_setup_test_context(
        &m_libspdm_requester_chunk_send_test_context);

    return cmocka_run_group_tests(spdm_requester_chunk_send_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP*/
