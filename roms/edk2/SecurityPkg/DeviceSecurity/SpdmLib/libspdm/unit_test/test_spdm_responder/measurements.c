/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP

spdm_get_measurements_request_t m_libspdm_get_measurements_request1 = {
    { SPDM_MESSAGE_VERSION_10, SPDM_GET_MEASUREMENTS, 0,
      SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS },
};
size_t m_libspdm_get_measurements_request1_size = sizeof(spdm_message_header_t);

spdm_get_measurements_request_t m_libspdm_get_measurements_request3 = {
    { SPDM_MESSAGE_VERSION_10, SPDM_GET_MEASUREMENTS,
      SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE, 1 },
};
size_t m_libspdm_get_measurements_request3_size =
    sizeof(m_libspdm_get_measurements_request3) - sizeof(uint8_t);

spdm_get_measurements_request_t m_libspdm_get_measurements_request4 = {
    { SPDM_MESSAGE_VERSION_10, SPDM_GET_MEASUREMENTS,
      SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE, 1 },
};
size_t m_libspdm_get_measurements_request4_size = sizeof(spdm_message_header_t);

spdm_get_measurements_request_t m_libspdm_get_measurements_request5 = {
    { SPDM_MESSAGE_VERSION_10, SPDM_GET_MEASUREMENTS,
      SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
      SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS },
};
size_t m_libspdm_get_measurements_request5_size =
    sizeof(m_libspdm_get_measurements_request5) - sizeof(uint8_t);

spdm_get_measurements_request_t m_libspdm_get_measurements_request6 = {
    { SPDM_MESSAGE_VERSION_10, SPDM_GET_MEASUREMENTS, 0, 1 },
};
size_t m_libspdm_get_measurements_request6_size = sizeof(spdm_message_header_t);

spdm_get_measurements_request_t m_libspdm_get_measurements_request7 = {
    { SPDM_MESSAGE_VERSION_10, SPDM_GET_MEASUREMENTS, 0,
      SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS },
};
size_t m_libspdm_get_measurements_request7_size = sizeof(spdm_message_header_t);

spdm_get_measurements_request_t m_libspdm_get_measurements_request8 = {
    { SPDM_MESSAGE_VERSION_10, SPDM_GET_MEASUREMENTS,
      SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
      SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS },
};
size_t m_libspdm_get_measurements_request8_size =
    sizeof(m_libspdm_get_measurements_request8) - sizeof(uint8_t);

spdm_get_measurements_request_t m_libspdm_get_measurements_request9 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_GET_MEASUREMENTS, 0, 1 },
};
size_t m_libspdm_get_measurements_request9_size = sizeof(spdm_message_header_t);

spdm_get_measurements_request_t m_libspdm_get_measurements_request10 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_GET_MEASUREMENTS,
      SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE, 1 },
};
size_t m_libspdm_get_measurements_request10_size =
    sizeof(m_libspdm_get_measurements_request10);

spdm_get_measurements_request_t m_libspdm_get_measurements_request11 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_GET_MEASUREMENTS,
      SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE, 1 },
    /* nonce
     * SlotId != 0*/
};
size_t m_libspdm_get_measurements_request11_size =
    sizeof(m_libspdm_get_measurements_request11);

spdm_get_measurements_request_t m_libspdm_get_measurements_request12 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_GET_MEASUREMENTS,
      SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE, 1 },
    /* nonce
     * SlotId >= SPDM_MAX_SLOT_COUNT*/
};
size_t m_libspdm_get_measurements_request12_size =
    sizeof(m_libspdm_get_measurements_request12);

spdm_get_measurements_request_t m_libspdm_get_measurements_request13 = {
    { SPDM_MESSAGE_VERSION_11, SPDM_GET_MEASUREMENTS, 0, 0xF0 },
};
size_t m_libspdm_get_measurements_request13_size = sizeof(spdm_message_header_t);

spdm_get_measurements_request_t m_libspdm_get_measurements_request14 = {
    { SPDM_MESSAGE_VERSION_12, SPDM_GET_MEASUREMENTS,
      SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED, 1},
};
size_t m_libspdm_get_measurements_request14_size = sizeof(spdm_message_header_t);

spdm_get_measurements_request_t m_libspdm_get_measurements_request15 = {
    { SPDM_MESSAGE_VERSION_12, SPDM_GET_MEASUREMENTS,
      SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE, 1},
};
size_t m_libspdm_get_measurements_request15_size = sizeof(m_libspdm_get_measurements_request14);

spdm_get_measurements_request_t m_libspdm_get_measurements_request16 = {
    { SPDM_MESSAGE_VERSION_12, SPDM_GET_MEASUREMENTS,
      SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE, 1 },
};
size_t m_libspdm_get_measurements_request16_size = sizeof(m_libspdm_get_measurements_request16);

spdm_get_measurements_request_t m_libspdm_get_measurements_request17 = {
    { SPDM_MESSAGE_VERSION_13, SPDM_GET_MEASUREMENTS, 0,
      SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS },
};
size_t m_libspdm_get_measurements_request17_size = sizeof(spdm_message_header_t);

extern size_t libspdm_secret_lib_meas_opaque_data_size;

/**
 * Test 1: Successful response to get a number of measurements without signature
 * Expected Behavior: get a RETURN_SUCCESS return code, correct transcript.message_m size, and correct response message size and fields
 **/
void libspdm_test_responder_measurements_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_m(spdm_context, NULL);

    libspdm_secret_lib_meas_opaque_data_size = 0;

    response_size = sizeof(response);

    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request1_size,
        &m_libspdm_get_measurements_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_measurements_response_t) + SPDM_NONCE_SIZE + sizeof(uint16_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
    assert_int_equal(spdm_response->header.param1,
                     LIBSPDM_MEASUREMENT_BLOCK_NUMBER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     m_libspdm_get_measurements_request1_size +
                     sizeof(spdm_measurements_response_t) +
                     SPDM_NONCE_SIZE +
                     sizeof(uint16_t));
#endif
}

/**
 * Test 2:
 * Expected Behavior:
 **/
void libspdm_test_responder_measurements_case2(void **state)
{
}

/**
 * Test 3: Force response_state = SPDM_RESPONSE_STATE_BUSY when asked GET_MEASUREMENTS
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_BUSY
 **/
void libspdm_test_responder_measurements_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request1.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request1_size,
        &m_libspdm_get_measurements_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_BUSY);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 4: Force response_state = SPDM_RESPONSE_STATE_NEED_RESYNC when asked GET_MEASUREMENTS
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_REQUEST_RESYNCH
 **/
void libspdm_test_responder_measurements_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request1.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request1_size,
        &m_libspdm_get_measurements_request1, &response_size, response);
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
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
/**
 * Test 5: Force response_state = SPDM_RESPONSE_STATE_NOT_READY when asked GET_MEASUREMENTS
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_RESPONSE_NOT_READY
 **/
void libspdm_test_responder_measurements_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    spdm_error_data_response_not_ready_t *error_data;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request1.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request1_size,
        &m_libspdm_get_measurements_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_error_response_t) +
                     sizeof(spdm_error_data_response_not_ready_t));
    spdm_response = (void *)response;
    error_data = (spdm_error_data_response_not_ready_t
                  *)(&spdm_response->number_of_blocks);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESPONSE_NOT_READY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_NOT_READY);
    assert_int_equal(error_data->request_code, SPDM_GET_MEASUREMENTS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

/**
 * Test 6: simulate wrong connection_state when asked GET_MEASUREMENTS
 *        (missing SPDM_GET_DIGESTS_RECEIVE_FLAG, SPDM_GET_CAPABILITIES_RECEIVE_FLAG and SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG)
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_UNEXPECTED_REQUEST
 **/
void libspdm_test_responder_measurements_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request1.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request1_size,
        &m_libspdm_get_measurements_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 7: Successful response to get a number of measurements with signature
 * Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m, and correct response message size and fields
 **/
void libspdm_test_responder_measurements_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    size_t measurment_sig_size;

    bool result;
    uint32_t measurement_record_data_length;
    uint8_t *measurement_record_data;
    uint8_t *ptr;
    uint16_t opaque_length;
    void *signature;
    size_t signature_size;
    libspdm_session_info_t *session_info;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
                          libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request5.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request5_size,
        &m_libspdm_get_measurements_request5, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_measurements_response_t) +
                     measurment_sig_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
    assert_int_equal(spdm_response->header.param1,
                     LIBSPDM_MEASUREMENT_BLOCK_NUMBER);

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    measurement_record_data_length = libspdm_read_uint24(spdm_response->measurement_record_length);
    measurement_record_data = (void *)(spdm_response + 1);
    ptr = measurement_record_data + measurement_record_data_length;
    ptr += SPDM_NONCE_SIZE;
    opaque_length = libspdm_read_uint16((const uint8_t *)ptr);
    ptr += sizeof(uint16_t);
    ptr += opaque_length;
    signature = ptr;
    signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
    session_info = NULL;

    status = libspdm_append_message_m(spdm_context, session_info,
                                      &m_libspdm_get_measurements_request5,
                                      m_libspdm_get_measurements_request5_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    status = libspdm_append_message_m(spdm_context, session_info, spdm_response,
                                      response_size - signature_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    result = libspdm_verify_measurement_signature(
        spdm_context, session_info, signature, signature_size);
    assert_true(result);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 8: Successful response to get one measurement with signature
 * Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m, and correct response message size and fields
 **/
void libspdm_test_responder_measurements_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    size_t measurment_sig_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
                          libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request3.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request3_size,
        &m_libspdm_get_measurements_request3, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_measurements_response_t) +
                     sizeof(spdm_measurement_block_dmtf_t) +
                     libspdm_get_measurement_hash_size(
                         m_libspdm_use_measurement_hash_algo) +
                     measurment_sig_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 9: Error case, Bad request size (sizeof(spdm_message_header_t)x) to get measurement number with signature
 * Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
 **/
void libspdm_test_responder_measurements_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request4.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request4_size,
        &m_libspdm_get_measurements_request4, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 10: Successful response to get one measurement without signature
 * Expected Behavior: get a RETURN_SUCCESS return code, correct transcript.message_m size, and correct response message size and fields
 **/
void libspdm_test_responder_measurements_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request6.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request6_size,
        &m_libspdm_get_measurements_request6, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_measurements_response_t) +
                     sizeof(spdm_measurement_block_dmtf_t) +
                     libspdm_get_measurement_hash_size(
                         m_libspdm_use_measurement_hash_algo) + SPDM_NONCE_SIZE +
                     sizeof(uint16_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     m_libspdm_get_measurements_request6_size +
                     sizeof(spdm_measurements_response_t) +
                     sizeof(spdm_measurement_block_dmtf_t) +
                     libspdm_get_measurement_hash_size(
                         m_libspdm_use_measurement_hash_algo) + SPDM_NONCE_SIZE +
                     sizeof(uint16_t));
#endif
}

/**
 * Test 11: Successful response to get all measurements with signature
 * Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m, and correct response message size and fields
 **/
void libspdm_test_responder_measurements_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    size_t measurment_sig_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
                          libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request8.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request8_size,
        &m_libspdm_get_measurements_request8, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_measurements_response_t) +
                     LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER *
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      libspdm_get_measurement_hash_size(
                          m_libspdm_use_measurement_hash_algo)) +
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      sizeof(spdm_measurements_secure_version_number_t)) +
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      LIBSPDM_MEASUREMENT_MANIFEST_SIZE) +
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      sizeof(spdm_measurements_device_mode_t)) +
                     measurment_sig_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
    assert_int_equal(spdm_response->number_of_blocks,
                     LIBSPDM_MEASUREMENT_BLOCK_NUMBER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 12: Successful response to get all measurements without signature
 * Expected Behavior: get a RETURN_SUCCESS return code, correct transcript.message_m size, and correct response message size and fields
 **/
void libspdm_test_responder_measurements_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request7.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request7_size,
        &m_libspdm_get_measurements_request7, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_measurements_response_t) +
                     LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER *
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      libspdm_get_measurement_hash_size(
                          m_libspdm_use_measurement_hash_algo)) +
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      sizeof(spdm_measurements_secure_version_number_t)) +
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      LIBSPDM_MEASUREMENT_MANIFEST_SIZE) +
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      sizeof(spdm_measurements_device_mode_t)) +
                     SPDM_NONCE_SIZE + sizeof(uint16_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
    assert_int_equal(spdm_response->number_of_blocks,
                     LIBSPDM_MEASUREMENT_BLOCK_NUMBER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     m_libspdm_get_measurements_request7_size +
                     sizeof(spdm_measurements_response_t) +
                     LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER *
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      libspdm_get_measurement_hash_size(
                          m_libspdm_use_measurement_hash_algo)) +
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      sizeof(spdm_measurements_secure_version_number_t)) +
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      LIBSPDM_MEASUREMENT_MANIFEST_SIZE) +
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      sizeof(spdm_measurements_device_mode_t)) +
                     SPDM_NONCE_SIZE + sizeof(uint16_t));
#endif
}

/**
 * Test 13:
 * Expected Behavior:
 **/
void libspdm_test_responder_measurements_case13(void **state)
{
}

/**
 * Test 14: Error case, signature was required, but there is no nonce and/or slotID
 * Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
 **/
void libspdm_test_responder_measurements_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    uint16_t TestMsgSizes[3];

    TestMsgSizes[0] =
        (uint16_t)(m_libspdm_get_measurements_request10_size -
                   sizeof(m_libspdm_get_measurements_request10.slot_id_param) -
                   sizeof(m_libspdm_get_measurements_request10.nonce));
    TestMsgSizes[1] =
        (uint16_t)(m_libspdm_get_measurements_request10_size -
                   sizeof(m_libspdm_get_measurements_request10.slot_id_param));
    TestMsgSizes[2] =
        (uint16_t)(m_libspdm_get_measurements_request10_size -
                   sizeof(m_libspdm_get_measurements_request10.nonce));

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;

    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request10.nonce);
    for (int i = 0; i < sizeof(TestMsgSizes) / sizeof(TestMsgSizes[0]);
         i++) {
        response_size = sizeof(response);
        status = libspdm_get_response_measurements(
            spdm_context, TestMsgSizes[i],
            &m_libspdm_get_measurements_request10, &response_size,
            response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        assert_int_equal(response_size, sizeof(spdm_error_response_t));
        spdm_response = (void *)response;
        assert_int_equal(spdm_response->header.request_response_code,
                         SPDM_ERROR);
        assert_int_equal(spdm_response->header.param1,
                         SPDM_ERROR_CODE_INVALID_REQUEST);
        assert_int_equal(spdm_response->header.param2, 0);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                         0);
#endif
    }
}

/**
 * Test 15: Error case, meas_cap = 01b, but signature was requested (request message includes nonce and slotID)
 * Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
 **/
void libspdm_test_responder_measurements_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    /* size_t                measurment_sig_size;*/

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    /* measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 + libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);*/

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request10.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request10_size,
        &m_libspdm_get_measurements_request10, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 16: Error case, meas_cap = 01b, but signature was requested (request message does not include nonce and slotID)
 * Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
 **/
void libspdm_test_responder_measurements_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    /* size_t                measurment_sig_size;*/

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    /* measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 + libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);*/

    response_size = sizeof(response);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request9_size,
        &m_libspdm_get_measurements_request10, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 17: Error case, meas_cap = 00
 * Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
 **/
void libspdm_test_responder_measurements_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    /* size_t                measurment_sig_size;*/

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    /* measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 + libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);*/

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request9.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request9_size,
        &m_libspdm_get_measurements_request9, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(
        spdm_response->header.param2,
        m_libspdm_get_measurements_request10.header.request_response_code);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 18: Successful response to get one measurement with signature, SlotId different from default
 * Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m, and correct response message size and fields
 **/
void libspdm_test_responder_measurements_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    void *data;
    size_t data_size;
    size_t measurment_sig_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, NULL, NULL);
    measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
                          libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
    for (int i = 0; i < SPDM_MAX_SLOT_COUNT; i++) {
        spdm_context->local_context.local_cert_chain_provision_size[i] =
            data_size;
        spdm_context->local_context.local_cert_chain_provision[i] =
            data;
    }

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request11.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request11_size,
        &m_libspdm_get_measurements_request11, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_measurements_response_t) +
                     sizeof(spdm_measurement_block_dmtf_t) +
                     libspdm_get_measurement_hash_size(
                         m_libspdm_use_measurement_hash_algo) +
                     measurment_sig_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    assert_int_equal(m_libspdm_get_measurements_request11.slot_id_param,
                     spdm_response->header.param2);

    free(data);
}

/**
 * Test 19: Error case, invalid SlotId parameter (SlotId >= SPDM_MAX_SLOT_COUNT)
 * Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
 **/
void libspdm_test_responder_measurements_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    /* size_t                measurment_sig_size;*/

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    /* measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 + libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);*/

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request12.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request12_size,
        &m_libspdm_get_measurements_request12, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 21: Error case, request a measurement index not found
 * Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m size, and Error message as response
 **/
void libspdm_test_responder_measurements_case21(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request13.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request13_size,
        &m_libspdm_get_measurements_request13, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 22: request a large number of measurements before requesting a singed response
 * Expected Behavior: while transcript.message_m is not full, get a RETURN_SUCCESS return code, empty transcript.message_m, and correct response message size and fields
 *                    if transcript.message_m has no more room, an error response is expected
 **/
void libspdm_test_responder_measurements_case22(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    size_t NumberOfMessages;
#define TOTAL_MESSAGES 100

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;

    for (NumberOfMessages = 1; NumberOfMessages <= TOTAL_MESSAGES; NumberOfMessages++) {
        libspdm_get_random_number(SPDM_NONCE_SIZE,
                                  m_libspdm_get_measurements_request9.nonce);
        response_size = sizeof(response);
        status = libspdm_get_response_measurements(
            spdm_context, m_libspdm_get_measurements_request9_size,
            &m_libspdm_get_measurements_request9, &response_size,
            response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        spdm_response = (void *)response;
        if (spdm_response->header.request_response_code ==
            SPDM_MEASUREMENTS) {
            assert_int_equal(
                spdm_response->header.request_response_code,
                SPDM_MEASUREMENTS);
            assert_int_equal(
                response_size,
                sizeof(spdm_measurements_response_t) +
                sizeof(spdm_measurement_block_dmtf_t) +
                libspdm_get_measurement_hash_size(
                    m_libspdm_use_measurement_hash_algo) + SPDM_NONCE_SIZE +
                sizeof(uint16_t));
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
            assert_int_equal(
                spdm_context->transcript.message_m.buffer_size,
                NumberOfMessages *
                (m_libspdm_get_measurements_request9_size +
                 sizeof(spdm_measurements_response_t) +
                 sizeof(spdm_measurement_block_dmtf_t) +
                 libspdm_get_measurement_hash_size(
                     m_libspdm_use_measurement_hash_algo) + SPDM_NONCE_SIZE +
                 sizeof(uint16_t)));
#endif
        } else {
            assert_int_equal(
                spdm_response->header.request_response_code,
                SPDM_ERROR);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
            assert_int_equal(
                spdm_context->transcript.message_m.buffer_size,
                0);
#endif
            break;
        }
    }
}

/**
 * Test 23: Successful response to get a session based measurement with signature
 * Expected Behavior: get a RETURN_SUCCESS return code, with an empty session_transcript.message_m
 **/
void libspdm_test_responder_measurements_case23(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    size_t measurment_sig_size;
    libspdm_session_info_t *session_info;
    uint32_t session_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_secret_lib_meas_opaque_data_size = 0;
    measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
                          libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request5.nonce);


    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request5_size,
        &m_libspdm_get_measurements_request5, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_measurements_response_t) +
                     measurment_sig_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
    assert_int_equal(spdm_response->header.param1,
                     LIBSPDM_MEASUREMENT_BLOCK_NUMBER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(session_info->session_transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 24: receiving a correct GET_MEASUREMENTS from the requester that does not request a
 * signature. Buffer M already has arbitrary data.
 * Expected behavior: the responder accepts the request and produces a valid
 * MEASUREMENTS response message, and buffer M appends the exchanged GET_MEASUREMENTS and MEASUREMENTS
 * messages.
 **/
void libspdm_test_responder_measurements_case24(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t arbitrary_size;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    spdm_context->last_spdm_request_session_id_valid = 0;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /*filling M buffer with arbitrary data*/
    arbitrary_size = 18;
    libspdm_set_mem(spdm_context->transcript.message_m.buffer, arbitrary_size, (uint8_t) 0xFF);
    spdm_context->transcript.message_m.buffer_size = arbitrary_size;
#endif

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE, m_libspdm_get_measurements_request7.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request7_size,
        &m_libspdm_get_measurements_request7, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_measurements_response_t) + LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER*
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      libspdm_get_measurement_hash_size(m_libspdm_use_measurement_hash_algo)) +
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      sizeof(spdm_measurements_secure_version_number_t)) +
                     (sizeof(spdm_measurement_block_dmtf_t) + LIBSPDM_MEASUREMENT_MANIFEST_SIZE) +
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      sizeof(spdm_measurements_device_mode_t)) +
                     SPDM_NONCE_SIZE + sizeof(uint16_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_MEASUREMENTS);
    assert_int_equal(spdm_response->number_of_blocks, LIBSPDM_MEASUREMENT_BLOCK_NUMBER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     arbitrary_size + m_libspdm_get_measurements_request7_size +
                     sizeof(spdm_measurements_response_t) + LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER*
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      libspdm_get_measurement_hash_size(m_libspdm_use_measurement_hash_algo)) +
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      sizeof(spdm_measurements_secure_version_number_t)) +
                     (sizeof(spdm_measurement_block_dmtf_t) + LIBSPDM_MEASUREMENT_MANIFEST_SIZE) +
                     (sizeof(spdm_measurement_block_dmtf_t) +
                      sizeof(spdm_measurements_device_mode_t)) +
                     SPDM_NONCE_SIZE + sizeof(uint16_t));

    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     arbitrary_size + m_libspdm_get_measurements_request7_size + response_size);
    assert_memory_equal(spdm_context->transcript.message_m.buffer + arbitrary_size,
                        &m_libspdm_get_measurements_request7,
                        m_libspdm_get_measurements_request7_size);
    assert_memory_equal(spdm_context->transcript.message_m.buffer + arbitrary_size
                        + m_libspdm_get_measurements_request7_size,
                        response, response_size);
#endif
}

void libspdm_test_responder_measurements_case25(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request14.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request14_size,
        &m_libspdm_get_measurements_request14, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_measurements_response_t) +
                     sizeof(spdm_measurement_block_dmtf_t) +
                     LIBSPDM_MEASUREMENT_RAW_DATA_SIZE + SPDM_NONCE_SIZE +
                     sizeof(uint16_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     m_libspdm_get_measurements_request14_size +
                     sizeof(spdm_measurements_response_t) +
                     sizeof(spdm_measurement_block_dmtf_t) +
                     LIBSPDM_MEASUREMENT_RAW_DATA_SIZE + SPDM_NONCE_SIZE +
                     sizeof(uint16_t));
#endif
}

void libspdm_test_responder_measurements_case26(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    void *data;
    size_t data_size;
    size_t measurment_sig_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1A;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, NULL, NULL);
    measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
                          libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
    for (int i = 0; i < SPDM_MAX_SLOT_COUNT; i++) {
        spdm_context->local_context.local_cert_chain_provision_size[i] =
            data_size;
        spdm_context->local_context.local_cert_chain_provision[i] =
            data;
    }

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request15.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request15_size,
        &m_libspdm_get_measurements_request15, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_measurements_response_t) +
                     sizeof(spdm_measurement_block_dmtf_t) +
                     libspdm_get_measurement_hash_size(
                         m_libspdm_use_measurement_hash_algo) +
                     measurment_sig_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    assert_int_equal(spdm_response->header.param2, m_libspdm_get_measurements_request15.slot_id_param|
                     (SPDM_MEASUREMENTS_RESPONSE_CONTENT_NO_CHANGE_DETECTED &
                      SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_MASK));

    free(data);
}

void libspdm_test_responder_measurements_case27(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    void *data;
    size_t data_size;
    size_t measurment_sig_size;
    uint8_t content_changed;
    uint8_t measurements_count;
    uint8_t *measurement_record_data;
    size_t measurement_record_data_length;
    uint8_t expect_measurement_record_data[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    size_t expect_measurement_record_data_length;
    uint8_t *opaque_data;
    uint16_t *opaque_data_size;
    uint8_t expect_opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    size_t expect_opaque_data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1B;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_reset_message_m(spdm_context, NULL);

    /*opaque data*/
    libspdm_secret_lib_meas_opaque_data_size = 0x20;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, NULL, NULL);
    measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) +
                          libspdm_secret_lib_meas_opaque_data_size +
                          libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
    for (int i = 0; i < SPDM_MAX_SLOT_COUNT; i++) {
        spdm_context->local_context.local_cert_chain_provision_size[i] = data_size;
        spdm_context->local_context.local_cert_chain_provision[i] = data;
    }

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE, m_libspdm_get_measurements_request15.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request15_size,
        &m_libspdm_get_measurements_request15, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_measurements_response_t) +
                     sizeof(spdm_measurement_block_dmtf_t) +
                     libspdm_get_measurement_hash_size(m_libspdm_use_measurement_hash_algo) +
                     measurment_sig_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);

    expect_measurement_record_data_length = sizeof(expect_measurement_record_data);
    expect_opaque_data_size = sizeof(expect_opaque_data);

    libspdm_measurement_collection(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        spdm_context->connection_info.version,
        spdm_context->connection_info.algorithm.measurement_spec,
        spdm_context->connection_info.algorithm.measurement_hash_algo,
        m_libspdm_get_measurements_request15.header.param2,
        m_libspdm_get_measurements_request15.header.param1,
        &content_changed,
        &measurements_count,
        expect_measurement_record_data,
        &expect_measurement_record_data_length);

    libspdm_measurement_opaque_data(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        spdm_context->connection_info.version,
        spdm_context->connection_info.algorithm.measurement_spec,
        spdm_context->connection_info.algorithm.measurement_hash_algo,
        m_libspdm_get_measurements_request15.header.param2,
        m_libspdm_get_measurements_request15.header.param1,
        expect_opaque_data,
        &expect_opaque_data_size);

    measurement_record_data = (uint8_t *)response + sizeof(spdm_measurements_response_t);
    opaque_data_size =
        (uint16_t *)(measurement_record_data + sizeof(spdm_measurement_block_dmtf_t) +
                     libspdm_get_measurement_hash_size(
                         m_libspdm_use_measurement_hash_algo) +
                     SPDM_NONCE_SIZE);
    opaque_data = (uint8_t *)opaque_data_size + sizeof(uint16_t);

    measurement_record_data_length = libspdm_read_uint24(spdm_response->measurement_record_length);

    assert_int_equal(measurement_record_data_length, expect_measurement_record_data_length );
    assert_memory_equal(measurement_record_data, expect_measurement_record_data,
                        expect_measurement_record_data_length);
    assert_int_equal(*opaque_data_size, libspdm_secret_lib_meas_opaque_data_size);
    assert_memory_equal(opaque_data, expect_opaque_data, libspdm_secret_lib_meas_opaque_data_size);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    assert_int_equal(spdm_response->header.param2, m_libspdm_get_measurements_request15.slot_id_param|
                     (SPDM_MEASUREMENTS_RESPONSE_CONTENT_NO_CHANGE_DETECTED &
                      SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_MASK));

    free(data);
}

/**
 * Test 28: Successful response to get all measurements with signature using slot_id 0xFF
 * Expected Behavior: get a RETURN_SUCCESS return code, empty transcript.message_m, and correct response message size and fields
 **/
void libspdm_test_responder_measurements_case28(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    void *data;
    size_t data_size;
    size_t measurment_sig_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1C;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_reset_message_m(spdm_context, NULL);

    /*opaque data*/
    libspdm_secret_lib_meas_opaque_data_size = 0x20;

    libspdm_read_responder_public_key(m_libspdm_use_asym_algo, &data, &data_size);
    spdm_context->local_context.local_public_key_provision = data;
    spdm_context->local_context.local_public_key_provision_size = data_size;

    measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) +
                          libspdm_secret_lib_meas_opaque_data_size +
                          libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request16.nonce);
    m_libspdm_get_measurements_request16.slot_id_param = 0xF;
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request16_size,
        &m_libspdm_get_measurements_request16, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_measurements_response_t) + sizeof(spdm_measurement_block_dmtf_t) +
                     libspdm_get_measurement_hash_size(m_libspdm_use_measurement_hash_algo) +
                     measurment_sig_size);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
    assert_int_equal(spdm_response->header.param2,
                     m_libspdm_get_measurements_request16.slot_id_param |
                     (SPDM_MEASUREMENTS_RESPONSE_CONTENT_NO_CHANGE_DETECTED &
                      SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_MASK));

    free(data);
}

/**
 * Test 29: Based of Test Case 7  Successful response to get a number of measurements
 * with signature.
 * Signature test with signing in big endian but verification in little endian.
 *
 * Expected Behavior: Failing signature verification
 **/
void libspdm_test_responder_measurements_case29(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t* spdm_response;
    size_t measurment_sig_size;

    bool result;
    uint32_t measurement_record_data_length;
    uint8_t* measurement_record_data;
    uint8_t* ptr;
    uint16_t opaque_length;
    void* signature;
    size_t signature_size;
    libspdm_session_info_t* session_info;
    void* data;
    size_t data_size;
    void* hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 29;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->spdm_10_11_verify_signature_endian =
        LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY;

    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
                          libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request5.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request5_size,
        &m_libspdm_get_measurements_request5, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_measurements_response_t) +
                     measurment_sig_size);
    spdm_response = (void*)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
    assert_int_equal(spdm_response->header.param1,
                     LIBSPDM_MEASUREMENT_BLOCK_NUMBER);

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    measurement_record_data_length = libspdm_read_uint24(spdm_response->measurement_record_length);
    measurement_record_data = (void*)(spdm_response + 1);
    ptr = measurement_record_data + measurement_record_data_length;
    ptr += SPDM_NONCE_SIZE;
    opaque_length = libspdm_read_uint16((const uint8_t*)ptr);
    ptr += sizeof(uint16_t);
    ptr += opaque_length;
    signature = ptr;
    signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
    session_info = NULL;

    status = libspdm_append_message_m(spdm_context, session_info,
                                      &m_libspdm_get_measurements_request5,
                                      m_libspdm_get_measurements_request5_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    status = libspdm_append_message_m(spdm_context, session_info, spdm_response,
                                      response_size - signature_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    result = libspdm_verify_measurement_signature(
        spdm_context, session_info, signature, signature_size);
    assert_true(result == false);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 30: Based of Test Case 7  Successful response to get a number of measurements
 * with signature.
 * Signature test with signing in big endian but verification in little endian.
 *
 * Expected Behavior: Failing signature verification
 **/
void libspdm_test_responder_measurements_case30(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t* spdm_response;
    size_t measurment_sig_size;

    bool result;
    uint32_t measurement_record_data_length;
    uint8_t* measurement_record_data;
    uint8_t* ptr;
    uint16_t opaque_length;
    void* signature;
    size_t signature_size;
    libspdm_session_info_t* session_info;
    void* data;
    size_t data_size;
    void* hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 30;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->spdm_10_11_verify_signature_endian =
        LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY;

    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
                          libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request5.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request5_size,
        &m_libspdm_get_measurements_request5, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_measurements_response_t) +
                     measurment_sig_size);
    spdm_response = (void*)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
    assert_int_equal(spdm_response->header.param1,
                     LIBSPDM_MEASUREMENT_BLOCK_NUMBER);

    libspdm_read_responder_public_certificate_chain(
        m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
        &data, &data_size,
        &hash, &hash_size);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    measurement_record_data_length = libspdm_read_uint24(spdm_response->measurement_record_length);
    measurement_record_data = (void*)(spdm_response + 1);
    ptr = measurement_record_data + measurement_record_data_length;
    ptr += SPDM_NONCE_SIZE;
    opaque_length = libspdm_read_uint16((const uint8_t*)ptr);
    ptr += sizeof(uint16_t);
    ptr += opaque_length;
    signature = ptr;
    signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
    session_info = NULL;

    status = libspdm_append_message_m(
        spdm_context, session_info,
        &m_libspdm_get_measurements_request5,
        m_libspdm_get_measurements_request5_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    status = libspdm_append_message_m(
        spdm_context, session_info, spdm_response,
        response_size - signature_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    result = libspdm_verify_measurement_signature(
        spdm_context, session_info, signature, signature_size);
    assert_true(result == true);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 31: Based of Test Case 7  Successful response to get a number of measurements
 * with signature.
 * Signature test with signing in big endian but verification in big or little endian.
 *
 * Expected Behavior: Passing signature verification
 **/
void libspdm_test_responder_measurements_case31(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t* spdm_response;
    size_t measurment_sig_size;

    bool result;
    uint32_t measurement_record_data_length;
    uint8_t* measurement_record_data;
    uint8_t* ptr;
    uint16_t opaque_length;
    void* signature;
    size_t signature_size;
    libspdm_session_info_t* session_info;
    void* data;
    size_t data_size;
    void* hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 31;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->spdm_10_11_verify_signature_endian =
        LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE;

    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
                          libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request5.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request5_size,
        &m_libspdm_get_measurements_request5, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_measurements_response_t) +
                     measurment_sig_size);
    spdm_response = (void*)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
    assert_int_equal(spdm_response->header.param1,
                     LIBSPDM_MEASUREMENT_BLOCK_NUMBER);

    libspdm_read_responder_public_certificate_chain(
        m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
        &data, &data_size,
        &hash, &hash_size);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    measurement_record_data_length = libspdm_read_uint24(spdm_response->measurement_record_length);
    measurement_record_data = (void*)(spdm_response + 1);
    ptr = measurement_record_data + measurement_record_data_length;
    ptr += SPDM_NONCE_SIZE;
    opaque_length = libspdm_read_uint16((const uint8_t*)ptr);
    ptr += sizeof(uint16_t);
    ptr += opaque_length;
    signature = ptr;
    signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
    session_info = NULL;

    status = libspdm_append_message_m(
        spdm_context, session_info,
        &m_libspdm_get_measurements_request5,
        m_libspdm_get_measurements_request5_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    status = libspdm_append_message_m(
        spdm_context, session_info, spdm_response,
        response_size - signature_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    result = libspdm_verify_measurement_signature(
        spdm_context, session_info, signature, signature_size);
    assert_true(result == true);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 32: Based of Test Case 7  Successful response to get a number of measurements
 * with signature.
 * Signature test with signing in little endian but verification in little endian.
 *
 * Expected Behavior: Failing signature verification
 **/
void libspdm_test_responder_measurements_case32(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t* spdm_response;
    size_t measurment_sig_size;

    bool result;
    uint32_t measurement_record_data_length;
    uint8_t* measurement_record_data;
    uint8_t* ptr;
    uint16_t opaque_length;
    void* signature;
    size_t signature_size;
    libspdm_session_info_t* session_info;
    void* data;
    size_t data_size;
    void* hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 32;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->spdm_10_11_verify_signature_endian =
        LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_LITTLE_ONLY;

    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
                          libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request5.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request5_size,
        &m_libspdm_get_measurements_request5, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_measurements_response_t) +
                     measurment_sig_size);
    spdm_response = (void*)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
    assert_int_equal(spdm_response->header.param1,
                     LIBSPDM_MEASUREMENT_BLOCK_NUMBER);

    libspdm_read_responder_public_certificate_chain(
        m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
        &data, &data_size,
        &hash, &hash_size);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    measurement_record_data_length = libspdm_read_uint24(spdm_response->measurement_record_length);
    measurement_record_data = (void*)(spdm_response + 1);
    ptr = measurement_record_data + measurement_record_data_length;
    ptr += SPDM_NONCE_SIZE;
    opaque_length = libspdm_read_uint16((const uint8_t*)ptr);
    ptr += sizeof(uint16_t);
    ptr += opaque_length;
    signature = ptr;
    signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

    libspdm_copy_signature_swap_endian(
        m_libspdm_use_asym_algo,
        signature, signature_size, signature, signature_size);

    session_info = NULL;

    status = libspdm_append_message_m(
        spdm_context, session_info,
        &m_libspdm_get_measurements_request5,
        m_libspdm_get_measurements_request5_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    status = libspdm_append_message_m(
        spdm_context, session_info, spdm_response,
        response_size - signature_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    result = libspdm_verify_measurement_signature(
        spdm_context, session_info, signature, signature_size);
    assert_true(result == true);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 33: Based of Test Case 7  Successful response to get a number of measurements
 * with signature.
 * Signature test with signing in little endian but verification in big endian.
 *
 * Expected Behavior: Failing signature verification
 **/
void libspdm_test_responder_measurements_case33(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t* spdm_response;
    size_t measurment_sig_size;

    bool result;
    uint32_t measurement_record_data_length;
    uint8_t* measurement_record_data;
    uint8_t* ptr;
    uint16_t opaque_length;
    void* signature;
    size_t signature_size;
    libspdm_session_info_t* session_info;
    void* data;
    size_t data_size;
    void* hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 33;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->spdm_10_11_verify_signature_endian =
        LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY;

    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
                          libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request5.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request5_size,
        &m_libspdm_get_measurements_request5, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_measurements_response_t) +
                     measurment_sig_size);
    spdm_response = (void*)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
    assert_int_equal(spdm_response->header.param1,
                     LIBSPDM_MEASUREMENT_BLOCK_NUMBER);

    libspdm_read_responder_public_certificate_chain(
        m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
        &data, &data_size,
        &hash, &hash_size);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    measurement_record_data_length = libspdm_read_uint24(spdm_response->measurement_record_length);
    measurement_record_data = (void*)(spdm_response + 1);
    ptr = measurement_record_data + measurement_record_data_length;
    ptr += SPDM_NONCE_SIZE;
    opaque_length = libspdm_read_uint16((const uint8_t*)ptr);
    ptr += sizeof(uint16_t);
    ptr += opaque_length;
    signature = ptr;
    signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

    libspdm_copy_signature_swap_endian(
        m_libspdm_use_asym_algo,
        signature, signature_size, signature, signature_size);

    session_info = NULL;

    status = libspdm_append_message_m(
        spdm_context, session_info,
        &m_libspdm_get_measurements_request5,
        m_libspdm_get_measurements_request5_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    status = libspdm_append_message_m(
        spdm_context, session_info, spdm_response,
        response_size - signature_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    result = libspdm_verify_measurement_signature(
        spdm_context, session_info, signature, signature_size);
    assert_true(result == false);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}


/**
 * Test 34: Based of Test Case 7  Successful response to get a number of measurements
 * with signature.
 * Signature test with signing in little endian but verification in big or little endian.
 *
 * Expected Behavior: Passing signature verification
 **/
void libspdm_test_responder_measurements_case34(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t* spdm_response;
    size_t measurment_sig_size;

    bool result;
    uint32_t measurement_record_data_length;
    uint8_t* measurement_record_data;
    uint8_t* ptr;
    uint16_t opaque_length;
    void* signature;
    size_t signature_size;
    libspdm_session_info_t* session_info;
    void* data;
    size_t data_size;
    void* hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 34;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->spdm_10_11_verify_signature_endian =
        LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE;

    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    measurment_sig_size = SPDM_NONCE_SIZE + sizeof(uint16_t) + 0 +
                          libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);

    response_size = sizeof(response);
    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request5.nonce);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request5_size,
        &m_libspdm_get_measurements_request5, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_measurements_response_t) +
                     measurment_sig_size);
    spdm_response = (void*)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
    assert_int_equal(spdm_response->header.param1,
                     LIBSPDM_MEASUREMENT_BLOCK_NUMBER);

    libspdm_read_responder_public_certificate_chain(
        m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
        &data, &data_size,
        &hash, &hash_size);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    measurement_record_data_length = libspdm_read_uint24(spdm_response->measurement_record_length);
    measurement_record_data = (void*)(spdm_response + 1);
    ptr = measurement_record_data + measurement_record_data_length;
    ptr += SPDM_NONCE_SIZE;
    opaque_length = libspdm_read_uint16((const uint8_t*)ptr);
    ptr += sizeof(uint16_t);
    ptr += opaque_length;
    signature = ptr;
    signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
    libspdm_copy_signature_swap_endian(
        m_libspdm_use_asym_algo,
        signature, signature_size, signature, signature_size);

    session_info = NULL;

    status = libspdm_append_message_m(
        spdm_context, session_info,
        &m_libspdm_get_measurements_request5,
        m_libspdm_get_measurements_request5_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    status = libspdm_append_message_m(
        spdm_context, session_info, spdm_response,
        response_size - signature_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    result = libspdm_verify_measurement_signature(
        spdm_context, session_info, signature, signature_size);
    assert_true(result == true);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

/**
 * Test 35: Successful response V1.3 to get a number of measurements without signature
 * Expected Behavior: get a RETURN_SUCCESS return code, correct context field
 **/
void libspdm_test_responder_measurements_case35(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    uint8_t *requester_context;
    uint8_t *responder_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 35;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    libspdm_reset_message_m(spdm_context, NULL);

    libspdm_secret_lib_meas_opaque_data_size = 0;

    response_size = sizeof(response);

    requester_context = ((uint8_t *)&m_libspdm_get_measurements_request17) +
                        m_libspdm_get_measurements_request17_size;
    libspdm_set_mem(requester_context, SPDM_REQ_CONTEXT_SIZE, 0xAA);
    m_libspdm_get_measurements_request17_size += SPDM_REQ_CONTEXT_SIZE;

    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request17_size,
        &m_libspdm_get_measurements_request17, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size,
                     sizeof(spdm_measurements_response_t) + SPDM_NONCE_SIZE + sizeof(uint16_t) +
                     SPDM_REQ_CONTEXT_SIZE);
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_MEASUREMENTS);
    responder_context = (void *)response;
    responder_context += sizeof(spdm_measurements_response_t) + SPDM_NONCE_SIZE + sizeof(uint16_t);
    assert_memory_equal((void *)requester_context, responder_context, SPDM_REQ_CONTEXT_SIZE);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     m_libspdm_get_measurements_request17_size +
                     sizeof(spdm_measurements_response_t) +
                     SPDM_NONCE_SIZE +
                     sizeof(uint16_t) +
                     SPDM_REQ_CONTEXT_SIZE);
#endif
}

/**
 * Test 36: The key usage bit mask is not set, the SlotID fields in GET_MEASUREMENTS and MEASUREMENTS shall not specify this certificate slot
 * Expected Behavior: get a SPDM_ERROR_CODE_INVALID_REQUEST return code
 **/
void libspdm_test_responder_measurements_case36(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response;
    uint8_t *requester_context;
    uint8_t slot_id;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 36;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.multi_key_conn_rsp = true;
    libspdm_reset_message_m(spdm_context, NULL);

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, NULL, NULL);
    for (int i = 0; i < SPDM_MAX_SLOT_COUNT; i++) {
        spdm_context->local_context.local_cert_chain_provision_size[i] = data_size;
        spdm_context->local_context.local_cert_chain_provision[i] = data;
    }

    /* If set, the SlotID fields in GET_MEASUREMENTS and MEASUREMENTS can specify this certificate slot. If not set,
     * the SlotID fields in GET_MEASUREMENTS and MEASUREMENTS shall not specify this certificate slot. */
    slot_id = 0;
    m_libspdm_get_measurements_request17.slot_id_param = slot_id;
    spdm_context->local_context.local_key_usage_bit_mask[slot_id] =
        SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE |
        SPDM_KEY_USAGE_BIT_MASK_CHALLENGE_USE;

    libspdm_get_random_number(SPDM_NONCE_SIZE,
                              m_libspdm_get_measurements_request17.nonce);
    m_libspdm_get_measurements_request17.header.param1 =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
    m_libspdm_get_measurements_request17.header.param2 = 1;

    requester_context = ((uint8_t *)&m_libspdm_get_measurements_request17) +
                        sizeof(m_libspdm_get_measurements_request17);
    libspdm_set_mem(requester_context, SPDM_REQ_CONTEXT_SIZE, 0xAA);
    m_libspdm_get_measurements_request17_size = sizeof(m_libspdm_get_measurements_request17) +
                                                SPDM_REQ_CONTEXT_SIZE;

    response_size = sizeof(response);
    status = libspdm_get_response_measurements(
        spdm_context, m_libspdm_get_measurements_request17_size,
        &m_libspdm_get_measurements_request17, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

libspdm_test_context_t m_libspdm_responder_measurements_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_measurements_test_main(void)
{
    m_libspdm_get_measurements_request11.slot_id_param = SPDM_MAX_SLOT_COUNT - 1;
    m_libspdm_get_measurements_request12.slot_id_param = SPDM_MAX_SLOT_COUNT + 1;

    const struct CMUnitTest spdm_responder_measurements_tests[] = {
        /* Success Case to get measurement number without signature*/
        cmocka_unit_test(libspdm_test_responder_measurements_case1),
        /* Can be populated with new test.*/
        cmocka_unit_test(libspdm_test_responder_measurements_case2),
        /* response_state: SPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(libspdm_test_responder_measurements_case3),
        /* response_state: SPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(libspdm_test_responder_measurements_case4),
        #if LIBSPDM_RESPOND_IF_READY_SUPPORT
        /* response_state: SPDM_RESPONSE_STATE_NOT_READY*/
        cmocka_unit_test(libspdm_test_responder_measurements_case5),
        #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
        /* connection_state Check*/
        cmocka_unit_test(libspdm_test_responder_measurements_case6),
        /* Success Case to get measurement number with signature*/
        cmocka_unit_test(libspdm_test_responder_measurements_case7),
        /* Success Case to get one measurement with signature*/
        cmocka_unit_test(libspdm_test_responder_measurements_case8),
        /* Bad request size to get one measurement with signature*/
        cmocka_unit_test(libspdm_test_responder_measurements_case9),
        /* Success Case to get one measurement without signature*/
        cmocka_unit_test(libspdm_test_responder_measurements_case10),
        /* Success Case to get all measurements with signature*/
        cmocka_unit_test(libspdm_test_responder_measurements_case11),
        /* Success Case to get all measurements without signature*/
        cmocka_unit_test(libspdm_test_responder_measurements_case12),
        /* Can be populated with new test.*/
        cmocka_unit_test(libspdm_test_responder_measurements_case13),
        /* Error Case: sig required, but no nonce and/or SlotID*/
        cmocka_unit_test(libspdm_test_responder_measurements_case14),
        /* Error Case: sig required, but meas_cap = 01b (including nonce and SlotId on request)*/
        cmocka_unit_test(libspdm_test_responder_measurements_case15),
        /* Error Case: sig required, but meas_cap = 01b (not including nonce and SlotId on request)*/
        cmocka_unit_test(libspdm_test_responder_measurements_case16),
        /* Error Case: meas_cap = 00b*/
        cmocka_unit_test(libspdm_test_responder_measurements_case17),
        /* Success Case: SlotId different from default*/
        cmocka_unit_test(libspdm_test_responder_measurements_case18),
        /* Bad SlotId parameter (>= SPDM_MAX_SLOT_COUNT)*/
        cmocka_unit_test(libspdm_test_responder_measurements_case19),
        /* Error Case: request a measurement out of bounds*/
        cmocka_unit_test(libspdm_test_responder_measurements_case21),
        /* Large number of requests before requiring a signature*/
        cmocka_unit_test(libspdm_test_responder_measurements_case22),
        /* Successful response to get a session based measurement with signature*/
        cmocka_unit_test(libspdm_test_responder_measurements_case23),
        /* Buffer verification */
        cmocka_unit_test(libspdm_test_responder_measurements_case24),
        /* Success Case V1.2 to get one measurement without signature*/
        cmocka_unit_test(libspdm_test_responder_measurements_case25),
        /* Successful response V1.2 to get one measurement with signature and without opqaue data*/
        cmocka_unit_test(libspdm_test_responder_measurements_case26),
        /* Successful response V1.2 to get one measurement with signature and with opqaue data*/
        cmocka_unit_test(libspdm_test_responder_measurements_case27),
        /* Success Case to get measurement with signature using slot_id 0xFF */
        cmocka_unit_test(libspdm_test_responder_measurements_case28),
        /* Error Case: Big Endian Signature. Little Endian Verify */
        cmocka_unit_test(libspdm_test_responder_measurements_case29),
        /* Success Case: Big Endian Signature. Big Endian Verify */
        cmocka_unit_test(libspdm_test_responder_measurements_case30),
        /* Success Case: Big Endian Signature. Big or Little Endian Verify */
        cmocka_unit_test(libspdm_test_responder_measurements_case31),
        /* Success Case: Little Endian Signature. Little Endian Verify */
        cmocka_unit_test(libspdm_test_responder_measurements_case32),
        /* Error Case: Little Endian Signature. Big Endian Verify */
        cmocka_unit_test(libspdm_test_responder_measurements_case33),
        /* Success Case: Little Endian Signature. Big or Little Endian Verify */
        cmocka_unit_test(libspdm_test_responder_measurements_case34),
        /* Success Case: V1.3 get a correct context field */
        cmocka_unit_test(libspdm_test_responder_measurements_case35),
        /* The key usage bit mask is not set, failed Case*/
        cmocka_unit_test(libspdm_test_responder_measurements_case36),
    };

    libspdm_setup_test_context(&m_libspdm_responder_measurements_test_context);

    return cmocka_run_group_tests(spdm_responder_measurements_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/
