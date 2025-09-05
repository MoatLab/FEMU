/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP

uint8_t temp_buf[LIBSPDM_RECEIVER_BUFFER_SIZE];

#define CHUNK_GET_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE (44)

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

libspdm_return_t libspdm_device_send_message(void *spdm_context,
                                             size_t request_size, const void *request,
                                             uint64_t timeout)
{
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_device_receive_message(void *spdm_context,
                                                size_t *response_size,
                                                void **response,
                                                uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    static uint8_t *spdm_response;
    size_t spdm_response_size;
    size_t test_message_header_size;
    static bool error_large_response_sent = false;
    static size_t chunk_rsp_buf = 0;
    spdm_chunk_response_response_t* chunk_rsp;

    size_t chunk_rsp_size;

    spdm_test_context = libspdm_get_test_context();

    spdm_error_response_t* error_rsp;
    size_t error_rsp_size;

    test_message_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    spdm_response_size = spdm_test_context->test_buffer_size;

    if (error_large_response_sent == false) {
        error_large_response_sent = true;

        spdm_response = (void *)((uint8_t *)temp_buf + test_message_header_size);
        if (spdm_response_size >
            sizeof(temp_buf) - test_message_header_size - LIBSPDM_TEST_ALIGNMENT) {
            spdm_response_size = sizeof(temp_buf) - test_message_header_size -
                                 LIBSPDM_TEST_ALIGNMENT;
        }
        libspdm_copy_mem((uint8_t *)temp_buf + test_message_header_size,
                         sizeof(temp_buf) - test_message_header_size,
                         spdm_test_context->test_buffer,
                         spdm_response_size);

        error_rsp = (void *)(spdm_response);
        error_rsp_size = sizeof(spdm_error_response_t) + sizeof(uint8_t);

        error_rsp->header.request_response_code = SPDM_ERROR;

        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            error_rsp_size, error_rsp,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }
    chunk_rsp = (void *)(spdm_response);

    chunk_rsp_size = sizeof(spdm_chunk_response_response_t)
                     + sizeof(uint32_t) + sizeof(spdm_algorithms_response_t);

    chunk_rsp_buf += chunk_rsp_size;
    if (chunk_rsp_buf + sizeof(spdm_error_response_t) + sizeof(uint8_t) > spdm_response_size) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    libspdm_transport_test_encode_message(
        spdm_context, NULL, false, false,
        chunk_rsp_size, chunk_rsp,
        response_size, response);

    spdm_response += chunk_rsp_size;

    return LIBSPDM_STATUS_SUCCESS;
}

void libspdm_test_requester_chunk_get_case1(void **State)
{
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->connection_info.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->local_context.capability.data_transfer_size
        = CHUNK_GET_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE;

    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);

    libspdm_negotiate_algorithms(spdm_context);
}

libspdm_test_context_t m_libspdm_requester_chunk_get_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_chunk_get_test_context);

    m_libspdm_requester_chunk_get_test_context.test_buffer = test_buffer;
    m_libspdm_requester_chunk_get_test_context.test_buffer_size =
        test_buffer_size;

    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_chunk_get_case1(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP*/
