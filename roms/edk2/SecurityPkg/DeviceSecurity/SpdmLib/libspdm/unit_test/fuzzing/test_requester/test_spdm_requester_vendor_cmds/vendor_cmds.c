/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES

typedef struct {
    spdm_message_header_t header;
    uint16_t standard_id;
    uint8_t vendor_id_len;
    uint8_t vendor_id[SPDM_MAX_VENDOR_ID_LENGTH];
    uint16_t data_len;
    uint8_t data[SPDM_MAX_VENDOR_DEFINED_DATA_LEN];
} libspdm_vendor_request_test;

typedef struct {
    spdm_message_header_t header;
    uint16_t standard_id;
    uint8_t vendor_id_len;
    uint8_t vendor_id[SPDM_MAX_VENDOR_ID_LENGTH];
    uint16_t data_len;
    uint8_t data[SPDM_MAX_VENDOR_DEFINED_DATA_LEN];
} libspdm_vendor_response_test;
#pragma pack()


uint8_t temp_buf[LIBSPDM_RECEIVER_BUFFER_SIZE];

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
    uint8_t *spdm_response;
    size_t spdm_response_size;
    size_t test_message_header_size;

    spdm_test_context = libspdm_get_test_context();

    test_message_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    spdm_response = (void *)((uint8_t *)temp_buf + test_message_header_size);
    spdm_response_size = spdm_test_context->test_buffer_size;
    if (spdm_response_size > sizeof(temp_buf) - test_message_header_size - LIBSPDM_TEST_ALIGNMENT) {
        spdm_response_size = sizeof(temp_buf) - test_message_header_size - LIBSPDM_TEST_ALIGNMENT;
    }
    libspdm_copy_mem((uint8_t *)temp_buf + test_message_header_size,
                     sizeof(temp_buf) - test_message_header_size,
                     spdm_test_context->test_buffer,
                     spdm_response_size);

    libspdm_transport_test_encode_message(spdm_context, NULL,
                                          false, false, spdm_response_size,
                                          spdm_response, response_size, response);

    return LIBSPDM_STATUS_SUCCESS;
}



static void libspdm_test_requester_vendor_cmds_case1(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_vendor_request_test request = {0};
    libspdm_vendor_response_test response = {0};

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.is_requester = true;

    response.vendor_id_len = SPDM_MAX_VENDOR_ID_LENGTH;
    response.data_len = SPDM_MAX_VENDOR_DEFINED_DATA_LEN;

    request.standard_id = 0x01;
    request.vendor_id_len = 1;
    libspdm_set_mem(request.vendor_id, request.vendor_id_len, 0xAA);
    request.data_len = 1;
    libspdm_set_mem(request.data, request.data_len, 0xAA);

    libspdm_vendor_send_request_receive_response(spdm_context, NULL,
                                                 request.standard_id,
                                                 request.vendor_id_len,
                                                 request.vendor_id, request.data_len,
                                                 request.data,
                                                 &response.standard_id,
                                                 &response.vendor_id_len,
                                                 response.vendor_id, &response.data_len,
                                                 response.data);
}


libspdm_test_context_t m_libspdm_requester_event_types_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_event_types_test_context);

    m_libspdm_requester_event_types_test_context.test_buffer = test_buffer;
    m_libspdm_requester_event_types_test_context.test_buffer_size =
        test_buffer_size;

    /* Successful response*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_vendor_cmds_case1(&State);
    libspdm_unit_test_group_teardown(&State);

}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /*LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES*/
