/**
 *  Copyright Notice:
 *  Copyright 2023-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint16_t standard_id;
    uint8_t vendor_id_len;
    uint8_t vendor_id[SPDM_MAX_VENDOR_ID_LENGTH];
    uint16_t data_len;
    uint8_t data[16];
} libspdm_vendor_request_test;

typedef struct {
    spdm_message_header_t header;
    uint16_t standard_id;
    uint8_t vendor_id_len;
    uint8_t vendor_id[SPDM_MAX_VENDOR_ID_LENGTH];
    uint16_t data_len;
    uint8_t data[64];
} libspdm_vendor_response_test;
#pragma pack()

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE];

libspdm_return_t libspdm_vendor_get_id_func_err_test(
    void *spdm_context,
    uint16_t *resp_standard_id,
    uint8_t *resp_vendor_id_len,
    void *resp_vendor_id)
{
    *resp_standard_id = 6;
    *resp_vendor_id_len = 2;
    ((uint8_t*)resp_vendor_id)[0] = 0xAA;
    ((uint8_t*)resp_vendor_id)[1] = 0xAA;

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_vendor_response_func_err_test(
    void *spdm_context,
    uint16_t req_standard_id,
    uint8_t req_vendor_id_len,
    const void *req_vendor_id,
    uint16_t req_size,
    const void *req_data,
    uint16_t *resp_size,
    void *resp_data)
{
    libspdm_vendor_response_test test_response;
    /* get pointer to response data payload and populate */
    uint8_t *resp_payload = (uint8_t *)resp_data;
    /* get pointer to response length and populate */
    *resp_size = sizeof(test_response.data);
    /* store length of response */
    libspdm_set_mem(resp_payload, *resp_size, 0xFF);

    if (resp_size == NULL || *resp_size == 0)
        return LIBSPDM_STATUS_INVALID_PARAMETER;

    /* TBD make an error here, like response len 65000, but different this time. */

    printf("Got request 0x%x, sent response 0x%x\n",
           ((const uint8_t*)req_data)[0], ((uint8_t*)resp_data)[0]);

    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t libspdm_requester_vendor_cmds_err_test_send_message(
    void *spdm_context, size_t request_size, const void *request,
    uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1: {
        const uint8_t *ptr = (const uint8_t *)request;

        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         ptr, request_size);
        m_libspdm_local_buffer_size += request_size;
    }
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

/* Acts as the Responder Integration */
static libspdm_return_t libspdm_requester_vendor_cmds_err_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_return_t status = LIBSPDM_STATUS_SUCCESS;

    uint32_t* session_id = NULL;
    bool is_app_message = false;
    size_t transport_message_size = sizeof(libspdm_vendor_request_test);

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1: {
        libspdm_vendor_response_test *spdm_response;
        libspdm_vendor_request_test* spdm_request = NULL;
        status = libspdm_transport_test_decode_message(
            spdm_test_context, &session_id, &is_app_message, true,
            m_libspdm_local_buffer_size, m_libspdm_local_buffer,
            &transport_message_size, (void **)(&spdm_request));
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_vendor_response_test);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VENDOR_DEFINED_RESPONSE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;

        spdm_response->standard_id = spdm_request->standard_id;
        spdm_response->vendor_id_len = spdm_request->vendor_id_len;
        /* usually 2 bytes for vendor id */
        assert_int_equal(spdm_response->vendor_id_len, sizeof(uint16_t));
        libspdm_copy_mem(spdm_response->vendor_id, spdm_request->vendor_id_len,
                         spdm_request->vendor_id, spdm_request->vendor_id_len);

        if (spdm_response->data_len < sizeof(spdm_response->data))
            return LIBSPDM_STATUS_INVALID_PARAMETER;

        spdm_response->data_len = sizeof(spdm_response->data);
        libspdm_set_mem(spdm_response->data, sizeof(spdm_response->data), 0xff);

        status = libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                                       false, spdm_response_size,
                                                       spdm_response,
                                                       response_size, response);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    }
        return LIBSPDM_STATUS_SUCCESS;

    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

/**
 * Test 1: Sending a vendor defined request
 * Expected behavior: client returns a status of LIBSPDM_STATUS_INVALID_PARAMETER
 * due to invalid length of data field in the response
 **/
static void libspdm_test_requester_vendor_cmds_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_vendor_request_test request;
    libspdm_vendor_response_test response = {0};
    response.vendor_id_len = sizeof(response.vendor_id);
    response.data_len = sizeof(response.data);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.is_requester = true;

    status = libspdm_register_vendor_get_id_callback_func(spdm_context,
                                                          libspdm_vendor_get_id_func_err_test);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    status = libspdm_register_vendor_callback_func(spdm_context,
                                                   libspdm_vendor_response_func_err_test);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    request.standard_id = 6;
    request.vendor_id_len = 2;
    request.vendor_id[0] = 0xAA;
    request.vendor_id[1] = 0xAA;
    request.data_len = sizeof(request.data);
    libspdm_set_mem(request.data, sizeof(request.data), 0xAA);

    response.data_len = 0; /* will generate error */

    status = libspdm_vendor_send_request_receive_response(spdm_context, NULL,
                                                          request.standard_id,
                                                          request.vendor_id_len,
                                                          request.vendor_id, request.data_len,
                                                          request.data,
                                                          &response.standard_id,
                                                          &response.vendor_id_len,
                                                          response.vendor_id, &response.data_len,
                                                          response.data);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
    assert_int_equal(
        spdm_context->connection_info.version >> SPDM_VERSION_NUMBER_SHIFT_BIT,
        SPDM_MESSAGE_VERSION_10);

    printf("case 1 %d\n", response.data[0]);
}

libspdm_test_context_t m_libspdm_requester_vendor_cmds_err_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_vendor_cmds_err_test_send_message,
    libspdm_requester_vendor_cmds_err_test_receive_message,
};

int libspdm_requester_vendor_cmds_error_test_main(void)
{
    const struct CMUnitTest spdm_requester_vendor_cmds_tests[] = {
        cmocka_unit_test(libspdm_test_requester_vendor_cmds_err_case1),
    };

    libspdm_setup_test_context(&m_libspdm_requester_vendor_cmds_err_test_context);

    return cmocka_run_group_tests(spdm_requester_vendor_cmds_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}


#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */
