/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint8_t reserved;
    uint8_t version_number_entry_count;
    spdm_version_number_t version_number_entry[LIBSPDM_MAX_VERSION_COUNT];
} libspdm_version_response_mine_t;
#pragma pack()

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE];

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request,
    uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_SEND_FAIL;
    case 0x2:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x3:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x4:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x5:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x6:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x7:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x8:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x9:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xA:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xB:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xC:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xD:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xE:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xF:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x10: {
        const uint8_t *ptr = (const uint8_t *)request;

        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         &ptr[1], request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x11:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x12:
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x2:
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: {
        spdm_version_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_version_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x4: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x5: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x6: {
        static size_t sub_index1 = 0;
        if (sub_index1 == 0) {
            spdm_error_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;

            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            libspdm_zero_mem(spdm_response, spdm_response_size);
            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response->header.param2 = 0;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
        } else if (sub_index1 == 1) {
            libspdm_version_response_mine_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;

            spdm_response_size = sizeof(libspdm_version_response_mine_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            libspdm_zero_mem(spdm_response, spdm_response_size);
            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code =
                SPDM_VERSION;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            spdm_response->version_number_entry_count = 2;
            spdm_response->version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
            spdm_response->version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
        }
        sub_index1++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x7: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x8: {
        spdm_error_response_data_response_not_ready_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 =
            SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response->header.param2 = 0;
        spdm_response->extend_error_data.rd_exponent = 1;
        spdm_response->extend_error_data.rd_tm = 2;
        spdm_response->extend_error_data.request_code = SPDM_GET_VERSION;
        spdm_response->extend_error_data.token = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x9: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 255;
        spdm_response->version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[2] = 0x12 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xA:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0xB: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 2;
        spdm_response->version_number_entry[0] = 0xA0 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0xA1 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xC: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 2;
        spdm_response->version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xD: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_GET_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 2;
        spdm_response->version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xE:
    {
        static uint16_t error_code = LIBSPDM_ERROR_CODE_RESERVED_00;

        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        if(error_code <= 0xff) {
            libspdm_zero_mem (spdm_response, spdm_response_size);
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = (uint8_t) error_code;

            libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                                   spdm_response_size, spdm_response,
                                                   response_size, response);
        }

        error_code++;
        if(error_code == SPDM_ERROR_CODE_BUSY) { /*busy is treated in cases 5 and 6*/
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) { /*skip some reserved error codes (0d to 3e)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xF: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 5;
        spdm_response->version_number_entry[0] = 0x42 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0x52 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[2] = 0x12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[3] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[4] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x10: {
        libspdm_version_response_mine_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_version_response_mine_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = 2;
        spdm_response->version_number_entry[0] = 0x10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        spdm_response->version_number_entry[1] = 0x11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

        spdm_response_size = 10;

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) - m_libspdm_local_buffer_size,
                         (uint8_t *)spdm_response, spdm_response_size);
        m_libspdm_local_buffer_size += spdm_response_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x11: {
        spdm_message_header_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_message_header_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->request_response_code = SPDM_VERSION;
        spdm_response->param1 = 0;
        spdm_response->param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);

    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x12: {
        spdm_version_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_version_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_VERSION;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->version_number_entry_count = LIBSPDM_MAX_VERSION_COUNT;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);

    }
        return LIBSPDM_STATUS_SUCCESS;

    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

/**
 * Test 1: Unable to send the GET_VERSION request.
 * Expected behavior: returns a status of LIBSPDM_STATUS_SEND_FAIL.
 **/
static void libspdm_test_requester_get_version_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
}

/**
 * Test 2: Requester is unable to acquire the sender buffer.
 * Expected behavior: returns with status LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void libspdm_test_requester_get_version_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    libspdm_force_error (LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);
    status = libspdm_get_version(spdm_context, NULL, NULL);
    libspdm_release_error (LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 3: receiving a correct VERSION message header, but with 0 versions available.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_version_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 4: receiving an InvalidRequest ERROR message from the responder.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_ERROR_PEER.
 **/
static void libspdm_test_requester_get_version_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
}

/**
 * Test 5: receiving a Busy ERROR message correct VERSION message from the responder.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_BUSY_PEER.
 **/
static void libspdm_test_requester_get_version_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);
}

/**
 * Test 6: Requester is unable to acquire the receiver buffer.
 * Expected behavior: returns with status LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void libspdm_test_requester_get_version_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    libspdm_force_error (LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);
    status = libspdm_get_version(spdm_context, NULL, NULL);
    libspdm_release_error (LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 7: receiving a RequestResynch ERROR message from the responder.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_RESYNCH_PEER, and the
 * internal state should be reset.
 **/
static void libspdm_test_requester_get_version_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
}

/**
 * Test 8: receiving a ResponseNotReady ERROR message from the responder,
 * but Responder shall not respond to the GET_VERSION request message with ErrorCode=ResponseNotReady.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_ERROR_PEER,
 * Received an unexpected error message.
 **/
static void libspdm_test_requester_get_version_err_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
}

/**
 * Test 9: Number of version entries are larger than what the Requester can tolerate.
 * Expected behavior: returns a status of LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_version_err_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    LIBSPDM_ASSERT(LIBSPDM_MAX_VERSION_COUNT != 255);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 10: Requester is unable to receive a VERSION response from the Responder.
 * Expected behavior: returns a status of LIBSPDM_STATUS_RECEIVE_FAIL.
 **/
static void libspdm_test_requester_get_version_err_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xa;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 11: receiving a correct VERSION message with available version 1.0 and 1.1, but
 * the requester do not have compatible versions with the responder.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_NEGOTIATION_FAIL.
 **/
static void libspdm_test_requester_get_version_err_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_NEGOTIATION_FAIL);
}

/**
 * Test 12: receiving a VERSION message in SPDM version 1.1 (in the header), but correct
 * 1.0-version format, with available version 1.0 and 1.1.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_version_err_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 13: receiving a VERSION message with wrong SPDM request_response_code (in this
 * case, GET_VERSION 0x84 instead of VERSION 0x04). The remaining data is a correct
 * VERSION message, with available version 1.0 and 1.1.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_version_err_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 14: receiving an unexpected ERROR message from the responder.
 * There are tests for all named codes, including some reserved ones
 * (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
 * However, for having specific test cases, it is excluded from this case:
 * Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
 * Expected behavior: client returns a status of LIBSPDM_STATUS_ERROR_PEER.
 **/
static void libspdm_test_requester_get_version_err_case14(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint16_t error_code;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;

    error_code = LIBSPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        /* no additional state control is necessary as a new GET_VERSION resets the state*/
        status = libspdm_get_version (spdm_context, NULL, NULL);
        LIBSPDM_ASSERT_INT_EQUAL_CASE (status, LIBSPDM_STATUS_ERROR_PEER, error_code);

        error_code++;
        if(error_code == SPDM_ERROR_CODE_BUSY) { /*busy is treated in cases 5 and 6*/
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) { /*skip some reserved error codes (0d to 3e)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }
}

/*
 * static void libspdm_test_requester_get_version_err_case15(void **state)
 * {
 * }
 */

/*
 * static void libspdm_test_requester_get_version_err_case16(void **state)
 * {
 * }
 */

/**
 * Test 17: when no VERSION message is received, and the client returns a device error.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_version_err_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 18: when no VERSION message is received, and the client returns a device error.
 * Expected behavior: client returns a status of LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_version_err_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;

    status = libspdm_get_version(spdm_context, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

static libspdm_test_context_t m_libspdm_requester_get_version_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    send_message,
    receive_message,
};

int libspdm_requester_get_version_error_test_main(void)
{
    const struct CMUnitTest spdm_requester_get_version_tests[] = {
        cmocka_unit_test(libspdm_test_requester_get_version_err_case1),
        cmocka_unit_test(libspdm_test_requester_get_version_err_case2),
        cmocka_unit_test(libspdm_test_requester_get_version_err_case3),
        cmocka_unit_test(libspdm_test_requester_get_version_err_case4),
        cmocka_unit_test(libspdm_test_requester_get_version_err_case5),
        cmocka_unit_test(libspdm_test_requester_get_version_err_case6),
        cmocka_unit_test(libspdm_test_requester_get_version_err_case7),
        cmocka_unit_test(libspdm_test_requester_get_version_err_case8),
        cmocka_unit_test(libspdm_test_requester_get_version_err_case9),
        cmocka_unit_test(libspdm_test_requester_get_version_err_case10),
        cmocka_unit_test(libspdm_test_requester_get_version_err_case11),
        cmocka_unit_test(libspdm_test_requester_get_version_err_case12),
        cmocka_unit_test(libspdm_test_requester_get_version_err_case13),
        cmocka_unit_test(libspdm_test_requester_get_version_err_case14),
        /* cmocka_unit_test(libspdm_test_requester_get_version_err_case15),
         * cmocka_unit_test(libspdm_test_requester_get_version_err_case16), */
        cmocka_unit_test(libspdm_test_requester_get_version_err_case17),
        cmocka_unit_test(libspdm_test_requester_get_version_err_case18),
    };

    libspdm_setup_test_context(&m_libspdm_requester_get_version_test_context);

    return cmocka_run_group_tests(spdm_requester_get_version_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
