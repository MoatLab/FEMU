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
    uint16_t length;
    uint8_t measurement_specification_sel;
    uint8_t other_params_selection;
    uint32_t measurement_hash_algo;
    uint32_t base_asym_sel;
    uint32_t base_hash_sel;
    uint8_t reserved2[11];
    uint8_t mel_specification_sel;
    uint8_t ext_asym_sel_count;
    uint8_t ext_hash_sel_count;
    uint16_t reserved3;
    spdm_negotiate_algorithms_common_struct_table_t struct_table[4];
} libspdm_algorithms_response_spdm11_t;
#pragma pack()

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_VCA_BUFFER_SIZE];

static uint8_t m_connection_other_params_support;

static uint8_t m_mel_specification_sel;

static uint8_t m_measurement_specification_sel;

static libspdm_return_t libspdm_requester_negotiate_algorithms_test_send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
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
    case 0x10:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x11:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x12:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x13:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x14:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x15:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x16:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x17:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x18:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x19:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1A:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1B:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1C:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1D:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1E:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1F:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x20: {
        const uint8_t *ptr = (const uint8_t *)request;

        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         &ptr[1], request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x21: {
        const spdm_negotiate_algorithms_request_t *spdm_request;
        spdm_request =
            (const spdm_negotiate_algorithms_request_t *)((const uint8_t *)request +
                                                          sizeof(libspdm_test_message_header_t));

        assert_int_equal (spdm_request->header.spdm_version, SPDM_MESSAGE_VERSION_12);
        assert_int_equal (spdm_request->header.request_response_code, SPDM_NEGOTIATE_ALGORITHMS);
        assert_int_equal (spdm_request->other_params_support, SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x22:
    case 0x23:
    case 0x24:
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

static libspdm_return_t libspdm_requester_negotiate_algorithm_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x2: {
        spdm_algorithms_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_algorithms_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
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

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: {
        spdm_algorithms_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_algorithms_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(spdm_algorithms_response_t);
        spdm_response->measurement_specification_sel =
            m_measurement_specification_sel;
        spdm_response->measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;

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
            spdm_algorithms_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;

            spdm_response_size = sizeof(spdm_algorithms_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            libspdm_zero_mem(spdm_response, spdm_response_size);
            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code =
                SPDM_ALGORITHMS;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            spdm_response->length =
                sizeof(spdm_algorithms_response_t);
            spdm_response->measurement_specification_sel =
                SPDM_MEASUREMENT_SPECIFICATION_DMTF;
            spdm_response->measurement_hash_algo =
                m_libspdm_use_measurement_hash_algo;
            spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
            spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
            spdm_response->ext_asym_sel_count = 0;
            spdm_response->ext_hash_sel_count = 0;

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
        spdm_response->extend_error_data.request_code =
            SPDM_NEGOTIATE_ALGORITHMS;
        spdm_response->extend_error_data.token = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x9:
        return LIBSPDM_STATUS_SUCCESS;

    case 0xA: {
        spdm_algorithms_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_algorithms_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(spdm_algorithms_response_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = 0;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xB: {
        spdm_algorithms_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_algorithms_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(spdm_algorithms_response_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = 0;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xC: {
        spdm_algorithms_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_algorithms_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(spdm_algorithms_response_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = 0;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xD:
    {
        spdm_algorithms_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_algorithms_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(spdm_algorithms_response_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_message_header_t), spdm_response,
                                               response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xE:
    {
        spdm_algorithms_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_algorithms_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(spdm_algorithms_response_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;


        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               sizeof(spdm_algorithms_response_t)/2, spdm_response,
                                               response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xF:
    {
        spdm_algorithms_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_algorithms_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(spdm_algorithms_response_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 2;
        spdm_response->ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x10:
    {
        spdm_algorithms_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_algorithms_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(spdm_algorithms_response_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 2;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x11:
    {
        spdm_algorithms_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_algorithms_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(spdm_algorithms_response_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x12:
    {
        spdm_algorithms_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_algorithms_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(spdm_algorithms_response_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x13:
    {
        spdm_algorithms_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_algorithms_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(spdm_algorithms_response_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo|
                                               SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x14:
    {
        spdm_algorithms_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_algorithms_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(spdm_algorithms_response_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo|
                                       SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x15:
    {
        spdm_algorithms_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_algorithms_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(spdm_algorithms_response_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo|
                                       SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x16:
    {
        libspdm_algorithms_response_spdm11_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_algorithms_response_spdm11_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 4;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;
        spdm_response->struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response->struct_table[0].alg_count = 0x20;
        spdm_response->struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response->struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response->struct_table[1].alg_count = 0x20;
        spdm_response->struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response->struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response->struct_table[2].alg_count = 0x20;
        spdm_response->struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response->struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response->struct_table[3].alg_count = 0x20;
        spdm_response->struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x17:
    {
        libspdm_algorithms_response_spdm11_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_algorithms_response_spdm11_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 4;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;
        spdm_response->struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response->struct_table[0].alg_count = 0x20;
        spdm_response->struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response->struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response->struct_table[1].alg_count = 0x20;
        spdm_response->struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response->struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response->struct_table[2].alg_count = 0x20;
        spdm_response->struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response->struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response->struct_table[3].alg_count = 0x20;
        spdm_response->struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x18:
    {
        libspdm_algorithms_response_spdm11_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_algorithms_response_spdm11_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 4;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;
        spdm_response->struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response->struct_table[0].alg_count = 0x20;
        spdm_response->struct_table[0].alg_supported = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1;
        spdm_response->struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response->struct_table[1].alg_count = 0x20;
        spdm_response->struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response->struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response->struct_table[2].alg_count = 0x20;
        spdm_response->struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response->struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response->struct_table[3].alg_count = 0x20;
        spdm_response->struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x19:
    {
        libspdm_algorithms_response_spdm11_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_algorithms_response_spdm11_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 4;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;
        spdm_response->struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response->struct_table[0].alg_count = 0x20;
        spdm_response->struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response->struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response->struct_table[1].alg_count = 0x20;
        spdm_response->struct_table[1].alg_supported =
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305;
        spdm_response->struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response->struct_table[2].alg_count = 0x20;
        spdm_response->struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response->struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response->struct_table[3].alg_count = 0x20;
        spdm_response->struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1A:
    {
        libspdm_algorithms_response_spdm11_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_algorithms_response_spdm11_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 4;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;
        spdm_response->struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response->struct_table[0].alg_count = 0x20;
        spdm_response->struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response->struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response->struct_table[1].alg_count = 0x20;
        spdm_response->struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response->struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response->struct_table[2].alg_count = 0x20;
        spdm_response->struct_table[2].alg_supported =
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
        spdm_response->struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response->struct_table[3].alg_count = 0x20;
        spdm_response->struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1B:
    {
        libspdm_algorithms_response_spdm11_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_algorithms_response_spdm11_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 4;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;
        spdm_response->struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response->struct_table[0].alg_count = 0x20;
        spdm_response->struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response->struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response->struct_table[1].alg_count = 0x20;
        spdm_response->struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response->struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response->struct_table[2].alg_count = 0x20;
        spdm_response->struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response->struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response->struct_table[3].alg_count = 0x20;
        spdm_response->struct_table[3].alg_supported = 0x00000020;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1C:
    {
        libspdm_algorithms_response_spdm11_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_algorithms_response_spdm11_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 4;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;
        spdm_response->struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response->struct_table[0].alg_count = 0x20;
        spdm_response->struct_table[0].alg_supported = m_libspdm_use_dhe_algo |
                                                       SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1;
        spdm_response->struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response->struct_table[1].alg_count = 0x20;
        spdm_response->struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response->struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response->struct_table[2].alg_count = 0x20;
        spdm_response->struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response->struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response->struct_table[3].alg_count = 0x20;
        spdm_response->struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1D:
    {
        libspdm_algorithms_response_spdm11_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_algorithms_response_spdm11_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 4;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;
        spdm_response->struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response->struct_table[0].alg_count = 0x20;
        spdm_response->struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response->struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response->struct_table[1].alg_count = 0x20;
        spdm_response->struct_table[1].alg_supported = m_libspdm_use_aead_algo |
                                                       SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305;
        spdm_response->struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response->struct_table[2].alg_count = 0x20;
        spdm_response->struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response->struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response->struct_table[3].alg_count = 0x20;
        spdm_response->struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1E:
    {
        libspdm_algorithms_response_spdm11_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_algorithms_response_spdm11_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 4;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;
        spdm_response->struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response->struct_table[0].alg_count = 0x20;
        spdm_response->struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response->struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response->struct_table[1].alg_count = 0x20;
        spdm_response->struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response->struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response->struct_table[2].alg_count = 0x20;
        spdm_response->struct_table[2].alg_supported = m_libspdm_use_req_asym_algo |
                                                       SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
        spdm_response->struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response->struct_table[3].alg_count = 0x20;
        spdm_response->struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1F:
    {
        libspdm_algorithms_response_spdm11_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_algorithms_response_spdm11_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 4;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;
        spdm_response->struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response->struct_table[0].alg_count = 0x20;
        spdm_response->struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response->struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response->struct_table[1].alg_count = 0x20;
        spdm_response->struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response->struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response->struct_table[2].alg_count = 0x20;
        spdm_response->struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response->struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response->struct_table[3].alg_count = 0x20;
        spdm_response->struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo | 0x00000020;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x20:
    {
        libspdm_algorithms_response_spdm11_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_algorithms_response_spdm11_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 4;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;
        spdm_response->struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response->struct_table[0].alg_count = 0x20;
        spdm_response->struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response->struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response->struct_table[1].alg_count = 0x20;
        spdm_response->struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response->struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response->struct_table[2].alg_count = 0x20;
        spdm_response->struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response->struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response->struct_table[3].alg_count = 0x20;
        spdm_response->struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) - m_libspdm_local_buffer_size,
                         (uint8_t *)spdm_response, spdm_response_size);
        m_libspdm_local_buffer_size += spdm_response_size;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x21:
    {
        libspdm_algorithms_response_spdm11_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_algorithms_response_spdm11_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 4;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->other_params_selection = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;
        spdm_response->struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response->struct_table[0].alg_count = 0x20;
        spdm_response->struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response->struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response->struct_table[1].alg_count = 0x20;
        spdm_response->struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response->struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response->struct_table[2].alg_count = 0x20;
        spdm_response->struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response->struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response->struct_table[3].alg_count = 0x20;
        spdm_response->struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x22:
    {
        libspdm_algorithms_response_spdm11_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_algorithms_response_spdm11_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 4;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->other_params_selection = 0;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;
        spdm_response->struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response->struct_table[0].alg_count = 0x20;
        spdm_response->struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response->struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response->struct_table[1].alg_count = 0x20;
        spdm_response->struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response->struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response->struct_table[2].alg_count = 0x20;
        spdm_response->struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response->struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response->struct_table[3].alg_count = 0x20;
        spdm_response->struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x23:
    {
        spdm_algorithms_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_algorithms_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
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
        spdm_response->other_params_selection = m_connection_other_params_support;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x24:
    {
        libspdm_algorithms_response_spdm11_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(libspdm_algorithms_response_spdm11_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ALGORITHMS;
        spdm_response->header.param1 = 4;
        spdm_response->header.param2 = 0;
        spdm_response->length = sizeof(libspdm_algorithms_response_spdm11_t);
        spdm_response->measurement_specification_sel =
            SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        spdm_response->measurement_hash_algo = m_libspdm_use_measurement_hash_algo;
        spdm_response->base_asym_sel = m_libspdm_use_asym_algo;
        spdm_response->base_hash_sel = m_libspdm_use_hash_algo;
        spdm_response->ext_asym_sel_count = 0;
        spdm_response->ext_hash_sel_count = 0;
        spdm_response->mel_specification_sel = m_mel_specification_sel;
        spdm_response->other_params_selection = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;

        spdm_response->struct_table[0].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
        spdm_response->struct_table[0].alg_count = 0x20;
        spdm_response->struct_table[0].alg_supported = m_libspdm_use_dhe_algo;
        spdm_response->struct_table[1].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
        spdm_response->struct_table[1].alg_count = 0x20;
        spdm_response->struct_table[1].alg_supported = m_libspdm_use_aead_algo;
        spdm_response->struct_table[2].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
        spdm_response->struct_table[2].alg_count = 0x20;
        spdm_response->struct_table[2].alg_supported = m_libspdm_use_req_asym_algo;
        spdm_response->struct_table[3].alg_type =
            SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
        spdm_response->struct_table[3].alg_count = 0x20;
        spdm_response->struct_table[3].alg_supported = m_libspdm_use_key_schedule_algo;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                               spdm_response_size,
                                               spdm_response, response_size, response);

    }
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

static void libspdm_test_requester_negotiate_algorithms_case1(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_a.buffer_size,
                     sizeof(spdm_negotiate_algorithms_request_t) +
                     sizeof(spdm_algorithms_response_t));
#endif
}

/**
 * Case 3:
 * +---------------+--------------------------+--------------------------+-----------------------------------+
 * | MEAS_CAP | MeasurementSpecification   | MeasurementSpecificationSel |          Expected result          |
 * |          | NEGOTIATE_ALGORITHMS       |       ALGORITHMS            |                                   |
 * +----------+----------------------------+-----------------------------+-----------------------------------+
 * | set      | DMTFmeasSpec               | DMTFmeasSpec                | LIBSPDM_STATUS_SUCCESS            |
 *  ---------------------------------------------------------------------------------------------------------+
 * | set      | DMTFmeasSpec               | 0                           | LIBSPDM_STATUS_INVALID_MSG_FIELD  |
 *  ----------------------------------------------------------------------------------------------------------
 * | set      | 0                          | DMTFmeasSpec                | LIBSPDM_STATUS_INVALID_MSG_FIELD  |
 *  ---------------------------------------------------------------------------------------------------------+
 * | set      | 0                          | 0                           | LIBSPDM_STATUS_SUCCESS            |
 *  ----------------------------------------------------------------------------------------------------------
 * | Not set  | DMTFmeasSpec               | DMTFmeasSpec                | LIBSPDM_STATUS_INVALID_MSG_FIELD  |
 *  ---------------------------------------------------------------------------------------------------------+
 * | Not set  | DMTFmeasSpec               | 0                           | LIBSPDM_STATUS_SUCCESS            |
 *  ----------------------------------------------------------------------------------------------------------
 * | Not set  | 0                          | DMTFmeasSpec                | LIBSPDM_STATUS_INVALID_MSG_FIELD  |
 *  ---------------------------------------------------------------------------------------------------------+
 * | Not set  | 0                          | 0                           | LIBSPDM_STATUS_SUCCESS            |
 *  ----------------------------------------------------------------------------------------------------------
 **/
static void libspdm_test_requester_negotiate_algorithms_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.capability.flags = 0;

    /* Sub Case 1: MEAS_CAP set 1, measurement_spec_sel and measurement_spec set SPDM_MEASUREMENT_SPECIFICATION_DMTF*/
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    libspdm_reset_message_a(spdm_context);
    m_measurement_specification_sel = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* Sub Case 2: MEAS_CAP set 1, measurement_spec_sel set 0 , measurement_spec set SPDM_MEASUREMENT_SPECIFICATION_DMTF*/
    libspdm_reset_message_a(spdm_context);
    m_measurement_specification_sel = 0;
    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    /* Sub Case 3: MEAS_CAP set 1, measurement_spec_sel set SPDM_MEASUREMENT_SPECIFICATION_DMTF , measurement_spec set 0*/
    libspdm_reset_message_a(spdm_context);
    m_measurement_specification_sel = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.algorithm.measurement_spec = 0;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    /* Sub Case 4: MEAS_CAP set 1,measurement_spec_sel set 0 , measurement_spec set 0*/
    libspdm_reset_message_a(spdm_context);
    m_measurement_specification_sel = 0;
    spdm_context->local_context.algorithm.measurement_spec = 0;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* Sub Case 5:MEAS_CAP set 0, measurement_spec_sel and measurement_spec set SPDM_MEASUREMENT_SPECIFICATION_DMTF*/
    spdm_context->connection_info.capability.flags = 0;
    libspdm_reset_message_a(spdm_context);
    m_measurement_specification_sel = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    /* Sub Case 6: MEAS_CAP set 0, measurement_spec_sel set 0 , measurement_spec set SPDM_MEASUREMENT_SPECIFICATION_DMTF*/
    libspdm_reset_message_a(spdm_context);
    m_measurement_specification_sel = 0;
    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* Sub Case 7: MEAS_CAP set 0,measurement_spec_sel set SPDM_MEASUREMENT_SPECIFICATION_DMTF , measurement_spec set 0*/
    libspdm_reset_message_a(spdm_context);
    m_measurement_specification_sel = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.algorithm.measurement_spec = 0;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    /* Sub Case 8: MEAS_CAP set 0,measurement_spec_sel set 0 , measurement_spec set 0*/
    libspdm_reset_message_a(spdm_context);
    m_measurement_specification_sel = 0;
    spdm_context->local_context.algorithm.measurement_spec = 0;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

static void libspdm_test_requester_negotiate_algorithms_case4(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case5(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->retry_times = 3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_a.buffer_size,
                     sizeof(spdm_negotiate_algorithms_request_t) +
                     sizeof(spdm_algorithms_response_t));
#endif
}

static void libspdm_test_requester_negotiate_algorithms_case7(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case8(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case9(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case10(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case11(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case12(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case13(void **state)
{

}

static void libspdm_test_requester_negotiate_algorithms_case14(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case15(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case16(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case17(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case18(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case19(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case20(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case21(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case22(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case23(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;

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

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal (spdm_context->transcript.message_a.buffer_size,
                      sizeof(spdm_negotiate_algorithms_request_t) + 4*
                      sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                      sizeof(libspdm_algorithms_response_spdm11_t));
#endif
}

static void libspdm_test_requester_negotiate_algorithms_case24(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case25(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case26(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case27(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case28(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case29(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case30(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case31(void **state)
{
}

static void libspdm_test_requester_negotiate_algorithms_case32(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t arbitrary_size;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x20;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /*filling A with arbitrary data*/
    arbitrary_size = 10;
    libspdm_set_mem(spdm_context->transcript.message_a.buffer, arbitrary_size, (uint8_t) 0xFF);
    spdm_context->transcript.message_a.buffer_size = arbitrary_size;
#endif

    status = libspdm_negotiate_algorithms (spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal (spdm_context->transcript.message_a.buffer_size,
                      arbitrary_size + m_libspdm_local_buffer_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer (0x%x):\n",
                   m_libspdm_local_buffer_size));
    libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
    assert_memory_equal(spdm_context->transcript.message_a.buffer + arbitrary_size,
                        m_libspdm_local_buffer, m_libspdm_local_buffer_size);
#endif
}

static void libspdm_test_requester_negotiate_algorithms_case33(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x21;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
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
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;

    /* Sub Case 1: other_params_support set OpaqueDataFmt1 */
    spdm_context->local_context.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.algorithm.other_params_support,
                     SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1);

    /* Sub Case 2: Populate reserved field for version 1.2, field values marked as Reserved shall be written as zero ( 0 )*/
    spdm_context->local_context.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1 |
        SPDM_ALGORITHMS_MULTI_KEY_CONN;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.algorithm.other_params_support,
                     SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal (spdm_context->transcript.message_a.buffer_size,
                      sizeof(spdm_negotiate_algorithms_request_t) + 4*
                      sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                      sizeof(libspdm_algorithms_response_spdm11_t));
#endif
}


static void libspdm_test_requester_negotiate_algorithms_case34(void **state)
{
}

/**
 * Test 35: MULTI_KEY_CONN_REQ and MULTI_KEY_CONN_RSP value calculation
 * +---------------+--------------------------+--------------------+
 * | MULTI_KEY_CAP | RequesterMultiKeyConnSel | MULTI_KEY_CONN_REQ |
 * +---------------+--------------------------+--------------------+
 * | 00b           | 0                        | false              |
 *  ----------------------------------------------------------------
 * | 00b           | 1                        | invalid            |
 *  ----------------------------------------------------------------
 * | 01b           | 0                        | invalid            |
 *  ----------------------------------------------------------------
 * | 01b           | 1                        | true               |
 *  ----------------------------------------------------------------
 * | 10b           | 0                        | false              |
 *  ----------------------------------------------------------------
 * | 10b           | 1                        | true               |
 * +---------------+--------------------------+--------------------+
 * | MULTI_KEY_CAP | ResponderMultiKeyConn    | MULTI_KEY_CONN_RSP |
 * +---------------+--------------------------+--------------------+
 * | 00b           | 0                        | false              |
 *  ----------------------------------------------------------------
 * | 00b           | 1                        | invalid            |
 *  ----------------------------------------------------------------
 * | 01b           | 0                        | invalid            |
 *  ----------------------------------------------------------------
 * | 01b           | 1                        | true               |
 *  ----------------------------------------------------------------
 * | 10b           | 0                        | false              |
 *  ----------------------------------------------------------------
 * | 10b           | 1                        | true               |
 *  ----------------------------------------------------------------
 **/
static void libspdm_test_requester_negotiate_algorithms_case35(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x23;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    libspdm_reset_message_a(spdm_context);

    spdm_context->connection_info.capability.flags = 0;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.algorithm.other_params_support = 0;
    m_connection_other_params_support = 0;

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_rsp, false);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_req, false);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    spdm_context->connection_info.capability.flags = 0;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.algorithm.other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;
    m_connection_other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;

    status = libspdm_negotiate_algorithms(spdm_context);
    /* MULTI_KEY_CONN_REQ and MULTI_KEY_CONN_RSP invalid */
    assert_int_equal(status, LIBSPDM_STATUS_NEGOTIATION_FAIL);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_ONLY;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.algorithm.other_params_support = 0;
    m_connection_other_params_support = 0;

    status = libspdm_negotiate_algorithms(spdm_context);
    /* MULTI_KEY_CONN_REQ and MULTI_KEY_CONN_RSP invalid */
    assert_int_equal(status, LIBSPDM_STATUS_NEGOTIATION_FAIL);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_ONLY;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.algorithm.other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;
    m_connection_other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_rsp, true);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_req, true);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_NEG;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_NEG;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.algorithm.other_params_support = 0;
    m_connection_other_params_support = 0;

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_rsp, false);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_req, false);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    libspdm_reset_message_a(spdm_context);

    spdm_context->connection_info.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_NEG;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_NEG;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
    spdm_context->local_context.algorithm.other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;
    m_connection_other_params_support = SPDM_ALGORITHMS_MULTI_KEY_CONN;

    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_rsp, true);
    assert_int_equal(spdm_context->connection_info.multi_key_conn_req, true);
}

/**
 * Test 36: ALGORITHMS message received with MEL
 * +---------------+--------------------------+--------------------------+-----------------------------------+
 * | MEAS_CAP |       MELspecification     |     MELspecificationSel     |          Expected result          |
 * |          |     NEGOTIATE_ALGORITHMS   |         ALGORITHMS          |                                   |
 * +----------+----------------------------+-----------------------------+-----------------------------------+
 * | set      | DMTFmeasSpec               | DMTFmeasSpec                | LIBSPDM_STATUS_SUCCESS            |
 *  ---------------------------------------------------------------------------------------------------------+
 * | set      | DMTFmeasSpec               | 0                           | LIBSPDM_STATUS_INVALID_MSG_FIELD  |
 *  ----------------------------------------------------------------------------------------------------------
 * | set      | 0                          | DMTFmeasSpec                | LIBSPDM_STATUS_INVALID_MSG_FIELD  |
 *  ---------------------------------------------------------------------------------------------------------+
 * | set      | 0                          | 0                           | LIBSPDM_STATUS_SUCCESS            |
 *  ----------------------------------------------------------------------------------------------------------
 * | Not set  | DMTFmeasSpec               | DMTFmeasSpec                | LIBSPDM_STATUS_INVALID_MSG_FIELD  |
 *  ---------------------------------------------------------------------------------------------------------+
 * | Not set  | DMTFmeasSpec               | 0                           | LIBSPDM_STATUS_SUCCESS            |
 *  ----------------------------------------------------------------------------------------------------------
 * | Not set  | 0                          | DMTFmeasSpec                | LIBSPDM_STATUS_INVALID_MSG_FIELD  |
 *  ---------------------------------------------------------------------------------------------------------+
 * | Not set  | 0                          | 0                           | LIBSPDM_STATUS_SUCCESS            |
 *  ----------------------------------------------------------------------------------------------------------
 **/
static void libspdm_test_requester_negotiate_algorithms_case36(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t local_capability_flags;
    uint32_t connection_capability_flags;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x24;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.algorithm.other_params_support = 0;

    local_capability_flags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
                             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP|
                             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP|
                             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP|
                             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    connection_capability_flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    spdm_context->connection_info.capability.flags = connection_capability_flags;
    spdm_context->local_context.capability.flags = local_capability_flags;

    /* Sub Case 1: MEL_CAP set 1, mel_specification_sel and mel_specification set SPDM_MEL_SPECIFICATION_DMTF*/
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;
    libspdm_reset_message_a(spdm_context);
    m_mel_specification_sel = SPDM_MEL_SPECIFICATION_DMTF;
    spdm_context->local_context.algorithm.mel_spec = SPDM_MEL_SPECIFICATION_DMTF;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* Sub Case 2: MEL_CAP set 1, mel_specification_sel set 0 , mel_specification set SPDM_MEL_SPECIFICATION_DMTF*/
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;
    libspdm_reset_message_a(spdm_context);
    m_mel_specification_sel = 0;
    spdm_context->local_context.algorithm.mel_spec = SPDM_MEL_SPECIFICATION_DMTF;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    /* Sub Case 3: MEL_CAP set 1, mel_specification_sel set SPDM_MEL_SPECIFICATION_DMTF , mel_specification set 0*/
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;
    libspdm_reset_message_a(spdm_context);
    m_mel_specification_sel = SPDM_MEL_SPECIFICATION_DMTF;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.mel_spec = 0;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    /* Sub Case 4: MEL_CAP set 1,mel_specification_sel set 0 , mel_specification set 0*/
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP;
    libspdm_reset_message_a(spdm_context);
    m_mel_specification_sel = 0;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.mel_spec = 0;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* Sub Case 5:MEL_CAP set 0, mel_specification_sel and mel_specification set SPDM_MEL_SPECIFICATION_DMTF*/
    spdm_context->connection_info.capability.flags = connection_capability_flags;
    libspdm_reset_message_a(spdm_context);
    m_mel_specification_sel = SPDM_MEL_SPECIFICATION_DMTF;
    spdm_context->local_context.algorithm.mel_spec = SPDM_MEL_SPECIFICATION_DMTF;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    /* Sub Case 6: MEL_CAP set 0, mel_specification_sel set 0 , mel_specification set SPDM_MEL_SPECIFICATION_DMTF*/
    spdm_context->connection_info.capability.flags = connection_capability_flags;
    libspdm_reset_message_a(spdm_context);
    m_mel_specification_sel = 0;
    spdm_context->local_context.algorithm.mel_spec = SPDM_MEL_SPECIFICATION_DMTF;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* Sub Case 7: MEL_CAP set 0,mel_specification_sel set SPDM_MEL_SPECIFICATION_DMTF , mel_specification set 0*/
    spdm_context->connection_info.capability.flags = connection_capability_flags;
    libspdm_reset_message_a(spdm_context);
    m_mel_specification_sel = SPDM_MEL_SPECIFICATION_DMTF;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.mel_spec = 0;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    /* Sub Case 8: MEL_CAP set 0,mel_specification_sel set 0 , mel_specification set 0*/
    spdm_context->connection_info.capability.flags = connection_capability_flags;
    libspdm_reset_message_a(spdm_context);
    m_mel_specification_sel = 0;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
    spdm_context->local_context.algorithm.mel_spec = 0;
    status = libspdm_negotiate_algorithms(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

static libspdm_test_context_t m_libspdm_requester_negotiate_algorithms_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_negotiate_algorithms_test_send_message,
    libspdm_requester_negotiate_algorithm_test_receive_message,
};

int libspdm_requester_negotiate_algorithms_test_main(void)
{
    const struct CMUnitTest spdm_requester_negotiate_algorithms_tests[] = {
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case1),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case2),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case3),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case4),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case5),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case6),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case7),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case8),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case9),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case10),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case11),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case12),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case13),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case14),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case15),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case16),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case17),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case18),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case19),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case20),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case21),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case22),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case23),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case24),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case25),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case26),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case27),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case28),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case29),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case30),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case31),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case32),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case33),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case34),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case35),
        cmocka_unit_test(libspdm_test_requester_negotiate_algorithms_case36),
    };

    libspdm_setup_test_context(&m_libspdm_requester_negotiate_algorithms_test_context);

    return cmocka_run_group_tests(spdm_requester_negotiate_algorithms_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
