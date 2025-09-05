/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

#define LIBSPDM_DEFAULT_CAPABILITY_FLAG \
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP)

#define LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11 \
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)

#define LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_12  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP

#define LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 \
    (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)

#define LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_12 \
    (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP | \
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP | \
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)

static libspdm_return_t libspdm_requester_get_capabilities_test_send_message(
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
    case 0xa:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xb:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xc:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xd:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xe:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xf:
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
    case 0x1a:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1b:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1c:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1d:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1E:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1F:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x20:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x21:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x22:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x23:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x24:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x25:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x26:
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

static libspdm_return_t libspdm_requester_get_capabilities_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x2: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

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
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG |
                               SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
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
        spdm_response->header.param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response->header.param2 = 0;
        spdm_response->extend_error_data.rd_exponent = 1;
        spdm_response->extend_error_data.rd_tm = 2;
        spdm_response->extend_error_data.request_code = SPDM_GET_CAPABILITIES;
        spdm_response->extend_error_data.token = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x9: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xa: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xb: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xc: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xd: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            sizeof(spdm_message_header_t), spdm_response,
            response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xe: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            sizeof(spdm_capabilities_response_t) + sizeof(uint8_t), spdm_response,
            response_size, response);
    }
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;

    case 0xf: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            sizeof(spdm_capabilities_response_t) - sizeof(uint8_t), spdm_response,
            response_size, response);
    }
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;

    case 0x10: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
                               SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x11: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x12: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x13: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));
        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x14: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x15: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x16: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x17: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x18: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x19: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 &
            (0xFFFFFFFF ^
             (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP));

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1a: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 |
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1b: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_GET_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1c: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = 0xFF;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags =
            LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1d: {
        static uint16_t error_code = LIBSPDM_ERROR_CODE_RESERVED_00;

        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        if(error_code <= 0xff) {
            libspdm_zero_mem(spdm_response, spdm_response_size);
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = (uint8_t) error_code;
            spdm_response->header.param2 = 0;

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

    case 0x1e: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1F:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x20: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x21: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;
        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x22: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x23: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
        spdm_response->data_transfer_size = 0;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x24: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE - 1;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x25: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = 0;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_12;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_DATA_TRANSFER_SIZE - 1;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x26: {
        spdm_capabilities_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_capabilities_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response, spdm_response_size);
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CAPABILITIES;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->ct_exponent = LIBSPDM_MAX_CT_EXPONENT + 1;
        spdm_response->flags = LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_12;
        spdm_response->data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
        spdm_response->max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

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

static void libspdm_test_requester_get_capabilities_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
}

/**
 * Test 2: Responder sets MEAS_FRESH_CAP but does not set MEAS_CAP.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_capabilities_err_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

static void libspdm_test_requester_get_capabilities_err_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NOT_STARTED;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
}

static void libspdm_test_requester_get_capabilities_err_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
}

static void libspdm_test_requester_get_capabilities_err_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);
}

/**
 * Test 6: Responder sets illegal SPDM 1.0 combination of MEAS_CAP (no signature), CERT_CAP,
 *         and CHAL_CAP.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_capabilities_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

static void libspdm_test_requester_get_capabilities_err_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
}

static void libspdm_test_requester_get_capabilities_err_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
}

/**
 * Test 9: Responder returns a Reserved MEAS_CAP value.
 * Expected behavior: returns a status of LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_capabilities_err_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 10: Responder sets illegal SPDM 1.0 combination of MEAS_CAP (with signature), CERT_CAP,
 *          and CHAL_CAP.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_capabilities_err_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xa;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 11: Responder sets illegal 1.1/1.2 PSK_CAP value (3).
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_capabilities_err_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xb;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 11: Responder sets illegal 1.1/1.2 combination of values.
 *          CERT_CAP enabled.
 *          CHAL_CAP and KEY_EX_CAP disabled.
 *          MEAS_CAP with signature is disabled.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_capabilities_err_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xc;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

static void libspdm_test_requester_get_capabilities_err_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xd;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

static void libspdm_test_requester_get_capabilities_err_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xe;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

static void libspdm_test_requester_get_capabilities_err_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xf;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
}

/**
 * Test 16: Responder sets illegal 1.1/1.2 combination of values.
 *          CERT_CAP and PUB_KEY_ID_CAP disabled.
 *          At least one of CHAL_CAP, KEY_EX_CAP, MEAS_CAP (with signature), or MUT_AUTH_CAP
 *          is enabled.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_capabilities_err_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

static void libspdm_test_requester_get_capabilities_err_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    /*assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
     * assert_int_equal (spdm_context->connection_info.capability.flags, LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));*/
}

static void libspdm_test_requester_get_capabilities_err_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags =
        LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    /*assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
     * assert_int_equal (spdm_context->connection_info.capability.flags, LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));*/
}

static void libspdm_test_requester_get_capabilities_err_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    /*assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
     * assert_int_equal (spdm_context->connection_info.capability.flags, LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));*/
}

static void libspdm_test_requester_get_capabilities_err_case20(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    /*assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
     * assert_int_equal (spdm_context->connection_info.capability.flags, LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));*/
}

static void libspdm_test_requester_get_capabilities_err_case21(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    /*assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
     * assert_int_equal (spdm_context->connection_info.capability.flags, LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));*/
}

static void libspdm_test_requester_get_capabilities_err_case22(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    /*assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
     * assert_int_equal (spdm_context->connection_info.capability.flags, LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));*/
}

static void libspdm_test_requester_get_capabilities_err_case23(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    /*assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
     * assert_int_equal (spdm_context->connection_info.capability.flags, LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP)));*/
}

static void libspdm_test_requester_get_capabilities_err_case24(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    /*assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
     * assert_int_equal (spdm_context->connection_info.capability.flags, LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)));*/
}

static void libspdm_test_requester_get_capabilities_err_case25(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    /*assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
     * assert_int_equal (spdm_context->connection_info.capability.flags, LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)));*/
}

static void libspdm_test_requester_get_capabilities_err_case26(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1a;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    /*assert_int_equal (spdm_context->connection_info.capability.ct_exponent, 0);
     * assert_int_equal (spdm_context->connection_info.capability.flags, LIBSPDM_DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP);*/
}

static void libspdm_test_requester_get_capabilities_err_case27(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1b;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

static void libspdm_test_requester_get_capabilities_err_case28(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1c;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    libspdm_reset_message_a(spdm_context);

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

static void libspdm_test_requester_get_capabilities_err_case29(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint16_t error_code;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1d;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG_VERSION_11;

    error_code = LIBSPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
        libspdm_reset_message_a(spdm_context);

        status = libspdm_get_capabilities (spdm_context);
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

/**
 * Test 30: Responder sets illegal 1.2 combination of values.
 *          CERT_CAP is disabled.
 *          ALIAS_CERT_CAP is enabled.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_capabilities_err_case30(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1E;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

static void libspdm_test_requester_get_capabilities_err_case31(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1F;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_RECEIVE_FAIL);
}

/**
 * Test 32: Responder sets illegal 1.2 combination of values.
 *          CSR_CAP is enabled.
 *          SET_CERT_CAP is disabled.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_capabilities_err_case32(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x20;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 33: Responder sets illegal 1.2 combination of values.
 *          CERT_INSTALL_RESET_CAP is enabled.
 *          CSR_CAP and SET_CERT_CAP are disabled.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_capabilities_err_case33(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x21;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

static void libspdm_test_requester_get_capabilities_err_case34(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x22;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
    spdm_context->transcript.message_a.buffer_size =
        spdm_context->transcript.message_a.max_buffer_size;
    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;
    status = libspdm_get_capabilities(spdm_context);
    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_FULL);

    spdm_context->transcript.message_a.buffer_size = 0;
}

/**
 * Test 35: Unable to acquire sender buffer.
 * Expected behavior: returns with status LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void libspdm_test_requester_get_capabilities_err_case35(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

    libspdm_force_error (LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);
    status = libspdm_get_capabilities(spdm_context);
    libspdm_release_error (LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 36: Unable to acquire receiver buffer.
 * Expected behavior: returns with status LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void libspdm_test_requester_get_capabilities_err_case36(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

    libspdm_force_error (LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);
    status = libspdm_get_capabilities(spdm_context);
    libspdm_release_error (LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 37: Responder sets illegal DataTransferSize that is less than MinDataTransferSize.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_capabilities_err_case37(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x23;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

    status = libspdm_get_capabilities(spdm_context);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 38: Responder does not support chunking but also does not set DataTransferSize equal
 *          to MaxSPDMmsgSize.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_capabilities_err_case38(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x24;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

    status = libspdm_get_capabilities(spdm_context);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 39: Responder sets illegal MaxSPDMmsgSize that is less than DataTransferSize.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_capabilities_err_case39(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x25;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

    status = libspdm_get_capabilities(spdm_context);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 40: Responder returns a CTExponent value that is larger than LIBSPDM_MAX_CT_EXPONENT.
 * Expected behavior: returns with status LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_get_capabilities_err_case40(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x26;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    spdm_context->local_context.capability.ct_exponent = 0;
    spdm_context->local_context.capability.flags = LIBSPDM_DEFAULT_CAPABILITY_FLAG;

    status = libspdm_get_capabilities(spdm_context);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

static libspdm_test_context_t m_libspdm_requester_get_capabilities_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_get_capabilities_test_send_message,
    libspdm_requester_get_capabilities_test_receive_message,
};

int libspdm_requester_get_capabilities_error_test_main(void)
{
    const struct CMUnitTest m_spdm_requester_get_capabilities_tests[] = {
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case1),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case2),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case3),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case4),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case5),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case6),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case7),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case8),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case9),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case10),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case11),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case12),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case13),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case14),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case15),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case16),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case17),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case18),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case19),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case20),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case21),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case22),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case23),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case24),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case25),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case26),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case27),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case28),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case29),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case30),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case31),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case32),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case33),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case34),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case35),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case36),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case37),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case38),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case39),
        cmocka_unit_test(libspdm_test_requester_get_capabilities_err_case40),
    };

    libspdm_setup_test_context(&m_libspdm_requester_get_capabilities_test_context);

    return cmocka_run_group_tests(m_spdm_requester_get_capabilities_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
