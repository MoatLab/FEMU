/**
 *  Copyright Notice:
 *  Copyright 2023-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES

#define SPDM_MAX_VENDOR_PAYLOAD_LEN (SPDM_MAX_VENDOR_ID_LENGTH + 2 + \
                                     SPDM_MAX_VENDOR_DEFINED_DATA_LEN)

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint16_t standard_id;
    uint8_t vendor_id_len;
    uint8_t vendor_plus_request[SPDM_MAX_VENDOR_PAYLOAD_LEN];
} libspdm_vendor_defined_response_msg_max_t;
#pragma pack()

libspdm_return_t libspdm_try_vendor_send_request_receive_response(
    libspdm_context_t *spdm_context,
    const uint32_t *session_id,
    uint16_t req_standard_id,
    uint8_t req_vendor_id_len,
    const void *req_vendor_id,
    uint16_t req_size,
    const void *req_data,
    uint16_t *resp_standard_id,
    uint8_t *resp_vendor_id_len,
    void *resp_vendor_id,
    uint16_t *resp_size,
    void *resp_data)
{
    libspdm_return_t status;
    spdm_vendor_defined_request_msg_t *spdm_request;
    size_t spdm_request_size;
    libspdm_vendor_defined_response_msg_max_t *spdm_response;
    size_t spdm_response_size;
    uint8_t *message;
    size_t message_size = 0;
    size_t transport_header_size;
    size_t max_payload = 0;
    uint8_t* vendor_request = NULL;
    uint8_t *response_ptr = NULL;
    uint16_t response_size = 0;

    /* -=[Check Parameters Phase]=- */
    if (spdm_context == NULL ||
        (req_size != 0 && req_data == NULL) ||
        resp_standard_id == NULL ||
        resp_vendor_id_len == NULL ||
        resp_vendor_id == NULL ||
        resp_size == NULL ||
        (*resp_size != 0 && resp_data == NULL)
        ) {
        status = LIBSPDM_STATUS_INVALID_PARAMETER;
        goto done;
    }

    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    transport_header_size = spdm_context->local_context.capability.transport_header_size;

    /* -=[Construct Request Phase]=- */
    status = libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    /* calculate useful payload the sender buffer can hold after
     * removing all protocol, spdm and vendor defined message headers
     * -3 bytes is for the standard_id and vendor_id_len fields in the vendor header
     * -2 bytes is for the payload length field */
    max_payload = message_size - transport_header_size -
                  spdm_context->local_context.capability.transport_tail_size
                  - sizeof(spdm_request->header) - 3 - req_vendor_id_len - 2;

    LIBSPDM_ASSERT (message_size >= transport_header_size +
                    spdm_context->local_context.capability.transport_tail_size);

    /* do not accept requests exceeding maximum allowed payload */
    if ((size_t)req_size > max_payload) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    spdm_request = (void *)(message + transport_header_size);

    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_VENDOR_DEFINED_REQUEST;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    /* Message header here */
    spdm_request->standard_id = req_standard_id;
    spdm_request->len = req_vendor_id_len;

    /* Copy Vendor id */
    vendor_request = ((uint8_t *)spdm_request) + sizeof(spdm_vendor_defined_request_msg_t);
    if (req_vendor_id_len != 0) {
        libspdm_copy_mem(vendor_request, req_vendor_id_len, req_vendor_id, req_vendor_id_len);
        vendor_request += req_vendor_id_len;
    }

    /* Copy request_len */
    libspdm_copy_mem(vendor_request, sizeof(uint16_t), &req_size, sizeof(uint16_t));
    vendor_request += sizeof(uint16_t);

    /* Copy payload */
    if (req_size != 0) {
        libspdm_copy_mem(vendor_request, req_size, req_data, req_size);
    }

    spdm_request_size = sizeof(spdm_vendor_defined_request_msg_t) +
                        req_vendor_id_len + sizeof(uint16_t) + req_size;

    /* -=[Send Request Phase]=- */
    status =
        libspdm_send_spdm_request(spdm_context, session_id, spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        status = LIBSPDM_STATUS_SEND_FAIL;
        goto done;
    }
    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* -=[Receive Response Phase]=- */
    status = libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    libspdm_zero_mem(spdm_response, spdm_response_size);
    status = libspdm_receive_spdm_response(spdm_context, session_id,
                                           &spdm_response_size,
                                           (void **)&spdm_response);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        status = LIBSPDM_STATUS_RECEIVE_FAIL;
        goto done;
    }

    /* -=[Validate Response Phase]=- */
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, session_id,
            &spdm_response_size,
            (void **)&spdm_response, SPDM_VENDOR_DEFINED_REQUEST,
            SPDM_VENDOR_DEFINED_RESPONSE);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_VENDOR_DEFINED_RESPONSE) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto done;
    }

    if (spdm_response_size < sizeof(spdm_vendor_defined_response_msg_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto done;
    }
    /* check response buffer size at least spdm response default header plus
     * number of bytes required by vendor id and 2 bytes for response payload size */
    if (spdm_response_size < sizeof(spdm_vendor_defined_response_msg_t) +
        spdm_response->vendor_id_len + sizeof(uint16_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto done;
    }

    *resp_standard_id = spdm_response->standard_id;
    if (*resp_vendor_id_len < spdm_response->vendor_id_len) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto done;
    }
    *resp_vendor_id_len = spdm_response->vendor_id_len;
    if ((*resp_vendor_id_len) != 0) {
        libspdm_copy_mem(resp_vendor_id, *resp_vendor_id_len, spdm_response->vendor_plus_request,
                         *resp_vendor_id_len);
    }

    /* -=[Process Response Phase]=- */
    response_ptr = spdm_response->vendor_plus_request + spdm_response->vendor_id_len;
    response_size = *((uint16_t*)response_ptr);
    if (spdm_response_size < response_size +
        sizeof(spdm_vendor_defined_response_msg_t) +
        spdm_response->vendor_id_len + sizeof(uint16_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto done;
    }
    response_ptr += sizeof(uint16_t);
    if (*resp_size < response_size) {
        status = LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        goto done;
    }
    libspdm_copy_mem(resp_data, *resp_size, response_ptr, response_size);
    *resp_size = response_size;

    /* -=[Log Message Phase]=- */
    #if LIBSPDM_ENABLE_MSG_LOG
    libspdm_append_msg_log(spdm_context, spdm_response, spdm_response_size);
    #endif /* LIBSPDM_ENABLE_MSG_LOG */

    status = LIBSPDM_STATUS_SUCCESS;
done:
    libspdm_release_receiver_buffer (spdm_context); /* this will free up response-message, need to find workaround */
    return status;
}

libspdm_return_t libspdm_vendor_send_request_receive_response(
    void *spdm_context,
    const uint32_t *session_id,
    uint16_t req_standard_id,
    uint8_t req_vendor_id_len,
    const void *req_vendor_id,
    uint16_t req_size,
    const void *req_data,
    uint16_t *resp_standard_id,
    uint8_t *resp_vendor_id_len,
    void *resp_vendor_id,
    uint16_t *resp_size,
    void *resp_data)
{
    libspdm_context_t *context;
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;

    context = spdm_context;
    context->crypto_request = true;
    retry = context->retry_times;
    retry_delay_time = context->retry_delay_time;
    do {
        status = libspdm_try_vendor_send_request_receive_response(
            context,
            session_id,
            req_standard_id,
            req_vendor_id_len,
            req_vendor_id,
            req_size,
            req_data,
            resp_standard_id,
            resp_vendor_id_len,
            resp_vendor_id,
            resp_size,
            resp_data);
        if ((status != LIBSPDM_STATUS_BUSY_PEER) || (retry == 0)) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */
