/**
 *  Copyright Notice:
 *  Copyright 2023-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES

/* expected number of bytes for VENDOR MESSAGE HEADERS */
#define SPDM_VENDOR_DEFINED_FIXED_HEADER_LEN 7

libspdm_return_t libspdm_register_vendor_get_id_callback_func(void *spdm_context,
                                                              libspdm_vendor_get_id_callback_func resp_callback)
{

    libspdm_context_t *context = (libspdm_context_t *)spdm_context;
    context->vendor_response_get_id = resp_callback;
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_register_vendor_callback_func(void *spdm_context,
                                                       libspdm_vendor_response_callback_func resp_callback)
{

    libspdm_context_t *context = (libspdm_context_t *)spdm_context;
    context->vendor_response_callback = resp_callback;
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_get_vendor_defined_response(libspdm_context_t *spdm_context,
                                                     size_t request_size,
                                                     const void *request,
                                                     size_t *response_size,
                                                     void *response)
{
    const spdm_vendor_defined_request_msg_t *spdm_request;
    spdm_vendor_defined_response_msg_t *spdm_response;
    uint16_t header_length;
    size_t response_capacity = 0;
    libspdm_return_t status = LIBSPDM_STATUS_SUCCESS;

    libspdm_session_info_t *session_info = NULL;
    libspdm_session_state_t session_state = 0;
    const uint32_t *session_id = NULL;
    uint8_t *resp_data = NULL;
    const uint8_t *req_vendor_id;
    const uint8_t *req_data;
    uint16_t resp_size = 0;
    uint16_t req_size = 0;

    /* -=[Check Parameters Phase]=- */
    if (request == NULL ||
        response == NULL ||
        response_size == NULL) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    if (spdm_context->last_spdm_request_session_id_valid) {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context,
            spdm_context->last_spdm_request_session_id);
        if (session_info == NULL) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
        session_id = &session_info->session_id;
    }

    /* Check if caller is using the old Vendor Defined API */
    if ((spdm_context->vendor_response_callback == NULL ||
         spdm_context->vendor_response_get_id == NULL)) {

        if (spdm_context->get_response_func != NULL) {

            return ((libspdm_get_response_func)spdm_context->get_response_func)(
                spdm_context,
                session_id,
                false,
                request_size,
                request,
                response_size,
                response
                );
        } else
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    spdm_request = request;

    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }
    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }
    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }

    if (request_size < sizeof(spdm_vendor_defined_request_msg_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (request_size < sizeof(spdm_vendor_defined_request_msg_t) +
        spdm_request->len + sizeof(uint16_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    req_vendor_id = ((const uint8_t *)request) +
                    sizeof(spdm_vendor_defined_request_msg_t);
    req_size = *(const uint16_t *)(req_vendor_id + spdm_request->len);
    if (request_size < sizeof(spdm_vendor_defined_request_msg_t) +
        spdm_request->len + sizeof(uint16_t) + req_size) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (spdm_context->vendor_response_get_id == NULL) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (spdm_context->vendor_response_callback == NULL) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    /* length of spdm request/response header before payload start */
    header_length = sizeof(spdm_vendor_defined_response_msg_t) + spdm_request->len +
                    sizeof(uint16_t);

    LIBSPDM_ASSERT(*response_size >= header_length);
    LIBSPDM_ASSERT(
        sizeof(spdm_vendor_defined_response_msg_t) == SPDM_VENDOR_DEFINED_FIXED_HEADER_LEN);
    response_capacity = *response_size - header_length;
    libspdm_zero_mem(response, header_length);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_VENDOR_DEFINED_RESPONSE;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    /* SPDM Response format
     *  1 byte SPDMVersion
     *  1 byte RequestResponseCode
     *  2 bytes Reserved
     *  2 bytes StandardID
     *  1 bytes VendorID Length Len1, based on StandardID
     *  Len1 bytes VendorID
     *  2 bytes Response Length Len2
     *  Len2 bytes Response Payload
     */

    /* replace capacity with size */
    spdm_response->len = SPDM_MAX_VENDOR_ID_LENGTH;
    resp_data = ((uint8_t *)response) + sizeof(spdm_vendor_defined_response_msg_t);

    req_data = ((const uint8_t *)request) +
               sizeof(spdm_vendor_defined_request_msg_t) +
               ((const spdm_vendor_defined_request_msg_t*)request)->len +
               sizeof(uint16_t);

    status = spdm_context->vendor_response_get_id(
        spdm_context,
        &spdm_response->standard_id,
        &spdm_response->len,
        resp_data);

    /* move pointer and adjust buffer size */
    resp_data += spdm_response->len + sizeof(uint16_t);
    response_capacity -= spdm_response->len + sizeof(uint16_t);
    resp_size = (uint16_t)response_capacity;

    status = spdm_context->vendor_response_callback(spdm_context,
                                                    spdm_request->standard_id,
                                                    spdm_request->len,
                                                    req_vendor_id, req_size, req_data,
                                                    &resp_size,
                                                    resp_data
                                                    );

    /* store back the response payload size */
    *((uint16_t*)(resp_data - sizeof(uint16_t))) = resp_size;
    *response_size = resp_size + (size_t)header_length;

    LIBSPDM_ASSERT(sizeof(spdm_vendor_defined_request_msg_t) ==
                   SPDM_VENDOR_DEFINED_FIXED_HEADER_LEN);

    return status;
}

#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */
