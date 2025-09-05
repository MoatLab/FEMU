/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint8_t reserved;
    uint8_t version_number_entry_count;
    spdm_version_number_t version_number_entry[SPDM_MAX_VERSION_COUNT];
} libspdm_version_response_mine_t;
#pragma pack()

static libspdm_return_t generate_invalid_version_error(size_t *response_size, void *response)
{
    spdm_error_response_t *spdm_response;

    spdm_response = response;
    *response_size = sizeof(spdm_error_response_t);

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_response->header.request_response_code = SPDM_ERROR;
    spdm_response->header.param1 = SPDM_ERROR_CODE_VERSION_MISMATCH;
    spdm_response->header.param2 = 0;

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_get_response_version(libspdm_context_t *spdm_context, size_t request_size,
                                              const void *request,
                                              size_t *response_size,
                                              void *response)
{
    const spdm_get_version_request_t *spdm_request;
    libspdm_version_response_mine_t *spdm_response;
    libspdm_return_t status;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_GET_VERSION);

    /* -=[Validate Request Phase]=- */
    if (request_size < sizeof(spdm_get_version_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (spdm_context->last_spdm_request_session_id_valid) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }

    if (spdm_request->header.spdm_version != SPDM_MESSAGE_VERSION_10) {
        /* If the GET_VERSION request is improperly formed then the version of the error message
         * must be 1.0, regardless of what the negotiated version is. */
        return generate_invalid_version_error(response_size, response);
    }

    libspdm_set_connection_state(spdm_context, LIBSPDM_CONNECTION_STATE_NOT_STARTED);

    if ((spdm_context->response_state == LIBSPDM_RESPONSE_STATE_NEED_RESYNC) ||
        (spdm_context->response_state == LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP)) {
        /* receiving a GET_VERSION resets a need to resynchronization*/
        spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    }
    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }

    /* -=[Process Request Phase]=- */
    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_d(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);

    request_size = sizeof(spdm_get_version_request_t);
    status = libspdm_append_message_a(spdm_context, spdm_request, request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    libspdm_reset_context(spdm_context);

    /* -=[Construct Response Phase]=- */
    LIBSPDM_ASSERT(*response_size >= sizeof(libspdm_version_response_mine_t));
    *response_size =
        sizeof(spdm_version_response_t) +
        spdm_context->local_context.version.spdm_version_count *
        sizeof(spdm_version_number_t);
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_VERSION;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->version_number_entry_count =
        spdm_context->local_context.version.spdm_version_count;
    libspdm_copy_mem(spdm_response->version_number_entry,
                     sizeof(spdm_response->version_number_entry),
                     spdm_context->local_context.version.spdm_version,
                     sizeof(spdm_version_number_t) *
                     spdm_context->local_context.version.spdm_version_count);

    status = libspdm_append_message_a(spdm_context, spdm_response, *response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_reset_message_a(spdm_context);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    /* -=[Update State Phase]=- */
    libspdm_set_connection_state(spdm_context, LIBSPDM_CONNECTION_STATE_AFTER_VERSION);

    /*Set the role of device*/
    spdm_context->local_context.is_requester = false;

    return LIBSPDM_STATUS_SUCCESS;
}
