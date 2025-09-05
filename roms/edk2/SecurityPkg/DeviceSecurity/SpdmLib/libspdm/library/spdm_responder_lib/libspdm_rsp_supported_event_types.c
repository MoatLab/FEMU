/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP

libspdm_return_t libspdm_get_response_supported_event_types(libspdm_context_t *spdm_context,
                                                            size_t request_size,
                                                            const void *request,
                                                            size_t *response_size,
                                                            void *response)
{
    spdm_supported_event_types_response_t *spdm_response;
    const spdm_get_supported_event_types_request_t *spdm_request;
    const size_t response_buffer_size = *response_size;
    uint32_t supported_event_groups_list_len;
    uint8_t event_group_count;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_GET_SUPPORTED_EVENT_TYPES);

    /* -=[Verify State Phase]=- */
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
    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_13) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                                               SPDM_GET_SUPPORTED_EVENT_TYPES,
                                               response_size, response);
    }
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_SUPPORTED_EVENT_TYPES, response_size, response);
    }
    if (!spdm_context->last_spdm_request_session_id_valid) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_SESSION_REQUIRED, 0,
                                               response_size, response);
    }
    session_id = spdm_context->last_spdm_request_session_id;
    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_SESSION_REQUIRED, 0,
                                               response_size, response);
    }
    session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                                               response_size, response);
    }
    /* This message can only be in secured session.
     * Thus don't need to consider transport layer padding, just check its exact size. */
    if (request_size != sizeof(spdm_get_supported_event_types_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }

    /* -=[Construct Response Phase]=- */
    LIBSPDM_ASSERT(response_buffer_size >= sizeof(spdm_supported_event_types_response_t));
    libspdm_zero_mem(response, response_buffer_size);
    spdm_response = response;

    spdm_response->header.spdm_version = libspdm_get_connection_version(spdm_context);
    spdm_response->header.request_response_code = SPDM_SUPPORTED_EVENT_TYPES;
    spdm_response->header.param2 = 0;

    supported_event_groups_list_len = (uint32_t)response_buffer_size -
                                      sizeof(spdm_supported_event_types_response_t);

    if (!libspdm_event_get_types(spdm_context, spdm_context->connection_info.version,
                                 (void *)(spdm_response + 1), &supported_event_groups_list_len,
                                 &event_group_count)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    LIBSPDM_ASSERT(supported_event_groups_list_len > 0);
    LIBSPDM_ASSERT(supported_event_groups_list_len <=
                   (response_buffer_size - sizeof(spdm_supported_event_types_response_t)));
    LIBSPDM_ASSERT(event_group_count > 0);

    spdm_response->header.param1 = event_group_count;
    spdm_response->supported_event_groups_list_len = supported_event_groups_list_len;

    *response_size = sizeof(spdm_supported_event_types_response_t) +
                     supported_event_groups_list_len;

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
