/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_RESPOND_IF_READY_SUPPORT

libspdm_return_t libspdm_get_response_respond_if_ready(libspdm_context_t *spdm_context,
                                                       size_t request_size,
                                                       const void *request,
                                                       size_t *response_size,
                                                       void *response)
{
    const spdm_message_header_t *spdm_request;
    libspdm_get_spdm_response_func get_response_func;
    libspdm_return_t status;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->request_response_code == SPDM_RESPOND_IF_READY);

    if (spdm_request->spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }
    if (spdm_context->response_state == LIBSPDM_RESPONSE_STATE_NEED_RESYNC ||
        spdm_context->response_state == LIBSPDM_RESPONSE_STATE_NOT_READY) {
        return libspdm_responder_handle_response_state(
            spdm_context, spdm_request->request_response_code,
            response_size, response);
    }

    if (request_size < sizeof(spdm_message_header_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (spdm_request->param1 != spdm_context->error_data.request_code) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (spdm_request->param1 == SPDM_RESPOND_IF_READY) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (spdm_request->param2 != spdm_context->error_data.token) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    get_response_func = NULL;
    get_response_func = libspdm_get_response_func_via_request_code(spdm_request->param1);
    if (get_response_func == NULL) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            spdm_request->param1, response_size, response);
    }
    status = get_response_func(spdm_context,
                               spdm_context->cache_spdm_request_size,
                               spdm_context->cache_spdm_request,
                               response_size, response);

    return status;
}

#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
