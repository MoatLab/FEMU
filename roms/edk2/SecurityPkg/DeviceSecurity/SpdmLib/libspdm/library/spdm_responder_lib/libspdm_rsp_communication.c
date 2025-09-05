/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

libspdm_return_t libspdm_responder_dispatch_message(void *spdm_context)
{
    libspdm_return_t status;
    libspdm_context_t *context;
    uint8_t *request;
    size_t request_size;
    uint8_t *response;
    size_t response_size;
    uint32_t tmp_session_id;
    uint32_t *session_id;
    uint32_t *session_id_ptr;
    bool is_app_message;
    void *message;
    size_t message_size;

    context = spdm_context;

    /* receive and process request message */
    status = libspdm_acquire_receiver_buffer (context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    request = message;
    request_size = message_size;
    #if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
    /* need get real receiver buffer, because acquire receiver buffer will return scratch buffer*/
    libspdm_get_receiver_buffer (context, (void **)&request, &request_size);
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */
    status = context->receive_message(context, &request_size, (void **)&request, 0);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_receiver_buffer (context);
        return status;
    }
    status = libspdm_process_request(context, &session_id, &is_app_message,
                                     request_size, request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_receiver_buffer (context);
        return status;
    }

    /* save the value of session_id */
    if (session_id != NULL) {
        tmp_session_id = *session_id;
        session_id_ptr = &tmp_session_id;
    } else {
        session_id_ptr = NULL;
    }
    /* release buffer after use session_id, before acquire buffer */
    libspdm_release_receiver_buffer (context);

    /* build and send response message */
    status = libspdm_acquire_sender_buffer (context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    response = message;
    response_size = message_size;
    libspdm_zero_mem(response, response_size);

    status = libspdm_build_response(context, session_id_ptr, is_app_message,
                                    &response_size, (void **)&response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (context);
        return status;
    }

    status = context->send_message(context, response_size, response, 0);

    libspdm_release_sender_buffer (context);

    return status;
}
