/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_EVENT_RECIPIENT_SUPPORT

static libspdm_return_t libspdm_try_get_event_types(libspdm_context_t *spdm_context,
                                                    uint32_t session_id,
                                                    uint8_t *event_group_count,
                                                    uint32_t *supported_event_groups_list_len,
                                                    void *supported_event_groups_list)
{
    libspdm_return_t status;
    libspdm_session_info_t *session_info;
    spdm_get_supported_event_types_request_t *spdm_request;
    size_t spdm_request_size;
    spdm_supported_event_types_response_t *spdm_response;
    size_t spdm_response_size;
    size_t transport_header_size;
    uint8_t *message;
    size_t message_size;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(event_group_count != NULL);
    LIBSPDM_ASSERT(supported_event_groups_list_len != NULL);
    LIBSPDM_ASSERT(supported_event_groups_list != NULL);

    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);

    if (session_info == NULL) {
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }
    if (libspdm_secured_message_get_session_state(session_info->secured_message_context) !=
        LIBSPDM_SESSION_STATE_ESTABLISHED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    /* -=[Verify State Phase]=- */
    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_13) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    /* -=[Construct Request Phase]=- */
    transport_header_size = spdm_context->local_context.capability.transport_header_size;
    status = libspdm_acquire_sender_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size +
                    spdm_context->local_context.capability.transport_tail_size);
    spdm_request = (void *)(message + transport_header_size);
    spdm_request_size = message_size - transport_header_size -
                        spdm_context->local_context.capability.transport_tail_size;

    spdm_request->header.spdm_version = libspdm_get_connection_version(spdm_context);
    spdm_request->header.request_response_code = SPDM_GET_SUPPORTED_EVENT_TYPES;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;
    spdm_request_size = sizeof(spdm_get_supported_event_types_request_t);

    /* -=[Send Request Phase]=- */
    status = libspdm_send_spdm_request(spdm_context, &session_id, spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* -=[Receive Response Phase]=- */
    status = libspdm_acquire_receiver_buffer(spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    libspdm_zero_mem(spdm_response, spdm_response_size);
    status = libspdm_receive_spdm_response(
        spdm_context, &session_id, &spdm_response_size, (void **)&spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    /* -=[Validate Response Phase]=- */
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, &session_id,
            &spdm_response_size, (void **)&spdm_response,
            SPDM_GET_SUPPORTED_EVENT_TYPES, SPDM_SUPPORTED_EVENT_TYPES);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_SUPPORTED_EVENT_TYPES) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.param1 == 0) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response_size < sizeof(spdm_supported_event_types_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_response->supported_event_groups_list_len == 0) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    } else if (spdm_response->supported_event_groups_list_len > *supported_event_groups_list_len) {
        status = LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        goto receive_done;
    }
    if (spdm_response_size != sizeof(spdm_supported_event_types_response_t) +
        (uint64_t)spdm_response->supported_event_groups_list_len) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    /* -=[Process Response Phase]=- */
    *event_group_count = spdm_response->header.param1;
    libspdm_copy_mem(supported_event_groups_list, *supported_event_groups_list_len,
                     spdm_response + 1, spdm_response->supported_event_groups_list_len);
    *supported_event_groups_list_len = spdm_response->supported_event_groups_list_len;

receive_done:
    libspdm_release_receiver_buffer(spdm_context);

    return status;
}

libspdm_return_t libspdm_get_event_types(void *spdm_context,
                                         uint32_t session_id,
                                         uint8_t *event_group_count,
                                         uint32_t *supported_event_groups_list_len,
                                         void *supported_event_groups_list)
{
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;
    libspdm_context_t *context;

    context = spdm_context;
    context->crypto_request = true;
    retry = context->retry_times;
    retry_delay_time = context->retry_delay_time;
    do {
        status = libspdm_try_get_event_types(context,
                                             session_id,
                                             event_group_count,
                                             supported_event_groups_list_len,
                                             supported_event_groups_list);
        if ((status != LIBSPDM_STATUS_BUSY_PEER) || (retry == 0)) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_EVENT_RECIPIENT_SUPPORT */
