/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

/**
 * Process the SPDM KEY_UPDATE request and return the response.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  request_size                  size in bytes of the request data.
 * @param  request                      A pointer to the request data.
 * @param  response_size                 size in bytes of the response data.
 *                                     On input, it means the size in bytes of response data buffer.
 *                                     On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
 *                                     and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  response                     A pointer to the response data.
 *
 * @retval RETURN_SUCCESS               The request is processed and the response is returned.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
libspdm_return_t libspdm_get_response_key_update(libspdm_context_t *spdm_context,
                                                 size_t request_size,
                                                 const void *request,
                                                 size_t *response_size,
                                                 void *response)
{
    uint32_t session_id;
    spdm_key_update_response_t *spdm_response;
    const spdm_key_update_request_t *spdm_request;
    spdm_key_update_request_t *prev_spdm_request;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    spdm_key_update_request_t spdm_key_init_update_operation;
    bool result;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_KEY_UPDATE);

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_11) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                                               SPDM_KEY_UPDATE,
                                               response_size, response);
    }

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

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_KEY_UPDATE, response_size, response);
    }
    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }

    if (!spdm_context->last_spdm_request_session_id_valid) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_SESSION_REQUIRED, 0,
                                               response_size, response);
    }
    session_id = spdm_context->last_spdm_request_session_id;
    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
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

    /* this message can only be in secured session
     * thus don't need to consider transport layer padding, just check its exact size */
    if (request_size != sizeof(spdm_key_update_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    /*last key operation*/
    prev_spdm_request = &(session_info->last_key_update_request);

    /*the end status of the successful key update overall flow*/
    libspdm_zero_mem(&spdm_key_init_update_operation, sizeof(spdm_key_update_request_t));

    switch (spdm_request->header.param1) {
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY:
        if(!libspdm_consttime_is_mem_equal(prev_spdm_request,
                                           &spdm_key_init_update_operation,
                                           sizeof(spdm_key_update_request_t))) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_create_update_session_data_key[%x] Requester\n",
                       session_id));
        result = libspdm_create_update_session_data_key(
            session_info->secured_message_context,
            LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);
        if (!result) {
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }
        libspdm_trigger_key_update_callback(
            spdm_context, session_id, LIBSPDM_KEY_UPDATE_OPERATION_CREATE_UPDATE,
            LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);

        /*save the last update operation*/
        libspdm_copy_mem(prev_spdm_request, sizeof(spdm_key_update_request_t),
                         spdm_request, request_size);
        break;
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS:
        if(!libspdm_consttime_is_mem_equal(prev_spdm_request,
                                           &spdm_key_init_update_operation,
                                           sizeof(spdm_key_update_request_t))) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_create_update_session_data_key[%x] Requester\n",
                       session_id));
        result = libspdm_create_update_session_data_key(
            session_info->secured_message_context,
            LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);
        if (!result) {
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }
        libspdm_trigger_key_update_callback(
            spdm_context, session_id, LIBSPDM_KEY_UPDATE_OPERATION_CREATE_UPDATE,
            LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_create_update_session_data_key[%x] Responder\n",
                       session_id));
        result = libspdm_create_update_session_data_key(
            session_info->secured_message_context,
            LIBSPDM_KEY_UPDATE_ACTION_RESPONDER);
        if (!result) {
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }
        libspdm_trigger_key_update_callback(
            spdm_context, session_id, LIBSPDM_KEY_UPDATE_OPERATION_CREATE_UPDATE,
            LIBSPDM_KEY_UPDATE_ACTION_RESPONDER);

        /* We can commit to Responder key. */
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_activate_update_session_data_key[%x] Responder new\n",
                       session_id));
        result = libspdm_activate_update_session_data_key(
            session_info->secured_message_context,
            LIBSPDM_KEY_UPDATE_ACTION_RESPONDER, true);
        if (!result) {
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }
        libspdm_trigger_key_update_callback(
            spdm_context, session_id, LIBSPDM_KEY_UPDATE_OPERATION_COMMIT_UPDATE,
            LIBSPDM_KEY_UPDATE_ACTION_RESPONDER);

        /*save the last update operation*/
        libspdm_copy_mem(prev_spdm_request, sizeof(spdm_key_update_request_t),
                         spdm_request, request_size);
        break;
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY:
        if(prev_spdm_request->header.param1 !=
           SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY &&
           prev_spdm_request->header.param1 !=
           SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
        /* With Requester key verified, we can discard backups. */
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_activate_update_session_data_key[%x] Requester new\n",
                       session_id));
        result = libspdm_activate_update_session_data_key(
            session_info->secured_message_context,
            LIBSPDM_KEY_UPDATE_ACTION_REQUESTER, true);
        if (!result) {
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }
        libspdm_trigger_key_update_callback(
            spdm_context, session_id, LIBSPDM_KEY_UPDATE_OPERATION_COMMIT_UPDATE,
            LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);

        /*clear last_key_update_request*/
        libspdm_zero_mem (prev_spdm_request, sizeof(spdm_key_update_request_t));
        break;
    default:
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "espurious case\n"));
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  spdm_request->header.request_response_code);

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_key_update_response_t));
    *response_size = sizeof(spdm_key_update_response_t);
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_KEY_UPDATE_ACK;
    spdm_response->header.param1 = spdm_request->header.param1;
    spdm_response->header.param2 = spdm_request->header.param2;

    return LIBSPDM_STATUS_SUCCESS;
}
