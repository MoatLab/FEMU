/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

/**
 * Return the GET_SPDM_RESPONSE function via request code.
 *
 * @param  request_code                  The SPDM request code.
 *
 * @return GET_SPDM_RESPONSE function according to the request code.
 **/
libspdm_get_spdm_response_func libspdm_get_response_func_via_request_code(uint8_t request_code)
{
    size_t index;

    typedef struct {
        uint8_t request_response_code;
        libspdm_get_spdm_response_func get_response_func;
    } libspdm_get_response_struct_t;

    libspdm_get_response_struct_t get_response_struct[] = {
        { SPDM_GET_VERSION, libspdm_get_response_version },
        { SPDM_GET_CAPABILITIES, libspdm_get_response_capabilities },
        { SPDM_NEGOTIATE_ALGORITHMS, libspdm_get_response_algorithms },

        #if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
        { SPDM_GET_DIGESTS, libspdm_get_response_digests },
        { SPDM_GET_CERTIFICATE, libspdm_get_response_certificate },
        #endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP */

        #if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
        { SPDM_CHALLENGE, libspdm_get_response_challenge_auth },
        #endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/

        #if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
        { SPDM_GET_MEASUREMENTS, libspdm_get_response_measurements },
        #endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

        #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
        { SPDM_KEY_EXCHANGE, libspdm_get_response_key_exchange },
        #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

        #if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
        { SPDM_PSK_EXCHANGE, libspdm_get_response_psk_exchange },
        #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/

        #if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
        { SPDM_GET_ENCAPSULATED_REQUEST, libspdm_get_response_encapsulated_request },
        { SPDM_DELIVER_ENCAPSULATED_RESPONSE, libspdm_get_response_encapsulated_response_ack },
        #endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */

        #if LIBSPDM_RESPOND_IF_READY_SUPPORT
        { SPDM_RESPOND_IF_READY, libspdm_get_response_respond_if_ready },
        #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

        #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
        { SPDM_FINISH, libspdm_get_response_finish },
        #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

        #if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
        { SPDM_PSK_FINISH, libspdm_get_response_psk_finish },
        #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/

        #if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
        { SPDM_END_SESSION, libspdm_get_response_end_session },
        { SPDM_HEARTBEAT, libspdm_get_response_heartbeat },
        { SPDM_KEY_UPDATE, libspdm_get_response_key_update },
        #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/

        #if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
        { SPDM_GET_CSR, libspdm_get_response_csr },
        #endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP*/

        #if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
        { SPDM_SET_CERTIFICATE, libspdm_get_response_set_certificate },
        #endif /*LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP*/

        #if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
        { SPDM_CHUNK_GET, libspdm_get_response_chunk_get},
        { SPDM_CHUNK_SEND, libspdm_get_response_chunk_send},
        #endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

        #if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
        { SPDM_SUPPORTED_EVENT_TYPES, libspdm_get_response_supported_event_types },
        #endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */

        #if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
        { SPDM_VENDOR_DEFINED_REQUEST, libspdm_get_vendor_defined_response },
        #endif /*LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES*/
    };

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(get_response_struct); index++) {
        if (request_code == get_response_struct[index].request_response_code) {
            return get_response_struct[index].get_response_func;
        }
    }
    return NULL;
}

/**
 * Return the GET_SPDM_RESPONSE function via last request.
 *
 * @param  spdm_context                  The SPDM context for the device.
 *
 * @return GET_SPDM_RESPONSE function according to the last request.
 **/
static libspdm_get_spdm_response_func libspdm_get_response_func_via_last_request(
    libspdm_context_t *spdm_context)
{
    spdm_message_header_t *spdm_request;

    spdm_request = (void *)spdm_context->last_spdm_request;
    return libspdm_get_response_func_via_request_code(spdm_request->request_response_code);
}

/**
 * Process a SPDM request from a device.
 *
 * @param  spdm_context                  The SPDM context for the device.
 * @param  session_id                    Indicate if the request is a secured message.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  request_size                  size in bytes of the request data buffer.
 * @param  request                      A pointer to a destination buffer to store the request.
 *                                     The caller is responsible for having
 *                                     either implicit or explicit ownership of the buffer.
 *
 * @retval RETURN_SUCCESS               The SPDM request is received successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM request is received from the device.
 **/
libspdm_return_t libspdm_process_request(void *spdm_context, uint32_t **session_id,
                                         bool *is_app_message,
                                         size_t request_size, void *request)
{
    libspdm_context_t *context;
    void *temp_session_context;
    libspdm_return_t status;
    libspdm_session_info_t *session_info;
    uint32_t *message_session_id;
    uint8_t *decoded_message_ptr;
    size_t decoded_message_size;
    uint8_t *backup_decoded_message_ptr;
    size_t backup_decoded_message_size;
    bool result;
    bool reset_key_update;

    context = spdm_context;
    size_t transport_header_size;
    uint8_t *scratch_buffer;
    size_t scratch_buffer_size;

    if (request == NULL) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
    if (request_size == 0) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SpdmReceiveRequest[.] ...\n"));

    message_session_id = NULL;
    context->last_spdm_request_session_id_valid = false;
    context->last_spdm_request_size =
        libspdm_get_scratch_buffer_last_spdm_request_capacity(context);

    /* always use scratch buffer to response.
     * if it is secured message, this scratch buffer will be used.
     * if it is normal message, the response ptr will point to receiver buffer. */
    transport_header_size = context->local_context.capability.transport_header_size;
    libspdm_get_scratch_buffer (context, (void **)&scratch_buffer, &scratch_buffer_size);
    #if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
    decoded_message_ptr = scratch_buffer +
                          libspdm_get_scratch_buffer_secure_message_offset(context) +
                          transport_header_size;
    decoded_message_size = libspdm_get_scratch_buffer_secure_message_capacity(context) -
                           transport_header_size;
    #else
    decoded_message_ptr = scratch_buffer + transport_header_size;
    decoded_message_size = scratch_buffer_size - transport_header_size;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

    backup_decoded_message_ptr = decoded_message_ptr;
    backup_decoded_message_size = decoded_message_size;

    status = context->transport_decode_message(
        context, &message_session_id, is_app_message, true,
        request_size, request, &decoded_message_size,
        (void **)&decoded_message_ptr);

    reset_key_update = false;
    temp_session_context = NULL;

    if (status == LIBSPDM_STATUS_SESSION_TRY_DISCARD_KEY_UPDATE) {
        /* Failed to decode, but have backup keys. Try rolling back before aborting.
         * message_session_id must be valid for us to have attempted decryption. */
        if (message_session_id == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        temp_session_context = libspdm_get_secured_message_context_via_session_id(
            context, *message_session_id);
        if (temp_session_context == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }

        result = libspdm_activate_update_session_data_key(
            temp_session_context, LIBSPDM_KEY_UPDATE_ACTION_REQUESTER, false);
        if (!result) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        libspdm_trigger_key_update_callback(
            context, *message_session_id,
            LIBSPDM_KEY_UPDATE_OPERATION_DISCARD_UPDATE,
            LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);

        /* Retry decoding message with backup Requester key.
         * Must reset some of the parameters in case they were modified */
        message_session_id = NULL;
        decoded_message_ptr = backup_decoded_message_ptr;
        decoded_message_size = backup_decoded_message_size;
        status = context->transport_decode_message(
            context, &message_session_id, is_app_message, true,
            request_size, request, &decoded_message_size,
            (void **)&decoded_message_ptr);

        reset_key_update = true;
    }

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "transport_decode_message : %xu\n", status));
        if (context->last_spdm_error.error_code != 0) {

            /* If the SPDM error code is Non-Zero, that means we need send the error message back to requester.
             * In this case, we need return SUCCESS and let caller invoke libspdm_build_response() to send an ERROR message.*/

            *session_id = &context->last_spdm_error.session_id;
            *is_app_message = false;
            return LIBSPDM_STATUS_SUCCESS;
        }
        return status;
    }

    /* Handle special case for bi-directional communication:
     * If the Requester returns RESPONSE_NOT_READY error to KEY_UPDATE, the Responder needs
     * to activate backup key to parse the error. Then later the Requester will return SUCCESS,
     * the Responder needs new key. So we need to restore the environment by
     * libspdm_create_update_session_data_key() again.*/
    if (reset_key_update) {
        /* temp_session_context and message_session_id must necessarily
         * be valid for us to reach here. */
        if (temp_session_context == NULL || message_session_id == NULL) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        result = libspdm_create_update_session_data_key(
            temp_session_context, LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);
        if (!result) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        libspdm_trigger_key_update_callback(
            context, *message_session_id,
            LIBSPDM_KEY_UPDATE_OPERATION_CREATE_UPDATE,
            LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);
    }

    context->last_spdm_request_size = decoded_message_size;
    libspdm_copy_mem (context->last_spdm_request,
                      libspdm_get_scratch_buffer_last_spdm_request_capacity(context),
                      decoded_message_ptr,
                      decoded_message_size);

    if (!(*is_app_message)) {
        /* Check for minimal SPDM message size. */
        if (context->last_spdm_request_size < sizeof(spdm_message_header_t)) {
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }
    }

    *session_id = message_session_id;

    if (message_session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(context, *message_session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }
        context->last_spdm_request_session_id = *message_session_id;
        context->last_spdm_request_session_id_valid = true;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SpdmReceiveRequest[%x] msg %s(0x%x), size (0x%zx): \n",
                   (message_session_id != NULL) ? *message_session_id : 0,
                   libspdm_get_code_str(((spdm_message_header_t *)context->last_spdm_request)->
                                        request_response_code),
                   ((spdm_message_header_t *)context->last_spdm_request)->request_response_code,
                   context->last_spdm_request_size));
    LIBSPDM_INTERNAL_DUMP_HEX((uint8_t *)context->last_spdm_request,
                              context->last_spdm_request_size);

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Notify the session state to a session APP.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    The session_id of a session.
 * @param  session_state                 The state of a session.
 **/
static void libspdm_trigger_session_state_callback(libspdm_context_t *spdm_context,
                                                   uint32_t session_id,
                                                   libspdm_session_state_t session_state)
{
    if (spdm_context->spdm_session_state_callback != NULL) {
        ((libspdm_session_state_callback_func)
         spdm_context->spdm_session_state_callback)(spdm_context, session_id, session_state);
    }
}

/**
 * Set session_state to an SPDM secured message context and trigger callback.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicate the SPDM session ID.
 * @param  session_state                 Indicate the SPDM session state.
 */
void libspdm_set_session_state(libspdm_context_t *spdm_context,
                               uint32_t session_id,
                               libspdm_session_state_t session_state)
{
    libspdm_session_info_t *session_info;
    libspdm_session_state_t old_session_state;

    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        LIBSPDM_ASSERT(false);
        return;
    }

    old_session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (old_session_state != session_state) {
        libspdm_secured_message_set_session_state(
            session_info->secured_message_context, session_state);
        libspdm_trigger_session_state_callback(
            spdm_context, session_info->session_id, session_state);
    }
}

/**
 * Notify the connection state to an SPDM context register.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  connection_state              Indicate the SPDM connection state.
 **/
static void libspdm_trigger_connection_state_callback(libspdm_context_t *spdm_context,
                                                      const libspdm_connection_state_t
                                                      connection_state)
{
    if (spdm_context->spdm_connection_state_callback != NULL) {
        ((libspdm_connection_state_callback_func)
         spdm_context->spdm_connection_state_callback)(spdm_context, connection_state);
    }
}

/**
 * Set connection_state to an SPDM context and trigger callback.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  connection_state              Indicate the SPDM connection state.
 */
void libspdm_set_connection_state(libspdm_context_t *spdm_context,
                                  libspdm_connection_state_t connection_state)
{
    if (spdm_context->connection_info.connection_state != connection_state) {
        spdm_context->connection_info.connection_state = connection_state;
        libspdm_trigger_connection_state_callback(spdm_context, connection_state);
    }
}

void libspdm_trigger_key_update_callback(void *spdm_context, uint32_t session_id,
                                         libspdm_key_update_operation_t key_update_op,
                                         libspdm_key_update_action_t key_update_action)
{
    libspdm_context_t *context;

    context = spdm_context;
    if (context->spdm_key_update_callback != NULL) {
        ((libspdm_key_update_callback_func)
         context->spdm_key_update_callback)(context, session_id, key_update_op,
                                            key_update_action);
    }
}

/**
 * Build a SPDM response to a device.
 *
 * @param  spdm_context                  The SPDM context for the device.
 * @param  session_id                    Indicate if the response is a secured message.
 *                                     If session_id is NULL, it is a normal message.
 *                                     If session_id is NOT NULL, it is a secured message.
 * @param  is_app_message                 Indicates if it is an APP message or SPDM message.
 * @param  response_size                 size in bytes of the response data buffer.
 * @param  response                     A pointer to a destination buffer to store the response.
 *                                     The caller is responsible for having
 *                                     either implicit or explicit ownership of the buffer.
 *
 * @retval RETURN_SUCCESS               The SPDM response is sent successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM response is sent to the device.
 * @retval RETURN_UNSUPPORTED           Just ignore this message: return UNSUPPORTED and clear response_size.
 *                                      Continue the dispatch without send response.
 **/
libspdm_return_t libspdm_build_response(void *spdm_context, const uint32_t *session_id,
                                        bool is_app_message,
                                        size_t *response_size,
                                        void **response)
{
    libspdm_context_t *context;
    uint8_t *my_response;
    size_t my_response_size;
    libspdm_return_t status;
    libspdm_get_spdm_response_func get_response_func;
    libspdm_session_info_t *session_info;
    spdm_message_header_t *spdm_request;
    spdm_message_header_t *spdm_response;
    size_t transport_header_size;
    uint8_t *scratch_buffer;
    size_t scratch_buffer_size;
    uint8_t request_response_code;
    uint32_t actual_size;

    #if LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP
    bool result;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP */

    #if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
    uint8_t *large_buffer;
    size_t large_buffer_size;
    libspdm_chunk_info_t* get_info;
    spdm_chunk_response_response_t *chunk_rsp;
    uint8_t *chunk_ptr;
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

    context = spdm_context;
    status = LIBSPDM_STATUS_UNSUPPORTED_CAP;

    /* For secure message, setup my_response to scratch buffer
     * For non-secure message, setup my_response to sender buffer*/
    transport_header_size = context->local_context.capability.transport_header_size;
    if (session_id != NULL) {
        libspdm_get_scratch_buffer (context, (void **)&scratch_buffer, &scratch_buffer_size);
        #if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
        my_response = scratch_buffer + libspdm_get_scratch_buffer_secure_message_offset(context) +
                      transport_header_size;
        my_response_size = libspdm_get_scratch_buffer_secure_message_capacity(context) -
                           transport_header_size -
                           context->local_context.capability.transport_tail_size;
        #else
        my_response = scratch_buffer + transport_header_size;
        my_response_size = scratch_buffer_size - transport_header_size -
                           context->local_context.capability.transport_tail_size;
        #endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */
    } else {
        my_response = (uint8_t *)*response + transport_header_size;
        my_response_size = *response_size - transport_header_size -
                           context->local_context.capability.transport_tail_size;
    }
    libspdm_zero_mem(my_response, my_response_size);

    spdm_response = (void *)my_response;

    if (context->last_spdm_error.error_code != 0) {

        /* Error in libspdm_process_request(), and we need send error message directly.*/

        switch (context->last_spdm_error.error_code) {
        case SPDM_ERROR_CODE_DECRYPT_ERROR:
            /* session ID is valid. Use it to encrypt the error message.*/
            if((context->handle_error_return_policy &
                LIBSPDM_DATA_HANDLE_ERROR_RETURN_POLICY_DROP_ON_DECRYPT_ERROR) == 0) {
                status = libspdm_generate_error_response(
                    context, SPDM_ERROR_CODE_DECRYPT_ERROR, 0,
                    &my_response_size, my_response);
            } else {
                /**
                 * just ignore this message
                 * return UNSUPPORTED and clear response_size to continue the dispatch without send response
                 **/
                *response_size = 0;
                status = LIBSPDM_STATUS_UNSUPPORTED_CAP;
            }
            break;
        case SPDM_ERROR_CODE_INVALID_SESSION:
            /**
             * don't use session ID, because we dont know which right session ID should be used.
             * just ignore this message
             * return UNSUPPORTED and clear response_size to continue the dispatch without send response
             **/
            *response_size = 0;
            status = LIBSPDM_STATUS_UNSUPPORTED_CAP;
            break;
        default:
            LIBSPDM_ASSERT(false);
            status = LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }

        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            if ((session_id != NULL) &&
                (context->last_spdm_error.error_code == SPDM_ERROR_CODE_DECRYPT_ERROR)) {
                libspdm_free_session_id(context, *session_id);
            }
            return status;
        }

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SpdmSendResponse[%x]: msg %s(0x%x), size (0x%zx): \n",
                       (session_id != NULL) ? *session_id : 0,
                       libspdm_get_code_str(spdm_response->request_response_code),
                       spdm_response->request_response_code,
                       my_response_size));
        LIBSPDM_INTERNAL_DUMP_HEX(my_response, my_response_size);

        status = context->transport_encode_message(
            context, session_id, false, false,
            my_response_size, my_response, response_size, response);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            if ((session_id != NULL) &&
                ((status == LIBSPDM_STATUS_SEQUENCE_NUMBER_OVERFLOW) ||
                 (status == LIBSPDM_STATUS_CRYPTO_ERROR))) {
                libspdm_free_session_id(context, *session_id);
            }
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "transport_encode_message : %xu\n", status));
            return status;
        }

        if ((session_id != NULL) &&
            (context->last_spdm_error.error_code == SPDM_ERROR_CODE_DECRYPT_ERROR)) {
            libspdm_free_session_id(context, *session_id);
        }

        libspdm_zero_mem(&context->last_spdm_error, sizeof(context->last_spdm_error));
        return LIBSPDM_STATUS_SUCCESS;
    }

    if (session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(context, *session_id);
        if (session_info == NULL) {
            LIBSPDM_ASSERT(false);
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }
    }

    if (*response == NULL) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
    if (response_size == NULL) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }
    if (*response_size == 0) {
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SpdmSendResponse[%x] ...\n",
                   (session_id != NULL) ? *session_id : 0));

    spdm_request = (void *)context->last_spdm_request;
    if (context->last_spdm_request_size == 0) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    get_response_func = NULL;
    if (!is_app_message) {
        get_response_func = libspdm_get_response_func_via_last_request(context);

        #if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
        /* If responder is expecting chunk_get or chunk_send requests
         * and gets other requests instead, drop out of chunking mode */
        if (context->chunk_context.get.chunk_in_use
            && get_response_func != libspdm_get_response_chunk_get) {

            context->chunk_context.get.chunk_in_use = false;
            context->chunk_context.get.chunk_handle++; /* implicit wrap - around to 0. */
            context->chunk_context.get.chunk_seq_no = 0;

            context->chunk_context.get.large_message = NULL;
            context->chunk_context.get.large_message_size = 0;
            context->chunk_context.get.chunk_bytes_transferred = 0;
        }
        if (context->chunk_context.send.chunk_in_use
            && get_response_func != libspdm_get_response_chunk_send) {

            context->chunk_context.send.chunk_in_use = false;
            context->chunk_context.send.chunk_handle = 0;
            context->chunk_context.send.chunk_seq_no = 0;

            context->chunk_context.send.large_message = NULL;
            context->chunk_context.send.large_message_size = 0;
            context->chunk_context.send.chunk_bytes_transferred = 0;
        }
        #endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

        if (get_response_func != NULL) {
            status = get_response_func(
                context,
                context->last_spdm_request_size,
                context->last_spdm_request,
                &my_response_size, my_response);
        }
    }
    if (is_app_message || (get_response_func == NULL)) {
        if (context->get_response_func != NULL) {
            status = ((libspdm_get_response_func) context->get_response_func)(
                context, session_id, is_app_message,
                context->last_spdm_request_size,
                context->last_spdm_request,
                &my_response_size, my_response);
        } else {
            status = LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }
    }

    if (status == LIBSPDM_STATUS_SUCCESS) {
        LIBSPDM_ASSERT (my_response_size <= context->local_context.capability.max_spdm_msg_size);
        /* large SPDM message is the SPDM message whose size is greater than the DataTransferSize of the receiving
         * SPDM endpoint or greater than the transmit buffer size of the sending SPDM endpoint */
        if ((context->connection_info.capability.max_spdm_msg_size != 0) &&
            (my_response_size > context->connection_info.capability.max_spdm_msg_size)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "my_response_size > req max_spdm_msg_size\n"));
            actual_size = (uint32_t)my_response_size;
            status = libspdm_generate_extended_error_response(context,
                                                              SPDM_ERROR_CODE_RESPONSE_TOO_LARGE,
                                                              0,
                                                              sizeof(uint32_t),
                                                              (uint8_t *)&actual_size,
                                                              &my_response_size, my_response);
        } else if ((((context->connection_info.capability.data_transfer_size != 0) &&
                     (my_response_size > context->connection_info.capability.data_transfer_size)) ||
                    ((context->local_context.capability.sender_data_transfer_size != 0) &&
                     (my_response_size >
                      context->local_context.capability.sender_data_transfer_size))) &&
                   libspdm_is_capabilities_flag_supported(
                       context, false, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP,
                       SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP)) {
            #if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP

            get_info = &context->chunk_context.get;

            /* Saving multiple large responses is not an expected use case.
             * Therefore, if the requester did not perform chunk_get requests for
             * previous large responses, they will be lost. */
            if (get_info->chunk_in_use) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                               "Warning: Overwriting previous unrequested chunk_get info.\n"));
            }

            libspdm_get_scratch_buffer(context, (void **)&scratch_buffer, &scratch_buffer_size);

            /* The first section of the scratch
             * buffer may be used for other purposes. Use only after that section. */

            large_buffer = (uint8_t*)scratch_buffer +
                           libspdm_get_scratch_buffer_large_message_offset(spdm_context);
            large_buffer_size = libspdm_get_scratch_buffer_large_message_capacity(spdm_context);

            get_info->chunk_in_use = true;
            /* Increment chunk_handle here as opposed to end of chunk_get handler
             * in case requester never issues chunk_get. */
            get_info->chunk_handle++;
            get_info->chunk_seq_no = 0;
            get_info->chunk_bytes_transferred = 0;

            libspdm_zero_mem(large_buffer, large_buffer_size);

            /* It's possible that the large response that was to be sent to the requester was
             * a CHUNK_SEND_ACK + non-chunk response. In this case, to prevent chunking within
             * chunking, only send back the actual response, by saving only non-chunk portion
             * in the scratch buffer, used to respond to the next CHUNK_GET request. */
            if (((spdm_message_header_t*) my_response)
                ->request_response_code == SPDM_CHUNK_SEND_ACK) {
                libspdm_copy_mem(large_buffer, large_buffer_size,
                                 my_response + sizeof(spdm_chunk_send_ack_response_t),
                                 my_response_size - sizeof(spdm_chunk_send_ack_response_t));

                get_info->large_message = large_buffer;
                get_info->large_message_size =
                    my_response_size - sizeof(spdm_chunk_send_ack_response_t);
            } else {
                libspdm_copy_mem(large_buffer, large_buffer_size,
                                 my_response, my_response_size);

                get_info->large_message = large_buffer;
                get_info->large_message_size = my_response_size;
            }

            status = libspdm_generate_extended_error_response(context,
                                                              SPDM_ERROR_CODE_LARGE_RESPONSE, 0,
                                                              sizeof(uint8_t),
                                                              &get_info->chunk_handle,
                                                              &my_response_size, my_response);
            #else
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "Warning: Could not save chunk. Scratch buffer too small.\n"));

            status = libspdm_generate_extended_error_response(context,
                                                              SPDM_ERROR_CODE_LARGE_RESPONSE,
                                                              0, 0, NULL,
                                                              &my_response_size, my_response);
            #endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }
        }
    }

    /* if return the status: Responder drop the response
     * just ignore this message
     * return UNSUPPORTED and clear response_size to continue the dispatch without send response.*/
    if((my_response_size == 0) && (status == LIBSPDM_STATUS_UNSUPPORTED_CAP)) {
        *response_size = 0;
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        status = libspdm_generate_error_response(
            context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            spdm_request->request_response_code, &my_response_size,
            my_response);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SpdmSendResponse[%x]: msg %s(0x%x), size (0x%zx): \n",
                   (session_id != NULL) ? *session_id : 0,
                   libspdm_get_code_str(spdm_response->request_response_code),
                   spdm_response->request_response_code,
                   my_response_size));
    LIBSPDM_INTERNAL_DUMP_HEX(my_response, my_response_size);

    status = context->transport_encode_message(
        context, session_id, is_app_message, false,
        my_response_size, my_response, response_size, response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        if ((session_id != NULL) &&
            ((status == LIBSPDM_STATUS_SEQUENCE_NUMBER_OVERFLOW) ||
             (status == LIBSPDM_STATUS_CRYPTO_ERROR))) {
            libspdm_free_session_id(context, *session_id);
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "transport_encode_message : %xu\n", status));
        return status;
    }

    request_response_code = spdm_response->request_response_code;
    #if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
    switch (request_response_code) {
    case SPDM_CHUNK_SEND_ACK:
        if (my_response_size > sizeof(spdm_chunk_send_ack_response_t)) {
            request_response_code =
                ((spdm_message_header_t*)(my_response + sizeof(spdm_chunk_send_ack_response_t)))
                ->request_response_code;
        }
        break;
    case SPDM_CHUNK_RESPONSE:
        chunk_rsp = (spdm_chunk_response_response_t *)my_response;
        chunk_ptr = (uint8_t*) (((uint32_t*) (chunk_rsp + 1)) + 1);
        if (chunk_rsp->chunk_seq_no == 0) {
            request_response_code = ((spdm_message_header_t*)chunk_ptr)->request_response_code;
        }
        break;
    default:
        break;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

    if (session_id != NULL) {
        switch (request_response_code) {
        case SPDM_FINISH_RSP:
            if (!libspdm_is_capabilities_flag_supported(
                    context, false,
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
                    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
                libspdm_set_session_state(
                    context, *session_id,
                    LIBSPDM_SESSION_STATE_ESTABLISHED);
            }
            break;
        case SPDM_PSK_FINISH_RSP:
            libspdm_set_session_state(context, *session_id,
                                      LIBSPDM_SESSION_STATE_ESTABLISHED);
            break;
        case SPDM_END_SESSION_ACK:
            libspdm_set_session_state(context, *session_id,
                                      LIBSPDM_SESSION_STATE_NOT_STARTED);
            #if LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP
            if (libspdm_is_capabilities_flag_supported(
                    context, false,
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP,
                    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP)) {
                result = libspdm_stop_watchdog(*session_id);
                if (!result) {
                    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_stop_watchdog error\n"));
                    /* No need to return error for internal watchdog error. */
                }
            }
            #endif /* LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP */
            libspdm_free_session_id(context, *session_id);
            break;
        default:
            #if LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP
            if (libspdm_is_capabilities_flag_supported(
                    context, false,
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP,
                    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP)) {
                /* reset watchdog in any session messages. */
                result = libspdm_reset_watchdog(*session_id);
                if (!result) {
                    LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_reset_watchdog error\n"));
                    /* No need to return error for internal watchdog error. */
                }
            }
            #endif /* LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP */
            break;
        }
    } else {
        switch (request_response_code) {
        case SPDM_FINISH_RSP:
            if (libspdm_is_capabilities_flag_supported(
                    context, false,
                    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
                    SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
                libspdm_set_session_state(
                    context,
                    context->latest_session_id,
                    LIBSPDM_SESSION_STATE_ESTABLISHED);
            }
            break;
        default:
            /* No session state update needed */
            break;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

void libspdm_register_get_response_func(void *context, libspdm_get_response_func get_response_func)
{
    libspdm_context_t *spdm_context;

    spdm_context = context;
    spdm_context->get_response_func = (void *)get_response_func;
}

void libspdm_register_session_state_callback_func(
    void *spdm_context,
    libspdm_session_state_callback_func spdm_session_state_callback)
{
    libspdm_context_t *context;

    LIBSPDM_ASSERT(spdm_context != NULL);

    context = spdm_context;

    context->spdm_session_state_callback = (void *)spdm_session_state_callback;
}

void libspdm_register_connection_state_callback_func(
    void *spdm_context,
    libspdm_connection_state_callback_func spdm_connection_state_callback)
{
    libspdm_context_t *context;

    LIBSPDM_ASSERT(spdm_context != NULL);

    context = spdm_context;
    context->spdm_connection_state_callback = (void *)spdm_connection_state_callback;
}

void libspdm_register_key_update_callback_func(
    void *spdm_context, libspdm_key_update_callback_func spdm_key_update_callback)
{
    libspdm_context_t *context;

    LIBSPDM_ASSERT(spdm_context != NULL);

    context = spdm_context;
    context->spdm_key_update_callback = (void *)spdm_key_update_callback;
}

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && \
    (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)
void libspdm_register_cert_chain_buffer(
    void *spdm_context, void *cert_chain_buffer, size_t cert_chain_buffer_max_size)
{
    libspdm_context_t *context;

    LIBSPDM_ASSERT(spdm_context != NULL);

    context = spdm_context;
    context->mut_auth_cert_chain_buffer = cert_chain_buffer;
    context->mut_auth_cert_chain_buffer_max_size = cert_chain_buffer_max_size;
    context->mut_auth_cert_chain_buffer_size = 0;
}
#endif
