/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP

bool libspdm_verify_psk_finish_req_hmac(libspdm_context_t *spdm_context,
                                        libspdm_session_info_t *session_info,
                                        const uint8_t *hmac, size_t hmac_size)
{
    uint8_t hmac_data[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t *th_curr_data;
    size_t th_curr_data_size;
    libspdm_th_managed_buffer_t th_curr;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
#endif

    hash_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    LIBSPDM_ASSERT(hmac_size == hash_size);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_calculate_th_for_finish(spdm_context, session_info, NULL,
                                             0, NULL, 0, &th_curr);
    if (!result) {
        return false;
    }
    th_curr_data = libspdm_get_managed_buffer(&th_curr);
    th_curr_data_size = libspdm_get_managed_buffer_size(&th_curr);

    result = libspdm_hash_all (spdm_context->connection_info.algorithm.base_hash_algo,
                               th_curr_data, th_curr_data_size, hash_data);
    if (!result) {
        return false;
    }

    result = libspdm_hmac_all_with_request_finished_key(
        session_info->secured_message_context, hash_data,
        hash_size, hmac_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hmac_for_finish_req(
        spdm_context, session_info, &hash_size, hmac_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Calc th_curr hmac - "));
    LIBSPDM_INTERNAL_DUMP_DATA(hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    if (!libspdm_consttime_is_mem_equal(hmac, hmac_data, hash_size)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "!!! verify_psk_finish_req_hmac - FAIL !!!\n"));
        return false;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "!!! verify_psk_finish_req_hmac - PASS !!!\n"));
    return true;
}

libspdm_return_t libspdm_get_response_psk_finish(libspdm_context_t *spdm_context,
                                                 size_t request_size,
                                                 const void *request,
                                                 size_t *response_size,
                                                 void *response)
{
    uint32_t session_id;
    bool result;
    uint32_t hmac_size;
    spdm_psk_finish_response_t *spdm_response;
    libspdm_session_info_t *session_info;
    uint8_t th2_hash_data[LIBSPDM_MAX_HASH_SIZE];
    const spdm_psk_finish_request_t *spdm_request;
    libspdm_return_t status;
    libspdm_session_state_t session_state;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_PSK_FINISH);

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_11) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                                               SPDM_PSK_FINISH,
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
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_PSK_FINISH, response_size, response);
    }
    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
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
    if (!session_info->use_psk) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                                               response_size, response);
    }
    session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (session_state != LIBSPDM_SESSION_STATE_HANDSHAKING) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                                               response_size, response);
    }

    /* remove HMAC*/
    hmac_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    /* this message can only be in secured session
     * thus don't need to consider transport layer padding, just check its exact size */
    if (request_size != sizeof(spdm_psk_finish_request_t) + hmac_size) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  spdm_request->header.request_response_code);

    status = libspdm_append_message_f(spdm_context, session_info, false, request,
                                      request_size - hmac_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_psk_finish_response_t));
    *response_size = sizeof(spdm_psk_finish_response_t);
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_PSK_FINISH_RSP;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    result = libspdm_verify_psk_finish_req_hmac(
        spdm_context, session_info,
        (const uint8_t *)request + sizeof(spdm_psk_finish_request_t),
        hmac_size);
    if (!result) {
        if((spdm_context->handle_error_return_policy &
            LIBSPDM_DATA_HANDLE_ERROR_RETURN_POLICY_DROP_ON_DECRYPT_ERROR) == 0) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_DECRYPT_ERROR, 0,
                response_size, response);
        } else {
            /**
             * just ignore this message
             * return UNSUPPORTED and clear response_size to continue the dispatch without send response
             **/
            *response_size = 0;
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }
    }
    status = libspdm_append_message_f(
        spdm_context, session_info, false,
        (const uint8_t *)request + request_size - hmac_size,
        hmac_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    status = libspdm_append_message_f(spdm_context, session_info, false, spdm_response,
                                      *response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_data_key[%x]\n", session_id));
    result = libspdm_calculate_th2_hash(spdm_context, session_info, false,
                                        th2_hash_data);
    if (!result) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    result = libspdm_generate_session_data_key(
        session_info->secured_message_context, th2_hash_data);
    if (!result) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    #if LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP
    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP)) {
        result = libspdm_start_watchdog(
            session_id, spdm_context->local_context.heartbeat_period * 2);
        if (!result) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                                   response_size, response);
        }
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP */

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */
