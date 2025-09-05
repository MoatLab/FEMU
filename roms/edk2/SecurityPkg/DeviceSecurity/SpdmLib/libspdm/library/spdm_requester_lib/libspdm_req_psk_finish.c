/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} libspdm_psk_finish_request_mine_t;

typedef struct {
    spdm_message_header_t header;
    uint8_t dummy_data[sizeof(spdm_error_data_response_not_ready_t)];
} libspdm_psk_finish_response_max_t;
#pragma pack()

/**
 * This function generates the PSK finish HMAC based upon TH.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_info                  The session info of an SPDM session.
 * @param  hmac                         The buffer to store the finish HMAC.
 *
 * @retval true  PSK finish HMAC is generated.
 * @retval false PSK finish HMAC is not generated.
 **/
bool libspdm_generate_psk_exchange_req_hmac(libspdm_context_t *spdm_context,
                                            libspdm_session_info_t *session_info,
                                            void *hmac)
{
    size_t hash_size;
    uint8_t calc_hmac_data[LIBSPDM_MAX_HASH_SIZE];
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t *th_curr_data;
    size_t th_curr_data_size;
    libspdm_th_managed_buffer_t th_curr;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
#endif

    hash_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);

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
        hash_size, calc_hmac_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hmac_for_finish_req(
        spdm_context, session_info, &hash_size, calc_hmac_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hmac - "));
    LIBSPDM_INTERNAL_DUMP_DATA(calc_hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    libspdm_copy_mem(hmac, hash_size, calc_hmac_data, hash_size);

    return true;
}

/**
 * This function sends PSK_FINISH and receives PSK_FINISH_RSP for SPDM PSK finish.
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    session_id to the PSK_FINISH request.
 *
 * @retval RETURN_SUCCESS               The PSK_FINISH is sent and the PSK_FINISH_RSP is received.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 **/
static libspdm_return_t libspdm_try_send_receive_psk_finish(libspdm_context_t *spdm_context,
                                                            uint32_t session_id)
{
    libspdm_return_t status;
    libspdm_psk_finish_request_mine_t *spdm_request;
    size_t spdm_request_size;
    size_t hmac_size;
    libspdm_psk_finish_response_max_t *spdm_response;
    size_t spdm_response_size;
    libspdm_session_info_t *session_info;
    uint8_t th2_hash_data[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_state_t session_state;
    bool result;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_11) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
        status = LIBSPDM_STATUS_UNSUPPORTED_CAP;
        goto error;
    }

    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        status = LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        goto error;
    }

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        LIBSPDM_ASSERT(false);
        status = LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        goto error;
    }
    session_state = libspdm_secured_message_get_session_state(
        session_info->secured_message_context);
    if (session_state != LIBSPDM_SESSION_STATE_HANDSHAKING) {
        status = LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        goto error;
    }

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

    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_PSK_FINISH;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;

    hmac_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    spdm_request_size = sizeof(spdm_psk_finish_request_t) + hmac_size;

    status = libspdm_append_message_f(spdm_context, session_info, true, (uint8_t *)spdm_request,
                                      spdm_request_size - hmac_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        goto error;
    }

    result = libspdm_generate_psk_exchange_req_hmac(spdm_context, session_info,
                                                    spdm_request->verify_data);
    if (!result) {
        libspdm_release_sender_buffer (spdm_context);
        status = LIBSPDM_STATUS_CRYPTO_ERROR;
        goto error;
    }

    status = libspdm_append_message_f(spdm_context, session_info, true,
                                      (uint8_t *)spdm_request +
                                      spdm_request_size - hmac_size,
                                      hmac_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        goto error;
    }

    status = libspdm_send_spdm_request(spdm_context, &session_id,
                                       spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        goto error;
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  SPDM_PSK_FINISH);

    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* receive */

    status = libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto error;
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
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        if (spdm_response->header.param1 == SPDM_ERROR_CODE_DECRYPT_ERROR) {
            status = LIBSPDM_STATUS_SESSION_MSG_ERROR;
            goto receive_done;
        }
        status = libspdm_handle_error_response_main(
            spdm_context, &session_id,
            &spdm_response_size, (void **)&spdm_response,
            SPDM_PSK_FINISH, SPDM_PSK_FINISH_RSP);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code !=
               SPDM_PSK_FINISH_RSP) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    /* this message can only be in secured session
     * thus don't need to consider transport layer padding, just check its exact size */
    if (spdm_response_size != sizeof(spdm_psk_finish_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    status = libspdm_append_message_f(spdm_context, session_info, true, spdm_response,
                                      spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_data_key[%x]\n", session_id));
    result = libspdm_calculate_th2_hash(spdm_context, session_info, true,
                                        th2_hash_data);
    if (!result) {
        status = LIBSPDM_STATUS_CRYPTO_ERROR;
        goto receive_done;
    }
    result = libspdm_generate_session_data_key(
        session_info->secured_message_context, th2_hash_data);
    if (!result) {
        status = LIBSPDM_STATUS_CRYPTO_ERROR;
        goto receive_done;
    }

    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    /* -=[Log Message Phase]=- */
    #if LIBSPDM_ENABLE_MSG_LOG
    libspdm_append_msg_log(spdm_context, spdm_response, spdm_response_size);
    #endif /* LIBSPDM_ENABLE_MSG_LOG */

    libspdm_release_receiver_buffer (spdm_context);
    return LIBSPDM_STATUS_SUCCESS;

receive_done:
    libspdm_release_receiver_buffer (spdm_context);
error:
    if (LIBSPDM_STATUS_BUSY_PEER != status) {
        libspdm_free_session_id(spdm_context, session_id);
    }
    return status;
}

libspdm_return_t libspdm_send_receive_psk_finish(libspdm_context_t *spdm_context,
                                                 uint32_t session_id)
{
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;

    spdm_context->crypto_request = true;
    retry = spdm_context->retry_times;
    retry_delay_time = spdm_context->retry_delay_time;
    do {
        status = libspdm_try_send_receive_psk_finish(spdm_context,
                                                     session_id);
        if ((status != LIBSPDM_STATUS_BUSY_PEER) || (retry == 0)) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/
