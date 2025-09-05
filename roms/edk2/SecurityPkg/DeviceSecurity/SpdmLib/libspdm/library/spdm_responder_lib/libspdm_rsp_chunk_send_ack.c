/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP

libspdm_return_t libspdm_get_response_chunk_send(libspdm_context_t *spdm_context,
                                                 size_t request_size,
                                                 const void *request,
                                                 size_t *response_size,
                                                 void *response)
{
    const spdm_chunk_send_request_t *spdm_request;
    spdm_chunk_send_ack_response_t *spdm_response;
    libspdm_chunk_info_t *send_info;
    libspdm_return_t status = LIBSPDM_STATUS_SUCCESS;
    const uint8_t *chunk;
    uint32_t large_message_size;
    uint32_t calc_max_chunk_size;
    uint8_t *scratch_buffer;
    size_t scratch_buffer_size;
    uint8_t* chunk_response;
    size_t chunk_response_size;

    spdm_request = (const spdm_chunk_send_request_t*) request;

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_12) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                                               SPDM_CHUNK_SEND,
                                               response_size, response);
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP)) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
            response_size, response);
    }

    /*chunk mechanism can be used for normal or encap state*/
    if ((spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) &&
        (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP)) {
        return libspdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }

    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES) {
        libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
            response_size, response);
        return LIBSPDM_STATUS_SUCCESS;
    }

    if (request_size < sizeof(spdm_chunk_send_request_t)) {
        libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
        return LIBSPDM_STATUS_SUCCESS;
    }

    if (spdm_request->header.spdm_version < SPDM_MESSAGE_VERSION_12) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_CHUNK_SEND,
            response_size, response);
    }

    if (spdm_request->header.spdm_version
        != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
            response_size, response);
    }

    if (spdm_context->chunk_context.get.chunk_in_use) {
        /* Spec does not support simultanious chunk send and chunk get */
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
            response_size, response);
    }

    send_info = &spdm_context->chunk_context.send;

    if (!send_info->chunk_in_use) {

        if (request_size < sizeof(spdm_chunk_send_request_t) + sizeof(uint32_t)) {
            libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                response_size, response);
            return LIBSPDM_STATUS_SUCCESS;
        }

        large_message_size = *(const uint32_t*) (spdm_request + 1);
        chunk = (((const uint8_t*) (spdm_request + 1)) + sizeof(uint32_t));
        calc_max_chunk_size =
            (uint32_t)request_size - (sizeof(spdm_chunk_send_request_t) + sizeof(uint32_t));

        if (spdm_request->chunk_seq_no != 0
            || (spdm_request->chunk_size
                < SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_12
                - sizeof(spdm_chunk_send_request_t)
                - sizeof(uint32_t))
            || spdm_request->chunk_size > calc_max_chunk_size
            || (uint32_t)request_size > spdm_context->local_context.capability.data_transfer_size
            || large_message_size > spdm_context->local_context.capability.max_spdm_msg_size
            || large_message_size <= SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_12
            || (spdm_request->header.param1 & SPDM_CHUNK_SEND_REQUEST_ATTRIBUTE_LAST_CHUNK)
            ) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        } else {
            libspdm_get_scratch_buffer(spdm_context, (void**) &scratch_buffer,
                                       &scratch_buffer_size);

            send_info->chunk_in_use = true;
            send_info->chunk_handle = spdm_request->header.param2;
            send_info->chunk_seq_no = spdm_request->chunk_seq_no;

            send_info->large_message = scratch_buffer +
                                       libspdm_get_scratch_buffer_large_message_offset(spdm_context);
            send_info->large_message_capacity =
                libspdm_get_scratch_buffer_large_message_capacity(spdm_context);
            send_info->large_message_size = large_message_size;
            send_info->chunk_bytes_transferred = spdm_request->chunk_size;

            libspdm_copy_mem(
                send_info->large_message, send_info->large_message_capacity,
                chunk, spdm_request->chunk_size);
        }
    } else {

        chunk = (const uint8_t*) (spdm_request + 1);
        calc_max_chunk_size =
            (uint32_t)request_size - sizeof(spdm_chunk_send_request_t);

        if (spdm_request->chunk_seq_no != send_info->chunk_seq_no + 1
            || spdm_request->header.param2 != send_info->chunk_handle
            || spdm_request->chunk_size > calc_max_chunk_size
            || spdm_request->chunk_size + send_info->chunk_bytes_transferred
            > send_info->large_message_size) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        } else if ((spdm_request->header.param1 & SPDM_CHUNK_SEND_REQUEST_ATTRIBUTE_LAST_CHUNK)
                   && (spdm_request->chunk_size + send_info->chunk_bytes_transferred
                       != send_info->large_message_size)) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        } else if (!(spdm_request->header.param1 & SPDM_CHUNK_SEND_REQUEST_ATTRIBUTE_LAST_CHUNK)
                   && ((spdm_request->chunk_size + send_info->chunk_bytes_transferred
                        > send_info->large_message_size)
                       || (spdm_request->chunk_size
                           < SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_12
                           - sizeof(spdm_chunk_send_request_t))
                       || ((uint32_t) request_size
                           > spdm_context->local_context.capability.data_transfer_size))) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        } else {

            libspdm_copy_mem(
                (uint8_t*)send_info->large_message + send_info->chunk_bytes_transferred,
                send_info->large_message_size - send_info->chunk_bytes_transferred,
                chunk, spdm_request->chunk_size);

            send_info->chunk_seq_no = spdm_request->chunk_seq_no;
            send_info->chunk_bytes_transferred += spdm_request->chunk_size;
            if (spdm_request->header.param1 & SPDM_CHUNK_SEND_REQUEST_ATTRIBUTE_LAST_CHUNK) {
                send_info->chunk_in_use= false;
            }
        }
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_chunk_send_ack_response_t));

    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_CHUNK_SEND_ACK;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = spdm_request->header.param2; /* handle */
    spdm_response->chunk_seq_no = spdm_request->chunk_seq_no;

    chunk_response = (uint8_t*) (spdm_response + 1);
    chunk_response_size = *response_size - sizeof(spdm_chunk_send_ack_response_t);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        /* Set the EARLY_ERROR_DETECTED bit here, because one of the CHUNK_SEND requests failed.
         * If there is an error after all chunks have been sent by the requester correctly,
         * the responder reflects the error in the ChunkSendAck.ResponseToLargeRequest buffer,
         * and not in the EARLY_ERROR_DETECTED bit. */

        spdm_response->header.param1
            |= SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED;

        libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            &chunk_response_size, chunk_response);

        *response_size = sizeof(spdm_chunk_send_ack_response_t) + chunk_response_size;

        send_info->chunk_in_use = false;
        send_info->chunk_handle = 0;
        send_info->chunk_seq_no = 0;
        send_info->chunk_bytes_transferred = 0;
        send_info->large_message = NULL;
        send_info->large_message_size = 0;
    } else if (send_info->chunk_bytes_transferred == send_info->large_message_size) {
        uint8_t opcode;

        opcode = ((spdm_message_header_t*)send_info->large_message)->request_response_code;
        libspdm_get_spdm_response_func response_func =
            libspdm_get_response_func_via_request_code(opcode);

        if ((response_func != NULL) &&
            (opcode != SPDM_CHUNK_SEND) && (opcode != SPDM_CHUNK_GET)) {
            status = response_func(
                spdm_context,
                send_info->large_message_size, send_info->large_message,
                &chunk_response_size, chunk_response);
        } else {
            status = LIBSPDM_STATUS_SUCCESS;
            libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                &chunk_response_size, chunk_response);
        }

        send_info->chunk_in_use = false;
        send_info->chunk_handle = 0;
        send_info->chunk_seq_no = 0;
        send_info->chunk_bytes_transferred = 0;
        send_info->large_message = NULL;
        send_info->large_message_size = 0;

        *response_size = sizeof(spdm_chunk_send_ack_response_t) + chunk_response_size;
    } else {
        *response_size = sizeof(spdm_chunk_send_ack_response_t);
    }

    return status;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */
