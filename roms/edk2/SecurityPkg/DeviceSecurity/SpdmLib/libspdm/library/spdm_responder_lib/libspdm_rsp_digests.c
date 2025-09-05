/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

libspdm_return_t libspdm_get_response_digests(libspdm_context_t *spdm_context, size_t request_size,
                                              const void *request,
                                              size_t *response_size,
                                              void *response)
{
    const spdm_get_digest_request_t *spdm_request;
    spdm_digest_response_t *spdm_response;
    size_t index;
    bool no_local_cert_chain;
    uint32_t hash_size;
    uint8_t *digest;
    libspdm_return_t status;
    bool result;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    /*total populated slot count*/
    uint8_t slot_count;
    /*populated slot index*/
    uint8_t slot_index;
    size_t additional_size;
    spdm_key_pair_id_t *key_pair_id;
    spdm_certificate_info_t *cert_info;
    spdm_key_usage_bit_mask_t *key_usage_bit_mask;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_GET_DIGESTS);

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
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_DIGESTS, response_size, response);
    }
    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }
    session_info = NULL;
    if (spdm_context->last_spdm_request_session_id_valid) {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context,
            spdm_context->last_spdm_request_session_id);
        if (session_info == NULL) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
    }

    if (request_size < sizeof(spdm_get_digest_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  spdm_request->header.request_response_code);

    no_local_cert_chain = true;
    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        if (spdm_context->local_context
            .local_cert_chain_provision[index] != NULL) {
            no_local_cert_chain = false;
        }
    }
    if (no_local_cert_chain) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
            0, response_size, response);
    }

    hash_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);

    slot_count = libspdm_get_cert_slot_count(spdm_context);
    additional_size = 0;
    if ((spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) &&
        spdm_context->connection_info.multi_key_conn_rsp) {
        additional_size = sizeof(spdm_key_pair_id_t) + sizeof(spdm_certificate_info_t) +
                          sizeof(spdm_key_usage_bit_mask_t);
    }
    LIBSPDM_ASSERT(*response_size >=
                   sizeof(spdm_digest_response_t) + (hash_size + additional_size) * slot_count);
    *response_size = sizeof(spdm_digest_response_t) + (hash_size + additional_size) * slot_count;
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_DIGESTS;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        spdm_response->header.param1 = spdm_context->local_context.local_supported_slot_mask;
    }

    digest = (void *)(spdm_response + 1);
    key_pair_id = (spdm_key_pair_id_t *)((uint8_t *)digest + hash_size * slot_count);
    cert_info = (spdm_certificate_info_t *)((uint8_t *)key_pair_id +
                                            sizeof(spdm_key_pair_id_t) * slot_count);
    key_usage_bit_mask = (spdm_key_usage_bit_mask_t *)((uint8_t *)cert_info +
                                                       sizeof(spdm_certificate_info_t) *
                                                       slot_count);

    slot_index = 0;
    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        if (spdm_context->local_context
            .local_cert_chain_provision[index] != NULL) {
            spdm_response->header.param2 |= (1 << index);
            result = libspdm_generate_cert_chain_hash(spdm_context, index,
                                                      &digest[hash_size * slot_index]);
            if ((spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) &&
                spdm_context->connection_info.multi_key_conn_rsp) {
                key_pair_id[slot_index] = spdm_context->local_context.local_key_pair_id[index];
                cert_info[slot_index] = spdm_context->local_context.local_cert_info[index];
                key_usage_bit_mask[slot_index] =
                    spdm_context->local_context.local_key_usage_bit_mask[index];
            }
            slot_index++;
            if (!result) {
                return libspdm_generate_error_response(
                    spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                    0, response_size, response);
            }
        }
    }

    if (session_info == NULL) {
        /* Log to transcript. */
        const size_t spdm_request_size = sizeof(spdm_get_digest_request_t);

        status = libspdm_append_message_b(spdm_context, spdm_request, spdm_request_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                                   response_size, response);
        }

        status = libspdm_append_message_b(spdm_context, spdm_response, *response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                                   response_size, response);
        }

        if (spdm_context->connection_info.multi_key_conn_rsp) {
            status = libspdm_append_message_d(spdm_context, spdm_response, *response_size);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return libspdm_generate_error_response(spdm_context,
                                                       SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                                       response_size, response);
            }
        }
    }

    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS) {
        libspdm_set_connection_state(spdm_context,
                                     LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
