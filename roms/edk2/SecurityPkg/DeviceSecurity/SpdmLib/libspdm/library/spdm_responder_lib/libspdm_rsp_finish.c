/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

bool libspdm_verify_finish_req_hmac(libspdm_context_t *spdm_context,
                                    libspdm_session_info_t *session_info,
                                    const uint8_t *hmac, size_t hmac_size)
{
    uint8_t hmac_data[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t slot_id;
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    size_t mut_cert_chain_buffer_size;
    uint8_t *th_curr_data;
    size_t th_curr_data_size;
    libspdm_th_managed_buffer_t th_curr;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
#endif

    hash_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    LIBSPDM_ASSERT(hmac_size == hash_size);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    slot_id = spdm_context->connection_info.local_used_cert_chain_slot_id;
    LIBSPDM_ASSERT((slot_id < SPDM_MAX_SLOT_COUNT) || (slot_id == 0xFF));
    if (slot_id == 0xFF) {
        result = libspdm_get_local_public_key_buffer(
            spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    } else {
        result = libspdm_get_local_cert_chain_buffer(
            spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    }
    if (!result) {
        return false;
    }

    if (session_info->mut_auth_requested) {
        slot_id = spdm_context->connection_info.peer_used_cert_chain_slot_id;
        LIBSPDM_ASSERT((slot_id < SPDM_MAX_SLOT_COUNT) || (slot_id == 0xFF));
        if (slot_id == 0xFF) {
            result = libspdm_get_peer_public_key_buffer(
                spdm_context, (const void **)&mut_cert_chain_buffer, &mut_cert_chain_buffer_size);
        } else {
            result = libspdm_get_peer_cert_chain_buffer(
                spdm_context, (const void **)&mut_cert_chain_buffer, &mut_cert_chain_buffer_size);
        }
        if (!result) {
            return false;
        }
    } else {
        mut_cert_chain_buffer = NULL;
        mut_cert_chain_buffer_size = 0;
    }

    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr);
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
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hmac - "));
    LIBSPDM_INTERNAL_DUMP_DATA(hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    if (!libspdm_consttime_is_mem_equal(hmac, hmac_data, hash_size)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "!!! verify_finish_req_hmac - FAIL !!!\n"));
        return false;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "!!! verify_finish_req_hmac - PASS !!!\n"));
    return true;
}

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
bool libspdm_verify_finish_req_signature(libspdm_context_t *spdm_context,
                                         libspdm_session_info_t *session_info,
                                         const void *sign_data,
                                         const size_t sign_data_size)
{
    bool result;
    void *context;
    uint8_t slot_id;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    size_t mut_cert_chain_buffer_size;
    uint8_t *th_curr_data;
    size_t th_curr_data_size;
    libspdm_th_managed_buffer_t th_curr;
    const uint8_t *mut_cert_chain_data;
    size_t mut_cert_chain_data_size;
    const uint8_t *mut_cert_buffer;
    size_t mut_cert_buffer_size;
#endif
#if ((LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT) && (LIBSPDM_DEBUG_BLOCK_ENABLE)) || \
    !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
#endif
#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT) || (LIBSPDM_DEBUG_PRINT_ENABLE)
    size_t hash_size;

    hash_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
#endif

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    slot_id = spdm_context->connection_info.local_used_cert_chain_slot_id;
    LIBSPDM_ASSERT((slot_id < SPDM_MAX_SLOT_COUNT) || (slot_id == 0xFF));
    if (slot_id == 0xFF) {
        result = libspdm_get_local_public_key_buffer(
            spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    } else {
        result = libspdm_get_local_cert_chain_buffer(
            spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    }
    if (!result) {
        return false;
    }

    slot_id = spdm_context->connection_info.peer_used_cert_chain_slot_id;
    LIBSPDM_ASSERT((slot_id < SPDM_MAX_SLOT_COUNT) || (slot_id == 0xFF));
    if (slot_id == 0xFF) {
        result = libspdm_get_peer_public_key_buffer(
            spdm_context, (const void **)&mut_cert_chain_buffer, &mut_cert_chain_buffer_size);
    } else {
        result = libspdm_get_peer_cert_chain_buffer(
            spdm_context, (const void **)&mut_cert_chain_buffer, &mut_cert_chain_buffer_size);
    }
    if (!result) {
        return false;
    }

    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr);
    if (!result) {
        return false;
    }
    th_curr_data = libspdm_get_managed_buffer(&th_curr);
    th_curr_data_size = libspdm_get_managed_buffer_size(&th_curr);

    /* Debug code only - required for debug print of th_curr below*/
    LIBSPDM_DEBUG_CODE(
        if (!libspdm_hash_all(
                spdm_context->connection_info.algorithm.base_hash_algo,
                th_curr_data, th_curr_data_size, hash_data)) {
        return false;
    }
        );
#else
    result = libspdm_calculate_th_hash_for_finish(
        spdm_context, session_info, &hash_size, hash_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hash - "));
    LIBSPDM_INTERNAL_DUMP_DATA(hash_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "signature - "));
    LIBSPDM_INTERNAL_DUMP_DATA(sign_data, sign_data_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    slot_id = spdm_context->connection_info.peer_used_cert_chain_slot_id;
    LIBSPDM_ASSERT((slot_id < SPDM_MAX_SLOT_COUNT) || (slot_id == 0xFF));

    if (slot_id == 0xFF) {
        result = libspdm_req_asym_get_public_key_from_der(
            spdm_context->connection_info.algorithm.req_base_asym_alg,
            spdm_context->local_context.peer_public_key_provision,
            spdm_context->local_context.peer_public_key_provision_size,
            &context);
        if (!result) {
            return false;
        }
    } else {
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        /* Get leaf cert from cert chain*/
        result = libspdm_get_peer_cert_chain_data(spdm_context,
                                                  (const void **)&mut_cert_chain_data,
                                                  &mut_cert_chain_data_size);
        if (!result) {
            return false;
        }

        result = libspdm_x509_get_cert_from_cert_chain(mut_cert_chain_data,
                                                       mut_cert_chain_data_size, -1,
                                                       &mut_cert_buffer,
                                                       &mut_cert_buffer_size);
        if (!result) {
            return false;
        }

        result = libspdm_req_asym_get_public_key_from_x509(
            spdm_context->connection_info.algorithm.req_base_asym_alg,
            mut_cert_buffer, mut_cert_buffer_size, &context);
        if (!result) {
            return false;
        }
#else
        context = spdm_context->connection_info.peer_used_cert_chain[slot_id].leaf_cert_public_key;
        LIBSPDM_ASSERT(context != NULL);
#endif
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_req_asym_verify_ex(
        spdm_context->connection_info.version, SPDM_FINISH,
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        spdm_context->connection_info.algorithm.base_hash_algo,
        context, th_curr_data, th_curr_data_size, sign_data, sign_data_size,
        &spdm_context->spdm_10_11_verify_signature_endian);
    libspdm_req_asym_free(spdm_context->connection_info.algorithm.req_base_asym_alg, context);
#else
    result = libspdm_req_asym_verify_hash_ex(
        spdm_context->connection_info.version, SPDM_FINISH,
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        spdm_context->connection_info.algorithm.base_hash_algo,
        context, hash_data, hash_size, sign_data, sign_data_size,
        &spdm_context->spdm_10_11_verify_signature_endian);
    if (slot_id == 0xFF) {
        libspdm_req_asym_free(spdm_context->connection_info.algorithm.req_base_asym_alg, context);
    }
#endif

    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "!!! VerifyFinishSignature - FAIL !!!\n"));
        return false;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "!!! VerifyFinishSignature - PASS !!!\n"));

    return true;
}
#endif

bool libspdm_generate_finish_rsp_hmac(libspdm_context_t *spdm_context,
                                      libspdm_session_info_t *session_info,
                                      uint8_t *hmac)
{
    uint8_t hmac_data[LIBSPDM_MAX_HASH_SIZE];
    size_t hash_size;
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    uint8_t slot_id;
    uint8_t *cert_chain_buffer;
    size_t cert_chain_buffer_size;
    uint8_t *mut_cert_chain_buffer;
    size_t mut_cert_chain_buffer_size;
    uint8_t *th_curr_data;
    size_t th_curr_data_size;
    libspdm_th_managed_buffer_t th_curr;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
#endif

    hash_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    slot_id = spdm_context->connection_info.local_used_cert_chain_slot_id;
    LIBSPDM_ASSERT((slot_id < SPDM_MAX_SLOT_COUNT) || (slot_id == 0xFF));
    if (slot_id == 0xFF) {
        result = libspdm_get_local_public_key_buffer(
            spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    } else {
        result = libspdm_get_local_cert_chain_buffer(
            spdm_context, (const void **)&cert_chain_buffer, &cert_chain_buffer_size);
    }
    if (!result) {
        return false;
    }

    if (session_info->mut_auth_requested) {
        slot_id = spdm_context->connection_info.peer_used_cert_chain_slot_id;
        LIBSPDM_ASSERT((slot_id < SPDM_MAX_SLOT_COUNT) || (slot_id == 0xFF));
        if (slot_id == 0xFF) {
            result = libspdm_get_peer_public_key_buffer(
                spdm_context, (const void **)&mut_cert_chain_buffer, &mut_cert_chain_buffer_size);
        } else {
            result = libspdm_get_peer_cert_chain_buffer(
                spdm_context, (const void **)&mut_cert_chain_buffer, &mut_cert_chain_buffer_size);
        }
        if (!result) {
            return false;
        }
    } else {
        mut_cert_chain_buffer = NULL;
        mut_cert_chain_buffer_size = 0;
    }

    result = libspdm_calculate_th_for_finish(
        spdm_context, session_info, cert_chain_buffer,
        cert_chain_buffer_size, mut_cert_chain_buffer,
        mut_cert_chain_buffer_size, &th_curr);
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

    result = libspdm_hmac_all_with_response_finished_key(
        session_info->secured_message_context, hash_data,
        hash_size, hmac_data);
    if (!result) {
        return false;
    }
#else
    result = libspdm_calculate_th_hmac_for_finish_rsp(
        spdm_context, session_info, &hash_size, hmac_data);
    if (!result) {
        return false;
    }
#endif
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "th_curr hmac - "));
    LIBSPDM_INTERNAL_DUMP_DATA(hmac_data, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    libspdm_copy_mem(hmac, hash_size, hmac_data, hash_size);

    return true;
}

libspdm_return_t libspdm_get_response_finish(libspdm_context_t *spdm_context, size_t request_size,
                                             const void *request,
                                             size_t *response_size,
                                             void *response)
{
    uint32_t session_id;
    bool result;
    uint32_t hmac_size;
    uint32_t signature_size;
    uint8_t req_slot_id;
    const spdm_finish_request_t *spdm_request;
    spdm_finish_response_t *spdm_response;
    libspdm_session_info_t *session_info;
    uint8_t th2_hash_data[LIBSPDM_MAX_HASH_SIZE];
    libspdm_return_t status;
    libspdm_session_state_t session_state;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_FINISH);

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_11) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                                               SPDM_FINISH,
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
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_FINISH, response_size, response);
    }
    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        /* No handshake in clear, then it must be in a session.*/
        if (!spdm_context->last_spdm_request_session_id_valid) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_SESSION_REQUIRED, 0, response_size, response);
        }
    } else {
        /* handshake in clear, then it must not be in a session.*/
        if (spdm_context->last_spdm_request_session_id_valid) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_SESSION_REQUIRED, 0,
                response_size, response);
        }
    }
    if (spdm_context->last_spdm_request_session_id_valid) {
        session_id = spdm_context->last_spdm_request_session_id;
    } else {
        session_id = spdm_context->latest_session_id;
    }
    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_SESSION_REQUIRED, 0,
                                               response_size, response);
    }
    if (session_info->use_psk) {
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

    if (((session_info->mut_auth_requested == 0) &&
         ((spdm_request->header.param1 & SPDM_FINISH_REQUEST_ATTRIBUTES_SIGNATURE_INCLUDED) !=
          0)) ||
        ((session_info->mut_auth_requested != 0) &&
         ((spdm_request->header.param1 & SPDM_FINISH_REQUEST_ATTRIBUTES_SIGNATURE_INCLUDED) ==
          0))) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    hmac_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    signature_size = 0;
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    if (session_info->mut_auth_requested) {
        signature_size = libspdm_get_req_asym_signature_size(
            spdm_context->connection_info.algorithm.req_base_asym_alg);
    }
#endif

    if (request_size <
        sizeof(spdm_finish_request_t) + signature_size + hmac_size) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if ((spdm_request->header.param1 & SPDM_FINISH_REQUEST_ATTRIBUTES_SIGNATURE_INCLUDED) != 0) {
        req_slot_id = spdm_request->header.param2;
        if ((req_slot_id != 0xFF) &&
            (req_slot_id >= SPDM_MAX_SLOT_COUNT)) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }

        if (libspdm_is_capabilities_flag_supported(
                spdm_context, false,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
            if (((session_info->mut_auth_requested ==
                  SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST) ||
                 (session_info->mut_auth_requested ==
                  SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS)) &&
                (req_slot_id != spdm_context->encap_context.req_slot_id)) {
                return libspdm_generate_error_response(spdm_context,
                                                       SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                       response_size, response);
            }
        }
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  spdm_request->header.request_response_code);

    status = libspdm_append_message_f(spdm_context, session_info, false, request,
                                      sizeof(spdm_finish_request_t));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    if (session_info->mut_auth_requested) {
        result = libspdm_verify_finish_req_signature(
            spdm_context, session_info,
            (const uint8_t *)request + sizeof(spdm_finish_request_t), signature_size);
        if (!result) {
            if((spdm_context->handle_error_return_policy &
                LIBSPDM_DATA_HANDLE_ERROR_RETURN_POLICY_DROP_ON_DECRYPT_ERROR) == 0) {
                return libspdm_generate_error_response(
                    spdm_context, SPDM_ERROR_CODE_DECRYPT_ERROR, 0,
                    response_size, response);
            } else {
                /**
                 * just ignore this message
                 * return UNSUPPORTED and clear response_size to continue the dispatch without send response.
                 **/
                *response_size = 0;
                return LIBSPDM_STATUS_UNSUPPORTED_CAP;
            }
        }
        status = libspdm_append_message_f(
            spdm_context, session_info, false,
            (const uint8_t *)request + sizeof(spdm_finish_request_t),
            signature_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
    }
#endif

    result = libspdm_verify_finish_req_hmac(
        spdm_context, session_info, (const uint8_t *)request + signature_size +
        sizeof(spdm_finish_request_t), hmac_size);
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

    status = libspdm_append_message_f(spdm_context, session_info, false,
                                      (const uint8_t *)request + signature_size +
                                      sizeof(spdm_finish_request_t),
                                      hmac_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        hmac_size = 0;
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_finish_response_t) + hmac_size);
    *response_size = sizeof(spdm_finish_response_t) + hmac_size;
    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_FINISH_RSP;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    status = libspdm_append_message_f(spdm_context, session_info, false, spdm_response,
                                      sizeof(spdm_finish_response_t));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
        result = libspdm_generate_finish_rsp_hmac(
            spdm_context, session_info,
            (uint8_t *)spdm_response + sizeof(spdm_finish_request_t));
        if (!result) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }

        status = libspdm_append_message_f(
            spdm_context, session_info, false,
            (uint8_t *)spdm_response + sizeof(spdm_finish_request_t),
            hmac_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_data_key[%x]\n", session_id));
    result = libspdm_calculate_th2_hash(spdm_context, session_info, false, th2_hash_data);
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

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP */
