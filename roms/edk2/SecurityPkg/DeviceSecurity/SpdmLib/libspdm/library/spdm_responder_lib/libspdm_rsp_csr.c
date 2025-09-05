/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP

libspdm_return_t libspdm_get_response_csr(libspdm_context_t *spdm_context,
                                          size_t request_size, const void *request,
                                          size_t *response_size, void *response)
{
    const spdm_get_csr_request_t *spdm_request;
    spdm_csr_response_t *spdm_response;
    bool result;

    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    size_t csr_len;
    uint8_t *csr_p;
    uint16_t requester_info_length;
    uint16_t opaque_data_length;
    uint8_t *opaque_data;
    uint8_t *requester_info;
    bool need_reset;
    bool is_device_cert_model;
    uint8_t csr_tracking_tag;
#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX
    bool overwrite;
    uint8_t req_cert_model;
    uint8_t key_pair_id;
#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX*/

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_GET_CSR);

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_12) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
                                               SPDM_GET_CSR,
                                               response_size, response);
    }

    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }

    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
        return libspdm_responder_handle_response_state(spdm_context,
                                                       spdm_request->header.request_response_code,
                                                       response_size, response);
    }

    if (request_size < sizeof(spdm_get_csr_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
            response_size, response);
    }

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

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_CSR, response_size, response);
    }

    requester_info_length = spdm_request->requester_info_length;
    opaque_data_length = spdm_request->opaque_data_length;

    if (opaque_data_length > SPDM_MAX_OPAQUE_DATA_SIZE) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    if (((spdm_context->connection_info.algorithm.other_params_support &
          SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_MASK) == SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_NONE)
        && (opaque_data_length != 0)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (opaque_data_length >
        request_size - sizeof(spdm_get_csr_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (requester_info_length >
        request_size - sizeof(spdm_get_csr_request_t) - opaque_data_length) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    requester_info = (void *)((size_t)(spdm_request + 1));

    opaque_data = (void *)(requester_info + requester_info_length);
    if (opaque_data_length != 0) {
        result = libspdm_process_general_opaque_data_check(spdm_context, opaque_data_length,
                                                           opaque_data);
        if (!result) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
    }

    need_reset = libspdm_is_capabilities_flag_supported(
        spdm_context, false, 0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP);

    result = libspdm_verify_req_info(requester_info, requester_info_length);
    if (!result) {
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_INVALID_REQUEST, 0,
            response_size, response);
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_csr_response_t));

    spdm_response = response;
    libspdm_zero_mem(response, *response_size);

    is_device_cert_model = false;

    if((spdm_context->local_context.capability.flags &
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP) == 0) {
        is_device_cert_model = true;
    }

    csr_len = *response_size - sizeof(spdm_csr_response_t);
    csr_p = (uint8_t*)(spdm_response + 1);

    csr_tracking_tag = 0;
    if (libspdm_get_connection_version(spdm_context) >= SPDM_MESSAGE_VERSION_13) {
#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX
        csr_tracking_tag =
            (spdm_request->header.param2 & SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_MASK) >>
            SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET;

        if ((spdm_request->header.param2 & SPDM_GET_CSR_REQUEST_ATTRIBUTES_OVERWRITE) != 0) {
            overwrite = true;
        } else {
            overwrite = false;
        }

        req_cert_model = spdm_request->header.param2 &
                         SPDM_GET_CSR_REQUEST_ATTRIBUTES_CERT_MODEL_MASK;

        key_pair_id = spdm_request->header.param1;

        /*SPDM 1.3 parameters check*/
        if (((spdm_context->connection_info.multi_key_conn_rsp) == (key_pair_id == 0)) ||
            ((!spdm_context->connection_info.multi_key_conn_rsp) && (req_cert_model != 0)) ||
            (req_cert_model >= SPDM_GET_CSR_REQUEST_ATTRIBUTES_MAX_CSR_CERT_MODEL) ||
            (overwrite && (csr_tracking_tag != 0)) ||
            ((!need_reset) && (csr_tracking_tag != 0))) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }

        result = libspdm_gen_csr_ex(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.base_asym_algo,
            &need_reset, request, request_size,
            requester_info, requester_info_length,
            opaque_data, opaque_data_length,
            &csr_len, csr_p, req_cert_model,
            &csr_tracking_tag, key_pair_id, overwrite);
#else
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
            response_size, response);
#endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX*/
    } else {
        result = libspdm_gen_csr(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.base_asym_algo,
            &need_reset, request, request_size,
            requester_info, requester_info_length,
            opaque_data, opaque_data_length,
            &csr_len, csr_p, is_device_cert_model);
    }

    if (!result) {
        if ((csr_tracking_tag == 0xFF) &&
            (libspdm_get_connection_version(spdm_context) >= SPDM_MESSAGE_VERSION_13)) {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_BUSY, 0,
                response_size, response);
        } else {
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
    }

    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_csr_response_t) + csr_len);
    *response_size = sizeof(spdm_csr_response_t) + csr_len;

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP) &&
        need_reset) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_RESET_REQUIRED, csr_tracking_tag,
                                               response_size, response);
    } else {
        spdm_response->header.spdm_version = spdm_request->header.spdm_version;
        spdm_response->header.request_response_code = SPDM_CSR;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->csr_length = (uint16_t)csr_len;
        spdm_response->reserved = 0;
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP*/
