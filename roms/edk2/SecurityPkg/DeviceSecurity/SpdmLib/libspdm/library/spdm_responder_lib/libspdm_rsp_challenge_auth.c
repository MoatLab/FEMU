/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"


#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP

libspdm_return_t libspdm_get_response_challenge_auth(libspdm_context_t *spdm_context,
                                                     size_t request_size,
                                                     const void *request,
                                                     size_t *response_size,
                                                     void *response)
{
    const spdm_challenge_request_t *spdm_request;
    size_t spdm_request_size;
    spdm_challenge_auth_response_t *spdm_response;
    bool result;
    size_t signature_size;
    uint8_t slot_id;
    uint32_t hash_size;
    uint8_t *measurement_summary_hash;
    uint32_t measurement_summary_hash_size;
    uint8_t *ptr;
    uint8_t auth_attribute;
    libspdm_return_t status;
    uint8_t slot_mask;
    uint8_t *opaque_data;
    size_t opaque_data_size;
    size_t spdm_response_size;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_CHALLENGE);

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
    if (spdm_context->last_spdm_request_session_id_valid) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                                               response_size, response);
    }
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_CHALLENGE, response_size, response);
    }
    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
                                               0, response_size, response);
    }

    if (request_size < sizeof(spdm_challenge_request_t)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }
    spdm_request_size = sizeof(spdm_challenge_request_t);
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        if (request_size < sizeof(spdm_challenge_request_t) + SPDM_REQ_CONTEXT_SIZE) {
            return libspdm_generate_error_response(spdm_context,
                                                   SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                                   response_size, response);
        }
        spdm_request_size += SPDM_REQ_CONTEXT_SIZE;
    }
    if (spdm_request->header.param2 > 0) {
        if (!libspdm_is_capabilities_flag_supported(
                spdm_context, false, 0,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) ||
            (spdm_context->connection_info.algorithm.measurement_spec == 0) ||
            (spdm_context->connection_info.algorithm.measurement_hash_algo == 0) ) {
            return libspdm_generate_error_response (spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                                                    0, response_size, response);
        }
    }

    slot_id = spdm_request->header.param1;

    if ((slot_id != 0xFF) && (slot_id >= SPDM_MAX_SLOT_COUNT)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                                               response_size, response);
    }

    if (slot_id != 0xFF) {
        if (spdm_context->local_context.local_cert_chain_provision[slot_id] == NULL) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
    } else {
        if (spdm_context->local_context.local_public_key_provision == NULL) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
    }

    if ((spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) &&
        spdm_context->connection_info.multi_key_conn_rsp) {
        if ((spdm_context->local_context.local_key_usage_bit_mask[slot_id] &
             SPDM_KEY_USAGE_BIT_MASK_CHALLENGE_USE) == 0) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
    }

    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
    hash_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    measurement_summary_hash_size = libspdm_get_measurement_summary_hash_size(
        spdm_context, false, spdm_request->header.param2);
    if ((measurement_summary_hash_size == 0) &&
        (spdm_request->header.param2 != SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_INVALID_REQUEST,
                                               0, response_size, response);
    }

    /* response_size should be large enough to hold a challenge response without opaque data. */
    LIBSPDM_ASSERT(*response_size >= sizeof(spdm_challenge_auth_response_t) + hash_size +
                   SPDM_NONCE_SIZE + measurement_summary_hash_size + sizeof(uint16_t) +
                   SPDM_REQ_CONTEXT_SIZE + signature_size);

    libspdm_zero_mem(response, *response_size);
    spdm_response = response;

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    spdm_response->header.spdm_version = spdm_request->header.spdm_version;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    auth_attribute = (uint8_t)(slot_id & 0xF);
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        if (libspdm_is_capabilities_flag_supported(
                spdm_context, false,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP) &&
            libspdm_is_capabilities_flag_supported(
                spdm_context, false,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP, 0) &&
            (libspdm_is_capabilities_flag_supported(
                 spdm_context, false,
                 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0) ||
             libspdm_is_capabilities_flag_supported(
                 spdm_context, false,
                 SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP, 0))) {
            if (spdm_context->local_context.basic_mut_auth_requested) {
                auth_attribute =
                    (uint8_t)(auth_attribute |
                              SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_BASIC_MUT_AUTH_REQ);
            }
        }
        if ((auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_BASIC_MUT_AUTH_REQ) != 0) {
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_SEND_CHALLENGE_SUPPORT)
            libspdm_init_basic_mut_auth_encap_state(spdm_context);
#else
            auth_attribute =
                (uint8_t)(auth_attribute &
                          ~SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_BASIC_MUT_AUTH_REQ);
#endif
        }
    }

    spdm_response->header.param1 = auth_attribute;

    if (slot_id == 0xFF) {
        spdm_response->header.param2 = 0;
    } else {
        slot_mask = libspdm_get_cert_slot_mask(spdm_context);
        if (slot_mask != 0) {
            spdm_response->header.param2 = slot_mask;
        } else {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
    }

    ptr = (void *)(spdm_response + 1);
    if (slot_id == 0xFF) {
        result = libspdm_generate_public_key_hash(spdm_context, ptr);
    } else {
        result = libspdm_generate_cert_chain_hash(spdm_context, slot_id, ptr);
    }
    if (!result) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    ptr += hash_size;

    result = libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
    if (!result) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    ptr += SPDM_NONCE_SIZE;

    measurement_summary_hash = ptr;

    if (libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {

        result = libspdm_generate_measurement_summary_hash(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_context->connection_info.version,
            spdm_context->connection_info.algorithm.base_hash_algo,
            spdm_context->connection_info.algorithm.measurement_spec,
            spdm_context->connection_info.algorithm.measurement_hash_algo,
            spdm_request->header.param2,
            ptr,
            measurement_summary_hash_size);
    } else {
        result = true;
    }

    if (!result) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    ptr += measurement_summary_hash_size;

    opaque_data_size = *response_size - (sizeof(spdm_challenge_auth_response_t) + hash_size +
                                         SPDM_NONCE_SIZE + measurement_summary_hash_size +
                                         sizeof(uint16_t) + signature_size);
    opaque_data =
        (uint8_t*)response + sizeof(spdm_challenge_auth_response_t) + hash_size + SPDM_NONCE_SIZE +
        measurement_summary_hash_size + sizeof(uint16_t);

    if ((libspdm_get_connection_version(spdm_context) >= SPDM_MESSAGE_VERSION_12) &&
        ((spdm_context->connection_info.algorithm.other_params_support &
          SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_MASK) == SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_NONE)) {
        opaque_data_size = 0;
    } else {
        result = libspdm_challenge_opaque_data(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_context->connection_info.version,
            slot_id,
            measurement_summary_hash, measurement_summary_hash_size,
            opaque_data, &opaque_data_size);
        if (!result) {
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
    }

    /*write opaque_data_size*/
    libspdm_write_uint16 (ptr, (uint16_t)opaque_data_size);
    ptr += sizeof(uint16_t);

    /*the opaque_data is stored by libspdm_challenge_opaque_data*/
    ptr += opaque_data_size;

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        libspdm_copy_mem(ptr, SPDM_REQ_CONTEXT_SIZE,
                         spdm_request + 1, SPDM_REQ_CONTEXT_SIZE);
        ptr += SPDM_REQ_CONTEXT_SIZE;
    }

    /*get actual response size*/
    spdm_response_size =
        sizeof(spdm_challenge_auth_response_t) + hash_size +
        SPDM_NONCE_SIZE + measurement_summary_hash_size +
        sizeof(uint16_t) + opaque_data_size + signature_size;
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        spdm_response_size += SPDM_REQ_CONTEXT_SIZE;
    }

    LIBSPDM_ASSERT(*response_size >= spdm_response_size);

    *response_size = spdm_response_size;

    /* Calc Sign*/

    status = libspdm_append_message_c(spdm_context, spdm_request, spdm_request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    status = libspdm_append_message_c(spdm_context, spdm_response,
                                      (size_t)ptr - (size_t)spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_reset_message_c(spdm_context);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    result = libspdm_generate_challenge_auth_signature(spdm_context, false, ptr);
    if (!result) {
        libspdm_reset_message_c(spdm_context);
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
            0, response_size, response);
    }
    ptr += signature_size;

    if ((auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_BASIC_MUT_AUTH_REQ) == 0) {
        libspdm_set_connection_state(spdm_context,
                                     LIBSPDM_CONNECTION_STATE_AUTHENTICATED);
    }

    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP */
