/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
bool libspdm_generate_measurement_signature(libspdm_context_t *spdm_context,
                                            libspdm_session_info_t *session_info,
                                            uint8_t *signature)
{
    size_t signature_size;
    bool result;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_l1l2_managed_buffer_t l1l2;
    uint8_t *l1l2_buffer;
    size_t l1l2_buffer_size;
#else
    uint8_t l1l2_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t l1l2_hash_size;
#endif

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    result = libspdm_calculate_l1l2(spdm_context, session_info, &l1l2);
#else
    l1l2_hash_size = sizeof(l1l2_hash);
    result = libspdm_calculate_l1l2_hash(spdm_context, session_info, &l1l2_hash_size, l1l2_hash);
#endif
    libspdm_reset_message_m(spdm_context, session_info);
    if (!result) {
        return false;
    }

    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    l1l2_buffer = libspdm_get_managed_buffer(&l1l2);
    l1l2_buffer_size = libspdm_get_managed_buffer_size(&l1l2);

    result = libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        spdm_context->connection_info.version, SPDM_MEASUREMENTS,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_hash_algo,
        false, l1l2_buffer, l1l2_buffer_size, signature, &signature_size);
#else
    result = libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        spdm_context->connection_info.version, SPDM_MEASUREMENTS,
        spdm_context->connection_info.algorithm.base_asym_algo,
        spdm_context->connection_info.algorithm.base_hash_algo,
        true, l1l2_hash, l1l2_hash_size, signature, &signature_size);
#endif
    return result;
}
libspdm_return_t libspdm_get_response_measurements(libspdm_context_t *spdm_context,
                                                   size_t request_size,
                                                   const void *request,
                                                   size_t *response_size,
                                                   void *response)
{
    const spdm_get_measurements_request_t *spdm_request;
    size_t spdm_request_size;
    spdm_measurements_response_t *spdm_response;
    size_t spdm_response_size;
    libspdm_return_t status;
    size_t signature_size;
    uint8_t slot_id_param;
    uint8_t measurements_index;
    uint8_t measurements_count;
    uint8_t *measurements;
    size_t measurements_size;
    uint8_t *opaque_data;
    size_t opaque_data_size;
    size_t meas_opaque_buffer_size;
    bool ret;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;
    uint8_t content_changed;
    uint8_t *fill_response_ptr;

    spdm_request = request;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT(spdm_request->header.request_response_code == SPDM_GET_MEASUREMENTS);

    if (!spdm_context->last_spdm_request_session_id_valid) {
        session_info = NULL;
    } else {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context,
            spdm_context->last_spdm_request_session_id);
        if (session_info == NULL) {
            /* do not reset message_m because it is unclear which context it should be used. */
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            libspdm_reset_message_m(spdm_context, session_info);
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
                response_size, response);
        }
    }

    if (spdm_request->header.spdm_version != libspdm_get_connection_version(spdm_context)) {
        libspdm_reset_message_m(spdm_context, session_info);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_VERSION_MISMATCH, 0,
                                               response_size, response);
    }
    if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NORMAL) {
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
        if (spdm_context->response_state != LIBSPDM_RESPONSE_STATE_NOT_READY) {
#endif
        libspdm_reset_message_m(spdm_context, session_info);
#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    }
#endif
        return libspdm_responder_handle_response_state(
            spdm_context,
            spdm_request->header.request_response_code,
            response_size, response);
    }
    /* check local context here, because meas_cap is reserved for requester.*/
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
        libspdm_reset_message_m(spdm_context, session_info);
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
            SPDM_GET_MEASUREMENTS, response_size, response);
    }
    if ((spdm_context->connection_info.algorithm.measurement_spec == 0) ||
        (spdm_context->connection_info.algorithm.measurement_hash_algo == 0) ) {
        libspdm_reset_message_m(spdm_context, session_info);
        return libspdm_generate_error_response(
            spdm_context, SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
            0, response_size, response);
    }
    if (spdm_context->connection_info.connection_state <
        LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        libspdm_reset_message_m(spdm_context, session_info);
        return libspdm_generate_error_response(
            spdm_context,
            SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0,
            response_size, response);
    }

    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
            if (request_size < sizeof(spdm_get_measurements_request_t)) {
                libspdm_reset_message_m(spdm_context, session_info);
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                    response_size, response);
            }
            spdm_request_size = sizeof(spdm_get_measurements_request_t);
        } else {
            if (request_size <
                sizeof(spdm_get_measurements_request_t) -
                sizeof(spdm_request->slot_id_param)) {
                libspdm_reset_message_m(spdm_context, session_info);
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                    response_size, response);
            }
            spdm_request_size = sizeof(spdm_get_measurements_request_t) -
                                sizeof(spdm_request->slot_id_param);
        }
    } else {
        if (request_size < sizeof(spdm_message_header_t)) {
            libspdm_reset_message_m(spdm_context, session_info);
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
        spdm_request_size = sizeof(spdm_message_header_t);
    }
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        if (request_size < spdm_request_size + SPDM_REQ_CONTEXT_SIZE) {
            libspdm_reset_message_m(spdm_context, session_info);
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
        spdm_request_size += SPDM_REQ_CONTEXT_SIZE;
    }

    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
        if (!libspdm_is_capabilities_flag_supported(
                spdm_context, false, 0,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG)) {
            libspdm_reset_message_m(spdm_context, session_info);
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        }
    }

    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) == 0) {
        signature_size = 0;
    } else {
        signature_size = libspdm_get_asym_signature_size(
            spdm_context->connection_info.algorithm.base_asym_algo);
    }


    /* response_size should be large enough to hold a MEASUREMENTS response without
     * measurements or opaque data. */
    LIBSPDM_ASSERT(*response_size >= (sizeof(spdm_measurements_response_t) +
                                      SPDM_NONCE_SIZE + sizeof(uint16_t) + signature_size));

    meas_opaque_buffer_size = *response_size - (sizeof(spdm_measurements_response_t) +
                                                SPDM_NONCE_SIZE + sizeof(uint16_t) +
                                                signature_size);

    libspdm_zero_mem(response, *response_size);

    measurements_index = spdm_request->header.param2;
    measurements_count = 0;
    measurements = (uint8_t*)response + sizeof(spdm_measurements_response_t);
    measurements_size = meas_opaque_buffer_size;

    status = libspdm_measurement_collection(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        spdm_context->connection_info.version,
        spdm_context->connection_info.algorithm.measurement_spec,
        spdm_context->connection_info.algorithm.measurement_hash_algo,
        measurements_index,
        spdm_request->header.param1,
        &content_changed,
        &measurements_count,
        measurements,
        &measurements_size);

    LIBSPDM_ASSERT(measurements_size <= SPDM_MAX_MEASUREMENT_RECORD_LENGTH);
    LIBSPDM_ASSERT(measurements_size <= meas_opaque_buffer_size);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        if (status == LIBSPDM_STATUS_MEAS_INVALID_INDEX) {
            libspdm_reset_message_m(spdm_context, session_info);
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                0, response_size, response);
        } else {
            libspdm_reset_message_m(spdm_context, session_info);
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
    }

    if (measurements_index == 0) {
        measurements_size = 0;
    }

    opaque_data =
        (uint8_t*)response + sizeof(spdm_measurements_response_t) + measurements_size +
        SPDM_NONCE_SIZE + sizeof(uint16_t);

    if ((libspdm_get_connection_version(spdm_context) >= SPDM_MESSAGE_VERSION_12) &&
        ((spdm_context->connection_info.algorithm.other_params_support &
          SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_MASK) == SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_NONE)) {
        opaque_data_size = 0;
    } else {
        opaque_data_size = meas_opaque_buffer_size - measurements_size;

        ret = libspdm_measurement_opaque_data(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_context->connection_info.version,
            spdm_context->connection_info.algorithm.measurement_spec,
            spdm_context->connection_info.algorithm.measurement_hash_algo,
            measurements_index,
            spdm_request->header.param1,
            opaque_data,
            &opaque_data_size);

        if (!ret) {
            libspdm_reset_message_m(spdm_context, session_info);
            return libspdm_generate_error_response(
                spdm_context, SPDM_ERROR_CODE_UNSPECIFIED,
                0, response_size, response);
        }
    }

    LIBSPDM_ASSERT(opaque_data_size <= (meas_opaque_buffer_size - measurements_size));

    spdm_response_size =
        sizeof(spdm_measurements_response_t) + measurements_size + SPDM_NONCE_SIZE +
        sizeof(uint16_t) + opaque_data_size + signature_size;
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        spdm_response_size += SPDM_REQ_CONTEXT_SIZE;
    }

    LIBSPDM_ASSERT(*response_size >= spdm_response_size);

    *response_size = spdm_response_size;
    spdm_response = response;

    switch (spdm_request->header.param2) {
    case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS:
        spdm_response->header.spdm_version = spdm_request->header.spdm_version;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = measurements_count;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 0;
        libspdm_write_uint24(spdm_response->measurement_record_length, 0);
        break;
    case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS:
        LIBSPDM_DEBUG_CODE(
            uint8_t index;
            size_t debug_measurements_record_size;
            size_t debug_measurements_block_size;
            spdm_measurement_block_dmtf_t *debug_measurement_block;

            debug_measurements_record_size = 0;
            debug_measurement_block = (void *)measurements;
            for (index = 0; index < measurements_count; index++) {
            debug_measurements_block_size =
                sizeof(spdm_measurement_block_dmtf_t) +
                debug_measurement_block->measurement_block_dmtf_header
                .dmtf_spec_measurement_value_size;
            debug_measurements_record_size += debug_measurements_block_size;
            debug_measurement_block =
                (void *)((size_t)debug_measurement_block + debug_measurements_block_size);
        }
            LIBSPDM_ASSERT(debug_measurements_record_size == measurements_size);
            );

        spdm_response->header.spdm_version = spdm_request->header.spdm_version;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = measurements_count;
        libspdm_write_uint24(spdm_response->measurement_record_length, (uint32_t)measurements_size);
        break;
    default:
        LIBSPDM_ASSERT(measurements_count == 1);

        spdm_response->header.spdm_version = spdm_request->header.spdm_version;
        spdm_response->header.request_response_code = SPDM_MEASUREMENTS;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->number_of_blocks = 1;
        libspdm_write_uint24(spdm_response->measurement_record_length, (uint32_t)measurements_size);
        break;
    }

    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
        if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
            slot_id_param = spdm_request->slot_id_param &
                            SPDM_GET_MEASUREMENTS_REQUEST_SLOT_ID_MASK;
            if ((slot_id_param != 0xF) && (slot_id_param >= SPDM_MAX_SLOT_COUNT)) {
                libspdm_reset_message_m(spdm_context, session_info);
                return libspdm_generate_error_response(
                    spdm_context,
                    SPDM_ERROR_CODE_INVALID_REQUEST, 0,
                    response_size, response);
            }
            if (slot_id_param != 0xF) {
                if (spdm_context->local_context
                    .local_cert_chain_provision[slot_id_param] == NULL) {
                    libspdm_reset_message_m(spdm_context, session_info);
                    return libspdm_generate_error_response(
                        spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                        0, response_size, response);
                }
            } else {
                if (spdm_context->local_context
                    .local_public_key_provision == NULL) {
                    libspdm_reset_message_m(spdm_context, session_info);
                    return libspdm_generate_error_response(
                        spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                        0, response_size, response);
                }
            }

            if ((spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) &&
                spdm_context->connection_info.multi_key_conn_rsp) {
                if ((spdm_context->local_context.local_key_usage_bit_mask[slot_id_param] &
                     SPDM_KEY_USAGE_BIT_MASK_MEASUREMENT_USE) == 0) {
                    return libspdm_generate_error_response(
                        spdm_context, SPDM_ERROR_CODE_INVALID_REQUEST,
                        0, response_size, response);
                }
            }

            spdm_response->header.param2 = slot_id_param;
            if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
                spdm_response->header.param2 = slot_id_param |
                                               (content_changed &
                                                SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_MASK);
            }
        }
    }

    fill_response_ptr =
        (uint8_t*)response + sizeof(spdm_measurements_response_t) + measurements_size;

    if(!libspdm_get_random_number(SPDM_NONCE_SIZE, fill_response_ptr)) {
        libspdm_reset_message_m(spdm_context, session_info);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }
    fill_response_ptr += SPDM_NONCE_SIZE;

    libspdm_write_uint16(fill_response_ptr, (uint16_t)opaque_data_size);
    fill_response_ptr += sizeof(uint16_t);

    fill_response_ptr += opaque_data_size;

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        libspdm_copy_mem(fill_response_ptr, SPDM_REQ_CONTEXT_SIZE,
                         (const uint8_t *)spdm_request + spdm_request_size - SPDM_REQ_CONTEXT_SIZE,
                         SPDM_REQ_CONTEXT_SIZE);
        fill_response_ptr += SPDM_REQ_CONTEXT_SIZE;
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, session_info,
                                                  spdm_request->header.request_response_code);

    status = libspdm_append_message_m(spdm_context, session_info, spdm_request, spdm_request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_reset_message_m(spdm_context, session_info);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    status = libspdm_append_message_m(spdm_context, session_info,
                                      spdm_response, *response_size - signature_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_reset_message_m(spdm_context, session_info);
        return libspdm_generate_error_response(spdm_context,
                                               SPDM_ERROR_CODE_UNSPECIFIED, 0,
                                               response_size, response);
    }

    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {

        ret = libspdm_generate_measurement_signature(spdm_context, session_info, fill_response_ptr);

        if (!ret) {
            libspdm_reset_message_m(spdm_context, session_info);
            return libspdm_generate_error_response(
                spdm_context,
                SPDM_ERROR_CODE_UNSPECIFIED,
                0,
                response_size, response);
        }
        /*reset*/
        libspdm_reset_message_m(spdm_context, session_info);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/
