/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && \
    (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)

libspdm_return_t libspdm_get_encap_request_get_digest(libspdm_context_t *spdm_context,
                                                      size_t *encap_request_size,
                                                      void *encap_request)
{
    spdm_get_digest_request_t *spdm_request;
    libspdm_return_t status;

    spdm_context->encap_context.last_encap_request_size = 0;

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_11) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    LIBSPDM_ASSERT(*encap_request_size >= sizeof(spdm_get_digest_request_t));
    *encap_request_size = sizeof(spdm_get_digest_request_t);

    spdm_request = encap_request;

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);

    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_GET_DIGESTS;
    spdm_request->header.param1 = 0;
    spdm_request->header.param2 = 0;


    /* Cache data*/

    status = libspdm_append_message_mut_b(spdm_context, spdm_request,
                                          *encap_request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    libspdm_copy_mem(&spdm_context->encap_context.last_encap_request_header,
                     sizeof(spdm_context->encap_context.last_encap_request_header),
                     &spdm_request->header, sizeof(spdm_message_header_t));
    spdm_context->encap_context.last_encap_request_size =
        *encap_request_size;

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_process_encap_response_digest(
    libspdm_context_t *spdm_context, size_t encap_response_size,
    const void *encap_response, bool *need_continue)
{
    const spdm_digest_response_t *spdm_response;
    size_t spdm_response_size;
    size_t digest_size;
    size_t digest_count;
    size_t index;
    libspdm_return_t status;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    size_t additional_size;
    spdm_key_pair_id_t *key_pair_id;
    spdm_certificate_info_t *cert_info;
    spdm_key_usage_bit_mask_t *key_usage_bit_mask;
    size_t slot_index;
    uint8_t cert_model;
    uint8_t zero_digest[LIBSPDM_MAX_HASH_SIZE] = {0};

    spdm_response = encap_response;
    spdm_response_size = encap_response_size;

    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (spdm_response->header.spdm_version != libspdm_get_connection_version (spdm_context)) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_encap_error_response_main(
            spdm_context,
            spdm_response->header.param1);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
    } else if (spdm_response->header.request_response_code !=
               SPDM_DIGESTS) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response_size < sizeof(spdm_digest_response_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "provisioned_slot_mask - 0x%02x\n",
                   spdm_response->header.param2));
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "supported_slot_mask - 0x%02x\n",
                       spdm_response->header.param1));
        if ((spdm_response->header.param1 & spdm_response->header.param2) !=
            spdm_response->header.param2) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    }

    digest_size = libspdm_get_hash_size(
        spdm_context->connection_info.algorithm.base_hash_algo);
    digest_count = 0;
    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        if (spdm_response->header.param2 & (1 << index)) {
            digest_count++;
        }
    }
    if (digest_count == 0) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }

    additional_size = 0;
    if ((spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) &&
        spdm_context->connection_info.multi_key_conn_req) {
        additional_size = sizeof(spdm_key_pair_id_t) + sizeof(spdm_certificate_info_t) +
                          sizeof(spdm_key_usage_bit_mask_t);
    }
    if (spdm_response_size <
        sizeof(spdm_digest_response_t) + digest_count * (digest_size + additional_size)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    spdm_response_size =
        sizeof(spdm_digest_response_t) + digest_count * (digest_size + additional_size);

    /* Cache data*/

    status = libspdm_append_message_mut_b(spdm_context, spdm_response,
                                          spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    if (spdm_context->last_spdm_request_session_id_valid) {
        session_id = spdm_context->last_spdm_request_session_id;
    } else {
        session_id = spdm_context->latest_session_id;
    }
    if (session_id != INVALID_SESSION_ID) {
        session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    } else {
        session_info = NULL;
    }
    if (session_info != NULL) {
        if (spdm_context->connection_info.multi_key_conn_req) {
            status = libspdm_append_message_encap_d(spdm_context, session_info, false,
                                                    spdm_response, spdm_response_size);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return LIBSPDM_STATUS_BUFFER_FULL;
            }
        }
    }

    key_pair_id =
        (spdm_key_pair_id_t *)((size_t)(spdm_response + 1) + digest_size * digest_count);
    cert_info =
        (spdm_certificate_info_t *)((uint8_t *)key_pair_id + sizeof(spdm_key_pair_id_t) *
                                    digest_count);
    key_usage_bit_mask =
        (spdm_key_usage_bit_mask_t *)((uint8_t *)cert_info + sizeof(spdm_certificate_info_t) *
                                      digest_count);
    for (index = 0; index < digest_count; index++) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "digest (0x%zx) - ", index));
        LIBSPDM_INTERNAL_DUMP_DATA(
            (const uint8_t *)(spdm_response + 1) + (digest_size * index), digest_size);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    }
    if ((spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) &&
        spdm_context->connection_info.multi_key_conn_req) {
        for (index = 0; index < digest_count; index++) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key_pair_id (0x%zx) - 0x%02x\n", index,
                           key_pair_id[index]));
        }
        for (index = 0; index < digest_count; index++) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "cert_info (0x%zx) - 0x%02x\n", index,
                           cert_info[index]));
        }
        for (index = 0; index < digest_count; index++) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "key_usage_bit_mask (0x%zx) - 0x%04x\n", index,
                           key_usage_bit_mask[index]));
        }
    }

    spdm_context->connection_info.peer_provisioned_slot_mask = spdm_response->header.param2;
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        spdm_context->connection_info.peer_supported_slot_mask = spdm_response->header.param1;
    } else {
        spdm_context->connection_info.peer_supported_slot_mask = spdm_response->header.param2;
    }
    libspdm_copy_mem(
        spdm_context->connection_info.peer_total_digest_buffer,
        sizeof(spdm_context->connection_info.peer_total_digest_buffer),
        spdm_response + 1, digest_size * digest_count);
    libspdm_zero_mem(spdm_context->connection_info.peer_key_pair_id,
                     sizeof(spdm_context->connection_info.peer_key_pair_id));
    libspdm_zero_mem(spdm_context->connection_info.peer_cert_info,
                     sizeof(spdm_context->connection_info.peer_cert_info));
    libspdm_zero_mem(spdm_context->connection_info.peer_key_usage_bit_mask,
                     sizeof(spdm_context->connection_info.peer_key_usage_bit_mask));
    if ((spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) &&
        spdm_context->connection_info.multi_key_conn_req) {
        slot_index = 0;
        for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
            if (spdm_response->header.param2 & (1 << index)) {
                spdm_context->connection_info.peer_key_pair_id[index] = key_pair_id[slot_index];
                cert_model = cert_info[slot_index] & SPDM_CERTIFICATE_INFO_CERT_MODEL_MASK;
                if (cert_model > SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT) {
                    return LIBSPDM_STATUS_INVALID_MSG_FIELD;
                }
                if (index == 0) {
                    if (cert_model == SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT) {
                        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
                    }
                    if ((key_usage_bit_mask[slot_index] &
                         (SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE |
                          SPDM_KEY_USAGE_BIT_MASK_CHALLENGE_USE |
                          SPDM_KEY_USAGE_BIT_MASK_MEASUREMENT_USE |
                          SPDM_KEY_USAGE_BIT_MASK_ENDPOINT_INFO_USE)) == 0) {
                        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
                    }
                }
                if ((cert_model == SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE) &&
                    (!libspdm_consttime_is_mem_equal(
                         (const uint8_t *)(spdm_response + 1) + digest_size * slot_index,
                         zero_digest,
                         digest_size))) {
                    return LIBSPDM_STATUS_INVALID_MSG_FIELD;
                }
                spdm_context->connection_info.peer_cert_info[index] = cert_model;
                spdm_context->connection_info.peer_key_usage_bit_mask[index] =
                    key_usage_bit_mask[slot_index];
                slot_index++;
            }
        }
    }

    *need_continue = false;

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (...) */
