/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && \
    (LIBSPDM_SEND_CHALLENGE_SUPPORT)

libspdm_return_t libspdm_get_encap_request_challenge(libspdm_context_t *spdm_context,
                                                     size_t *encap_request_size,
                                                     void *encap_request)
{
    spdm_challenge_request_t *spdm_request;
    size_t spdm_request_size;
    libspdm_return_t status;

    spdm_context->encap_context.last_encap_request_size = 0;

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_11) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, false,
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP, 0)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    spdm_request_size = sizeof(spdm_challenge_request_t);
    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_13) {
        spdm_request_size = sizeof(spdm_challenge_request_t) + SPDM_REQ_CONTEXT_SIZE;
    }

    if(*encap_request_size < spdm_request_size) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    *encap_request_size = spdm_request_size;

    spdm_request = encap_request;

    spdm_request->header.spdm_version = libspdm_get_connection_version (spdm_context);
    spdm_request->header.request_response_code = SPDM_CHALLENGE;
    spdm_request->header.param1 = spdm_context->encap_context.req_slot_id;
    spdm_request->header.param2 =
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH;
    if(!libspdm_get_random_number(SPDM_NONCE_SIZE, spdm_request->nonce)) {
        return LIBSPDM_STATUS_LOW_ENTROPY;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Encap RequesterNonce - "));
    LIBSPDM_INTERNAL_DUMP_DATA(spdm_request->nonce, SPDM_NONCE_SIZE);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        libspdm_copy_mem(spdm_request + 1, SPDM_REQ_CONTEXT_SIZE,
                         spdm_context->encap_context.req_context, SPDM_REQ_CONTEXT_SIZE);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Encap RequesterContext - "));
        LIBSPDM_INTERNAL_DUMP_DATA((uint8_t *)(spdm_request + 1), SPDM_REQ_CONTEXT_SIZE);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL,
                                                  spdm_request->header.request_response_code);


    /* Cache data*/

    status = libspdm_append_message_mut_c(spdm_context, spdm_request,
                                          spdm_request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    libspdm_copy_mem(&spdm_context->encap_context.last_encap_request_header,
                     sizeof(spdm_context->encap_context.last_encap_request_header),
                     &spdm_request->header, sizeof(spdm_message_header_t));
    spdm_context->encap_context.last_encap_request_size = spdm_request_size;

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_process_encap_response_challenge_auth(
    libspdm_context_t *spdm_context, size_t encap_response_size,
    const void *encap_response, bool *need_continue)
{
    bool result;
    const spdm_challenge_auth_response_t *spdm_response;
    size_t spdm_response_size;
    const uint8_t *ptr;
    const void *cert_chain_hash;
    size_t hash_size;
    uint32_t measurement_summary_hash_size;
    uint16_t opaque_length;
    const void *signature;
    size_t signature_size;
    uint8_t auth_attribute;
    libspdm_return_t status;

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
    } else if (spdm_response->header.request_response_code != SPDM_CHALLENGE_AUTH) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    if (spdm_response_size < sizeof(spdm_challenge_auth_response_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        if (spdm_response_size < sizeof(spdm_challenge_auth_response_t) + SPDM_REQ_CONTEXT_SIZE) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
    }

    auth_attribute = spdm_response->header.param1;
    if (spdm_context->encap_context.req_slot_id == 0xFF) {
        if ((auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_SLOT_ID_MASK) != 0xF) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if (spdm_response->header.param2 != 0) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    } else {
        if ((auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_SLOT_ID_MASK) !=
            spdm_context->encap_context.req_slot_id) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        if ((spdm_response->header.param2 &
             (1 << spdm_context->encap_context.req_slot_id)) == 0) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
    }

    spdm_context->connection_info.peer_used_cert_chain_slot_id =
        spdm_context->encap_context.req_slot_id;

    hash_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    signature_size = libspdm_get_req_asym_signature_size(
        spdm_context->connection_info.algorithm.req_base_asym_alg);
    measurement_summary_hash_size = 0;

    if (spdm_response_size <= sizeof(spdm_challenge_auth_response_t) +
        hash_size + SPDM_NONCE_SIZE +
        measurement_summary_hash_size +
        sizeof(uint16_t)) {
        return LIBSPDM_STATUS_INVALID_MSG_SIZE;
    }

    ptr = (const void *)(spdm_response + 1);

    cert_chain_hash = ptr;
    ptr += hash_size;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Encap cert_chain_hash (0x%zx) - ", hash_size));
    LIBSPDM_INTERNAL_DUMP_DATA(cert_chain_hash, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    if (spdm_context->connection_info.peer_used_cert_chain_slot_id == 0xFF) {
        result = libspdm_verify_public_key_hash(spdm_context, cert_chain_hash, hash_size);
    } else {
        result = libspdm_verify_certificate_chain_hash(spdm_context, cert_chain_hash, hash_size);
    }
    if (!result) {
        return LIBSPDM_STATUS_INVALID_CERT;
    }

    LIBSPDM_DEBUG_CODE(
        const void *nonce;
        nonce = ptr;
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Encap nonce (0x%x) - ", SPDM_NONCE_SIZE));
        LIBSPDM_INTERNAL_DUMP_DATA(nonce, SPDM_NONCE_SIZE);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
        );
    ptr += SPDM_NONCE_SIZE;

    LIBSPDM_DEBUG_CODE(
        const void *measurement_summary_hash;
        measurement_summary_hash = ptr;
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Encap measurement_summary_hash (0x%x) - ",
                       measurement_summary_hash_size));
        LIBSPDM_INTERNAL_DUMP_DATA(measurement_summary_hash, measurement_summary_hash_size);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
        );
    ptr += measurement_summary_hash_size;

    opaque_length = *(const uint16_t *)ptr;
    if (opaque_length > SPDM_MAX_OPAQUE_DATA_SIZE) {
        return LIBSPDM_STATUS_INVALID_MSG_FIELD;
    }
    ptr += sizeof(uint16_t);

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        if (spdm_response_size <
            sizeof(spdm_challenge_auth_response_t) + hash_size +
            SPDM_NONCE_SIZE + measurement_summary_hash_size +
            sizeof(uint16_t) + opaque_length + SPDM_REQ_CONTEXT_SIZE + signature_size) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             hash_size + SPDM_NONCE_SIZE +
                             measurement_summary_hash_size + sizeof(uint16_t) +
                             opaque_length + SPDM_REQ_CONTEXT_SIZE + signature_size;
    } else {
        if (spdm_response_size <
            sizeof(spdm_challenge_auth_response_t) + hash_size +
            SPDM_NONCE_SIZE + measurement_summary_hash_size +
            sizeof(uint16_t) + opaque_length + signature_size) {
            return LIBSPDM_STATUS_INVALID_MSG_SIZE;
        }
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             hash_size + SPDM_NONCE_SIZE +
                             measurement_summary_hash_size + sizeof(uint16_t) +
                             opaque_length + signature_size;
    }

    LIBSPDM_DEBUG_CODE(
        const void *opaque;
        opaque = ptr;
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Encap opaque (0x%x):\n", opaque_length));
        LIBSPDM_INTERNAL_DUMP_HEX(opaque, opaque_length);
        );
    ptr += opaque_length;

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        if (!libspdm_consttime_is_mem_equal(spdm_context->encap_context.req_context, ptr,
                                            SPDM_REQ_CONTEXT_SIZE)) {
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Encap RequesterContext - "));
        LIBSPDM_INTERNAL_DUMP_DATA(ptr, SPDM_REQ_CONTEXT_SIZE);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
        ptr += SPDM_REQ_CONTEXT_SIZE;
    }

    status = libspdm_append_message_mut_c(spdm_context, spdm_response,
                                          spdm_response_size - signature_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    signature = ptr;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Encap signature (0x%zx):\n", signature_size));
    LIBSPDM_INTERNAL_DUMP_HEX(signature, signature_size);
    result = libspdm_verify_challenge_auth_signature(
        spdm_context, false, signature, signature_size);
    if (!result) {
        return LIBSPDM_STATUS_VERIF_FAIL;
    }

    libspdm_set_connection_state(spdm_context,
                                 LIBSPDM_CONNECTION_STATE_AUTHENTICATED);

    *need_continue = false;

    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (..) */
