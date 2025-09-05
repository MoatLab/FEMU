/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint8_t cert_chain_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t nonce[SPDM_NONCE_SIZE];
    uint8_t measurement_summary_hash[LIBSPDM_MAX_HASH_SIZE];
    uint16_t opaque_length;
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    uint8_t requester_context[SPDM_REQ_CONTEXT_SIZE];
    uint8_t signature[LIBSPDM_MAX_ASYM_KEY_SIZE];
} libspdm_challenge_auth_response_max_t;
#pragma pack()

/**
 * This function sends CHALLENGE to authenticate the device based upon the key in one slot.
 *
 * This function verifies the signature in the challenge auth.
 *
 * If basic mutual authentication is requested from the responder,
 * this function also perform the basic mutual authentication.
 *
 * @param  spdm_context           A pointer to the SPDM context.
 * @param  slot_id                The number of slot for the challenge.
 * @param  requester_context      If not NULL, a buffer to hold the requester context (8 bytes).
 *                                It is used only if the negotiated version >= 1.3.
 * @param  measurement_hash_type  The type of the measurement hash.
 * @param  measurement_hash       A pointer to a destination buffer to store the measurement hash.
 * @param  slot_mask              A pointer to a destination to store the slot mask.
 * @param  requester_nonce_in     If not NULL, a buffer that holds the requester nonce (32 bytes)
 * @param  requester_nonce        If not NULL, a buffer to hold the requester nonce (32 bytes).
 * @param  responder_nonce        If not NULL, a buffer to hold the responder nonce (32 bytes).
 *
 * @retval RETURN_SUCCESS               The challenge auth is got successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
static libspdm_return_t libspdm_try_challenge(libspdm_context_t *spdm_context,
                                              uint8_t slot_id,
                                              const void *requester_context,
                                              uint8_t measurement_hash_type,
                                              void *measurement_hash,
                                              uint8_t *slot_mask,
                                              const void *requester_nonce_in,
                                              void *requester_nonce,
                                              void *responder_nonce,
                                              void *opaque_data,
                                              size_t *opaque_data_size)
{
    libspdm_return_t status;
    bool result;
    spdm_challenge_request_t *spdm_request;
    size_t spdm_request_size;
    libspdm_challenge_auth_response_max_t *spdm_response;
    size_t spdm_response_size;
    uint8_t *ptr;
    void *cert_chain_hash;
    size_t hash_size;
    uint32_t measurement_summary_hash_size;
    void *nonce;
    void *measurement_summary_hash;
    uint16_t opaque_length;
    void *signature;
    size_t signature_size;
    uint8_t auth_attribute;
    uint8_t *message;
    size_t message_size;
    size_t transport_header_size;

    /* -=[Check Parameters Phase]=- */
    LIBSPDM_ASSERT((slot_id < SPDM_MAX_SLOT_COUNT) || (slot_id == 0xff));
    LIBSPDM_ASSERT((slot_id != 0xff) ||
                   (spdm_context->local_context.peer_public_key_provision_size != 0));
    LIBSPDM_ASSERT(measurement_hash_type == SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH ||
                   measurement_hash_type == SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH ||
                   measurement_hash_type == SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH);

    /* -=[Verify State Phase]=- */
    if (!libspdm_is_capabilities_flag_supported(
            spdm_context, true, 0,
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    libspdm_reset_message_buffer_via_request_code(spdm_context, NULL, SPDM_CHALLENGE);

    /* -=[Construct Request Phase]=- */
    spdm_context->connection_info.peer_used_cert_chain_slot_id = slot_id;
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
    spdm_request->header.request_response_code = SPDM_CHALLENGE;
    spdm_request->header.param1 = slot_id;
    spdm_request->header.param2 = measurement_hash_type;
    spdm_request_size = sizeof(spdm_challenge_request_t);
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        spdm_request_size = sizeof(spdm_challenge_request_t) + SPDM_REQ_CONTEXT_SIZE;
    }
    if (requester_nonce_in == NULL) {
        if(!libspdm_get_random_number(SPDM_NONCE_SIZE, spdm_request->nonce)) {
            libspdm_release_sender_buffer (spdm_context);
            return LIBSPDM_STATUS_LOW_ENTROPY;
        }
    } else {
        libspdm_copy_mem(spdm_request->nonce, sizeof(spdm_request->nonce),
                         requester_nonce_in, SPDM_NONCE_SIZE);
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "RequesterNonce - "));
    LIBSPDM_INTERNAL_DUMP_DATA(spdm_request->nonce, SPDM_NONCE_SIZE);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    if (requester_nonce != NULL) {
        libspdm_copy_mem(requester_nonce, SPDM_NONCE_SIZE, spdm_request->nonce, SPDM_NONCE_SIZE);
    }
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        if (requester_context == NULL) {
            libspdm_zero_mem(spdm_request + 1, SPDM_REQ_CONTEXT_SIZE);
        } else {
            libspdm_copy_mem(spdm_request + 1, SPDM_REQ_CONTEXT_SIZE,
                             requester_context, SPDM_REQ_CONTEXT_SIZE);
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "RequesterContext - "));
        LIBSPDM_INTERNAL_DUMP_DATA((uint8_t *)(spdm_request + 1), SPDM_REQ_CONTEXT_SIZE);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    }

    /* -=[Send Request Phase]=- */
    status = libspdm_send_spdm_request(spdm_context, NULL, spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* -=[Receive Response Phase]=- */
    status = libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    libspdm_zero_mem(spdm_response, spdm_response_size);
    status = libspdm_receive_spdm_response(
        spdm_context, NULL, &spdm_response_size, (void **)&spdm_response);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }

    /* -=[Validate Response Phase]=- */
    if (spdm_response_size < sizeof(spdm_message_header_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version != spdm_request->header.spdm_version) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        status = libspdm_handle_error_response_main(
            spdm_context, NULL,
            &spdm_response_size,
            (void **)&spdm_response, SPDM_CHALLENGE, SPDM_CHALLENGE_AUTH);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_CHALLENGE_AUTH) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response_size < sizeof(spdm_challenge_auth_response_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }
    auth_attribute = spdm_response->header.param1;
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_11 && slot_id == 0xFF) {
        if ((auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_SLOT_ID_MASK) != 0xF) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
    } else {
        if ((spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_11 &&
             (auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_SLOT_ID_MASK) != slot_id) ||
            (spdm_response->header.spdm_version == SPDM_MESSAGE_VERSION_10 &&
             auth_attribute != slot_id)) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
        if ((spdm_response->header.param2 & (1 << slot_id)) == 0) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
    }
    if ((auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_BASIC_MUT_AUTH_REQ) != 0) {
        if (!libspdm_is_capabilities_flag_supported(
                spdm_context, true,
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP)) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
    }

    /* -=[Process Response Phase]=- */
    hash_size = libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    signature_size = libspdm_get_asym_signature_size(
        spdm_context->connection_info.algorithm.base_asym_algo);
    measurement_summary_hash_size = libspdm_get_measurement_summary_hash_size(
        spdm_context, true, measurement_hash_type);

    if (spdm_response_size <= sizeof(spdm_challenge_auth_response_t) +
        hash_size + SPDM_NONCE_SIZE + measurement_summary_hash_size + sizeof(uint16_t)) {
        status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
        goto receive_done;
    }

    ptr = spdm_response->cert_chain_hash;

    cert_chain_hash = ptr;
    ptr += hash_size;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "cert_chain_hash (0x%zx) - ", hash_size));
    LIBSPDM_INTERNAL_DUMP_DATA(cert_chain_hash, hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    if (slot_id == 0xFF) {
        result = libspdm_verify_public_key_hash(spdm_context, cert_chain_hash, hash_size);
    } else {
        result = libspdm_verify_certificate_chain_hash(spdm_context, cert_chain_hash, hash_size);
    }
    if (!result) {
        status = LIBSPDM_STATUS_VERIF_FAIL;
        goto receive_done;
    }

    nonce = ptr;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "nonce (0x%x) - ", SPDM_NONCE_SIZE));
    LIBSPDM_INTERNAL_DUMP_DATA(nonce, SPDM_NONCE_SIZE);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    ptr += SPDM_NONCE_SIZE;
    if (responder_nonce != NULL) {
        libspdm_copy_mem(responder_nonce, SPDM_NONCE_SIZE, nonce, SPDM_NONCE_SIZE);
    }

    measurement_summary_hash = ptr;
    ptr += measurement_summary_hash_size;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "measurement_summary_hash (0x%x) - ",
                   measurement_summary_hash_size));
    LIBSPDM_INTERNAL_DUMP_DATA(measurement_summary_hash, measurement_summary_hash_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));

    opaque_length = libspdm_read_uint16((const uint8_t *)ptr);
    if (opaque_length > SPDM_MAX_OPAQUE_DATA_SIZE) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        if (((spdm_context->connection_info.algorithm.other_params_support &
              SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_MASK) ==
             SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_NONE) &&
            (opaque_length != 0)) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
    }
    ptr += sizeof(uint16_t);
    if (opaque_length != 0) {
        result = libspdm_process_general_opaque_data_check(spdm_context, opaque_length, ptr);
        if (!result) {
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
    }

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        if (spdm_response_size <
            sizeof(spdm_challenge_auth_response_t) + hash_size +
            SPDM_NONCE_SIZE + measurement_summary_hash_size +
            sizeof(uint16_t) + opaque_length + SPDM_REQ_CONTEXT_SIZE +
            signature_size) {
            status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
            goto receive_done;
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
            status = LIBSPDM_STATUS_INVALID_MSG_SIZE;
            goto receive_done;
        }
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             hash_size + SPDM_NONCE_SIZE +
                             measurement_summary_hash_size + sizeof(uint16_t) +
                             opaque_length + signature_size;
    }

    if ((opaque_data != NULL) && (opaque_data_size != NULL)) {
        if (opaque_length >= *opaque_data_size) {
            status = LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            goto receive_done;
        }
        libspdm_copy_mem(opaque_data, *opaque_data_size, ptr, opaque_length);
        *opaque_data_size = opaque_length;
    }

    ptr += opaque_length;
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "RequesterContext - "));
        LIBSPDM_INTERNAL_DUMP_DATA(ptr, SPDM_REQ_CONTEXT_SIZE);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
        if (!libspdm_consttime_is_mem_equal(spdm_request + 1, ptr, SPDM_REQ_CONTEXT_SIZE)) {
            libspdm_reset_message_c(spdm_context);
            status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
            goto receive_done;
        }
        ptr += SPDM_REQ_CONTEXT_SIZE;
    }

    status = libspdm_append_message_c(spdm_context, spdm_request, spdm_request_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        goto receive_done;
    }
    status = libspdm_append_message_c(spdm_context, spdm_response,
                                      spdm_response_size - signature_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_reset_message_c(spdm_context);
        goto receive_done;
    }

    signature = ptr;
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "signature (0x%zx):\n", signature_size));
    LIBSPDM_INTERNAL_DUMP_HEX(signature, signature_size);
    result = libspdm_verify_challenge_auth_signature(spdm_context, true, signature, signature_size);
    if (!result) {
        libspdm_reset_message_c(spdm_context);
        status = LIBSPDM_STATUS_VERIF_FAIL;
        goto receive_done;
    }

    if (measurement_hash != NULL) {
        libspdm_copy_mem(measurement_hash, measurement_summary_hash_size,
                         measurement_summary_hash, measurement_summary_hash_size);
    }
    if (slot_mask != NULL) {
        *slot_mask = spdm_response->header.param2;
    }

    /* -=[Update State Phase]=- */
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP)
    if ((auth_attribute & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_BASIC_MUT_AUTH_REQ) != 0) {
        /* we must release it here, because libspdm_encapsulated_request() will acquire again. */
        libspdm_release_receiver_buffer (spdm_context);

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "BasicMutAuth :\n"));
        status = libspdm_encapsulated_request(spdm_context, NULL, 0, NULL);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                       "libspdm_challenge - libspdm_encapsulated_request - %xu\n", status));
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            libspdm_reset_message_c(spdm_context);
            return status;
        }
        spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
        return LIBSPDM_STATUS_SUCCESS;
    }
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) */

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    status = LIBSPDM_STATUS_SUCCESS;

receive_done:
    libspdm_release_receiver_buffer (spdm_context);
    return status;
}

libspdm_return_t libspdm_challenge(void *spdm_context, void *reserved,
                                   uint8_t slot_id,
                                   uint8_t measurement_hash_type,
                                   void *measurement_hash,
                                   uint8_t *slot_mask)
{
    libspdm_context_t *context;
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;

    context = spdm_context;
    context->crypto_request = true;
    retry = context->retry_times;
    retry_delay_time = context->retry_delay_time;
    do {
        status = libspdm_try_challenge(context, slot_id, NULL,
                                       measurement_hash_type,
                                       measurement_hash, slot_mask,
                                       NULL, NULL, NULL, NULL, NULL);
        if ((status != LIBSPDM_STATUS_BUSY_PEER) || (retry == 0)) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

libspdm_return_t libspdm_challenge_ex(void *spdm_context, void *reserved,
                                      uint8_t slot_id,
                                      uint8_t measurement_hash_type,
                                      void *measurement_hash,
                                      uint8_t *slot_mask,
                                      const void *requester_nonce_in,
                                      void *requester_nonce,
                                      void *responder_nonce,
                                      void *opaque_data,
                                      size_t *opaque_data_size)
{
    libspdm_context_t *context;
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;

    context = spdm_context;
    context->crypto_request = true;
    retry = context->retry_times;
    retry_delay_time = context->retry_delay_time;
    do {
        status = libspdm_try_challenge(context, slot_id, NULL,
                                       measurement_hash_type,
                                       measurement_hash,
                                       slot_mask,
                                       requester_nonce_in,
                                       requester_nonce, responder_nonce,
                                       opaque_data,
                                       opaque_data_size);
        if ((status != LIBSPDM_STATUS_BUSY_PEER) || (retry == 0)) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

libspdm_return_t libspdm_challenge_ex2(void *spdm_context, void *reserved,
                                       uint8_t slot_id,
                                       const void *requester_context,
                                       uint8_t measurement_hash_type,
                                       void *measurement_hash,
                                       uint8_t *slot_mask,
                                       const void *requester_nonce_in,
                                       void *requester_nonce,
                                       void *responder_nonce,
                                       void *opaque_data,
                                       size_t *opaque_data_size)
{
    libspdm_context_t *context;
    size_t retry;
    uint64_t retry_delay_time;
    libspdm_return_t status;

    context = spdm_context;
    context->crypto_request = true;
    retry = context->retry_times;
    retry_delay_time = context->retry_delay_time;
    do {
        status = libspdm_try_challenge(context, slot_id, requester_context,
                                       measurement_hash_type,
                                       measurement_hash,
                                       slot_mask,
                                       requester_nonce_in,
                                       requester_nonce, responder_nonce,
                                       opaque_data,
                                       opaque_data_size);
        if ((status != LIBSPDM_STATUS_BUSY_PEER) || (retry == 0)) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP */
