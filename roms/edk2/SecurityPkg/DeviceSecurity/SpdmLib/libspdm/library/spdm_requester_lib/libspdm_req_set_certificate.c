/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
/**
 * This function sends SET_CERTIFICATE
 * to set certificate from the device.
 *
 * @param  context                      A pointer to the SPDM context.
 * @param  session_id                   Indicates if it is a secured message protected via SPDM session.
 *                                      If session_id is NULL, it is a normal message.
 *                                      If session_id is NOT NULL, it is a secured message.
 * @param  slot_id                      The number of slot for the certificate chain.
 * @param  cert_chain                   The pointer for the certificate chain to set.
 *                                      The cert chain is a full SPDM certificate chain, including Length and Root Cert Hash.
 * @param  cert_chain_size              The size of the certificate chain to set.
 * @param  request_attribute            Set certificate request attributes. This field is only used for SPDM 1.3 and above.
 *                                      And the bit[0~3] of request_attribute must be 0.
 * @param  key_pair_id                  The value of this field shall be the unique key pair number identifying the desired
 *                                      asymmetric key pair to associate with SlotID .
 *
 * @retval RETURN_SUCCESS               The measurement is got successfully.
 * @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
 * @retval RETURN_SECURITY_VIOLATION    Any verification fails.
 **/
static libspdm_return_t libspdm_try_set_certificate(libspdm_context_t *spdm_context,
                                                    const uint32_t *session_id, uint8_t slot_id,
                                                    void *cert_chain, size_t cert_chain_size,
                                                    uint8_t request_attribute,
                                                    uint8_t key_pair_id)
{
    libspdm_return_t status;
    spdm_set_certificate_request_t *spdm_request;
    size_t spdm_request_size;
    spdm_set_certificate_response_t *spdm_response;
    size_t spdm_response_size;
    size_t transport_header_size;
    uint8_t *message;
    size_t message_size;
    libspdm_session_info_t *session_info;
    libspdm_session_state_t session_state;

    LIBSPDM_ASSERT(slot_id < SPDM_MAX_SLOT_COUNT);

    if (libspdm_get_connection_version(spdm_context) < SPDM_MESSAGE_VERSION_12) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }
    if (libspdm_get_connection_version (spdm_context) < SPDM_MESSAGE_VERSION_13) {
        if ((cert_chain == NULL) || (cert_chain_size == 0)) {
            return LIBSPDM_STATUS_INVALID_PARAMETER;
        }
    }
    /* SET_CERT_CAP for a 1.2 Responder is not checked because it was not defined in SPDM 1.2.0. */
    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_13) {
        if (!libspdm_is_capabilities_flag_supported(
                spdm_context, true, 0,
                SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP)) {
            return LIBSPDM_STATUS_UNSUPPORTED_CAP;
        }
    }

    if (spdm_context->connection_info.connection_state < LIBSPDM_CONNECTION_STATE_NEGOTIATED) {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    if (session_id != NULL) {
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, *session_id);
        if (session_info == NULL) {
            LIBSPDM_ASSERT(false);
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        session_state = libspdm_secured_message_get_session_state(
            session_info->secured_message_context);
        if (session_state != LIBSPDM_SESSION_STATE_ESTABLISHED) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
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
    spdm_request->header.request_response_code = SPDM_SET_CERTIFICATE;
    spdm_request->header.param1 = slot_id & SPDM_SET_CERTIFICATE_REQUEST_SLOT_ID_MASK;
    spdm_request->header.param2 = 0;

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        /*And the bit[0~3] of request_attribute must be 0.*/
        if ((request_attribute & SPDM_SET_CERTIFICATE_REQUEST_SLOT_ID_MASK) != 0) {
            return LIBSPDM_STATUS_INVALID_PARAMETER;
        }

        if ((request_attribute & SPDM_SET_CERTIFICATE_REQUEST_ATTRIBUTES_ERASE) != 0) {
            /*the CertChain field shall be absent*/
            cert_chain_size = 0;
            /*the value of SetCertModel shall be zero*/
            spdm_request->header.param1 &= ~SPDM_SET_CERTIFICATE_REQUEST_ATTRIBUTES_CERT_MODEL_MASK;
            /*set Erase bit */
            spdm_request->header.param1 |= SPDM_SET_CERTIFICATE_REQUEST_ATTRIBUTES_ERASE;
        }

        if (spdm_context->connection_info.multi_key_conn_rsp) {
            spdm_request->header.param2 = key_pair_id;
        }
    }

    LIBSPDM_ASSERT(spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12);

    if ((libspdm_get_connection_version (spdm_context) < SPDM_MESSAGE_VERSION_13) ||
        (cert_chain_size != 0)) {
        if (cert_chain == NULL) {
            return LIBSPDM_STATUS_INVALID_PARAMETER;
        }

        libspdm_copy_mem(spdm_request + 1,
                         spdm_request_size - sizeof(spdm_set_certificate_request_t),
                         (uint8_t *)cert_chain, cert_chain_size);
    }

    spdm_request_size = sizeof(spdm_set_certificate_request_t) + cert_chain_size;

    status = libspdm_send_spdm_request(spdm_context, session_id, spdm_request_size, spdm_request);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        libspdm_release_sender_buffer (spdm_context);
        return status;
    }
    libspdm_release_sender_buffer (spdm_context);
    spdm_request = (void *)spdm_context->last_spdm_request;

    /* receive */
    status = libspdm_acquire_receiver_buffer (spdm_context, &message_size, (void **)&message);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_ASSERT (message_size >= transport_header_size);
    spdm_response = (void *)(message);
    spdm_response_size = message_size;

    libspdm_zero_mem(spdm_response, spdm_response_size);
    status = libspdm_receive_spdm_response(spdm_context, session_id,
                                           &spdm_response_size, (void **)&spdm_response);

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
        status = libspdm_handle_error_response_main(
            spdm_context, NULL,
            &spdm_response_size,
            (void **)&spdm_response, SPDM_SET_CERTIFICATE, SPDM_SET_CERTIFICATE_RSP);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            goto receive_done;
        }
    } else if (spdm_response->header.request_response_code != SPDM_SET_CERTIFICATE_RSP) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }
    if ((spdm_response->header.param1 & SPDM_CERTIFICATE_RESPONSE_SLOT_ID_MASK) != slot_id) {
        status = LIBSPDM_STATUS_INVALID_MSG_FIELD;
        goto receive_done;
    }

    /* -=[Log Message Phase]=- */
    #if LIBSPDM_ENABLE_MSG_LOG
    libspdm_append_msg_log(spdm_context, spdm_response, spdm_response_size);
    #endif /* LIBSPDM_ENABLE_MSG_LOG */

    status = LIBSPDM_STATUS_SUCCESS;

receive_done:
    libspdm_release_receiver_buffer (spdm_context);
    return status;
}

libspdm_return_t libspdm_set_certificate(void *spdm_context,
                                         const uint32_t *session_id, uint8_t slot_id,
                                         void *cert_chain, size_t cert_chain_size)
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
        status = libspdm_try_set_certificate(context, session_id, slot_id,
                                             cert_chain, cert_chain_size, 0, 0);
        if ((status != LIBSPDM_STATUS_BUSY_PEER) || (retry == 0)) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

libspdm_return_t libspdm_set_certificate_ex(void *spdm_context,
                                            const uint32_t *session_id, uint8_t slot_id,
                                            void *cert_chain, size_t cert_chain_size,
                                            uint8_t request_attribute,
                                            uint8_t key_pair_id)
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
        status = libspdm_try_set_certificate(context, session_id, slot_id,
                                             cert_chain, cert_chain_size,
                                             request_attribute, key_pair_id);
        if ((status != LIBSPDM_STATUS_BUSY_PEER) || (retry == 0)) {
            return status;
        }

        libspdm_sleep(retry_delay_time);
    } while (retry-- != 0);

    return status;
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP*/
