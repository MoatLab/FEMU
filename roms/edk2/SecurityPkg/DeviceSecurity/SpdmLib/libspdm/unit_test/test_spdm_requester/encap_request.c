/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP

static uint8_t m_libspdm_local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
static uint8_t temp_buf[LIBSPDM_RECEIVER_BUFFER_SIZE];
static uint8_t temp_buff[LIBSPDM_MAX_SPDM_MSG_SIZE];

libspdm_return_t libspdm_requester_encap_request_test_send_message(void *spdm_context,
                                                                   size_t request_size,
                                                                   const void *request,
                                                                   uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    static uint8_t sub_index = 0;
    spdm_deliver_encapsulated_response_request_t *spdm_deliver_encapsulated_response_request;
    uint8_t send_temp_buf[LIBSPDM_SENDER_BUFFER_SIZE];
    size_t decode_message_size;
    spdm_error_response_t *spdm_response;
    libspdm_return_t status;
    uint32_t *message_session_id;
    bool is_message_app_message;
    uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

    memcpy(message_buffer, request, request_size);

    switch (spdm_test_context->case_id)
    {
    case 0x1:
        return LIBSPDM_STATUS_SEND_FAIL;
    case 0x2:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x3:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x4:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x5:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x6:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x7:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x8:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x9:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xA:
    {
        if (sub_index == 0) {
            sub_index++;
        } else if (sub_index == 1) {
            sub_index = 0;
            message_session_id = NULL;
            is_message_app_message = false;
            spdm_deliver_encapsulated_response_request = (void*) send_temp_buf;
            decode_message_size = sizeof(spdm_deliver_encapsulated_response_request_t) +
                                  sizeof(spdm_error_response_t);
            status = libspdm_transport_test_decode_message(spdm_context, &message_session_id,
                                                           &is_message_app_message, true,
                                                           request_size, message_buffer,
                                                           &decode_message_size,
                                                           (void **)&spdm_deliver_encapsulated_response_request);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "transport_decode_message - %xu\n",
                               status));
            }
            spdm_response = (void*) (spdm_deliver_encapsulated_response_request + 1);
            if (spdm_response->header.request_response_code != SPDM_ERROR) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }
            if (spdm_response->header.param1 != SPDM_ERROR_CODE_UNEXPECTED_REQUEST) { /* Here check ErrorCode should be UnexpectedRequestd */
                return LIBSPDM_STATUS_SEND_FAIL;
            }
            if (spdm_response->header.param2 != 0) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }
        }
        return LIBSPDM_STATUS_SUCCESS;
    }
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t libspdm_requester_encap_request_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{

    libspdm_test_context_t *spdm_test_context;
    spdm_encapsulated_request_response_t *libspdm_encapsulated_request_response;
    uint8_t *digest;
    size_t temp_buf_size;
    uint8_t *temp_buf_ptr;

    spdm_test_context = libspdm_get_test_context();
    static uint8_t sub_index = 0;
    switch (spdm_test_context->case_id)
    {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x2:
    {
        spdm_digest_response_t *spdm_response;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        if (sub_index == 0) {
            temp_buf_size = sizeof(spdm_digest_response_t) +
                            libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                            sizeof(spdm_encapsulated_request_response_t);
            libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
            temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);
            libspdm_encapsulated_request_response = (void*) temp_buf_ptr;
            libspdm_encapsulated_request_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            libspdm_encapsulated_request_response->header.request_response_code =
                SPDM_ENCAPSULATED_REQUEST;
            libspdm_encapsulated_request_response->header.param1 = 0;
            libspdm_encapsulated_request_response->header.param2 = 0;

            spdm_response = (void *)(temp_buf_ptr
                                     + sizeof(spdm_encapsulated_request_response_t));
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_GET_DIGESTS;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            libspdm_set_mem(m_libspdm_local_certificate_chain,
                            sizeof(m_libspdm_local_certificate_chain),
                            (uint8_t)(0xFF));

            digest = (void *)(spdm_response + 1);
            libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_certificate_chain,
                             sizeof(m_libspdm_local_certificate_chain), &digest[0]);
            spdm_response->header.param2 |= (0x01 << 0);
            sub_index++;
        } else if (sub_index == 1) {
            /*When the version is SPDM_MESSAGE_VERSION_12, use the following code*/
            spdm_message_header_t *spdm_encapsulated_response_ack_response;
            temp_buf_size = sizeof(spdm_message_header_t);
            libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
            temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);
            spdm_encapsulated_response_ack_response = (void*) temp_buf_ptr;
            spdm_encapsulated_response_ack_response->spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_encapsulated_response_ack_response->request_response_code =
                SPDM_ENCAPSULATED_RESPONSE_ACK;
            spdm_encapsulated_response_ack_response->param1 = 0;
            spdm_encapsulated_response_ack_response->param2 =
                SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT;
            sub_index = 0;
        } else {
            temp_buf_size = 0;
            temp_buf_ptr = NULL;
        }
        libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                              temp_buf_size, temp_buf_ptr,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x3:
    {
        spdm_digest_response_t *spdm_response;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        if (sub_index == 0) {
            temp_buf_size = sizeof(spdm_digest_response_t) +
                            libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                            sizeof(spdm_encapsulated_request_response_t);
            libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
            temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);
            libspdm_encapsulated_request_response = (void *) temp_buf_ptr;
            libspdm_encapsulated_request_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            libspdm_encapsulated_request_response->header.request_response_code =
                SPDM_ENCAPSULATED_REQUEST;
            libspdm_encapsulated_request_response->header.param1 = 0;
            libspdm_encapsulated_request_response->header.param2 = 0;

            spdm_response =
                (void *)(temp_buf_ptr + sizeof(spdm_encapsulated_request_response_t));
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_GET_DIGESTS;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            libspdm_set_mem(m_libspdm_local_certificate_chain,
                            sizeof(m_libspdm_local_certificate_chain),
                            (uint8_t)(0xFF));

            digest = (void *)(spdm_response + 1);
            libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_certificate_chain,
                             sizeof(m_libspdm_local_certificate_chain), &digest[0]);
            spdm_response->header.param2 |= (0x01 << 0);
            sub_index++;
        } else if (sub_index == 1) {
            /*When the version is SPDM_MESSAGE_VERSION_12, use the following code*/
            spdm_encapsulated_response_ack_response_t *spdm_encapsulated_response_ack_response;
            temp_buf_size = sizeof(spdm_encapsulated_response_ack_response_t);
            libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
            temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);
            spdm_encapsulated_response_ack_response = (void *) temp_buf_ptr;
            spdm_encapsulated_response_ack_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_encapsulated_response_ack_response->header.request_response_code =
                SPDM_ENCAPSULATED_RESPONSE_ACK;
            spdm_encapsulated_response_ack_response->header.param1 = 0;
            spdm_encapsulated_response_ack_response->header.param2 =
                SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT;
            sub_index = 0;
        } else {
            temp_buf_size = 0;
            temp_buf_ptr = NULL;
        }
        libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                              temp_buf_size, temp_buf_ptr,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x4:
    {
        spdm_digest_response_t *spdm_response;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        temp_buf_size = sizeof(spdm_encapsulated_request_response_t);
        libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
        temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);
        spdm_response = (void *) temp_buf_ptr;
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ENCAPSULATED_REQUEST;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                              temp_buf_size, temp_buf_ptr,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x5:
    {
        spdm_digest_response_t *spdm_response;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        if (sub_index == 0) {
            temp_buf_size = sizeof(spdm_digest_response_t) +
                            libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                            sizeof(spdm_encapsulated_request_response_t);
            libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
            temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);
            libspdm_encapsulated_request_response = (void *)temp_buf_ptr;
            libspdm_encapsulated_request_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            libspdm_encapsulated_request_response->header.request_response_code =
                SPDM_ENCAPSULATED_REQUEST;
            libspdm_encapsulated_request_response->header.param1 = 0;
            libspdm_encapsulated_request_response->header.param2 = 0;

            spdm_response =
                (void *)(temp_buf_ptr + sizeof(spdm_encapsulated_request_response_t));
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_GET_DIGESTS;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            libspdm_set_mem(m_libspdm_local_certificate_chain,
                            sizeof(m_libspdm_local_certificate_chain),
                            (uint8_t)(0xFF));

            digest = (void *)(spdm_response + 1);
            libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_certificate_chain,
                             sizeof(m_libspdm_local_certificate_chain), &digest[0]);
            spdm_response->header.param2 |= (0x01 << 0);

            libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                                  temp_buf_size, temp_buf_ptr,
                                                  response_size, response);
            sub_index++;
        } else if (sub_index == 1) {
            size_t temp_buff_size;
            uint8_t *temp_buff_ptr;

            temp_buff_size = sizeof(spdm_message_header_t);
            libspdm_zero_mem(temp_buff, LIBSPDM_MAX_SPDM_MSG_SIZE);
            temp_buff_ptr = temp_buff + sizeof(libspdm_test_message_header_t);

            sub_index = 0;
            libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                                  temp_buff_size, temp_buff_ptr,
                                                  response_size, response);
        }
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x6:
    {
        spdm_digest_response_t *spdm_response;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        if (sub_index == 0) {
            temp_buf_size =
                sizeof(spdm_digest_response_t) +
                libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                sizeof(spdm_encapsulated_request_response_t);
            libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
            temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);

            libspdm_encapsulated_request_response = (void*) temp_buf_ptr;
            libspdm_encapsulated_request_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            libspdm_encapsulated_request_response->header.request_response_code =
                SPDM_ENCAPSULATED_REQUEST;
            libspdm_encapsulated_request_response->header.param1 = 0;
            libspdm_encapsulated_request_response->header.param2 = 0;

            spdm_response =
                (void*) (temp_buf_ptr + sizeof(spdm_encapsulated_request_response_t));
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_GET_DIGESTS;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            libspdm_set_mem(m_libspdm_local_certificate_chain,
                            sizeof(m_libspdm_local_certificate_chain),
                            (uint8_t) (0xFF));

            digest = (void*) (spdm_response + 1);
            libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_certificate_chain,
                             sizeof(m_libspdm_local_certificate_chain), &digest[0]);
            spdm_response->header.param2 |= (0x01 << 0);
            sub_index++;
        } else if (sub_index == 1) {
            spdm_encapsulated_response_ack_response_t* spdm_encapsulated_response_ack_response;
            temp_buf_size = sizeof(spdm_encapsulated_response_ack_response_t);
            libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
            temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);
            spdm_encapsulated_response_ack_response = (void*) temp_buf_ptr;
            spdm_encapsulated_response_ack_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_encapsulated_response_ack_response->header.request_response_code =
                SPDM_ENCAPSULATED_RESPONSE_ACK;
            spdm_encapsulated_response_ack_response->header.param1 = 0;
            spdm_encapsulated_response_ack_response->header.param2 = 0;
            sub_index = 0;
        } else {
            temp_buf_size = 0;
            temp_buf_ptr = NULL;
        }
        libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                              temp_buf_size, temp_buf_ptr,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x7:
    {
        spdm_digest_response_t *spdm_response;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        if (sub_index == 0) {
            temp_buf_size = sizeof(spdm_digest_response_t) +
                            libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                            sizeof(spdm_encapsulated_request_response_t);
            libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
            temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);
            libspdm_encapsulated_request_response = (void *)temp_buf_ptr;
            libspdm_encapsulated_request_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            libspdm_encapsulated_request_response->header.request_response_code =
                SPDM_ENCAPSULATED_REQUEST;
            libspdm_encapsulated_request_response->header.param1 = 0;
            libspdm_encapsulated_request_response->header.param2 = 0;

            spdm_response =
                (void *)(temp_buf_ptr + sizeof(spdm_encapsulated_request_response_t));
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_GET_DIGESTS;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            libspdm_set_mem(m_libspdm_local_certificate_chain,
                            sizeof(m_libspdm_local_certificate_chain),
                            (uint8_t)(0xFF));

            digest = (void *)(spdm_response + 1);
            libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_certificate_chain,
                             sizeof(m_libspdm_local_certificate_chain), &digest[0]);
            spdm_response->header.param2 |= (0x01 << 0);
            sub_index++;
        } else if (sub_index == 1) {
            spdm_encapsulated_response_ack_response_t *spdm_encapsulated_response_ack_response;
            temp_buf_size = sizeof(spdm_encapsulated_response_ack_response_t);
            libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
            temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);
            spdm_encapsulated_response_ack_response = (void *) temp_buf_ptr;
            spdm_encapsulated_response_ack_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_encapsulated_response_ack_response->header.request_response_code =
                SPDM_ENCAPSULATED_RESPONSE_ACK;
            spdm_encapsulated_response_ack_response->header.param1 = 0;
            spdm_encapsulated_response_ack_response->header.param2 =
                SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER;
            sub_index = 0;
        } else {
            temp_buf_size = 0;
            temp_buf_ptr = NULL;
        }
        libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                              temp_buf_size, temp_buf_ptr,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x8:
    {
        spdm_get_certificate_request_t *spdm_response;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        if (sub_index == 0) {
            temp_buf_size = sizeof(spdm_get_certificate_request_t) +
                            sizeof(spdm_encapsulated_request_response_t);
            libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
            temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);
            libspdm_encapsulated_request_response = (void *)temp_buf_ptr;
            libspdm_encapsulated_request_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            libspdm_encapsulated_request_response->header.request_response_code =
                SPDM_ENCAPSULATED_REQUEST;
            libspdm_encapsulated_request_response->header.param1 = 0;
            libspdm_encapsulated_request_response->header.param2 = 0;

            spdm_response =
                (void *)(temp_buf_ptr + sizeof(spdm_encapsulated_request_response_t));
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_GET_CERTIFICATE;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            spdm_response->offset = 0;
            spdm_response->length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            sub_index++;
        } else if (sub_index == 1) {
            /*When the version is SPDM_MESSAGE_VERSION_12, use the following code*/
            spdm_message_header_t *spdm_encapsulated_response_ack_response;
            temp_buf_size = sizeof(spdm_message_header_t);
            libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
            temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);
            spdm_encapsulated_response_ack_response = (void *)temp_buf_ptr;
            spdm_encapsulated_response_ack_response->spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_encapsulated_response_ack_response->request_response_code =
                SPDM_ENCAPSULATED_RESPONSE_ACK;
            spdm_encapsulated_response_ack_response->param1 = 0;
            spdm_encapsulated_response_ack_response->param2 =
                SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT;
            sub_index = 0;
        } else {
            temp_buf_size = 0;
            temp_buf_ptr = NULL;
        }
        libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                              temp_buf_size, temp_buf_ptr,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x9:
    {
        spdm_key_update_request_t *spdm_response;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        if (sub_index == 0) {
            temp_buf_size = sizeof(spdm_key_update_request_t) +
                            sizeof(spdm_encapsulated_request_response_t);
            libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
            temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);
            libspdm_encapsulated_request_response = (void *)temp_buf_ptr;
            libspdm_encapsulated_request_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            libspdm_encapsulated_request_response->header.request_response_code =
                SPDM_ENCAPSULATED_REQUEST;
            libspdm_encapsulated_request_response->header.param1 = 0;
            libspdm_encapsulated_request_response->header.param2 = 0;

            spdm_response =
                (void *)(temp_buf_ptr + sizeof(spdm_encapsulated_request_response_t));
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_KEY_UPDATE;
            spdm_response->header.param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = 0x3;

            sub_index++;
        } else if (sub_index == 1) {
            /*When the version is SPDM_MESSAGE_VERSION_12, use the following code*/
            spdm_message_header_t *spdm_encapsulated_response_ack_response;
            temp_buf_size = sizeof(spdm_message_header_t);
            libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
            temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);
            spdm_encapsulated_response_ack_response = (void *)temp_buf_ptr;
            spdm_encapsulated_response_ack_response->spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_encapsulated_response_ack_response->request_response_code =
                SPDM_ENCAPSULATED_RESPONSE_ACK;
            spdm_encapsulated_response_ack_response->param1 = 0;
            spdm_encapsulated_response_ack_response->param2 =
                SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT;
            sub_index = 0;
        } else {
            temp_buf_size = 0;
            temp_buf_ptr = NULL;
        }
        libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                              temp_buf_size, temp_buf_ptr,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xA:
    {
        spdm_get_encapsulated_request_request_t *spdm_response;

        if (sub_index == 0) {
            temp_buf_size = sizeof(spdm_encapsulated_request_response_t) +
                            sizeof(spdm_get_encapsulated_request_request_t);
            libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
            temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);

            /* The following is ENCAPSULATED_REQUEST response message */
            libspdm_encapsulated_request_response = (void *) temp_buf_ptr;
            libspdm_encapsulated_request_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            libspdm_encapsulated_request_response->header.request_response_code =
                SPDM_ENCAPSULATED_REQUEST;
            libspdm_encapsulated_request_response->header.param1 = 0;
            libspdm_encapsulated_request_response->header.param2 = 0;

            /* The following is EncapsulatedRequest Field of the above ENCAPSULATED_REQUEST response message*/
            spdm_response =
                (void *)(temp_buf_ptr + sizeof(spdm_get_encapsulated_request_request_t));
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_GET_ENCAPSULATED_REQUEST;  /* Here invalid: GET_ENCAPSULATED_REQUEST is encapsulated */
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;

            sub_index++;
        } else if (sub_index == 1) {
            spdm_message_header_t *spdm_encapsulated_response_ack_response;
            temp_buf_size = sizeof(spdm_message_header_t);
            libspdm_zero_mem(temp_buf, LIBSPDM_RECEIVER_BUFFER_SIZE);
            temp_buf_ptr = temp_buf + sizeof(libspdm_test_message_header_t);
            spdm_encapsulated_response_ack_response = (void *)temp_buf_ptr;
            spdm_encapsulated_response_ack_response->spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_encapsulated_response_ack_response->request_response_code =
                SPDM_ENCAPSULATED_RESPONSE_ACK;
            spdm_encapsulated_response_ack_response->param1 = 0;
            spdm_encapsulated_response_ack_response->param2 =
                SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT;
            sub_index = 0;
        } else {
            temp_buf_size = 0;
            temp_buf_ptr = NULL;
        }
        libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                              temp_buf_size, temp_buf_ptr,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP)
void libspdm_test_requester_encap_request_case1(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    libspdm_register_get_encap_response_func(spdm_context, libspdm_get_encap_response_digest);
    status = libspdm_encapsulated_request(spdm_context, NULL, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
    free(data);
}

void libspdm_test_requester_encap_request_case2(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    libspdm_register_get_encap_response_func(spdm_context, libspdm_get_encap_response_digest);
    status = libspdm_encapsulated_request(spdm_context, NULL, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    free(data);
}

void libspdm_test_requester_encap_request_case3(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    libspdm_register_get_encap_response_func(spdm_context, libspdm_get_encap_response_digest);
    status = libspdm_encapsulated_request(spdm_context, NULL, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
    free(data);
}

void libspdm_test_requester_encap_request_case4(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    libspdm_register_get_encap_response_func(spdm_context, libspdm_get_encap_response_digest);
    status = libspdm_encapsulated_request(spdm_context, NULL, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    free(data);
}

void libspdm_test_requester_encap_request_case5(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    libspdm_register_get_encap_response_func(spdm_context, libspdm_get_encap_response_digest);
    status = libspdm_encapsulated_request(spdm_context, NULL, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

void libspdm_test_requester_encap_request_case6(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    libspdm_register_get_encap_response_func(spdm_context, libspdm_get_encap_response_digest);
    status = libspdm_encapsulated_request(spdm_context, NULL, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
    free(data);
}

void libspdm_test_requester_encap_request_case7(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    libspdm_register_get_encap_response_func(spdm_context, libspdm_get_encap_response_digest);
    status = libspdm_encapsulated_request(spdm_context, NULL, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    free(data);
}

void libspdm_test_requester_encap_request_case8(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    libspdm_register_get_encap_response_func(spdm_context, libspdm_get_encap_response_certificate);
    status = libspdm_encapsulated_request(spdm_context, NULL, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    free(data);
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP) */

void libspdm_test_requester_encap_request_case9(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    libspdm_register_get_encap_response_func(spdm_context, libspdm_get_encap_response_key_update);
    status = libspdm_encapsulated_request(spdm_context, NULL, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    free(data);
}

/**
 * Test 10: GET_ENCAPSULATED_REQUEST request message is encapsulated in ENCAPSULATED_REQUEST response message.
 * Expected Behavior: the Requester should respond with ErrorCode=UnexpectedRequest.
 **/
void libspdm_test_requester_encap_request_case10(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    libspdm_register_get_encap_response_func(spdm_context, NULL);
    status = libspdm_encapsulated_request(spdm_context, NULL, 0, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

libspdm_test_context_t m_libspdm_requester_encap_request_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_encap_request_test_send_message,
    libspdm_requester_encap_request_test_receive_message,
};

int libspdm_requester_encap_request_test_main(void)
{
    const struct CMUnitTest spdm_requester_encap_request_tests[] = {
        /* SendRequest failed*/
#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP)
        cmocka_unit_test(libspdm_test_requester_encap_request_case1),
        /* Success Case ,func :libspdm_get_encap_response_digest*/
        cmocka_unit_test(libspdm_test_requester_encap_request_case2),
        /* Error response: When spdm_encapsulated_response_ack_response versions are inconsistent*/
        cmocka_unit_test(libspdm_test_requester_encap_request_case3),
        /* Error response:Receive message only SPDM ENCAPSULATED_REQUEST response*/
        cmocka_unit_test(libspdm_test_requester_encap_request_case4),
        /* Error response: spdm_encapsulated_response_ack_response == NULL*/
        cmocka_unit_test(libspdm_test_requester_encap_request_case5),
        /* Error response: spdm_encapsulated_response_ack_response.param2 == NULL*/
        cmocka_unit_test(libspdm_test_requester_encap_request_case6),
        /* response: param2 == SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER*/
        cmocka_unit_test(libspdm_test_requester_encap_request_case7),
        /*Success Case ,func :libspdm_get_encap_response_certificate */
        cmocka_unit_test(libspdm_test_requester_encap_request_case8),
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (..) */

        /*Success Case ,func :libspdm_get_encap_response_key_update */
        cmocka_unit_test(libspdm_test_requester_encap_request_case9),
        /*Error response: GET_ENCAPSULATED_REQUEST message is encapsulated */
        cmocka_unit_test(libspdm_test_requester_encap_request_case10),
    };

    libspdm_setup_test_context(&m_libspdm_requester_encap_request_test_context);

    return cmocka_run_group_tests(spdm_requester_encap_request_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */
