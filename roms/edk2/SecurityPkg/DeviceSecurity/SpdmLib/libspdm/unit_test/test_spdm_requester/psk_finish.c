/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP

static uint8_t m_libspdm_dummy_key_buffer[LIBSPDM_MAX_AEAD_KEY_SIZE];
static uint8_t m_libspdm_dummy_salt_buffer[LIBSPDM_MAX_AEAD_IV_SIZE];

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_TH_BUFFER_SIZE];

static void libspdm_secured_message_set_dummy_finished_key(
    void *spdm_secured_message_context)
{
}

void libspdm_secured_message_set_response_handshake_encryption_key(
    void *spdm_secured_message_context, const void *key, size_t key_size)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    LIBSPDM_ASSERT(key_size == secured_message_context->aead_key_size);
    libspdm_copy_mem(secured_message_context->handshake_secret.response_handshake_encryption_key,
                     sizeof(secured_message_context->handshake_secret.
                            response_handshake_encryption_key),
                     key, secured_message_context->aead_key_size);
}

void libspdm_secured_message_set_response_handshake_salt(
    void *spdm_secured_message_context, const void *salt,
    size_t salt_size)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    LIBSPDM_ASSERT(salt_size == secured_message_context->aead_iv_size);
    libspdm_copy_mem(secured_message_context->handshake_secret.response_handshake_salt,
                     sizeof(secured_message_context->handshake_secret.response_handshake_salt),
                     salt, secured_message_context->aead_iv_size);
}

libspdm_return_t libspdm_requester_psk_finish_test_send_message(void *spdm_context,
                                                                size_t request_size,
                                                                const void *request,
                                                                uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
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
        return LIBSPDM_STATUS_SUCCESS;
    case 0xB:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xC:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xD:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xE:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xF:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x10: {
        libspdm_return_t status;
        uint8_t *decoded_message;
        size_t decoded_message_size;
        uint32_t session_id;
        uint32_t *message_session_id;
        bool is_app_message;
        libspdm_session_info_t *session_info;
        uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

        message_session_id = NULL;
        session_id = 0xFFFFFFFF;
        decoded_message = (uint8_t *) &m_libspdm_local_buffer[0];
        decoded_message_size = sizeof(m_libspdm_local_buffer);

        session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_SEND_FAIL;
        }

        memcpy(message_buffer, request, request_size);

        ((libspdm_secured_message_context_t *)(session_info->secured_message_context))
        ->handshake_secret.request_handshake_sequence_number--;
        m_libspdm_local_buffer_size = 0;
        libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message, &decoded_message_size);
        status = libspdm_transport_test_decode_message(
            spdm_context,
            &message_session_id, &is_app_message, true, request_size, message_buffer,
            &decoded_message_size, (void **)&decoded_message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return LIBSPDM_STATUS_SEND_FAIL;
        }
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) - m_libspdm_local_buffer_size,
                         decoded_message, decoded_message_size);
        m_libspdm_local_buffer_size += decoded_message_size;
    }
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t libspdm_requester_psk_finish_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x2: {
        spdm_psk_finish_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        session_id = 0xFFFFFFFF;
        spdm_response_size = sizeof(spdm_psk_finish_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        /* WALKAROUND: If just use single context to encode message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->handshake_secret.response_handshake_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: {
        spdm_psk_finish_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        session_id = 0xFFFFFFFF;
        spdm_response_size = sizeof(spdm_psk_finish_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->handshake_secret.response_handshake_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x4: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
        spdm_response->header.param2 = 0;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false,
                                              spdm_response_size,
                                              spdm_response,
                                              response_size, response);
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->handshake_secret.response_handshake_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x5: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
        spdm_response->header.param2 = 0;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false,
                                              spdm_response_size,
                                              spdm_response,
                                              response_size, response);
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->handshake_secret.response_handshake_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x6: {
        static size_t sub_index1 = 0;
        if (sub_index1 == 0) {
            spdm_error_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint32_t session_id;
            libspdm_session_info_t *session_info;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            session_id = 0xFFFFFFFF;
            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response->header.param2 = 0;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(
                spdm_context, &session_id, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
            sub_index1++;
            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->handshake_secret
            .response_handshake_sequence_number--;
        } else if (sub_index1 == 1) {
            spdm_psk_finish_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint32_t session_id;
            libspdm_session_info_t *session_info;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            session_id = 0xFFFFFFFF;
            spdm_response_size = sizeof(spdm_psk_finish_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_PSK_FINISH_RSP;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(
                spdm_context, &session_id, false, false,
                spdm_response_size, spdm_response, response_size,
                response);
            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->handshake_secret
            .response_handshake_sequence_number--;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x7: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
        spdm_response->header.param2 = 0;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false,
                                              spdm_response_size,
                                              spdm_response,
                                              response_size, response);
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->handshake_secret.response_handshake_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x8: {
        spdm_error_response_data_response_not_ready_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 =
            SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response->header.param2 = 0;
        spdm_response->extend_error_data.rd_exponent = 1;
        spdm_response->extend_error_data.rd_tm = 2;
        spdm_response->extend_error_data.request_code = SPDM_PSK_FINISH;
        spdm_response->extend_error_data.token = 0;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false,
                                              spdm_response_size,
                                              spdm_response,
                                              response_size, response);
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->handshake_secret.response_handshake_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x9: {
        static size_t sub_index2 = 0;
        if (sub_index2 == 0) {
            spdm_error_response_data_response_not_ready_t
            *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint32_t session_id;
            libspdm_session_info_t *session_info;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            session_id = 0xFFFFFFFF;
            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 =
                SPDM_ERROR_CODE_RESPONSE_NOT_READY;
            spdm_response->header.param2 = 0;
            spdm_response->extend_error_data.rd_exponent = 1;
            spdm_response->extend_error_data.rd_tm = 2;
            spdm_response->extend_error_data.request_code =
                SPDM_PSK_FINISH;
            spdm_response->extend_error_data.token = 1;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(
                spdm_context, &session_id, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
            sub_index2++;
            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->handshake_secret
            .response_handshake_sequence_number--;
        } else if (sub_index2 == 1) {
            spdm_psk_finish_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint32_t session_id;
            libspdm_session_info_t *session_info;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            session_id = 0xFFFFFFFF;
            spdm_response_size = sizeof(spdm_psk_finish_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_PSK_FINISH_RSP;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(
                spdm_context, &session_id, false, false,
                spdm_response_size, spdm_response, response_size,
                response);
            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->handshake_secret
            .response_handshake_sequence_number--;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xA:
    {
        static uint16_t error_code = LIBSPDM_ERROR_CODE_RESERVED_00;

        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t      *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        session_id = 0xFFFFFFFF;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        if(error_code <= 0xff) {
            libspdm_zero_mem (spdm_response, spdm_response_size);
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = (uint8_t) error_code;
            spdm_response->header.param2 = 0;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message (spdm_context, &session_id, false, false,
                                                   spdm_response_size, spdm_response,
                                                   response_size, response);
            session_info = libspdm_get_session_info_via_session_id (spdm_context, session_id);
            ((libspdm_secured_message_context_t*)(session_info->secured_message_context))->
            handshake_secret.response_handshake_sequence_number--;
        }

        error_code++;
        if(error_code == SPDM_ERROR_CODE_BUSY) { /*busy is treated in cases 5 and 6*/
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) { /*skip some reserved error codes (0d to 3e)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0xB: {
        spdm_psk_finish_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        session_id = 0xFFFFFFFF;
        spdm_response_size = sizeof(spdm_psk_finish_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        /* WALKAROUND: If just use single context to encode message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->handshake_secret.response_handshake_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xC: {
        spdm_psk_finish_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        session_id = 0xFFFFFFFF;
        spdm_response_size = sizeof(spdm_psk_finish_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        /* WALKAROUND: If just use single context to encode message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->handshake_secret.response_handshake_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xD: {
        spdm_psk_finish_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        session_id = 0xFFFFFFFF;
        spdm_response_size = sizeof(spdm_psk_finish_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_FINISH_RSP; /*wrong response code*/
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        /* WALKAROUND: If just use single context to encode message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->handshake_secret.response_handshake_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xE: {
        spdm_psk_finish_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        session_id = 0xFFFFFFFF;
        spdm_response_size = sizeof(spdm_psk_finish_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        /* WALKAROUND: If just use single context to encode message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->handshake_secret.response_handshake_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xF: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        session_id = 0xFFFFFFFF;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_DECRYPT_ERROR;
        spdm_response->header.param2 = 0;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false,
                                              spdm_response_size,
                                              spdm_response,
                                              response_size, response);
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->handshake_secret.response_handshake_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x10: {
        spdm_psk_finish_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        session_id = 0xFFFFFFFF;
        spdm_response_size = sizeof(spdm_psk_finish_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_FINISH_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) - m_libspdm_local_buffer_size,
                         spdm_response, spdm_response_size);
        m_libspdm_local_buffer_size += spdm_response_size;

        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
        session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        /* WALKAROUND: If just use single context to encode message and then decode message */
        ((libspdm_secured_message_context_t*)(session_info->secured_message_context))
        ->handshake_secret.response_handshake_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

/**
 * Test 1: when no PSK_FINISH_RSP message is received, and the client returns
 * a device error.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_psk_finish_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

    status = libspdm_send_receive_psk_finish(spdm_context, session_id);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
    free(data);
}

/**
 * Test 2: receiving a correct PSK_FINISH_RSP message.
 * Expected behavior: client returns a Status of RETURN_SUCCESS and
 * session is established.
 **/
void libspdm_test_requester_psk_finish_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    libspdm_set_mem(m_libspdm_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_encryption_key(
        session_info->secured_message_context, m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_libspdm_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_salt(
        session_info->secured_message_context, m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->handshake_secret.response_handshake_sequence_number = 0;
    libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

    status = libspdm_send_receive_psk_finish(spdm_context, session_id);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    free(data);
}

/**
 * Test 3: requester state has not been negotiated, as if GET_VERSION,
 * GET_CAPABILITIES and NEGOTIATE_ALGORITHMS had not been exchanged.
 * Expected behavior: client returns a Status of RETURN_UNSUPPORTED.
 **/
void libspdm_test_requester_psk_finish_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    libspdm_set_mem(m_libspdm_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_encryption_key(
        session_info->secured_message_context, m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_libspdm_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_salt(
        session_info->secured_message_context, m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->handshake_secret.response_handshake_sequence_number = 0;
    libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

    status = libspdm_send_receive_psk_finish(spdm_context, session_id);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
    free(data);
}

/**
 * Test 4: the requester is setup correctly, but receives an ERROR message
 * indicating InvalidParameters.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_psk_finish_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    libspdm_set_mem(m_libspdm_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_encryption_key(
        session_info->secured_message_context, m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_libspdm_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_salt(
        session_info->secured_message_context, m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->handshake_secret.response_handshake_sequence_number = 0;
    libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

    status = libspdm_send_receive_psk_finish(spdm_context, session_id);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
    assert_int_equal(spdm_context->session_info->session_id, INVALID_SESSION_ID);
    free(data);
}

/**
 * Test 5: the requester is setup correctly, but receives an ERROR message
 * indicating the Busy status of the responder.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_psk_finish_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    libspdm_set_mem(m_libspdm_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_encryption_key(
        session_info->secured_message_context, m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_libspdm_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_salt(
        session_info->secured_message_context, m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->handshake_secret.response_handshake_sequence_number = 0;
    libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

    status = libspdm_send_receive_psk_finish(spdm_context, session_id);
    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);
    free(data);
}

/**
 * Test 6: the requester is setup correctly, but, on the first try, receiving
 * a Busy ERROR message, and, on retry, receiving a correct PSK_FINISH_RSP
 * message.
 * Expected behavior: client returns a Status of RETURN_SUCCESS and session
 * is established.
 **/
void libspdm_test_requester_psk_finish_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->retry_times = 3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    libspdm_set_mem(m_libspdm_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_encryption_key(
        session_info->secured_message_context, m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_libspdm_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_salt(
        session_info->secured_message_context, m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->handshake_secret.response_handshake_sequence_number = 0;
    libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

    status = libspdm_send_receive_psk_finish(spdm_context, session_id);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    free(data);
}

/**
 * Test 7: the requester is setup correctly, but receives an ERROR message
 * indicating the RequestResynch status of the responder.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and the
 * communication is reset to expect a new GET_VERSION message.
 **/
void libspdm_test_requester_psk_finish_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    libspdm_set_mem(m_libspdm_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_encryption_key(
        session_info->secured_message_context, m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_libspdm_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_salt(
        session_info->secured_message_context, m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->handshake_secret.response_handshake_sequence_number = 0;
    libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

    status = libspdm_send_receive_psk_finish(spdm_context, session_id);
    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
    free(data);
}

/**
 * Test 8: the requester is setup correctly, but receives an ERROR message
 * indicating the ResponseNotReady status of the responder.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_psk_finish_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    libspdm_set_mem(m_libspdm_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_encryption_key(
        session_info->secured_message_context, m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_libspdm_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_salt(
        session_info->secured_message_context, m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->handshake_secret.response_handshake_sequence_number = 0;
    libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

    status = libspdm_send_receive_psk_finish(spdm_context, session_id);
    assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    free(data);
}

/**
 * Test 9: the requester is setup correctly, but, on the first try, receiving
 * a ResponseNotReady ERROR message, and, on retry, receiving a correct
 * PSK_FINISH_RSP message.
 * Expected behavior: client returns a Status of RETURN_SUCCESS and session
 * is established.
 **/
void libspdm_test_requester_psk_finish_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    libspdm_set_mem(m_libspdm_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_encryption_key(
        session_info->secured_message_context, m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_libspdm_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_salt(
        session_info->secured_message_context, m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->handshake_secret.response_handshake_sequence_number = 0;
    libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

    status = libspdm_send_receive_psk_finish(spdm_context, session_id);
    if (LIBSPDM_RESPOND_IF_READY_SUPPORT) {
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        assert_int_equal(
            libspdm_secured_message_get_session_state(
                spdm_context->session_info[0].secured_message_context),
            LIBSPDM_SESSION_STATE_ESTABLISHED);
    } else {
        assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    }

    free(data);
}

/**
 * Test 10: receiving an unexpected ERROR message from the responder.
 * There are tests for all named codes, including some reserved ones
 * (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
 * However, for having specific test cases, it is excluded from this case:
 * Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_psk_finish_case10(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint32_t session_id;
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;
    libspdm_session_info_t    *session_info;
    uint16_t error_code;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
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

    error_code = LIBSPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
        libspdm_reset_message_a(spdm_context);

        session_id = 0xFFFFFFFF;
        session_info = &spdm_context->session_info[0];
        libspdm_session_info_init (spdm_context, session_info, session_id, true);
        libspdm_session_info_set_psk_hint(session_info,
                                          LIBSPDM_TEST_PSK_HINT_STRING,
                                          sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
        libspdm_secured_message_set_session_state (session_info->secured_message_context,
                                                   LIBSPDM_SESSION_STATE_HANDSHAKING);
        libspdm_set_mem (m_libspdm_dummy_key_buffer,
                         ((libspdm_secured_message_context_t*)(session_info->secured_message_context))->aead_key_size,
                         (uint8_t)(0xFF));
        libspdm_secured_message_set_response_handshake_encryption_key (
            session_info->secured_message_context, m_libspdm_dummy_key_buffer,
            ((libspdm_secured_message_context_t*)(session_info->secured_message_context))->aead_key_size);
        libspdm_set_mem (m_libspdm_dummy_salt_buffer,
                         ((libspdm_secured_message_context_t*)(session_info->secured_message_context))->aead_iv_size,
                         (uint8_t)(0xFF));
        libspdm_secured_message_set_response_handshake_salt (session_info->secured_message_context,
                                                             m_libspdm_dummy_salt_buffer,
                                                             ((libspdm_secured_message_context_t*)(
                                                                  session_info->
                                                                  secured_message_context))->aead_iv_size);
        ((libspdm_secured_message_context_t*)(session_info->secured_message_context))->
        handshake_secret
        .response_handshake_sequence_number = 0;
        libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

        status = libspdm_send_receive_psk_finish (spdm_context, session_id);
        if(error_code != SPDM_ERROR_CODE_DECRYPT_ERROR) {
            LIBSPDM_ASSERT_INT_EQUAL_CASE (status, LIBSPDM_STATUS_ERROR_PEER, error_code);
        } else {
            LIBSPDM_ASSERT_INT_EQUAL_CASE (status, LIBSPDM_STATUS_SESSION_MSG_ERROR, error_code);
        }

        error_code++;
        if(error_code == SPDM_ERROR_CODE_BUSY) { /*busy is treated in cases 5 and 6*/
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) { /*skip some reserved error codes (0d to 3e)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }

    free(data);
}

void libspdm_test_requester_psk_finish_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    libspdm_set_mem(m_libspdm_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_encryption_key(
        session_info->secured_message_context, m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_libspdm_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_salt(
        session_info->secured_message_context, m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->handshake_secret.response_handshake_sequence_number = 0;
    libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    session_info->session_transcript.message_m.buffer_size =
        session_info->session_transcript.message_m.max_buffer_size;
    spdm_context->transcript.message_b.buffer_size =
        spdm_context->transcript.message_b.max_buffer_size;
    spdm_context->transcript.message_c.buffer_size =
        spdm_context->transcript.message_c.max_buffer_size;
    spdm_context->transcript.message_mut_b.buffer_size =
        spdm_context->transcript.message_mut_b.max_buffer_size;
    spdm_context->transcript.message_mut_c.buffer_size =
        spdm_context->transcript.message_mut_c.max_buffer_size;
#endif

    status = libspdm_send_receive_psk_finish(spdm_context, session_id);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_ESTABLISHED);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(session_info->session_transcript.message_m.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 12: requester is not setup correctly to support pre-shared keys
 * (no capabilities). The responder would attempt to return a correct
 * PSK_FINISH_RSP message.
 * Expected behavior: client returns a Status of RETURN_UNSUPPORTED.
 **/
void libspdm_test_requester_psk_finish_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    /*no PSK capabilities*/
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    spdm_context->transcript.message_a.buffer_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    libspdm_set_mem(m_libspdm_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_encryption_key(
        session_info->secured_message_context, m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_libspdm_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_salt(
        session_info->secured_message_context, m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->handshake_secret.response_handshake_sequence_number = 0;
    libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

    status = libspdm_send_receive_psk_finish(spdm_context, session_id);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    free(data);
}

/**
 * Test 13: receiving an incorrect FINISH_RSP message, with wrong response
 * code, but all other field correct.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_psk_finish_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    /*no PSK capabilities*/
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    spdm_context->transcript.message_a.buffer_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    libspdm_set_mem(m_libspdm_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_encryption_key(
        session_info->secured_message_context, m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_libspdm_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_salt(
        session_info->secured_message_context, m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->handshake_secret.response_handshake_sequence_number = 0;
    libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

    status = libspdm_send_receive_psk_finish(spdm_context, session_id);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

/**
 * Test 14: requester is not setup correctly by not initializing a
 * session during PSK_EXCHANGE. The responder would attempt to
 * return a correct PSK_FINISH_RSP message.
 * Expected behavior: client returns a Status of RETURN_UNSUPPORTED.
 **/
void libspdm_test_requester_psk_finish_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    /*no PSK capabilities*/
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    spdm_context->transcript.message_a.buffer_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_NOT_STARTED);
    libspdm_set_mem(m_libspdm_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_encryption_key(
        session_info->secured_message_context, m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_libspdm_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_salt(
        session_info->secured_message_context, m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->handshake_secret.response_handshake_sequence_number = 0;
    libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

    status = libspdm_send_receive_psk_finish(spdm_context, session_id);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
    free(data);
}

/**
 * Test 15 the requester is setup correctly, but receives an ERROR with SPDM_ERROR_CODE_DECRYPT_ERROR.
 * Expected behavior: client returns a Status of INVALID_SESSION_ID  and free the session ID.
 **/
void libspdm_test_requester_psk_finish_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    libspdm_set_mem(m_libspdm_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_encryption_key(
        session_info->secured_message_context, m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_libspdm_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_salt(
        session_info->secured_message_context, m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->handshake_secret.response_handshake_sequence_number = 0;
    libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

    status = libspdm_send_receive_psk_finish(spdm_context, session_id);
    assert_int_equal(status, LIBSPDM_STATUS_SESSION_MSG_ERROR);
    assert_int_equal(spdm_context->session_info->session_id, INVALID_SESSION_ID);
    free(data);
}

/**
 * Test 16: a request message is successfully sent and a response message is successfully received.
 * Expected Behavior: requester returns the status RETURN_SUCCESS and a PSK_FINISH_RSP message is
 * received, buffer F appends the exchanged PSK_FINISH and PSK_FINISH_RSP messages.
 **/
void libspdm_test_requester_psk_finish_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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


    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    libspdm_set_mem(m_libspdm_dummy_key_buffer,
                    ((libspdm_secured_message_context_t*)(session_info->secured_message_context))
                    ->aead_key_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_encryption_key(
        session_info->secured_message_context, m_libspdm_dummy_key_buffer,
        ((libspdm_secured_message_context_t*)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_libspdm_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t*)(session_info->secured_message_context))
                    ->aead_iv_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_response_handshake_salt(
        session_info->secured_message_context, m_libspdm_dummy_salt_buffer,
        ((libspdm_secured_message_context_t*)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info->secured_message_context))
    ->handshake_secret.response_handshake_sequence_number = 0;
    ((libspdm_secured_message_context_t *)(session_info->secured_message_context))
    ->handshake_secret.request_handshake_sequence_number = 0;
    libspdm_secured_message_set_dummy_finished_key (session_info->secured_message_context);

    status = libspdm_send_receive_psk_finish(spdm_context, session_id);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_ESTABLISHED);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->session_info[0].session_transcript.message_f.buffer_size,
                     m_libspdm_local_buffer_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer (0x%x):\n",
                   m_libspdm_local_buffer_size));
    libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
    assert_memory_equal(spdm_context->session_info[0].session_transcript.message_f.buffer,
                        m_libspdm_local_buffer, m_libspdm_local_buffer_size);
#endif
    free(data);
}

libspdm_test_context_t m_libspdm_requester_psk_finish_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_psk_finish_test_send_message,
    libspdm_requester_psk_finish_test_receive_message,
};

int libspdm_requester_psk_finish_test_main(void)
{
    const struct CMUnitTest spdm_requester_psk_finish_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case1),
        /* Successful response*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case2),
        /* connection_state check failed*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case3),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case4),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case5),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case6),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case7),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case8),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case9),
        /* Unexpected errors*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case10),
        /* Buffer reset*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case11),
        /* No correct setup*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case12),
        /* Wrong response code*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case13),
        /* Uninitialized session*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case14),
        /* Error response: SPDM_ERROR_CODE_DECRYPT_ERROR*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case15),
        /* Buffer verification*/
        cmocka_unit_test(libspdm_test_requester_psk_finish_case16),
    };

    libspdm_setup_test_context(&m_libspdm_requester_psk_finish_test_context);

    return cmocka_run_group_tests(spdm_requester_psk_finish_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/
