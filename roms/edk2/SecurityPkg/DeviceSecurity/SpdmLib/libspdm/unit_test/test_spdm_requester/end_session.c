/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)

static uint8_t m_dummy_key_buffer[LIBSPDM_MAX_AEAD_KEY_SIZE];
static uint8_t m_dummy_salt_buffer[LIBSPDM_MAX_AEAD_IV_SIZE];

static void libspdm_secured_message_set_response_data_encryption_key(
    void *spdm_secured_message_context, const void *key, size_t key_size)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    LIBSPDM_ASSERT(key_size == secured_message_context->aead_key_size);
    libspdm_copy_mem(secured_message_context->application_secret.response_data_encryption_key,
                     sizeof(secured_message_context->application_secret.response_data_encryption_key),
                     key, secured_message_context->aead_key_size);
}

static void libspdm_secured_message_set_response_data_salt(
    void *spdm_secured_message_context, const void *salt,
    size_t salt_size)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    LIBSPDM_ASSERT(salt_size == secured_message_context->aead_iv_size);
    libspdm_copy_mem(secured_message_context->application_secret.response_data_salt,
                     sizeof(secured_message_context->application_secret.response_data_salt),
                     salt, secured_message_context->aead_iv_size);
}

libspdm_return_t libspdm_requester_end_session_test_send_message(
    void *spdm_context, size_t request_size, const void *request,
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
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t libspdm_requester_end_session_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x2: {
        spdm_end_session_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        session_id = 0xFFFFFFFF;
        spdm_response_size = sizeof(spdm_end_session_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_END_SESSION_ACK;
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
        ->application_secret.response_data_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: {
        spdm_end_session_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        session_id = 0xFFFFFFFF;
        spdm_response_size = sizeof(spdm_end_session_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_END_SESSION_ACK;
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
        ->application_secret.response_data_sequence_number--;
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
        ->application_secret.response_data_sequence_number--;
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
        ->application_secret.response_data_sequence_number--;
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
            ->application_secret
            .response_data_sequence_number--;
        } else if (sub_index1 == 1) {
            spdm_end_session_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint32_t session_id;
            libspdm_session_info_t *session_info;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            session_id = 0xFFFFFFFF;
            spdm_response_size = sizeof(spdm_end_session_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_END_SESSION_ACK;
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
            ->application_secret
            .response_data_sequence_number--;
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
        ->application_secret.response_data_sequence_number--;
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
        spdm_response->extend_error_data.request_code = SPDM_END_SESSION;
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
        ->application_secret.response_data_sequence_number--;
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
                SPDM_END_SESSION;
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
            ->application_secret
            .response_data_sequence_number--;
        } else if (sub_index2 == 1) {
            spdm_end_session_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint32_t session_id;
            libspdm_session_info_t *session_info;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            session_id = 0xFFFFFFFF;
            spdm_response_size = sizeof(spdm_end_session_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_END_SESSION_ACK;
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
            ->application_secret
            .response_data_sequence_number--;
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

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;

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
            application_secret.response_data_sequence_number--;
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
        spdm_end_session_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        session_id = 0xFFFFFFFF;
        spdm_response_size = sizeof(spdm_end_session_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_END_SESSION_ACK;
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
        ->application_secret.response_data_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0xC: {
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
        ->application_secret.response_data_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

void libspdm_test_requester_end_session_case1(void **state)
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
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    status = libspdm_send_receive_end_session(spdm_context, session_id, 0);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
    free(data);
}

void libspdm_test_requester_end_session_case2(void **state)
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
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_set_mem(m_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_encryption_key(
        session_info->secured_message_context, m_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_salt(
        session_info->secured_message_context, m_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->application_secret.response_data_sequence_number = 0;

    status = libspdm_send_receive_end_session(spdm_context, session_id, 0);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_NOT_STARTED);
    free(data);
}

void libspdm_test_requester_end_session_case3(void **state)
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
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_set_mem(m_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_encryption_key(
        session_info->secured_message_context, m_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_salt(
        session_info->secured_message_context, m_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->application_secret.response_data_sequence_number = 0;

    status = libspdm_send_receive_end_session(spdm_context, session_id, 0);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
    free(data);
}

void libspdm_test_requester_end_session_case4(void **state)
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
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_set_mem(m_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_encryption_key(
        session_info->secured_message_context, m_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_salt(
        session_info->secured_message_context, m_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->application_secret.response_data_sequence_number = 0;

    status = libspdm_send_receive_end_session(spdm_context, session_id, 0);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
    free(data);
}

void libspdm_test_requester_end_session_case5(void **state)
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
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_set_mem(m_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_encryption_key(
        session_info->secured_message_context, m_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_salt(
        session_info->secured_message_context, m_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->application_secret.response_data_sequence_number = 0;

    status = libspdm_send_receive_end_session(spdm_context, session_id, 0);
    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);
    free(data);
}

void libspdm_test_requester_end_session_case6(void **state)
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
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_set_mem(m_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_encryption_key(
        session_info->secured_message_context, m_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_salt(
        session_info->secured_message_context, m_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->application_secret.response_data_sequence_number = 0;

    status = libspdm_send_receive_end_session(spdm_context, session_id, 0);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_NOT_STARTED);
    free(data);
}

void libspdm_test_requester_end_session_case7(void **state)
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
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_set_mem(m_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_encryption_key(
        session_info->secured_message_context, m_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_salt(
        session_info->secured_message_context, m_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->application_secret.response_data_sequence_number = 0;

    status = libspdm_send_receive_end_session(spdm_context, session_id, 0);
    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
    free(data);
}

void libspdm_test_requester_end_session_case8(void **state)
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
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_set_mem(m_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_encryption_key(
        session_info->secured_message_context, m_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_salt(
        session_info->secured_message_context, m_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->application_secret.response_data_sequence_number = 0;

    status = libspdm_send_receive_end_session(spdm_context, session_id, 0);
    assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    free(data);
}

void libspdm_test_requester_end_session_case9(void **state)
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
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_set_mem(m_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_encryption_key(
        session_info->secured_message_context, m_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_salt(
        session_info->secured_message_context, m_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info->secured_message_context))
    ->application_secret.response_data_sequence_number = 0;

    status = libspdm_send_receive_end_session(spdm_context, session_id, 0);
    if (LIBSPDM_RESPOND_IF_READY_SUPPORT) {
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        assert_int_equal(
            libspdm_secured_message_get_session_state(
                spdm_context->session_info[0].secured_message_context),
            LIBSPDM_SESSION_STATE_NOT_STARTED);
    } else {
        assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    }
    free(data);
}

void libspdm_test_requester_end_session_case10(void **state) {
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
        libspdm_secured_message_set_session_state (session_info->secured_message_context,
                                                   LIBSPDM_SESSION_STATE_ESTABLISHED);
        libspdm_set_mem (m_dummy_key_buffer,
                         ((libspdm_secured_message_context_t*)(session_info->secured_message_context))->aead_key_size,
                         (uint8_t)(0xFF));
        libspdm_secured_message_set_response_data_encryption_key (
            session_info->secured_message_context, m_dummy_key_buffer,
            ((libspdm_secured_message_context_t*)(session_info->secured_message_context))->aead_key_size);
        libspdm_set_mem (m_dummy_salt_buffer,
                         ((libspdm_secured_message_context_t*)(session_info->secured_message_context))->aead_iv_size,
                         (uint8_t)(0xFF));
        libspdm_secured_message_set_response_data_salt (session_info->secured_message_context,
                                                        m_dummy_salt_buffer,
                                                        ((libspdm_secured_message_context_t*)(
                                                             session_info
                                                             ->
                                                             secured_message_context))->aead_iv_size);
        ((libspdm_secured_message_context_t*)(session_info->secured_message_context))->
        application_secret.response_data_sequence_number = 0;

        status = libspdm_send_receive_end_session (spdm_context, session_id, 0);
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

void libspdm_test_requester_end_session_case11(void **state)
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
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_set_mem(m_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_encryption_key(
        session_info->secured_message_context, m_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_salt(
        session_info->secured_message_context, m_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->application_secret.response_data_sequence_number = 0;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    session_info->session_transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
    spdm_context->transcript.message_b.buffer_size =
        spdm_context->transcript.message_b.max_buffer_size;
    spdm_context->transcript.message_c.buffer_size =
        spdm_context->transcript.message_c.max_buffer_size;
    spdm_context->transcript.message_mut_b.buffer_size =
        spdm_context->transcript.message_mut_b.max_buffer_size;
    spdm_context->transcript.message_mut_c.buffer_size =
        spdm_context->transcript.message_mut_c.max_buffer_size;
#endif

    status = libspdm_send_receive_end_session(spdm_context, session_id, 0);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_NOT_STARTED);
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
 * Test 12: the requester is setup correctly, but receives an ERROR with SPDM_ERROR_CODE_DECRYPT_ERROR.
 * Expected behavior: client returns a Status of INVALID_SESSION_ID  and free the session ID.
 **/
void libspdm_test_requester_end_session_case12(void **state)
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
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_set_mem(m_dummy_key_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_key_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_encryption_key(
        session_info->secured_message_context, m_dummy_key_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_key_size);
    libspdm_set_mem(m_dummy_salt_buffer,
                    ((libspdm_secured_message_context_t
                      *)(session_info->secured_message_context))
                    ->aead_iv_size,
                    (uint8_t)(0xFF));
    libspdm_secured_message_set_response_data_salt(
        session_info->secured_message_context, m_dummy_salt_buffer,
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->aead_iv_size);
    ((libspdm_secured_message_context_t *)(session_info
                                           ->secured_message_context))
    ->application_secret.response_data_sequence_number = 0;

    status = libspdm_send_receive_end_session(spdm_context, session_id, 0);
    assert_int_equal(status, LIBSPDM_STATUS_SESSION_MSG_ERROR);
    assert_int_equal(spdm_context->session_info->session_id, INVALID_SESSION_ID);

    free(data);
}

libspdm_test_context_t m_libspdm_requester_end_session_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_end_session_test_send_message,
    libspdm_requester_end_session_test_receive_message,
};

int libspdm_requester_end_session_test_main(void)
{
    const struct CMUnitTest spdm_requester_end_session_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(libspdm_test_requester_end_session_case1),
        /* Successful response*/
        cmocka_unit_test(libspdm_test_requester_end_session_case2),
        /* connection_state check failed*/
        cmocka_unit_test(libspdm_test_requester_end_session_case3),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(libspdm_test_requester_end_session_case4),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(libspdm_test_requester_end_session_case5),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_end_session_case6),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(libspdm_test_requester_end_session_case7),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(libspdm_test_requester_end_session_case8),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_end_session_case9),
        /* Unexpected errors*/
        cmocka_unit_test(libspdm_test_requester_end_session_case10),
        /* Buffer reset*/
        cmocka_unit_test(libspdm_test_requester_end_session_case11),
        /* Error response: SPDM_ERROR_CODE_DECRYPT_ERROR*/
        cmocka_unit_test(libspdm_test_requester_end_session_case12),
    };

    libspdm_setup_test_context(&m_libspdm_requester_end_session_test_context);

    return cmocka_run_group_tests(spdm_requester_end_session_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
