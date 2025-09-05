/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)

static uint8_t m_libspdm_last_token;
static uint8_t m_libspdm_last_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
static uint8_t m_libspdm_last_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
static uint64_t m_libspdm_last_rsp_sequence_number;

static void libspdm_set_standard_key_update_test_state(
    libspdm_context_t *spdm_context, uint32_t *session_id)
{
    void                   *data;
    size_t data_size;
    void                   *hash;
    size_t hash_size;
    libspdm_session_info_t    *session_info;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
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

    *session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, *session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    free(data);
}

static void libspdm_set_standard_key_update_test_secrets(
    libspdm_secured_message_context_t *secured_message_context,
    uint8_t *m_rsp_secret_buffer, uint8_t rsp_secret_fill,
    uint8_t *m_req_secret_buffer, uint8_t req_secret_fill)
{
    libspdm_set_mem(m_rsp_secret_buffer, secured_message_context
                    ->hash_size, rsp_secret_fill);
    libspdm_set_mem(m_req_secret_buffer, secured_message_context
                    ->hash_size, req_secret_fill);

    libspdm_copy_mem(secured_message_context->application_secret.response_data_secret,
                     sizeof(secured_message_context->application_secret.response_data_secret),
                     m_rsp_secret_buffer, secured_message_context->aead_key_size);
    libspdm_copy_mem(secured_message_context->application_secret.request_data_secret,
                     sizeof(secured_message_context->application_secret.request_data_secret),
                     m_req_secret_buffer, secured_message_context->aead_key_size);

    libspdm_set_mem(secured_message_context->application_secret
                    .response_data_encryption_key,
                    secured_message_context->aead_key_size, (uint8_t)(0xFF));
    libspdm_set_mem(secured_message_context->application_secret
                    .response_data_salt,
                    secured_message_context->aead_iv_size, (uint8_t)(0xFF));


    libspdm_set_mem(secured_message_context->application_secret
                    .request_data_encryption_key,
                    secured_message_context->aead_key_size, (uint8_t)(0xEE));
    libspdm_set_mem(secured_message_context->application_secret
                    .request_data_salt,
                    secured_message_context->aead_iv_size, (uint8_t)(0xEE));

    secured_message_context->application_secret.
    response_data_sequence_number = 0;
    secured_message_context->application_secret.
    request_data_sequence_number = 0;
}

static void libspdm_compute_secret_update(spdm_version_number_t spdm_version,
                                          size_t hash_size,
                                          const uint8_t *in_secret, uint8_t *out_secret,
                                          size_t out_secret_size)
{
    uint8_t bin_str9[128];
    size_t bin_str9_size;

    bin_str9_size = sizeof(bin_str9);
    libspdm_bin_concat(spdm_version,
                       SPDM_BIN_STR_9_LABEL, sizeof(SPDM_BIN_STR_9_LABEL) - 1,
                       NULL, (uint16_t)hash_size, hash_size, bin_str9,
                       &bin_str9_size);

    libspdm_hkdf_expand(m_libspdm_use_hash_algo, in_secret, hash_size, bin_str9,
                        bin_str9_size, out_secret, out_secret_size);
}

libspdm_return_t libspdm_requester_key_update_test_send_message(
    void *spdm_context, size_t request_size, const void *request,
    uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_SEND_FAIL;
    case 0x2: {
        libspdm_return_t status;
        uint8_t *decoded_message;
        size_t decoded_message_size;
        uint32_t session_id;
        uint32_t              *message_session_id;
        bool is_app_message;
        libspdm_session_info_t *session_info;
        uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

        message_session_id = NULL;
        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_SEND_FAIL;
        }

        memcpy(message_buffer, request, request_size);

        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.request_data_sequence_number--;
        libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message, &decoded_message_size);
        status = libspdm_transport_test_decode_message(spdm_context,
                                                       &message_session_id, &is_app_message, true,
                                                       request_size,
                                                       message_buffer, &decoded_message_size,
                                                       (void **)&decoded_message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return LIBSPDM_STATUS_SEND_FAIL;
        }

        m_libspdm_last_token = ((spdm_key_update_request_t
                                 *) decoded_message)->header.param2;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x3: {
        static size_t sub_index = 0;

        if(sub_index > 0) {
            libspdm_return_t status;
            uint8_t *decoded_message;
            size_t decoded_message_size;
            uint32_t session_id;
            uint32_t              *message_session_id;
            bool is_app_message;
            libspdm_session_info_t *session_info;
            uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            memcpy(message_buffer, request, request_size);

            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.request_data_sequence_number--;
            libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message,
                                        &decoded_message_size);
            status = libspdm_transport_test_decode_message(spdm_context,
                                                           &message_session_id, &is_app_message,
                                                           true,
                                                           request_size,
                                                           message_buffer, &decoded_message_size,
                                                           (void **)&decoded_message);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            m_libspdm_last_token = ((spdm_key_update_request_t
                                     *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x4: {
        static size_t sub_index = 0;

        if(sub_index > 0) {
            libspdm_return_t status;
            uint8_t *decoded_message;
            size_t decoded_message_size;
            uint32_t session_id;
            uint32_t              *message_session_id;
            bool is_app_message;
            libspdm_session_info_t *session_info;
            uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            memcpy(message_buffer, request, request_size);

            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.request_data_sequence_number--;
            libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message,
                                        &decoded_message_size);
            status = libspdm_transport_test_decode_message(spdm_context,
                                                           &message_session_id, &is_app_message,
                                                           true,
                                                           request_size,
                                                           message_buffer, &decoded_message_size,
                                                           (void **)&decoded_message);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            m_libspdm_last_token = ((spdm_key_update_request_t
                                     *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x5: {
        static size_t sub_index = 0;

        if(sub_index > 0) {
            libspdm_return_t status;
            uint8_t *decoded_message;
            size_t decoded_message_size;
            uint32_t session_id;
            uint32_t              *message_session_id;
            bool is_app_message;
            libspdm_session_info_t *session_info;
            uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            memcpy(message_buffer, request, request_size);

            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.request_data_sequence_number--;
            libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message,
                                        &decoded_message_size);
            status = libspdm_transport_test_decode_message(spdm_context,
                                                           &message_session_id, &is_app_message,
                                                           true,
                                                           request_size,
                                                           message_buffer, &decoded_message_size,
                                                           (void **)&decoded_message);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            m_libspdm_last_token = ((spdm_key_update_request_t
                                     *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x6: {
        static size_t sub_index = 0;

        if(sub_index > 0) {
            libspdm_return_t status;
            uint8_t *decoded_message;
            size_t decoded_message_size;
            uint32_t session_id;
            uint32_t              *message_session_id;
            bool is_app_message;
            libspdm_session_info_t *session_info;
            uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            memcpy(message_buffer, request, request_size);

            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.request_data_sequence_number--;
            libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message,
                                        &decoded_message_size);
            status = libspdm_transport_test_decode_message(spdm_context,
                                                           &message_session_id, &is_app_message,
                                                           true,
                                                           request_size,
                                                           message_buffer, &decoded_message_size,
                                                           (void **)&decoded_message);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            m_libspdm_last_token = ((spdm_key_update_request_t
                                     *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x7:
    case 0x8:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x9: {
        static size_t sub_index = 0;

        if(sub_index != 1) {
            libspdm_return_t status;
            uint8_t *decoded_message;
            size_t decoded_message_size;
            uint32_t session_id;
            uint32_t *message_session_id;
            bool is_app_message;
            libspdm_session_info_t    *session_info;
            uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            memcpy(message_buffer, request, request_size);

            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.request_data_sequence_number--;
            libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message,
                                        &decoded_message_size);
            status = libspdm_transport_test_decode_message(spdm_context,
                                                           &message_session_id, &is_app_message,
                                                           true,
                                                           request_size,
                                                           message_buffer, &decoded_message_size,
                                                           (void **)&decoded_message);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            m_libspdm_last_token = ((spdm_key_update_request_t
                                     *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0xA:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xB:
    case 0xC:
    case 0xD:
    case 0xE:
    case 0xF:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x15: {
        libspdm_return_t status;
        uint8_t *decoded_message;
        size_t decoded_message_size;
        uint32_t session_id;
        uint32_t              *message_session_id;
        bool is_app_message;
        libspdm_session_info_t *session_info;
        uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

        message_session_id = NULL;
        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_SEND_FAIL;
        }

        memcpy(message_buffer, request, request_size);

        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.request_data_sequence_number--;
        libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message, &decoded_message_size);
        status = libspdm_transport_test_decode_message(spdm_context,
                                                       &message_session_id, &is_app_message, true,
                                                       request_size,
                                                       message_buffer, &decoded_message_size,
                                                       (void **)&decoded_message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return LIBSPDM_STATUS_SEND_FAIL;
        }

        m_libspdm_last_token = ((spdm_key_update_request_t
                                 *) decoded_message)->header.param2;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x16: {
        static size_t sub_index = 0;

        if(sub_index < 2) {
            libspdm_return_t status;
            uint8_t *decoded_message;
            size_t decoded_message_size;
            uint32_t session_id;
            uint32_t *message_session_id;
            bool is_app_message;
            libspdm_session_info_t    *session_info;
            uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            memcpy(message_buffer, request, request_size);

            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.request_data_sequence_number--;
            libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message,
                                        &decoded_message_size);
            status = libspdm_transport_test_decode_message(spdm_context,
                                                           &message_session_id, &is_app_message,
                                                           true,
                                                           request_size,
                                                           message_buffer, &decoded_message_size,
                                                           (void **)&decoded_message);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            m_libspdm_last_token = ((spdm_key_update_request_t
                                     *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x17: {
        static size_t sub_index = 0;

        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "send message: %zu\n", sub_index));

        if(sub_index%2 == 0) {
            libspdm_return_t status;
            uint8_t *decoded_message;
            size_t decoded_message_size;
            uint32_t session_id;
            uint32_t *message_session_id;
            bool is_app_message;
            libspdm_session_info_t    *session_info;
            uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            memcpy(message_buffer, request, request_size);

            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.request_data_sequence_number--;
            libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message,
                                        &decoded_message_size);
            status = libspdm_transport_test_decode_message(spdm_context,
                                                           &message_session_id, &is_app_message,
                                                           true,
                                                           request_size,
                                                           message_buffer, &decoded_message_size,
                                                           (void **)&decoded_message);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            m_libspdm_last_token = ((spdm_key_update_request_t
                                     *) decoded_message)->header.param2;

            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "last token: %x\n", m_libspdm_last_token));
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x18:
    case 0x19:
    case 0x1A: {
        libspdm_return_t status;
        uint8_t *decoded_message;
        size_t decoded_message_size;
        uint32_t session_id;
        uint32_t              *message_session_id;
        bool is_app_message;
        libspdm_session_info_t *session_info;
        uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

        message_session_id = NULL;
        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_SEND_FAIL;
        }

        memcpy(message_buffer, request, request_size);

        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.request_data_sequence_number--;
        libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message, &decoded_message_size);
        status = libspdm_transport_test_decode_message(spdm_context,
                                                       &message_session_id, &is_app_message, true,
                                                       request_size,
                                                       message_buffer, &decoded_message_size,
                                                       (void **)&decoded_message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return LIBSPDM_STATUS_SEND_FAIL;
        }

        m_libspdm_last_token = ((spdm_key_update_request_t
                                 *) decoded_message)->header.param2;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1B: {
        libspdm_return_t status;
        uint8_t *decoded_message;
        size_t decoded_message_size;
        uint32_t session_id;
        uint32_t              *message_session_id;
        bool is_app_message;
        libspdm_session_info_t *session_info;
        uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

        message_session_id = NULL;
        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_SEND_FAIL;
        }

        memcpy(message_buffer, request, request_size);

        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.request_data_sequence_number--;
        libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message, &decoded_message_size);
        status = libspdm_transport_test_decode_message(spdm_context,
                                                       &message_session_id, &is_app_message, true,
                                                       request_size,
                                                       message_buffer, &decoded_message_size,
                                                       (void **)&decoded_message);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return LIBSPDM_STATUS_SEND_FAIL;
        }

        m_libspdm_last_token = ((spdm_key_update_request_t
                                 *) decoded_message)->header.param2;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1C: {
        static size_t sub_index = 0;

        if(sub_index > 0) {
            libspdm_return_t status;
            uint8_t *decoded_message;
            size_t decoded_message_size;
            uint32_t session_id;
            uint32_t              *message_session_id;
            bool is_app_message;
            libspdm_session_info_t *session_info;
            uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            memcpy(message_buffer, request, request_size);

            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.request_data_sequence_number--;
            libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message,
                                        &decoded_message_size);
            status = libspdm_transport_test_decode_message(spdm_context,
                                                           &message_session_id, &is_app_message,
                                                           true,
                                                           request_size,
                                                           message_buffer, &decoded_message_size,
                                                           (void **)&decoded_message);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            m_libspdm_last_token = ((spdm_key_update_request_t
                                     *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1D: {
        static size_t sub_index = 0;

        if(sub_index > 0) {
            libspdm_return_t status;
            uint8_t *decoded_message;
            size_t decoded_message_size;
            uint32_t session_id;
            uint32_t              *message_session_id;
            bool is_app_message;
            libspdm_session_info_t *session_info;
            uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            memcpy(message_buffer, request, request_size);

            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.request_data_sequence_number--;
            libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message,
                                        &decoded_message_size);
            status = libspdm_transport_test_decode_message(spdm_context,
                                                           &message_session_id, &is_app_message,
                                                           true,
                                                           request_size,
                                                           message_buffer, &decoded_message_size,
                                                           (void **)&decoded_message);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            m_libspdm_last_token = ((spdm_key_update_request_t
                                     *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1E: {
        static size_t sub_index = 0;

        if(sub_index > 0) {
            libspdm_return_t status;
            uint8_t *decoded_message;
            size_t decoded_message_size;
            uint32_t session_id;
            uint32_t              *message_session_id;
            bool is_app_message;
            libspdm_session_info_t *session_info;
            uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            memcpy(message_buffer, request, request_size);

            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.request_data_sequence_number--;
            libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message,
                                        &decoded_message_size);
            status = libspdm_transport_test_decode_message(spdm_context,
                                                           &message_session_id, &is_app_message,
                                                           true,
                                                           request_size,
                                                           message_buffer, &decoded_message_size,
                                                           (void **)&decoded_message);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            m_libspdm_last_token = ((spdm_key_update_request_t
                                     *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1F:
    case 0x20:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x21: {
        static size_t sub_index = 0;

        if(sub_index != 1) {
            libspdm_return_t status;
            uint8_t *decoded_message;
            size_t decoded_message_size;
            uint32_t session_id;
            uint32_t *message_session_id;
            bool is_app_message;
            libspdm_session_info_t    *session_info;
            uint8_t message_buffer[LIBSPDM_SENDER_BUFFER_SIZE];

            message_session_id = NULL;
            session_id = 0xFFFFFFFF;

            session_info = libspdm_get_session_info_via_session_id(
                spdm_context, session_id);
            if (session_info == NULL) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            memcpy(message_buffer, request, request_size);

            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.request_data_sequence_number--;
            libspdm_get_scratch_buffer (spdm_context, (void **)&decoded_message,
                                        &decoded_message_size);
            status = libspdm_transport_test_decode_message(spdm_context,
                                                           &message_session_id, &is_app_message,
                                                           true,
                                                           request_size,
                                                           message_buffer, &decoded_message_size,
                                                           (void **)&decoded_message);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return LIBSPDM_STATUS_SEND_FAIL;
            }

            m_libspdm_last_token = ((spdm_key_update_request_t
                                     *) decoded_message)->header.param2;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x22:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x23:
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t libspdm_requester_key_update_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x2: {
        static size_t sub_index = 0;

        spdm_key_update_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t        *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_key_update_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        } else if (sub_index == 1) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        }

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: {
        static size_t sub_index = 0;

        spdm_key_update_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t        *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_key_update_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        } else if (sub_index == 1) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        }

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x4: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t    *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

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
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
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
        libspdm_session_info_t    *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

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
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x6: {
        static size_t sub_index = 0;

        uint32_t session_id;
        libspdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        if (sub_index == 0) {
            spdm_error_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

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
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        } else if (sub_index == 1) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        } else if (sub_index == 2) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x7: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t    *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

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
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
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
        libspdm_session_info_t    *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 =
            SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response->header.param2 = 0;
        spdm_response->extend_error_data.rd_exponent = 1;
        spdm_response->extend_error_data.rd_tm = 2;
        spdm_response->extend_error_data.request_code = SPDM_KEY_UPDATE;
        spdm_response->extend_error_data.token = 0;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x9: {
        static size_t sub_index = 0;

        uint32_t session_id;
        libspdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        if (sub_index == 0) {
            spdm_error_response_data_response_not_ready_t
            *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 =
                SPDM_ERROR_CODE_RESPONSE_NOT_READY;
            spdm_response->header.param2 = 0;
            spdm_response->extend_error_data.rd_exponent = 1;
            spdm_response->extend_error_data.rd_tm = 2;
            spdm_response->extend_error_data.request_code =
                SPDM_KEY_UPDATE;
            spdm_response->extend_error_data.token = 1;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        } else if (sub_index == 1) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        } else if (sub_index == 2) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xA: {
        static uint16_t error_code = LIBSPDM_ERROR_CODE_RESERVED_00;

        uint32_t session_id;
        libspdm_session_info_t    *session_info;

        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        if(error_code <= 0xff) {
            /* skip SPDM_ERROR_CODE_DECRYPT_ERROR, because this case will free context*/
            if(error_code == SPDM_ERROR_CODE_DECRYPT_ERROR) {
                error_code++;
            }
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
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        }

        error_code++;
        /*busy is treated in cases 5 and 6*/
        if(error_code == SPDM_ERROR_CODE_BUSY) {
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        /*skip some reserved error codes (0d to 3e)*/
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) {
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xB: {
        static size_t sub_index = 0;

        spdm_key_update_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t        *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_key_update_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        } else if (sub_index == 1) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        }

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xC: {
        static size_t sub_index = 0;

        spdm_key_update_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t        *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_key_update_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        /*wrong response code*/
        spdm_response->header.request_response_code =
            SPDM_KEY_UPDATE;
        if (sub_index == 0) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        } else if (sub_index == 1) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        }

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xD: {
        static size_t sub_index = 0;

        spdm_key_update_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t        *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_key_update_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        } else if (sub_index == 1) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        }

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xE: {
        static size_t sub_index = 0;

        spdm_key_update_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t        *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_key_update_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        } else if (sub_index == 1) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        }

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xF: {
        static size_t sub_index = 0;

        spdm_key_update_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t        *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_key_update_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            /*wrong token*/
            spdm_response->header.param2 = m_libspdm_last_token + 1;
        } else if (sub_index == 1) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        }

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x10: {
        static size_t sub_index = 0;

        spdm_key_update_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t        *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_key_update_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            /*wrong operation code*/
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS;
            spdm_response->header.param2 = m_libspdm_last_token;
        } else if (sub_index == 1) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        }

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x11: {
        static size_t sub_index = 0;

        uint32_t session_id;
        libspdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        if (sub_index == 0) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        } else if (sub_index == 1) {
            spdm_error_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
            spdm_response->header.param2 = 0;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x12: {
        static size_t sub_index = 0;

        uint32_t session_id;
        libspdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        if (sub_index == 0) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        } else {
            spdm_error_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
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
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x13: {
        static size_t sub_index = 0;

        uint32_t session_id;
        libspdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        if (sub_index == 0) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        } else if (sub_index == 1) {
            spdm_error_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

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
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        } else if (sub_index == 2) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x14: {
        static size_t sub_index = 0;

        uint32_t session_id;
        libspdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        if (sub_index == 0) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        } else if (sub_index == 1) {
            spdm_error_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
            spdm_response->header.param2 = 0;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x15: {
        static size_t sub_index = 0;

        uint32_t session_id;
        libspdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        if (sub_index == 0) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        } else {
            spdm_error_response_data_response_not_ready_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 =
                SPDM_ERROR_CODE_RESPONSE_NOT_READY;
            spdm_response->header.param2 = 0;
            spdm_response->extend_error_data.rd_exponent = 1;
            spdm_response->extend_error_data.rd_tm = 2;
            spdm_response->extend_error_data.request_code = SPDM_KEY_UPDATE;
            spdm_response->extend_error_data.token = 0;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x16: {
        static size_t sub_index = 0;

        uint32_t session_id;
        libspdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        if (sub_index == 0) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        } else if (sub_index == 1) {
            spdm_error_response_data_response_not_ready_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 =
                SPDM_ERROR_CODE_RESPONSE_NOT_READY;
            spdm_response->header.param2 = 0;
            spdm_response->extend_error_data.rd_exponent = 1;
            spdm_response->extend_error_data.rd_tm = 2;
            spdm_response->extend_error_data.request_code = SPDM_KEY_UPDATE;
            spdm_response->extend_error_data.token = 0;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        } else if (sub_index == 2) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            ((libspdm_secured_message_context_t
              *)(session_info->secured_message_context))
            ->application_secret.response_data_sequence_number--;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x17: {
        static size_t sub_index = 0;
        static uint16_t error_code = LIBSPDM_ERROR_CODE_RESERVED_00;

        uint32_t session_id;
        libspdm_session_info_t    *session_info;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        if(error_code <= 0xff) {
            /* skip SPDM_ERROR_CODE_DECRYPT_ERROR, because this case will free context*/
            if(error_code == SPDM_ERROR_CODE_DECRYPT_ERROR) {
                error_code++;
            }
            if (sub_index%2 == 0) {
                spdm_key_update_response_t *spdm_response;
                size_t spdm_response_size;
                size_t transport_header_size;
                uint8_t *scratch_buffer;
                size_t scratch_buffer_size;

                spdm_response_size = sizeof(spdm_key_update_response_t);
                transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
                spdm_response = (void *)((uint8_t *)*response + transport_header_size);

                spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
                spdm_response->header.request_response_code =
                    SPDM_KEY_UPDATE_ACK;
                spdm_response->header.param1 =
                    SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
                spdm_response->header.param2 = m_libspdm_last_token;

                /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
                 * transport_message is always in sender buffer. */
                libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                            &scratch_buffer_size);
                libspdm_copy_mem (scratch_buffer + transport_header_size,
                                  scratch_buffer_size - transport_header_size,
                                  spdm_response, spdm_response_size);
                spdm_response = (void *)(scratch_buffer + transport_header_size);
                libspdm_transport_test_encode_message(spdm_context,
                                                      &session_id, false, false,
                                                      spdm_response_size, spdm_response,
                                                      response_size, response);
                /* WALKAROUND: If just use single context to encode
                 * message and then decode message */
                ((libspdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;
            } else {
                spdm_error_response_t *spdm_response;
                size_t spdm_response_size;
                size_t transport_header_size;
                uint8_t *scratch_buffer;
                size_t scratch_buffer_size;

                spdm_response_size = sizeof(spdm_error_response_t);
                transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
                spdm_response = (void *)((uint8_t *)*response + transport_header_size);

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
                libspdm_transport_test_encode_message(spdm_context,
                                                      &session_id, false, false,
                                                      spdm_response_size, spdm_response,
                                                      response_size, response);
                /* WALKAROUND: If just use single context to encode
                 * message and then decode message */
                ((libspdm_secured_message_context_t
                  *)(session_info->secured_message_context))
                ->application_secret.response_data_sequence_number--;

                error_code++;
                /*busy is treated in cases 5 and 6*/
                if(error_code == SPDM_ERROR_CODE_BUSY) {
                    error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
                }
                /*skip some reserved error codes (0d to 3e)*/
                if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) {
                    error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
                }
                /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
                if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
                    error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
                }
            }
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x18: {
        static size_t sub_index = 0;

        spdm_key_update_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t        *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_key_update_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        } else if (sub_index == 1) {
            /*wrong response code*/
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        }

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x19: {
        static size_t sub_index = 0;

        spdm_key_update_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t        *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_key_update_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        } else if (sub_index == 1) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            /*wrong token*/
            spdm_response->header.param2 = m_libspdm_last_token + 1;
        }

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1A: {
        static size_t sub_index = 0;

        spdm_key_update_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t        *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_key_update_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        } else if (sub_index == 1) {
            /*wrong operation code*/
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;
        }

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1B: {
        static size_t sub_index = 0;

        spdm_key_update_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t        *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_key_update_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;

        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_KEY_UPDATE_ACK;
        if (sub_index == 0) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS;
            spdm_response->header.param2 = m_libspdm_last_token;
        } else if (sub_index == 1) {
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* as it is using single context, the keys were updated
             * in the requester and do not need to be updated before
             * sending the response */
        }

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1C: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t    *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        libspdm_secured_message_context_t *secured_message_context;
        uint8_t curr_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
        uint8_t curr_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
        uint64_t curr_rsp_sequence_number;

        spdm_response_size = sizeof(spdm_key_update_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        secured_message_context = session_info->secured_message_context;

        /*use previous key to send*/
        libspdm_copy_mem(curr_rsp_enc_key, sizeof(curr_rsp_enc_key),
                         secured_message_context
                         ->application_secret.response_data_encryption_key,
                         secured_message_context->aead_key_size);
        libspdm_copy_mem(curr_rsp_salt, sizeof(curr_rsp_salt),
                         secured_message_context
                         ->application_secret.response_data_salt,
                         secured_message_context->aead_iv_size);
        curr_rsp_sequence_number = m_libspdm_last_rsp_sequence_number;

        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_encryption_key,
                         sizeof(secured_message_context->application_secret
                                .response_data_encryption_key),
                         m_libspdm_last_rsp_enc_key,
                         secured_message_context->aead_key_size);
        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_salt,
                         sizeof(secured_message_context->application_secret
                                .response_data_salt),
                         m_libspdm_last_rsp_salt,
                         secured_message_context->aead_iv_size);
        secured_message_context->application_secret
        .response_data_sequence_number = m_libspdm_last_rsp_sequence_number;

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
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);

        /*restore new key*/
        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_encryption_key,
                         sizeof(secured_message_context->application_secret
                                .response_data_encryption_key),
                         curr_rsp_enc_key,
                         secured_message_context->aead_key_size);
        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_salt,
                         sizeof(secured_message_context->application_secret
                                .response_data_salt),
                         curr_rsp_salt,
                         secured_message_context->aead_iv_size);
        secured_message_context->application_secret
        .response_data_sequence_number = curr_rsp_sequence_number;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1D: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t    *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        libspdm_secured_message_context_t *secured_message_context;
        uint8_t curr_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
        uint8_t curr_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
        uint64_t curr_rsp_sequence_number;

        spdm_response_size = sizeof(spdm_key_update_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        secured_message_context = session_info->secured_message_context;

        /*use previous key to send*/
        libspdm_copy_mem(curr_rsp_enc_key, sizeof(curr_rsp_enc_key),
                         secured_message_context
                         ->application_secret.response_data_encryption_key,
                         secured_message_context->aead_key_size);
        libspdm_copy_mem(curr_rsp_salt, sizeof(curr_rsp_salt),
                         secured_message_context
                         ->application_secret.response_data_salt,
                         secured_message_context->aead_iv_size);
        curr_rsp_sequence_number = m_libspdm_last_rsp_sequence_number;

        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_encryption_key,
                         sizeof(secured_message_context->application_secret
                                .response_data_encryption_key),
                         m_libspdm_last_rsp_enc_key,
                         secured_message_context->aead_key_size);
        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_salt,
                         sizeof(secured_message_context->application_secret
                                .response_data_salt),
                         m_libspdm_last_rsp_salt,
                         secured_message_context->aead_iv_size);
        secured_message_context->application_secret
        .response_data_sequence_number = m_libspdm_last_rsp_sequence_number;

        /* once the sequence number is used, it should be increased for next BUSY message.*/
        m_libspdm_last_rsp_sequence_number++;

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
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);

        /*restore new key*/
        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_encryption_key,
                         sizeof(secured_message_context->application_secret
                                .response_data_encryption_key),
                         curr_rsp_enc_key,
                         secured_message_context->aead_key_size);
        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_salt,
                         sizeof(secured_message_context->application_secret
                                .response_data_salt),
                         curr_rsp_salt,
                         secured_message_context->aead_iv_size);
        secured_message_context->application_secret
        .response_data_sequence_number = curr_rsp_sequence_number;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1E: {
        static size_t sub_index = 0;

        uint32_t session_id;
        libspdm_session_info_t    *session_info;

        libspdm_secured_message_context_t *secured_message_context;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        secured_message_context = session_info->secured_message_context;

        if (sub_index == 0) {
            spdm_error_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            uint8_t curr_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
            uint8_t curr_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
            uint64_t curr_rsp_sequence_number;

            /*use previous key to send*/
            libspdm_copy_mem(curr_rsp_enc_key, sizeof(curr_rsp_enc_key),
                             secured_message_context
                             ->application_secret.response_data_encryption_key,
                             secured_message_context->aead_key_size);
            libspdm_copy_mem(curr_rsp_salt, sizeof(curr_rsp_salt),
                             secured_message_context
                             ->application_secret.response_data_salt,
                             secured_message_context->aead_iv_size);
            curr_rsp_sequence_number = m_libspdm_last_rsp_sequence_number;

            libspdm_copy_mem(secured_message_context->application_secret
                             .response_data_encryption_key,
                             sizeof(secured_message_context->application_secret
                                    .response_data_encryption_key),
                             m_libspdm_last_rsp_enc_key,
                             secured_message_context->aead_key_size);
            libspdm_copy_mem(secured_message_context->application_secret
                             .response_data_salt,
                             sizeof(secured_message_context->application_secret
                                    .response_data_salt),
                             m_libspdm_last_rsp_salt,
                             secured_message_context->aead_iv_size);
            secured_message_context->application_secret
            .response_data_sequence_number = m_libspdm_last_rsp_sequence_number;

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
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);

            /*restore new key*/
            libspdm_copy_mem(secured_message_context->application_secret
                             .response_data_encryption_key,
                             sizeof(secured_message_context->application_secret
                                    .response_data_encryption_key),
                             curr_rsp_enc_key,
                             secured_message_context->aead_key_size);
            libspdm_copy_mem(secured_message_context->application_secret
                             .response_data_salt,
                             sizeof(secured_message_context->application_secret
                                    .response_data_salt),
                             curr_rsp_salt,
                             secured_message_context->aead_iv_size);
            secured_message_context->application_secret
            .response_data_sequence_number = curr_rsp_sequence_number;
        } else if (sub_index == 1) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            secured_message_context->application_secret
            .response_data_sequence_number--;
        } else if (sub_index == 2) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            secured_message_context->application_secret
            .response_data_sequence_number--;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1F: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t    *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        libspdm_secured_message_context_t *secured_message_context;
        uint8_t curr_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
        uint8_t curr_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
        uint64_t curr_rsp_sequence_number;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        secured_message_context = session_info->secured_message_context;

        /*use previous key to send*/
        libspdm_copy_mem(curr_rsp_enc_key, sizeof(curr_rsp_enc_key),
                         secured_message_context
                         ->application_secret.response_data_encryption_key,
                         secured_message_context->aead_key_size);
        libspdm_copy_mem(curr_rsp_salt, sizeof(curr_rsp_salt),
                         secured_message_context
                         ->application_secret.response_data_salt,
                         secured_message_context->aead_iv_size);
        curr_rsp_sequence_number = m_libspdm_last_rsp_sequence_number;

        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_encryption_key,
                         sizeof(secured_message_context->application_secret
                                .response_data_encryption_key),
                         m_libspdm_last_rsp_enc_key,
                         secured_message_context->aead_key_size);
        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_salt,
                         sizeof(secured_message_context->application_secret
                                .response_data_salt),
                         m_libspdm_last_rsp_salt,
                         secured_message_context->aead_iv_size);
        secured_message_context->application_secret
        .response_data_sequence_number = m_libspdm_last_rsp_sequence_number;

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
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);

        /*restore new key*/
        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_encryption_key,
                         sizeof(secured_message_context->application_secret
                                .response_data_encryption_key),
                         curr_rsp_enc_key,
                         secured_message_context->aead_key_size);
        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_salt,
                         sizeof(secured_message_context->application_secret
                                .response_data_salt),
                         curr_rsp_salt,
                         secured_message_context->aead_iv_size);
        secured_message_context->application_secret
        .response_data_sequence_number = curr_rsp_sequence_number;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x20: {
        spdm_error_response_data_response_not_ready_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t    *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        libspdm_secured_message_context_t *secured_message_context;
        uint8_t curr_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
        uint8_t curr_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
        uint64_t curr_rsp_sequence_number;

        spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        secured_message_context = session_info->secured_message_context;

        /*use previous key to send*/
        libspdm_copy_mem(curr_rsp_enc_key, sizeof(curr_rsp_enc_key),
                         secured_message_context
                         ->application_secret.response_data_encryption_key,
                         secured_message_context->aead_key_size);
        libspdm_copy_mem(curr_rsp_salt, sizeof(curr_rsp_salt),
                         secured_message_context
                         ->application_secret.response_data_salt,
                         secured_message_context->aead_iv_size);
        curr_rsp_sequence_number = m_libspdm_last_rsp_sequence_number;

        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_encryption_key,
                         sizeof(secured_message_context->application_secret
                                .response_data_encryption_key),
                         m_libspdm_last_rsp_enc_key,
                         secured_message_context->aead_key_size);
        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_salt,
                         sizeof(secured_message_context->application_secret
                                .response_data_salt),
                         m_libspdm_last_rsp_salt,
                         secured_message_context->aead_iv_size);
        secured_message_context->application_secret
        .response_data_sequence_number = m_libspdm_last_rsp_sequence_number;

        /* once the sequence number is used, it should be increased for next NOT_READY message.*/
        m_libspdm_last_rsp_sequence_number++;

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 =
            SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response->header.param2 = 0;
        spdm_response->extend_error_data.rd_exponent = 1;
        spdm_response->extend_error_data.rd_tm = 2;
        spdm_response->extend_error_data.request_code = SPDM_KEY_UPDATE;
        spdm_response->extend_error_data.token = 0;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);

        /*restore new key*/
        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_encryption_key,
                         sizeof(secured_message_context->application_secret
                                .response_data_encryption_key),
                         curr_rsp_enc_key,
                         secured_message_context->aead_key_size);
        libspdm_copy_mem(secured_message_context->application_secret
                         .response_data_salt,
                         sizeof(secured_message_context->application_secret
                                .response_data_salt),
                         curr_rsp_salt,
                         secured_message_context->aead_iv_size);
        secured_message_context->application_secret
        .response_data_sequence_number = curr_rsp_sequence_number;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x21: {
        static size_t sub_index = 0;

        uint32_t session_id;
        libspdm_session_info_t    *session_info;

        libspdm_secured_message_context_t *secured_message_context;

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        secured_message_context = session_info->secured_message_context;

        if (sub_index == 0) {
            spdm_error_response_data_response_not_ready_t
            *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            uint8_t curr_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
            uint8_t curr_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
            uint64_t curr_rsp_sequence_number;

            spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            /*use previous key to send*/
            libspdm_copy_mem(curr_rsp_enc_key, sizeof(curr_rsp_enc_key),
                             secured_message_context
                             ->application_secret.response_data_encryption_key,
                             secured_message_context->aead_key_size);
            libspdm_copy_mem(curr_rsp_salt, sizeof(curr_rsp_salt),
                             secured_message_context
                             ->application_secret.response_data_salt,
                             secured_message_context->aead_iv_size);
            curr_rsp_sequence_number = m_libspdm_last_rsp_sequence_number;

            libspdm_copy_mem(secured_message_context->application_secret
                             .response_data_encryption_key,
                             sizeof(secured_message_context->application_secret
                                    .response_data_encryption_key),
                             m_libspdm_last_rsp_enc_key,
                             secured_message_context->aead_key_size);
            libspdm_copy_mem(secured_message_context->application_secret
                             .response_data_salt,
                             sizeof(secured_message_context->application_secret
                                    .response_data_salt),
                             m_libspdm_last_rsp_salt,
                             secured_message_context->aead_iv_size);
            secured_message_context->application_secret
            .response_data_sequence_number = m_libspdm_last_rsp_sequence_number;

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 =
                SPDM_ERROR_CODE_RESPONSE_NOT_READY;
            spdm_response->header.param2 = 0;
            spdm_response->extend_error_data.rd_exponent = 1;
            spdm_response->extend_error_data.rd_tm = 2;
            spdm_response->extend_error_data.request_code =
                SPDM_KEY_UPDATE;
            spdm_response->extend_error_data.token = 1;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);

            /*restore new key*/
            libspdm_copy_mem(secured_message_context->application_secret
                             .response_data_encryption_key,
                             sizeof(secured_message_context->application_secret
                                    .response_data_encryption_key),
                             curr_rsp_enc_key,
                             secured_message_context->aead_key_size);
            libspdm_copy_mem(secured_message_context->application_secret
                             .response_data_salt,
                             sizeof(secured_message_context->application_secret
                                    .response_data_salt),
                             curr_rsp_salt,
                             secured_message_context->aead_iv_size);
            secured_message_context->application_secret
            .response_data_sequence_number = curr_rsp_sequence_number;
        } else if (sub_index == 1) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            secured_message_context->application_secret
            .response_data_sequence_number--;
        } else if (sub_index == 2) {
            spdm_key_update_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint8_t *scratch_buffer;
            size_t scratch_buffer_size;

            spdm_response_size = sizeof(spdm_key_update_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_UPDATE_ACK;
            spdm_response->header.param1 =
                SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
            spdm_response->header.param2 = m_libspdm_last_token;

            /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
             * transport_message is always in sender buffer. */
            libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer,
                                        &scratch_buffer_size);
            libspdm_copy_mem (scratch_buffer + transport_header_size,
                              scratch_buffer_size - transport_header_size,
                              spdm_response, spdm_response_size);
            spdm_response = (void *)(scratch_buffer + transport_header_size);
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);
            /* WALKAROUND: If just use single context to encode
             * message and then decode message */
            secured_message_context->application_secret
            .response_data_sequence_number--;
        }

        sub_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x22: {
        static uint16_t error_code = LIBSPDM_ERROR_CODE_RESERVED_00;

        uint32_t session_id;
        libspdm_session_info_t    *session_info;

        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        libspdm_secured_message_context_t *secured_message_context;
        uint8_t curr_rsp_enc_key[LIBSPDM_MAX_AEAD_KEY_SIZE];
        uint8_t curr_rsp_salt[LIBSPDM_MAX_AEAD_IV_SIZE];
        uint64_t curr_rsp_sequence_number;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        secured_message_context = session_info->secured_message_context;

        if(error_code <= 0xff) {
            /* skip SPDM_ERROR_CODE_DECRYPT_ERROR, because this case will free context*/
            if(error_code == SPDM_ERROR_CODE_DECRYPT_ERROR) {
                error_code++;
            }
            /*use previous key to send*/
            libspdm_copy_mem(curr_rsp_enc_key, sizeof(curr_rsp_enc_key),
                             secured_message_context
                             ->application_secret.response_data_encryption_key,
                             secured_message_context->aead_key_size);
            libspdm_copy_mem(curr_rsp_salt, sizeof(curr_rsp_salt),
                             secured_message_context
                             ->application_secret.response_data_salt,
                             secured_message_context->aead_iv_size);
            curr_rsp_sequence_number = m_libspdm_last_rsp_sequence_number;

            libspdm_copy_mem(secured_message_context->application_secret
                             .response_data_encryption_key,
                             sizeof(secured_message_context->application_secret
                                    .response_data_encryption_key),
                             m_libspdm_last_rsp_enc_key,
                             secured_message_context->aead_key_size);
            libspdm_copy_mem(secured_message_context->application_secret
                             .response_data_salt,
                             sizeof(secured_message_context->application_secret
                                    .response_data_salt),
                             m_libspdm_last_rsp_salt,
                             secured_message_context->aead_iv_size);
            secured_message_context->application_secret
            .response_data_sequence_number = m_libspdm_last_rsp_sequence_number;

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
            libspdm_transport_test_encode_message(spdm_context,
                                                  &session_id, false, false,
                                                  spdm_response_size, spdm_response,
                                                  response_size, response);

            /*restore new key*/
            libspdm_copy_mem(secured_message_context->application_secret
                             .response_data_encryption_key,
                             sizeof(secured_message_context->application_secret
                                    .response_data_encryption_key),
                             curr_rsp_enc_key,
                             secured_message_context->aead_key_size);
            libspdm_copy_mem(secured_message_context->application_secret
                             .response_data_salt,
                             sizeof(secured_message_context->application_secret
                                    .response_data_salt),
                             curr_rsp_salt,
                             secured_message_context->aead_iv_size);
            secured_message_context->application_secret
            .response_data_sequence_number = curr_rsp_sequence_number;
        }

        error_code++;
        /*busy is treated in cases 5 and 6*/
        if(error_code == SPDM_ERROR_CODE_BUSY) {
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        /*skip some reserved error codes (0d to 3e)*/
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) {
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x23: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint32_t session_id;
        libspdm_session_info_t    *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = 0xFFFFFFFF;
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

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
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);
        /* WALKAROUND: If just use single context to encode
         * message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;

    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}


/**
 * Test 1: when no KEY_UPDATE_ACK message is received, and the client
 * returns a device error.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_key_update_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
}

/**
 * Test 2: receiving a correct UPDATE_KEY_ACK message for updating
 * only the request data key.
 * Expected behavior: client returns a Status of RETURN_SUCCESS, the
 * request data key is updated, but not the response data key.
 **/
void libspdm_test_requester_key_update_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_req_secret_buffer, m_req_secret_buffer,
                                  sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 3: requester state has not been negotiated, as if GET_VERSION,
 * GET_CAPABILITIES and NEGOTIATE_ALGORITHMS had not been exchanged.
 * Expected behavior: client returns a Status of RETURN_UNSUPPORTED.
 **/
void libspdm_test_requester_key_update_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    /*state not negotiated*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
}

/**
 * Test 4: the requester is setup correctly (see Test 2), but receives an ERROR
 * message indicating InvalidParameters when updating key.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and
 * no keys should be updated.
 **/
void libspdm_test_requester_key_update_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 5: the requester is setup correctly (see Test 2), but receives an ERROR
 * message indicating the Busy status of the responder, when updating key.
 * Expected behavior: client returns a Status of RETURN_NO_RESPONSE, and
 * no keys should be updated.
 **/
void libspdm_test_requester_key_update_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 6: the requester is setup correctly (see Test 2), but, when updating
 * key, on the first try, receiving a Busy ERROR message, and on retry,
 * receiving a correct KEY_UPDATE_ACK message. The VERIFY_KEY behavior is
 * not altered.
 * Expected behavior: client returns a Status of RETURN_SUCCESS, the
 * request data key is updated, but not the response data key.
 **/
void libspdm_test_requester_key_update_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;

    spdm_context->retry_times = 3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_req_secret_buffer, m_req_secret_buffer,
                                  sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 7: the requester is setup correctly (see Test 2), but receives an ERROR
 * message indicating the RequestResynch status of the responder, when updating
 * key.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and the
 * communication is reset to expect a new GET_VERSION message.
 **/
void libspdm_test_requester_key_update_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
}

/**
 * Test 8: the requester is setup correctly (see Test 2), but receives an ERROR
 * message indicating the ResponseNotReady status of the responder, when
 * updating key.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and
 * no keys should be updated.
 **/
void libspdm_test_requester_key_update_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 9: the requester is setup correctly (see Test 2), but, when updating
 * key, on the first try, receiving a ResponseNotReady ERROR message, and on
 * retry, receiving a correct KEY_UPDATE_ACK message. The VERIFY_KEY
 * behavior is not altered.
 * Expected behavior: client returns a Status of RETURN_SUCCESS, the
 * request data key is updated, but not the response data key.
 **/
void libspdm_test_requester_key_update_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_req_secret_buffer, m_req_secret_buffer,
                                  sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(spdm_context, session_id, true);

    if (LIBSPDM_RESPOND_IF_READY_SUPPORT) {
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        assert_memory_equal(((libspdm_secured_message_context_t *)
                             (session_info->secured_message_context))->application_secret.request_data_secret,
                            m_req_secret_buffer, ((libspdm_secured_message_context_t *)
                                                  (session_info->secured_message_context))->hash_size);

        assert_memory_equal(((libspdm_secured_message_context_t *)
                             (session_info->secured_message_context))->application_secret.response_data_secret,
                            m_rsp_secret_buffer, ((libspdm_secured_message_context_t *)
                                                  (session_info->secured_message_context))->hash_size);
    } else {
        assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    }

}

/**
 * Test 10: receiving an unexpected ERROR message from the responder,
 * when updating key.
 * There are tests for all named codes, including some reserved ones
 * (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
 * However, for having specific test cases, it is excluded from this case:
 * Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR, and
 * no keys should be updated.
 **/
void libspdm_test_requester_key_update_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;
    uint16_t error_code;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    error_code = LIBSPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        /* skip SPDM_ERROR_CODE_DECRYPT_ERROR, because this case will free context*/
        if(error_code == SPDM_ERROR_CODE_DECRYPT_ERROR) {
            error_code++;
        }
        libspdm_set_standard_key_update_test_secrets(
            session_info->secured_message_context,
            m_rsp_secret_buffer, (uint8_t)(0xFF),
            m_req_secret_buffer, (uint8_t)(0xEE));

        /*no keys are updated*/

        status = libspdm_key_update(
            spdm_context, session_id, true);

        LIBSPDM_ASSERT_INT_EQUAL_CASE (status, LIBSPDM_STATUS_ERROR_PEER, error_code);
        assert_memory_equal(((libspdm_secured_message_context_t
                              *)(session_info->secured_message_context))
                            ->application_secret.request_data_secret,
                            m_req_secret_buffer, ((libspdm_secured_message_context_t
                                                   *)(session_info->secured_message_context))->hash_size);
        assert_memory_equal(((libspdm_secured_message_context_t
                              *)(session_info->secured_message_context))
                            ->application_secret.response_data_secret,
                            m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                                   *)(session_info->secured_message_context))->hash_size);

        error_code++;
        /*busy is treated in cases 5 and 6*/
        if(error_code == SPDM_ERROR_CODE_BUSY) {
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        /*skip some reserved error codes (0d to 3e)*/
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) {
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }
}

void libspdm_test_requester_key_update_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_req_secret_buffer, m_req_secret_buffer,
                                  sizeof(m_req_secret_buffer));
    /*response side *not* updated*/
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

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(session_info->session_transcript.message_m.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#endif
}

/**
 * Test 12: requester is not setup correctly to support key update
 * (no capabilities). The responder would attempt to return a correct
 * KEY_UPDATE_ACK message.
 * Expected behavior: client returns a Status of RETURN_UNSUPPORTED,
 * and no keys are updated.
 **/
void libspdm_test_requester_key_update_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    /*no capabilities*/
    spdm_context->connection_info.capability.flags &=
        !SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags &=
        !SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 13: receiving an incorrect KEY_UPDATE_ACK message, with wrong
 * response code, but all other field correct, when updating key.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR,
 * no keys are updated.
 **/
void libspdm_test_requester_key_update_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 14: requester is not setup correctly by not initializing a
 * session during KEY_EXCHANGE. The responder would attempt to
 * return a correct KEY_UPDATE_ACK message.
 * Expected behavior: client returns a Status of RETURN_UNSUPPORTED,
 * and no keys are updated.
 **/
void libspdm_test_requester_key_update_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    /*session not initialized*/
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_NOT_STARTED);

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 15: the requester is setup correctly (see Test 2), but receives a
 * KEY_UPDATE_ACK response with the wrong token. The VERIFY_KEY behavior
 * is not altered.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and
 * no keys should be updated.
 **/
void libspdm_test_requester_key_update_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 16: the requester is setup correctly (see Test 2), but receives a
 * KEY_UPDATE_ACK response with the operation code. The VERIFY_KEY
 * behavior is not altered.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and
 * no keys should be updated.
 **/
void libspdm_test_requester_key_update_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 17: the requester is setup correctly (see Test 2), but receives an
 * ERROR message indicating InvalidParameters when verifying key.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, the
 * request data key is not rollbacked.
 **/
void libspdm_test_requester_key_update_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_req_secret_buffer, m_req_secret_buffer,
                                  sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 18: the requester is setup correctly (see Test 2), but receives an
 * ERROR message indicating the Busy status of the responder, when verifying
 * key.
 * Expected behavior: client returns a Status of RETURN_NO_RESPONSE, the
 * request data key is not rollbacked.
 **/
void libspdm_test_requester_key_update_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_req_secret_buffer, m_req_secret_buffer,
                                  sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 19: the requester is setup correctly (see Test 2), but, when
 * verifying key, on the first try, receiving a Busy ERROR message,
 * and on retry, receiving a correct KEY_UPDATE_ACK message. The
 * VERIFY_KEY behavior is not altered.
 * Expected behavior: client returns a Status of RETURN_SUCCESS, the
 * request data key is not rollbacked.
 **/
void libspdm_test_requester_key_update_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;

    spdm_context->retry_times = 3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_req_secret_buffer, m_req_secret_buffer,
                                  sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 20: the requester is setup correctly (see Test 2), but receives an
 * ERROR message indicating the RequestResynch status of the responder, when
 * verifying key.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and the
 * communication is reset to expect a new GET_VERSION message.
 **/
void libspdm_test_requester_key_update_case20(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
}

/**
 * Test 21: the requester is setup correctly (see Test 2), but receives an
 * ERROR message indicating the ResponseNotReady status of the responder, when
 * verifying key.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, the
 * request data key is not rollbacked.
 **/
void libspdm_test_requester_key_update_case21(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_req_secret_buffer, m_req_secret_buffer,
                                  sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 22: the requester is setup correctly (see Test 2), but, when verifying
 * key, on the first try, receiving a ResponseNotReady ERROR message, and on
 * retry, receiving a correct KEY_UPDATE_ACK message.
 * Expected behavior: client returns a Status of RETURN_SUCCESS, the
 * request data key is not rollbacked.
 **/
void libspdm_test_requester_key_update_case22(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_req_secret_buffer, m_req_secret_buffer,
                                  sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(spdm_context, session_id, true);

    if (LIBSPDM_RESPOND_IF_READY_SUPPORT) {
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        assert_memory_equal(((libspdm_secured_message_context_t
                              *)(session_info->secured_message_context))
                            ->application_secret.request_data_secret,
                            m_req_secret_buffer, ((libspdm_secured_message_context_t
                                                   *)(session_info->secured_message_context))->hash_size);
        assert_memory_equal(((libspdm_secured_message_context_t
                              *)(session_info->secured_message_context))
                            ->application_secret.response_data_secret,
                            m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                                   *)(session_info->secured_message_context))->hash_size);
    } else {
        assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    }
}

/**
 * Test 23: receiving an unexpected ERROR message from the responder,
 * when verifying key.
 * There are tests for all named codes, including some reserved ones
 * (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
 * However, for having specific test cases, it is excluded from this case:
 * Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR, the
 * request data key is not rollbacked.
 **/
void libspdm_test_requester_key_update_case23(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;
    uint16_t error_code;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    error_code = LIBSPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        /* skip SPDM_ERROR_CODE_DECRYPT_ERROR, because this case will free context*/
        if(error_code == SPDM_ERROR_CODE_DECRYPT_ERROR) {
            error_code++;
        }
        libspdm_set_standard_key_update_test_secrets(
            session_info->secured_message_context,
            m_rsp_secret_buffer, (uint8_t)(0xFF),
            m_req_secret_buffer, (uint8_t)(0xEE));

        /*request side updated*/
        libspdm_compute_secret_update(spdm_context->connection_info.version,
                                      ((libspdm_secured_message_context_t
                                        *)(session_info->secured_message_context))->hash_size,
                                      m_req_secret_buffer, m_req_secret_buffer,
                                      sizeof(m_req_secret_buffer));
        /*response side *not* updated*/

        status = libspdm_key_update(
            spdm_context, session_id, true);

        LIBSPDM_ASSERT_INT_EQUAL_CASE (status, LIBSPDM_STATUS_ERROR_PEER, error_code);
        assert_memory_equal(((libspdm_secured_message_context_t
                              *)(session_info->secured_message_context))
                            ->application_secret.request_data_secret,
                            m_req_secret_buffer, ((libspdm_secured_message_context_t
                                                   *)(session_info->secured_message_context))->hash_size);
        assert_memory_equal(((libspdm_secured_message_context_t
                              *)(session_info->secured_message_context))
                            ->application_secret.response_data_secret,
                            m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                                   *)(session_info->secured_message_context))->hash_size);

        error_code++;
        /*busy is treated in cases 5 and 6*/
        if(error_code == SPDM_ERROR_CODE_BUSY) {
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        /*skip some reserved error codes (0d to 3e)*/
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) {
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }
}

/**
 * Test 24: receiving an incorrect KEY_UPDATE_ACK message, with wrong
 * response code, but all other field correct, when verifying key.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, the
 * request data key is not rollbacked.
 **/
void libspdm_test_requester_key_update_case24(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_req_secret_buffer, m_req_secret_buffer,
                                  sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 25: the requester is setup correctly (see Test 2), and receives a
 * correct KEY_UPDATE_ACK to update key. However, it receives a
 * KEY_UPDATE_ACK response with the wrong token to verify the key.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, the
 * request data key is not rollbacked.
 **/
void libspdm_test_requester_key_update_case25(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_req_secret_buffer, m_req_secret_buffer,
                                  sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 26: the requester is setup correctly (see Test 2) and receives a
 * correct KEY_UPDATE_ACK to update key. However, it receives a
 * KEY_UPDATE_ACK response with the wrong operation code to verify the key.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, the
 * request data key is not rollbacked.
 **/
void libspdm_test_requester_key_update_case26(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1A;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_req_secret_buffer, m_req_secret_buffer,
                                  sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    status = libspdm_key_update(
        spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 27: receiving a correct UPDATE_KEY_ACK message for updating
 * both the request data key and the response data key.
 * Expected behavior: client returns a Status of RETURN_SUCCESS, and
 * the request data key and response data key are updated.
 **/
void libspdm_test_requester_key_update_case27(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1B;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_req_secret_buffer, m_req_secret_buffer,
                                  sizeof(m_req_secret_buffer));
    /*response side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_rsp_secret_buffer, m_rsp_secret_buffer,
                                  sizeof(m_rsp_secret_buffer));

    status = libspdm_key_update(
        spdm_context, session_id, false);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 28: the requester is setup correctly (see Test 27), but receives an
 * ERROR message indicating InvalidParameters when updating all keys.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and
 * no keys should be updated.
 **/
void libspdm_test_requester_key_update_case28(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    libspdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1C;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*store previous encryption state*/
    libspdm_copy_mem(m_libspdm_last_rsp_enc_key, sizeof(m_libspdm_last_rsp_enc_key),
                     secured_message_context
                     ->application_secret.response_data_encryption_key,
                     secured_message_context->aead_key_size);
    libspdm_copy_mem(m_libspdm_last_rsp_salt, sizeof(m_libspdm_last_rsp_salt),
                     secured_message_context
                     ->application_secret.response_data_salt,
                     secured_message_context->aead_iv_size);
    m_libspdm_last_rsp_sequence_number = secured_message_context
                                         ->application_secret.response_data_sequence_number;

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, false);

    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 29: the requester is setup correctly (see Test 27), but receives an
 * ERROR message indicating the Busy status of the responder, when updating
 * all keys.
 * Expected behavior: client returns a Status of RETURN_NO_RESPONSE, and
 * no keys should be updated.
 **/
void libspdm_test_requester_key_update_case29(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    libspdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1D;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*store previous encryption state*/
    libspdm_copy_mem(m_libspdm_last_rsp_enc_key, sizeof(m_libspdm_last_rsp_enc_key),
                     secured_message_context
                     ->application_secret.response_data_encryption_key,
                     secured_message_context->aead_key_size);
    libspdm_copy_mem(m_libspdm_last_rsp_salt, sizeof(m_libspdm_last_rsp_salt),
                     secured_message_context
                     ->application_secret.response_data_salt,
                     secured_message_context->aead_iv_size);
    m_libspdm_last_rsp_sequence_number = secured_message_context
                                         ->application_secret.response_data_sequence_number;

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, false);

    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 30: the requester is setup correctly (see Test 27), but, when updating
 * all keys, on the first try, receiving a Busy ERROR message, and on retry,
 * receiving a correct KEY_UPDATE_ACK message. The VERIFY_KEY behavior is
 * not altered.
 * Expected behavior: client returns a Status of RETURN_SUCCESS, and
 * the request data key and response data key are updated.
 **/
void libspdm_test_requester_key_update_case30(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    libspdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1E;

    spdm_context->retry_times = 3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*store previous encryption state*/
    libspdm_copy_mem(m_libspdm_last_rsp_enc_key, sizeof(m_libspdm_last_rsp_enc_key),
                     secured_message_context
                     ->application_secret.response_data_encryption_key,
                     secured_message_context->aead_key_size);
    libspdm_copy_mem(m_libspdm_last_rsp_salt, sizeof(m_libspdm_last_rsp_salt),
                     secured_message_context
                     ->application_secret.response_data_salt,
                     secured_message_context->aead_iv_size);
    m_libspdm_last_rsp_sequence_number = secured_message_context
                                         ->application_secret.response_data_sequence_number;

    /*request side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_req_secret_buffer, m_req_secret_buffer,
                                  sizeof(m_req_secret_buffer));
    /*response side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_rsp_secret_buffer, m_rsp_secret_buffer,
                                  sizeof(m_rsp_secret_buffer));

    status = libspdm_key_update(
        spdm_context, session_id, false);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 31: the requester is setup correctly (see Test 27), but receives an
 * ERROR message indicating the RequestResynch status of the responder, when
 * updating all keys.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and the
 * communication is reset to expect a new GET_VERSION message.
 **/
void libspdm_test_requester_key_update_case31(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    libspdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1F;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*store previous encryption state*/
    libspdm_copy_mem(m_libspdm_last_rsp_enc_key, sizeof(m_libspdm_last_rsp_enc_key),
                     secured_message_context
                     ->application_secret.response_data_encryption_key,
                     secured_message_context->aead_key_size);
    libspdm_copy_mem(m_libspdm_last_rsp_salt, sizeof(m_libspdm_last_rsp_salt),
                     secured_message_context
                     ->application_secret.response_data_salt,
                     secured_message_context->aead_iv_size);
    m_libspdm_last_rsp_sequence_number = secured_message_context
                                         ->application_secret.response_data_sequence_number;

    status = libspdm_key_update(
        spdm_context, session_id, false);

    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
}

/**
 * Test 32: the requester is setup correctly (see Test 27), but receives an
 * ERROR message indicating the ResponseNotReady status of the responder, when
 * updating all keys.
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and
 * no keys should be updated.
 **/
void libspdm_test_requester_key_update_case32(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    libspdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x20;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*store previous encryption state*/
    libspdm_copy_mem(m_libspdm_last_rsp_enc_key, sizeof(m_libspdm_last_rsp_enc_key),
                     secured_message_context
                     ->application_secret.response_data_encryption_key,
                     secured_message_context->aead_key_size);
    libspdm_copy_mem(m_libspdm_last_rsp_salt, sizeof(m_libspdm_last_rsp_salt),
                     secured_message_context
                     ->application_secret.response_data_salt,
                     secured_message_context->aead_iv_size);
    m_libspdm_last_rsp_sequence_number = secured_message_context
                                         ->application_secret.response_data_sequence_number;

    /*no keys are updated*/

    status = libspdm_key_update(
        spdm_context, session_id, false);

    assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.request_data_secret,
                        m_req_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
    assert_memory_equal(((libspdm_secured_message_context_t
                          *)(session_info->secured_message_context))
                        ->application_secret.response_data_secret,
                        m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                               *)(session_info->secured_message_context))->hash_size);
}

/**
 * Test 33: the requester is setup correctly (see Test 27), but, when updating
 * all keys, on the first try, receiving a ResponseNotReady ERROR message, and
 * on retry, receiving a correct KEY_UPDATE_ACK message. The VERIFY_KEY
 * behavior is not altered.
 * Expected behavior: client returns a Status of RETURN_SUCCESS, and
 * the request data key and response data key are updated.
 **/
void libspdm_test_requester_key_update_case33(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    libspdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x21;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*store previous encryption state*/
    libspdm_copy_mem(m_libspdm_last_rsp_enc_key, sizeof(m_libspdm_last_rsp_enc_key),
                     secured_message_context
                     ->application_secret.response_data_encryption_key,
                     secured_message_context->aead_key_size);
    libspdm_copy_mem(m_libspdm_last_rsp_salt, sizeof(m_libspdm_last_rsp_salt),
                     secured_message_context
                     ->application_secret.response_data_salt,
                     secured_message_context->aead_iv_size);
    m_libspdm_last_rsp_sequence_number = secured_message_context
                                         ->application_secret.response_data_sequence_number;

    /*request side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_req_secret_buffer, m_req_secret_buffer,
                                  sizeof(m_req_secret_buffer));
    /*response side updated*/
    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  ((libspdm_secured_message_context_t
                                    *)(session_info->secured_message_context))->hash_size,
                                  m_rsp_secret_buffer, m_rsp_secret_buffer,
                                  sizeof(m_rsp_secret_buffer));

    status = libspdm_key_update(spdm_context, session_id, false);

    if (LIBSPDM_RESPOND_IF_READY_SUPPORT) {
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        assert_memory_equal(((libspdm_secured_message_context_t
                              *)(session_info->secured_message_context))
                            ->application_secret.request_data_secret,
                            m_req_secret_buffer, ((libspdm_secured_message_context_t
                                                   *)(session_info->secured_message_context))->hash_size);
        assert_memory_equal(((libspdm_secured_message_context_t
                              *)(session_info->secured_message_context))
                            ->application_secret.response_data_secret,
                            m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                                   *)(session_info->secured_message_context))->hash_size);
    } else {
        assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    }
}

/**
 * Test 34: receiving an unexpected ERROR message from the responder,
 * when updating all keys.
 * There are tests for all named codes, including some reserved ones
 * (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
 * However, for having specific test cases, it is excluded from this case:
 * Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR, and
 * no keys should be updated.
 **/
void libspdm_test_requester_key_update_case34(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;
    uint16_t error_code;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    libspdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x22;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    error_code = LIBSPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        /* skip SPDM_ERROR_CODE_DECRYPT_ERROR, because this case will free context*/
        if(error_code == SPDM_ERROR_CODE_DECRYPT_ERROR) {
            error_code++;
        }
        libspdm_set_standard_key_update_test_secrets(
            session_info->secured_message_context,
            m_rsp_secret_buffer, (uint8_t)(0xFF),
            m_req_secret_buffer, (uint8_t)(0xEE));

        /*store previous encryption state*/
        libspdm_copy_mem(m_libspdm_last_rsp_enc_key, sizeof(m_libspdm_last_rsp_enc_key),
                         secured_message_context
                         ->application_secret.response_data_encryption_key,
                         secured_message_context->aead_key_size);
        libspdm_copy_mem(m_libspdm_last_rsp_salt, sizeof(m_libspdm_last_rsp_salt),
                         secured_message_context
                         ->application_secret.response_data_salt,
                         secured_message_context->aead_iv_size);
        m_libspdm_last_rsp_sequence_number = secured_message_context
                                             ->application_secret.response_data_sequence_number;

        /*no keys are updated*/

        status = libspdm_key_update(
            spdm_context, session_id, false);

        LIBSPDM_ASSERT_INT_EQUAL_CASE (status, LIBSPDM_STATUS_ERROR_PEER, error_code);
        assert_memory_equal(((libspdm_secured_message_context_t
                              *)(session_info->secured_message_context))
                            ->application_secret.request_data_secret,
                            m_req_secret_buffer, ((libspdm_secured_message_context_t
                                                   *)(session_info->secured_message_context))->hash_size);
        assert_memory_equal(((libspdm_secured_message_context_t
                              *)(session_info->secured_message_context))
                            ->application_secret.response_data_secret,
                            m_rsp_secret_buffer, ((libspdm_secured_message_context_t
                                                   *)(session_info->secured_message_context))->hash_size);

        error_code++;
        /*busy is treated in cases 5 and 6*/
        if(error_code == SPDM_ERROR_CODE_BUSY) {
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        /*skip some reserved error codes (0d to 3e)*/
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) {
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }
}

/**
 * Test 35: the requester is setup correctly, but receives an ERROR with SPDM_ERROR_CODE_DECRYPT_ERROR.
 * Expected behavior: client returns a Status of INVALID_SESSION_ID  and free the session ID.
 **/
void libspdm_test_requester_key_update_case35(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t         *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t    *session_info;

    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x23;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(
        session_info->secured_message_context,
        m_rsp_secret_buffer, (uint8_t)(0xFF),
        m_req_secret_buffer, (uint8_t)(0xEE));

    /*no keys are updated*/

    status = libspdm_key_update(spdm_context, session_id, true);

    assert_int_equal(status, LIBSPDM_STATUS_SESSION_MSG_ERROR);
    assert_int_equal(spdm_context->session_info->session_id, INVALID_SESSION_ID);
}

libspdm_test_context_t m_libspdm_requester_key_update_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_key_update_test_send_message,
    libspdm_requester_key_update_test_receive_message,
};

int libspdm_requester_key_update_test_main(void)
{
    const struct CMUnitTest spdm_requester_key_update_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(libspdm_test_requester_key_update_case1),
        /* update single key
         * Successful response*/
        cmocka_unit_test(libspdm_test_requester_key_update_case2),
        /* connection_state check failed*/
        cmocka_unit_test(libspdm_test_requester_key_update_case3),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(libspdm_test_requester_key_update_case4),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(libspdm_test_requester_key_update_case5),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_key_update_case6),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(libspdm_test_requester_key_update_case7),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(libspdm_test_requester_key_update_case8),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_key_update_case9),
        /* Unexpected errors*/
        cmocka_unit_test(libspdm_test_requester_key_update_case10),
        /* Buffer reset*/
        cmocka_unit_test(libspdm_test_requester_key_update_case11),
        /* No correct setup*/
        cmocka_unit_test(libspdm_test_requester_key_update_case12),
        cmocka_unit_test(libspdm_test_requester_key_update_case13),
        cmocka_unit_test(libspdm_test_requester_key_update_case14),
        /* Wrong parameters*/
        cmocka_unit_test(libspdm_test_requester_key_update_case15),
        cmocka_unit_test(libspdm_test_requester_key_update_case16),
        /* verify key
         * Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(libspdm_test_requester_key_update_case17),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(libspdm_test_requester_key_update_case18),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_key_update_case19),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(libspdm_test_requester_key_update_case20),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(libspdm_test_requester_key_update_case21),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_key_update_case22),
        /* Unexpected errors*/
        cmocka_unit_test(libspdm_test_requester_key_update_case23),
        /* No correct setup*/
        cmocka_unit_test(libspdm_test_requester_key_update_case24),
        /* Wrong parameters*/
        cmocka_unit_test(libspdm_test_requester_key_update_case25),
        cmocka_unit_test(libspdm_test_requester_key_update_case26),
        /* update all keys
         * Sucessful response*/
        cmocka_unit_test(libspdm_test_requester_key_update_case27),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(libspdm_test_requester_key_update_case28),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(libspdm_test_requester_key_update_case29),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_key_update_case30),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(libspdm_test_requester_key_update_case31),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(libspdm_test_requester_key_update_case32),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_key_update_case33),
        /* Unexpected errors*/
        cmocka_unit_test(libspdm_test_requester_key_update_case34),
        /* Error response: SPDM_ERROR_CODE_DECRYPT_ERROR*/
        cmocka_unit_test(libspdm_test_requester_key_update_case35),
    };

    libspdm_setup_test_context(&m_libspdm_requester_key_update_test_context);

    return cmocka_run_group_tests(spdm_requester_key_update_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
