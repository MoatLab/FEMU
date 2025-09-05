/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)

static uint8_t m_libspdm_last_token;

static void libspdm_set_standard_key_update_test_state(libspdm_context_t *spdm_context,
                                                       uint32_t *session_id)
{
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    libspdm_session_info_t *session_info;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
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
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    free(data);
}

static void libspdm_compute_secret_update(spdm_version_number_t spdm_version,
                                          size_t hash_size, const uint8_t *in_secret,
                                          uint8_t *out_secret, size_t out_secret_size)
{
    uint8_t bin_str9[128];
    size_t bin_str9_size;

    bin_str9_size = sizeof(bin_str9);
    libspdm_bin_concat(spdm_version,
                       SPDM_BIN_STR_9_LABEL, sizeof(SPDM_BIN_STR_9_LABEL) - 1,
                       NULL, (uint16_t)hash_size, hash_size, bin_str9,
                       &bin_str9_size);

    libspdm_hkdf_expand(m_libspdm_use_hash_algo, in_secret, hash_size, bin_str9, bin_str9_size,
                        out_secret, out_secret_size);
}

static void libspdm_set_standard_key_update_test_secrets(
    libspdm_secured_message_context_t *secured_message_context,
    uint8_t *m_rsp_secret_buffer, uint8_t rsp_secret_fill, uint8_t *m_req_secret_buffer,
    uint8_t req_secret_fill)
{
    libspdm_set_mem(m_rsp_secret_buffer, secured_message_context->hash_size, rsp_secret_fill);
    libspdm_set_mem(m_req_secret_buffer, secured_message_context->hash_size, req_secret_fill);

    libspdm_copy_mem(secured_message_context->application_secret.response_data_secret,
                     sizeof(secured_message_context->application_secret.response_data_secret),
                     m_rsp_secret_buffer, secured_message_context->aead_key_size);
    libspdm_copy_mem(secured_message_context->application_secret.request_data_secret,
                     sizeof(secured_message_context->application_secret.request_data_secret),
                     m_req_secret_buffer, secured_message_context->aead_key_size);

    libspdm_set_mem(secured_message_context->application_secret.response_data_encryption_key,
                    secured_message_context->aead_key_size, (uint8_t)(0xFF));
    libspdm_set_mem(secured_message_context->application_secret.response_data_salt,
                    secured_message_context->aead_iv_size, (uint8_t)(0xFF));

    libspdm_set_mem(secured_message_context->application_secret.request_data_encryption_key,
                    secured_message_context->aead_key_size, (uint8_t)(0xEE));
    libspdm_set_mem(secured_message_context->application_secret.request_data_salt,
                    secured_message_context->aead_iv_size, (uint8_t)(0xEE));

    secured_message_context->application_secret.response_data_sequence_number = 0;
    secured_message_context->application_secret.request_data_sequence_number = 0;
}

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

libspdm_return_t libspdm_device_send_message(void *spdm_context, size_t request_size,
                                             const void *request, uint64_t timeout)
{
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

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_device_receive_message(void *spdm_context, size_t *response_size,
                                                void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    spdm_key_update_response_t *spdm_response;
    size_t spdm_response_size;
    size_t test_message_header_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    uint8_t *scratch_buffer;
    size_t scratch_buffer_size;
    size_t aead_tag_max_size;
    static uint8_t sub_index = 0;

    session_id = 0xFFFFFFFF;
    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    spdm_test_context = libspdm_get_test_context();
    test_message_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    spdm_response_size = spdm_test_context->test_buffer_size;
    /* limit the encoding buffer to avoid assert, because the input buffer is controlled by the the libspdm consumer. */
    test_message_header_size += sizeof(spdm_secured_message_a_data_header1_t) +
                                2 +     /* MCTP_SEQUENCE_NUMBER_COUNT */
                                sizeof(spdm_secured_message_a_data_header2_t) +
                                sizeof(spdm_secured_message_cipher_header_t) +
                                32 /* MCTP_MAX_RANDOM_NUMBER_COUNT */;
    aead_tag_max_size = LIBSPDM_MAX_AEAD_TAG_SIZE;

    /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
     * transport_message is always in sender buffer. */
    libspdm_get_scratch_buffer(spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
    spdm_response = (void *)(scratch_buffer + test_message_header_size);
    spdm_response_size = spdm_test_context->test_buffer_size;
    if (spdm_response_size >
        LIBSPDM_MAX_SPDM_MSG_SIZE - test_message_header_size - aead_tag_max_size -
        LIBSPDM_TEST_ALIGNMENT) {
        spdm_response_size = LIBSPDM_MAX_SPDM_MSG_SIZE - test_message_header_size -
                             aead_tag_max_size -
                             LIBSPDM_TEST_ALIGNMENT;
    }

    if (spdm_response_size > (sub_index + 1) * sizeof(spdm_key_update_response_t)) {
        spdm_response_size = sizeof(spdm_key_update_response_t);
    } else if (spdm_response_size > sub_index * sizeof(spdm_key_update_response_t)) {
        spdm_response_size = spdm_response_size - sub_index * sizeof(spdm_key_update_response_t);
    } else {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    libspdm_copy_mem (scratch_buffer + test_message_header_size,
                      scratch_buffer_size - test_message_header_size,
                      (uint8_t *)spdm_test_context->test_buffer +
                      sizeof(spdm_key_update_response_t) * sub_index,
                      spdm_response_size);

    spdm_response->header.param2 = m_libspdm_last_token;

    libspdm_transport_test_encode_message(spdm_context, &session_id, false, false,
                                          spdm_response_size,
                                          spdm_response, response_size, response);

    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    /* WALKAROUND: If just use single context to encode message and then decode message */
    ((libspdm_secured_message_context_t *)(session_info->secured_message_context))
    ->application_secret.response_data_sequence_number--;

    if (sub_index != 0) {
        sub_index = 0;
    }
    sub_index++;
    return LIBSPDM_STATUS_SUCCESS;
}

void libspdm_test_requester_key_update_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint32_t session_id;
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *State;
    session_id = 0xFFFFFFFF;

    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(session_info->secured_message_context,
                                                 m_rsp_secret_buffer, (uint8_t)(0xFF),
                                                 m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(
        spdm_context->connection_info.version,
        ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->hash_size,
        m_req_secret_buffer, m_req_secret_buffer, sizeof(m_req_secret_buffer));
    /*response side *not* updated*/

    libspdm_key_update(spdm_context, session_id, true);
}

void libspdm_test_requester_key_update_case2(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    session_id = 0xFFFFFFFF;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];

    libspdm_set_standard_key_update_test_secrets(session_info->secured_message_context,
                                                 m_rsp_secret_buffer, (uint8_t)(0xFF),
                                                 m_req_secret_buffer, (uint8_t)(0xEE));

    /*request side updated*/
    libspdm_compute_secret_update(
        spdm_context->connection_info.version,
        ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->hash_size,
        m_req_secret_buffer, m_req_secret_buffer, sizeof(m_req_secret_buffer));
    /*response side updated*/
    libspdm_compute_secret_update(
        spdm_context->connection_info.version,
        ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->hash_size,
        m_rsp_secret_buffer, m_rsp_secret_buffer, sizeof(m_rsp_secret_buffer));

    libspdm_key_update(spdm_context, session_id, false);
}

libspdm_test_context_t m_libspdm_requester_key_update_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_key_update_test_context);

    m_libspdm_requester_key_update_test_context.test_buffer = test_buffer;
    m_libspdm_requester_key_update_test_context.test_buffer_size = test_buffer_size;

    /* Successful response. update single key */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_key_update_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Sucessful response  update all keys*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_key_update_case2(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */
