/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP

static void libspdm_set_standard_key_update_test_state(libspdm_context_t *spdm_context,
                                                       uint32_t *session_id)
{
    libspdm_session_info_t *session_info;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;

    spdm_context->transcript.message_a.buffer_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    *session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = *session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = *session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, *session_id, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
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

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

void libspdm_test_requester_encap_key_update(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    libspdm_secured_message_context_t *secured_message_context;
    size_t request_size;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t m_req_secret_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t m_rsp_secret_buffer[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(spdm_context, &session_id);

    session_info = &spdm_context->session_info[0];
    secured_message_context = session_info->secured_message_context;

    libspdm_set_standard_key_update_test_secrets(session_info->secured_message_context,
                                                 m_rsp_secret_buffer, (uint8_t)(0xFF),
                                                 m_req_secret_buffer, (uint8_t)(0xEE));

    libspdm_compute_secret_update(spdm_context->connection_info.version,
                                  secured_message_context->hash_size, m_req_secret_buffer,
                                  m_req_secret_buffer, secured_message_context->hash_size);

    request_size = spdm_test_context->test_buffer_size;
    if (request_size > sizeof(spdm_key_update_request_t)) {
        request_size = sizeof(spdm_key_update_request_t);
    }

    response_size = sizeof(response);
    libspdm_get_encap_response_key_update(spdm_context, request_size,
                                          (uint8_t *)spdm_test_context->test_buffer,
                                          &response_size, response);
}

libspdm_test_context_t m_libspdm_requester_encap_key_update_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_encap_key_update_test_context);

    m_libspdm_requester_encap_key_update_test_context.test_buffer = test_buffer;
    m_libspdm_requester_encap_key_update_test_context.test_buffer_size = test_buffer_size;

    /* Successful response*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_encap_key_update(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP*/
