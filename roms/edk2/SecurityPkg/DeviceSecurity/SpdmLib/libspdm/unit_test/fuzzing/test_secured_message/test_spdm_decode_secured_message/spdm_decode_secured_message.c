/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_secured_message_lib.h"
#include "spdm_transport_mctp_lib.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_RECEIVER_BUFFER_SIZE;
}

void libspdm_test_decode_secured_message(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t app_message_size;
    uint8_t *app_message;
    libspdm_secured_message_callbacks_t spdm_secured_message_callbacks;
    libspdm_session_info_t *session_info;
    bool is_requester;
    uint32_t session_id;
    libspdm_secured_message_context_t *secured_message_context;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    is_requester = spdm_test_context->is_requester;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_secured_message_callbacks.version = LIBSPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    spdm_secured_message_callbacks.get_sequence_number = libspdm_mctp_get_sequence_number;
    spdm_secured_message_callbacks.get_max_random_number_count =
        libspdm_mctp_get_max_random_number_count;
    spdm_secured_message_callbacks.get_secured_spdm_version =
        libspdm_mctp_get_secured_spdm_version;
    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, false);
    secured_message_context = session_info->secured_message_context;
    secured_message_context->session_type = LIBSPDM_SESSION_TYPE_MAC_ONLY;
    secured_message_context->session_state = LIBSPDM_SESSION_STATE_HANDSHAKING;

    app_message_size = spdm_test_context->test_buffer_size;

    libspdm_decode_secured_message(secured_message_context, session_id, is_requester,
                                   spdm_test_context->test_buffer_size,
                                   spdm_test_context->test_buffer,
                                   &app_message_size, (void **)&app_message,
                                   &spdm_secured_message_callbacks);
}

libspdm_test_context_t m_libspdm_transport_mctp_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_transport_mctp_test_context);

    m_libspdm_transport_mctp_test_context.test_buffer = test_buffer;
    m_libspdm_transport_mctp_test_context.test_buffer_size = test_buffer_size;

    libspdm_unit_test_group_setup(&State);

    libspdm_test_decode_secured_message(&State);

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
