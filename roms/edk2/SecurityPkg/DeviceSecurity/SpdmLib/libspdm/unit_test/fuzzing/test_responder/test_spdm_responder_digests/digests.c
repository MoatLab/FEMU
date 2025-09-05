/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

void libspdm_test_responder_digests_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t m_local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] =
        m_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_local_certificate_chain);
    libspdm_set_mem(m_local_certificate_chain, sizeof(m_local_certificate_chain),
                    (uint8_t)(0xFF));

    response_size = sizeof(response);
    libspdm_get_response_digests(spdm_context,
                                 spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer,
                                 &response_size, response);
    libspdm_reset_message_b(spdm_context);
}

void libspdm_test_responder_digests_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *State;

    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    response_size = sizeof(response);
    libspdm_get_response_digests(spdm_context,
                                 spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer,
                                 &response_size, response);
    libspdm_reset_message_b(spdm_context);
}

void libspdm_test_responder_digests_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *State;

    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->local_context.capability.flags |= 0;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;

    response_size = sizeof(response);
    libspdm_get_response_digests(spdm_context,
                                 spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer,
                                 &response_size, response);
    libspdm_reset_message_b(spdm_context);
}

void libspdm_test_responder_digests_case4(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;

    spdm_test_context = *State;

    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->local_context.capability.flags =
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;

    response_size = sizeof(response);
    libspdm_get_response_digests(spdm_context,
                                 spdm_test_context->test_buffer_size,
                                 spdm_test_context->test_buffer,
                                 &response_size, response);
    libspdm_reset_message_b(spdm_context);
}

libspdm_test_context_t m_libspdm_responder_digests_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;
    spdm_message_header_t *spdm_request_header;
    libspdm_setup_test_context(&m_libspdm_responder_digests_test_context);

    spdm_request_header = (spdm_message_header_t*)test_buffer;

    if (spdm_request_header->request_response_code != SPDM_GET_DIGESTS) {
        spdm_request_header->request_response_code = SPDM_GET_DIGESTS;
    }

    m_libspdm_responder_digests_test_context.test_buffer = test_buffer;
    m_libspdm_responder_digests_test_context.test_buffer_size =
        test_buffer_size;

    /* Success Case*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_digests_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /* response_state: LIBSPDM_RESPONSE_STATE_BUSY*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_digests_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    /* response_state: LIBSPDM_RESPONSE_STATE_NORMAL*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_digests_case3(&State);
    libspdm_unit_test_group_teardown(&State);

    /* capabilities.flag: SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_digests_case4(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/
