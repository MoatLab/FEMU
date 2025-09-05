/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && \
    (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

libspdm_test_context_t m_libspdm_responder_encap_get_digests_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_test_responder_encap_get_digests_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    bool need_continue;
    uint8_t m_local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_local_certificate_chain);
    libspdm_set_mem(m_local_certificate_chain, sizeof(m_local_certificate_chain), (uint8_t)(0xFF));

    libspdm_process_encap_response_digest(spdm_context, spdm_test_context->test_buffer_size,
                                          spdm_test_context->test_buffer, &need_continue);
    libspdm_reset_message_mut_c(spdm_context);
}

void libspdm_test_get_encap_request_get_digest_case2(void **State)
{

    libspdm_test_context_t *spdm_test_context;
    spdm_get_digest_request_t *spdm_request;
    libspdm_context_t *spdm_context;
    size_t encap_request_size;
    void *data;
    size_t data_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    encap_request_size = spdm_test_context->test_buffer_size;

    if (encap_request_size < sizeof(spdm_get_digest_request_t)) {
        encap_request_size = sizeof(spdm_get_digest_request_t);
    }
    spdm_request = malloc(encap_request_size);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_b(spdm_context);

    libspdm_get_encap_request_get_digest(spdm_context, &encap_request_size, spdm_request);
    libspdm_reset_message_mut_c(spdm_context);
    free(spdm_request);
    free(data);
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_responder_encap_get_digests_test_context);

    m_libspdm_responder_encap_get_digests_test_context.test_buffer = test_buffer;
    m_libspdm_responder_encap_get_digests_test_context.test_buffer_size = test_buffer_size;

    /* Success Case */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_encap_get_digests_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Success Case */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_get_encap_request_get_digest_case2(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (...) */
