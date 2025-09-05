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
    (LIBSPDM_SEND_CHALLENGE_SUPPORT)

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

libspdm_test_context_t m_libspdm_responder_encap_challenge_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_M1M2_BUFFER_SIZE];

void libspdm_test_responder_encap_challenge_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_challenge_auth_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];

    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t *ptr;
    size_t spdm_response_size;
    void *data;
    size_t data_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_response_size = spdm_test_context->test_buffer_size;

    spdm_response = (void *)(uint8_t *)temp_buf;
    spdm_response_size = spdm_test_context->test_buffer_size;
    if (spdm_response_size > sizeof(temp_buf)) {
        spdm_response_size = sizeof(temp_buf);
    }
    libspdm_copy_mem((uint8_t *)temp_buf,
                     sizeof(temp_buf),
                     spdm_test_context->test_buffer,
                     spdm_response_size);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.req_base_asym_alg,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
    spdm_context->connection_info.peer_used_cert_chain_slot_id = 0;

    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;

    ptr = (void *)(spdm_response + 1);
    libspdm_hash_all(m_libspdm_use_hash_algo,
                     (spdm_context)->local_context.local_cert_chain_provision[0],
                     (spdm_context)->local_context.local_cert_chain_provision_size[0], ptr);
    ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);

    libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
    libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                     hash_data);
    libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);

    libspdm_process_encap_response_challenge_auth(spdm_context, spdm_response_size, spdm_response,
                                                  NULL);
    free(data);
    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    #else
    free(spdm_context->transcript.digest_context_mut_m1m2);
    libspdm_asym_free(spdm_context->connection_info.algorithm.req_base_asym_alg,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
    #endif
}

void libspdm_test_get_encap_request_challenge_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t encap_request_size;
    void *data;
    size_t data_size;

    spdm_challenge_request_t *spdm_request;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    encap_request_size = spdm_test_context->test_buffer_size;
    if (encap_request_size < sizeof(spdm_get_certificate_request_t)) {
        encap_request_size = sizeof(spdm_get_certificate_request_t);
    }
    spdm_request = malloc(encap_request_size);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_c(spdm_context);

    libspdm_get_encap_request_challenge(spdm_context, &encap_request_size, spdm_request);
    libspdm_reset_message_mut_c(spdm_context);
    free(spdm_request);
    free(data);
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_responder_encap_challenge_test_context);

    m_libspdm_responder_encap_challenge_test_context.test_buffer = test_buffer;
    m_libspdm_responder_encap_challenge_test_context.test_buffer_size = test_buffer_size;

    /* Success Case */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_encap_challenge_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Success Case */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_get_encap_request_challenge_case2(&State);
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
