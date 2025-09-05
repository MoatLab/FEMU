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

uint8_t m_cert_chain_buffer[SPDM_MAX_CERTIFICATE_CHAIN_SIZE];

bool libspdm_test_verify_spdm_cert_chain(void *spdm_context, uint8_t slot_id,
                                         size_t cert_chain_size, const void *cert_chain,
                                         const void **trust_anchor,
                                         size_t *trust_anchor_size)
{
    return true;
}

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

libspdm_test_context_t m_libspdm_responder_encap_get_certificate_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_test_responder_encap_get_certificate_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    spdm_certificate_response_t *spdm_response;
    size_t spdm_response_size;
    bool need_continue;

    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;

    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_response_size = spdm_test_context->test_buffer_size;
    spdm_response = (spdm_certificate_response_t *)spdm_test_context->test_buffer;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert,
                                          &root_cert_size);
    libspdm_dump_hex(root_cert, root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    libspdm_reset_message_b(spdm_context);

    libspdm_register_cert_chain_buffer(spdm_context, m_cert_chain_buffer,
                                       sizeof(m_cert_chain_buffer));

    libspdm_copy_mem(m_cert_chain_buffer, sizeof(m_cert_chain_buffer), data, data_size);
    spdm_context->mut_auth_cert_chain_buffer_size = data_size;

    uint16_t cert_chain_total_len =
        (uint16_t)spdm_context->mut_auth_cert_chain_buffer_size +
        spdm_response->portion_length + spdm_response->remainder_length;
    spdm_context->encap_context.cert_chain_total_len = cert_chain_total_len;

    libspdm_process_encap_response_certificate(spdm_context, spdm_response_size, spdm_response,
                                               &need_continue);
    libspdm_reset_message_mut_b(spdm_context);
    free(data);
    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    libspdm_asym_free(spdm_context->connection_info.algorithm.req_base_asym_alg,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
}

void libspdm_test_responder_encap_get_certificate_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    spdm_certificate_response_t *spdm_response;
    size_t spdm_response_size;
    bool need_continue;

    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;

    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_response_size = spdm_test_context->test_buffer_size;
    spdm_response = (spdm_certificate_response_t *)spdm_test_context->test_buffer;
    spdm_response->remainder_length = 0;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;


    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert,
                                          &root_cert_size);
    libspdm_dump_hex(root_cert, root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    if(data_size > LIBSPDM_MAX_CERT_CHAIN_SIZE ||
       spdm_response->portion_length + data_size > LIBSPDM_MAX_CERT_CHAIN_SIZE) {
        data_size = LIBSPDM_MAX_CERT_CHAIN_SIZE - spdm_response->portion_length;
    }
#endif
    libspdm_register_cert_chain_buffer(spdm_context, m_cert_chain_buffer,
                                       sizeof(m_cert_chain_buffer));

    libspdm_copy_mem(m_cert_chain_buffer, sizeof(m_cert_chain_buffer), data, data_size);
    spdm_context->mut_auth_cert_chain_buffer_size = data_size;

    uint16_t cert_chain_total_len =
        (uint16_t)spdm_context->mut_auth_cert_chain_buffer_size +
        spdm_response->portion_length + spdm_response->remainder_length;
    spdm_context->encap_context.cert_chain_total_len = cert_chain_total_len;

    libspdm_process_encap_response_certificate(spdm_context, spdm_response_size, spdm_response,
                                               &need_continue);

    libspdm_reset_message_mut_b(spdm_context);
    free(data);
    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    libspdm_asym_free(spdm_context->connection_info.algorithm.req_base_asym_alg,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
}

void libspdm_test_responder_encap_get_certificate_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    spdm_certificate_response_t *spdm_response;
    size_t spdm_response_size;
    bool need_continue;

    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;

    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_response_size = spdm_test_context->test_buffer_size;
    spdm_response = (spdm_certificate_response_t *)spdm_test_context->test_buffer;
    spdm_response->remainder_length = 0;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_register_verify_spdm_cert_chain_func (spdm_context,
                                                  libspdm_test_verify_spdm_cert_chain);

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert,
                                          &root_cert_size);
    libspdm_dump_hex(root_cert, root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    if(data_size > LIBSPDM_MAX_CERT_CHAIN_SIZE ||
       spdm_response->portion_length + data_size > LIBSPDM_MAX_CERT_CHAIN_SIZE) {
        data_size = LIBSPDM_MAX_CERT_CHAIN_SIZE - spdm_response->portion_length;
    }
#endif
    libspdm_register_cert_chain_buffer(spdm_context, m_cert_chain_buffer,
                                       sizeof(m_cert_chain_buffer));

    libspdm_copy_mem(m_cert_chain_buffer, sizeof(m_cert_chain_buffer), data, data_size);
    spdm_context->mut_auth_cert_chain_buffer_size = data_size;

    uint16_t cert_chain_total_len =
        (uint16_t)spdm_context->mut_auth_cert_chain_buffer_size +
        spdm_response->portion_length + spdm_response->remainder_length;
    spdm_context->encap_context.cert_chain_total_len = cert_chain_total_len;

    libspdm_process_encap_response_certificate(spdm_context, spdm_response_size, spdm_response,
                                               &need_continue);

    libspdm_reset_message_mut_b(spdm_context);
    free(data);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    libspdm_asym_free(spdm_context->connection_info.algorithm.req_base_asym_alg,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
}

void libspdm_test_get_encap_request_get_certificate_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t encap_request_size;
    void *data;
    size_t data_size;

    spdm_get_certificate_request_t *spdm_request;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    encap_request_size = spdm_test_context->test_buffer_size;

    if (encap_request_size < sizeof(spdm_get_certificate_request_t)) {
        encap_request_size = sizeof(spdm_get_certificate_request_t);
    }

    spdm_request = malloc(encap_request_size);

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    libspdm_reset_message_b(spdm_context);

    libspdm_get_encap_request_get_certificate(spdm_context, &encap_request_size,
                                              spdm_request);
    libspdm_reset_message_mut_b(spdm_context);
    free(spdm_request);
    free(data);
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_responder_encap_get_certificate_test_context);

    m_libspdm_responder_encap_get_certificate_test_context.test_buffer = test_buffer;
    m_libspdm_responder_encap_get_certificate_test_context.test_buffer_size = test_buffer_size;

    /* Success Case */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_encap_get_certificate_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Force spdm_response->remainder_length to zero
     * It is convenient for fuzzy testing and testing other branches*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_encap_get_certificate_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Use Peer Cert verify*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_encap_get_certificate_case3(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Success Case */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_get_encap_request_get_certificate_case2(&State);
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
