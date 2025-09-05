/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT

uint8_t temp_buf[LIBSPDM_RECEIVER_BUFFER_SIZE];
size_t calling_index = 0;

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

libspdm_return_t libspdm_device_send_message(void *spdm_context, size_t request_size,
                                             const void *request, uint64_t timeout)
{
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_device_receive_message(void *spdm_context, size_t *response_size,
                                                void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    uint8_t *spdm_response;
    size_t spdm_response_size;
    size_t test_message_header_size;

    spdm_test_context = libspdm_get_test_context();

    test_message_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    spdm_response = (void *)((uint8_t *)temp_buf + test_message_header_size);
    spdm_response_size = spdm_test_context->test_buffer_size;
    if (spdm_response_size >
        (calling_index + 1) *
        (LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + sizeof(spdm_certificate_response_t))) {
        spdm_response_size = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + sizeof(spdm_certificate_response_t);
    } else if (spdm_response_size >
               calling_index *
               (LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + sizeof(spdm_certificate_response_t))) {
        spdm_response_size = spdm_response_size - calling_index *
                             (LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN+sizeof(spdm_certificate_response_t));
    } else {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    libspdm_copy_mem((uint8_t *)temp_buf + test_message_header_size,
                     sizeof(temp_buf) - test_message_header_size,
                     (const uint8_t *)spdm_test_context->test_buffer +
                     (LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + sizeof(spdm_certificate_response_t)) * calling_index,
                     spdm_response_size);

    libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                          spdm_response_size,
                                          spdm_response, response_size, response);
    calling_index++;

    return LIBSPDM_STATUS_SUCCESS;
}

void libspdm_test_requester_get_certificate_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    calling_index = 0;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;

    spdm_context->local_context.is_requester = true;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert,
                                          &root_cert_size);
    libspdm_dump_hex(root_cert, root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));

    libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    free(data);
    libspdm_reset_message_b(spdm_context);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    if (spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key != NULL) {
        libspdm_asym_free(
            spdm_context->connection_info.algorithm.base_asym_algo,
            spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
    }
#endif
}

void libspdm_test_requester_get_certificate_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    calling_index = 0;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.is_requester = true;
    libspdm_register_verify_spdm_cert_chain_func (spdm_context,
                                                  libspdm_test_verify_spdm_cert_chain);
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert,
                                          &root_cert_size);
    libspdm_dump_hex(root_cert, root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));

    libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    free(data);
    libspdm_reset_message_b(spdm_context);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    if (spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key != NULL) {
        libspdm_asym_free(
            spdm_context->connection_info.algorithm.base_asym_algo,
            spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
    }
#endif
}

void libspdm_test_requester_get_certificate_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    calling_index = 0;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;

    spdm_context->local_context.is_requester = true;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert,
                                          &root_cert_size);
    libspdm_dump_hex(root_cert, root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));

    libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    free(data);
    libspdm_reset_message_b(spdm_context);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    if (spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key != NULL) {
        libspdm_asym_free(
            spdm_context->connection_info.algorithm.base_asym_algo,
            spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
    }
#endif
}

void libspdm_test_requester_get_certificate_ex_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    calling_index = 0;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.is_requester = true;
    libspdm_register_verify_spdm_cert_chain_func (spdm_context,
                                                  libspdm_test_verify_spdm_cert_chain);
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert,
                                          &root_cert_size);
    libspdm_dump_hex(root_cert, root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    libspdm_get_certificate_ex(spdm_context, NULL, 0, &cert_chain_size, cert_chain,NULL,NULL);

    free(data);
    libspdm_reset_message_b(spdm_context);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    if (spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key != NULL) {
        libspdm_asym_free(
            spdm_context->connection_info.algorithm.base_asym_algo,
            spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
    }
#endif
}

void libspdm_test_requester_get_certificate_in_session_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    calling_index = 0;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
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
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->local_context.is_requester = true;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    session_info->session_transcript.message_m.buffer_size =
        session_info->session_transcript.message_m.max_buffer_size;
#endif
    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    libspdm_get_certificate_ex(spdm_context, &session_id, 0, &cert_chain_size, cert_chain,
                               NULL, NULL);

    free(data);
    libspdm_reset_message_b(spdm_context);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    if (spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key != NULL) {
        libspdm_asym_free(
            spdm_context->connection_info.algorithm.base_asym_algo,
            spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
    }
#endif
}

libspdm_test_context_t m_libspdm_requester_get_certificate_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_get_certificate_test_context);

    m_libspdm_requester_get_certificate_test_context.test_buffer = test_buffer;
    m_libspdm_requester_get_certificate_test_context.test_buffer_size = test_buffer_size;

    /* Successful response*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_get_certificate_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /*Support local_context.verify_peer_spdm_cert_chain  */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_get_certificate_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_get_certificate_case3(&State);
    libspdm_unit_test_group_teardown(&State);

    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_get_certificate_ex_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_get_certificate_in_session_case1(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
