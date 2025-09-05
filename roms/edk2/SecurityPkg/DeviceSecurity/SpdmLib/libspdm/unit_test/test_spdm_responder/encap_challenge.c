/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && \
    (LIBSPDM_SEND_CHALLENGE_SUPPORT)

static uint8_t m_requester_context[SPDM_REQ_CONTEXT_SIZE];

void libspdm_test_responder_encap_challenge_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_challenge_auth_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_SENDER_BUFFER_SIZE];
    uint8_t *ptr;
    size_t response_size;
    size_t sig_size;
    bool need_continue;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    libspdm_reset_message_mut_c(spdm_context);
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
    spdm_context->encap_context.req_slot_id = 0;

    sig_size = libspdm_get_asym_signature_size(m_libspdm_use_req_asym_algo);
    response_size = sizeof(spdm_challenge_auth_response_t) +
                    libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                    SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 + sig_size;
    spdm_response = (void *)temp_buf;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = (1 << 0);

    ptr = (void *)(spdm_response + 1);
    libspdm_hash_all(m_libspdm_use_hash_algo, data, data_size, ptr);
    ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
    ptr += SPDM_NONCE_SIZE;

    *(uint16_t *)ptr = 0;
    ptr += sizeof(uint16_t);

    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_CHALLENGE_AUTH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, (uint8_t*)spdm_response, response_size - sig_size,
            ptr, &sig_size);

    status =  libspdm_process_encap_response_challenge_auth(spdm_context, response_size,
                                                            spdm_response,
                                                            &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    /* Completion of CHALLENGE sets M1/M2 to null. */
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#else
    assert_null(spdm_context->transcript.digest_context_mut_m1m2);
#endif
    free(data);
}

void libspdm_test_responder_encap_challenge_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_error_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
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
    spdm_context->encap_context.req_slot_id = 0;

    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;

    response_size = sizeof(spdm_error_response_t);
    spdm_response = (void *)temp_buf;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.request_response_code = SPDM_ERROR;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    status =   libspdm_process_encap_response_challenge_auth(spdm_context, response_size,
                                                             spdm_response,
                                                             NULL);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
    free(data);
}


void libspdm_test_responder_encap_challenge_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_challenge_auth_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
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
    spdm_context->encap_context.req_slot_id = 0;

    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;

    response_size = sizeof(spdm_error_response_t);
    spdm_response = (void *)temp_buf;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.request_response_code = SPDM_CERTIFICATE;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    status =   libspdm_process_encap_response_challenge_auth(spdm_context, response_size,
                                                             spdm_response,
                                                             NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

void libspdm_test_responder_encap_challenge_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_challenge_auth_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
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
    spdm_context->encap_context.req_slot_id = 0;

    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;

    response_size = sizeof(spdm_error_response_t);
    spdm_response = (void *)temp_buf;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;

    status =   libspdm_process_encap_response_challenge_auth(spdm_context, response_size,
                                                             spdm_response,
                                                             NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

void libspdm_test_responder_encap_challenge_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_challenge_auth_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    size_t sig_size;
    uint8_t *ptr;
    bool need_continue;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;

    libspdm_read_requester_public_key(m_libspdm_use_req_asym_algo, &data, &data_size);
    spdm_context->local_context.peer_public_key_provision = data;
    spdm_context->local_context.peer_public_key_provision_size = data_size;

    spdm_context->encap_context.req_slot_id = 0xFF;

    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);

    sig_size = libspdm_get_asym_signature_size(m_libspdm_use_req_asym_algo);
    response_size = sizeof(spdm_challenge_auth_response_t) +
                    libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                    SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 + sig_size;
    spdm_response = (void *)temp_buf;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    spdm_response->header.param1 = (0xFF & SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_SLOT_ID_MASK);
    spdm_response->header.param2 = 0;

    ptr = (void *)(spdm_response + 1);
    libspdm_hash_all(m_libspdm_use_hash_algo, data, data_size, ptr);
    ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
    ptr += SPDM_NONCE_SIZE;

    *(uint16_t *)ptr = 0;
    ptr += sizeof(uint16_t);

    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_CHALLENGE_AUTH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, (uint8_t*)spdm_response, response_size - sig_size,
            ptr, &sig_size);

    status = libspdm_process_encap_response_challenge_auth(spdm_context, response_size,
                                                           spdm_response,
                                                           &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    free(data);
}

/**
 * Test 6: Successful case , With the correct challenge context field
 * Expected Behavior: client returns a status of RETURN_SUCCESS.
 **/
void libspdm_test_responder_encap_challenge_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_challenge_auth_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_SENDER_BUFFER_SIZE];
    uint8_t *ptr;
    size_t response_size;
    size_t sig_size;
    bool need_continue;
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    libspdm_read_requester_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_req_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    libspdm_reset_message_mut_c(spdm_context);
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
    spdm_context->encap_context.req_slot_id = 0;
    libspdm_set_mem(m_requester_context, SPDM_REQ_CONTEXT_SIZE, 0xAA);
    libspdm_copy_mem(spdm_context->encap_context.req_context, SPDM_REQ_CONTEXT_SIZE,
                     m_requester_context, SPDM_REQ_CONTEXT_SIZE);


    sig_size = libspdm_get_asym_signature_size(m_libspdm_use_req_asym_algo);
    response_size = sizeof(spdm_challenge_auth_response_t) +
                    libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                    SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 + SPDM_REQ_CONTEXT_SIZE + sig_size;
    spdm_response = (void *)temp_buf;
    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = (1 << 0);

    ptr = (void *)(spdm_response + 1);
    libspdm_hash_all(m_libspdm_use_hash_algo, data, data_size, ptr);
    ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
    ptr += SPDM_NONCE_SIZE;

    *(uint16_t *)ptr = 0;
    ptr += sizeof(uint16_t);

    libspdm_set_mem(ptr, SPDM_REQ_CONTEXT_SIZE, 0xAA);
    ptr += SPDM_REQ_CONTEXT_SIZE;

    libspdm_requester_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
        spdm_context,
#endif
        spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            SPDM_CHALLENGE_AUTH,
            m_libspdm_use_req_asym_algo, m_libspdm_use_hash_algo,
            false, (uint8_t*)spdm_response, response_size - sig_size,
            ptr, &sig_size);

    status =  libspdm_process_encap_response_challenge_auth(spdm_context, response_size,
                                                            spdm_response,
                                                            &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#else
    assert_null(spdm_context->transcript.digest_context_mut_m1m2);
#endif
    free(data);
}

libspdm_test_context_t m_libspdm_responder_encap_challenge_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_encap_challenge_auth_test_main(void)
{
    const struct CMUnitTest spdm_responder_challenge_tests[] = {
        cmocka_unit_test(libspdm_test_responder_encap_challenge_case1),
        /* Error response: SPDM_ERROR*/
        cmocka_unit_test(libspdm_test_responder_encap_challenge_case2),
        /* Error request_response_code  : SPDM_CERTIFICATE */
        cmocka_unit_test(libspdm_test_responder_encap_challenge_case3),
        /* Error spdm_response_size */
        cmocka_unit_test(libspdm_test_responder_encap_challenge_case4),
        /* Success Case, use provisioned public key (slot 0xFF) */
        cmocka_unit_test(libspdm_test_responder_encap_challenge_case5),
        /* Success Case, V1.3 With the correct challenge context field */
        cmocka_unit_test(libspdm_test_responder_encap_challenge_case6),
    };

    libspdm_setup_test_context(&m_libspdm_responder_encap_challenge_test_context);

    return cmocka_run_group_tests(spdm_responder_challenge_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (...) */
