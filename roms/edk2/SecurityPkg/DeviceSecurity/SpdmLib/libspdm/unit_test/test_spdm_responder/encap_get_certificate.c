/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && \
    (LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT)

static void *m_libspdm_local_certificate_chain;
static size_t m_libspdm_local_certificate_chain_size;

spdm_certificate_response_t m_spdm_get_certificate_response1;
size_t m_spdm_get_certificate_response1_size;

spdm_certificate_response_t m_spdm_get_certificate_response2 = {
    {SPDM_MESSAGE_VERSION_10, SPDM_ERROR, SPDM_ERROR_CODE_INVALID_REQUEST, 0},
    0,
    0
};
size_t m_spdm_get_certificate_response2_size = sizeof(m_spdm_get_certificate_response2);

/**
 * Test 1: Normal case, request a certificate chain
 * Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
 **/
void test_spdm_responder_encap_get_certificate_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    bool need_continue;
    spdm_certificate_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t temp_buf_size;
    uint16_t portion_length;
    uint16_t remainder_length;
    static size_t calling_index = 0;
    size_t spdm_response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->connection_info.algorithm.req_base_asym_alg =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;

    if (m_libspdm_local_certificate_chain == NULL) {
        libspdm_read_responder_public_certificate_chain(
            m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
            &m_libspdm_local_certificate_chain,
            &m_libspdm_local_certificate_chain_size, NULL, NULL);
    }

    portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    remainder_length =
        (uint16_t)(m_libspdm_local_certificate_chain_size -
                   LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                   (calling_index + 1));

    temp_buf_size =
        sizeof(spdm_certificate_response_t) + portion_length;
    spdm_response_size = temp_buf_size;
    spdm_response = (void *)temp_buf;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_response->header.request_response_code = SPDM_CERTIFICATE;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->portion_length = portion_length;
    spdm_response->remainder_length = remainder_length;
    libspdm_copy_mem(spdm_response + 1,
                     sizeof(temp_buf) - sizeof(*spdm_response),
                     (uint8_t *)m_libspdm_local_certificate_chain +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                     portion_length);

    free(m_libspdm_local_certificate_chain);
    m_libspdm_local_certificate_chain = NULL;
    m_libspdm_local_certificate_chain_size = 0;

    status = libspdm_process_encap_response_certificate(spdm_context, spdm_response_size,
                                                        spdm_response,
                                                        &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_context->mut_auth_cert_chain_buffer_size = 0;
    free(data);
}


/**
 * Test 2: force responder to send an ERROR message with code SPDM_ERROR_CODE_INVALID_REQUEST
 * Expected Behavior: get a RETURN_DEVICE_ERROR, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
 **/
void test_spdm_responder_encap_get_certificate_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->connection_info.algorithm.req_base_asym_alg =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;

    status = libspdm_process_encap_response_certificate(spdm_context,
                                                        m_spdm_get_certificate_response2_size,
                                                        &m_spdm_get_certificate_response2,
                                                        &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif

    spdm_context->mut_auth_cert_chain_buffer_size = 0;
    free(data);
}

/**
 * Test 3: Fail case, request a certificate chain,
 * spdm_request.offset + spdm_response.portion_length + spdm_response.remainder_length !=
 * total_responder_cert_chain_buffer_length.
 * Expected Behavior:returns a status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_responder_encap_get_certificate_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    bool need_continue;
    spdm_certificate_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t temp_buf_size;
    uint16_t portion_length;
    uint16_t remainder_length;
    static size_t calling_index = 0;
    size_t spdm_response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;


    spdm_context->connection_info.algorithm.req_base_asym_alg =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;

    if (m_libspdm_local_certificate_chain == NULL) {
        libspdm_read_responder_public_certificate_chain(
            m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
            &m_libspdm_local_certificate_chain,
            &m_libspdm_local_certificate_chain_size, NULL, NULL);
    }

    portion_length = 0;
    /* Fail response: spdm_request.offset + spdm_response.portion_length + spdm_response.remainder_length !=
     * total_responder_cert_chain_buffer_length.*/
    remainder_length =
        (uint16_t)(m_libspdm_local_certificate_chain_size - 1 -
                   LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (calling_index + 1));

    temp_buf_size =
        sizeof(spdm_certificate_response_t) + portion_length;
    spdm_response_size = temp_buf_size;
    spdm_response = (void *)temp_buf;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_response->header.request_response_code = SPDM_CERTIFICATE;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->portion_length = portion_length;
    spdm_response->remainder_length = remainder_length;
    libspdm_copy_mem(spdm_response + 1,
                     sizeof(temp_buf) - sizeof(*spdm_response),
                     (uint8_t *)m_libspdm_local_certificate_chain +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                     portion_length);

    free(m_libspdm_local_certificate_chain);
    m_libspdm_local_certificate_chain = NULL;
    m_libspdm_local_certificate_chain_size = 0;

    status = libspdm_process_encap_response_certificate(spdm_context, spdm_response_size,
                                                        spdm_response,
                                                        &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    spdm_context->mut_auth_cert_chain_buffer_size = 0;
    free(data);
}

/**
 * Test 4: Fail case, request a certificate chain, responder return portion_length > spdm_request.length.
 * Expected Behavior:returns a status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_responder_encap_get_certificate_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    bool need_continue;
    spdm_certificate_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t temp_buf_size;
    uint16_t portion_length;
    uint16_t remainder_length;
    static size_t calling_index = 0;
    size_t spdm_response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->connection_info.algorithm.req_base_asym_alg =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;

    if (m_libspdm_local_certificate_chain == NULL) {
        libspdm_read_responder_public_certificate_chain(
            m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
            &m_libspdm_local_certificate_chain,
            &m_libspdm_local_certificate_chain_size, NULL, NULL);
    }

    portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1; /* Fail response: responder return portion_length > spdm_request.length*/
    remainder_length =
        (uint16_t)(m_libspdm_local_certificate_chain_size - 1 -
                   LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (calling_index + 1));

    temp_buf_size =
        sizeof(spdm_certificate_response_t) + portion_length;
    spdm_response_size = temp_buf_size;
    spdm_response = (void *)temp_buf;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_response->header.request_response_code = SPDM_CERTIFICATE;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->portion_length = portion_length;
    spdm_response->remainder_length = remainder_length;
    libspdm_copy_mem(spdm_response + 1,
                     sizeof(temp_buf) - sizeof(*spdm_response),
                     (uint8_t *)m_libspdm_local_certificate_chain +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                     portion_length);

    free(m_libspdm_local_certificate_chain);
    m_libspdm_local_certificate_chain = NULL;
    m_libspdm_local_certificate_chain_size = 0;

    status = libspdm_process_encap_response_certificate(spdm_context, spdm_response_size,
                                                        spdm_response,
                                                        &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    spdm_context->mut_auth_cert_chain_buffer_size = 0;
    free(data);
}

/**
 * Test 5: check request attributes and response attributes ,
 * Set CertModel to determine whether it meets expectations
 * Expected Behavior: requester returns the status LIBSPDM_STATUS_SUCCESS
 * Expected Behavior: CertModel is GenericCert model and slot 0 , returns a status of RETURN_DEVICE_ERROR.
 * Expected Behavior: CertModel Value of 0 and certificate chain is valid, returns a status of RETURN_DEVICE_ERROR.
 **/
void test_spdm_responder_encap_get_certificate_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    bool need_continue;
    spdm_certificate_response_t *spdm_response;
    uint8_t temp_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t temp_buf_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    uint16_t portion_length;
    uint16_t remainder_length;
    size_t spdm_response_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);

    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;

    libspdm_read_responder_public_certificate_chain(
        m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
        &m_libspdm_local_certificate_chain,
        &m_libspdm_local_certificate_chain_size, NULL, NULL);

    portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    remainder_length =
        (uint16_t)(m_libspdm_local_certificate_chain_size -
                   LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);

    temp_buf_size =
        sizeof(spdm_certificate_response_t) + portion_length;
    spdm_response_size = temp_buf_size;
    spdm_response = (void *)temp_buf;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_response->header.request_response_code = SPDM_CERTIFICATE;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = 0;
    spdm_response->portion_length = portion_length;
    spdm_response->remainder_length = remainder_length;
    libspdm_copy_mem(spdm_response + 1,
                     sizeof(temp_buf) - sizeof(*spdm_response),
                     (uint8_t *)m_libspdm_local_certificate_chain,
                     portion_length);

    /* Sub Case 1: CertModel Value of 1 , DeviceCert model*/
    spdm_context->connection_info.multi_key_conn_req = true;
    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->connection_info.peer_cert_info[0] = 0;
    spdm_context->mut_auth_cert_chain_buffer_size = 0;
    spdm_response->header.param2 = SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
    libspdm_reset_message_mut_b(spdm_context);

    status = libspdm_process_encap_response_certificate(spdm_context, spdm_response_size,
                                                        spdm_response,
                                                        &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.peer_cert_info[0],
                     SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT);
    assert_int_equal(spdm_context->mut_auth_cert_chain_buffer_size,
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    assert_memory_equal(spdm_context->mut_auth_cert_chain_buffer, m_libspdm_local_certificate_chain,
                        LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);

    /* Sub Case 2: CertModel Value of 2 , AliasCert model*/
    spdm_context->connection_info.multi_key_conn_req = true;
    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->connection_info.peer_cert_info[0] = 0;
    spdm_response->header.param2 = SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT;
    libspdm_reset_message_mut_b(spdm_context);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    spdm_context->mut_auth_cert_chain_buffer_size = 0;
    spdm_context->mut_auth_cert_chain_buffer = cert_chain;

    status = libspdm_process_encap_response_certificate(spdm_context, spdm_response_size,
                                                        spdm_response,
                                                        &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.peer_cert_info[0],
                     SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT);
    assert_int_equal(spdm_context->mut_auth_cert_chain_buffer_size,
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    assert_memory_equal(spdm_context->mut_auth_cert_chain_buffer, m_libspdm_local_certificate_chain,
                        LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);

    /* Sub Case 3: CertModel Value of 3 GenericCert model , slot_id set 1
     * In all cases, the certificate model for slot 0 shall be either the device certificate model or the alias certificate model*/
    spdm_context->connection_info.multi_key_conn_req = true;
    spdm_context->encap_context.req_slot_id = 1;
    spdm_context->connection_info.peer_cert_info[1] = 0;
    spdm_context->mut_auth_cert_chain_buffer_size = 0;
    spdm_response->header.param1 = 1;
    spdm_response->header.param2 = SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT;
    libspdm_reset_message_mut_b(spdm_context);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    spdm_context->mut_auth_cert_chain_buffer_size = 0;
    spdm_context->mut_auth_cert_chain_buffer = cert_chain;

    status = libspdm_process_encap_response_certificate(spdm_context, spdm_response_size,
                                                        spdm_response,
                                                        &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.peer_cert_info[1],
                     SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT);
    assert_int_equal(spdm_context->mut_auth_cert_chain_buffer_size,
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    assert_memory_equal(spdm_context->mut_auth_cert_chain_buffer, m_libspdm_local_certificate_chain,
                        LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);

    /* Sub Case 4: CertModel Value of 3 , GenericCert model ,slot_id set 0
     * In all cases, the certificate model for slot 0 shall be either the device certificate model or the alias certificate model*/
    spdm_context->connection_info.multi_key_conn_req = true;
    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->connection_info.peer_cert_info[0] = 0;
    spdm_context->mut_auth_cert_chain_buffer_size = 0;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT;
    libspdm_reset_message_mut_b(spdm_context);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    spdm_context->mut_auth_cert_chain_buffer_size = 0;
    spdm_context->mut_auth_cert_chain_buffer = cert_chain;

    status = libspdm_process_encap_response_certificate(spdm_context, spdm_response_size,
                                                        spdm_response,
                                                        &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_int_equal(spdm_context->connection_info.peer_cert_info[0], 0);

    /* Sub Case 5: CertModel Value of 0 , MULTI_KEY_CONN_REQ is true*/
    /* Value of 0 indicates either that the certificate slot does not contain any certificates or that the corresponding
     * MULTI_KEY_CONN_REQ or MULTI_KEY_CONN_RSP is false. */
    spdm_context->connection_info.multi_key_conn_req = true;
    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->connection_info.peer_cert_info[0] = 0;
    spdm_context->mut_auth_cert_chain_buffer_size = 0;
    spdm_response->header.param2 = SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE;
    libspdm_reset_message_mut_b(spdm_context);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    spdm_context->mut_auth_cert_chain_buffer_size = 0;
    spdm_context->mut_auth_cert_chain_buffer = cert_chain;

    status = libspdm_process_encap_response_certificate(spdm_context, spdm_response_size,
                                                        spdm_response,
                                                        &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_int_equal(spdm_context->connection_info.peer_cert_info[0],
                     SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE);

    /* Sub Case 6: CertModel Value of 0 , MULTI_KEY_CONN_REQ is false*/
    /* Value of 0 indicates either that the certificate slot does not contain any certificates or that the corresponding
     * MULTI_KEY_CONN_REQ or MULTI_KEY_CONN_RSP is false. */
    spdm_context->connection_info.multi_key_conn_req = false;
    spdm_context->encap_context.req_slot_id = 0;
    spdm_context->connection_info.peer_cert_info[0] = 0;
    spdm_context->mut_auth_cert_chain_buffer_size = 0;
    spdm_response->header.param2 = SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE;
    libspdm_reset_message_mut_b(spdm_context);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    spdm_context->mut_auth_cert_chain_buffer_size = 0;
    spdm_context->mut_auth_cert_chain_buffer = cert_chain;

    status = libspdm_process_encap_response_certificate(spdm_context, spdm_response_size,
                                                        spdm_response,
                                                        &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.peer_cert_info[0],
                     SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE);
    assert_int_equal(spdm_context->mut_auth_cert_chain_buffer_size,
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    assert_memory_equal(spdm_context->mut_auth_cert_chain_buffer, m_libspdm_local_certificate_chain,
                        LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);

    free(data);
    free(m_libspdm_local_certificate_chain);
    m_libspdm_local_certificate_chain = NULL;
    m_libspdm_local_certificate_chain_size = 0;
}

libspdm_test_context_t m_spdm_responder_encap_get_certificate_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int spdm_responder_encap_get_certificate_test_main(void)
{
    const struct CMUnitTest spdm_responder_certificate_tests[] = {
        /* Success Case*/
        cmocka_unit_test(test_spdm_responder_encap_get_certificate_case1),
        /* Bad request size ,remaining length is 0*/
        cmocka_unit_test(test_spdm_responder_encap_get_certificate_case2),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(test_spdm_responder_encap_get_certificate_case2),
        /* Fail response: spdm_request.offset + spdm_response.portion_length + spdm_response.remainder_length !=
         * total_responder_cert_chain_buffer_length.*/
        cmocka_unit_test(test_spdm_responder_encap_get_certificate_case3),
        /* Fail response: responder return portion_length > spdm_request.length*/
        cmocka_unit_test(test_spdm_responder_encap_get_certificate_case4),
        /* check request attributes and response attributes*/
        cmocka_unit_test(test_spdm_responder_encap_get_certificate_case5),
    };

    libspdm_setup_test_context(&m_spdm_responder_encap_get_certificate_test_context);

    return cmocka_run_group_tests(spdm_responder_certificate_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (...) */
