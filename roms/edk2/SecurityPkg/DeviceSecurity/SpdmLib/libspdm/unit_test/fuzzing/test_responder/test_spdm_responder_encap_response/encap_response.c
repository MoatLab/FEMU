/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

libspdm_test_context_t m_libspdm_response_encapsulated_request_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_test_get_response_encapsulated_request_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t data_size;
    void *data;
    size_t response_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->encap_context.request_id = 0x00;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.request_op_code_count =
        LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT;
    spdm_context->encap_context.current_request_op_code = 0;
    spdm_context->encap_context.request_op_code_sequence[0] = SPDM_GET_DIGESTS;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
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
    response_size = sizeof(response);
    libspdm_get_response_encapsulated_request(spdm_context,
                                              spdm_test_context->test_buffer_size,
                                              spdm_test_context->test_buffer,
                                              &response_size,
                                              response);
    libspdm_reset_message_mut_c(spdm_context);
    free(data);
}

void libspdm_test_get_response_encapsulated_request_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->encap_context.request_id = 0x00;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->encap_context.current_request_op_code = SPDM_CHALLENGE;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(local_certificate_chain);
    libspdm_set_mem(local_certificate_chain, sizeof(local_certificate_chain), (uint8_t)(0xFF));

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_request(spdm_context,
                                              spdm_test_context->test_buffer_size,
                                              spdm_test_context->test_buffer,
                                              &response_size,
                                              response);
    libspdm_reset_message_mut_c(spdm_context);
}

void libspdm_test_get_response_encapsulated_request_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->encap_context.request_id = 0x00;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->encap_context.current_request_op_code = SPDM_GET_DIGESTS;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(local_certificate_chain);
    libspdm_set_mem(local_certificate_chain, sizeof(local_certificate_chain), (uint8_t)(0xFF));

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_request(spdm_context,
                                              spdm_test_context->test_buffer_size,
                                              spdm_test_context->test_buffer,
                                              &response_size,
                                              response);
    libspdm_reset_message_mut_c(spdm_context);
}

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
void libspdm_test_get_response_encapsulated_request_case4(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->encap_context.request_id = 0x00;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;

    spdm_context->encap_context.current_request_op_code = SPDM_GET_DIGESTS;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(local_certificate_chain);
    libspdm_set_mem(local_certificate_chain, sizeof(local_certificate_chain), (uint8_t)(0xFF));

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_request(spdm_context,
                                              spdm_test_context->test_buffer_size,
                                              spdm_test_context->test_buffer,
                                              &response_size,
                                              response);
    libspdm_reset_message_mut_c(spdm_context);
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

void libspdm_test_get_response_encapsulated_request_case5(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->encap_context.request_id = 0x00;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.request_op_code_count =
        LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT;
    spdm_context->encap_context.current_request_op_code = 0;

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_request(spdm_context,
                                              spdm_test_context->test_buffer_size,
                                              spdm_test_context->test_buffer,
                                              &response_size,
                                              response);
    libspdm_reset_message_mut_c(spdm_context);
}

void libspdm_test_get_response_encapsulated_response_ack_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t data_size;
    void *data;
    size_t response_size;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->encap_context.request_id = 0x01;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.request_op_code_count =
        LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT;

    spdm_context->encap_context.current_request_op_code = 0;
    spdm_context->encap_context.request_op_code_sequence[0] = SPDM_GET_DIGESTS;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
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

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                   spdm_test_context->test_buffer_size,
                                                   spdm_test_context->test_buffer, &response_size,
                                                   response);
    libspdm_reset_message_mut_b(spdm_context);
    free(data);
}

void libspdm_test_get_response_encapsulated_response_ack_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->encap_context.request_id = 0x01;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.request_op_code_count =
        LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT;
    spdm_context->encap_context.current_request_op_code = 0;

    response_size = sizeof(response);

    libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                   spdm_test_context->test_buffer_size,
                                                   spdm_test_context->test_buffer, &response_size,
                                                   response);
}

void libspdm_test_get_response_encapsulated_response_ack_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t data_size;
    void *data;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->encap_context.request_id = 0x01;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.request_op_code_count =
        LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT;
    spdm_context->encap_context.current_request_op_code = SPDM_GET_DIGESTS;
    spdm_context->encap_context.request_op_code_sequence[0] = SPDM_GET_DIGESTS;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
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
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(local_certificate_chain);
    libspdm_set_mem(local_certificate_chain, sizeof(local_certificate_chain), (uint8_t)(0xFF));

    libspdm_reset_message_b(spdm_context);

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                   spdm_test_context->test_buffer_size,
                                                   spdm_test_context->test_buffer, &response_size,
                                                   response);
    libspdm_reset_message_mut_b(spdm_context);
    free(data);
}

void libspdm_test_get_response_encapsulated_response_ack_case4(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->encap_context.request_id = 0x01;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.request_op_code_count =
        LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT;

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                   spdm_test_context->test_buffer_size,
                                                   spdm_test_context->test_buffer, &response_size,
                                                   response);
}

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
void libspdm_test_get_response_encapsulated_response_ack_case5(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->encap_context.request_id = 0x01;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.request_op_code_count =
        LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT;

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                   spdm_test_context->test_buffer_size,
                                                   spdm_test_context->test_buffer, &response_size,
                                                   response);
}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

void libspdm_test_get_response_encapsulated_response_ack_case6(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t data_size;
    void *data;
    size_t response_size;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->encap_context.request_id = 0xFF;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_PROCESSING_ENCAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP;
    spdm_context->encap_context.request_op_code_count =
        LIBSPDM_MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT;

    spdm_context->encap_context.current_request_op_code = 0;
    spdm_context->encap_context.request_op_code_sequence[0] = SPDM_GET_DIGESTS;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
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

    response_size = sizeof(response);
    libspdm_get_response_encapsulated_response_ack(spdm_context,
                                                   spdm_test_context->test_buffer_size,
                                                   spdm_test_context->test_buffer, &response_size,
                                                   response);
    libspdm_reset_message_mut_b(spdm_context);
    free(data);
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_response_encapsulated_request_test_context);

    m_libspdm_response_encapsulated_request_test_context.test_buffer = test_buffer;
    m_libspdm_response_encapsulated_request_test_context.test_buffer_size = test_buffer_size;

    /* Success Case */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_request_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /*current_request_op_code: SPDM_CHALLENGE */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_request_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    /*response_state : LIBSPDM_RESPONSE_STATE_NORMAL */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_request_case3(&State);
    libspdm_unit_test_group_teardown(&State);

    #if SPDM_RESPONSE_STATE_NOT_READY
    /*response_state : LIBSPDM_RESPONSE_STATE_NOT_READY */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_request_case4(&State);
    libspdm_unit_test_group_teardown(&State);
    #endif /* SPDM_RESPONSE_STATE_NOT_READY */

    /* current_request_op_code: NULL */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_request_case5(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Success Case */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_response_ack_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /* current_request_op_code: NULL */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_response_ack_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    /*current_request_op_code: SPDM_GET_DIGESTS */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_response_ack_case3(&State);
    libspdm_unit_test_group_teardown(&State);

    /*response_state : LIBSPDM_RESPONSE_STATE_NORMAL */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_response_ack_case4(&State);
    libspdm_unit_test_group_teardown(&State);

    #if SPDM_RESPONSE_STATE_NOT_READY
    /*response_state : LIBSPDM_RESPONSE_STATE_NOT_READY */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_response_ack_case5(&State);
    libspdm_unit_test_group_teardown(&State);
    #endif /* SPDM_RESPONSE_STATE_NOT_READY */

    /*Success Case  When version is greater than V1.2 */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_get_response_encapsulated_response_ack_case6(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */
