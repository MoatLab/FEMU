/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_RESPOND_IF_READY_SUPPORT

#define LIBSPDM_MY_TEST_TOKEN 0x30

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

libspdm_test_context_t m_libspdm_responder_if_ready_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_test_responder_respond_if_ready(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_get_digest_request_t spdm_test_get_digest_request = {
        { SPDM_MESSAGE_VERSION_11, SPDM_GET_DIGESTS, 0, 0 },
    };
    size_t spdm_test_get_digest_request_size = sizeof(spdm_message_header_t);

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.local_cert_chain_provision[0] =
        local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(local_certificate_chain);
    libspdm_set_mem(local_certificate_chain, sizeof(local_certificate_chain),
                    (uint8_t)(0xFF));

    spdm_context->last_spdm_request_size = spdm_test_get_digest_request_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_test_get_digest_request,  spdm_test_get_digest_request_size);

    spdm_context->cache_spdm_request_size =
        spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm = 1;
    spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
    spdm_context->error_data.token = LIBSPDM_MY_TEST_TOKEN;

    response_size = sizeof(response);
    libspdm_get_response_respond_if_ready(spdm_context,
                                          spdm_test_context->test_buffer_size,
                                          spdm_test_context->test_buffer,
                                          &response_size, response);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
}

void libspdm_test_responder_respond_if_ready_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;
    spdm_get_digest_request_t spdm_test_get_digest_request = {
        { SPDM_MESSAGE_VERSION_11, SPDM_GET_DIGESTS, 0, 0 },
    };
    size_t spdm_test_get_digest_request_size = sizeof(spdm_message_header_t);

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.local_cert_chain_provision[0] =
        local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(local_certificate_chain);
    libspdm_set_mem(local_certificate_chain, sizeof(local_certificate_chain),
                    (uint8_t)(0xFF));

    spdm_context->last_spdm_request_size = spdm_test_get_digest_request_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_test_get_digest_request,  spdm_test_get_digest_request_size);

    spdm_context->cache_spdm_request_size =
        spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm = 1;
    spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
    spdm_context->error_data.token = LIBSPDM_MY_TEST_TOKEN;

    response_size = sizeof(response);
    libspdm_get_response_respond_if_ready(spdm_context,
                                          spdm_test_context->test_buffer_size,
                                          spdm_test_context->test_buffer,
                                          &response_size, response);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
}

void libspdm_test_responder_respond_if_ready_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    uint8_t local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;
    spdm_get_digest_request_t spdm_test_get_digest_request = {
        { SPDM_MESSAGE_VERSION_11, SPDM_GET_DIGESTS, 0, 0 },
    };
    size_t spdm_test_get_digest_request_size = sizeof(spdm_message_header_t);

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.local_cert_chain_provision[0] =
        local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(local_certificate_chain);
    libspdm_set_mem(local_certificate_chain, sizeof(local_certificate_chain),
                    (uint8_t)(0xFF));

    spdm_context->last_spdm_request_size = spdm_test_get_digest_request_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &spdm_test_get_digest_request,  spdm_test_get_digest_request_size);

    spdm_context->cache_spdm_request_size =
        spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm = 1;
    spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
    spdm_context->error_data.token = LIBSPDM_MY_TEST_TOKEN;

    response_size = sizeof(response);
    libspdm_get_response_respond_if_ready(spdm_context,
                                          spdm_test_context->test_buffer_size,
                                          spdm_test_context->test_buffer,
                                          &response_size, response);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_responder_if_ready_test_context);

    m_libspdm_responder_if_ready_test_context.test_buffer = test_buffer;
    m_libspdm_responder_if_ready_test_context.test_buffer_size =
        test_buffer_size;

    /* Success Case*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_respond_if_ready(&State);
    libspdm_unit_test_group_teardown(&State);

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_respond_if_ready_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_respond_if_ready_case3(&State);
    libspdm_unit_test_group_teardown(&State);
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
