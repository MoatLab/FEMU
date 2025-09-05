/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && \
    (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP)

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

void libspdm_test_requester_encap_certificate(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_certificate_request_t *spdm_request;
    size_t request_size;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void *data;
    size_t data_size;
    uint8_t slot_id;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;

    spdm_request = (spdm_get_certificate_request_t *)spdm_test_context->test_buffer;
    slot_id = spdm_request->header.param1;

    request_size = spdm_test_context->test_buffer_size;
    if (request_size > sizeof(spdm_get_certificate_request_t)) {
        request_size = sizeof(spdm_get_certificate_request_t);
    }

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);

    spdm_context->local_context.local_cert_chain_provision[slot_id] = data;
    spdm_context->local_context.local_cert_chain_provision_size[slot_id] = data_size;

    response_size = sizeof(response);
    libspdm_get_encap_response_certificate(spdm_context, request_size,
                                           (uint8_t *)spdm_test_context->test_buffer,
                                           &response_size, response);
    spdm_error_response_t *spdm_response = (spdm_error_response_t *)response;
    if (spdm_response->header.request_response_code != SPDM_ERROR) {
        libspdm_reset_message_mut_b(spdm_context);
    }
    free(data);
}

libspdm_test_context_t m_libspdm_requester_encap_certificate_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_encap_certificate_test_context);

    m_libspdm_requester_encap_certificate_test_context.test_buffer = test_buffer;
    m_libspdm_requester_encap_certificate_test_context.test_buffer_size = test_buffer_size;

    /* Successful response */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_encap_certificate(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (..) */
