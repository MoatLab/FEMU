/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

libspdm_return_t libspdm_vendor_get_id_func_test(
    void *spdm_context,
    uint16_t *resp_standard_id,
    uint8_t *resp_vendor_id_len,
    void *resp_vendor_id)
{
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_vendor_response_func_test(
    void *spdm_context,
    uint16_t req_standard_id,
    uint8_t req_vendor_id_len,
    const void *req_vendor_id,
    uint16_t req_size,
    const void *req_data,
    uint16_t *resp_size,
    void *resp_data)
{
    return LIBSPDM_STATUS_SUCCESS;
}

void libspdm_test_responder_vendor_cmds_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    libspdm_session_info_t *session_info;
    uint32_t session_id;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.is_requester = true;

    libspdm_register_vendor_get_id_callback_func(spdm_context,
                                                 libspdm_vendor_get_id_func_test);
    libspdm_register_vendor_callback_func(spdm_context,
                                          libspdm_vendor_response_func_test);

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);

    response_size = sizeof(response);
    libspdm_get_vendor_defined_response(spdm_context,
                                        spdm_test_context->test_buffer_size,
                                        spdm_test_context->test_buffer,
                                        &response_size, response);
}

libspdm_test_context_t m_libspdm_responder_vendor_cmds_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;
    libspdm_setup_test_context(&m_libspdm_responder_vendor_cmds_test_context);

    m_libspdm_responder_vendor_cmds_test_context.test_buffer = test_buffer;
    m_libspdm_responder_vendor_cmds_test_context.test_buffer_size =
        test_buffer_size;

    /* Success Case*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_vendor_cmds_case1(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /*LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES*/
