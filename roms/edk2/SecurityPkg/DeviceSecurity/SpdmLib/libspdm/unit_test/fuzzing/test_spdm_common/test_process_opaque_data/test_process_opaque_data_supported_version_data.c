/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "library/spdm_crypt_lib.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_responder_lib.h"


size_t libspdm_get_max_buffer_size(void)
{
    return SPDM_MAX_OPAQUE_DATA_SIZE;
}

void libspdm_test_process_opaque_data_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;


    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    libspdm_process_opaque_data_supported_version_data(
        spdm_context, spdm_test_context->test_buffer_size,
        (uint8_t *)spdm_test_context->test_buffer);

}


void libspdm_test_process_opaque_data_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;


    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    libspdm_process_opaque_data_supported_version_data(
        spdm_context, spdm_test_context->test_buffer_size,
        (uint8_t *)spdm_test_context->test_buffer);

}


libspdm_test_context_t m_spdm_process_opaque_data_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_spdm_process_opaque_data_test_context);

    m_spdm_process_opaque_data_test_context.test_buffer = test_buffer;
    m_spdm_process_opaque_data_test_context.test_buffer_size =
        test_buffer_size;

    /* Success Case*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_process_opaque_data_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Success Case*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_process_opaque_data_case2(&State);
    libspdm_unit_test_group_teardown(&State);
}
