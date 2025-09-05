/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_responder_lib.h"

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

void libspdm_test_responder_capabilities_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    libspdm_get_response_capabilities(spdm_context,
                                      spdm_test_context->test_buffer_size,
                                      spdm_test_context->test_buffer,
                                      &response_size, response);
}

void libspdm_test_responder_capabilities_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    libspdm_get_response_capabilities(spdm_context,
                                      spdm_test_context->test_buffer_size,
                                      spdm_test_context->test_buffer,
                                      &response_size, response);
}

void libspdm_test_responder_capabilities_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    libspdm_get_response_capabilities(spdm_context,
                                      spdm_test_context->test_buffer_size,
                                      spdm_test_context->test_buffer,
                                      &response_size, response);
}

libspdm_test_context_t libspdm_test_responder_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;
    spdm_message_header_t *spdm_request_header;
    libspdm_setup_test_context(&libspdm_test_responder_context);

    spdm_request_header = (spdm_message_header_t*)test_buffer;

    if (spdm_request_header->request_response_code != SPDM_GET_CAPABILITIES) {
        spdm_request_header->request_response_code = SPDM_GET_CAPABILITIES;
    }

    libspdm_test_responder_context.test_buffer = test_buffer;
    libspdm_test_responder_context.test_buffer_size = test_buffer_size;

    libspdm_unit_test_group_setup(&State);

    /* Success Case */
    libspdm_test_responder_capabilities_case1(&State);
    /* connection_state Check*/
    libspdm_test_responder_capabilities_case2(&State);
    /* response_state*/
    libspdm_test_responder_capabilities_case3(&State);

    libspdm_unit_test_group_teardown(&State);
}
