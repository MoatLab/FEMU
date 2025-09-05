/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP

#define CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE (44)

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

void libspdm_test_responder_chunk_get_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_chunk_get_request_t *spdm_request;

    void* scratch_buffer;
    size_t scratch_buffer_size;
    uint32_t data_transfer_size;
    uint32_t first_chunk_size;
    uint32_t second_chunk_size;
    uint32_t third_chunk_size;
    uint32_t total_chunk_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.capability.data_transfer_size =
        CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;

    data_transfer_size = CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.capability.data_transfer_size = data_transfer_size;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);

    scratch_buffer = (uint8_t*)scratch_buffer +
                     libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    scratch_buffer_size = scratch_buffer_size -
                          libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    libspdm_zero_mem(scratch_buffer, scratch_buffer_size);

    first_chunk_size = data_transfer_size -
                       (sizeof(spdm_chunk_response_response_t) + sizeof(uint32_t));
    second_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    third_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    total_chunk_size = first_chunk_size + second_chunk_size + third_chunk_size;

    libspdm_set_mem(scratch_buffer, first_chunk_size, 1);
    libspdm_set_mem((uint8_t*)scratch_buffer + first_chunk_size, second_chunk_size, 2);
    libspdm_set_mem((uint8_t*) scratch_buffer + first_chunk_size + second_chunk_size,
                    third_chunk_size, 3);

    spdm_request = (spdm_chunk_get_request_t *)spdm_test_context->test_buffer;

    spdm_context->chunk_context.get.chunk_in_use = true;
    spdm_context->chunk_context.get.chunk_handle = 0;
    spdm_context->chunk_context.get.chunk_seq_no = spdm_request->chunk_seq_no;
    spdm_context->chunk_context.get.large_message = scratch_buffer;
    spdm_context->chunk_context.get.large_message_size = total_chunk_size;
    spdm_context->chunk_context.get.chunk_bytes_transferred = 0;

    response_size = sizeof(response);
    libspdm_get_response_chunk_get(spdm_context,
                                   spdm_test_context->test_buffer_size,
                                   spdm_test_context->test_buffer,
                                   &response_size, response);
}

void libspdm_test_responder_chunk_get_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    void* scratch_buffer;
    size_t scratch_buffer_size;
    uint32_t data_transfer_size;
    uint32_t first_chunk_size;
    uint32_t second_chunk_size;
    uint32_t third_chunk_size;
    uint32_t total_chunk_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.capability.data_transfer_size =
        CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;

    data_transfer_size = CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.capability.data_transfer_size = data_transfer_size;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);

    scratch_buffer = (uint8_t*)scratch_buffer +
                     libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    scratch_buffer_size = scratch_buffer_size -
                          libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    libspdm_zero_mem(scratch_buffer, scratch_buffer_size);

    first_chunk_size = data_transfer_size -
                       (sizeof(spdm_chunk_response_response_t) + sizeof(uint32_t));
    second_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    third_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    total_chunk_size = first_chunk_size + second_chunk_size + third_chunk_size;

    libspdm_set_mem(scratch_buffer, first_chunk_size, 1);
    libspdm_set_mem((uint8_t*)scratch_buffer + first_chunk_size, second_chunk_size, 2);
    libspdm_set_mem((uint8_t*) scratch_buffer + first_chunk_size + second_chunk_size,
                    third_chunk_size, 3);

    spdm_context->chunk_context.get.chunk_in_use = true;
    spdm_context->chunk_context.get.chunk_handle = 0;
    spdm_context->chunk_context.get.chunk_seq_no = 0;
    spdm_context->chunk_context.get.large_message = scratch_buffer;
    spdm_context->chunk_context.get.large_message_size = total_chunk_size;
    spdm_context->chunk_context.get.chunk_bytes_transferred = 0;

    response_size = sizeof(response);
    libspdm_get_response_chunk_get(spdm_context,
                                   spdm_test_context->test_buffer_size,
                                   spdm_test_context->test_buffer,
                                   &response_size, response);
}

void libspdm_test_responder_chunk_get_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    void* scratch_buffer;
    size_t scratch_buffer_size;
    uint32_t data_transfer_size;
    uint32_t first_chunk_size;
    uint32_t second_chunk_size;
    uint32_t third_chunk_size;
    uint32_t total_chunk_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.capability.data_transfer_size =
        CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;

    data_transfer_size = CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.capability.data_transfer_size = data_transfer_size;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);

    scratch_buffer = (uint8_t*)scratch_buffer +
                     libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    scratch_buffer_size = scratch_buffer_size -
                          libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    libspdm_zero_mem(scratch_buffer, scratch_buffer_size);

    first_chunk_size = data_transfer_size -
                       (sizeof(spdm_chunk_response_response_t) + sizeof(uint32_t));
    second_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    third_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    total_chunk_size = first_chunk_size + second_chunk_size + third_chunk_size;

    libspdm_set_mem(scratch_buffer, first_chunk_size, 1);
    libspdm_set_mem((uint8_t*)scratch_buffer + first_chunk_size, second_chunk_size, 2);
    libspdm_set_mem((uint8_t*) scratch_buffer + first_chunk_size + second_chunk_size,
                    third_chunk_size, 3);

    spdm_context->chunk_context.get.chunk_in_use = true;
    spdm_context->chunk_context.get.chunk_handle = 0;
    spdm_context->chunk_context.get.chunk_seq_no = 0;
    spdm_context->chunk_context.get.large_message = scratch_buffer;
    spdm_context->chunk_context.get.large_message_size = total_chunk_size;
    spdm_context->chunk_context.get.chunk_bytes_transferred = 0;

    response_size = sizeof(response);
    libspdm_get_response_chunk_get(spdm_context,
                                   spdm_test_context->test_buffer_size,
                                   spdm_test_context->test_buffer,
                                   &response_size, response);
}

void libspdm_test_responder_chunk_get_case4(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_chunk_get_request_t *spdm_request;

    void* scratch_buffer;
    size_t scratch_buffer_size;
    uint32_t data_transfer_size;
    uint32_t first_chunk_size;
    uint32_t second_chunk_size;
    uint32_t third_chunk_size;
    uint32_t total_chunk_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.capability.data_transfer_size =
        CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;

    data_transfer_size = CHUNK_GET_RESPONDER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.capability.data_transfer_size = data_transfer_size;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;

    libspdm_get_scratch_buffer(spdm_context, &scratch_buffer, &scratch_buffer_size);

    scratch_buffer = (uint8_t*)scratch_buffer +
                     libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    scratch_buffer_size = scratch_buffer_size -
                          libspdm_get_scratch_buffer_large_message_offset(spdm_context);
    libspdm_zero_mem(scratch_buffer, scratch_buffer_size);

    first_chunk_size = data_transfer_size -
                       (sizeof(spdm_chunk_response_response_t) + sizeof(uint32_t));
    second_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    third_chunk_size = data_transfer_size - sizeof(spdm_chunk_response_response_t);
    total_chunk_size = first_chunk_size + second_chunk_size + third_chunk_size;

    libspdm_set_mem(scratch_buffer, first_chunk_size, 1);
    libspdm_set_mem((uint8_t*)scratch_buffer + first_chunk_size, second_chunk_size, 2);
    libspdm_set_mem((uint8_t*) scratch_buffer + first_chunk_size + second_chunk_size,
                    third_chunk_size, 3);

    spdm_request = (spdm_chunk_get_request_t *)spdm_test_context->test_buffer;

    spdm_context->chunk_context.get.chunk_in_use = true;
    spdm_context->chunk_context.get.chunk_handle = 0;
    spdm_context->chunk_context.get.chunk_seq_no = spdm_request->chunk_seq_no;
    spdm_context->chunk_context.get.large_message = scratch_buffer;
    spdm_context->chunk_context.get.large_message_size = total_chunk_size;
    spdm_context->chunk_context.get.chunk_bytes_transferred = first_chunk_size + second_chunk_size;

    response_size = sizeof(response);
    libspdm_get_response_chunk_get(spdm_context,
                                   spdm_test_context->test_buffer_size,
                                   spdm_test_context->test_buffer,
                                   &response_size, response);
}

libspdm_test_context_t m_libspdm_responder_chunk_get_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_responder_chunk_get_test_context);

    m_libspdm_responder_chunk_get_test_context.test_buffer = test_buffer;
    m_libspdm_responder_chunk_get_test_context.test_buffer_size =
        test_buffer_size;

    /* Successful request of chunk*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_chunk_get_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /*Successful request of first chunk*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_chunk_get_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    /* When request.chunk_seq_no is 0xff. Successful request of chunk */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_chunk_get_case3(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Succesful request of  chunk, where size is exactly max chunk size */
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_chunk_get_case4(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP*/
