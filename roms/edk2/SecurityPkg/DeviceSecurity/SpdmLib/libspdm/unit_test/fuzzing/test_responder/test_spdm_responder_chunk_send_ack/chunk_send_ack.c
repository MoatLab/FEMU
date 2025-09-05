/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

void libspdm_test_responder_chunk_send_ack_setup_algo_state(libspdm_context_t *spdm_context)
{
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->local_context.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->local_context.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->local_context.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_reset_message_a(spdm_context);
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
}

void libspdm_test_responder_chunk_send_ack_case1(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    size_t request_size;
    size_t response_size;

    uint8_t *request;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];

    spdm_chunk_send_request_t *chunk_send_request;

    uint16_t chunk_num;
    size_t bytes_sent;
    size_t bytes_total;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    libspdm_test_responder_chunk_send_ack_setup_algo_state(spdm_context);

    chunk_num = 0;
    bytes_sent = 0;
    bytes_total = spdm_test_context->test_buffer_size;
    /* All chunk send message sequences, including chunk_send_header and spdm_chunk. */
    request = (uint8_t *)spdm_test_context->test_buffer;

    do
    {
        if (chunk_num == 0) {
            /* (uint32_t)LargeMessageSize , This field shall only be present when ChunkSeqNo
             * is zero and shall have a non-zero value.
             * The bytes_total should not be less than the minimum effective size.*/
            if(bytes_total < sizeof(spdm_chunk_send_request_t) + sizeof(uint32_t)) {
                break;
            }
            chunk_send_request = (spdm_chunk_send_request_t *)request;

            request_size = sizeof(spdm_chunk_send_request_t) + sizeof(uint32_t) +
                           chunk_send_request->chunk_size;

            /* Remaining space should meet the chunk_size. */
            if(bytes_total - sizeof(spdm_chunk_send_request_t) - sizeof(uint32_t) <
               chunk_send_request->chunk_size) {
                break;
            }

            spdm_context->local_context.capability.data_transfer_size =
                chunk_send_request->chunk_size + sizeof(spdm_chunk_send_request_t) +
                sizeof(uint32_t);
        } else {
            /* The remaining number of bytes should not be less than the minimum effective size*/
            if(bytes_total - bytes_sent < sizeof(spdm_chunk_send_request_t)) {
                break;
            }
            chunk_send_request = (spdm_chunk_send_request_t *)request;

            request_size = sizeof(spdm_chunk_send_request_t) + chunk_send_request->chunk_size;

            /* Remaining space should meet the chunk_size. */
            if(bytes_total - bytes_sent - sizeof(spdm_chunk_send_request_t) <
               chunk_send_request->chunk_size) {
                break;
            }

            spdm_context->local_context.capability.data_transfer_size =
                chunk_send_request->chunk_size + sizeof(spdm_chunk_send_request_t);

            if (bytes_total - bytes_sent == chunk_send_request->chunk_size) {
                chunk_send_request->header.param1 = SPDM_CHUNK_SEND_REQUEST_ATTRIBUTE_LAST_CHUNK;
            }
        }


        response_size = sizeof(response);
        status = libspdm_get_response_chunk_send(
            spdm_context,
            request_size, request,
            &response_size, response);

        request += request_size;
        bytes_sent += request_size;
        chunk_num++;

        if (status != LIBSPDM_STATUS_SUCCESS) {
            break;
        }
    }while (true);
}

libspdm_test_context_t m_libspdm_responder_chunk_send_ack_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_responder_chunk_send_ack_test_context);

    m_libspdm_responder_chunk_send_ack_test_context.test_buffer = test_buffer;
    m_libspdm_responder_chunk_send_ack_test_context.test_buffer_size =
        test_buffer_size;

    /* Success Case*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_chunk_send_ack_case1(&State);
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
