/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_transport_mctp_lib.h"
#include "industry_standard/mctp.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

void libspdm_test_transport_mctp_encode_message(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t transport_message_size;
    uint8_t *transport_message;
    bool is_app_message;
    bool is_requester;
    size_t record_header_max_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    is_requester = spdm_test_context->is_requester;
    is_app_message = false;

    /* limit the encoding buffer to avoid assert, because the input buffer is controlled by the the libspdm consumer. */
    record_header_max_size = sizeof(mctp_message_header_t) +
                             sizeof(spdm_secured_message_a_data_header1_t) +
                             2 + /* MCTP_SEQUENCE_NUMBER_COUNT */
                             sizeof(spdm_secured_message_a_data_header2_t) +
                             sizeof(spdm_secured_message_cipher_header_t) +
                             32; /* MCTP_MAX_RANDOM_NUMBER_COUNT */
    LIBSPDM_ASSERT(spdm_test_context->test_buffer_size > record_header_max_size);

    transport_message_size = spdm_test_context->test_buffer_size;
    transport_message = spdm_test_context->test_buffer;

    libspdm_transport_mctp_encode_message(spdm_context, NULL, is_app_message, is_requester,
                                          spdm_test_context->test_buffer_size - record_header_max_size,
                                          (uint8_t *)spdm_test_context->test_buffer + record_header_max_size,
                                          &transport_message_size,
                                          (void **)&transport_message);

}

libspdm_test_context_t m_libspdm_transport_mctp_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;
    size_t record_header_max_size;
    size_t aead_tag_max_size;
    size_t buffer_size;

    libspdm_setup_test_context(&m_libspdm_transport_mctp_test_context);

    /* limit the encoding buffer to avoid assert, because the input buffer is controlled by the the libspdm consumer. */
    record_header_max_size = sizeof(mctp_message_header_t) +
                             sizeof(spdm_secured_message_a_data_header1_t) +
                             2 + /* MCTP_SEQUENCE_NUMBER_COUNT */
                             sizeof(spdm_secured_message_a_data_header2_t) +
                             sizeof(spdm_secured_message_cipher_header_t) +
                             32; /* MCTP_MAX_RANDOM_NUMBER_COUNT */
    aead_tag_max_size = LIBSPDM_MAX_AEAD_TAG_SIZE;
    buffer_size = test_buffer_size;

    if (buffer_size < record_header_max_size + aead_tag_max_size) {
        /* buffer too small */
        return;
    }

    m_libspdm_transport_mctp_test_context.test_buffer = test_buffer;
    m_libspdm_transport_mctp_test_context.test_buffer_size = buffer_size;

    libspdm_unit_test_group_setup(&State);

    libspdm_test_transport_mctp_encode_message(&State);

    libspdm_unit_test_group_teardown(&State);
}
