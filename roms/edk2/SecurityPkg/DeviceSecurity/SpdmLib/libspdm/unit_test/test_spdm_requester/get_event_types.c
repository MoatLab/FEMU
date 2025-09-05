/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_EVENT_RECIPIENT_SUPPORT

static uint8_t m_supported_event_groups_list[0x1000];
static uint8_t m_spdm_request_buffer[0x1000];

static const uint32_t m_session_id = 0xffffffff;

#pragma pack(1)
typedef struct {
    uint8_t id;
    uint8_t vendor_id_len;
} event_group_id_0byte_t;

typedef struct {
    uint8_t id;
    uint8_t vendor_id_len;
    uint16_t vendor_id;
} event_group_id_2byte_t;

typedef struct {
    uint16_t event_type_count;
    uint16_t event_group_ver;
    uint32_t attributes;
    /* uint8_t event_type_list[] */
} event_group_t;

typedef struct {
    uint16_t event_type_id;
    uint16_t reserved;
} event_type_t;
#pragma pack()

static void set_standard_state(libspdm_context_t *spdm_context, uint32_t *session_id)
{
    libspdm_session_info_t *session_info;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    *session_id = m_session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, *session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context, LIBSPDM_SESSION_STATE_ESTABLISHED);
}

static void generate_dmtf_event_group(void *buffer, uint8_t *total_bytes,
                                      bool inc_event_lost, bool inc_meas_changed,
                                      bool inc_meas_pre_update, bool inc_cert_changed)
{
    uint8_t *ptr;
    uint16_t event_type_count;

    event_type_count = 0;

    if (inc_event_lost) {
        event_type_count++;
    }
    if (inc_meas_changed) {
        event_type_count++;
    }
    if (inc_meas_pre_update) {
        event_type_count++;
    }
    if (inc_cert_changed) {
        event_type_count++;
    }

    ptr = buffer;
    *total_bytes = 0;

    ((event_group_id_0byte_t *)ptr)->id = SPDM_REGISTRY_ID_DMTF;
    ((event_group_id_0byte_t *)ptr)->vendor_id_len = 0;

    ptr += sizeof(event_group_id_0byte_t);
    *total_bytes += (uint8_t)sizeof(event_group_id_0byte_t);

    ((event_group_t *)ptr)->event_type_count = event_type_count;
    ((event_group_t *)ptr)->event_group_ver = 1;
    ((event_group_t *)ptr)->attributes = 0;

    ptr += sizeof(event_group_t);
    *total_bytes += (uint8_t)sizeof(event_group_t);

    if (inc_event_lost) {
        ((event_type_t *)ptr)->event_type_id = SPDM_DMTF_EVENT_TYPE_EVENT_LOST;
        ((event_type_t *)ptr)->reserved = 0;
        ptr += sizeof(event_type_t);
        *total_bytes += (uint8_t)sizeof(event_type_t);
    }
    if (inc_meas_changed) {
        ((event_type_t *)ptr)->event_type_id = SPDM_DMTF_EVENT_TYPE_MEASUREMENT_CHANGED;
        ((event_type_t *)ptr)->reserved = 0;
        ptr += sizeof(event_type_t);
        *total_bytes += (uint8_t)sizeof(event_type_t);
    }
    if (inc_meas_pre_update) {
        ((event_type_t *)ptr)->event_type_id = SPDM_DMTF_EVENT_TYPE_MEASUREMENT_PRE_UPDATE;
        ((event_type_t *)ptr)->reserved = 0;
        ptr += sizeof(event_type_t);
        *total_bytes += (uint8_t)sizeof(event_type_t);
    }
    if (inc_cert_changed) {
        ((event_type_t *)ptr)->event_type_id = SPDM_DMTF_EVENT_TYPE_CERTIFICATE_CHANGED;
        ((event_type_t *)ptr)->reserved = 0;
        *total_bytes += (uint8_t)sizeof(event_type_t);
    }
}

static libspdm_return_t send_message(
    void *spdm_context, size_t request_size, const void *request, uint64_t timeout)
{
    libspdm_return_t status;
    uint32_t session_id;
    uint32_t *message_session_id;
    spdm_get_supported_event_types_request_t *spdm_message;
    bool is_app_message;
    void *spdm_request_buffer;
    size_t spdm_request_size;
    libspdm_session_info_t *session_info;
    uint8_t request_buffer[0x1000];

    /* Workaround request being const. */
    libspdm_copy_mem(request_buffer, sizeof(request_buffer), request, request_size);

    session_id = m_session_id;
    session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
    LIBSPDM_ASSERT(session_info != NULL);

    ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->
    application_secret.request_data_sequence_number--;

    spdm_request_buffer = m_spdm_request_buffer;
    spdm_request_size = sizeof(m_spdm_request_buffer);

    status = libspdm_transport_test_decode_message(spdm_context, &message_session_id,
                                                   &is_app_message, true,
                                                   request_size, request_buffer,
                                                   &spdm_request_size, &spdm_request_buffer);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(sizeof(spdm_get_supported_event_types_request_t), spdm_request_size);

    spdm_message = spdm_request_buffer;

    assert_int_equal(spdm_message->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_message->header.request_response_code, SPDM_GET_SUPPORTED_EVENT_TYPES);
    assert_int_equal(spdm_message->header.param1, 0);
    assert_int_equal(spdm_message->header.param2, 0);

    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t receive_message(
    void *spdm_context, size_t *response_size, void **response, uint64_t timeout)
{
    spdm_supported_event_types_response_t *spdm_response;
    size_t spdm_response_size;
    size_t transport_header_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;
    uint8_t *scratch_buffer;
    size_t scratch_buffer_size;
    uint8_t event_group_total_bytes;
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 1: {
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        session_id = m_session_id;

        session_info = libspdm_get_session_info_via_session_id(spdm_context, session_id);
        LIBSPDM_ASSERT((session_info != NULL));

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_SUPPORTED_EVENT_TYPES;
        spdm_response->header.param1 = 1;
        spdm_response->header.param2 = 0;

        generate_dmtf_event_group(spdm_response + 1, &event_group_total_bytes,
                                  true, true, true, true);
        spdm_response->supported_event_groups_list_len = event_group_total_bytes;

        spdm_response_size = sizeof(spdm_supported_event_types_response_t) +
                             event_group_total_bytes;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer(spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        libspdm_copy_mem(scratch_buffer + transport_header_size,
                         scratch_buffer_size - transport_header_size,
                         spdm_response, spdm_response_size);

        spdm_response = (void *)(scratch_buffer + transport_header_size);

        libspdm_transport_test_encode_message(spdm_context, &session_id,
                                              false, false, spdm_response_size,
                                              spdm_response, response_size, response);

        /* Workaround: Use single context to encode message and then decode message. */
        ((libspdm_secured_message_context_t *)(session_info->secured_message_context))->
        application_secret.response_data_sequence_number--;
    }
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

/**
 * Test 1: Successful response to get supported event types.
 * Expected Behavior: Returns LIBSPDM_STATUS_SUCCESS with the expected values.
 **/
static void libspdm_test_requester_get_event_types_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t event_group_count;
    uint32_t supported_event_groups_list_len = sizeof(m_supported_event_groups_list);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 1;

    set_standard_state(spdm_context, &session_id);

    status = libspdm_get_event_types(spdm_context, session_id, &event_group_count,
                                     &supported_event_groups_list_len,
                                     (void *)&m_supported_event_groups_list);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(event_group_count, 1);
}

static libspdm_test_context_t m_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    send_message,
    receive_message,
};

int libspdm_requester_get_event_types_test_main(void)
{
    const struct CMUnitTest spdm_requester_get_event_types_tests[] = {
        cmocka_unit_test(libspdm_test_requester_get_event_types_case1)
    };

    libspdm_setup_test_context(&m_test_context);

    return cmocka_run_group_tests(spdm_requester_get_event_types_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_EVENT_RECIPIENT_SUPPORT */
