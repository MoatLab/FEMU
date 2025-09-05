/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP

extern uint32_t g_supported_event_groups_list_len;
extern uint8_t g_event_group_count;

static void set_standard_state(libspdm_context_t *spdm_context)
{
    libspdm_session_info_t *session_info;
    uint32_t session_id;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

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
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(
        session_info->secured_message_context,
        LIBSPDM_SESSION_STATE_ESTABLISHED);
}

/**
 * Test 1: Successful response to get supported event types.
 * Expected Behavior: Returns LIBSPDM_STATUS_SUCCESS with the expected values.
 **/
static void libspdm_test_responder_supported_event_types_err_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    spdm_get_supported_event_types_request_t spdm_request;
    size_t spdm_request_size = sizeof(spdm_request);
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    size_t response_size = sizeof(response);
    spdm_error_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 1;

    set_standard_state(spdm_context);

    /* Responder is not an event notifier. */
    spdm_context->local_context.capability.flags &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP;

    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_13;
    spdm_request.header.request_response_code = SPDM_GET_SUPPORTED_EVENT_TYPES;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    status = libspdm_get_response_supported_event_types(spdm_context,
                                                        spdm_request_size, &spdm_request,
                                                        &response_size, response);
    spdm_response = (spdm_error_response_t *)response;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, SPDM_GET_SUPPORTED_EVENT_TYPES);
}

int libspdm_responder_supported_event_types_error_test_main(void)
{
    libspdm_test_context_t m_test_context = {
        LIBSPDM_TEST_CONTEXT_VERSION,
        false,
    };

    const struct CMUnitTest spdm_responder_supported_event_types_err_tests[] = {
        cmocka_unit_test(libspdm_test_responder_supported_event_types_err_case1),
    };

    libspdm_setup_test_context(&m_test_context);

    return cmocka_run_group_tests(spdm_responder_supported_event_types_err_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */
