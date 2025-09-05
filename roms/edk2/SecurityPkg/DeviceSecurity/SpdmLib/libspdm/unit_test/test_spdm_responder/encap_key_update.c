/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/
#include "spdm_unit_test.h"
#include "internal/libspdm_secured_message_lib.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP

static void libspdm_set_standard_key_update_test_state(libspdm_context_t *spdm_context,
                                                       uint32_t *session_id)
{
    libspdm_session_info_t *session_info;

    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;

    spdm_context->transcript.message_a.buffer_size = 0;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    *session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = *session_id;
    spdm_context->last_spdm_request_session_id = *session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, *session_id, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
}

/**
 * Test 1: receiving a correct UPDATE_KEY_ACK message for updating
 * only the request data key.
 * Expected behavior: client returns a Status of RETURN_SUCCESS,Communication needs to continue.
 **/
void libspdm_test_responder_encap_key_update_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x1;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    spdm_context->encap_context.last_encap_request_header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_context->encap_context.last_encap_request_header.request_response_code =
        SPDM_KEY_UPDATE_ACK;
    spdm_context->encap_context.last_encap_request_header.param1 =
        SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
    spdm_context->encap_context.last_encap_request_header.param2 = 0;

    spdm_key_update_response_t spdm_response;
    size_t spdm_response_size = sizeof(spdm_key_update_response_t);

    spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response.header.request_response_code = SPDM_KEY_UPDATE_ACK;
    spdm_response.header.param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
    spdm_response.header.param2 = 0;

    status = libspdm_process_encap_response_key_update(spdm_context, spdm_response_size,
                                                       &spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(need_continue, true);
}

/**
 * Test 2: receiving a correct UPDATE_KEY_ACK message for updating
 * only the request data key.
 * Expected behavior: client returns a Status of RETURN_SUCCESS,Communication needs to continue.
 **/
void libspdm_test_responder_encap_key_update_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x2;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    spdm_context->encap_context.last_encap_request_header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_context->encap_context.last_encap_request_header.request_response_code =
        SPDM_KEY_UPDATE_ACK;
    spdm_context->encap_context.last_encap_request_header.param1 =
        SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
    spdm_context->encap_context.last_encap_request_header.param2 = 0;

    spdm_key_update_response_t spdm_response;
    size_t spdm_response_size = sizeof(spdm_key_update_response_t);

    spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response.header.request_response_code = SPDM_KEY_UPDATE_ACK;
    spdm_response.header.param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
    spdm_response.header.param2 = 0;

    status = libspdm_process_encap_response_key_update(spdm_context, spdm_response_size,
                                                       &spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(need_continue, false);
}
/**
 * Test 3: receiving a correct UPDATE_KEY_ACK message for updating
 * only the request data key. last_spdm_request_session_id_valid invalid
 * Expected behavior: client returns a Status of RETURN_UNSUPPORTED,No further communication is required.
 **/
void libspdm_test_responder_encap_key_update_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x3;
    spdm_context->last_spdm_request_session_id_valid = false;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    spdm_key_update_response_t spdm_response;
    size_t spdm_response_size = sizeof(spdm_key_update_response_t);

    spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response.header.request_response_code =    SPDM_KEY_UPDATE_ACK;
    spdm_response.header.param1 = 0;
    spdm_response.header.param2 = 0;

    status = libspdm_process_encap_response_key_update(spdm_context, spdm_response_size,
                                                       &spdm_response, &need_continue);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

/**
 * Test 4: receives an ERROR message indicating InvalidParameters when updating key.
 * Expected behavior: client returns a Status of RETURN_SECURITY_VIOLATION, and
 * no keys should be updated.
 **/
void libspdm_test_responder_encap_key_update_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x4;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    spdm_key_update_response_t spdm_response;
    size_t spdm_response_size = sizeof(spdm_key_update_response_t);

    spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response.header.request_response_code = SPDM_ERROR;
    spdm_response.header.param1 = SPDM_ERROR_CODE_DECRYPT_ERROR;
    spdm_response.header.param2 = 0;

    status = libspdm_process_encap_response_key_update(spdm_context, spdm_response_size,
                                                       &spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_SESSION_MSG_ERROR);
}

/**
 * Test 5: spdm_response message is correct but does not match last_encap_request_header error message
 * Expected behavior: client returns a Status of RETURN_DEVICE_ERROR
 **/
void libspdm_test_responder_encap_key_update_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    bool need_continue;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    spdm_test_context->case_id = 0x5;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_standard_key_update_test_state(
        spdm_context, &session_id);

    spdm_context->encap_context.last_encap_request_header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_context->encap_context.last_encap_request_header.request_response_code =
        SPDM_KEY_UPDATE_ACK;
    spdm_context->encap_context.last_encap_request_header.param1 = SPDM_ERROR_CODE_DECRYPT_ERROR;
    spdm_context->encap_context.last_encap_request_header.param2 = 0;

    spdm_key_update_response_t spdm_response;
    size_t spdm_response_size = sizeof(spdm_key_update_response_t);

    spdm_response.header.spdm_version = SPDM_MESSAGE_VERSION_11;
    spdm_response.header.request_response_code = SPDM_KEY_UPDATE_ACK;
    spdm_response.header.param1 = 0;
    spdm_response.header.param2 = 0;

    status = libspdm_process_encap_response_key_update(spdm_context, spdm_response_size,
                                                       &spdm_response, &need_continue);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

libspdm_test_context_t m_libspdm_responder_encap_key_update_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_encap_key_update_test_main(void)
{
    const struct CMUnitTest spdm_responder_key_update_tests[] = {
        /* Successful response*/
        cmocka_unit_test(libspdm_test_responder_encap_key_update_case1),
        /* Successful response,No further communication is required.*/
        cmocka_unit_test(libspdm_test_responder_encap_key_update_case2),
        /* last_spdm_request_session_id_valid : false */
        cmocka_unit_test(libspdm_test_responder_encap_key_update_case3),
        /* Error response: RETURN_SECURITY_VIOLATION */
        cmocka_unit_test(libspdm_test_responder_encap_key_update_case4),
        /* Error response: RETURN_DEVICE_ERROR */
        cmocka_unit_test(libspdm_test_responder_encap_key_update_case5),
    };

    libspdm_setup_test_context(&m_libspdm_responder_encap_key_update_test_context);

    return cmocka_run_group_tests(spdm_responder_key_update_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP*/
