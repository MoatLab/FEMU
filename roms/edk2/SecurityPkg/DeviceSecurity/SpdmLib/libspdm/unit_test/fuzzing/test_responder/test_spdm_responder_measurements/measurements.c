/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP

#define LIBSPDM_TEST_PSK_HINT_STRING "TestPskHint"

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

extern size_t libspdm_secret_lib_meas_opaque_data_size;

void libspdm_test_responder_measurements_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_get_measurements_request_t *spdm_request;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;

    response_size = sizeof(response);
    libspdm_get_response_measurements(spdm_context, spdm_test_context->test_buffer_size,
                                      spdm_test_context->test_buffer, &response_size, response);
    spdm_request = (spdm_get_measurements_request_t * )spdm_test_context->test_buffer;
    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) == 0) {
        libspdm_reset_message_m(spdm_context, NULL);
    }
}

void libspdm_test_responder_measurements_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_session_info_t *session_info;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint32_t session_id;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_get_measurements_request_t *spdm_request;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_secret_lib_meas_opaque_data_size = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);

    response_size = sizeof(response);

    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_get_response_measurements(spdm_context, spdm_test_context->test_buffer_size,
                                      spdm_test_context->test_buffer, &response_size, response);
    spdm_request = (spdm_get_measurements_request_t * )spdm_test_context->test_buffer;
    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) == 0) {
        libspdm_reset_message_m(spdm_context, spdm_context->session_info);
    }
}

void libspdm_test_responder_measurements_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    void *data;
    size_t data_size;
    spdm_get_measurements_request_t *spdm_request;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    for (int i = 1; i < SPDM_MAX_SLOT_COUNT; i++) {
        spdm_context->local_context.local_cert_chain_provision_size[i] = data_size;
        spdm_context->local_context.local_cert_chain_provision[i] = data;
    }

    response_size = sizeof(response);

    libspdm_get_response_measurements(spdm_context, spdm_test_context->test_buffer_size,
                                      spdm_test_context->test_buffer, &response_size, response);
    free(data);
    spdm_request = (spdm_get_measurements_request_t * )spdm_test_context->test_buffer;
    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) == 0) {
        libspdm_reset_message_m(spdm_context, NULL);
    }
}

void libspdm_test_responder_measurements_case4(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_session_info_t *session_info;
    libspdm_context_t *spdm_context;
    size_t response_size;
    size_t data_size;
    void *data;
    uint32_t session_id;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_get_measurements_request_t *spdm_request;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    for (int i = 1; i < SPDM_MAX_SLOT_COUNT; i++) {
        spdm_context->local_context.local_cert_chain_provision_size[i] = data_size;
        spdm_context->local_context.local_cert_chain_provision[i] = data;
    }

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);

    response_size = sizeof(response);

    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);
    libspdm_get_response_measurements(spdm_context, spdm_test_context->test_buffer_size,
                                      spdm_test_context->test_buffer, &response_size, response);
    free(data);
    spdm_request = (spdm_get_measurements_request_t * )spdm_test_context->test_buffer;
    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) == 0) {
        libspdm_reset_message_m(spdm_context, spdm_context->session_info);
    }
}

void libspdm_test_responder_measurements_case5(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_get_measurements_request_t *spdm_request;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

    libspdm_reset_message_m(spdm_context, NULL);
    libspdm_secret_lib_meas_opaque_data_size = 0;

    response_size = sizeof(response);
    libspdm_get_response_measurements(spdm_context, spdm_test_context->test_buffer_size,
                                      spdm_test_context->test_buffer, &response_size, response);
    spdm_request = (spdm_get_measurements_request_t * )spdm_test_context->test_buffer;
    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) == 0) {
        libspdm_reset_message_m(spdm_context, NULL);
    }
}

libspdm_test_context_t m_libspdm_responder_measurements_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;
    spdm_message_header_t *spdm_request_header;
    libspdm_setup_test_context(&m_libspdm_responder_measurements_test_context);

    spdm_request_header = (spdm_message_header_t*)test_buffer;

    if (spdm_request_header->request_response_code != SPDM_GET_MEASUREMENTS) {
        spdm_request_header->request_response_code = SPDM_GET_MEASUREMENTS;
    }

    m_libspdm_responder_measurements_test_context.test_buffer = test_buffer;
    m_libspdm_responder_measurements_test_context.test_buffer_size = test_buffer_size;

    /* Success Case*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_measurements_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /*last_spdm_request_session_id_valid: true*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_measurements_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    /*Select version based on GET_VERSION/VERSION support*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_measurements_case3(&State);
    libspdm_unit_test_group_teardown(&State);

    /*Select version based on GET_VERSION/VERSION support
     * last_spdm_request_session_id_valid: true*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_measurements_case4(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Successful response V1.2 to get one measurement with signature and without opqaue data*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_responder_measurements_case5(&State);
    libspdm_unit_test_group_teardown(&State);

}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/
