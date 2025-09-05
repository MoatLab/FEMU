/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP

static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_TH_BUFFER_SIZE];
static size_t m_libspdm_local_buffer_size;

static libspdm_th_managed_buffer_t th_curr;

uint8_t temp_buf[LIBSPDM_RECEIVER_BUFFER_SIZE];

size_t libspdm_test_get_psk_exchange_request_size(const void *spdm_context, const void *buffer,
                                                  size_t buffer_size)
{
    const spdm_psk_exchange_request_t *spdm_request;
    size_t message_size;

    spdm_request = buffer;
    message_size = sizeof(spdm_message_header_t);
    if (buffer_size < message_size) {
        return buffer_size;
    }

    if (spdm_request->header.request_response_code != SPDM_PSK_EXCHANGE) {
        return buffer_size;
    }

    message_size = sizeof(spdm_psk_exchange_request_t);
    if (buffer_size < message_size) {
        return buffer_size;
    }

    message_size +=
        spdm_request->psk_hint_length + spdm_request->context_length + spdm_request->opaque_length;
    if (buffer_size < message_size) {
        return buffer_size;
    }

    /* Good message, return actual size*/
    return message_size;
}

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

libspdm_return_t libspdm_device_send_message(void *spdm_context, size_t request_size,
                                             const void *request, uint64_t timeout)
{
    size_t header_size;
    size_t message_size;

    header_size = sizeof(libspdm_test_message_header_t);
    m_libspdm_local_buffer_size = 0;
    message_size = libspdm_test_get_psk_exchange_request_size(
        spdm_context, (const uint8_t *)request + header_size, request_size - header_size);
    libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                     (const uint8_t *)request + header_size, message_size);
    m_libspdm_local_buffer_size += message_size;
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_device_receive_message(void *spdm_context, size_t *response_size,
                                                void **response, uint64_t timeout)
{
    spdm_psk_exchange_response_t *spdm_response;
    libspdm_test_context_t *spdm_test_context;
    size_t spdm_response_size;
    size_t test_message_header_size;
    uint32_t hash_size;
    uint32_t hmac_size;
    uint8_t *ptr;
    size_t opaque_psk_exchange_rsp_size;
    void *data;
    size_t data_size;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t bin_str2[128];
    size_t bin_str2_size;
    uint8_t bin_str7[128];
    size_t bin_str7_size;
    uint8_t response_handshake_secret[LIBSPDM_MAX_HASH_SIZE];
    uint8_t response_finished_key[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = libspdm_get_test_context();
    test_message_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
    spdm_response = (void *)((uint8_t *)temp_buf + test_message_header_size);
    spdm_response_size = spdm_test_context->test_buffer_size;
    if (spdm_response_size > sizeof(temp_buf) - test_message_header_size - LIBSPDM_TEST_ALIGNMENT) {
        spdm_response_size = sizeof(temp_buf) - test_message_header_size - LIBSPDM_TEST_ALIGNMENT;
    }
    libspdm_copy_mem((uint8_t *)temp_buf + test_message_header_size,
                     sizeof(temp_buf) - test_message_header_size,
                     (uint8_t *)spdm_test_context->test_buffer,
                     spdm_response_size);

    ((libspdm_context_t *)spdm_context)->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    ((libspdm_context_t *)spdm_context)->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    ((libspdm_context_t *)spdm_context)->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    ((libspdm_context_t *)spdm_context)->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
    opaque_psk_exchange_rsp_size =
        libspdm_get_opaque_data_version_selection_data_size(spdm_context);

    ptr = (void *)(spdm_response + 1);
    libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
    libspdm_build_opaque_data_version_selection_data(spdm_context, &opaque_psk_exchange_rsp_size,
                                                     ptr);
    ptr += opaque_psk_exchange_rsp_size;
    libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                     sizeof(m_libspdm_local_buffer) -
                     (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] - m_libspdm_local_buffer),
                     spdm_response, (size_t)ptr - (size_t)spdm_response);
    m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                   m_libspdm_local_buffer_size));
    libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    NULL, NULL);
    cert_buffer = (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
    cert_buffer_size = data_size - (sizeof(spdm_cert_chain_t) + hash_size);
    libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size, cert_buffer_hash);
    /* transcript.message_a size is 0*/
    libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer, m_libspdm_local_buffer_size);
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    free(data);
    bin_str2_size = sizeof(bin_str2);
    libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                       SPDM_BIN_STR_2_LABEL, sizeof(SPDM_BIN_STR_2_LABEL) - 1, hash_data,
                       (uint16_t)hash_size, hash_size, bin_str2, &bin_str2_size);
    libspdm_psk_handshake_secret_hkdf_expand(
        spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
            m_libspdm_use_hash_algo,
            (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
            bin_str2, bin_str2_size,
            response_handshake_secret, hash_size);
    bin_str7_size = sizeof(bin_str7);
    libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                       SPDM_BIN_STR_7_LABEL, sizeof(SPDM_BIN_STR_7_LABEL) - 1, NULL,
                       (uint16_t)hash_size, hash_size, bin_str7, &bin_str7_size);
    libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret, hash_size, bin_str7,
                        bin_str7_size, response_finished_key, hash_size);
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     response_finished_key, hash_size, ptr);
    ptr += hmac_size;

    libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                          spdm_response_size,
                                          spdm_response, response_size, response);

    return LIBSPDM_STATUS_SUCCESS;
}

void libspdm_test_requester_psk_exchange_case1(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.secured_message_version =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    heartbeat_period = 0;
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_send_receive_psk_exchange(spdm_context,
                                               LIBSPDM_TEST_PSK_HINT_STRING,
                                               sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
                                               SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                               0, &session_id, &heartbeat_period, measurement_hash);
    if (status == LIBSPDM_STATUS_SUCCESS) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}

void libspdm_test_requester_psk_exchange_case2(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t responder_opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    size_t responder_opaque_data_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.secured_message_version =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    heartbeat_period = 0;
    responder_opaque_data_size = sizeof(responder_opaque_data);
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));

    status = libspdm_send_receive_psk_exchange_ex(spdm_context,
                                                  LIBSPDM_TEST_PSK_HINT_STRING,
                                                  sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
                                                  SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                                  0, &session_id, &heartbeat_period,
                                                  measurement_hash, NULL, 0,
                                                  NULL, NULL, NULL, NULL, NULL, 0,
                                                  responder_opaque_data,
                                                  &responder_opaque_data_size);
    if (status == LIBSPDM_STATUS_SUCCESS) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}

void libspdm_test_requester_psk_exchange_case3(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.secured_message_version =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    heartbeat_period = 0;
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_send_receive_psk_exchange(spdm_context,
                                               LIBSPDM_TEST_PSK_HINT_STRING,
                                               sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
                                               SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                               0, &session_id, &heartbeat_period, measurement_hash);
    if (status == LIBSPDM_STATUS_SUCCESS) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
    free(data);
}

void libspdm_test_requester_psk_exchange_ex_case1(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t responder_opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    size_t responder_opaque_data_size;

    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.secured_message_version =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    heartbeat_period = 0;
    responder_opaque_data_size = sizeof(responder_opaque_data);
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));

    status = libspdm_send_receive_psk_exchange_ex(spdm_context,
                                                  LIBSPDM_TEST_PSK_HINT_STRING,
                                                  sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
                                                  SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0,
                                                  &session_id, &heartbeat_period, measurement_hash, NULL, 0,
                                                  NULL, NULL, NULL, NULL,
                                                  NULL, 0,
                                                  responder_opaque_data,
                                                  &responder_opaque_data_size);
    if (status == LIBSPDM_STATUS_SUCCESS) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }

    free(data);
}


libspdm_test_context_t m_libspdm_requester_psk_exchange_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_psk_exchange_test_context);

    m_libspdm_requester_psk_exchange_test_context.test_buffer = (void *)test_buffer;
    m_libspdm_requester_psk_exchange_test_context.test_buffer_size = test_buffer_size;

    /* Successful response*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_psk_exchange_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_psk_exchange_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_psk_exchange_ex_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /*  PSK_CAP and context check*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_psk_exchange_case3(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size){

}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/
