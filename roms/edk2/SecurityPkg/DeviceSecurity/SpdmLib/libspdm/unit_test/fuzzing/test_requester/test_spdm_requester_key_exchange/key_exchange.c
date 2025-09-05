/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_TH_BUFFER_SIZE];
static uint8_t m_libspdm_test_case_id;

static uint8_t m_libspdm_zero_filled_buffer[LIBSPDM_MAX_HASH_SIZE];

static libspdm_th_managed_buffer_t th_curr;

uint8_t temp_buf[LIBSPDM_RECEIVER_BUFFER_SIZE];

size_t libspdm_test_get_key_exchange_request_size(const void *spdm_context, const void *buffer,
                                                  size_t buffer_size)
{
    const spdm_key_exchange_request_t *spdm_request;
    size_t message_size;
    size_t dhe_key_size;
    uint16_t opaque_length;

    spdm_request = buffer;
    message_size = sizeof(spdm_message_header_t);
    if (buffer_size < message_size) {
        return buffer_size;
    }

    if (spdm_request->header.request_response_code != SPDM_KEY_EXCHANGE) {
        return buffer_size;
    }

    message_size = sizeof(spdm_key_exchange_request_t);
    if (buffer_size < message_size) {
        return buffer_size;
    }

    dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
    message_size += dhe_key_size + sizeof(uint16_t);
    if (buffer_size < message_size) {
        return buffer_size;
    }

    opaque_length =
        *(uint16_t *)((size_t)buffer + sizeof(spdm_key_exchange_request_t) + dhe_key_size);
    message_size += opaque_length;
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
    message_size = libspdm_test_get_key_exchange_request_size(
        spdm_context, (const uint8_t *)request + header_size, request_size - header_size);
    libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                     (const uint8_t *)request + header_size, message_size);
    m_libspdm_local_buffer_size += message_size;
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t libspdm_device_receive_message(void *spdm_context, size_t *response_size,
                                                void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    spdm_key_exchange_response_t *spdm_response;
    size_t spdm_response_size;
    size_t test_message_header_size;

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

    switch (m_libspdm_test_case_id) {
    case 0x01: {
        size_t dhe_key_size;
        uint32_t hash_size;
        size_t signature_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *dhe_context;
        uint8_t final_key[LIBSPDM_MAX_DHE_KEY_SIZE];
        size_t final_key_size;
        size_t opaque_key_exchange_rsp_size;
        void *data;
        size_t data_size;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        uint8_t *cert_buffer;
        size_t cert_buffer_size;
        uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
        uint8_t th_curr_hash_data[LIBSPDM_MAX_HASH_SIZE];
        uint8_t bin_str0[128];
        size_t bin_str0_size;
        uint8_t bin_str2[128];
        size_t bin_str2_size;
        uint8_t bin_str7[128];
        size_t bin_str7_size;
        uint8_t handshake_secret[LIBSPDM_MAX_HASH_SIZE];
        uint8_t response_handshake_secret[LIBSPDM_MAX_HASH_SIZE];
        uint8_t response_finished_key[LIBSPDM_MAX_HASH_SIZE];

        ((libspdm_context_t *)spdm_context)->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) + dhe_key_size + 0 +
                             sizeof(uint16_t) + opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        /* The caller need guarantee the version is correct, both of MajorVersion and MinorVersion should be less than 10.*/
        if (((spdm_response->header.spdm_version & 0xF) >= 10) ||
            (((spdm_response->header.spdm_version >> 4) & 0xF) >= 10)) {
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        }

        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context =
            libspdm_dhe_new(spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                            m_libspdm_use_dhe_algo, true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(m_libspdm_use_dhe_algo, dhe_context,
                                (uint8_t *)&m_libspdm_local_buffer[0] +
                                sizeof(spdm_key_exchange_request_t),
                                dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(spdm_context,
                                                         &opaque_key_exchange_rsp_size,
                                                         ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo,
                                                        &data, &data_size,
                                                        NULL, NULL);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response,
                         (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size, cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, cert_buffer_hash, hash_size);
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_KEY_EXCHANGE_RSP, m_libspdm_use_asym_algo, m_libspdm_use_hash_algo, false,
                libspdm_get_managed_buffer(&th_curr), libspdm_get_managed_buffer_size(
                &th_curr), ptr, &signature_size);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         ptr, signature_size);
        m_libspdm_local_buffer_size += signature_size;
        libspdm_append_managed_buffer(&th_curr, ptr, signature_size);
        ptr += signature_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr),
                         th_curr_hash_data);
        bin_str0_size = sizeof(bin_str0);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_0_LABEL, sizeof(SPDM_BIN_STR_0_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str0,
                           &bin_str0_size);
        libspdm_hmac_all(m_libspdm_use_hash_algo, final_key, final_key_size,
                         m_libspdm_zero_filled_buffer, hash_size,handshake_secret);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_2_LABEL, sizeof(SPDM_BIN_STR_2_LABEL) - 1,
                           th_curr_hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, handshake_secret, hash_size,
                            bin_str2, bin_str2_size,
                            response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_7_LABEL, sizeof(SPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hmac_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(
                             &th_curr), response_finished_key, hash_size, ptr);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        break;
    }
    case 0x02: {
        break;
    }
    }

    libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                          spdm_response_size,
                                          spdm_response, response_size, response);

    return LIBSPDM_STATUS_SUCCESS;
}

void libspdm_test_requester_key_exchange_case1(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t slot_id_param;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    m_libspdm_test_case_id = 0x01;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.secured_message_version = SECURED_SPDM_VERSION_11
                                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    heartbeat_period = 0;
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));

    status = libspdm_send_receive_key_exchange(spdm_context,
                                               SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                               0, 0, &session_id, &heartbeat_period, &slot_id_param,
                                               measurement_hash);
    free(data);

    if (status == LIBSPDM_STATUS_SUCCESS) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }

#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
}

void libspdm_test_requester_key_exchange_case2(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t slot_id_param;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    m_libspdm_test_case_id = 0x02;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.secured_message_version = SECURED_SPDM_VERSION_11
                                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    heartbeat_period = 0;
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));

    status = libspdm_send_receive_key_exchange(spdm_context,
                                               SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                               0, 0, &session_id, &heartbeat_period, &slot_id_param,
                                               measurement_hash);
    free(data);
    if (status == LIBSPDM_STATUS_SUCCESS) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
}

void libspdm_test_requester_key_exchange_case3(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t slot_id_param;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    m_libspdm_test_case_id = 0x01;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.secured_message_version = SECURED_SPDM_VERSION_11
                                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_session_info_init(spdm_context,
                              spdm_context->session_info,
                              INVALID_SESSION_ID, false);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    heartbeat_period = 0;
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));

    status = libspdm_send_receive_key_exchange(
        spdm_context,
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0xFF,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);

    free(data);
    if (status == LIBSPDM_STATUS_SUCCESS) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }

#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
}

void libspdm_test_requester_key_exchange_case4(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t slot_id_param;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    m_libspdm_test_case_id = 0x01;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.secured_message_version = SECURED_SPDM_VERSION_11
                                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_session_info_init(spdm_context,
                              spdm_context->session_info,
                              INVALID_SESSION_ID, false);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    heartbeat_period = 0;
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));

    status = libspdm_send_receive_key_exchange(
        spdm_context,
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0xFF,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);

    free(data);
    if (status == LIBSPDM_STATUS_SUCCESS) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }

#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
}

void libspdm_test_requester_key_exchange_case5(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t slot_id_param;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *State;
    m_libspdm_test_case_id = 0x02;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.secured_message_version = SECURED_SPDM_VERSION_11
                                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    libspdm_session_info_init(spdm_context,
                              spdm_context->session_info,
                              INVALID_SESSION_ID, false);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    heartbeat_period = 0;
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));

    status = libspdm_send_receive_key_exchange(
        spdm_context,
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0xFF,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);

    free(data);
    if (status == LIBSPDM_STATUS_SUCCESS) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }

#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
}

void libspdm_test_requester_key_exchange_ex_case1(void **State)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t slot_id_param;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t requester_random_in[LIBSPDM_MAX_BUFFER_SIZE];
    uint8_t requester_random[LIBSPDM_MAX_BUFFER_SIZE];
    uint8_t responder_random[LIBSPDM_MAX_BUFFER_SIZE];
    uint8_t responder_opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    size_t responder_opaque_data_size;

    spdm_test_context = *State;
    m_libspdm_test_case_id = 0x01;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.secured_message_version = SECURED_SPDM_VERSION_11
                                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data, data_size,
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data, data_size,
        &spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif

    heartbeat_period = 0;
    responder_opaque_data_size = sizeof(responder_opaque_data);
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_send_receive_key_exchange_ex(spdm_context,
                                                  SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                                  0, 0,
                                                  &session_id, &heartbeat_period, &slot_id_param,
                                                  measurement_hash, requester_random_in,
                                                  requester_random, responder_random,
                                                  NULL, 0,
                                                  responder_opaque_data,
                                                  &responder_opaque_data_size);
    free(data);
    if (status == LIBSPDM_STATUS_SUCCESS) {
        libspdm_reset_message_k(spdm_context, spdm_context->session_info);
    }
#if !(LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT)
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
}

libspdm_test_context_t m_libspdm_requester_key_exchange_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_key_exchange_test_context);

    m_libspdm_requester_key_exchange_test_context.test_buffer = (void *)test_buffer;
    m_libspdm_requester_key_exchange_test_context.test_buffer_size = test_buffer_size;

    /* Successful response*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_key_exchange_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_key_exchange_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Successful response V1.2*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_key_exchange_case3(&State);
    libspdm_unit_test_group_teardown(&State);

    /* mut_auth cap check*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_key_exchange_case4(&State);
    libspdm_unit_test_group_teardown(&State);

    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_key_exchange_case5(&State);
    libspdm_unit_test_group_teardown(&State);

    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_key_exchange_ex_case1(&State);
    libspdm_unit_test_group_teardown(&State);
}
#else
size_t libspdm_get_max_buffer_size(void)
{
    return 0;
}

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
