/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_requester_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP

bool m_secured_on_off;
static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_L1L2_BUFFER_SIZE];

uint8_t temp_buf[LIBSPDM_RECEIVER_BUFFER_SIZE];

size_t libspdm_get_max_buffer_size(void)
{
    return LIBSPDM_MAX_SPDM_MSG_SIZE;
}

size_t libspdm_test_get_measurement_request_size(const void *spdm_context, const void *buffer,
                                                 size_t buffer_size)
{
    const spdm_get_measurements_request_t *spdm_request;
    size_t message_size;

    spdm_request = buffer;
    message_size = sizeof(spdm_message_header_t);
    if (buffer_size < message_size) {
        return buffer_size;
    }

    if (spdm_request->header.request_response_code != SPDM_GET_MEASUREMENTS) {
        return buffer_size;
    }

    if ((spdm_request->header.param1 &
         SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
            if (buffer_size < sizeof(spdm_get_measurements_request_t)) {
                return buffer_size;
            }
            message_size = sizeof(spdm_get_measurements_request_t);
        } else {
            if (buffer_size <
                sizeof(spdm_get_measurements_request_t) - sizeof(spdm_request->slot_id_param)) {
                return buffer_size;
            }
            message_size =
                sizeof(spdm_get_measurements_request_t) - sizeof(spdm_request->slot_id_param);
        }
    } else {
        /* already checked before if buffer_size < sizeof(spdm_message_header_t)*/
        message_size = sizeof(spdm_message_header_t);
    }

    /* Good message, return actual size*/
    return message_size;
}

libspdm_return_t libspdm_device_send_message(void *spdm_context, size_t request_size,
                                             const void *request, uint64_t timeout)
{
    size_t header_size;
    size_t message_size;

    m_libspdm_local_buffer_size = 0;
    header_size = sizeof(libspdm_test_message_header_t);
    message_size = libspdm_test_get_measurement_request_size(
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
    uint8_t *spdm_response;
    size_t spdm_response_size;
    size_t test_message_header_size;

    spdm_test_context = libspdm_get_test_context();
    test_message_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;

    if (!m_secured_on_off) {
        spdm_response = (void *)((uint8_t *)temp_buf + test_message_header_size);
        spdm_response_size = spdm_test_context->test_buffer_size;
        if (spdm_response_size >
            sizeof(temp_buf) - test_message_header_size - LIBSPDM_TEST_ALIGNMENT) {
            spdm_response_size = sizeof(temp_buf) - test_message_header_size -
                                 LIBSPDM_TEST_ALIGNMENT;
        }
        libspdm_copy_mem((uint8_t *)temp_buf + test_message_header_size,
                         sizeof(temp_buf) - test_message_header_size,
                         spdm_test_context->test_buffer,
                         spdm_response_size);
        libspdm_transport_test_encode_message(spdm_context, NULL, false, false,
                                              spdm_response_size,
                                              spdm_response, response_size, response);

    } else {
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;
        size_t aead_tag_max_size;

        session_id = 0xFFFFFFFF;
        spdm_response_size = spdm_test_context->test_buffer_size;
        /* limit the encoding buffer to avoid assert, because the input buffer is controlled by the the libspdm consumer. */
        test_message_header_size += sizeof(spdm_secured_message_a_data_header1_t) +
                                    2 + /* MCTP_SEQUENCE_NUMBER_COUNT */
                                    sizeof(spdm_secured_message_a_data_header2_t) +
                                    sizeof(spdm_secured_message_cipher_header_t) +
                                    32 /* MCTP_MAX_RANDOM_NUMBER_COUNT */;
        aead_tag_max_size = LIBSPDM_MAX_AEAD_TAG_SIZE;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer(spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);
        spdm_response = (void *)(scratch_buffer + test_message_header_size);
        spdm_response_size = spdm_test_context->test_buffer_size;
        if (spdm_response_size >
            LIBSPDM_MAX_SPDM_MSG_SIZE - test_message_header_size - aead_tag_max_size -
            LIBSPDM_TEST_ALIGNMENT) {
            spdm_response_size = LIBSPDM_MAX_SPDM_MSG_SIZE - test_message_header_size -
                                 aead_tag_max_size -
                                 LIBSPDM_TEST_ALIGNMENT;
        }

        libspdm_copy_mem(scratch_buffer + test_message_header_size,
                         scratch_buffer_size - test_message_header_size,
                         spdm_test_context->test_buffer,
                         spdm_response_size);
        libspdm_transport_test_encode_message(spdm_context, &session_id, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
        session_info = libspdm_get_session_info_via_session_id(
            spdm_context, session_id);
        if (session_info == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        /* WALKAROUND: If just use single context to encode message and then decode message */
        ((libspdm_secured_message_context_t
          *)(session_info->secured_message_context))
        ->application_secret.response_data_sequence_number--;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

void libspdm_test_requester_get_measurement_case1(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    m_secured_on_off = false;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec =
        m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
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

    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

    measurement_record_length = sizeof(measurement_record);
    libspdm_get_measurement(spdm_context, NULL, request_attribute, 1, 0, NULL,
                            &number_of_block,
                            &measurement_record_length, measurement_record);
    free(data);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
}

void libspdm_test_requester_get_measurement_case2(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    size_t opaque_data_size;

    m_secured_on_off = false;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
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

    request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED;

    measurement_record_length = sizeof(measurement_record);
    opaque_data_size = sizeof(opaque_data);

    libspdm_get_measurement_ex(spdm_context, NULL, request_attribute, 1, 0, NULL,
                               &number_of_block,
                               &measurement_record_length, measurement_record,
                               NULL, NULL, NULL,
                               opaque_data, &opaque_data_size);
    free(data);
    libspdm_reset_message_m(spdm_context, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
}

void libspdm_test_requester_get_measurement_case3(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_session_info_t *session_info;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint32_t session_id;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    m_secured_on_off = true;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
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

    request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED;

    measurement_record_length = sizeof(measurement_record);
    libspdm_get_measurement(spdm_context, &session_id, request_attribute, 1, 0, NULL,
                            &number_of_block, &measurement_record_length,
                            measurement_record);
    free(data);
    libspdm_reset_message_m(spdm_context, spdm_context->session_info);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
}

void libspdm_test_requester_get_measurement_case4(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    m_secured_on_off = false;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;

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

    request_attribute = 0;

    measurement_record_length = sizeof(measurement_record);
    libspdm_get_measurement(spdm_context, NULL, request_attribute,
                            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS, 0,
                            NULL, &number_of_block, &measurement_record_length,
                            measurement_record);
    free(data);
    libspdm_reset_message_m(spdm_context, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
}

void libspdm_test_requester_get_measurement_case5(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    uint8_t content_changed[10];
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    size_t opaque_data_size;

    m_secured_on_off = false;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12
                                            << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size,
                                                    &hash, &hash_size);
    libspdm_reset_message_m(spdm_context, NULL);
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->local_context.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
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

    request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED;

    measurement_record_length = sizeof(measurement_record);
    opaque_data_size = sizeof(opaque_data);

    libspdm_get_measurement_ex(spdm_context, NULL, request_attribute, 1, 0, content_changed,
                               &number_of_block,
                               &measurement_record_length, measurement_record,
                               NULL, NULL, NULL,
                               opaque_data, &opaque_data_size);
    free(data);
    libspdm_reset_message_m(spdm_context, NULL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    libspdm_asym_free(spdm_context->connection_info.algorithm.base_asym_algo,
                      spdm_context->connection_info.peer_used_cert_chain[0].leaf_cert_public_key);
#endif
}

libspdm_test_context_t m_libspdm_requester_get_measurements_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_device_send_message,
    libspdm_device_receive_message,
};

void libspdm_run_test_harness(void *test_buffer, size_t test_buffer_size)
{
    void *State;

    libspdm_setup_test_context(&m_libspdm_requester_get_measurements_test_context);

    m_libspdm_requester_get_measurements_test_context.test_buffer = test_buffer;
    m_libspdm_requester_get_measurements_test_context.test_buffer_size = test_buffer_size;

    /* Successful response to get measurement with signature*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_get_measurement_case1(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Successful response to get measurement without signature*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_get_measurement_case2(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Successful response to get a session based measurement without signature*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_get_measurement_case3(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Successful response to get all measurements without signature*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_get_measurement_case4(&State);
    libspdm_unit_test_group_teardown(&State);

    /* Successful response V1.2 to  to get one measurement without signature*/
    libspdm_unit_test_group_setup(&State);
    libspdm_test_requester_get_measurement_case5(&State);
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
