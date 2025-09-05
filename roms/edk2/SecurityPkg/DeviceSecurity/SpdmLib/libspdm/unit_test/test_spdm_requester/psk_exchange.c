/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP

#define LIBSPDM_BIN_STR_2_LABEL "rsp hs data"
#define LIBSPDM_BIN_STR_7_LABEL "finished"

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_TH_BUFFER_SIZE];
static uint8_t m_libspdm_zero_filled_buffer[LIBSPDM_MAX_HASH_SIZE];

static libspdm_th_managed_buffer_t th_curr;

size_t libspdm_test_get_psk_exchange_request_size(const void *spdm_context,
                                                  const void *buffer,
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

    message_size += spdm_request->psk_hint_length +
                    spdm_request->context_length +
                    spdm_request->opaque_length;
    if (buffer_size < message_size) {
        return buffer_size;
    }

    /* Good message, return actual size*/
    return message_size;
}

libspdm_return_t libspdm_requester_psk_exchange_test_send_message(
    void *spdm_context, size_t request_size, const void *request,
    uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    size_t header_size;
    size_t message_size;

    spdm_test_context = libspdm_get_test_context();
    header_size = sizeof(libspdm_test_message_header_t);
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_SEND_FAIL;
    case 0x2:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x3:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x4:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x5:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x6:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x7:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x8:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x9: {
        static size_t sub_index = 0;
        if (sub_index == 0) {
            m_libspdm_local_buffer_size = 0;
            message_size = libspdm_test_get_psk_exchange_request_size(
                spdm_context, (const uint8_t *)request + header_size,
                request_size - header_size);
            libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                             (const uint8_t *)request + header_size, message_size);
            m_libspdm_local_buffer_size += message_size;
            sub_index++;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0xA:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0xB:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0xC:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size, request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0xD:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0xE:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0xF:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x10:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x11:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x12:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x13:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x14:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x15:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x16:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x17:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x18:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x19:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1A:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1B:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_psk_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t libspdm_requester_psk_exchange_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x2: {
        spdm_psk_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                             LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_2_LABEL, sizeof(LIBSPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_7_LABEL, sizeof(LIBSPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: {
        spdm_psk_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                             LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_2_LABEL, sizeof(LIBSPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_7_LABEL, sizeof(LIBSPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x4: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x5: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x6: {
        static size_t sub_index1 = 0;
        if (sub_index1 == 0) {
            spdm_error_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;

            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response->header.param2 = 0;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
            sub_index1++;
        } else if (sub_index1 == 1) {
            spdm_psk_exchange_response_t *spdm_response;
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
            size_t spdm_response_size;
            size_t transport_header_size;

            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_asym_algo =
                m_libspdm_use_asym_algo;
            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_hash_algo =
                m_libspdm_use_hash_algo;
            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm.dhe_named_group =
                m_libspdm_use_dhe_algo;
            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm
            .measurement_hash_algo =
                m_libspdm_use_measurement_hash_algo;
            hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
            hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
            opaque_psk_exchange_rsp_size =
                libspdm_get_opaque_data_version_selection_data_size(
                    spdm_context);
            spdm_response_size = sizeof(spdm_psk_exchange_response_t) +
                                 0 + LIBSPDM_PSK_CONTEXT_LENGTH +
                                 opaque_psk_exchange_rsp_size +
                                 hmac_size;
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_PSK_EXCHANGE_RSP;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            spdm_response->rsp_session_id =
                libspdm_allocate_rsp_session_id(spdm_context, true);
            spdm_response->reserved = 0;
            spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
            spdm_response->opaque_length =
                (uint16_t)opaque_psk_exchange_rsp_size;
            ptr = (void *)(spdm_response + 1);
            /* libspdm_zero_mem (ptr, hash_size);
             * ptr += hash_size;*/
            libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
            ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
            libspdm_build_opaque_data_version_selection_data(
                spdm_context, &opaque_psk_exchange_rsp_size,
                ptr);
            ptr += opaque_psk_exchange_rsp_size;
            libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                             sizeof(m_libspdm_local_buffer)
                             - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                                m_libspdm_local_buffer),
                             spdm_response, (size_t)ptr - (size_t)spdm_response);
            m_libspdm_local_buffer_size +=
                ((size_t)ptr - (size_t)spdm_response);
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                           m_libspdm_local_buffer_size));
            libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
            libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo, &data,
                &data_size, NULL, NULL);
            cert_buffer = (uint8_t *)data +
                          sizeof(spdm_cert_chain_t) + hash_size;
            cert_buffer_size =
                data_size -
                (sizeof(spdm_cert_chain_t) + hash_size);
            libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer,
                             cert_buffer_size, cert_buffer_hash);
            /* transcript.message_a size is 0*/
            libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                          m_libspdm_local_buffer_size);
            libspdm_hash_all(m_libspdm_use_hash_algo,
                             libspdm_get_managed_buffer(&th_curr),
                             libspdm_get_managed_buffer_size(&th_curr),
                             hash_data);
            free(data);
            bin_str2_size = sizeof(bin_str2);
            libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                               LIBSPDM_BIN_STR_2_LABEL,
                               sizeof(LIBSPDM_BIN_STR_2_LABEL) - 1, hash_data,
                               (uint16_t)hash_size, hash_size, bin_str2,
                               &bin_str2_size);
            libspdm_psk_handshake_secret_hkdf_expand(
                spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                    m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                    sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                    bin_str2_size, response_handshake_secret,
                    hash_size);
            bin_str7_size = sizeof(bin_str7);
            libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                               LIBSPDM_BIN_STR_7_LABEL,
                               sizeof(LIBSPDM_BIN_STR_7_LABEL) - 1, NULL,
                               (uint16_t)hash_size, hash_size, bin_str7,
                               &bin_str7_size);
            libspdm_hkdf_expand(m_libspdm_use_hash_algo,
                                response_handshake_secret, hash_size,
                                bin_str7, bin_str7_size,
                                response_finished_key, hash_size);
            libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                             libspdm_get_managed_buffer_size(&th_curr), hash_data);
            libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                             response_finished_key, hash_size, ptr);
            ptr += hmac_size;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false, spdm_response_size,
                spdm_response, response_size, response);
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x7: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
        spdm_response->header.param2 = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x8: {
        spdm_error_response_data_response_not_ready_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 =
            SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response->header.param2 = 0;
        spdm_response->extend_error_data.rd_exponent = 1;
        spdm_response->extend_error_data.rd_tm = 2;
        spdm_response->extend_error_data.request_code =
            SPDM_PSK_EXCHANGE;
        spdm_response->extend_error_data.token = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x9: {
        static size_t sub_index2 = 0;
        if (sub_index2 == 0) {
            spdm_error_response_data_response_not_ready_t
            *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;

            spdm_response_size = sizeof(spdm_error_response_data_response_not_ready_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 =
                SPDM_ERROR_CODE_RESPONSE_NOT_READY;
            spdm_response->header.param2 = 0;
            spdm_response->extend_error_data.rd_exponent = 1;
            spdm_response->extend_error_data.rd_tm = 2;
            spdm_response->extend_error_data.request_code =
                SPDM_PSK_EXCHANGE;
            spdm_response->extend_error_data.token = 1;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
            sub_index2++;
        } else if (sub_index2 == 1) {
            spdm_psk_exchange_response_t *spdm_response;
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
            size_t spdm_response_size;
            size_t transport_header_size;

            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_asym_algo =
                m_libspdm_use_asym_algo;
            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_hash_algo =
                m_libspdm_use_hash_algo;
            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm.dhe_named_group =
                m_libspdm_use_dhe_algo;
            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm
            .measurement_hash_algo =
                m_libspdm_use_measurement_hash_algo;
            hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
            hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
            opaque_psk_exchange_rsp_size =
                libspdm_get_opaque_data_version_selection_data_size(
                    spdm_context);
            spdm_response_size = sizeof(spdm_psk_exchange_response_t) +
                                 0 + LIBSPDM_PSK_CONTEXT_LENGTH +
                                 opaque_psk_exchange_rsp_size +
                                 hmac_size;
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_PSK_EXCHANGE_RSP;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            spdm_response->rsp_session_id =
                libspdm_allocate_rsp_session_id(spdm_context, true);
            spdm_response->reserved = 0;
            spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
            spdm_response->opaque_length =
                (uint16_t)opaque_psk_exchange_rsp_size;
            ptr = (void *)(spdm_response + 1);
            /* libspdm_zero_mem (ptr, hash_size);
             * ptr += hash_size;*/
            libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
            ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
            libspdm_build_opaque_data_version_selection_data(
                spdm_context, &opaque_psk_exchange_rsp_size,
                ptr);
            ptr += opaque_psk_exchange_rsp_size;
            libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                             sizeof(m_libspdm_local_buffer)
                             - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                                m_libspdm_local_buffer),
                             spdm_response, (size_t)ptr - (size_t)spdm_response);
            m_libspdm_local_buffer_size +=
                ((size_t)ptr - (size_t)spdm_response);
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                           m_libspdm_local_buffer_size));
            libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
            libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo, &data,
                &data_size, NULL, NULL);
            cert_buffer = (uint8_t *)data +
                          sizeof(spdm_cert_chain_t) + hash_size;
            cert_buffer_size =
                data_size -
                (sizeof(spdm_cert_chain_t) + hash_size);
            libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer,
                             cert_buffer_size, cert_buffer_hash);
            /* transcript.message_a size is 0*/
            libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                          m_libspdm_local_buffer_size);
            libspdm_hash_all(m_libspdm_use_hash_algo,
                             libspdm_get_managed_buffer(&th_curr),
                             libspdm_get_managed_buffer_size(&th_curr),
                             hash_data);
            free(data);
            bin_str2_size = sizeof(bin_str2);
            libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                               LIBSPDM_BIN_STR_2_LABEL,
                               sizeof(LIBSPDM_BIN_STR_2_LABEL) - 1, hash_data,
                               (uint16_t)hash_size, hash_size, bin_str2,
                               &bin_str2_size);
            libspdm_psk_handshake_secret_hkdf_expand(
                spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                    m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                    sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                    bin_str2_size, response_handshake_secret,
                    hash_size);
            bin_str7_size = sizeof(bin_str7);
            libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                               LIBSPDM_BIN_STR_7_LABEL,
                               sizeof(LIBSPDM_BIN_STR_7_LABEL) - 1, NULL,
                               (uint16_t)hash_size, hash_size, bin_str7,
                               &bin_str7_size);
            libspdm_hkdf_expand(m_libspdm_use_hash_algo,
                                response_handshake_secret, hash_size,
                                bin_str7, bin_str7_size,
                                response_finished_key, hash_size);
            libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                             libspdm_get_managed_buffer_size(&th_curr), hash_data);
            libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                             response_finished_key, hash_size, ptr);
            ptr += hmac_size;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false, spdm_response_size,
                spdm_response, response_size, response);
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xA:
    {
        static uint16_t error_code = LIBSPDM_ERROR_CODE_RESERVED_00;

        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        if(error_code <= 0xff) {
            libspdm_zero_mem (spdm_response, spdm_response_size);
            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = (uint8_t) error_code;
            spdm_response->header.param2 = 0;

            libspdm_transport_test_encode_message (spdm_context, NULL, false, false,
                                                   spdm_response_size, spdm_response,
                                                   response_size, response);
        }

        error_code++;
        if(error_code == SPDM_ERROR_CODE_BUSY) { /*busy is treated in cases 5 and 6*/
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) { /*skip some reserved error codes (0d to 3e)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xB: {
        spdm_psk_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                             LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_2_LABEL, sizeof(LIBSPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_7_LABEL, sizeof(LIBSPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xC: {
        spdm_psk_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

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
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                             LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id = libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length = (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) - m_libspdm_local_buffer_size,
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer = (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size = data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_2_LABEL, sizeof(SPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2, bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_7_LABEL, sizeof(SPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7, &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) - m_libspdm_local_buffer_size,
                         ptr, hmac_size);
        m_libspdm_local_buffer_size += hmac_size;
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0xD: {
        spdm_psk_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                             LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_2_LABEL, sizeof(LIBSPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_7_LABEL, sizeof(LIBSPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0xE: {
        spdm_psk_exchange_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint32_t measurement_hash_size;
        uint8_t *ptr;
        size_t opaque_psk_exchange_rsp_size;
        void *data;
        size_t data_size;
        uint8_t measurement_hash_data[LIBSPDM_MAX_HASH_SIZE];
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        measurement_hash_size = libspdm_get_hash_size(
            m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) +
                             measurement_hash_size + LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /*Mock measurement hash as TCB*/
        libspdm_copy_mem(measurement_hash_data, sizeof(measurement_hash_data),
                         m_libspdm_use_tcb_hash_value, measurement_hash_size);
        libspdm_copy_mem(ptr, spdm_response_size - (ptr - (uint8_t *)spdm_response),
                         measurement_hash_data, measurement_hash_size);
        /*libspdm_zero_mem (ptr, measurement_hash_size);*/
        ptr += measurement_hash_size;
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_2_LABEL, sizeof(SPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_7_LABEL, sizeof(SPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xF: {
        spdm_psk_exchange_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint32_t measurement_hash_size;
        uint8_t *ptr;
        size_t opaque_psk_exchange_rsp_size;
        void *data;
        size_t data_size;
        uint8_t measurement_hash_data[LIBSPDM_MAX_HASH_SIZE];
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        measurement_hash_size = libspdm_get_hash_size(
            m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) +
                             measurement_hash_size + LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /*Mock measurement hash as 0x00 array*/
        libspdm_zero_mem(measurement_hash_data, measurement_hash_size);
        libspdm_copy_mem(ptr, spdm_response_size - (ptr - (uint8_t *)spdm_response),
                         measurement_hash_data, measurement_hash_size);
        /*libspdm_zero_mem (ptr, measurement_hash_size);*/
        ptr += measurement_hash_size;
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_2_LABEL, sizeof(SPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_7_LABEL, sizeof(SPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x10: {
        spdm_psk_exchange_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint32_t measurement_hash_size;
        uint8_t *ptr;
        size_t opaque_psk_exchange_rsp_size;
        void *data;
        size_t data_size;
        uint8_t measurement_hash_data[LIBSPDM_MAX_HASH_SIZE];
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        measurement_hash_size = libspdm_get_hash_size(
            m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) +
                             measurement_hash_size + LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /*Mock measurement hash*/
        libspdm_copy_mem(measurement_hash_data, sizeof(measurement_hash_data),
                         m_libspdm_use_tcb_hash_value, measurement_hash_size);
        libspdm_copy_mem(ptr, spdm_response_size - (ptr - (uint8_t *)spdm_response),
                         measurement_hash_data, measurement_hash_size);
        /*libspdm_zero_mem (ptr, measurement_hash_size);*/
        ptr += measurement_hash_size;
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_2_LABEL, sizeof(SPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_7_LABEL, sizeof(SPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x11: {
        spdm_psk_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                             LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_2_LABEL, sizeof(SPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_7_LABEL, sizeof(SPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x12: {
        spdm_psk_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                             LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_2_LABEL, sizeof(SPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_7_LABEL, sizeof(SPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x13: {
        spdm_psk_exchange_response_t *spdm_response;
        uint32_t hash_size;
        uint32_t hmac_size;
        uint32_t measurement_hash_size;
        uint8_t *ptr;
        size_t opaque_psk_exchange_rsp_size;
        void *data;
        size_t data_size;
        uint8_t measurement_hash_data[LIBSPDM_MAX_HASH_SIZE];
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        measurement_hash_size = libspdm_get_hash_size(
            m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) +
                             measurement_hash_size + LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /*Mock measurement hash as TCB*/
        libspdm_copy_mem(measurement_hash_data, sizeof(measurement_hash_data),
                         m_libspdm_use_tcb_hash_value, measurement_hash_size);
        libspdm_copy_mem(ptr, spdm_response_size - (ptr - (uint8_t *)spdm_response),
                         measurement_hash_data, measurement_hash_size);
        /*libspdm_zero_mem (ptr, measurement_hash_size);*/
        ptr += measurement_hash_size;
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_2_LABEL, sizeof(SPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_7_LABEL, sizeof(SPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x14: {
        spdm_psk_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                             LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 5;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_2_LABEL, sizeof(LIBSPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_7_LABEL, sizeof(LIBSPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x15: {
        spdm_psk_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                             LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 5;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_2_LABEL, sizeof(LIBSPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_7_LABEL, sizeof(LIBSPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x16: {
        spdm_psk_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                             LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_2_LABEL, sizeof(LIBSPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_7_LABEL, sizeof(LIBSPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x17: {
        spdm_psk_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                             LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_2_LABEL, sizeof(LIBSPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_7_LABEL, sizeof(LIBSPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        /* Flip last byte of ResponderVerifyData*/
        ptr += hmac_size-1;
        *ptr ^= 0xFF;
        ptr++;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x18: {
        spdm_psk_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                             0 +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = 0;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        /* libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
         * ptr += LIBSPDM_PSK_CONTEXT_LENGTH;*/
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_2_LABEL, sizeof(LIBSPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_7_LABEL, sizeof(LIBSPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x19: {
        spdm_psk_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size = 0;
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                             LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        /* libspdm_build_opaque_data_version_selection_data(
         *    spdm_context, &opaque_psk_exchange_rsp_size, ptr);
         * ptr += opaque_psk_exchange_rsp_size;*/
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_2_LABEL, sizeof(LIBSPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_7_LABEL, sizeof(LIBSPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1A: {
        spdm_psk_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size = 0;
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                             0 +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = 0;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        /*libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
         * ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
         * libspdm_build_opaque_data_version_selection_data(
         *  spdm_context, &opaque_psk_exchange_rsp_size, ptr);
         * ptr += opaque_psk_exchange_rsp_size;*/
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_2_LABEL, sizeof(LIBSPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_7_LABEL, sizeof(LIBSPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1B: {
        spdm_psk_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)->connection_info.secured_message_version =
            SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group =
            m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        opaque_psk_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_psk_exchange_response_t) + 0 +
                             LIBSPDM_PSK_CONTEXT_LENGTH +
                             opaque_psk_exchange_rsp_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code =
            SPDM_PSK_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, true);
        spdm_response->reserved = 0;
        spdm_response->context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
        spdm_response->opaque_length =
            (uint16_t)opaque_psk_exchange_rsp_size;
        ptr = (void *)(spdm_response + 1);
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        libspdm_get_random_number(LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
        ptr += LIBSPDM_PSK_CONTEXT_LENGTH;
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_psk_exchange_rsp_size, ptr);
        ptr += opaque_psk_exchange_rsp_size;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        cert_buffer =
            (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size;
        cert_buffer_size =
            data_size - (sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
        /* transcript.message_a size is 0*/
        libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                      m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        free(data);
        bin_str2_size = sizeof(bin_str2);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_2_LABEL, sizeof(LIBSPDM_BIN_STR_2_LABEL) - 1,
                           hash_data, (uint16_t)hash_size, hash_size,
                           bin_str2, &bin_str2_size);
        libspdm_psk_handshake_secret_hkdf_expand(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_hash_algo, (const uint8_t *)LIBSPDM_TEST_PSK_HINT_STRING,
                sizeof(LIBSPDM_TEST_PSK_HINT_STRING), bin_str2,
                bin_str2_size,
                response_handshake_secret, hash_size);
        bin_str7_size = sizeof(bin_str7);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           LIBSPDM_BIN_STR_7_LABEL, sizeof(LIBSPDM_BIN_STR_7_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str7,
                           &bin_str7_size);
        libspdm_hkdf_expand(m_libspdm_use_hash_algo, response_handshake_secret,
                            hash_size, bin_str7, bin_str7_size,
                            response_finished_key, hash_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), hash_data);
        libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                         response_finished_key, hash_size, ptr);
        ptr += hmac_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

void libspdm_test_requester_psk_exchange_case1(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context, NULL, 0,
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
    free(data);
}

void libspdm_test_requester_psk_exchange_case2(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    free(data);
}

void libspdm_test_requester_psk_exchange_case3(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
    free(data);
}

void libspdm_test_requester_psk_exchange_case4(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
    free(data);
}

void libspdm_test_requester_psk_exchange_case5(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
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
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    heartbeat_period = 0;
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);
    free(data);
}

void libspdm_test_requester_psk_exchange_case6(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->retry_times = 3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, 0xFFFEFFFE);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    free(data);
}

void libspdm_test_requester_psk_exchange_case7(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
    free(data);
}

void libspdm_test_requester_psk_exchange_case8(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    free(data);
}

void libspdm_test_requester_psk_exchange_case9(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->retry_times = 3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    if (LIBSPDM_RESPOND_IF_READY_SUPPORT) {
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        assert_int_equal(session_id, 0xFFFDFFFD);
        assert_int_equal(
            libspdm_secured_message_get_session_state(
                spdm_context->session_info[0].secured_message_context),
            LIBSPDM_SESSION_STATE_HANDSHAKING);
    } else {
        assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    }

    free(data);
}

void libspdm_test_requester_psk_exchange_case10(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;
    uint16_t error_code;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
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

    error_code = LIBSPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
        libspdm_reset_message_a(spdm_context);

        heartbeat_period = 0;
        libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
        status = libspdm_send_receive_psk_exchange (spdm_context,
                                                    LIBSPDM_TEST_PSK_HINT_STRING,
                                                    sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
                                                    SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                                    0,
                                                    &session_id, &heartbeat_period,
                                                    measurement_hash);
        LIBSPDM_ASSERT_INT_EQUAL_CASE (status, LIBSPDM_STATUS_ERROR_PEER, error_code);

        error_code++;
        if(error_code == SPDM_ERROR_CODE_BUSY) { /*busy is treated in cases 5 and 6*/
            error_code = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
        }
        if(error_code == LIBSPDM_ERROR_CODE_RESERVED_0D) { /*skip some reserved error codes (0d to 3e)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_3F;
        }
        if(error_code == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { /*skip response not ready, request resync, and some reserved codes (44 to fc)*/
            error_code = LIBSPDM_ERROR_CODE_RESERVED_FD;
        }
    }

    free(data);
}

void libspdm_test_requester_psk_exchange_case11(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
    spdm_context->transcript.message_b.buffer_size =
        spdm_context->transcript.message_b.max_buffer_size;
    spdm_context->transcript.message_c.buffer_size =
        spdm_context->transcript.message_c.max_buffer_size;
    spdm_context->transcript.message_mut_b.buffer_size =
        spdm_context->transcript.message_mut_b.max_buffer_size;
    spdm_context->transcript.message_mut_c.buffer_size =
        spdm_context->transcript.message_mut_c.max_buffer_size;
#endif

    heartbeat_period = 0;
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_b.buffer_size, 0);
    assert_int_equal(spdm_context->transcript.message_mut_c.buffer_size, 0);
#endif

    free(data);
}

void libspdm_test_requester_psk_exchange_case12(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->session_info[0].session_transcript.message_k.buffer_size,
                     m_libspdm_local_buffer_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer (0x%x):\n",
                   m_libspdm_local_buffer_size));
    libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
    assert_memory_equal(spdm_context->session_info[0].session_transcript.message_k.buffer,
                        m_libspdm_local_buffer, m_libspdm_local_buffer_size);
#endif
    free(data);
}

void libspdm_test_requester_psk_exchange_case13(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
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
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_session_info_init(spdm_context,
                              spdm_context->session_info,
                              INVALID_SESSION_ID, false);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    heartbeat_period = 0;
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        SPDM_PSK_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    assert_int_equal(
        spdm_context->session_info[0].session_policy,
        SPDM_PSK_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH);
    free(data);
}

void libspdm_test_requester_psk_exchange_case14(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0xE;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
    spdm_context->connection_info.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_memory_equal(
        measurement_hash,
        m_libspdm_use_tcb_hash_value,
        libspdm_get_hash_size(m_libspdm_use_hash_algo));
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    free(data);
}

void libspdm_test_requester_psk_exchange_case15(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0xF;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->connection_info.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_memory_equal(
        measurement_hash,
        m_libspdm_zero_filled_buffer,
        libspdm_get_hash_size(m_libspdm_use_hash_algo));
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    free(data);
}

void libspdm_test_requester_psk_exchange_case16(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->connection_info.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_memory_equal(
        measurement_hash,
        m_libspdm_use_tcb_hash_value,
        libspdm_get_hash_size(m_libspdm_use_hash_algo));
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    free(data);
}

void libspdm_test_requester_psk_exchange_case17(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->connection_info.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
    free(data);
}

void libspdm_test_requester_psk_exchange_case18(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0x12;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->connection_info.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
    free(data);
}

void libspdm_test_requester_psk_exchange_case19(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0x13;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->connection_info.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

void libspdm_test_requester_psk_exchange_case20(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0x14;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->connection_info.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;


    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

void libspdm_test_requester_psk_exchange_case21(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0x15;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;

    spdm_context->connection_info.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;


    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    /* clear Heartbeat flags */
    spdm_context->connection_info.capability.flags &=
        !SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
    spdm_context->local_context.capability.flags &=
        !SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    assert_int_equal(heartbeat_period,5);
    free(data);
}

void libspdm_test_requester_psk_exchange_case22(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0x16;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;

    spdm_context->connection_info.algorithm.measurement_spec =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;


    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);

    /*clear Heartbeat flags*/
    spdm_context->connection_info.capability.flags &=
        !SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
    spdm_context->local_context.capability.flags &=
        !SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    assert_int_equal(heartbeat_period,0);
    free(data);
}

void libspdm_test_requester_psk_exchange_case23(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0x17;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_VERIF_FAIL);
    free(data);
}

void libspdm_test_requester_psk_exchange_case24(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0x18;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    free(data);
}

void libspdm_test_requester_psk_exchange_case25(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0x19;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    free(data);
}

void libspdm_test_requester_psk_exchange_case26(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0x1A;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_ESTABLISHED);
    free(data);
}

void libspdm_test_requester_psk_exchange_case27(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1B;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags &=
        ~(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP);
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule =
        m_libspdm_use_key_schedule_algo;
    libspdm_session_info_init(spdm_context,
                              spdm_context->session_info,
                              INVALID_SESSION_ID, false);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size =
        data_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[0].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[0].buffer),
                     data, data_size);
#endif

    heartbeat_period = 0;
    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_send_receive_psk_exchange(
        spdm_context,
        LIBSPDM_TEST_PSK_HINT_STRING, sizeof(LIBSPDM_TEST_PSK_HINT_STRING),
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        SPDM_PSK_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH, &session_id,
        &heartbeat_period, measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    assert_int_equal(
        spdm_context->session_info[0].session_policy,
        SPDM_PSK_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH);
    free(data);
}

libspdm_test_context_t m_libspdm_requester_psk_exchange_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_psk_exchange_test_send_message,
    libspdm_requester_psk_exchange_test_receive_message,
};

int libspdm_requester_psk_exchange_test_main(void)
{
    const struct CMUnitTest spdm_requester_psk_exchange_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case1),
        /* Successful response*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case2),
        /* connection_state check failed*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case3),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case4),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case5),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case6),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case7),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case8),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case9),
        /* Unexpected errors*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case10),
        /* Buffer verification*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case12),
        /* Successful response V1.2*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case13),
        /* Measurement hash 1, returns a measurement hash*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case14),
        /* Measurement hash 1, returns a 0x00 array (no TCB components)*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case15),
        /* Measurement hash FF, returns a measurement_hash*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case16),
        /* Measurement hash 1, returns no measurement_hash*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case17),
        /* Measurement hash FF, returns no measurement_hash*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case18),
        /* Measurement hash not requested, returns a measurement_hash*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case19),
        /* Heartbeat not supported, heartbeat period different from 0 sent*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case20),
        /* Heartbeat supported, heartbeat period different from 0 sent*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case21),
        /* Heartbeat supported, heartbeat period 0 sent NOTE: This should disable heartbeat*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case22),
        /* Wrong ResponderVerifyData*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case23),
        /* No ResponderContext*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case24),
        /* No OpaqueData*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case25),
        /* No ResponderContext and OpaqueData*/
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case26),
        /* OpaqueData only supports OpaqueDataFmt1, Success Case */
        cmocka_unit_test(libspdm_test_requester_psk_exchange_case27),
    };

    libspdm_setup_test_context(&m_libspdm_requester_psk_exchange_test_context);

    return cmocka_run_group_tests(spdm_requester_psk_exchange_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/
