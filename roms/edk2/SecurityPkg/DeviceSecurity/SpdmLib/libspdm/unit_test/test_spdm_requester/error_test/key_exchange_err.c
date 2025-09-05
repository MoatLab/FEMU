/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_TH_BUFFER_SIZE];
static uint8_t m_libspdm_zero_filled_buffer[LIBSPDM_MAX_HASH_SIZE];

static libspdm_th_managed_buffer_t th_curr;

static size_t libspdm_test_get_key_exchange_request_size(const void *spdm_context,
                                                         const void *buffer,
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
        *(uint16_t *)((size_t)buffer +
                      sizeof(spdm_key_exchange_request_t) + dhe_key_size);
    message_size += opaque_length;
    if (buffer_size < message_size) {
        return buffer_size;
    }

    /* Good message, return actual size*/
    return message_size;
}

static libspdm_return_t libspdm_requester_key_exchange_test_send_message(
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
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x3:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x4:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x5:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x6:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x7:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x8:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
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
            message_size = libspdm_test_get_key_exchange_request_size(
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
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0xB:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0xC:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0xD:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0xE:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0xF:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x10:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x11:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x12:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x13:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x14:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x15:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x16:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x17:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x18:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x19:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1A:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1B:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1C:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1D:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size,  message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1E:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
            spdm_context, (const uint8_t *)request + header_size,
            request_size - header_size);
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                         (const uint8_t *)request + header_size, message_size);
        m_libspdm_local_buffer_size += message_size;
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1F:
        m_libspdm_local_buffer_size = 0;
        message_size = libspdm_test_get_key_exchange_request_size(
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

static libspdm_return_t libspdm_requester_key_exchange_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x2: {
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested = 0;
        spdm_response->req_slot_id_param = 0;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested = 0;
        spdm_response->req_slot_id_param = 0;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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
            spdm_key_exchange_response_t *spdm_response;
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
            signature_size =
                libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
            hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
            hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
            dhe_key_size =
                libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
            opaque_key_exchange_rsp_size =
                libspdm_get_opaque_data_version_selection_data_size(
                    spdm_context);
            spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                                 dhe_key_size + 0 + sizeof(uint16_t) +
                                 opaque_key_exchange_rsp_size +
                                 signature_size + hmac_size;
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_EXCHANGE_RSP;
            spdm_response->header.param1 = 0;
            spdm_response->rsp_session_id =
                libspdm_allocate_rsp_session_id(spdm_context, false);
            spdm_response->mut_auth_requested = 0;
            spdm_response->req_slot_id_param = 0;
            libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                      spdm_response->random_data);
            ptr = (void *)(spdm_response + 1);
            dhe_context = libspdm_dhe_new(
                spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                    m_libspdm_use_dhe_algo, true);
            libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                     &dhe_key_size);
            final_key_size = sizeof(final_key);
            libspdm_dhe_compute_key(
                m_libspdm_use_dhe_algo, dhe_context,
                (uint8_t *)&m_libspdm_local_buffer[0] +
                sizeof(spdm_key_exchange_request_t),
                dhe_key_size, final_key, &final_key_size);
            libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
            ptr += dhe_key_size;
            /* libspdm_zero_mem (ptr, hash_size);
             * ptr += hash_size;*/
            *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
            ptr += sizeof(uint16_t);
            libspdm_build_opaque_data_version_selection_data(
                spdm_context, &opaque_key_exchange_rsp_size,
                ptr);
            ptr += opaque_key_exchange_rsp_size;
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo, &data,
                &data_size, NULL, NULL);
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
            cert_buffer = (uint8_t *)data;
            cert_buffer_size = data_size;
            libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer,
                             cert_buffer_size, cert_buffer_hash);
            /* transcript.message_a size is 0*/
            libspdm_append_managed_buffer(&th_curr, cert_buffer_hash,
                                          hash_size);
            libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                          m_libspdm_local_buffer_size);
            libspdm_hash_all(m_libspdm_use_hash_algo,
                             libspdm_get_managed_buffer(&th_curr),
                             libspdm_get_managed_buffer_size(&th_curr),
                             hash_data);
            free(data);
            libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
                spdm_context,
#endif
                spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                    SPDM_KEY_EXCHANGE_RSP,
                    m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                    false, libspdm_get_managed_buffer(&th_curr),
                    libspdm_get_managed_buffer_size(&th_curr), ptr,
                    &signature_size);
            libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                             sizeof(m_libspdm_local_buffer)
                             - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                                m_libspdm_local_buffer),
                             ptr, signature_size);
            m_libspdm_local_buffer_size += signature_size;
            libspdm_append_managed_buffer(&th_curr, ptr, signature_size);
            ptr += signature_size;
            libspdm_hash_all(m_libspdm_use_hash_algo,
                             libspdm_get_managed_buffer(&th_curr),
                             libspdm_get_managed_buffer_size(&th_curr),
                             th_curr_hash_data);
            bin_str0_size = sizeof(bin_str0);
            libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                               SPDM_BIN_STR_0_LABEL,
                               sizeof(SPDM_BIN_STR_0_LABEL) - 1, NULL,
                               (uint16_t)hash_size, hash_size, bin_str0,
                               &bin_str0_size);
            libspdm_hmac_all(m_libspdm_use_hash_algo, final_key, final_key_size,
                             m_libspdm_zero_filled_buffer, hash_size, handshake_secret);
            bin_str2_size = sizeof(bin_str2);
            libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                               SPDM_BIN_STR_2_LABEL,
                               sizeof(SPDM_BIN_STR_2_LABEL) - 1,
                               th_curr_hash_data, (uint16_t)hash_size,
                               hash_size, bin_str2, &bin_str2_size);
            libspdm_hkdf_expand(m_libspdm_use_hash_algo, handshake_secret,
                                hash_size, bin_str2, bin_str2_size,
                                response_handshake_secret, hash_size);
            bin_str7_size = sizeof(bin_str7);
            libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                               SPDM_BIN_STR_7_LABEL,
                               sizeof(SPDM_BIN_STR_7_LABEL) - 1, NULL,
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
            SPDM_KEY_EXCHANGE;
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
                SPDM_KEY_EXCHANGE;
            spdm_response->extend_error_data.token = 1;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
            sub_index2++;
        } else if (sub_index2 == 1) {
            spdm_key_exchange_response_t *spdm_response;
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
            signature_size =
                libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
            hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
            hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
            dhe_key_size =
                libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
            opaque_key_exchange_rsp_size =
                libspdm_get_opaque_data_version_selection_data_size(
                    spdm_context);
            spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                                 dhe_key_size + 0 + sizeof(uint16_t) +
                                 opaque_key_exchange_rsp_size +
                                 signature_size + hmac_size;
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_KEY_EXCHANGE_RSP;
            spdm_response->header.param1 = 0;
            spdm_response->rsp_session_id =
                libspdm_allocate_rsp_session_id(spdm_context, false);
            spdm_response->mut_auth_requested = 0;
            spdm_response->req_slot_id_param = 0;
            libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                      spdm_response->random_data);
            ptr = (void *)(spdm_response + 1);
            dhe_context = libspdm_dhe_new(
                spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                    m_libspdm_use_dhe_algo, true);
            libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                     &dhe_key_size);
            final_key_size = sizeof(final_key);
            libspdm_dhe_compute_key(
                m_libspdm_use_dhe_algo, dhe_context,
                (uint8_t *)&m_libspdm_local_buffer[0] +
                sizeof(spdm_key_exchange_request_t),
                dhe_key_size, final_key, &final_key_size);
            libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
            ptr += dhe_key_size;
            /* libspdm_zero_mem (ptr, hash_size);
             * ptr += hash_size;*/
            *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
            ptr += sizeof(uint16_t);
            libspdm_build_opaque_data_version_selection_data(
                spdm_context, &opaque_key_exchange_rsp_size,
                ptr);
            ptr += opaque_key_exchange_rsp_size;
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo, &data,
                &data_size, NULL, NULL);
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
            cert_buffer = (uint8_t *)data;
            cert_buffer_size = data_size;
            libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer,
                             cert_buffer_size, cert_buffer_hash);
            /* transcript.message_a size is 0*/
            libspdm_append_managed_buffer(&th_curr, cert_buffer_hash,
                                          hash_size);
            libspdm_append_managed_buffer(&th_curr, m_libspdm_local_buffer,
                                          m_libspdm_local_buffer_size);
            libspdm_hash_all(m_libspdm_use_hash_algo,
                             libspdm_get_managed_buffer(&th_curr),
                             libspdm_get_managed_buffer_size(&th_curr),
                             hash_data);
            free(data);
            libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
                spdm_context,
#endif
                spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                    SPDM_KEY_EXCHANGE_RSP,
                    m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                    false, libspdm_get_managed_buffer(&th_curr),
                    libspdm_get_managed_buffer_size(&th_curr), ptr,
                    &signature_size);
            libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                             sizeof(m_libspdm_local_buffer)
                             - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                                m_libspdm_local_buffer),
                             ptr, signature_size);
            m_libspdm_local_buffer_size += signature_size;
            libspdm_append_managed_buffer(&th_curr, ptr, signature_size);
            ptr += signature_size;
            libspdm_hash_all(m_libspdm_use_hash_algo,
                             libspdm_get_managed_buffer(&th_curr),
                             libspdm_get_managed_buffer_size(&th_curr),
                             th_curr_hash_data);
            bin_str0_size = sizeof(bin_str0);
            libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                               SPDM_BIN_STR_0_LABEL,
                               sizeof(SPDM_BIN_STR_0_LABEL) - 1, NULL,
                               (uint16_t)hash_size, hash_size, bin_str0,
                               &bin_str0_size);
            libspdm_hmac_all(m_libspdm_use_hash_algo, final_key, final_key_size,
                             m_libspdm_zero_filled_buffer, hash_size, handshake_secret);
            bin_str2_size = sizeof(bin_str2);
            libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                               SPDM_BIN_STR_2_LABEL,
                               sizeof(SPDM_BIN_STR_2_LABEL) - 1,
                               th_curr_hash_data, (uint16_t)hash_size,
                               hash_size, bin_str2, &bin_str2_size);
            libspdm_hkdf_expand(m_libspdm_use_hash_algo, handshake_secret,
                                hash_size, bin_str2, bin_str2_size,
                                response_handshake_secret, hash_size);
            bin_str7_size = sizeof(bin_str7);
            libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                               SPDM_BIN_STR_7_LABEL,
                               sizeof(SPDM_BIN_STR_7_LABEL) - 1, NULL,
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
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested = 0;
        spdm_response->req_slot_id_param = 0;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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
        spdm_key_exchange_response_t *spdm_response;
        size_t dhe_key_size;
        uint32_t hash_size;
        uint32_t measurement_hash_size;
        size_t signature_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *dhe_context;
        uint8_t final_key[LIBSPDM_MAX_DHE_KEY_SIZE];
        size_t final_key_size;
        size_t opaque_key_exchange_rsp_size;
        void *data;
        size_t data_size;
        uint8_t measurement_hash_data[LIBSPDM_MAX_HASH_SIZE];
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        measurement_hash_size = libspdm_get_hash_size(
            m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + measurement_hash_size + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        /* Incorrect version. Should be 1.1. */
        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested = 0;
        spdm_response->req_slot_id_param = 0;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /*Mock measurement hash as TCB*/
        libspdm_copy_mem(measurement_hash_data, sizeof(measurement_hash_data),
                         m_libspdm_use_tcb_hash_value, measurement_hash_size);
        libspdm_copy_mem(ptr, spdm_response_size - (ptr - (uint8_t *)spdm_response),
                         measurement_hash_data, measurement_hash_size);
        /*libspdm_zero_mem (ptr, measurement_hash_size);*/
        ptr += measurement_hash_size;
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer =  (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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

    case 0xD: {
        spdm_key_exchange_response_t *spdm_response;
        size_t dhe_key_size;
        uint32_t hash_size;
        uint32_t measurement_hash_size;
        size_t signature_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *dhe_context;
        uint8_t final_key[LIBSPDM_MAX_DHE_KEY_SIZE];
        size_t final_key_size;
        size_t opaque_key_exchange_rsp_size;
        void *data;
        size_t data_size;
        uint8_t measurement_hash_data[LIBSPDM_MAX_HASH_SIZE];
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        measurement_hash_size = libspdm_get_hash_size(
            m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + measurement_hash_size + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        /* Incorrect response code. */
        spdm_response->header.request_response_code = SPDM_DIGESTS;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id = libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested = 0;
        spdm_response->req_slot_id_param = 0;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo, true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /*Mock measurement hash as 0x00 array*/
        libspdm_zero_mem(measurement_hash_data, measurement_hash_size);
        libspdm_copy_mem(ptr, spdm_response_size - (ptr - (uint8_t *)spdm_response),
                         measurement_hash_data, measurement_hash_size);
        /*libspdm_zero_mem (ptr, measurement_hash_size);*/
        ptr += measurement_hash_size;
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer = (uint8_t *)data;
        cert_buffer_size =  data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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
        spdm_key_exchange_response_t *spdm_response;
        size_t dhe_key_size;
        uint32_t hash_size;
        uint32_t measurement_hash_size;
        size_t signature_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *dhe_context;
        uint8_t final_key[LIBSPDM_MAX_DHE_KEY_SIZE];
        size_t final_key_size;
        size_t opaque_key_exchange_rsp_size;
        void *data;
        size_t data_size;
        uint8_t measurement_hash_data[LIBSPDM_MAX_HASH_SIZE];
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        measurement_hash_size = libspdm_get_hash_size(
            m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + measurement_hash_size + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id = libspdm_allocate_rsp_session_id(spdm_context, false);
        /* Mutual authentication is requested even though it is not supported. */
        spdm_response->mut_auth_requested = 1;
        spdm_response->req_slot_id_param = 0;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /*Mock measurement hash*/
        libspdm_copy_mem(measurement_hash_data, sizeof(measurement_hash_data),
                         m_libspdm_use_tcb_hash_value, measurement_hash_size);
        libspdm_copy_mem(ptr, spdm_response_size - (ptr - (uint8_t *)spdm_response),
                         measurement_hash_data, measurement_hash_size);
        /*libspdm_zero_mem (ptr, measurement_hash_size);*/
        ptr += measurement_hash_size;
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer =  (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested = 0;
        spdm_response->req_slot_id_param = 0;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer =  (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested = 0;
        spdm_response->req_slot_id_param = 0;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer =  (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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
        spdm_key_exchange_response_t *spdm_response;
        size_t dhe_key_size;
        uint32_t hash_size;
        uint32_t measurement_hash_size;
        size_t signature_size;
        uint32_t hmac_size;
        uint8_t *ptr;
        void *dhe_context;
        uint8_t final_key[LIBSPDM_MAX_DHE_KEY_SIZE];
        size_t final_key_size;
        size_t opaque_key_exchange_rsp_size;
        void *data;
        size_t data_size;
        uint8_t measurement_hash_data[LIBSPDM_MAX_HASH_SIZE];
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        measurement_hash_size = libspdm_get_hash_size(
            m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + measurement_hash_size + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested = 0;
        spdm_response->req_slot_id_param = 0;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /*Mock measurement hash as TCB*/
        libspdm_copy_mem(measurement_hash_data, sizeof(measurement_hash_data),
                         m_libspdm_use_tcb_hash_value, measurement_hash_size);
        libspdm_copy_mem(ptr, spdm_response_size - (ptr - (uint8_t *)spdm_response),
                         measurement_hash_data, measurement_hash_size);
        /*libspdm_zero_mem (ptr, measurement_hash_size);*/
        ptr += measurement_hash_size;
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer =  (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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
        spdm_key_exchange_response_t *spdm_response;
        size_t dhe_key_size;
        uint32_t hash_size;
        uint32_t measurement_hash_size;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        measurement_hash_size = 0;
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + measurement_hash_size + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested = 0;
        spdm_response->req_slot_id_param = 0;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;

        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer =  (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer)
                         - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                            m_libspdm_local_buffer),
                         ptr, signature_size);
        m_libspdm_local_buffer_size += signature_size;
        libspdm_append_managed_buffer(&th_curr, ptr, signature_size);
        ptr += signature_size-1;
        *ptr ^= 0xFF;
        ptr++;
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
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x14: {
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 5;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested = 0;
        spdm_response->req_slot_id_param = 0;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer =  (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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
        spdm_key_exchange_response_t *spdm_response;
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
        size_t spdm_response_size;
        size_t transport_header_size;

        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.measurement_hash_algo =
            m_libspdm_use_measurement_hash_algo;
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size + hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id = libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested = 0;
        spdm_response->req_slot_id_param = 0;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo, true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;

        *(uint16_t *)ptr = SPDM_MAX_OPAQUE_DATA_SIZE + 1;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer = (uint8_t *)data;
        cert_buffer_size =  data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested = 0;
        spdm_response->req_slot_id_param = 0;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer =  (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested =
            SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
        spdm_response->req_slot_id_param = 0xF;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer =  (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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

    case 0x18: {
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested =
            SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST;
        spdm_response->req_slot_id_param = 0xF;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer =  (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested =
            SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS;
        spdm_response->req_slot_id_param = 0xF;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer =  (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested =
            SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED |
            SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST;
        spdm_response->req_slot_id_param = 0xF;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer =  (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested =
            SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED |
            SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS;
        spdm_response->req_slot_id_param = 0xF;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer =  (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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

    case 0x1C: {
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested =
            SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST |
            SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS;
        spdm_response->req_slot_id_param = 0xF;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer =  (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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

    case 0x1D: {
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id = libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested = 0;
        spdm_response->req_slot_id_param = 0;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE, spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo, true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] + sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) - m_libspdm_local_buffer_size,
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP, m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr, &signature_size);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) - m_libspdm_local_buffer_size,
                         ptr, signature_size);
        m_libspdm_local_buffer_size += signature_size;
        libspdm_append_managed_buffer(&th_curr, ptr, signature_size);
        ptr += signature_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                         libspdm_get_managed_buffer_size(&th_curr), th_curr_hash_data);
        bin_str0_size = sizeof(bin_str0);
        libspdm_bin_concat(((libspdm_context_t *)spdm_context)->connection_info.version,
                           SPDM_BIN_STR_0_LABEL, sizeof(SPDM_BIN_STR_0_LABEL) - 1,
                           NULL, (uint16_t)hash_size, hash_size, bin_str0, &bin_str0_size);
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
    case 0x1E: {
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested = 0;
        spdm_response->req_slot_id_param = 0;
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer = (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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

    case 0x1F: {
        spdm_key_exchange_response_t *spdm_response;
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
        signature_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        hmac_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        dhe_key_size = libspdm_get_dhe_pub_key_size(m_libspdm_use_dhe_algo);
        opaque_key_exchange_rsp_size =
            libspdm_get_opaque_data_version_selection_data_size(
                spdm_context);
        spdm_response_size = sizeof(spdm_key_exchange_response_t) +
                             dhe_key_size + 0 + sizeof(uint16_t) +
                             opaque_key_exchange_rsp_size + signature_size +
                             hmac_size;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        libspdm_zero_mem(spdm_response,spdm_response_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_KEY_EXCHANGE_RSP;
        spdm_response->header.param1 = 0;
        spdm_response->rsp_session_id =
            libspdm_allocate_rsp_session_id(spdm_context, false);
        spdm_response->mut_auth_requested =
            SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
        spdm_response->req_slot_id_param = 9;  /* Invalid SlotID */
        libspdm_get_random_number(SPDM_RANDOM_DATA_SIZE,
                                  spdm_response->random_data);
        ptr = (void *)(spdm_response + 1);
        dhe_context = libspdm_dhe_new(
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                m_libspdm_use_dhe_algo,
                true);
        libspdm_dhe_generate_key(m_libspdm_use_dhe_algo, dhe_context, ptr,
                                 &dhe_key_size);
        final_key_size = sizeof(final_key);
        libspdm_dhe_compute_key(
            m_libspdm_use_dhe_algo, dhe_context,
            (uint8_t *)&m_libspdm_local_buffer[0] +
            sizeof(spdm_key_exchange_request_t),
            dhe_key_size, final_key, &final_key_size);
        libspdm_dhe_free(m_libspdm_use_dhe_algo, dhe_context);
        ptr += dhe_key_size;
        /* libspdm_zero_mem (ptr, hash_size);
         * ptr += hash_size;*/
        *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_rsp_size;
        ptr += sizeof(uint16_t);
        libspdm_build_opaque_data_version_selection_data(
            spdm_context, &opaque_key_exchange_rsp_size, ptr);
        ptr += opaque_key_exchange_rsp_size;
        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
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
        cert_buffer =  (uint8_t *)data;
        cert_buffer_size = data_size;
        libspdm_hash_all(m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size,
                         cert_buffer_hash);
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
                SPDM_KEY_EXCHANGE_RSP,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, libspdm_get_managed_buffer(&th_curr),
                libspdm_get_managed_buffer_size(&th_curr), ptr,
                &signature_size);
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

static void libspdm_test_requester_key_exchange_err_case1(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
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
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
    free(data);
}

static void libspdm_test_requester_key_exchange_err_case2(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
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
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(session_id, 0xFFFFFFFF);
    assert_int_equal(
        libspdm_secured_message_get_session_state(
            spdm_context->session_info[0].secured_message_context),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
    free(data);
}

static void libspdm_test_requester_key_exchange_err_case3(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
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
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
    free(data);
}

static void libspdm_test_requester_key_exchange_err_case4(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
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
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
    free(data);
}

static void libspdm_test_requester_key_exchange_err_case5(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
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
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);
    free(data);
}

/**
 * Test 6: Requester / Responder do not support key exchange.
 * Expected Behavior: returns with error LIBSPDM_STATUS_UNSUPPORTED_CAP.
 **/
static void libspdm_test_requester_key_exchange_err_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t slot_id_param;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->local_context.capability.flags = 0;

    status = libspdm_send_receive_key_exchange(
        spdm_context, SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, NULL, &slot_id_param, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
}

static void libspdm_test_requester_key_exchange_err_case7(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
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
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
    free(data);
}

static void libspdm_test_requester_key_exchange_err_case8(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
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
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    free(data);
}

/**
 * Test 9: Unable to acquire the sender buffer.
 * Expected Behavior: returns with error LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void libspdm_test_requester_key_exchange_err_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t slot_id_param;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    libspdm_force_error (LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);
    status = libspdm_send_receive_key_exchange(
        spdm_context, SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, NULL, &slot_id_param, NULL);
    libspdm_release_error (LIBSPDM_ERR_ACQUIRE_SENDER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

static void libspdm_test_requester_key_exchange_err_case10(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint32_t session_id;
    uint8_t heartbeat_period;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t slot_id_param;
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
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
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

    error_code = LIBSPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
        libspdm_reset_message_a(spdm_context);

        heartbeat_period = 0;
        libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
        status = libspdm_send_receive_key_exchange (spdm_context,
                                                    SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                                    0, 0, &session_id, &heartbeat_period,
                                                    &slot_id_param, measurement_hash);
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

/**
 * Test 11: Unable to acquire the receiver buffer.
 * Expected Behavior: returns with error LIBSPDM_STATUS_ACQUIRE_FAIL.
 **/
static void libspdm_test_requester_key_exchange_err_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t slot_id_param;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xb;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    libspdm_force_error (LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);
    status = libspdm_send_receive_key_exchange(
        spdm_context, SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, NULL, &slot_id_param, NULL);
    libspdm_release_error (LIBSPDM_ERR_ACQUIRE_RECEIVER_BUFFER);

    assert_int_equal(status, LIBSPDM_STATUS_ACQUIRE_FAIL);
}

/**
 * Test 12: Version in response is incorrect.
 * Expected Behavior: returns with error LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_key_exchange_err_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t slot_id_param;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xc;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    status = libspdm_send_receive_key_exchange(
        spdm_context, SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, NULL, &slot_id_param, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 13: Response code is incorrect.
 * Expected Behavior: returns with error LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_key_exchange_err_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t slot_id_param;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xd;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    status = libspdm_send_receive_key_exchange(
        spdm_context, SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, NULL, &slot_id_param, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

/**
 * Test 14: Responder requests mutual authentication when it is not supported.
 * Expected Behavior: returns with error LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_key_exchange_err_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t slot_id_param;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xe;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    status = libspdm_send_receive_key_exchange(
        spdm_context, SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, NULL, &slot_id_param, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

static void libspdm_test_requester_key_exchange_err_case15(void **state)
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
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

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
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

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
        SPDM_KEY_EXCHANGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
    free(data);
}

static void libspdm_test_requester_key_exchange_err_case16(void **state)
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
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

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
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

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
        SPDM_KEY_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
    free(data);
}

static void libspdm_test_requester_key_exchange_err_case17(void **state)
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
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

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
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

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
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_SIZE);
    free(data);
}

static void libspdm_test_requester_key_exchange_err_case18(void **state)
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
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

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
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

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
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_VERIF_FAIL);
    free(data);
}

/**
 * Test 19:
 * Expected Behavior:
 **/
static void libspdm_test_requester_key_exchange_err_case19(void **state)
{
}

static void libspdm_test_requester_key_exchange_err_case20(void **state)
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
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;


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
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

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
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

/**
 * Test 21: OpaqueLength is larger than the recommended value.
 * Expected Behavior: Returns with LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_key_exchange_err_case21(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint32_t session_id;
    uint8_t slot_id_param;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    status = libspdm_send_receive_key_exchange(
        spdm_context, SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, NULL, &slot_id_param, NULL);

    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
}

static void libspdm_test_requester_key_exchange_err_case22(void **state)
{
}

static void libspdm_test_requester_key_exchange_err_case23(void **state)
{
}

static void libspdm_test_requester_key_exchange_err_case24(void **state)
{
}

static void libspdm_test_requester_key_exchange_err_case25(void **state)
{
}

static void libspdm_test_requester_key_exchange_err_case26(void **state)
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
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;


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
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

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
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    /* Clear Mut_auth flags */
    spdm_context->connection_info.capability.flags &=
        !SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;
    spdm_context->local_context.capability.flags &=
        !SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

static void libspdm_test_requester_key_exchange_err_case27(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0x1B;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;


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
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

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
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    /*Clear Mut_auth flags*/
    spdm_context->connection_info.capability.flags &=
        !SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;
    spdm_context->local_context.capability.flags &=
        !SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

static void libspdm_test_requester_key_exchange_err_case28(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0x1C;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;


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
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

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
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    /* Clear Mut_auth flags */
    spdm_context->connection_info.capability.flags &=
        !SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;
    spdm_context->local_context.capability.flags &=
        !SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

static void libspdm_test_requester_key_exchange_err_case29(void **state)
{
}

static void libspdm_test_requester_key_exchange_err_case30(void **state)
{
}

/**
 * Test 31: Fail case, Muth Auth requested bit 0 set, and SlotID is 9 in KEY_EXCHANGE_RSP response message,
 * but SlotID should be 0xF or between 0 and 7 inclusive.
 * Expected Behavior: returns a status of INVALID_MSG_FIELD.
 **/
static void libspdm_test_requester_key_exchange_err_case31(void **state)
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

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;

    if(spdm_context->session_info[0].session_id != INVALID_SESSION_ID) {
        libspdm_free_session_id(spdm_context,0xFFFFFFFF);
    }

    spdm_test_context->case_id = 0x1F;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;

    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;

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
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

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
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, 0, 0,
        &session_id, &heartbeat_period, &slot_id_param,
        measurement_hash);
    /* Clear Mut_auth flags */
    spdm_context->connection_info.capability.flags &=
        !SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;
    spdm_context->local_context.capability.flags &=
        !SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

static libspdm_test_context_t m_libspdm_requester_key_exchange_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_key_exchange_test_send_message,
    libspdm_requester_key_exchange_test_receive_message,
};

int libspdm_requester_key_exchange_error_test_main(void)
{
    const struct CMUnitTest spdm_requester_key_exchange_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case1),
        /* Successful response*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case2),
        /* connection_state check failed*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case3),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case4),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case5),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case6),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case7),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case8),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case9),
        /* Unexpected errors*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case10),
        /* Buffer reset*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case11),
        /* Measurement hash 1, returns a measurement hash*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case12),
        /* Measurement hash 1, returns a 0x00 array (no TCB components)*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case13),
        /* Measurement hash FF, returns a measurement_hash*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case14),
        /* Measurement hash 1, returns no measurement_hash*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case15),
        /* Measurement hash FF, returns no measurement_hash*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case16),
        /* Measurement hash not requested, returns a measurement_hash*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case17),
        /* Wrong signature*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case18),
        /* Can be populated with new test.*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case19),
        /* Heartbeat not supported, heartbeat period different from 0 sent*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case20),
        /* Heartbeat supported, heartbeat period different from 0 sent*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case21),
        /* Heartbeat supported, heartbeat period 0 sent NOTE: This should disable heartbeat*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case22),
        /* Muth Auth requested*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case23),
        /* Muth Auth requested with Encapsulated request*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case24),
        /* Muth Auth requested with implicit get digest*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case25),
        /* Muth Auth requested with Encapsulated request and bit 0 set*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case26),
        /* Muth Auth requested with implicit get digest and bit 0 set*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case27),
        /* Muth Auth requested with Encapsulated request and Muth Auth requested with implicit get digest simultaneously*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case28),
        /* Buffer verification*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case29),
        /* Successful response V1.2*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case30),
        /* Muth Auth requested bit 0 set, but Invalid SlotID in KEY_EXCHANGE_RSP response message*/
        cmocka_unit_test(libspdm_test_requester_key_exchange_err_case31),
    };

    libspdm_setup_test_context(&m_libspdm_requester_key_exchange_test_context);

    return cmocka_run_group_tests(spdm_requester_key_exchange_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/
