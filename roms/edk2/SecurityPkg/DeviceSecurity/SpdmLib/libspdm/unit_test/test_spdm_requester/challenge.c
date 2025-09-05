/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_M1M2_BUFFER_SIZE];

static size_t m_libspdm_opaque_data_size;
static uint8_t m_libspdm_opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];

static uint8_t m_requester_context[SPDM_REQ_CONTEXT_SIZE];

libspdm_return_t libspdm_requester_challenge_test_send_message(void *spdm_context,
                                                               size_t request_size,
                                                               const void *request,
                                                               uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    const uint8_t *ptr;

    spdm_test_context = libspdm_get_test_context();
    ptr = (const uint8_t *)request;
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_SEND_FAIL;
    case 0x2:
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer), &ptr[1],
                         request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
        return LIBSPDM_STATUS_SUCCESS;
    case 0x3:
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer), &ptr[1],
                         request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
        return LIBSPDM_STATUS_SUCCESS;
    case 0x4:
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer), &ptr[1],
                         request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
        return LIBSPDM_STATUS_SUCCESS;
    case 0x5:
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer), &ptr[1],
                         request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
        return LIBSPDM_STATUS_SUCCESS;
    case 0x6:
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer), &ptr[1],
                         request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
        return LIBSPDM_STATUS_SUCCESS;
    case 0x7:
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer), &ptr[1],
                         request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
        return LIBSPDM_STATUS_SUCCESS;
    case 0x8:
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer), &ptr[1],
                         request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
        return LIBSPDM_STATUS_SUCCESS;
    case 0x9: {
        static size_t sub_index = 0;
        if (sub_index == 0) {
            m_libspdm_local_buffer_size = 0;
            libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer), &ptr[1],
                             request_size - 1);
            m_libspdm_local_buffer_size += (request_size - 1);
            sub_index++;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0xA:
    case 0xB:
    case 0xC:
    case 0xD:
    case 0xE:
    case 0xF:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x15:
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer), &ptr[1],
                         request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
        return LIBSPDM_STATUS_SUCCESS;
    case 0x16: {
        /* arbitrary data must be inserted in the message buffer for computing
         * the response hash */
        m_libspdm_local_buffer_size = 0;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        libspdm_set_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size], 10, (uint8_t) 0xFF);
        m_libspdm_local_buffer_size += 10;
        libspdm_set_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size], 8, (uint8_t) 0xEE);
        m_libspdm_local_buffer_size += 8;
        libspdm_set_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size], 12, (uint8_t) 0xDD);
        m_libspdm_local_buffer_size += 12;
#endif
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) - m_libspdm_local_buffer_size,
                         &ptr[1], request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x17:
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer), &ptr[1],
                         request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
        return LIBSPDM_STATUS_SUCCESS;
    case 0x18:
    case 0x19:
    case 0x1A:
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer), &ptr[1],
                         request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1B:
    case 0x1C:
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer), &ptr[1],
                         request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t libspdm_requester_challenge_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x2: { /*correct CHALLENGE_AUTH message*/
        spdm_challenge_auth_response_t *spdm_response;
        void *data;
        size_t data_size;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        ((libspdm_context_t *)spdm_context)
        ->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t *)spdm_context)
        ->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 +
                             libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = (1 << 0);
        ptr = (void *)(spdm_response + 1);
        libspdm_hash_all(
            m_libspdm_use_hash_algo,
            ((libspdm_context_t *)spdm_context)
            ->local_context.local_cert_chain_provision[0],
            ((libspdm_context_t *)spdm_context)
            ->local_context
            .local_cert_chain_provision_size[0],
            ptr);
        free(data);
        ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        /* libspdm_zero_mem (ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
         * ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
        *(uint16_t *)ptr = 0;
        ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: { /*correct CHALLENGE_AUTH message*/
        spdm_challenge_auth_response_t *spdm_response;
        void *data;
        size_t data_size;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        ((libspdm_context_t *)spdm_context)
        ->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t *)spdm_context)
        ->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 +
                             libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = (1 << 0);
        ptr = (void *)(spdm_response + 1);
        libspdm_hash_all(
            m_libspdm_use_hash_algo,
            ((libspdm_context_t *)spdm_context)
            ->local_context.local_cert_chain_provision[0],
            ((libspdm_context_t *)spdm_context)
            ->local_context
            .local_cert_chain_provision_size[0],
            ptr);
        free(data);
        ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        /* libspdm_zero_mem (ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
         * ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
        *(uint16_t *)ptr = 0;
        ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x4: { /*correct ERROR message (invalid request)*/
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

    case 0x5: { /*correct ERROR message (busy)*/
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

    case 0x6: { /*correct ERROR message (busy) + correct CHALLENGE_AUTH message*/
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
            spdm_challenge_auth_response_t *spdm_response;
            void *data;
            size_t data_size;
            uint8_t *ptr;
            uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
            size_t sig_size;
            size_t spdm_response_size;
            size_t transport_header_size;

            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo, &data,
                &data_size, NULL, NULL);
            ((libspdm_context_t *)spdm_context)
            ->local_context
            .local_cert_chain_provision_size[0] = data_size;
            ((libspdm_context_t *)spdm_context)
            ->local_context.local_cert_chain_provision[0] =
                data;
            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_asym_algo =
                m_libspdm_use_asym_algo;
            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_hash_algo =
                m_libspdm_use_hash_algo;
            spdm_response_size =
                sizeof(spdm_challenge_auth_response_t) +
                libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 +
                libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_CHALLENGE_AUTH;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = (1 << 0);
            ptr = (void *)(spdm_response + 1);
            libspdm_hash_all(
                m_libspdm_use_hash_algo,
                ((libspdm_context_t *)spdm_context)
                ->local_context
                .local_cert_chain_provision[0],
                ((libspdm_context_t *)spdm_context)
                ->local_context
                .local_cert_chain_provision_size[0],
                ptr);
            free(data);
            ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
            libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
            ptr += SPDM_NONCE_SIZE;
            /* libspdm_zero_mem (ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
             * ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
            *(uint16_t *)ptr = 0;
            ptr += sizeof(uint16_t);
            libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                             sizeof(m_libspdm_local_buffer)
                             - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                                m_libspdm_local_buffer),
                             spdm_response,
                             (size_t)ptr - (size_t)spdm_response);
            m_libspdm_local_buffer_size +=
                ((size_t)ptr - (size_t)spdm_response);
            libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                             m_libspdm_local_buffer_size, hash_data);
            sig_size =
                libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
            libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
                spdm_context,
#endif
                spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                    SPDM_CHALLENGE_AUTH,
                    m_libspdm_use_asym_algo,
                    m_libspdm_use_hash_algo,
                    false, m_libspdm_local_buffer,
                    m_libspdm_local_buffer_size, ptr,
                    &sig_size);
            ptr += sig_size;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false, spdm_response_size,
                spdm_response, response_size, response);
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x7: { /*correct ERROR message (request resync)*/
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

    case 0x8: { /*correct ERROR message (response net ready)*/
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
        spdm_response->extend_error_data.request_code = SPDM_CHALLENGE;
        spdm_response->extend_error_data.token = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response,
                                              response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x9: { /*correct ERROR message (response not ready) + correct CHALLENGE_AUTH message*/
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
                SPDM_CHALLENGE;
            spdm_response->extend_error_data.token = 1;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
            sub_index2++;
        } else if (sub_index2 == 1) {
            spdm_challenge_auth_response_t *spdm_response;
            void *data;
            size_t data_size;
            uint8_t *ptr;
            uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
            size_t sig_size;
            size_t spdm_response_size;
            size_t transport_header_size;

            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo, &data,
                &data_size, NULL, NULL);
            ((libspdm_context_t *)spdm_context)
            ->local_context
            .local_cert_chain_provision_size[0] = data_size;
            ((libspdm_context_t *)spdm_context)
            ->local_context.local_cert_chain_provision[0] =
                data;
            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_asym_algo =
                m_libspdm_use_asym_algo;
            ((libspdm_context_t *)spdm_context)
            ->connection_info.algorithm.base_hash_algo =
                m_libspdm_use_hash_algo;
            spdm_response_size =
                sizeof(spdm_challenge_auth_response_t) +
                libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 +
                libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code =
                SPDM_CHALLENGE_AUTH;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = (1 << 0);
            ptr = (void *)(spdm_response + 1);
            libspdm_hash_all(
                m_libspdm_use_hash_algo,
                ((libspdm_context_t *)spdm_context)
                ->local_context
                .local_cert_chain_provision[0],
                ((libspdm_context_t *)spdm_context)
                ->local_context
                .local_cert_chain_provision_size[0],
                ptr);
            free(data);
            ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
            libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
            ptr += SPDM_NONCE_SIZE;
            /* libspdm_zero_mem (ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
             * ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
            *(uint16_t *)ptr = 0;
            ptr += sizeof(uint16_t);
            libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                             sizeof(m_libspdm_local_buffer)
                             - (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                                m_libspdm_local_buffer),
                             spdm_response,
                             (size_t)ptr - (size_t)spdm_response);
            m_libspdm_local_buffer_size +=
                ((size_t)ptr - (size_t)spdm_response);
            libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                             m_libspdm_local_buffer_size, hash_data);
            sig_size =
                libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
            libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
                spdm_context,
#endif
                spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                    SPDM_CHALLENGE_AUTH,
                    m_libspdm_use_asym_algo,
                    m_libspdm_use_hash_algo,
                    false, m_libspdm_local_buffer,
                    m_libspdm_local_buffer_size, ptr,
                    &sig_size);
            ptr += sig_size;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false, spdm_response_size,
                spdm_response, response_size, response);
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xA: /*correct CHALLENGE_AUTH message*/
    {
        spdm_challenge_auth_response_t  *spdm_response;
        void                          *data;
        size_t data_size;
        uint8_t                         *Ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data,
                                                         &data_size, NULL, NULL);
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size (m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE +
                             0 +
                             sizeof(uint16_t) + 0 +
                             libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = (1 << 0);
        Ptr = (void *)(spdm_response + 1);
        libspdm_hash_all (m_libspdm_use_hash_algo,
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[
                              0],
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[
                              0],
                          Ptr);
        free(data);
        Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);
        libspdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
        Ptr += SPDM_NONCE_SIZE;
        /* libspdm_zero_mem (Ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
         * Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
        *(uint16_t *)Ptr = 0;
        Ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response,
                         (size_t)Ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)Ptr - (size_t)spdm_response);
        libspdm_hash_all (m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                          m_libspdm_local_buffer_size, hash_data);
        sig_size = libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo, false, m_libspdm_local_buffer,
                m_libspdm_local_buffer_size, Ptr, &sig_size);
        Ptr += sig_size;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false, spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xB: /*CHALLENGE_AUTH message smaller than a SPDM header*/
    {
        spdm_challenge_auth_response_t  *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) - 1; /*smaller than standard message size*/

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = (1 << 0);

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false, spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xC: /*CHALLENGE_AUTH message with wrong version (1.0)*/
    {
        spdm_challenge_auth_response_t  *spdm_response;
        void                          *data;
        size_t data_size;
        uint8_t                         *Ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data,
                                                         &data_size, NULL, NULL);
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size (m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE +
                             libspdm_get_hash_size (m_libspdm_use_hash_algo) +
                             sizeof(uint16_t) + 0 +
                             libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10; /*wrong version*/
        spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = (1 << 0);
        Ptr = (void *)(spdm_response + 1);
        libspdm_hash_all (m_libspdm_use_hash_algo,
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[
                              0],
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[
                              0],
                          Ptr);
        free(data);
        Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);
        libspdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
        Ptr += SPDM_NONCE_SIZE;
        /* libspdm_zero_mem (Ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
         * Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
        *(uint16_t *)Ptr = 0;
        Ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response,
                         (size_t)Ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)Ptr - (size_t)spdm_response);
        libspdm_hash_all (m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                          m_libspdm_local_buffer_size, hash_data);
        sig_size = libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo, false, m_libspdm_local_buffer,
                m_libspdm_local_buffer_size, Ptr, &sig_size);
        Ptr += sig_size;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false, spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xD: /*SPDM (mostly CHALLENGE_AUTH) message with wrong response code (0x83)*/
    {
        spdm_challenge_auth_response_t  *spdm_response;
        void                          *data;
        size_t data_size;
        uint8_t                         *Ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data,
                                                         &data_size, NULL, NULL);
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size (m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE +
                             0 +
                             sizeof(uint16_t) + 0 +
                             libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CHALLENGE; /*wrong response code*/
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = (1 << 0);
        Ptr = (void *)(spdm_response + 1);
        libspdm_hash_all (m_libspdm_use_hash_algo,
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[
                              0],
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[
                              0],
                          Ptr);
        free(data);
        Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);
        libspdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
        Ptr += SPDM_NONCE_SIZE;
        /* libspdm_zero_mem (Ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
         * Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
        *(uint16_t *)Ptr = 0;
        Ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response,
                         (size_t)Ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)Ptr - (size_t)spdm_response);
        libspdm_hash_all (m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                          m_libspdm_local_buffer_size, hash_data);
        sig_size = libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo, false, m_libspdm_local_buffer,
                m_libspdm_local_buffer_size, Ptr, &sig_size);
        Ptr += sig_size;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false, spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xE: /*correct CHALLENGE_AUTH message with wrong slot number*/
    {
        spdm_challenge_auth_response_t  *spdm_response;
        void                          *data;
        size_t data_size;
        uint8_t                         *Ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data,
                                                         &data_size, NULL, NULL);
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size (m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE +
                             0 +
                             sizeof(uint16_t) + 0 +
                             libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = 1;
        spdm_response->header.param2 = (1 << 1); /*wrong slot number*/
        Ptr = (void *)(spdm_response + 1);
        libspdm_hash_all (m_libspdm_use_hash_algo,
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[
                              0],
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[
                              0],
                          Ptr);
        free(data);
        Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);
        libspdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
        Ptr += SPDM_NONCE_SIZE;
        /* libspdm_zero_mem (Ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
         * Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
        *(uint16_t *)Ptr = 0;
        Ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response,
                         (size_t)Ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)Ptr - (size_t)spdm_response);
        libspdm_hash_all (m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                          m_libspdm_local_buffer_size, hash_data);
        sig_size = libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo, false, m_libspdm_local_buffer,
                m_libspdm_local_buffer_size, Ptr, &sig_size);
        Ptr += sig_size;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false, spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xF: /*CHALLENGE_AUTH message with slot number overflow*/
    {
        spdm_challenge_auth_response_t  *spdm_response;
        void                          *data;
        size_t data_size;
        uint8_t                         *Ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data,
                                                         &data_size, NULL, NULL);
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size (m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE +
                             0 +
                             sizeof(uint16_t) + 0 +
                             libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = 8; /*slot number overflow*/
        spdm_response->header.param2 = (1 << 0);
        Ptr = (void *)(spdm_response + 1);
        libspdm_hash_all (m_libspdm_use_hash_algo,
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[
                              0],
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[
                              0],
                          Ptr);
        free(data);
        Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);
        libspdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
        Ptr += SPDM_NONCE_SIZE;
        /* libspdm_zero_mem (Ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
         * Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
        *(uint16_t *)Ptr = 0;
        Ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response,
                         (size_t)Ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)Ptr - (size_t)spdm_response);
        libspdm_hash_all (m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                          m_libspdm_local_buffer_size, hash_data);
        sig_size = libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo, false, m_libspdm_local_buffer,
                m_libspdm_local_buffer_size, Ptr, &sig_size);
        Ptr += sig_size;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false, spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x10: /*correct CHALLENGE_AUTH message with "libspdm" opaque data*/
    {
        spdm_challenge_auth_response_t  *spdm_response;
        void                          *data;
        size_t data_size;
        uint8_t                         *Ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data,
                                                         &data_size, NULL, NULL);
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size (m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE +
                             0 +
                             sizeof(uint16_t) + 8 +
                             libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = (1 << 0);
        Ptr = (void *)(spdm_response + 1);
        libspdm_hash_all (m_libspdm_use_hash_algo,
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[
                              0],
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[
                              0],
                          Ptr);
        free(data);
        Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);
        libspdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
        Ptr += SPDM_NONCE_SIZE;
        /* libspdm_zero_mem (Ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
         * Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
        *(uint16_t *)Ptr = (uint16_t)strlen("libspdm");
        Ptr += sizeof(uint16_t);
        libspdm_copy_mem(Ptr, (size_t)(*response) + *response_size - (size_t)Ptr, "libspdm",
                         strlen("libspdm"));
        Ptr += strlen("libspdm");
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response,
                         (size_t)Ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)Ptr - (size_t)spdm_response);
        libspdm_hash_all (m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                          m_libspdm_local_buffer_size, hash_data);
        sig_size = libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo, false, m_libspdm_local_buffer,
                m_libspdm_local_buffer_size, Ptr, &sig_size);
        Ptr += sig_size;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false, spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x11: /*correct CHALLENGE_AUTH message with invalid signature*/
    {
        spdm_challenge_auth_response_t  *spdm_response;
        void                          *data;
        size_t data_size;
        uint8_t                         *Ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data,
                                                         &data_size, NULL, NULL);
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size (m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE +
                             0 +
                             sizeof(uint16_t) + 0 +
                             libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = (1 << 0);
        Ptr = (void *)(spdm_response + 1);
        libspdm_hash_all (m_libspdm_use_hash_algo,
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[
                              0],
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[
                              0],
                          Ptr);
        free(data);
        Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);
        libspdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
        Ptr += SPDM_NONCE_SIZE;
        /* libspdm_zero_mem (Ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
         * Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
        *(uint16_t *)Ptr = 0;
        Ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response,
                         (size_t)Ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)Ptr - (size_t)spdm_response);
        libspdm_hash_all (m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                          m_libspdm_local_buffer_size, hash_data);
        libspdm_hash_all (m_libspdm_use_hash_algo, hash_data, libspdm_get_hash_size (
                              m_libspdm_use_hash_algo), hash_data);
        sig_size = libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo, false, hash_data, libspdm_get_hash_size (
                m_libspdm_use_hash_algo), Ptr, &sig_size);
        Ptr += sig_size;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false, spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x12: /*correct CHALLENGE_AUTH message*/
    case 0x13: /*correct CHALLENGE_AUTH message*/
    {
        spdm_challenge_auth_response_t  *spdm_response;
        void                          *data;
        size_t data_size;
        uint8_t                         *Ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data,
                                                         &data_size, NULL, NULL);
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size (m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE +
                             libspdm_get_hash_size (m_libspdm_use_hash_algo) +
                             sizeof(uint16_t) + 0 +
                             libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = (1 << 0);
        Ptr = (void *)(spdm_response + 1);
        libspdm_hash_all (m_libspdm_use_hash_algo,
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[
                              0],
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[
                              0],
                          Ptr);
        free(data);
        Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);
        libspdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
        Ptr += SPDM_NONCE_SIZE;
        libspdm_zero_mem (Ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
        Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);
        *(uint16_t *)Ptr = 0;
        Ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response,
                         (size_t)Ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)Ptr - (size_t)spdm_response);
        libspdm_hash_all (m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                          m_libspdm_local_buffer_size, hash_data);
        sig_size = libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo, false, m_libspdm_local_buffer,
                m_libspdm_local_buffer_size, Ptr, &sig_size);
        Ptr += sig_size;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false, spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x14:
    {
        static uint16_t error_code = LIBSPDM_ERROR_CODE_RESERVED_00;

        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        if(error_code <= 0xff) {
            spdm_response_size = sizeof(spdm_error_response_t);
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

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

    case 0x15: /*correct CHALLENGE_AUTH message with multiple slot numbers */
    {
        spdm_challenge_auth_response_t  *spdm_response;
        void                          *data;
        size_t data_size;
        uint8_t                       *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data,
                                                         &data_size, NULL, NULL);
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size (m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE +
                             0 +
                             sizeof(uint16_t) + 0 +
                             libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0x71; /*multiple slot numbers */
        ptr = (void *)(spdm_response + 1);
        libspdm_hash_all (m_libspdm_use_hash_algo,
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[
                              0],
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[
                              0],
                          ptr);
        free(data);
        ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);
        libspdm_get_random_number (SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        *(uint16_t *)ptr = 0;
        ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response,
                         (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        libspdm_hash_all (m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                          m_libspdm_local_buffer_size, hash_data);
        sig_size = libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo, false, m_libspdm_local_buffer,
                m_libspdm_local_buffer_size, ptr, &sig_size);
        ptr += sig_size;
        libspdm_transport_test_encode_message (spdm_context, NULL, false, false, spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x16: { /*correct CHALLENGE_AUTH message*/
        spdm_challenge_auth_response_t *spdm_response;
        void *data;
        size_t data_size;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data,
                                                         &data_size, NULL, NULL);
        ((libspdm_context_t *)spdm_context)->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t *)spdm_context)->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t *)spdm_context)->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 +
                             libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = (1 << 0);
        ptr = (void *)(spdm_response + 1);
        libspdm_hash_all(m_libspdm_use_hash_algo,
                         ((libspdm_context_t *)spdm_context)
                         ->local_context.local_cert_chain_provision[0],
                         ((libspdm_context_t *)spdm_context)
                         ->local_context.local_cert_chain_provision_size[0],
                         ptr);
        free(data);
        ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        /* libspdm_zero_mem (ptr, spdm_get_hash_size (m_libspdm_use_hash_algo));
         * ptr += spdm_get_hash_size (m_libspdm_use_hash_algo);*/
        *(uint16_t *)ptr = 0;
        ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) - m_libspdm_local_buffer_size,
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(hash_data, libspdm_get_hash_size(m_libspdm_use_hash_algo));
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version <<
                SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x17: { /*correct CHALLENGE_AUTH message*/
        spdm_challenge_auth_response_t *spdm_response;
        void *data;
        size_t data_size;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;
        static uint8_t slot_id = 0;

        if (slot_id == 0) {
            libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                            m_libspdm_use_asym_algo, &data,
                                                            &data_size, NULL, NULL);
        } else {
            libspdm_read_responder_public_certificate_chain_per_slot(1,
                                                                     m_libspdm_use_hash_algo,
                                                                     m_libspdm_use_asym_algo, &data,
                                                                     &data_size, NULL, NULL);
        }
        ((libspdm_context_t *)spdm_context)
        ->local_context.local_cert_chain_provision_size[slot_id] =
            data_size;
        ((libspdm_context_t *)spdm_context)
        ->local_context.local_cert_chain_provision[slot_id] = data;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 +
                             libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = slot_id & 0xF;
        spdm_response->header.param2 = (1 << slot_id);
        ptr = (void *)(spdm_response + 1);
        libspdm_hash_all(
            m_libspdm_use_hash_algo,
            ((libspdm_context_t *)spdm_context)
            ->local_context.local_cert_chain_provision[slot_id],
            ((libspdm_context_t *)spdm_context)
            ->local_context
            .local_cert_chain_provision_size[slot_id],
            ptr);
        free(data);
        ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        /* libspdm_zero_mem (ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
         * ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
        *(uint16_t *)ptr = 0;
        ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
        slot_id++;
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x18: { /* correct CHALLENGE_AUTH message using slot 0xFF */
        spdm_challenge_auth_response_t *spdm_response;
        void *data;
        size_t data_size;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_responder_public_key(m_libspdm_use_asym_algo, &data, &data_size);
        ((libspdm_context_t *)spdm_context)
        ->local_context.local_public_key_provision_size = data_size;
        ((libspdm_context_t *)spdm_context)
        ->local_context.local_public_key_provision = data;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 +
                             libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code =
            SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = 0x0F;
        spdm_response->header.param2 = 0;
        ptr = (void *)(spdm_response + 1);
        libspdm_hash_all(
            m_libspdm_use_hash_algo,
            ((libspdm_context_t *)spdm_context)
            ->local_context.local_public_key_provision,
            ((libspdm_context_t *)spdm_context)
            ->local_context
            .local_public_key_provision_size,
            ptr);
        free(data);
        ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        /* libspdm_zero_mem (ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
         * ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
        *(uint16_t *)ptr = 0;
        ptr += sizeof(uint16_t);
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x19: /*CHALLENGE_AUTH message contains opaque_length greater than the maximum allowed*/
    {
        spdm_challenge_auth_response_t  *spdm_response;
        void                          *data;
        size_t data_size;
        uint8_t                         *Ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t opaque_length;
        opaque_length = SPDM_MAX_OPAQUE_DATA_SIZE + 1;  /*opaque_length greater than the maximum allowed*/

        libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data,
                                                         &data_size, NULL, NULL);
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size (m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE +
                             0 +
                             sizeof(uint16_t) +
                             opaque_length +
                             libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
        spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = (1 << 0);
        Ptr = (void *)(spdm_response + 1);
        libspdm_hash_all (m_libspdm_use_hash_algo,
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[
                              0],
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[
                              0],
                          Ptr);
        free(data);
        Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);
        libspdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
        Ptr += SPDM_NONCE_SIZE;
        /* libspdm_zero_mem (Ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
         * Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
        *(uint16_t *)Ptr = opaque_length;
        Ptr += sizeof(uint16_t);
        libspdm_set_mem(Ptr, opaque_length, 255);
        Ptr += opaque_length;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response,
                         (size_t)Ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)Ptr - (size_t)spdm_response);
        libspdm_hash_all (m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                          m_libspdm_local_buffer_size, hash_data);
        sig_size = libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo, false, m_libspdm_local_buffer,
                m_libspdm_local_buffer_size, Ptr, &sig_size);
        Ptr += sig_size;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false, spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1A:
    {
        spdm_challenge_auth_response_t  *spdm_response;
        spdm_general_opaque_data_table_header_t
        *spdm_general_opaque_data_table_header;
        opaque_element_table_header_t
        *opaque_element_table_header;
        void *data;
        size_t data_size;
        uint8_t *Ptr;
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint8_t element_num;
        uint8_t element_index;
        size_t current_element_len;
        uint16_t opaque_element_data_len;

        libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                         m_libspdm_use_asym_algo,
                                                         &data,
                                                         &data_size, NULL, NULL);
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t*)spdm_context)->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;


        spdm_general_opaque_data_table_header = (void *)m_libspdm_opaque_data;
        spdm_general_opaque_data_table_header->total_elements = 4;
        opaque_element_table_header = (void *)(spdm_general_opaque_data_table_header + 1);

        element_num = spdm_general_opaque_data_table_header->total_elements;
        m_libspdm_opaque_data_size = sizeof(spdm_general_opaque_data_table_header_t);

        for (element_index = 0; element_index < element_num; element_index++) {
            opaque_element_table_header->id = SPDM_REGISTRY_ID_MAX;
            opaque_element_table_header->vendor_len = 0;
            opaque_element_data_len = (uint16_t)strlen("libspdm");;

            Ptr = (void *)(opaque_element_table_header + 1);
            Ptr += opaque_element_table_header->vendor_len;

            libspdm_copy_mem((uint16_t *)Ptr,
                             sizeof(opaque_element_data_len),
                             &opaque_element_data_len,
                             sizeof(opaque_element_data_len));

            libspdm_copy_mem(Ptr + sizeof(opaque_element_data_len),
                             SPDM_MAX_OPAQUE_DATA_SIZE -
                             sizeof(opaque_element_table_header_t), "libspdm",
                             strlen("libspdm"));

            current_element_len = sizeof(opaque_element_table_header_t) +
                                  opaque_element_table_header->vendor_len +
                                  sizeof(opaque_element_data_len) +
                                  opaque_element_data_len;
            current_element_len = (current_element_len + 3) & ~3;

            /*move to next element*/
            opaque_element_table_header =
                (opaque_element_table_header_t *)
                ((uint8_t *)opaque_element_table_header +
                 current_element_len);

            m_libspdm_opaque_data_size += current_element_len;
        }

        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size (m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE +
                             0 +
                             sizeof(uint16_t) + m_libspdm_opaque_data_size +
                             libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = (1 << 0);
        Ptr = (void *)(spdm_response + 1);
        libspdm_hash_all (m_libspdm_use_hash_algo,
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision[
                              0],
                          ((libspdm_context_t*)spdm_context)->local_context.local_cert_chain_provision_size[
                              0],
                          Ptr);
        free(data);
        Ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);
        libspdm_get_random_number (SPDM_NONCE_SIZE, Ptr);
        Ptr += SPDM_NONCE_SIZE;
        *(uint16_t *)Ptr = (uint16_t)m_libspdm_opaque_data_size;
        Ptr += sizeof(uint16_t);
        libspdm_copy_mem(Ptr, (size_t)(*response) + *response_size - (size_t)Ptr,
                         m_libspdm_opaque_data,
                         m_libspdm_opaque_data_size);
        Ptr += m_libspdm_opaque_data_size;

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response,
                         (size_t)Ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)Ptr - (size_t)spdm_response);
        sig_size = libspdm_get_asym_signature_size (m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo, false, m_libspdm_local_buffer,
                m_libspdm_local_buffer_size, Ptr, &sig_size);
        Ptr += sig_size;

        libspdm_transport_test_encode_message (spdm_context, NULL, false, false, spdm_response_size,
                                               spdm_response, response_size, response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1B: {
        spdm_challenge_auth_response_t *spdm_response;
        void *data;
        size_t data_size;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint8_t slot_id = 0;

        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        ((libspdm_context_t *)spdm_context)
        ->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t *)spdm_context)
        ->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 +
                             libspdm_get_asym_signature_size(m_libspdm_use_asym_algo) +
                             SPDM_REQ_CONTEXT_SIZE;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code =
            SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = slot_id;
        spdm_response->header.param2 = (1 << slot_id);
        ptr = (void *)(spdm_response + 1);
        libspdm_hash_all(
            m_libspdm_use_hash_algo,
            ((libspdm_context_t *)spdm_context)
            ->local_context.local_cert_chain_provision[slot_id],
            ((libspdm_context_t *)spdm_context)
            ->local_context
            .local_cert_chain_provision_size[slot_id],
            ptr);
        free(data);
        ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        *(uint16_t *)ptr = 0;
        ptr += sizeof(uint16_t);
        libspdm_copy_mem(ptr, SPDM_REQ_CONTEXT_SIZE, m_requester_context, SPDM_REQ_CONTEXT_SIZE);
        ptr += SPDM_REQ_CONTEXT_SIZE;
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1C: {
        spdm_challenge_auth_response_t *spdm_response;
        void *data;
        size_t data_size;
        uint8_t *ptr;
        uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
        size_t sig_size;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint8_t slot_id = 0;

        libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                        m_libspdm_use_asym_algo, &data,
                                                        &data_size, NULL, NULL);
        ((libspdm_context_t *)spdm_context)
        ->local_context.local_cert_chain_provision_size[0] =
            data_size;
        ((libspdm_context_t *)spdm_context)
        ->local_context.local_cert_chain_provision[0] = data;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_asym_algo =
            m_libspdm_use_asym_algo;
        ((libspdm_context_t *)spdm_context)
        ->connection_info.algorithm.base_hash_algo =
            m_libspdm_use_hash_algo;
        spdm_response_size = sizeof(spdm_challenge_auth_response_t) +
                             libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                             SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 +
                             libspdm_get_asym_signature_size(m_libspdm_use_asym_algo) +
                             SPDM_REQ_CONTEXT_SIZE;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code =
            SPDM_CHALLENGE_AUTH;
        spdm_response->header.param1 = slot_id;
        spdm_response->header.param2 = (1 << slot_id);
        ptr = (void *)(spdm_response + 1);
        libspdm_hash_all(
            m_libspdm_use_hash_algo,
            ((libspdm_context_t *)spdm_context)
            ->local_context.local_cert_chain_provision[slot_id],
            ((libspdm_context_t *)spdm_context)
            ->local_context
            .local_cert_chain_provision_size[slot_id],
            ptr);
        free(data);
        ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
        libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
        ptr += SPDM_NONCE_SIZE;
        *(uint16_t *)ptr = 0;
        ptr += sizeof(uint16_t);
        libspdm_get_random_number(SPDM_REQ_CONTEXT_SIZE,ptr);
        ptr += SPDM_REQ_CONTEXT_SIZE;

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) -
                         (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] -
                          m_libspdm_local_buffer),
                         spdm_response, (size_t)ptr - (size_t)spdm_response);
        m_libspdm_local_buffer_size += ((size_t)ptr - (size_t)spdm_response);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer_size (0x%zx):\n",
                       m_libspdm_local_buffer_size));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        libspdm_hash_all(m_libspdm_use_hash_algo, m_libspdm_local_buffer,
                         m_libspdm_local_buffer_size, hash_data);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HashDataSize (0x%x):\n",
                       libspdm_get_hash_size(m_libspdm_use_hash_algo)));
        libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
        sig_size = libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
        libspdm_responder_data_sign(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
            spdm_context,
#endif
            spdm_response->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT,
                SPDM_CHALLENGE_AUTH,
                m_libspdm_use_asym_algo, m_libspdm_use_hash_algo,
                false, m_libspdm_local_buffer, m_libspdm_local_buffer_size,
                ptr, &sig_size);
        ptr += sig_size;

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

/**
 * Test 1: when no CHALLENGE_AUTH message is received, and the client returns a
 * device error.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_challenge_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge(
        spdm_context, NULL, 0,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        measurement_hash, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 2: the requester is setup correctly to send a CHALLENGE message:
 * - it has flags indicating that the previous messages were sent
 * (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
 * - it received the CAPABILITIES message, allowing the use of hash and digital
 * signature algorithms, and the use of challenges.
 * - it has the responder's certificate chain.
 * The CHALLENGE message requests usage of the first certificate in the chain
 * (param1=0) and do not request measurements (param2=0).
 * The received CHALLENGE_AUTH message correctly responds to the challenge, with
 * no opaque data and a signature on the sent nonce.
 * Expected behavior: client returns a status of RETURN_SUCCESS.
 **/
void libspdm_test_requester_challenge_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge(
        spdm_context, NULL, 0,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        measurement_hash, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /* Completion of CHALLENGE sets M1/M2 to null. */
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
#else
    assert_null(spdm_context->transcript.digest_context_m1m2);
#endif
    free(data);
}

/**
 * Test 3: the requester is not setup correctly to send a CHALLENGE message:
 * - it has *no* flags indicating that the previous messages were sent
 * (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, GET_DIGESTS); but
 * - it received the CAPABILITIES message, allowing the use of hash and digital
 * signature algorithms, and the use of challenges.
 * - it has the responder's certificate chain.
 * The CHALLENGE message requests usage of the first certificate in the chain
 * (param1=0) and do not request measurements (param2=0).
 * The received CHALLENGE_AUTH message correctly responds to the challenge, with
 * no opaque data and a signature on the sent nonce.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR, and the "C"
 * transcript buffer is not set.
 **/
void libspdm_test_requester_challenge_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge(
        spdm_context, NULL, 0,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        measurement_hash, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 4: the requester is setup correctly (see Test 2), but receives an ERROR
 * message indicating InvalidParameters.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR, and the "C"
 * transcript buffer is reset.
 **/
void libspdm_test_requester_challenge_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge(
        spdm_context, NULL, 0,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        measurement_hash, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 5: the requester is setup correctly (see Test 2), but receives an ERROR
 * message indicating the Busy status of the responder.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR, and the "C"
 * transcript buffer is reset.
 **/
void libspdm_test_requester_challenge_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge(
        spdm_context, NULL, 0,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        measurement_hash, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 6: the requester is setup correctly (see Test 2), but, on the first try,
 * receiving a Busy ERROR message, and on retry, receiving a correct CHALLENGE_AUTH
 * message to the challenge, with no opaque data and a signature on the sent nonce.
 * Expected behavior: client returns a status of RETURN_SUCCESS.
 **/
void libspdm_test_requester_challenge_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->retry_times = 3;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge(
        spdm_context, NULL, 0,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        measurement_hash, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    free(data);
}

/**
 * Test 7: the requester is setup correctly (see Test 2), but receives an ERROR
 * message indicating the RequestResynch status of the responder.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR, the "C"
 * transcript buffer is reset, and the communication is reset to expect a new
 * GET_VERSION message.
 **/
void libspdm_test_requester_challenge_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge(
        spdm_context, NULL, 0,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        measurement_hash, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 8: the requester is setup correctly (see Test 2), but receives an ERROR
 * message indicating the ResponseNotReady status of the responder.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR, and the "C"
 * buffer stores nothing.
 **/
void libspdm_test_requester_challenge_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
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

    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));

    status = libspdm_challenge(
        spdm_context, NULL, 0,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        measurement_hash, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal (spdm_context->transcript.message_c.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 9: the requester is setup correctly (see Test 2), but, on the first try,
 * receiving a ResponseNotReady ERROR message, and on retry, receiving a correct
 * CHALLENGE_AUTH message to the challenge, with no opaque data and a signature
 * on the sent nonce.
 * Expected behavior: client returns a status of RETURN_SUCCESS.
 **/
void libspdm_test_requester_challenge_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = data_size;
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

    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge(
        spdm_context, NULL, 0,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        measurement_hash, NULL);
    if (LIBSPDM_RESPOND_IF_READY_SUPPORT) {
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    } else {
        assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    }
    free(data);
}

/**
 * Test 10: the requester is not setup correctly to send a CHALLENGE message.
 * Specifically, it has *not* received the capability for challenge, although it
 * has received capability for executing both hash and signature algorithms.
 * The remaining setup and message exchange were executed correctly (see Test 2).
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR, and the "C"
 * transcript buffer is not set.
 **/
void libspdm_test_requester_challenge_case10(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    /* spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;*/
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem (measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge (spdm_context, NULL, 0,
                                SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                measurement_hash, NULL);
    assert_int_equal (status, LIBSPDM_STATUS_UNSUPPORTED_CAP);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal (spdm_context->transcript.message_c.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 11: the requester is setup correctly (see Test 2), but receives a malformed
 * response message, smaller then a standard SPDM message header.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR,.
 **/
void libspdm_test_requester_challenge_case11(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem (measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge (spdm_context, NULL, 0,
                                SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                measurement_hash, NULL);
    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

/**
 * Test 12: the requester is setup correctly (see Test 2), but receives a malformed
 * response message, with version (1.0) different from the request (1.1).
 * The remaining message data is as a correct CHALLENGE_AUTH message.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_challenge_case12(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem (measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge (spdm_context, NULL, 0,
                                SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                measurement_hash, NULL);
    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

/**
 * Test 13: the requester is setup correctly (see Test 2), but receives a malformed
 * response message, with wrong request_response_code (CHALLENGE 0x83 instead of
 * CHALLENGE_AUTH 0x03).
 * The remaining message data is as a correct CHALLENGE_AUTH message.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_challenge_case13(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem (measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge (spdm_context, NULL, 0,
                                SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                measurement_hash, NULL);
    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

/**
 * Test 14: the requester is setup correctly (see Test 2), but receives a malformed
 * response message, with a slot number different from the requested.
 * The remaining message data is as a correct CHALLENGE_AUTH message.
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_challenge_case14(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem (measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge (spdm_context, NULL, 0,
                                SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                measurement_hash, NULL);
    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

/**
 * Test 15: free to be populated by test.
 **/
void libspdm_test_requester_challenge_case15(void **state) {
}

/**
 * Test 16: the requester is setup correctly to send a CHALLENGE message:
 * - it has flags indicating that the previous messages were sent
 * (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
 * - it received the CAPABILITIES message, allowing the use of hash and digital
 * signature algorithms, and the use of challenges.
 * - it has the responder's certificate chain.
 * The CHALLENGE message requests usage of the first certificate in the chain
 * (param1=0) and do not request measurements (param2=0).
 * The received CHALLENGE_AUTH message correctly responds to the challenge, opaque
 * data with bytes from the string "libspdm", and a signature on the sent nonce.
 * Expected behavior: client returns a status of RETURN_SUCCESS.
 **/
void libspdm_test_requester_challenge_case16(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    size_t opaque_data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    opaque_data_size = sizeof(opaque_data);

    libspdm_zero_mem (measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge_ex (spdm_context, NULL, 0,
                                   SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                   measurement_hash, NULL, NULL, NULL, NULL,
                                   opaque_data, &opaque_data_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(opaque_data_size, strlen("libspdm"));
    assert_memory_equal(opaque_data, "libspdm", opaque_data_size);
    free(data);
}

/**
 * Test 17: the requester is setup correctly to send a CHALLENGE message:
 * - it has flags indicating that the previous messages were sent
 * (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
 * - it received the CAPABILITIES message, allowing the use of hash and digital
 * signature algorithms, and the use of challenges.
 * - it has the responder's certificate chain.
 * The CHALLENGE message requests usage of the first certificate in the chain
 * (param1=0) and do not request measurements (param2=0).
 * The received CHALLENGE_AUTH message correctly responds to the challenge,
 * but with an invalid signature.
 * Expected behavior: client returns a status of RETURN_SECURITY_VIOLATION.
 **/
void libspdm_test_requester_challenge_case17(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem (measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge (spdm_context, NULL, 0,
                                SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                measurement_hash, NULL);
    assert_int_equal (status, LIBSPDM_STATUS_VERIF_FAIL);
    free(data);
}

/**
 * Test 18: the requester is setup correctly to send a CHALLENGE message:
 * - it has flags indicating that the previous messages were sent
 * (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
 * - it received the CAPABILITIES message, allowing the use of hash and digital
 * signature algorithms, the use of challenges, and of measurements.
 * - it has the responder's certificate chain.
 * The CHALLENGE message requests usage of the first certificate in the chain
 * (param1=0) and request TCB measurements (param2=1).
 * The received CHALLENGE_AUTH message correctly responds to the challenge, with
 * no opaque data and a signature on the sent nonce.
 * Expected behavior: client returns a status of RETURN_SUCCESS.
 **/
void libspdm_test_requester_challenge_case18(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP; /*additional measurement capability*/
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem (measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge (spdm_context, NULL, 0,
                                SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH,
                                measurement_hash, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 19: the requester is setup correctly to send a CHALLENGE message:
 * - it has flags indicating that the previous messages were sent
 * (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
 * - it received the CAPABILITIES message, allowing the use of hash and digital
 * signature algorithms, the use of challenges, and of measurements.
 * - it has the responder's certificate chain.
 * The CHALLENGE message requests usage of the first certificate in the chain
 * (param1=0) and request TCB measurements (param2=1).
 * The received CHALLENGE_AUTH message correctly responds to the challenge, with
 * no opaque data and a signature on the sent nonce.
 * Expected behavior: client returns a status of RETURN_SUCCESS.
 **/
void libspdm_test_requester_challenge_case19(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP; /*additional measurement capability*/
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem (measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge (spdm_context, NULL, 0,
                                SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH,
                                measurement_hash, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
}

/**
 * Test 20: receiving an unexpected ERROR message from the responder.
 * There are tests for all named codes, including some reserved ones
 * (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
 * However, for having specific test cases, it is excluded from this case:
 * Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
 * Expected behavior: client returns a status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_challenge_case20(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;
    uint16_t error_code;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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
        libspdm_reset_message_b(spdm_context);
        libspdm_reset_message_c(spdm_context);

        libspdm_zero_mem (measurement_hash, sizeof(measurement_hash));
        status = libspdm_challenge (spdm_context, NULL, 0,
                                    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                    measurement_hash, NULL);
        LIBSPDM_ASSERT_INT_EQUAL_CASE (status, LIBSPDM_STATUS_ERROR_PEER, error_code);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        /* assert_int_equal (spdm_context->transcript.message_c.buffer_size, 0);*/
        LIBSPDM_ASSERT_INT_EQUAL_CASE (spdm_context->transcript.message_c.buffer_size, 0,
                                       error_code);
#endif

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
 * Test 21: test correct CHALLENGE_AUTH message with multiple slot numbers
 * Expected behavior: success and slot_id is included in slot_mask.
 **/
void libspdm_test_requester_challenge_case21(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;
    uint8_t slot_id;
    uint8_t slot_mask;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
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

    libspdm_zero_mem (measurement_hash, sizeof(measurement_hash));

    slot_id = 0;
    status = libspdm_challenge (spdm_context, NULL, slot_id,
                                SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                measurement_hash, &slot_mask);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(1<<slot_id, slot_mask & (1<<slot_id));
    free(data);
}

/**
 * Test 22: a request message is successfully sent and a response message is successfully received.
 * Buffer C already has arbitrary data.
 * Expected Behavior: requester returns the status RETURN_SUCCESS and a CHALLENGE_AUTH message is
 * received, buffer C appends the exchanged CHALLENGE and CHALLENGE_AUTH messages.
 **/
void libspdm_test_requester_challenge_case22(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /*filling all buffers with arbitrary data*/
    libspdm_set_mem(spdm_context->transcript.message_a.buffer, 10, (uint8_t) 0xFF);
    spdm_context->transcript.message_a.buffer_size = 10;
    libspdm_set_mem(spdm_context->transcript.message_b.buffer, 8, (uint8_t) 0xEE);
    spdm_context->transcript.message_b.buffer_size = 8;
    libspdm_set_mem(spdm_context->transcript.message_c.buffer, 12, (uint8_t) 0xDD);
    spdm_context->transcript.message_c.buffer_size = 12;
#endif

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge(
        spdm_context, NULL, 0,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        measurement_hash, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer (0x%x):\n",
                   m_libspdm_local_buffer_size));
    libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
#endif
    free(data);
}

/**
 * Test 23: GetCert (Slot 0), GetCert (Slot 1), then Challenge (Slot 0), (Slot1):
 * - it has flags indicating that the previous messages were sent
 * (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
 * - it received the CAPABILITIES message, allowing the use of hash and digital
 * signature algorithms, and the use of challenges.
 * - it has the responder's certificate chain.
 * The CHALLENGE message requests usage of the first certificate in the chain
 * (param1=0) and do not request measurements (param2=0).
 * The received CHALLENGE_AUTH message correctly responds to the challenge, with
 * no opaque data and a signature on the sent nonce.
 * Expected behavior: client returns a status of RETURN_SUCCESS.
 **/
void libspdm_test_requester_challenge_case23(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    void *data1;
    size_t data_size;
    size_t data1_size;
    void *hash;
    void *hash1;
    size_t hash_size;
    size_t hash1_size;
    uint8_t slot_id;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;

    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
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

    libspdm_read_responder_public_certificate_chain_per_slot(
        1,
        m_libspdm_use_hash_algo,
        m_libspdm_use_asym_algo, &data1,
        &data1_size, &hash1, &hash1_size);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[1].buffer_size =
        data1_size;
    libspdm_copy_mem(spdm_context->connection_info.peer_used_cert_chain[1].buffer,
                     sizeof(spdm_context->connection_info.peer_used_cert_chain[1].buffer),
                     data1, data1_size);
#else
    libspdm_hash_all(
        spdm_context->connection_info.algorithm.base_hash_algo,
        data1, data1_size,
        spdm_context->connection_info.peer_used_cert_chain[1].buffer_hash);
    spdm_context->connection_info.peer_used_cert_chain[1].buffer_hash_size =
        libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo);
    libspdm_get_leaf_cert_public_key_from_cert_chain(
        spdm_context->connection_info.algorithm.base_hash_algo,
        spdm_context->connection_info.algorithm.base_asym_algo,
        data1, data1_size,
        &spdm_context->connection_info.peer_used_cert_chain[1].leaf_cert_public_key);
#endif

    for (slot_id = 0; slot_id < 2; slot_id++) {
        libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
        status = libspdm_challenge(
            spdm_context, NULL, slot_id,
            SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
            measurement_hash, NULL);
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    }
    free(data);
    free(data1);
}

/**
 * Test 24: Challenge using provisioned public key (slot_id 0xFF)
 * Expected behavior: client returns a status of RETURN_SUCCESS.
 **/
void libspdm_test_requester_challenge_case24(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP;
    libspdm_read_responder_public_key(m_libspdm_use_asym_algo, &data, &data_size);
    spdm_context->local_context.peer_public_key_provision = data;
    spdm_context->local_context.peer_public_key_provision_size = data_size;

    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge(
        spdm_context, NULL, 0xFF,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        measurement_hash, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    free(data);
}

/**
 * Test 25: Error case, CHALLENGE_AUTH message contains opaque_length greater than the maximum allowed.
 * Expected Behavior: get a LIBSPDM_STATUS_INVALID_MSG_FIELD return code.
 **/
void libspdm_test_requester_challenge_case25(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_zero_mem (measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge (spdm_context, NULL, 0,
                                SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                measurement_hash, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

/**
 * Test 26: the requester is setup correctly to send a CHALLENGE message:
 * - it has flags indicating that the previous messages were sent
 * The received CHALLENGE_AUTH message correctly responds to the challenge, opaque
 * data with bytes from the string "libspdm", and a signature on the sent nonce.
 * Expected behavior: client returns a status of RETURN_SUCCESS.
 **/
void libspdm_test_requester_challenge_case26(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    size_t opaque_data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1A;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    opaque_data_size = sizeof(opaque_data);

    libspdm_zero_mem (measurement_hash, sizeof(measurement_hash));
    status = libspdm_challenge_ex (spdm_context, NULL, 0,
                                   SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
                                   measurement_hash, NULL, NULL, NULL, NULL,
                                   opaque_data, &opaque_data_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(opaque_data_size, m_libspdm_opaque_data_size);
    assert_memory_equal(opaque_data, m_libspdm_opaque_data, opaque_data_size);
    free(data);
}

/**
 * Test 27: Successful case , With the correct challenge context field
 * Expected Behavior: client returns a status of RETURN_SUCCESS.
 **/
void libspdm_test_requester_challenge_case27(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1B;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_set_mem(m_requester_context, SPDM_REQ_CONTEXT_SIZE, 0xAA);

    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));

    status = libspdm_challenge_ex2(
        spdm_context, NULL, 0, m_requester_context,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        measurement_hash, NULL, NULL, NULL, NULL, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_c.buffer_size, 0);
#else
    assert_null(spdm_context->transcript.digest_context_m1m2);
#endif
    free(data);
}

/**
 * Test 28: Error case , challenge context fields are inconsistent
 * Expected Behavior: get a LIBSPDM_STATUS_INVALID_MSG_FIELD return code
 **/
void libspdm_test_requester_challenge_case28(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1C;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

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

    libspdm_set_mem(m_requester_context, SPDM_REQ_CONTEXT_SIZE, 0xAA);

    libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));

    status = libspdm_challenge_ex2(
        spdm_context, NULL, 0, m_requester_context,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        measurement_hash, NULL, NULL, NULL, NULL, NULL, NULL);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    free(data);
}

libspdm_test_context_t m_libspdm_requester_challenge_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_challenge_test_send_message,
    libspdm_requester_challenge_test_receive_message,
};

int libspdm_requester_challenge_test_main(void)
{
    const struct CMUnitTest spdm_requester_challenge_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(libspdm_test_requester_challenge_case1),
        /* Successful response*/
        cmocka_unit_test(libspdm_test_requester_challenge_case2),
        /* connection_state check failed*/
        cmocka_unit_test(libspdm_test_requester_challenge_case3),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(libspdm_test_requester_challenge_case4),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(libspdm_test_requester_challenge_case5),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_challenge_case6),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(libspdm_test_requester_challenge_case7),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(libspdm_test_requester_challenge_case8),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_challenge_case9),
        /* SpdmCmdReceiveState check failed*/
        cmocka_unit_test(libspdm_test_requester_challenge_case10),
        /* Successful response + device error*/
        cmocka_unit_test(libspdm_test_requester_challenge_case11),
        cmocka_unit_test(libspdm_test_requester_challenge_case12),
        cmocka_unit_test(libspdm_test_requester_challenge_case13),
        cmocka_unit_test(libspdm_test_requester_challenge_case14),
        /* Invalid parameter*/
        cmocka_unit_test(libspdm_test_requester_challenge_case15),
        /* Successful response*/
        cmocka_unit_test(libspdm_test_requester_challenge_case16),
        /* Signature check failed*/
        cmocka_unit_test(libspdm_test_requester_challenge_case17),
        /* Successful response*/
        cmocka_unit_test(libspdm_test_requester_challenge_case18),
        cmocka_unit_test(libspdm_test_requester_challenge_case19),
        /* Unexpected errors*/
        cmocka_unit_test(libspdm_test_requester_challenge_case20),
        /* Buffer verification*/
        cmocka_unit_test(libspdm_test_requester_challenge_case22),
        /* Challeng differenr slot with GetCert*/
        cmocka_unit_test(libspdm_test_requester_challenge_case23),
        /* Challeng using provisioned public key (slot_id 0xFF) */
        cmocka_unit_test(libspdm_test_requester_challenge_case24),
        /* opaque_length greater than the maximum allowed */
        cmocka_unit_test(libspdm_test_requester_challenge_case25),
        /* the OpaqueDataFmt1 bit is selected in OtherParamsSelection of ALGORITHMS*/
        cmocka_unit_test(libspdm_test_requester_challenge_case26),
        /* Successful response, With the correct challenge context field*/
        cmocka_unit_test(libspdm_test_requester_challenge_case27),
        /* Error response: challenge context fields are inconsistent*/
        cmocka_unit_test(libspdm_test_requester_challenge_case28),
    };

    libspdm_setup_test_context(&m_libspdm_requester_challenge_test_context);

    return cmocka_run_group_tests(spdm_requester_challenge_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* SPDM_ENABLE_CHALLEGE*/
