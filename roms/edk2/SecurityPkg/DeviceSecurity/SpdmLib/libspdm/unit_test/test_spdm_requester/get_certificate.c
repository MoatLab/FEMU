/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT

static void *m_libspdm_local_certificate_chain;
static size_t m_libspdm_local_certificate_chain_size;

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_M1M2_BUFFER_SIZE];

static bool m_get_cert;

static uint8_t m_cert_model;

static uint8_t m_slot_id;

static size_t m_calling_index;


/* Loading the target expiration certificate chain and saving root certificate hash
 * "rsa3072_Expiration/bundle_responder.certchain.der"*/
bool libspdm_libspdm_read_responder_public_certificate_chain_expiration(
    void **data, size_t *size, void **hash, size_t *hash_size)
{
    uint32_t base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    bool res;
    void *file_data;
    size_t file_size;
    spdm_cert_chain_t *cert_chain;
    size_t cert_chain_size;
    char *file;
    const uint8_t *root_cert;
    size_t root_cert_len;
    size_t digest_size;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    file = "rsa3072_Expiration/bundle_responder.certchain.der";
    res = libspdm_read_input_file(file, &file_data, &file_size);
    if (!res) {
        return res;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);

    cert_chain_size = sizeof(spdm_cert_chain_t) + digest_size + file_size;
    cert_chain = (void *)malloc(cert_chain_size);
    if (cert_chain == NULL) {
        free(file_data);
        return false;
    }
    cert_chain->length = (uint16_t)cert_chain_size;
    cert_chain->reserved = 0;

    /* Get Root Certificate and calculate hash value*/

    res = libspdm_x509_get_cert_from_cert_chain(file_data, file_size, 0, &root_cert,
                                                &root_cert_len);
    if (!res) {
        free(file_data);
        free(cert_chain);
        return res;
    }

    libspdm_hash_all(base_hash_algo, root_cert, root_cert_len,
                     (uint8_t *)(cert_chain + 1));
    libspdm_copy_mem((uint8_t *)cert_chain + sizeof(spdm_cert_chain_t) + digest_size,
                     cert_chain_size - (sizeof(spdm_cert_chain_t) + digest_size),
                     file_data, file_size);

    *data = cert_chain;
    *size = cert_chain_size;
    if (hash != NULL) {
        *hash = (cert_chain + 1);
    }
    if (hash_size != NULL) {
        *hash_size = digest_size;
    }

    free(file_data);
    return true;
}

libspdm_return_t libspdm_requester_get_certificate_test_send_message(
    void *spdm_context, size_t request_size, const void *request,
    uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_SEND_FAIL;
    case 0x2:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x3:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x4:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x5:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x6:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x7:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x8:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x9:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xA:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xB:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xC:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xD:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xE:
        return LIBSPDM_STATUS_SUCCESS;
    case 0xF:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x10:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x11:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x12:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x13:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x14:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x15:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x16:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x17: {
        static uint16_t req_cnt = 0;
        const uint8_t *ptr = (const uint8_t *)request;

        if(req_cnt == 0) {
            m_libspdm_local_buffer_size = 0;
        }
        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) - m_libspdm_local_buffer_size,
                         &ptr[1], request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);

        req_cnt++;
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x18:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x19: {
        const uint8_t *ptr;

        ptr = (const uint8_t *)request;
        m_libspdm_local_buffer_size = 0;
        libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer), &ptr[1],
                         request_size - 1);
        m_libspdm_local_buffer_size += (request_size - 1);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1A:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1B:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1C:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1D:
    case 0x1E:
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t libspdm_requester_get_certificate_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x2: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x4: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
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

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
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
                SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = SPDM_ERROR_CODE_BUSY;
            spdm_response->header.param2 = 0;
            sub_index1++;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
        } else if (sub_index1 == 1) {
            spdm_certificate_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint16_t portion_length;
            uint16_t remainder_length;
            size_t count;
            static size_t calling_index = 0;

            if (m_libspdm_local_certificate_chain == NULL) {
                libspdm_read_responder_public_certificate_chain(
                    m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                    &m_libspdm_local_certificate_chain,
                    &m_libspdm_local_certificate_chain_size, NULL,
                    NULL);
            }
            if (m_libspdm_local_certificate_chain == NULL) {
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
            count = (m_libspdm_local_certificate_chain_size +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            if (calling_index != count - 1) {
                portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
                remainder_length = (uint16_t)(
                    m_libspdm_local_certificate_chain_size -
                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                    (calling_index + 1));
            } else {
                portion_length = (uint16_t)(
                    m_libspdm_local_certificate_chain_size -
                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                    (count - 1));
                remainder_length = 0;
            }

            spdm_response_size = sizeof(spdm_certificate_response_t) +
                                 portion_length;
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code =
                SPDM_CERTIFICATE;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            spdm_response->portion_length = portion_length;
            spdm_response->remainder_length = remainder_length;
            libspdm_copy_mem(spdm_response + 1,
                             (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                             (uint8_t *)m_libspdm_local_certificate_chain +
                             LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                             calling_index,
                             portion_length);

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false, spdm_response_size,
                spdm_response, response_size, response);

            calling_index++;
            if (calling_index == count) {
                calling_index = 0;
                free(m_libspdm_local_certificate_chain);
                m_libspdm_local_certificate_chain = NULL;
                m_libspdm_local_certificate_chain_size = 0;
            }
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

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
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

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 =
            SPDM_ERROR_CODE_RESPONSE_NOT_READY;
        spdm_response->header.param2 = 0;
        spdm_response->extend_error_data.rd_exponent = 1;
        spdm_response->extend_error_data.rd_tm = 2;
        spdm_response->extend_error_data.request_code =
            SPDM_GET_CERTIFICATE;
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
                SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 =
                SPDM_ERROR_CODE_RESPONSE_NOT_READY;
            spdm_response->header.param2 = 0;
            spdm_response->extend_error_data.rd_exponent = 1;
            spdm_response->extend_error_data.rd_tm = 2;
            spdm_response->extend_error_data.request_code =
                SPDM_GET_CERTIFICATE;
            spdm_response->extend_error_data.token = 1;
            sub_index2++;

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false,
                spdm_response_size, spdm_response,
                response_size, response);
        } else if (sub_index2 == 1) {
            spdm_certificate_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint16_t portion_length;
            uint16_t remainder_length;
            size_t count;
            static size_t calling_index = 0;

            if (m_libspdm_local_certificate_chain == NULL) {
                libspdm_read_responder_public_certificate_chain(
                    m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                    &m_libspdm_local_certificate_chain,
                    &m_libspdm_local_certificate_chain_size, NULL,
                    NULL);
            }
            if (m_libspdm_local_certificate_chain == NULL) {
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
            count = (m_libspdm_local_certificate_chain_size +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            if (calling_index != count - 1) {
                portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
                remainder_length = (uint16_t)(
                    m_libspdm_local_certificate_chain_size -
                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                    (calling_index + 1));
            } else {
                portion_length = (uint16_t)(
                    m_libspdm_local_certificate_chain_size -
                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                    (count - 1));
                remainder_length = 0;
            }

            spdm_response_size = sizeof(spdm_certificate_response_t) +
                                 portion_length;
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version =
                SPDM_MESSAGE_VERSION_10;
            spdm_response->header.request_response_code =
                SPDM_CERTIFICATE;
            spdm_response->header.param1 = 0;
            spdm_response->header.param2 = 0;
            spdm_response->portion_length = portion_length;
            spdm_response->remainder_length = remainder_length;
            libspdm_copy_mem(spdm_response + 1,
                             (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                             (uint8_t *)m_libspdm_local_certificate_chain +
                             LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                             calling_index,
                             portion_length);

            libspdm_transport_test_encode_message(
                spdm_context, NULL, false, false, spdm_response_size,
                spdm_response, response_size, response);

            calling_index++;
            if (calling_index == count) {
                calling_index = 0;
                free(m_libspdm_local_certificate_chain);
                m_libspdm_local_certificate_chain = NULL;
                m_libspdm_local_certificate_chain_size = 0;
            }
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xA: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xB: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        const uint8_t *leaf_cert_buffer;
        size_t leaf_cert_buffer_size;
        uint8_t *cert_buffer;
        size_t cert_buffer_size;
        size_t hash_size;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
            if (m_libspdm_local_certificate_chain == NULL) {
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }

            /* load certificate*/
            hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
            cert_buffer = (uint8_t *)m_libspdm_local_certificate_chain +
                          sizeof(spdm_cert_chain_t) + hash_size;
            cert_buffer_size = m_libspdm_local_certificate_chain_size -
                               sizeof(spdm_cert_chain_t) -
                               hash_size;
            if (!libspdm_x509_get_cert_from_cert_chain(
                    cert_buffer, cert_buffer_size, -1,
                    &leaf_cert_buffer,
                    &leaf_cert_buffer_size)) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                               "!!! VerifyCertificateChain - FAIL (get leaf certificate failed)!!!\n"));
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
            /* tamper certificate signature on purpose
             * arbitrarily change the last byte of the certificate signature*/
            cert_buffer[cert_buffer_size - 1]++;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xC: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xD: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain_by_size(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                LIBSPDM_TEST_CERT_SMALL, &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xE: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        uint16_t get_cert_length;
        size_t count;
        static size_t calling_index = 0;

        /* this should match the value on the test function*/
        get_cert_length = 1;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size + get_cert_length + 1) /
                get_cert_length;
        if (calling_index != count - 1) {
            portion_length = get_cert_length;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           get_cert_length * (calling_index + 1));
        } else {
            portion_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           get_cert_length * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         get_cert_length * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0xF: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain_by_size(
                m_libspdm_use_hash_algo,
                /*MAXUINT16_CERT signature_algo is SHA256RSA */
                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
                LIBSPDM_TEST_CERT_MAXUINT16, &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x10:
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

    case 0x11: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        const uint8_t *leaf_cert_buffer;
        size_t leaf_cert_buffer_size;
        uint8_t *cert_buffer;
        size_t cert_buffer_size;
        size_t hash_size;
        uint8_t cert_chain_without_root[LIBSPDM_MAX_CERT_CHAIN_SIZE];
        size_t cert_chain_without_root_size;
        void *root_cert_data;
        size_t root_cert_size;

        root_cert_size = 0;
        cert_buffer_size = 0;
        hash_size = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
            if (m_libspdm_local_certificate_chain == NULL) {
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
        }

        /* read root certificate size*/
        libspdm_read_responder_root_public_certificate(
            m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
            &root_cert_data,
            &root_cert_size, NULL, NULL);
        /* load certificate*/
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        root_cert_size = root_cert_size - sizeof(spdm_cert_chain_t) - hash_size;
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root_cert_size %zu \n", root_cert_size));
        cert_buffer = (uint8_t *)m_libspdm_local_certificate_chain +
                      sizeof(spdm_cert_chain_t) + hash_size + root_cert_size;
        cert_buffer_size = m_libspdm_local_certificate_chain_size -
                           sizeof(spdm_cert_chain_t) -
                           hash_size - root_cert_size;

        if (!libspdm_x509_get_cert_from_cert_chain(
                cert_buffer, cert_buffer_size, -1,
                &leaf_cert_buffer,
                &leaf_cert_buffer_size)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "!!! VerifyCertificateChain - FAIL (get leaf certificate failed)!!!\n"));
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        libspdm_copy_mem(cert_chain_without_root,
                         sizeof(cert_chain_without_root),
                         m_libspdm_local_certificate_chain,
                         sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_copy_mem(cert_chain_without_root + sizeof(spdm_cert_chain_t) + hash_size,
                         sizeof(cert_chain_without_root) - (sizeof(spdm_cert_chain_t) + hash_size),
                         cert_buffer,
                         cert_buffer_size);
        cert_chain_without_root_size = m_libspdm_local_certificate_chain_size - root_cert_size;
        ((spdm_cert_chain_t *)cert_chain_without_root)->length =
            (uint16_t)cert_chain_without_root_size;
        count = (cert_chain_without_root_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(cert_chain_without_root_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                cert_chain_without_root_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        /* send certchain without root*/
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)cert_chain_without_root +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }

        free(root_cert_data);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x12: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        const uint8_t *leaf_cert_buffer;
        size_t leaf_cert_buffer_size;
        uint8_t *cert_buffer;
        size_t cert_buffer_size;
        size_t hash_size;
        uint8_t cert_chain_without_root[LIBSPDM_MAX_CERT_CHAIN_SIZE];
        size_t cert_chain_without_root_size;
        void *root_cert_data;
        size_t root_cert_size;

        root_cert_size = 0;
        cert_buffer_size = 0;
        hash_size = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
            if (m_libspdm_local_certificate_chain == NULL) {
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
        }

        /* read root certificate size*/
        libspdm_read_responder_root_public_certificate(
            m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
            &root_cert_data,
            &root_cert_size, NULL, NULL);
        /* load certificate*/
        hash_size = libspdm_get_hash_size(m_libspdm_use_hash_algo);
        root_cert_size = root_cert_size - sizeof(spdm_cert_chain_t) - hash_size;
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root_cert_size %zu \n", root_cert_size));
        cert_buffer = (uint8_t *)m_libspdm_local_certificate_chain +
                      sizeof(spdm_cert_chain_t) + hash_size + root_cert_size;
        cert_buffer_size = m_libspdm_local_certificate_chain_size -
                           sizeof(spdm_cert_chain_t) -
                           hash_size - root_cert_size;

        if (!libspdm_x509_get_cert_from_cert_chain(
                cert_buffer, cert_buffer_size, -1,
                &leaf_cert_buffer,
                &leaf_cert_buffer_size)) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                           "!!! VerifyCertificateChain - FAIL (get leaf certificate failed)!!!\n"));
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        /* tamper certificate signature on purpose
         * arbitrarily change the last byte of the certificate signature*/
        cert_buffer[cert_buffer_size - 1]++;

        libspdm_copy_mem(cert_chain_without_root,
                         sizeof(cert_chain_without_root),
                         m_libspdm_local_certificate_chain,
                         sizeof(spdm_cert_chain_t) + hash_size);
        libspdm_copy_mem(cert_chain_without_root + sizeof(spdm_cert_chain_t) + hash_size,
                         sizeof(cert_chain_without_root) - (sizeof(spdm_cert_chain_t) + hash_size),
                         cert_buffer,
                         cert_buffer_size);
        cert_chain_without_root_size = m_libspdm_local_certificate_chain_size - root_cert_size;
        ((spdm_cert_chain_t *)cert_chain_without_root)->length =
            (uint16_t)cert_chain_without_root_size;
        count = (cert_chain_without_root_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(cert_chain_without_root_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                cert_chain_without_root_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        /* send certchain without root*/
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)cert_chain_without_root +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }

        free(root_cert_data);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x13: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_libspdm_read_responder_public_certificate_chain_expiration(
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x14: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = 0; /* Fail response: responder return portion_length is 0.*/
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x15: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1; /* Fail response: responder return portion_length > spdm_request.length*/
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x16: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            /* Fail response: spdm_request.offset + spdm_response->portion_length + spdm_response->remainder_length !=
             * total_responder_cert_chain_buffer_length.*/
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size - 1 -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *(calling_index + 1));

        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x17: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_copy_mem(&m_libspdm_local_buffer[m_libspdm_local_buffer_size],
                         sizeof(m_libspdm_local_buffer) - m_libspdm_local_buffer_size,
                         spdm_response, spdm_response_size);
        m_libspdm_local_buffer_size += spdm_response_size;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x18: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x19: {
        if (m_get_cert) {
            spdm_certificate_response_t *spdm_response;
            size_t spdm_response_size;
            size_t transport_header_size;
            uint16_t portion_length;
            uint16_t remainder_length;
            size_t count;
            static size_t calling_index = 0;
            static uint8_t slot_id = 0;

            if (m_libspdm_local_certificate_chain == NULL) {
                if (slot_id == 0) {
                    libspdm_read_responder_public_certificate_chain(
                        m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                        &m_libspdm_local_certificate_chain,
                        &m_libspdm_local_certificate_chain_size, NULL, NULL);
                } else {
                    libspdm_read_responder_public_certificate_chain_per_slot(
                        1, m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                        &m_libspdm_local_certificate_chain,
                        &m_libspdm_local_certificate_chain_size, NULL, NULL);
                }
            }
            if (m_libspdm_local_certificate_chain == NULL) {
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
            count = (m_libspdm_local_certificate_chain_size +
                     LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            if (calling_index != count - 1) {
                portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
                remainder_length =
                    (uint16_t)(m_libspdm_local_certificate_chain_size -
                               LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                               (calling_index + 1));
            } else {
                portion_length = (uint16_t)(
                    m_libspdm_local_certificate_chain_size -
                    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
                remainder_length = 0;
            }

            spdm_response_size =
                sizeof(spdm_certificate_response_t) + portion_length;
            transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
            spdm_response = (void *)((uint8_t *)*response + transport_header_size);

            spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_11;
            spdm_response->header.request_response_code = SPDM_CERTIFICATE;
            spdm_response->header.param1 = slot_id;
            spdm_response->header.param2 = 0;
            spdm_response->portion_length = portion_length;
            spdm_response->remainder_length = remainder_length;
            libspdm_copy_mem(spdm_response + 1,
                             (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                             (uint8_t *)m_libspdm_local_certificate_chain +
                             LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                             portion_length);

            libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                                  false, spdm_response_size,
                                                  spdm_response, response_size,
                                                  response);

            calling_index++;
            if (calling_index == count) {
                calling_index = 0;
                free(m_libspdm_local_certificate_chain);
                m_libspdm_local_certificate_chain = NULL;
                m_libspdm_local_certificate_chain_size = 0;
                slot_id++;
            }
        } else { /*correct CHALLENGE_AUTH message*/
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
                                                                         m_libspdm_use_asym_algo,
                                                                         &data,
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
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1A: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;
        uint32_t session_id;
        libspdm_session_info_t *session_info;
        uint8_t *scratch_buffer;
        size_t scratch_buffer_size;

        session_id = 0xFFFFFFFF;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN + 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;

        /* For secure message, message is in sender buffer, we need copy it to scratch buffer.
         * transport_message is always in sender buffer. */
        libspdm_get_scratch_buffer (spdm_context, (void **)&scratch_buffer, &scratch_buffer_size);

        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);
        libspdm_copy_mem (scratch_buffer + transport_header_size,
                          scratch_buffer_size - transport_header_size,
                          spdm_response, spdm_response_size);
        spdm_response = (void *)(scratch_buffer + transport_header_size);

        libspdm_transport_test_encode_message(spdm_context, &session_id, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
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

    case 0x1B: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_10;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 3; /* Fail response: responder return wrong SlotID 3, not equal with SlotID 0 in request message. */
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1C: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain_alias_cert(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x1D: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;
        static size_t calling_index = 0;

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain_alias_cert_till_dev_cert_ca(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;
        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        calling_index++;
        if (calling_index == count) {
            calling_index = 0;
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x1E: {
        spdm_certificate_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;
        uint16_t portion_length;
        uint16_t remainder_length;
        size_t count;

        if (m_calling_index ==0) {
            free(m_libspdm_local_certificate_chain);
            m_libspdm_local_certificate_chain = NULL;
            m_libspdm_local_certificate_chain_size = 0;
        }

        if (m_libspdm_local_certificate_chain == NULL) {
            libspdm_read_responder_public_certificate_chain(
                m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
                &m_libspdm_local_certificate_chain,
                &m_libspdm_local_certificate_chain_size, NULL, NULL);
        }
        if (m_libspdm_local_certificate_chain == NULL) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        count = (m_libspdm_local_certificate_chain_size +
                 LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        if (m_calling_index != count - 1) {
            portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
            remainder_length =
                (uint16_t)(m_libspdm_local_certificate_chain_size -
                           LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                           (m_calling_index + 1));
        } else {
            portion_length = (uint16_t)(
                m_libspdm_local_certificate_chain_size -
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (count - 1));
            remainder_length = 0;
        }

        spdm_response_size =
            sizeof(spdm_certificate_response_t) + portion_length;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_CERTIFICATE;
        spdm_response->header.param1 = m_slot_id;
        spdm_response->header.param2 = m_cert_model;
        spdm_response->portion_length = portion_length;
        spdm_response->remainder_length = remainder_length;

        libspdm_copy_mem(spdm_response + 1,
                         (size_t)(*response) + *response_size - (size_t)(spdm_response + 1),
                         (uint8_t *)m_libspdm_local_certificate_chain +
                         LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * m_calling_index,
                         portion_length);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);

        m_calling_index++;
    }
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

/**
 * Test 1: message could not be sent
 * Expected Behavior: get a LIBSPDM_STATUS_SEND_FAIL, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
 **/
void libspdm_test_requester_get_certificate_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 2: Normal case, request a certificate chain
 * Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    libspdm_data_parameter_t parameter;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t count;
#else
    uint8_t set_data_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint32_t set_data_buffer_hash_size;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.is_requester = true;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    parameter.additional_data[0] = 0;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER, &parameter,
                     data, data_size);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#else
    set_data_buffer_hash_size =
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size;
    libspdm_copy_mem(set_data_buffer_hash, set_data_buffer_hash_size,
                     spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash,
                     set_data_buffer_hash_size);
#endif
    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#else
    /*
     * libspdm_get_certificate will get leaf_cert_public_key when LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT is not enabled.
     * The follow check is for libspdm_set_data.
     **/
    assert_int_equal(set_data_buffer_hash_size,
                     spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size);

    assert_memory_equal(set_data_buffer_hash,
                        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash,
                        set_data_buffer_hash_size);
#endif/*LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT*/
    free(data);
}

/**
 * Test 3: simulate wrong connection_state when sending GET_CERTIFICATE (missing SPDM_GET_DIGESTS_RECEIVE_FLAG and SPDM_GET_CAPABILITIES_RECEIVE_FLAG)
 * Expected Behavior: get a LIBSPDM_STATUS_INVALID_STATE_LOCAL, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
 **/
void libspdm_test_requester_get_certificate_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_STATE_LOCAL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 4: force responder to send an ERROR message with code SPDM_ERROR_CODE_INVALID_REQUEST
 * Expected Behavior: get a LIBSPDM_STATUS_ERROR_PEER, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
 **/
void libspdm_test_requester_get_certificate_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 5: force responder to send an ERROR message with code SPDM_ERROR_CODE_BUSY
 * Expected Behavior: get a LIBSPDM_STATUS_BUSY_PEER, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
 **/
void libspdm_test_requester_get_certificate_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_BUSY_PEER);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 6: force responder to first send an ERROR message with code SPDM_ERROR_CODE_BUSY, but functions normally afterwards
 * Expected Behavior: receives the correct number of CERTIFICATE messages
 **/
void libspdm_test_requester_get_certificate_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t count;
#endif
    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->retry_times = 3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.is_requester = true;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
#endif
    free(data);
}

/**
 * Test 7: force responder to send an ERROR message with code SPDM_ERROR_CODE_REQUEST_RESYNCH
 * Expected Behavior: get a LIBSPDM_STATUS_RESYNCH_PEER, with no CERTIFICATE messages received (checked in transcript.message_b buffer)
 **/
void libspdm_test_requester_get_certificate_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_RESYNCH_PEER);
    assert_int_equal(spdm_context->connection_info.connection_state,
                     LIBSPDM_CONNECTION_STATE_NOT_STARTED);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_b.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 8: force responder to send an ERROR message with code SPDM_ERROR_CODE_RESPONSE_NOT_READY
 * Expected Behavior: get a LIBSPDM_STATUS_ERROR_PEER
 **/
void libspdm_test_requester_get_certificate_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    free(data);
}

/**
 * Test 9: force responder to first send an ERROR message with code SPDM_ERROR_CODE_RESPONSE_NOT_READY, but functions normally afterwards
 * Expected Behavior: receives the correct number of CERTIFICATE messages
 **/
void libspdm_test_requester_get_certificate_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t count;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.is_requester = true;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    if (LIBSPDM_RESPOND_IF_READY_SUPPORT) {
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    } else {
        assert_int_equal(status, LIBSPDM_STATUS_NOT_READY_PEER);
    }

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) / LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count + data_size);
#endif
    free(data);
}

/**
 * Test 10: Normal case, request a certificate chain. Validates certificate by using a preloaded chain instead of root hash
 * Expected Behavior: receives the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t count;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);

    spdm_context->local_context.peer_root_cert_provision_size[0] = 0;
    spdm_context->local_context.peer_root_cert_provision[0] = NULL;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->local_context.is_requester = true;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
#endif
    free(data);
}

/**
 * Test 11: Normal procedure, but the retrieved certificate chain has an invalid signature
 * Expected Behavior: get a LIBSPDM_STATUS_VERIF_FAIL, and receives the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t count;
#endif
    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /* Loading certificate chain and saving root certificate hash*/
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    /* Reseting message buffer*/
    libspdm_reset_message_b(spdm_context);
    /* Calculating expected number of messages received*/

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_VERIF_FAIL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
#endif
    free(data);
}

/**
 * Test 12: Normal procedure, but the retrieved root certificate does not match
 * Expected Behavior: get a LIBSPDM_STATUS_VERIF_NO_AUTHORITY, and receives the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    uint8_t root_cert_buffer[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t count;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    /* arbitrarily changes the root certificate on purpose*/
    if (root_cert != NULL) {
        memcpy(root_cert_buffer, root_cert, root_cert_size);
        root_cert_buffer[0]++;
    }
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert_buffer;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    /* Reseting message buffer*/
    libspdm_reset_message_b(spdm_context);
    /* Calculating expected number of messages received*/
    spdm_context->local_context.is_requester = true;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_VERIF_NO_AUTHORITY);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
#endif
    free(data);
}

/**
 * Test 13: Gets a short certificate chain (fits in 1 message)
 * Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t count;
#endif

    /* This case requires a short certificate chain (fits in 1 message) for testing,
     * so skip when m_libspdm_use_asym_algo is other than ECC_P256 */
    if (m_libspdm_use_asym_algo !=
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256) {
        return;
    }

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /* Loading Root certificate and saving its hash*/
    libspdm_read_responder_public_certificate_chain_by_size(
        m_libspdm_use_hash_algo, m_libspdm_use_asym_algo, LIBSPDM_TEST_CERT_SMALL, &data,
        &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->local_context.is_requester = true;
    /* Reseting message buffer*/
    libspdm_reset_message_b(spdm_context);
    /* Calculating expected number of messages received*/

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
#endif
    free(data);
}

/**
 * Test 14: request a whole certificate chain byte by byte
 * Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    uint16_t get_cert_length;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t count;
#endif
    /* Get certificate chain byte by byte*/
    get_cert_length = 1;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /* Loading Root certificate and saving its hash*/
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    /* Reseting message buffer*/
    libspdm_reset_message_b(spdm_context);
    /* Calculating expected number of messages received*/

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate_choose_length(
        spdm_context, NULL, 0, get_cert_length, &cert_chain_size, cert_chain);
    /* It may fail because the spdm does not support too many messages.
     * assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);*/
    if (status == LIBSPDM_STATUS_SUCCESS) {
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        count = (data_size + get_cert_length - 1) / get_cert_length;
        assert_int_equal(
            spdm_context->transcript.message_b.buffer_size,
            sizeof(spdm_get_certificate_request_t) * count +
            sizeof(spdm_certificate_response_t) * count +
            data_size);
#endif
    }
    free(data);
}

/**
 * Test 15: request a long certificate chain
 * Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t count;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /* Loading Root certificate and saving its hash*/

    libspdm_read_responder_public_certificate_chain_by_size(
        /*MAXUINT16_CERT signature_algo is SHA256RSA */
        m_libspdm_use_hash_algo, SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
        LIBSPDM_TEST_CERT_MAXUINT16, &data, &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    /* Reseting message buffer*/
    libspdm_reset_message_b(spdm_context);
    /* Calculating expected number of messages received*/

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    /* It may fail because the spdm does not support too long message.
     * assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);*/
    if (status == LIBSPDM_STATUS_SUCCESS) {
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        assert_int_equal(
            spdm_context->transcript.message_b.buffer_size,
            sizeof(spdm_get_certificate_request_t) * count +
            sizeof(spdm_certificate_response_t) * count +
            data_size);
#endif
    }
    free(data);
}

/**
 * Test 16: receiving an unexpected ERROR message from the responder.
 * There are tests for all named codes, including some reserved ones
 * (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
 * However, for having specific test cases, it is excluded from this case:
 * Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
 * Expected behavior: client returns a status of LIBSPDM_STATUS_ERROR_PEER.
 **/
void libspdm_test_requester_get_certificate_case16(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void                 *data;
    size_t data_size;
    void                 *hash;
    size_t hash_size;
    const uint8_t                 *root_cert;
    size_t root_cert_size;
    uint16_t error_code;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;

    error_code = LIBSPDM_ERROR_CODE_RESERVED_00;
    while(error_code <= 0xff) {
        spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
        libspdm_reset_message_b(spdm_context);

        cert_chain_size = sizeof(cert_chain);
        libspdm_zero_mem (cert_chain, sizeof(cert_chain));
        status = libspdm_get_certificate (spdm_context, NULL, 0, &cert_chain_size, cert_chain);
        LIBSPDM_ASSERT_INT_EQUAL_CASE (status, LIBSPDM_STATUS_ERROR_PEER, error_code);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
        /* assert_int_equal (spdm_context->transcript.message_b.buffer_size, 0);*/
        LIBSPDM_ASSERT_INT_EQUAL_CASE (spdm_context->transcript.message_b.buffer_size, 0,
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
 * Test 17: Normal case, get a certificate chain start not with root cert. Validates certificate by using a preloaded chain.
 * Expected Behavior: receives the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);

    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->local_context.is_requester = true;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    free(data);
}

/**
 * Test 18: Fail case, get a certificate chain start not with root cert and with wrong signature. Validates certificate by using a preloaded chain.
 * Expected Behavior: receives the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);

    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_VERIF_FAIL);
    free(data);
}

/**
 * Test 19: Normal procedure, but one certificate in the retrieved certificate chain past its expiration date.
 * Expected Behavior: get a LIBSPDM_STATUS_VERIF_FAIL, and receives the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t count;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /* Loading the target expiration certificate chain and saving root certificate hash
     * "rsa3072_Expiration/bundle_responder.certchain.der"*/
    libspdm_libspdm_read_responder_public_certificate_chain_expiration(&data,
                                                                       &data_size, &hash,
                                                                       &hash_size);
    libspdm_x509_get_cert_from_cert_chain(
        (uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
        data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
        &root_cert, &root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    spdm_context->connection_info.algorithm.base_hash_algo =
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    /* Reseting message buffer*/
    libspdm_reset_message_b(spdm_context);
    /* Calculating expected number of messages received*/

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_VERIF_FAIL);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
#endif
    free(data);
}

/**
 * Test 20: Fail case, request a certificate chain, responder return portion_length is 0.
 * Expected Behavior:returns a status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_get_certificate_case20(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

/**
 * Test 21: Fail case, request a certificate chain, responder return portion_length > spdm_request.length.
 * Expected Behavior:returns a status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_get_certificate_case21(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

/**
 * Test 22: Fail case, request a certificate chain,
 * spdm_request.offset + spdm_response->portion_length + spdm_response->remainder_length !=
 * total_responder_cert_chain_buffer_length.
 * Expected Behavior:returns a status of LIBSPDM_STATUS_INVALID_MSG_FIELD.
 **/
void libspdm_test_requester_get_certificate_case22(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);
}

/**
 * Test 23: request messages are successfully sent and response messages are successfully
 * received. Buffer B already has arbitrary data.
 * Expected Behavior: requester returns the status RETURN_SUCCESS and CERTIFICATE messages are
 * received, buffer B appends the exchanged GET_CERTIFICATE and CERTIFICATE messages.
 **/
void libspdm_test_requester_get_certificate_case23(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t arbitrary_size;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_dump_hex(root_cert, root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] = root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg = m_libspdm_use_req_asym_algo;
    spdm_context->local_context.is_requester = true;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    /*filling B with arbitrary data*/
    arbitrary_size = 8;
    libspdm_set_mem(spdm_context->transcript.message_b.buffer, arbitrary_size, (uint8_t) 0xEE);
    spdm_context->transcript.message_b.buffer_size = arbitrary_size;
#endif
    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     (arbitrary_size + m_libspdm_local_buffer_size));
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "m_libspdm_local_buffer (0x%x):\n",
                   m_libspdm_local_buffer_size));
    libspdm_dump_hex(m_libspdm_local_buffer, m_libspdm_local_buffer_size);
    assert_memory_equal(spdm_context->transcript.message_b.buffer + arbitrary_size,
                        m_libspdm_local_buffer, m_libspdm_local_buffer_size);
#endif
    free(data);
}

/**
 * Test 24: test the Alias Cert model, hardware identify OID is found in AliasCert model cert
 * Expected Behavior: return RETURN_SECURITY_VIOLATION
 **/
void libspdm_test_requester_get_certificate_case24(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    /*The only different setting with normal case2: cert model is AliasCert model*/
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    LIBSPDM_INTERNAL_DUMP_HEX(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_VERIF_FAIL);
    free(data);
}
#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
/**
 * Test 25: Normal case, request a certificate chain
 * Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case25(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    void *data1;
    size_t data_size;
    size_t data1_size;
    void *hash;
    void *hash1;
    size_t hash_size;
    size_t hash1_size;
    const uint8_t *root_cert;
    const uint8_t *root_cert1;
    size_t root_cert_size;
    size_t root_cert1_size;
    uint8_t slot_id;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->local_context.is_requester = true;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;

    libspdm_read_responder_public_certificate_chain_per_slot(1, m_libspdm_use_hash_algo,
                                                             m_libspdm_use_asym_algo, &data1,
                                                             &data1_size, &hash1, &hash1_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data1 + sizeof(spdm_cert_chain_t) + hash1_size,
                                          data1_size - sizeof(spdm_cert_chain_t) - hash1_size, 0,
                                          &root_cert1, &root_cert1_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_dump_hex(
        root_cert1,
        root_cert1_size);
    spdm_context->local_context.peer_root_cert_provision_size[1] =
        root_cert1_size;
    spdm_context->local_context.peer_root_cert_provision[1] = root_cert1;

    m_get_cert = true;
    for (slot_id = 0; slot_id < 2; slot_id++) {
        cert_chain_size = sizeof(cert_chain);
        libspdm_zero_mem(cert_chain, sizeof(cert_chain));
        status = libspdm_get_certificate(spdm_context, NULL, slot_id, &cert_chain_size,
                                         cert_chain);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_get_certificate - %xu\n", status));
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    }

    libspdm_reset_message_b(spdm_context);
    m_get_cert = false;
    for (slot_id = 0; slot_id < 2; slot_id++) {
        libspdm_zero_mem(measurement_hash, sizeof(measurement_hash));
        status = libspdm_challenge(
            spdm_context, NULL, slot_id,
            SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
            measurement_hash, NULL);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_challenge - %xu\n", status));
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    }

    free(data);
    free(data1);
}
#endif
/**
 * Test 26: Normal case, request a certificate chain in a session
 * Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case26(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    uint32_t session_id;
    libspdm_session_info_t *session_info;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1A;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
    spdm_context->connection_info.algorithm.dhe_named_group =
        m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite =
        m_libspdm_use_aead_algo;

    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->local_context.is_requester = true;

    session_id = 0xFFFFFFFF;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init(spdm_context, session_info, session_id, true);
    libspdm_secured_message_set_session_state(session_info->secured_message_context,
                                              LIBSPDM_SESSION_STATE_ESTABLISHED);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    session_info->session_transcript.message_m.buffer_size =
        session_info->session_transcript.message_m.max_buffer_size;
#endif
    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate_ex(spdm_context, &session_id,
                                        0, &cert_chain_size,
                                        cert_chain, NULL, 0);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(session_info->session_transcript.message_m.buffer_size, 0);
#endif
    free(data);
}

/**
 * Test 27: Fail case, responder return wrong SlotID 3, but it should be equal with SlotID 0 in request message.
 * Expected Behavior:returns a status of INVALID_MSG_FIELD.
 **/
void libspdm_test_requester_get_certificate_case27(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1B;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_10 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    free(data);

    if (m_libspdm_local_certificate_chain != NULL) {
        free(m_libspdm_local_certificate_chain);
        m_libspdm_local_certificate_chain = NULL;
    }
}

/**
 * Test 28: Normal case, request a certificate chain. Validates certificate by using a preloaded chain instead of root hash
 * Expected Behavior: receives the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case28(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t count;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1C;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain_alias_cert(
        m_libspdm_use_hash_algo,
        m_libspdm_use_asym_algo, &data,
        &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);

    spdm_context->local_context.peer_root_cert_provision_size[0] = 0;
    spdm_context->local_context.peer_root_cert_provision[0] = NULL;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->local_context.is_requester = true;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
#endif
    free(data);
}

/**
 * Test 29: Normal case, request a certificate chain. Validates certificate by using a preloaded chain instead of root hash
 * Expected Behavior: receives the correct number of Certificate messages
 **/
void libspdm_test_requester_get_certificate_case29(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1D;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
    libspdm_read_responder_public_certificate_chain_alias_cert(
        m_libspdm_use_hash_algo,
        m_libspdm_use_asym_algo, &data,
        &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);

    spdm_context->local_context.peer_root_cert_provision_size[0] = 0;
    spdm_context->local_context.peer_root_cert_provision[0] = NULL;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;
    spdm_context->local_context.is_requester = true;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_VERIF_FAIL);
    free(data);
}

/**
 * Test 30: check request attributes and response attributes ,
 * Set CertModel to determine whether it meets expectations
 * Expected Behavior: requester returns the status LIBSPDM_STATUS_SUCCESS
 * Expected Behavior: CertModel is GenericCert model and slot 0 , returns a status of RETURN_DEVICE_ERROR.
 * Expected Behavior: CertModel Value of 0 and certificate chain is valid, returns a status of RETURN_DEVICE_ERROR.
 **/
void libspdm_test_requester_get_certificate_case30(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;
    libspdm_data_parameter_t parameter;

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#else
    uint8_t set_data_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint32_t set_data_buffer_hash_size;
#endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1E;
    spdm_context->retry_times = 1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.is_requester = true;
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "root cert data :\n"));
    libspdm_dump_hex(
        root_cert,
        root_cert_size);
    spdm_context->local_context.peer_root_cert_provision_size[0] =
        root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    libspdm_reset_message_b(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.req_base_asym_alg =
        m_libspdm_use_req_asym_algo;

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    parameter.additional_data[0] = 0;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER, &parameter,
                     data, data_size);

#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#else
    set_data_buffer_hash_size =
        spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size;
    libspdm_copy_mem(set_data_buffer_hash, set_data_buffer_hash_size,
                     spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash,
                     set_data_buffer_hash_size);
#endif

    /* Sub Case 1: CertModel Value of 1 , DeviceCert model*/
    spdm_context->connection_info.multi_key_conn_rsp = true;
    spdm_context->connection_info.peer_cert_info[0] = 0;
    m_cert_model = SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT;
    libspdm_reset_message_b(spdm_context);
    m_slot_id = 0;
    m_calling_index = 0;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, m_slot_id, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.peer_cert_info[0], m_cert_model);
    assert_int_equal(cert_chain_size, m_libspdm_local_certificate_chain_size);
    assert_memory_equal(cert_chain, m_libspdm_local_certificate_chain,
                        m_libspdm_local_certificate_chain_size);

    /* Sub Case 2: CertModel Value of 2 , AliasCert model*/
    spdm_context->connection_info.multi_key_conn_rsp = true;
    spdm_context->connection_info.peer_cert_info[0] = 0;
    m_cert_model = SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT;
    libspdm_reset_message_b(spdm_context);
    m_slot_id = 0;
    m_calling_index = 0;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, m_slot_id, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.peer_cert_info[0], m_cert_model);
    assert_int_equal(cert_chain_size, m_libspdm_local_certificate_chain_size);
    assert_memory_equal(cert_chain, m_libspdm_local_certificate_chain,
                        m_libspdm_local_certificate_chain_size);

    /* Sub Case 3: CertModel Value of 3 GenericCert model , slot_id set 1
     * In all cases, the certificate model for slot 0 shall be either the device certificate model or the alias certificate model*/
    spdm_context->connection_info.multi_key_conn_rsp = true;
    spdm_context->connection_info.peer_cert_info[1] = 0;
    m_cert_model = SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT;
    libspdm_reset_message_b(spdm_context);
    m_slot_id = 1;
    m_calling_index = 0;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, m_slot_id, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.peer_cert_info[1], m_cert_model);
    assert_int_equal(cert_chain_size, m_libspdm_local_certificate_chain_size);
    assert_memory_equal(cert_chain, m_libspdm_local_certificate_chain,
                        m_libspdm_local_certificate_chain_size);

    /* Sub Case 4: CertModel Value of 3 , GenericCert model , slot_id set 0
     * In all cases, the certificate model for slot 0 shall be either the device certificate model or the alias certificate model*/
    spdm_context->connection_info.multi_key_conn_rsp = true;
    spdm_context->connection_info.peer_cert_info[0] = 0;
    m_cert_model = SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT;
    libspdm_reset_message_b(spdm_context);
    m_slot_id = 0;
    m_calling_index = 0;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, m_slot_id, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_int_equal(spdm_context->connection_info.peer_cert_info[0], 0);

    /* Sub Case 5: CertModel Value of 0 , MULTI_KEY_CONN_RSP is true*/
    /* Value of 0 indicates either that the certificate slot does not contain any certificates or that the corresponding
     * MULTI_KEY_CONN_REQ or MULTI_KEY_CONN_RSP is false. */
    spdm_context->connection_info.multi_key_conn_rsp = true;
    spdm_context->connection_info.peer_cert_info[0] = 0;
    m_cert_model = SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE;
    libspdm_reset_message_b(spdm_context);
    m_slot_id = 0;
    m_calling_index = 0;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, m_slot_id, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_MSG_FIELD);
    assert_int_equal(spdm_context->connection_info.peer_cert_info[0], m_cert_model);

    /* Sub Case 6: CertModel Value of 0 , MULTI_KEY_CONN_RSP is false*/
    /* Value of 0 indicates either that the certificate slot does not contain any certificates or that the corresponding
     * MULTI_KEY_CONN_REQ or MULTI_KEY_CONN_RSP is false. */
    spdm_context->connection_info.multi_key_conn_rsp = false;
    spdm_context->connection_info.peer_cert_info[0] = 0;
    m_cert_model = SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE;
    libspdm_reset_message_b(spdm_context);
    m_slot_id = 0;
    m_calling_index = 0;

    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, m_slot_id, &cert_chain_size,
                                     cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(spdm_context->connection_info.peer_cert_info[0], m_cert_model);
    assert_int_equal(cert_chain_size, m_libspdm_local_certificate_chain_size);
    assert_memory_equal(cert_chain, m_libspdm_local_certificate_chain,
                        m_libspdm_local_certificate_chain_size);

    free(data);
    free(m_libspdm_local_certificate_chain);
}

libspdm_test_context_t m_libspdm_requester_get_certificate_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_get_certificate_test_send_message,
    libspdm_requester_get_certificate_test_receive_message,
};

int libspdm_requester_get_certificate_test_main(void)
{
    const struct CMUnitTest spdm_requester_get_certificate_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case1),
        /* Successful response: check root certificate hash*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case2),
        /* connection_state check failed*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case3),
        /* Error response: SPDM_ERROR_CODE_INVALID_REQUEST*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case4),
        /* Always SPDM_ERROR_CODE_BUSY*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case5),
        /* SPDM_ERROR_CODE_BUSY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case6),
        /* Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case7),
        /* Always SPDM_ERROR_CODE_RESPONSE_NOT_READY*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case8),
        /* SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case9),
        /* Successful response: check certificate chain*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case10),
        /* Invalid certificate signature*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case11),
        /* Fail certificate chain check*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case12),
        /* Sucessful response: get a certificate chain that fits in one single message*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case13),
        /* Sucessful response: get certificate chain byte by byte*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case14),
        /* Sucessful response: get a long certificate chain*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case15),
        /* Unexpected errors*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case16),
        /* Sucessful response: get a certificate chain not start with root cert.*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case17),
        /* Fail response: get a certificate chain not start with root cert but with wrong signature.*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case18),
        /* Fail response: one certificate in the retrieved certificate chain past its expiration date.*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case19),
        /* Fail response: responder return portion_length is 0.*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case20),
        /* Fail response: responder return portion_length > spdm_request.length*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case21),
        /* Fail response: spdm_request.offset + spdm_response->portion_length + spdm_response->remainder_length !=
         * total_responder_cert_chain_buffer_length.*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case22),
        /* Buffer verification*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case23),
        /* hardware identify OID is found in AliasCert model cert*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case24),
#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
        /* GetCert (0), GetCert(1) and Challenge(0) */
        cmocka_unit_test(libspdm_test_requester_get_certificate_case25),
#endif
        /* get cert in secure session */
        cmocka_unit_test(libspdm_test_requester_get_certificate_case26),
        /* Fail response: responder return wrong SlotID 3, not equal with SlotID 0 in request message. */
        cmocka_unit_test(libspdm_test_requester_get_certificate_case27),
        /*Successful response: get the entire alias_cert model cert_chain*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case28),
        /*Fail response: get the partial alias_cert model cert_chain*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case29),
        /* check request attributes and response attributes*/
        cmocka_unit_test(libspdm_test_requester_get_certificate_case30),
    };

    libspdm_setup_test_context(&m_libspdm_requester_get_certificate_test_context);

    return cmocka_run_group_tests(spdm_requester_get_certificate_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
