/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP

static void *m_libspdm_local_certificate_chain_test_case_1;
static size_t m_libspdm_local_certificate_chain_size_test_case_1;

static uint8_t m_libspdm_local_large_response_buffer[LIBSPDM_MAX_SPDM_MSG_SIZE];

static size_t m_libspdm_local_buffer_size;
static uint8_t m_libspdm_local_buffer[LIBSPDM_MAX_MESSAGE_M1M2_BUFFER_SIZE];

static uint8_t m_libspdm_local_certificate_chain_test_case_4[LIBSPDM_MAX_CERT_CHAIN_SIZE];

/* Override the LIBSPDM_DATA_TRANSFER_SIZE just for the unit tests in this file.
 * All other unit tests have the default data transfer size due to the specific
 * unit tests requests and responses hardcode for each test case. */
#define CHUNK_GET_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE (42)

/* Loading the target expiration certificate chain and saving root certificate hash
 * "rsa3072_Expiration/bundle_responder.certchain.der"*/
bool libspdm_libspdm_read_responder_public_certificate_chain_expiration(
    void** data, size_t* size, void** hash, size_t* hash_size);

#define CHUNK_GET_UNIT_TEST_CHUNK_HANDLE (10)

void libspdm_requester_chunk_get_test_case1_build_certificates_response(
    void *context, void *response, size_t *response_size,
    size_t sub_cert_index, size_t *sub_cert_count)
{
    spdm_certificate_response_t *cert_rsp;
    uint16_t sub_cert_portion_length;
    uint16_t sub_cert_remainder_length;

    if (m_libspdm_local_certificate_chain_test_case_1 == NULL) {
        libspdm_read_responder_public_certificate_chain(
            m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
            &m_libspdm_local_certificate_chain_test_case_1,
            &m_libspdm_local_certificate_chain_size_test_case_1, NULL, NULL);
    }
    LIBSPDM_ASSERT(m_libspdm_local_certificate_chain_test_case_1 != NULL);

    *sub_cert_count = (m_libspdm_local_certificate_chain_size_test_case_1 +
                       LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) /
                      LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;

    if (sub_cert_index != *sub_cert_count - 1) {
        sub_cert_portion_length = LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
        sub_cert_remainder_length =
            (uint16_t) (m_libspdm_local_certificate_chain_size_test_case_1 -
                        LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN *
                        (sub_cert_index + 1));
    } else {
        sub_cert_portion_length = (uint16_t) (
            m_libspdm_local_certificate_chain_size_test_case_1 -
            LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * (*sub_cert_count - 1));
        sub_cert_remainder_length = 0;
    }

    cert_rsp = (spdm_certificate_response_t*) ((uint8_t*) response);

    cert_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    cert_rsp->header.request_response_code = SPDM_CERTIFICATE;
    cert_rsp->header.param1 = 0;
    cert_rsp->header.param2 = 0;
    cert_rsp->portion_length = sub_cert_portion_length;
    cert_rsp->remainder_length = sub_cert_remainder_length;

    libspdm_copy_mem(
        cert_rsp + 1, sub_cert_portion_length,
        (uint8_t*) m_libspdm_local_certificate_chain_test_case_1 +
        LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN * sub_cert_index,
        sub_cert_portion_length);

    *response_size = sizeof(spdm_certificate_response_t) + sub_cert_portion_length;
}

void libspdm_requester_chunk_get_test_case2_build_measurements_response(
    void* context, void* response, size_t* response_size)
{
    libspdm_context_t* spdm_context;
    spdm_measurements_response_t* meas_rsp = NULL;
    spdm_measurement_block_dmtf_t* measurment_block;

    spdm_context = (libspdm_context_t*) context;
    /* This is get measurements test case 20, but changed to SPDM version 1.2
     * which includes opaque data */

    uint8_t* ptr;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

    *response_size = sizeof(spdm_measurements_response_t) +
                     2 * (sizeof(spdm_measurement_block_dmtf_t) +
                          libspdm_get_measurement_hash_size(
                              m_libspdm_use_measurement_hash_algo)) +
                     SPDM_NONCE_SIZE + sizeof(uint16_t);

    meas_rsp = (spdm_measurements_response_t*)((uint8_t*) response);
    meas_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    meas_rsp->header.request_response_code = SPDM_MEASUREMENTS;
    meas_rsp->header.param1 = 0;
    meas_rsp->header.param2 = 0;
    meas_rsp->number_of_blocks = 2;
    *(uint32_t*) meas_rsp->measurement_record_length =
        2 * ((uint32_t) (sizeof(spdm_measurement_block_dmtf_t) +
                         libspdm_get_measurement_hash_size(
                             m_libspdm_use_measurement_hash_algo)));
    measurment_block = (void*) (meas_rsp + 1);
    libspdm_set_mem(
        measurment_block,
        2 * (sizeof(spdm_measurement_block_dmtf_t) +
             libspdm_get_measurement_hash_size(
                 m_libspdm_use_measurement_hash_algo)),
        1);
    measurment_block->measurement_block_common_header.index = 1;
    measurment_block->measurement_block_common_header.measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    measurment_block->measurement_block_common_header.measurement_size =
        (uint16_t) (sizeof(spdm_measurement_block_dmtf_header_t) +
                    libspdm_get_measurement_hash_size(
                        m_libspdm_use_measurement_hash_algo));
    measurment_block =
        (void*) (((uint8_t*) measurment_block) +
                 (sizeof(spdm_measurement_block_dmtf_t) +
                  libspdm_get_measurement_hash_size(
                      m_libspdm_use_measurement_hash_algo)));
    measurment_block->measurement_block_common_header.index = 2;
    measurment_block->measurement_block_common_header.measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    measurment_block->measurement_block_common_header.measurement_size =
        (uint16_t) (sizeof(spdm_measurement_block_dmtf_header_t) +
                    libspdm_get_measurement_hash_size(
                        m_libspdm_use_measurement_hash_algo));
    ptr = (uint8_t*) meas_rsp + *response_size - SPDM_NONCE_SIZE - sizeof(uint16_t);
    libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
    ptr += SPDM_NONCE_SIZE;
    /* Set opaque data length to 0 */
    *ptr = 0;
    ptr++;
    *ptr = 0;
}

void libspdm_requester_chunk_get_test_case3_build_challenge_response(
    void* context, void* response, size_t* response_size)
{
    libspdm_context_t* spdm_context;
    spdm_challenge_auth_response_t* spdm_response;
    void* data;
    size_t data_size;
    uint8_t* ptr;
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    size_t sig_size;

    spdm_context = (libspdm_context_t*) context;
    libspdm_read_responder_public_certificate_chain(
        m_libspdm_use_hash_algo,
        m_libspdm_use_asym_algo, &data,
        &data_size, NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    *response_size = sizeof(spdm_challenge_auth_response_t) +
                     libspdm_get_hash_size(m_libspdm_use_hash_algo) +
                     SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 +
                     libspdm_get_asym_signature_size(m_libspdm_use_asym_algo);
    spdm_response = response;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_response->header.request_response_code = SPDM_CHALLENGE_AUTH;
    spdm_response->header.param1 = 0;
    spdm_response->header.param2 = (1 << 0);
    ptr = (void*) (spdm_response + 1);
    libspdm_hash_all(
        m_libspdm_use_hash_algo,
        spdm_context->local_context.local_cert_chain_provision[0],
        spdm_context->local_context.local_cert_chain_provision_size[0],
        ptr);
    free(data);
    data = NULL;

    ptr += libspdm_get_hash_size(m_libspdm_use_hash_algo);
    libspdm_get_random_number(SPDM_NONCE_SIZE, ptr);
    ptr += SPDM_NONCE_SIZE;
    /* libspdm_zero_mem (ptr, libspdm_get_hash_size (m_libspdm_use_hash_algo));
     * ptr += libspdm_get_hash_size (m_libspdm_use_hash_algo);*/
    *(uint16_t*) ptr = 0;
    ptr += sizeof(uint16_t);

    libspdm_copy_mem(
        &m_libspdm_local_buffer[m_libspdm_local_buffer_size],
        sizeof(m_libspdm_local_buffer) -
        (&m_libspdm_local_buffer[m_libspdm_local_buffer_size] - m_libspdm_local_buffer),
        spdm_response, (size_t) ptr - (size_t) spdm_response);
    m_libspdm_local_buffer_size += ((size_t) ptr - (size_t) spdm_response);
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
}

void libspdm_requester_chunk_get_test_case4_build_digest_response(
    void* context, void* response, size_t* response_size)
{
    libspdm_context_t *spdm_context;
    spdm_digest_response_t* spdm_response;
    uint8_t* digest;
    uint8_t slot_id;

    spdm_context = (libspdm_context_t*)context;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    *response_size = sizeof(spdm_digest_response_t) +
                     libspdm_get_hash_size(m_libspdm_use_hash_algo) * SPDM_MAX_SLOT_COUNT;
    spdm_response = response;

    spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    spdm_response->header.param1 = 0;
    spdm_response->header.request_response_code = SPDM_DIGESTS;
    spdm_response->header.param2 = 0;
    libspdm_set_mem(m_libspdm_local_certificate_chain_test_case_4,
                    sizeof(m_libspdm_local_certificate_chain_test_case_4),
                    (uint8_t) (0xFF));

    digest = (void*) (spdm_response + 1);
    libspdm_zero_mem(digest,
                     libspdm_get_hash_size(m_libspdm_use_hash_algo) * SPDM_MAX_SLOT_COUNT);
    for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
        libspdm_hash_all(
            m_libspdm_use_hash_algo,
            m_libspdm_local_certificate_chain_test_case_4,
            sizeof(m_libspdm_local_certificate_chain_test_case_4), &digest[0]);
        digest += libspdm_get_hash_size(m_libspdm_use_hash_algo);
    }
    spdm_response->header.param2 |= (0xFF << 0);
}

libspdm_return_t libspdm_requester_chunk_get_test_send_message(
    void* spdm_context, size_t request_size, const void* request,
    uint64_t timeout)
{
    libspdm_test_context_t* spdm_test_context;

    spdm_test_context = libspdm_get_test_context();
    if (spdm_test_context->case_id == 0x1) {
        return LIBSPDM_STATUS_SUCCESS;
    } else if (spdm_test_context->case_id == 0x2) {
        return LIBSPDM_STATUS_SUCCESS;
    } else if (spdm_test_context->case_id == 0x3) {
        const uint8_t* ptr;
        ptr = (const uint8_t*) request;

        if (ptr[2] == SPDM_CHALLENGE) {
            m_libspdm_local_buffer_size = 0;
            libspdm_copy_mem(m_libspdm_local_buffer, sizeof(m_libspdm_local_buffer),
                             &ptr[1], request_size - 1);
            m_libspdm_local_buffer_size += (request_size - 1);
        }
        return LIBSPDM_STATUS_SUCCESS;
    } else if (spdm_test_context->case_id == 0x4) {
        return LIBSPDM_STATUS_SUCCESS;
    } else if (spdm_test_context->case_id == 0x5) {
        return LIBSPDM_STATUS_SUCCESS;
    } else {
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t libspdm_requester_chunk_get_test_receive_message(
    void* spdm_context, size_t* response_size,
    void** response, uint64_t timeout)
{
    libspdm_test_context_t* spdm_test_context;
    uint8_t chunk_handle = CHUNK_GET_UNIT_TEST_CHUNK_HANDLE;
    static bool error_large_response_sent = false;

    static spdm_message_header_t* sub_rsp = NULL;
    static size_t sub_rsp_size = 0;
    static size_t sub_rsp_copied = 0;
    static size_t sub_rsp_remaining = 0;
    static uint16_t chunk_seq_no = 0;

    spdm_chunk_response_response_t* chunk_rsp;
    size_t chunk_rsp_size;
    uint8_t* chunk_copy_to;
    size_t chunk_copy_size;
    size_t transport_header_size;
    void (*build_response_func)(void*, void*, size_t *);

    build_response_func = NULL;

    spdm_test_context = libspdm_get_test_context();

    /* First response to these tests should always be error large response */
    if (error_large_response_sent == false) {
        error_large_response_sent = true;

        spdm_error_response_t* error_rsp;
        size_t error_rsp_size;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        error_rsp = (void*) ((uint8_t*) *response + transport_header_size);
        error_rsp_size = sizeof(spdm_error_response_t) + sizeof(uint8_t);

        error_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        error_rsp->header.request_response_code = SPDM_ERROR;
        error_rsp->header.param1 = SPDM_ERROR_CODE_LARGE_RESPONSE;
        error_rsp->header.param2 = 0;
        *((uint16_t*) (error_rsp + 1)) = chunk_handle;

        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            error_rsp_size, error_rsp,
            response_size, response);

        return LIBSPDM_STATUS_SUCCESS;
    }

    if (spdm_test_context->case_id == 0x1) {

        /* Refers to just the certificate portion in the cert response */
        static size_t sub_cert_index = 0;
        static size_t sub_cert_count = 0;

        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        chunk_rsp = (void*) ((uint8_t*) *response + transport_header_size);

        chunk_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_rsp->header.request_response_code = SPDM_CHUNK_RESPONSE;
        chunk_rsp->header.param1 = 0;
        chunk_rsp->header.param2 = chunk_handle;

        chunk_copy_to = (uint8_t*) (chunk_rsp + 1);
        chunk_copy_size = CHUNK_GET_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE
                          - sizeof(spdm_chunk_response_response_t);

        if (sub_rsp_copied == 0) {
            sub_rsp = (spdm_message_header_t*) m_libspdm_local_large_response_buffer;
            sub_rsp_size = sizeof(m_libspdm_local_large_response_buffer);
            libspdm_zero_mem(sub_rsp, sub_rsp_size);

            libspdm_requester_chunk_get_test_case1_build_certificates_response(
                spdm_context, sub_rsp, &sub_rsp_size, sub_cert_index, &sub_cert_count);

            sub_rsp_remaining = sub_rsp_size;
            sub_rsp_copied = 0;

            /* first chunk has size of large response */
            chunk_seq_no = 0;
            *((uint32_t*) (chunk_rsp + 1)) = (uint32_t) sub_rsp_size;

            chunk_copy_to += sizeof(uint32_t);
            chunk_copy_size -= sizeof(uint32_t);
            chunk_copy_size = LIBSPDM_MIN(sub_rsp_remaining, chunk_copy_size);
            chunk_rsp_size = sizeof(spdm_chunk_response_response_t)
                             + sizeof(uint32_t) + chunk_copy_size;
        } else {
            chunk_copy_size = LIBSPDM_MIN(sub_rsp_remaining, chunk_copy_size);
            chunk_rsp_size = sizeof(spdm_chunk_response_response_t) + chunk_copy_size;
        }

        if (chunk_copy_size == sub_rsp_remaining) {
            chunk_rsp->header.param1 = SPDM_CHUNK_GET_RESPONSE_ATTRIBUTE_LAST_CHUNK;
        }

        libspdm_copy_mem(chunk_copy_to,
                         *response_size - (chunk_copy_to - (uint8_t*)*response),
                         (uint8_t*) sub_rsp + sub_rsp_copied,
                         chunk_copy_size);

        sub_rsp_copied += chunk_copy_size;
        sub_rsp_remaining -= chunk_copy_size;
        chunk_rsp->chunk_size = (uint32_t) chunk_copy_size;
        chunk_rsp->chunk_seq_no = chunk_seq_no;
        chunk_seq_no++;

        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_rsp,
            response_size, response);

        if (sub_rsp_copied >= sub_rsp_size) {
            sub_cert_index++;
            sub_rsp = NULL;
            sub_rsp_size = 0;
            sub_rsp_copied = 0;
            sub_rsp_remaining = 0;
            chunk_seq_no = 0;
            error_large_response_sent = false;

            if (sub_cert_index == sub_cert_count) {
                sub_cert_index = 0;

                free(m_libspdm_local_certificate_chain_test_case_1);
                m_libspdm_local_certificate_chain_test_case_1 = NULL;
                m_libspdm_local_certificate_chain_size_test_case_1 = 0;
            }
        }

        return LIBSPDM_STATUS_SUCCESS;
    } else if (spdm_test_context->case_id == 0x2) {
        build_response_func =
            libspdm_requester_chunk_get_test_case2_build_measurements_response;
    } else if (spdm_test_context->case_id == 0x3) {
        build_response_func =
            libspdm_requester_chunk_get_test_case3_build_challenge_response;
    } else if (spdm_test_context->case_id == 0x4) {
        build_response_func =
            libspdm_requester_chunk_get_test_case4_build_digest_response;
    } else {
        LIBSPDM_ASSERT(0);
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    if (build_response_func) {
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        chunk_rsp = (void*) ((uint8_t*) *response + transport_header_size);

        chunk_rsp->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        chunk_rsp->header.request_response_code = SPDM_CHUNK_RESPONSE;
        chunk_rsp->header.param1 = 0;
        chunk_rsp->header.param2 = chunk_handle;

        chunk_copy_to = (uint8_t*) (chunk_rsp + 1);
        chunk_copy_size = CHUNK_GET_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE
                          - sizeof(spdm_chunk_response_response_t);

        if (sub_rsp_copied == 0) {

            sub_rsp = (spdm_message_header_t*) m_libspdm_local_large_response_buffer;
            sub_rsp_size = sizeof(m_libspdm_local_large_response_buffer);
            libspdm_zero_mem(sub_rsp, sub_rsp_size);

            build_response_func(spdm_context, sub_rsp, &sub_rsp_size);

            sub_rsp_remaining = sub_rsp_size;
            sub_rsp_copied = 0;

            /* first chunk has size of large response */
            chunk_seq_no = 0;
            *((uint32_t*) (chunk_rsp + 1)) = (uint32_t) sub_rsp_size;

            chunk_copy_to += sizeof(uint32_t);
            chunk_copy_size -= sizeof(uint32_t);
            chunk_copy_size = LIBSPDM_MIN(sub_rsp_remaining, chunk_copy_size);
            chunk_rsp_size = sizeof(spdm_chunk_response_response_t)
                             + sizeof(uint32_t) + chunk_copy_size;
        } else {
            chunk_copy_size = LIBSPDM_MIN(sub_rsp_remaining, chunk_copy_size);
            chunk_rsp_size = sizeof(spdm_chunk_response_response_t) + chunk_copy_size;
        }

        if (chunk_copy_size == sub_rsp_remaining) {
            chunk_rsp->header.param1 = SPDM_CHUNK_GET_RESPONSE_ATTRIBUTE_LAST_CHUNK;
        }

        libspdm_copy_mem(chunk_copy_to,
                         *response_size - (chunk_copy_to - (uint8_t*) *response),
                         (uint8_t*) sub_rsp + sub_rsp_copied,
                         chunk_copy_size);

        sub_rsp_copied += chunk_copy_size;
        sub_rsp_remaining -= chunk_copy_size;
        chunk_rsp->chunk_size = (uint32_t) chunk_copy_size;
        chunk_rsp->chunk_seq_no = chunk_seq_no++;

        libspdm_transport_test_encode_message(
            spdm_context, NULL, false, false,
            chunk_rsp_size, chunk_rsp,
            response_size, response);

        if (sub_rsp_copied >= sub_rsp_size) {
            sub_rsp = NULL;
            sub_rsp_size = 0;
            sub_rsp_copied = 0;
            sub_rsp_remaining = 0;
            chunk_seq_no = 0;
            error_large_response_sent = false;
        }
        return LIBSPDM_STATUS_SUCCESS;
    }
    return LIBSPDM_STATUS_SEND_FAIL;

}
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
void libspdm_test_requester_chunk_get_case1(void** state)
{
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    size_t cert_chain_size;
    uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    void* data;
    size_t data_size;
    void* hash;
    size_t hash_size;
    const uint8_t* root_cert;
    size_t root_cert_size;
    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    size_t count;
    #endif

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);

    spdm_context->local_context.capability.flags |=  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->local_context.capability.data_transfer_size
        = CHUNK_GET_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE;
    spdm_context->local_context.is_requester = true;

    libspdm_read_responder_public_certificate_chain(
        m_libspdm_use_hash_algo,
        m_libspdm_use_asym_algo, &data,
        &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain(
        (uint8_t*) data + sizeof(spdm_cert_chain_t) + hash_size,
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

    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
    #endif
    cert_chain_size = sizeof(cert_chain);
    libspdm_zero_mem(cert_chain, sizeof(cert_chain));
    status = libspdm_get_certificate(spdm_context, NULL, 0, &cert_chain_size, cert_chain);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    count = (data_size + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN - 1) / LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN;
    assert_int_equal(spdm_context->transcript.message_b.buffer_size,
                     sizeof(spdm_get_certificate_request_t) * count +
                     sizeof(spdm_certificate_response_t) * count +
                     data_size);
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = 0;
    #else
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size = 0;
    #endif
    free(data);
}
#endif
#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
void libspdm_test_requester_chunk_get_case2(void** state)
{
    /* Copied from Get Measurements Test Case 0x20 */
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    uint8_t number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t request_attribute;
    void* data;
    size_t data_size;
    void* hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x02;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->connection_info.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->local_context.capability.data_transfer_size
        = CHUNK_GET_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE;

    libspdm_read_responder_public_certificate_chain(
        m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
        &data, &data_size, &hash, &hash_size);
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
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = data_size;
    libspdm_copy_mem(
        spdm_context->connection_info.peer_used_cert_chain[0].buffer,
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
    status = libspdm_get_measurement(
        spdm_context, NULL, request_attribute,
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
        0, NULL, &number_of_block, &measurement_record_length,
        measurement_record);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size,
                     sizeof(spdm_message_header_t) +
                     sizeof(spdm_measurements_response_t) +
                     2 * (sizeof(spdm_measurement_block_dmtf_t) +
                          libspdm_get_measurement_hash_size(
                              m_libspdm_use_measurement_hash_algo)) +
                     sizeof(uint16_t) + SPDM_NONCE_SIZE);
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = 0;
    #else
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size = 0;
    #endif
    free(data);
}
#endif
#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
void libspdm_test_requester_chunk_get_case3(void** state)
{
    /* Copied from Challenge Test Case 2*/
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
    void* data;
    size_t data_size;
    void* hash;
    size_t hash_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->local_context.capability.data_transfer_size
        = CHUNK_GET_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE;

    libspdm_read_responder_public_certificate_chain(
        m_libspdm_use_hash_algo, m_libspdm_use_asym_algo,
        &data, &data_size, &hash, &hash_size);
    libspdm_reset_message_a(spdm_context);
    libspdm_reset_message_b(spdm_context);
    libspdm_reset_message_c(spdm_context);
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = data_size;
    libspdm_copy_mem(
        spdm_context->connection_info.peer_used_cert_chain[0].buffer,
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
    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_size = 0;
    #else
    spdm_context->connection_info.peer_used_cert_chain[0].buffer_hash_size = 0;
    #endif
}
#endif
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
void libspdm_test_requester_chunk_get_case4(void** state)
{
    /* Copied from Get Digests Test Case 2*/
    libspdm_return_t status;
    libspdm_test_context_t* spdm_test_context;
    libspdm_context_t* spdm_context;
    libspdm_data_parameter_t parameter;
    uint8_t slot_mask;
    uint8_t slot_id;
    uint8_t total_digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
    uint8_t my_total_digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
    uint8_t* digest;
    size_t data_return_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP
         | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP);

    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    spdm_context->local_context.capability.data_transfer_size
        = CHUNK_GET_REQUESTER_UNIT_TEST_DATA_TRANSFER_SIZE;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    libspdm_set_mem(
        m_libspdm_local_certificate_chain_test_case_4,
        sizeof(m_libspdm_local_certificate_chain_test_case_4),
        (uint8_t) (0xFF));
    libspdm_reset_message_b(spdm_context);

    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
    #endif
    libspdm_zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
    status = libspdm_get_digest(spdm_context, NULL, &slot_mask, &total_digest_buffer);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(slot_mask, 0xFF);
    libspdm_zero_mem(my_total_digest_buffer, sizeof(my_total_digest_buffer));
    digest = my_total_digest_buffer;
    for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
        libspdm_hash_all(m_libspdm_use_hash_algo,
                         m_libspdm_local_certificate_chain_test_case_4,
                         sizeof(m_libspdm_local_certificate_chain_test_case_4), digest);
        digest += libspdm_get_hash_size(m_libspdm_use_hash_algo);
    }
    assert_memory_equal(total_digest_buffer, my_total_digest_buffer,
                        sizeof(my_total_digest_buffer));

    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_return_size = sizeof(uint8_t);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_PEER_SLOT_MASK,
                              &parameter, &slot_mask, &data_return_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(data_return_size, sizeof(uint8_t));
    assert_int_equal(slot_mask, 0xFF);

    data_return_size = sizeof(total_digest_buffer);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_PEER_TOTAL_DIGEST_BUFFER,
                              &parameter, total_digest_buffer, &data_return_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(data_return_size, libspdm_get_hash_size(
                         m_libspdm_use_hash_algo) * SPDM_MAX_SLOT_COUNT);
    assert_memory_equal(total_digest_buffer, my_total_digest_buffer,
                        sizeof(my_total_digest_buffer));

    #if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(
        spdm_context->transcript.message_b.buffer_size,
        sizeof(spdm_get_digest_request_t) +
        sizeof(spdm_digest_response_t) +
        libspdm_get_hash_size(spdm_context->connection_info
                              .algorithm.base_hash_algo) * SPDM_MAX_SLOT_COUNT);
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
    #endif
}
#endif

libspdm_test_context_t m_libspdm_requester_chunk_get_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_chunk_get_test_send_message,
    libspdm_requester_chunk_get_test_receive_message,
};

int libspdm_requester_chunk_get_test_main(void)
{
    /* Test the CHUNK_GET handlers in various requester handlers */
    const struct CMUnitTest spdm_requester_chunk_get_tests[] = {
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
        /* Request a certificate in portions */
        cmocka_unit_test(libspdm_test_requester_chunk_get_case1),
#endif
#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
        /* Request all measurements */
        cmocka_unit_test(libspdm_test_requester_chunk_get_case2),
#endif
#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
        /* Request Challenge */
        cmocka_unit_test(libspdm_test_requester_chunk_get_case3),
#endif
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
        /* Request Digests */
        cmocka_unit_test(libspdm_test_requester_chunk_get_case4),
#endif
    };

    libspdm_setup_test_context(
        &m_libspdm_requester_chunk_get_test_context);

    return cmocka_run_group_tests(spdm_requester_chunk_get_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP*/
