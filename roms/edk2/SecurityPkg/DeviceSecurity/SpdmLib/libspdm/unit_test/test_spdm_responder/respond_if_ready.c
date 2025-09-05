/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_RESPOND_IF_READY_SUPPORT

#if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP || LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP || \
     LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP || LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || \
     LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)

#define LIBSPDM_MY_TEST_TOKEN            0x30
#define LIBSPDM_MY_WRONG_TEST_TOKEN      0x2F

static libspdm_th_managed_buffer_t th_curr;

extern size_t libspdm_secret_lib_challenge_opaque_data_size;

spdm_response_if_ready_request_t m_libspdm_respond_if_ready_request1 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_RESPOND_IF_READY,
        SPDM_GET_DIGESTS,
        LIBSPDM_MY_TEST_TOKEN
    },
};
size_t m_libspdm_respond_if_ready_request1_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t m_libspdm_respond_if_ready_request2 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_RESPOND_IF_READY,
        SPDM_GET_CERTIFICATE,
        LIBSPDM_MY_TEST_TOKEN
    },
};
size_t m_libspdm_respond_if_ready_request2_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t m_libspdm_respond_if_ready_request3 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_RESPOND_IF_READY,
        SPDM_CHALLENGE,
        LIBSPDM_MY_TEST_TOKEN
    },
};
size_t m_libspdm_respond_if_ready_request3_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t m_libspdm_respond_if_ready_request4 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_RESPOND_IF_READY,
        SPDM_GET_MEASUREMENTS,
        LIBSPDM_MY_TEST_TOKEN
    },
};
size_t m_libspdm_respond_if_ready_request4_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t m_libspdm_respond_if_ready_request5 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_RESPOND_IF_READY,
        SPDM_KEY_EXCHANGE,
        LIBSPDM_MY_TEST_TOKEN
    },
};
size_t m_libspdm_respond_if_ready_request5_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t m_libspdm_respond_if_ready_request6 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_RESPOND_IF_READY,
        SPDM_FINISH,
        LIBSPDM_MY_TEST_TOKEN
    },
};
size_t m_libspdm_respond_if_ready_request6_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t m_libspdm_respond_if_ready_request7 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_RESPOND_IF_READY,
        SPDM_PSK_EXCHANGE,
        LIBSPDM_MY_TEST_TOKEN
    },
};
size_t m_libspdm_respond_if_ready_request7_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t m_libspdm_respond_if_ready_request8 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_RESPOND_IF_READY,
        SPDM_PSK_FINISH,
        LIBSPDM_MY_TEST_TOKEN
    },
};
size_t m_libspdm_respond_if_ready_request8_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t m_libspdm_respond_if_ready_request10 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_RESPOND_IF_READY,
        SPDM_GET_DIGESTS,
        LIBSPDM_MY_WRONG_TEST_TOKEN /*wrong token*/
    },
};
size_t m_libspdm_respond_if_ready_request10_size = sizeof(spdm_message_header_t);

spdm_response_if_ready_request_t m_libspdm_respond_if_ready_request11 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_RESPOND_IF_READY,
        SPDM_GET_CERTIFICATE, /*wrong original request code*/
        LIBSPDM_MY_TEST_TOKEN
    },
};
size_t m_libspdm_respond_if_ready_request11_size = sizeof(spdm_message_header_t);

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
spdm_get_digest_request_t m_libspdm_get_digest_request = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_DIGESTS,
        0,
        0
    },
};
size_t m_libspdm_get_digest_request_size = sizeof(spdm_message_header_t);

spdm_get_certificate_request_t m_libspdm_get_certificate_request = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CERTIFICATE,
        0,
        0
    },
    0,
    LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN
};
size_t m_libspdm_get_certificate_request_size = sizeof(m_libspdm_get_certificate_request);

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP

spdm_challenge_request_t m_libspdm_challenge_request = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_CHALLENGE,
        0,
        SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH
    },
};
size_t m_libspdm_challenge_request_size = sizeof(m_libspdm_challenge_request);

#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
spdm_get_measurements_request_t m_libspdm_get_measurements_request = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_MEASUREMENTS,
        0,
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS
    },
};
size_t m_libspdm_get_measurements_request_size = sizeof(spdm_message_header_t);
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

#pragma pack(1)

typedef struct {
    spdm_message_header_t header;
    uint16_t req_session_id;
    uint8_t session_policy;
    uint8_t reserved;
    uint8_t random_data[SPDM_RANDOM_DATA_SIZE];
    uint8_t exchange_data[LIBSPDM_MAX_DHE_KEY_SIZE];
    uint16_t opaque_length;
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
} libspdm_key_exchange_request_mine_t;

typedef struct {
    spdm_message_header_t header;
    uint8_t signature[LIBSPDM_MAX_ASYM_KEY_SIZE];
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} libspdm_finish_request_mine_t;

typedef struct {
    spdm_message_header_t header;
    uint16_t req_session_id;
    uint16_t psk_hint_length;
    uint16_t requester_context_length;
    uint16_t opaque_length;
    uint8_t psk_hint[LIBSPDM_PSK_MAX_HINT_LENGTH];
    uint8_t requester_context[LIBSPDM_PSK_CONTEXT_LENGTH];
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
} libspdm_psk_exchange_request_mine_t;

typedef struct {
    spdm_message_header_t header;
    uint8_t verify_data[LIBSPDM_MAX_HASH_SIZE];
} libspdm_psk_finish_request_mine_t;

#pragma pack()

libspdm_key_exchange_request_mine_t m_libspdm_key_exchange_request = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_KEY_EXCHANGE,
        SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        0
    },
};
size_t m_libspdm_key_exchange_request_size = sizeof(m_libspdm_key_exchange_request);

libspdm_finish_request_mine_t m_libspdm_finish_request = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_FINISH,
        0,
        0
    },
};
size_t m_libspdm_finish_request_size = sizeof(m_libspdm_finish_request);

libspdm_psk_exchange_request_mine_t m_libspdm_psk_exchange_request = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_PSK_EXCHANGE,
        SPDM_PSK_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
        0
    },
};
size_t m_libspdm_psk_exchange_request_size = sizeof(m_libspdm_psk_exchange_request);

libspdm_psk_finish_request_mine_t m_libspdm_psk_finish_request = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_PSK_FINISH,
        0,
        0
    },
};
size_t m_libspdm_psk_finish_request_size = sizeof(m_libspdm_psk_finish_request);

spdm_end_session_request_t m_libspdm_end_session_request = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_END_SESSION,
        0,
        0
    }
};
size_t m_libspdm_end_session_request_size = sizeof(m_libspdm_end_session_request);
#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
static uint8_t m_libspdm_local_certificate_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
#endif
static void libspdm_secured_message_set_request_finished_key(
    void *spdm_secured_message_context, const void *key, size_t key_size)
{
    libspdm_secured_message_context_t *secured_message_context;

    secured_message_context = spdm_secured_message_context;
    LIBSPDM_ASSERT(key_size == secured_message_context->hash_size);
    libspdm_copy_mem(secured_message_context->handshake_secret.request_finished_key,
                     sizeof(secured_message_context->handshake_secret.request_finished_key),
                     key, secured_message_context->hash_size);
}

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
/**
 * Test 1: receiving a correct RESPOND_IF_READY from the requester, after a
 * GET_DIGESTS could not be processed.
 * Expected behavior: the responder accepts the request and produces a valid DIGESTS
 * response message.
 **/
void libspdm_test_responder_respond_if_ready_case1(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response; /*response to the original request (DIGESTS)*/

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    /*state for the the original request (GET_DIGESTS)*/
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.local_cert_chain_provision[0] = m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    libspdm_set_mem (m_libspdm_local_certificate_chain, sizeof(m_libspdm_local_certificate_chain),
                     (uint8_t)(0xFF));

    spdm_context->last_spdm_request_size = m_libspdm_get_digest_request_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &m_libspdm_get_digest_request, m_libspdm_get_digest_request_size);

    /*RESPOND_IF_READY specific data*/
    spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm        = 1;
    spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
    spdm_context->error_data.token       = LIBSPDM_MY_TEST_TOKEN;

    /*check DIGESTS response*/
    response_size = sizeof(response);
    status = libspdm_get_response_respond_if_ready(spdm_context,
                                                   m_libspdm_respond_if_ready_request1_size,
                                                   &m_libspdm_respond_if_ready_request1,
                                                   &response_size,
                                                   response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size,
                      sizeof(spdm_digest_response_t) +
                      libspdm_get_hash_size(spdm_context->connection_info.algorithm.base_hash_algo));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_DIGESTS);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

/**
 * Test 2: receiving a correct RESPOND_IF_READY from the requester, after a
 * GET_CERTIFICATE could not be processed.
 * Expected behavior: the responder accepts the request and produces a valid CERTIFICATE
 * response message.
 **/

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

void libspdm_test_responder_respond_if_ready_case2(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_certificate_response_t *spdm_response; /*response to the original request (CERTIFICATE)*/
    void                 *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    /*state for the the original request (GET_CERTIFICATE)*/
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    spdm_context->last_spdm_request_size = m_libspdm_get_certificate_request_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &m_libspdm_get_certificate_request, m_libspdm_get_certificate_request_size);

    /*RESPOND_IF_READY specific data*/
    spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm        = 1;
    spdm_context->error_data.request_code = SPDM_GET_CERTIFICATE;
    spdm_context->error_data.token       = LIBSPDM_MY_TEST_TOKEN;

    /*check CERTIFICATE response*/
    response_size = sizeof(response);
    status = libspdm_get_response_respond_if_ready(spdm_context,
                                                   m_libspdm_respond_if_ready_request2_size,
                                                   &m_libspdm_respond_if_ready_request2,
                                                   &response_size,
                                                   response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size,
                      sizeof(spdm_certificate_response_t) + LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_CERTIFICATE);
    assert_int_equal (spdm_response->header.param1, 0);
    assert_int_equal (spdm_response->portion_length, LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    assert_int_equal (spdm_response->remainder_length,
                      data_size - LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN);
    free(data);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

/**
 * Test 3: receiving a correct RESPOND_IF_READY from the requester, after a
 * CHALLENGE could not be processed.
 * Expected behavior: the responder accepts the request and produces a valid CHALLENGE_AUTH
 * response message.
 **/
#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
void libspdm_test_responder_respond_if_ready_case3(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_challenge_auth_response_t *spdm_response; /*response to the original request (CHALLENGE_AUTH)*/
    void                 *data;
    size_t data_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    /*state for the the original request (CHALLENGE)*/
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    libspdm_secret_lib_challenge_opaque_data_size = 0;

    spdm_context->last_spdm_request_size = m_libspdm_challenge_request_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &m_libspdm_challenge_request, m_libspdm_challenge_request_size);

    /*RESPOND_IF_READY specific data*/
    spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm        = 1;
    spdm_context->error_data.request_code = SPDM_CHALLENGE;
    spdm_context->error_data.token       = LIBSPDM_MY_TEST_TOKEN;

    /*check CHALLENGE response*/
    response_size = sizeof(response);
    libspdm_get_random_number (SPDM_NONCE_SIZE, m_libspdm_challenge_request.nonce);
    status = libspdm_get_response_respond_if_ready(spdm_context,
                                                   m_libspdm_respond_if_ready_request3_size,
                                                   &m_libspdm_respond_if_ready_request3,
                                                   &response_size,
                                                   response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_challenge_auth_response_t) + libspdm_get_hash_size (
                          m_libspdm_use_hash_algo) + SPDM_NONCE_SIZE + 0 + sizeof(uint16_t) + 0 + libspdm_get_asym_signature_size (
                          m_libspdm_use_asym_algo));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_CHALLENGE_AUTH);
    assert_int_equal (spdm_response->header.param1, 0);
    assert_int_equal (spdm_response->header.param2, 1 << 0);
    free(data);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/

/**
 * Test 4: receiving a correct RESPOND_IF_READY from the requester, after a
 * GET_MEASUREMENTS could not be processed.
 * Expected behavior: the responder accepts the request and produces a valid MEASUREMENTS
 * response message.
 **/

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP

extern size_t libspdm_secret_lib_meas_opaque_data_size;

void libspdm_test_responder_respond_if_ready_case4(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_measurements_response_t *spdm_response; /*response to the original request (MEASUREMENTS)*/

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    /*state for the the original request (GET_MEASUREMENTS)*/
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags = 0;
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

    spdm_context->last_spdm_request_size = m_libspdm_get_measurements_request_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &m_libspdm_get_measurements_request, m_libspdm_get_measurements_request_size);

    /*RESPOND_IF_READY specific data*/
    spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm        = 1;
    spdm_context->error_data.request_code = SPDM_GET_MEASUREMENTS;
    spdm_context->error_data.token       = LIBSPDM_MY_TEST_TOKEN;

    /*check MEASUREMENT response*/
    response_size = sizeof(response);
    libspdm_get_random_number (SPDM_NONCE_SIZE, m_libspdm_get_measurements_request.nonce);
    status = libspdm_get_response_respond_if_ready(spdm_context,
                                                   m_libspdm_respond_if_ready_request4_size,
                                                   &m_libspdm_respond_if_ready_request4,
                                                   &response_size,
                                                   response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size,
                      sizeof(spdm_measurements_response_t) + sizeof(uint16_t) + SPDM_NONCE_SIZE);
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_MEASUREMENTS);
    assert_int_equal (spdm_response->header.param1, LIBSPDM_MEASUREMENT_BLOCK_NUMBER);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

/**
 * Test 5: receiving a correct RESPOND_IF_READY from the requester, after a
 * KEY_EXCHANGE could not be processed.
 * Expected behavior: the responder accepts the request and produces a valid KEY_EXCHANGE_RSP
 * response message.
 **/
#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

void libspdm_test_responder_respond_if_ready_case5(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_key_exchange_response_t *spdm_response; /*response to the original request (KEY_EXCHANGE_RSP)*/
    void                 *data;
    size_t data_size;
    uint8_t                *ptr;
    size_t dhe_key_size;
    void                 *dhe_context;
    size_t opaque_key_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    /*state for the the original request (KEY_EXCHANGE)*/
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;

    spdm_context->local_context.mut_auth_requested = 0;

    m_libspdm_key_exchange_request.req_session_id = 0xFFFF;
    m_libspdm_key_exchange_request.reserved = 0;
    ptr = m_libspdm_key_exchange_request.random_data;
    libspdm_get_random_number (SPDM_RANDOM_DATA_SIZE, ptr);
    ptr += SPDM_RANDOM_DATA_SIZE;
    dhe_key_size = libspdm_get_dhe_pub_key_size (m_libspdm_use_dhe_algo);
    dhe_context = libspdm_dhe_new (spdm_context->connection_info.version, m_libspdm_use_dhe_algo,
                                   false);
    libspdm_dhe_generate_key (m_libspdm_use_dhe_algo, dhe_context, ptr, &dhe_key_size);
    ptr += dhe_key_size;
    libspdm_dhe_free (m_libspdm_use_dhe_algo, dhe_context);
    opaque_key_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size (spdm_context);
    *(uint16_t *)ptr = (uint16_t)opaque_key_exchange_req_size;
    ptr += sizeof(uint16_t);
    libspdm_build_opaque_data_supported_version_data (spdm_context, &opaque_key_exchange_req_size,
                                                      ptr);
    ptr += opaque_key_exchange_req_size;

    spdm_context->last_spdm_request_size = m_libspdm_key_exchange_request_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &m_libspdm_key_exchange_request, m_libspdm_key_exchange_request_size);

    /*RESPOND_IF_READY specific data*/
    spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm        = 1;
    spdm_context->error_data.request_code = SPDM_KEY_EXCHANGE;
    spdm_context->error_data.token       = LIBSPDM_MY_TEST_TOKEN;

    /*check KEY_EXCHANGE_RSP response*/
    response_size = sizeof(response);
    status = libspdm_get_response_respond_if_ready(spdm_context,
                                                   m_libspdm_respond_if_ready_request5_size,
                                                   &m_libspdm_respond_if_ready_request5,
                                                   &response_size,
                                                   response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_key_exchange_response_t) + dhe_key_size + 2 + libspdm_get_opaque_data_version_selection_data_size(
                          spdm_context) + libspdm_get_asym_signature_size (
                          m_libspdm_use_asym_algo) +
                      libspdm_get_hash_size (m_libspdm_use_hash_algo));
    assert_int_equal (libspdm_secured_message_get_session_state (spdm_context->session_info[0].
                                                                 secured_message_context),
                      LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_KEY_EXCHANGE_RSP);
    assert_int_equal (spdm_response->rsp_session_id, 0xFFFF);
    free(data);
    libspdm_free_session_id (spdm_context, (0xFFFFFFFF));
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

/**
 * Test 6: receiving a correct RESPOND_IF_READY from the requester, after a
 * FINISH could not be processed.
 * Expected behavior: the responder accepts the request and produces a valid FINISH_RSP
 * response message.
 **/
#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

void libspdm_test_responder_respond_if_ready_case6(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_finish_response_t *spdm_response; /*response to the original request (FINISH_RSP)*/
    void                 *data;
    size_t data_size;
    uint8_t                *ptr;
    uint8_t dummy_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t                *cert_buffer;
    size_t cert_buffer_size;
    uint8_t cert_buffer_hash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t    *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    /*state for the the original request (FINISH)*/
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->connection_info.local_used_cert_chain_buffer = data;
    spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size;

    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init (spdm_context, session_info, session_id, false);
    hash_size = libspdm_get_hash_size (m_libspdm_use_hash_algo);
    libspdm_set_mem (dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key (session_info->secured_message_context,
                                                      dummy_buffer, hash_size);
    libspdm_secured_message_set_session_state (session_info->secured_message_context,
                                               LIBSPDM_SESSION_STATE_HANDSHAKING);

    hash_size = libspdm_get_hash_size (m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size (m_libspdm_use_hash_algo);
    ptr = m_libspdm_finish_request.signature;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    cert_buffer = (uint8_t *)data;
    cert_buffer_size = data_size;
    libspdm_hash_all (m_libspdm_use_hash_algo, cert_buffer, cert_buffer_size, cert_buffer_hash);
    /* Transcript.MessageA size is 0*/
    libspdm_append_managed_buffer (&th_curr, cert_buffer_hash, hash_size);
    /* SessionTranscript.MessageK is 0*/
    libspdm_append_managed_buffer (&th_curr, (uint8_t *)&m_libspdm_finish_request,
                                   sizeof(spdm_finish_request_t));
    libspdm_set_mem (request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);

    spdm_context->last_spdm_request_size = sizeof(spdm_finish_request_t) + hmac_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &m_libspdm_finish_request, m_libspdm_finish_request_size);

    /*RESPOND_IF_READY specific data*/
    spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm        = 1;
    spdm_context->error_data.request_code = SPDM_FINISH;
    spdm_context->error_data.token       = LIBSPDM_MY_TEST_TOKEN;

    /*check FINISH_RSP response*/
    response_size = sizeof(response);
    status = libspdm_get_response_respond_if_ready(spdm_context,
                                                   m_libspdm_respond_if_ready_request6_size,
                                                   &m_libspdm_respond_if_ready_request6,
                                                   &response_size,
                                                   response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_finish_response_t) + hmac_size);
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_FINISH_RSP);
    free(data);
    libspdm_free_session_id (spdm_context, (0xFFFFFFFF));
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

/**
 * Test 7: receiving a correct RESPOND_IF_READY from the requester, after a
 * PSK_EXCHANGE could not be processed.
 * Expected behavior: the responder accepts the request and produces a valid PSK_EXCHANGE_RSP
 * response message.
 **/
#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP

void libspdm_test_responder_respond_if_ready_case7(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_exchange_response_t *spdm_response; /*response to the original request (PSK_EXCHANGE_RSP)*/
    void                 *data;
    size_t data_size;
    uint8_t                *ptr;
    size_t opaque_psk_exchange_req_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    /*state for the the original request (PSK_EXCHANGE)*/
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;
    spdm_context->connection_info.algorithm.key_schedule = m_libspdm_use_key_schedule_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->connection_info.local_used_cert_chain_buffer = data;
    spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size;

    m_libspdm_psk_exchange_request.psk_hint_length =
        (uint16_t)sizeof(LIBSPDM_TEST_PSK_HINT_STRING);
    m_libspdm_psk_exchange_request.requester_context_length = LIBSPDM_PSK_CONTEXT_LENGTH;
    opaque_psk_exchange_req_size =
        libspdm_get_opaque_data_supported_version_data_size (spdm_context);
    m_libspdm_psk_exchange_request.opaque_length = (uint16_t)opaque_psk_exchange_req_size;
    m_libspdm_psk_exchange_request.req_session_id = 0xFFFF;
    ptr = m_libspdm_psk_exchange_request.psk_hint;
    libspdm_copy_mem(ptr, sizeof(m_libspdm_psk_exchange_request.psk_hint),
                     LIBSPDM_TEST_PSK_HINT_STRING,
                     sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    ptr += m_libspdm_psk_exchange_request.psk_hint_length;
    libspdm_get_random_number (LIBSPDM_PSK_CONTEXT_LENGTH, ptr);
    ptr += m_libspdm_psk_exchange_request.requester_context_length;
    libspdm_build_opaque_data_supported_version_data (spdm_context, &opaque_psk_exchange_req_size,
                                                      ptr);
    ptr += opaque_psk_exchange_req_size;

    spdm_context->last_spdm_request_size = m_libspdm_psk_exchange_request_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &m_libspdm_psk_exchange_request, m_libspdm_psk_exchange_request_size);

    /*RESPOND_IF_READY specific data*/
    spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm        = 1;
    spdm_context->error_data.request_code = SPDM_PSK_EXCHANGE;
    spdm_context->error_data.token       = LIBSPDM_MY_TEST_TOKEN;

    /*check PSK_EXCHANGE_RSP response*/
    response_size = sizeof(response);
    status = libspdm_get_response_respond_if_ready(spdm_context,
                                                   m_libspdm_respond_if_ready_request7_size,
                                                   &m_libspdm_respond_if_ready_request7,
                                                   &response_size,
                                                   response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_psk_exchange_response_t) + LIBSPDM_PSK_CONTEXT_LENGTH + libspdm_get_opaque_data_version_selection_data_size(
                          spdm_context) + libspdm_get_hash_size (m_libspdm_use_hash_algo));
    assert_int_equal (libspdm_secured_message_get_session_state (spdm_context->session_info[0].
                                                                 secured_message_context),
                      LIBSPDM_SESSION_STATE_HANDSHAKING);
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_PSK_EXCHANGE_RSP);
    assert_int_equal (spdm_response->rsp_session_id, 0xFFFF);
    free(data);
    libspdm_free_session_id (spdm_context, (0xFFFFFFFF));
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/

/**
 * Test 8: receiving a correct RESPOND_IF_READY from the requester, after a
 * PSK_FINISH could not be processed.
 * Expected behavior: the responder accepts the request and produces a valid PSK_FINISH_RSP
 * response message.
 **/
#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
void libspdm_test_responder_respond_if_ready_case8(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_psk_finish_response_t *spdm_response; /*response to the original request (FINISH_PSK_RSP)*/
    void                 *data;
    size_t data_size;
    uint8_t                *ptr;
    uint8_t dummy_buffer[LIBSPDM_MAX_HASH_SIZE];
    uint8_t hash_data[LIBSPDM_MAX_HASH_SIZE];
    uint8_t request_finished_key[LIBSPDM_MAX_HASH_SIZE];
    libspdm_session_info_t    *session_info;
    uint32_t session_id;
    uint32_t hash_size;
    uint32_t hmac_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    /*state for the the original request (FINISH)*/
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AUTHENTICATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.measurement_spec = m_libspdm_use_measurement_spec;
    spdm_context->connection_info.algorithm.measurement_hash_algo =
        m_libspdm_use_measurement_hash_algo;
    spdm_context->connection_info.algorithm.dhe_named_group = m_libspdm_use_dhe_algo;
    spdm_context->connection_info.algorithm.aead_cipher_suite = m_libspdm_use_aead_algo;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_read_responder_public_certificate_chain (m_libspdm_use_hash_algo,
                                                     m_libspdm_use_asym_algo,
                                                     &data, &data_size,
                                                     NULL, NULL);
    spdm_context->local_context.local_cert_chain_provision[0] = data;
    spdm_context->local_context.local_cert_chain_provision_size[0] = data_size;
    spdm_context->connection_info.local_used_cert_chain_buffer = data;
    spdm_context->connection_info.local_used_cert_chain_buffer_size = data_size;

    spdm_context->local_context.mut_auth_requested = 0;

    session_id = 0xFFFFFFFF;
    spdm_context->latest_session_id = session_id;
    spdm_context->last_spdm_request_session_id_valid = true;
    spdm_context->last_spdm_request_session_id = session_id;
    session_info = &spdm_context->session_info[0];
    libspdm_session_info_init (spdm_context, session_info, session_id, true);
    libspdm_session_info_set_psk_hint(session_info,
                                      LIBSPDM_TEST_PSK_HINT_STRING,
                                      sizeof(LIBSPDM_TEST_PSK_HINT_STRING));
    hash_size = libspdm_get_hash_size (m_libspdm_use_hash_algo);
    libspdm_set_mem (dummy_buffer, hash_size, (uint8_t)(0xFF));
    libspdm_secured_message_set_request_finished_key (session_info->secured_message_context,
                                                      dummy_buffer, hash_size);
    libspdm_secured_message_set_session_state (session_info->secured_message_context,
                                               LIBSPDM_SESSION_STATE_HANDSHAKING);

    hash_size = libspdm_get_hash_size (m_libspdm_use_hash_algo);
    hmac_size = libspdm_get_hash_size (m_libspdm_use_hash_algo);
    ptr = m_libspdm_psk_finish_request.verify_data;
    libspdm_init_managed_buffer(&th_curr, sizeof(th_curr.buffer));
    /* Transcript.MessageA size is 0
     * SessionTranscript.MessageK is 0*/
    libspdm_append_managed_buffer (&th_curr, (uint8_t *)&m_libspdm_psk_finish_request,
                                   sizeof(spdm_psk_finish_request_t));
    libspdm_set_mem (request_finished_key, LIBSPDM_MAX_HASH_SIZE, (uint8_t)(0xFF));
    libspdm_hash_all(m_libspdm_use_hash_algo, libspdm_get_managed_buffer(&th_curr),
                     libspdm_get_managed_buffer_size(&th_curr), hash_data);
    libspdm_hmac_all(m_libspdm_use_hash_algo, hash_data, hash_size,
                     request_finished_key, hash_size, ptr);

    spdm_context->last_spdm_request_size = sizeof(spdm_psk_finish_request_t) + hmac_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &m_libspdm_psk_finish_request, m_libspdm_psk_finish_request_size);

    /*RESPOND_IF_READY specific data*/
    spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm        = 1;
    spdm_context->error_data.request_code = SPDM_PSK_FINISH;
    spdm_context->error_data.token       = LIBSPDM_MY_TEST_TOKEN;

    /*check FINISH_PSK_RSP response*/
    response_size = sizeof(response);
    status = libspdm_get_response_respond_if_ready(spdm_context,
                                                   m_libspdm_respond_if_ready_request8_size,
                                                   &m_libspdm_respond_if_ready_request8,
                                                   &response_size,
                                                   response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_psk_finish_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_PSK_FINISH_RSP);
    free(data);
    libspdm_free_session_id (spdm_context, (0xFFFFFFFF));
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

/**
 * Test 9:
 * Expected behavior:
 **/
void libspdm_test_responder_respond_if_ready_case9(void **state) {
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
/**
 * Test 10: receiving a correct RESPOND_IF_READY from the requester, but the responder is in
 * a Busy state.
 * Expected behavior: the responder accepts the request, but produces an ERROR message
 * indicating the Busy state.
 **/
void libspdm_test_responder_respond_if_ready_case10(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response; /*response to the original request (DIGESTS)*/

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;

    /*state for the the original request (GET_DIGESTS)*/
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    libspdm_set_mem (m_libspdm_local_certificate_chain, sizeof(m_libspdm_local_certificate_chain),
                     (uint8_t)(0xFF));

    spdm_context->last_spdm_request_size = m_libspdm_get_digest_request_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &m_libspdm_get_digest_request, m_libspdm_get_digest_request_size);

    /*RESPOND_IF_READY specific data*/
    spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm        = 1;
    spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
    spdm_context->error_data.token       = LIBSPDM_MY_TEST_TOKEN;

    /*check ERROR response*/
    response_size = sizeof(response);
    status = libspdm_get_response_respond_if_ready(spdm_context,
                                                   m_libspdm_respond_if_ready_request1_size,
                                                   &m_libspdm_respond_if_ready_request1,
                                                   &response_size,
                                                   response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
    assert_int_equal (spdm_response->header.param2, 0);
    assert_int_equal (spdm_context->response_state, LIBSPDM_RESPONSE_STATE_BUSY);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
/**
 * Test 11: receiving a correct RESPOND_IF_READY from the requester, but the responder requires
 * resynchronization with the requester.
 * Expected behavior: the responder accepts the request, but produces an ERROR message
 * indicating the NeedResynch state.
 **/
void libspdm_test_responder_respond_if_ready_case11(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response; /*response to the original request (DIGESTS)*/

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;

    /*state for the the original request (GET_DIGESTS)*/
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    libspdm_set_mem (m_libspdm_local_certificate_chain, sizeof(m_libspdm_local_certificate_chain),
                     (uint8_t)(0xFF));

    spdm_context->last_spdm_request_size = m_libspdm_get_digest_request_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &m_libspdm_get_digest_request, m_libspdm_get_digest_request_size);

    /*RESPOND_IF_READY specific data*/
    spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm        = 1;
    spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
    spdm_context->error_data.token       = LIBSPDM_MY_TEST_TOKEN;

    /*check ERROR response*/
    response_size = sizeof(response);
    status = libspdm_get_response_respond_if_ready(spdm_context,
                                                   m_libspdm_respond_if_ready_request1_size,
                                                   &m_libspdm_respond_if_ready_request1,
                                                   &response_size,
                                                   response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
    assert_int_equal (spdm_response->header.param2, 0);
    assert_int_equal (spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NEED_RESYNC);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

/**
 * Test 12: receiving a correct RESPOND_IF_READY from the requester, but the responder could not
 * produce the response in time.
 * Expected behavior: the responder accepts the request, but produces an ERROR message
 * indicating the ResponseNotReady state, with the same token as the request.
 **/
void libspdm_test_responder_respond_if_ready_case12(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response; /*response to the original request (DIGESTS)*/
    spdm_error_data_response_not_ready_t *error_data;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NOT_READY;

    /*state for the the original request (GET_DIGESTS)*/
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    libspdm_set_mem (m_libspdm_local_certificate_chain, sizeof(m_libspdm_local_certificate_chain),
                     (uint8_t)(0xFF));

    spdm_context->last_spdm_request_size = m_libspdm_get_digest_request_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &m_libspdm_get_digest_request, m_libspdm_get_digest_request_size);

    /*RESPOND_IF_READY specific data*/
    spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm        = 1;
    spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
    spdm_context->error_data.token       = LIBSPDM_MY_TEST_TOKEN;

    /*check ERROR response*/
    response_size = sizeof(response);
    status = libspdm_get_response_respond_if_ready(spdm_context,
                                                   m_libspdm_respond_if_ready_request1_size,
                                                   &m_libspdm_respond_if_ready_request1,
                                                   &response_size,
                                                   response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size,
                      sizeof(spdm_error_response_t) + sizeof(spdm_error_data_response_not_ready_t));
    spdm_response = (void *)response;
    error_data = (spdm_error_data_response_not_ready_t*)(spdm_response + 1);
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
    assert_int_equal (spdm_response->header.param2, 0);
    assert_int_equal (spdm_context->response_state, LIBSPDM_RESPONSE_STATE_NOT_READY);
    assert_int_equal (error_data->request_code, SPDM_GET_DIGESTS);
    assert_int_equal (error_data->token, LIBSPDM_MY_TEST_TOKEN);
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP

/**
 * Test 13: receiving a correct RESPOND_IF_READY from the requester, with the correct original
 * request code, but with a token different from the expected.
 * Expected behavior: the responder refuses the RESPOND_IF_READY message and produces an
 * ERROR message indicating the InvalidRequest.
 **/
void libspdm_test_responder_respond_if_ready_case13(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response; /*response to the original request (DIGESTS)*/

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    /*state for the the original request (GET_DIGESTS)*/
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    libspdm_set_mem (m_libspdm_local_certificate_chain, sizeof(m_libspdm_local_certificate_chain),
                     (uint8_t)(0xFF));

    spdm_context->last_spdm_request_size = m_libspdm_get_digest_request_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &m_libspdm_get_digest_request, m_libspdm_get_digest_request_size);

    /*RESPOND_IF_READY specific data*/
    spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm        = 1;
    spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
    spdm_context->error_data.token       = LIBSPDM_MY_TEST_TOKEN;

    /*check ERROR response*/
    response_size = sizeof(response);
    status = libspdm_get_response_respond_if_ready(spdm_context,
                                                   m_libspdm_respond_if_ready_request10_size,
                                                   &m_libspdm_respond_if_ready_request10,
                                                   &response_size,
                                                   response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
/**
 * Test 14: receiving a correct RESPOND_IF_READY from the requester, with the correct token,
 * but with a request code different from the expected.
 * Expected behavior: the responder refuses the RESPOND_IF_READY message and produces an
 * ERROR message indicating the InvalidRequest.
 **/
void libspdm_test_responder_respond_if_ready_case14(void **state) {
    libspdm_return_t status;
    libspdm_test_context_t    *spdm_test_context;
    libspdm_context_t  *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_digest_response_t *spdm_response; /*response to the original request (DIGESTS)*/

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;

    /*state for the the original request (GET_DIGESTS)*/
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->local_context.local_cert_chain_provision[0] = m_libspdm_local_certificate_chain;
    spdm_context->local_context.local_cert_chain_provision_size[0] =
        sizeof(m_libspdm_local_certificate_chain);
    libspdm_set_mem (m_libspdm_local_certificate_chain, sizeof(m_libspdm_local_certificate_chain),
                     (uint8_t)(0xFF));

    spdm_context->last_spdm_request_size = m_libspdm_get_digest_request_size;
    libspdm_copy_mem(spdm_context->last_spdm_request,
                     libspdm_get_scratch_buffer_last_spdm_request_capacity(spdm_context),
                     &m_libspdm_get_digest_request, m_libspdm_get_digest_request_size);

    /*RESPOND_IF_READY specific data*/
    spdm_context->cache_spdm_request_size = spdm_context->last_spdm_request_size;
    libspdm_copy_mem(spdm_context->cache_spdm_request,
                     libspdm_get_scratch_buffer_cache_spdm_request_capacity(spdm_context),
                     spdm_context->last_spdm_request, spdm_context->last_spdm_request_size);
    spdm_context->error_data.rd_exponent = 1;
    spdm_context->error_data.rd_tm        = 1;
    spdm_context->error_data.request_code = SPDM_GET_DIGESTS;
    spdm_context->error_data.token       = LIBSPDM_MY_TEST_TOKEN;

    /*check ERROR response*/
    response_size = sizeof(response);
    status = libspdm_get_response_respond_if_ready(spdm_context,
                                                   m_libspdm_respond_if_ready_request11_size,
                                                   &m_libspdm_respond_if_ready_request11,
                                                   &response_size,
                                                   response);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal (spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal (spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (spdm_response->header.param2, 0);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

libspdm_test_context_t m_libspdm_responder_respond_if_ready_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_respond_if_ready_test_main(void) {
    const struct CMUnitTest spdm_responder_respond_if_ready_tests[] = {
        /* Success Case*/
    #if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
        cmocka_unit_test(libspdm_test_responder_respond_if_ready_case1),
        cmocka_unit_test(libspdm_test_responder_respond_if_ready_case2),
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
        cmocka_unit_test(libspdm_test_responder_respond_if_ready_case3),
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
        cmocka_unit_test(libspdm_test_responder_respond_if_ready_case4),
    #endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
        cmocka_unit_test(libspdm_test_responder_respond_if_ready_case5),
        cmocka_unit_test(libspdm_test_responder_respond_if_ready_case6),
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
        cmocka_unit_test(libspdm_test_responder_respond_if_ready_case7),
        cmocka_unit_test(libspdm_test_responder_respond_if_ready_case8),
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
        cmocka_unit_test(libspdm_test_responder_respond_if_ready_case9),
        cmocka_unit_test(libspdm_test_responder_respond_if_ready_case10),
        cmocka_unit_test(libspdm_test_responder_respond_if_ready_case11),
        cmocka_unit_test(libspdm_test_responder_respond_if_ready_case12),
        cmocka_unit_test(libspdm_test_responder_respond_if_ready_case13),
        cmocka_unit_test(libspdm_test_responder_respond_if_ready_case14),
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

    };

    libspdm_setup_test_context (&m_libspdm_responder_respond_if_ready_test_context);

    return cmocka_run_group_tests(spdm_responder_respond_if_ready_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_*_CAP */
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */
