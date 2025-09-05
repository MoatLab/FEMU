/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_secured_message_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP

#define LIBSPDM_MAX_CSR_SIZE 0x1000

/*refer to https://github.com/Mbed-TLS/mbedtls/blob/3048c8c90654eb116a6b17c0d2d27c3ccbe6782c/programs/x509/cert_req.c#L119-L129*/
#define LIBSPDM_MAX_REQ_INFO_BUFFER_SIZE 4096

uint8_t csr_pointer[LIBSPDM_MAX_CSR_SIZE] = {0};
uint8_t *csr_data_pointer = csr_pointer;
size_t global_csr_len;

uint8_t m_csr_opaque_data[8] = "libspdm";
uint16_t m_csr_opaque_data_size = sizeof(m_csr_opaque_data);

/*ECC 256 req_info(include right req_info attribute)*/
uint8_t req_info_sequence[] = {0x30, 0x81, 0xBF,};
uint8_t req_info_version[] = {0x02, 0x01, 0x00,};
uint8_t req_info_subject[] = {
    0x30, 0x45, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31,
    0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x53, 0x6F, 0x6D, 0x65, 0x2D, 0x53,
    0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x18, 0x49,
    0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20,
    0x50, 0x74, 0x79, 0x20, 0x4C, 0x74, 0x64,
};
uint8_t req_info_right_attributes[] = {
    /*[0]: attributes*/
    0xA0, 0x18, 0x30, 0x16,
    /*OID*/
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07,
    /*attributes*/
    0x31, 0x09, 0x0C, 0x07, 0x74, 0x65, 0x73, 0x74, 0x31, 0x32, 0x33
};

/*the unique attribute from right_req_info*/
char right_req_info_string[] = {0x74, 0x65, 0x73, 0x74, 0x31, 0x32, 0x33};

static uint8_t right_req_info[LIBSPDM_MAX_REQ_INFO_BUFFER_SIZE];
static uint16_t right_req_info_size;

/*gen right_req_info*/
void libspdm_gen_req_info() {
    uint8_t *req_info_p;
    void *req_info_pkinfo;
    size_t req_info_pkinfo_len;

    libspdm_zero_mem(right_req_info, sizeof(right_req_info));

    req_info_p = right_req_info;
    right_req_info_size = sizeof(right_req_info);

    libspdm_read_responder_public_key(m_libspdm_use_asym_algo,
                                      &req_info_pkinfo, &req_info_pkinfo_len);

    /*concat right_req_info*/
    libspdm_copy_mem(req_info_p, right_req_info_size, req_info_sequence, sizeof(req_info_sequence));
    req_info_p += sizeof(req_info_sequence);
    right_req_info_size -= sizeof(req_info_sequence);

    libspdm_copy_mem(req_info_p, right_req_info_size, req_info_version, sizeof(req_info_version));
    req_info_p += sizeof(req_info_version);
    right_req_info_size -= sizeof(req_info_version);

    libspdm_copy_mem(req_info_p, right_req_info_size, req_info_subject, sizeof(req_info_subject));
    req_info_p += sizeof(req_info_subject);
    right_req_info_size -= sizeof(req_info_subject);

    libspdm_copy_mem(req_info_p, right_req_info_size, req_info_pkinfo, req_info_pkinfo_len);
    req_info_p += req_info_pkinfo_len;
    right_req_info_size = (uint16_t)(right_req_info_size - req_info_pkinfo_len);

    libspdm_copy_mem(req_info_p, right_req_info_size,
                     req_info_right_attributes, sizeof(req_info_right_attributes));
    req_info_p += sizeof(req_info_right_attributes);
    right_req_info_size -= sizeof(req_info_right_attributes);

    right_req_info_size = sizeof(right_req_info) - right_req_info_size;

    free(req_info_pkinfo);
}

bool libspdm_read_requester_gen_csr(void **csr_data, size_t *csr_len)
{
    char *file;
    bool res;

    file = "test_csr/cached.csr";
    res = libspdm_read_input_file(file, csr_data, csr_len);
    if (!res) {
        return res;
    }

    return res;
}

/*ensure that cached.csr exists in test_csr at the beginning*/
void libspdm_clear_cached_csr()
{
    char *new_name = "test_csr/cached.csr";
    char *file_name = "test_csr/cached.staging";

    rename(file_name, new_name);
}

libspdm_return_t libspdm_requester_get_csr_test_send_message(
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
    case 0x4: {
        const spdm_get_csr_request_t *spdm_request;
        uint16_t requester_info_length;
        uint16_t opaque_data_length;
        uint8_t *opaque_data;
        uint8_t *requester_info;

        /* Obtain the real spdm_request */
        spdm_request =
            (const spdm_get_csr_request_t *)((const uint8_t *)request +
                                             sizeof(libspdm_test_message_header_t));

        requester_info_length = spdm_request->requester_info_length;
        opaque_data_length = spdm_request->opaque_data_length;

        requester_info = (void*)((size_t)(spdm_request + 1));
        assert_memory_equal(requester_info, right_req_info, requester_info_length);
        opaque_data = (void *)(requester_info + requester_info_length);
        assert_memory_equal(opaque_data, m_csr_opaque_data, opaque_data_length);
        return LIBSPDM_STATUS_SUCCESS;
    }
    case 0x5:
        return LIBSPDM_STATUS_SUCCESS;
    case 0x6:
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t libspdm_requester_get_csr_test_receive_message(
    void *spdm_context, size_t *response_size,
    void **response, uint64_t timeout)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *context;

    spdm_test_context = libspdm_get_test_context();
    switch (spdm_test_context->case_id) {
    case 0x1:
        return LIBSPDM_STATUS_RECEIVE_FAIL;

    case 0x2: {
        spdm_csr_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_requester_gen_csr((void *)&csr_data_pointer, &global_csr_len);

        spdm_response_size = sizeof(spdm_csr_response_t) + global_csr_len;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CSR;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->csr_length = (uint16_t)global_csr_len;
        spdm_response->reserved = 0;

        libspdm_copy_mem(spdm_response + 1, global_csr_len, csr_data_pointer, global_csr_len);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;

    case 0x3: {
        spdm_csr_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_requester_gen_csr((void *)&csr_data_pointer, &global_csr_len);

        spdm_response_size = sizeof(spdm_csr_response_t) + global_csr_len;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.param2 = 0;
        spdm_response->csr_length = (uint16_t)global_csr_len;
        spdm_response->reserved = 0;

        context = spdm_context;

        if (context->connection_info.capability.flags &
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP) {
            spdm_response->header.request_response_code = SPDM_ERROR;
            spdm_response->header.param1 = SPDM_ERROR_CODE_RESET_REQUIRED;
        } else {
            spdm_response->header.request_response_code = SPDM_CSR;
            spdm_response->header.param1 = 0;

            libspdm_copy_mem(spdm_response + 1, global_csr_len, csr_data_pointer, global_csr_len);
        }

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x4: {
        spdm_csr_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_requester_gen_csr((void *)&csr_data_pointer, &global_csr_len);
        spdm_response_size = sizeof(spdm_csr_response_t) + global_csr_len;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_12;
        spdm_response->header.request_response_code = SPDM_CSR;
        spdm_response->header.param1 = 0;
        spdm_response->header.param2 = 0;
        spdm_response->csr_length = (uint16_t)global_csr_len;
        spdm_response->reserved = 0;
        libspdm_copy_mem(spdm_response + 1, global_csr_len, csr_data_pointer, global_csr_len);

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x5: {
        spdm_csr_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        libspdm_read_requester_gen_csr((void *)&csr_data_pointer, &global_csr_len);

        spdm_response_size = sizeof(spdm_csr_response_t) + global_csr_len;
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_RESET_REQUIRED;
        spdm_response->header.param2 = 1;
        spdm_response->csr_length = (uint16_t)global_csr_len;
        spdm_response->reserved = 0;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    case 0x6: {
        spdm_error_response_t *spdm_response;
        size_t spdm_response_size;
        size_t transport_header_size;

        spdm_response_size = sizeof(spdm_error_response_t);
        transport_header_size = LIBSPDM_TEST_TRANSPORT_HEADER_SIZE;
        spdm_response = (void *)((uint8_t *)*response + transport_header_size);

        spdm_response->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        spdm_response->header.request_response_code = SPDM_ERROR;
        spdm_response->header.param1 = SPDM_ERROR_CODE_RESET_REQUIRED;
        spdm_response->header.param2 = 1;

        libspdm_transport_test_encode_message(spdm_context, NULL, false,
                                              false, spdm_response_size,
                                              spdm_response, response_size,
                                              response);
    }
        return LIBSPDM_STATUS_SUCCESS;
    default:
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

/**
 * Test 1: message could not be sent
 * Expected Behavior: get a RETURN_DEVICE_ERROR return code
 **/
void libspdm_test_requester_get_csr_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    uint8_t csr_form_get[LIBSPDM_MAX_CSR_SIZE] = {0};
    size_t csr_len;

    csr_len = LIBSPDM_MAX_CSR_SIZE;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;

    /*init req_info*/
    libspdm_gen_req_info();

    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, (void *)&csr_form_get,
                             &csr_len);

    assert_int_equal(status, LIBSPDM_STATUS_SEND_FAIL);
}

/**
 * Test 2: Successful response to get csr
 * Expected Behavior: get a RETURN_SUCCESS return code
 **/
void libspdm_test_requester_get_csr_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    uint8_t csr_form_get[LIBSPDM_MAX_CSR_SIZE] = {0};
    size_t csr_len;

    csr_len = LIBSPDM_MAX_CSR_SIZE;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;

    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, (void *)&csr_form_get,
                             &csr_len);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(csr_len, global_csr_len);
    assert_memory_equal(csr_form_get, csr_data_pointer, global_csr_len);
}

/**
 * Test 3: Successful response to get csr,
 * with a reset required
 * Expected Behavior: get a RETURN_SUCCESS return code
 **/
void libspdm_test_requester_get_csr_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    uint8_t csr_form_get[LIBSPDM_MAX_CSR_SIZE] = {0};
    size_t csr_len;

    csr_len = LIBSPDM_MAX_CSR_SIZE;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, (void *)&csr_form_get,
                             &csr_len);

    assert_int_equal(status, LIBSPDM_STATUS_RESET_REQUIRED_PEER);

    /* Let's reset the responder and send the request again */
    spdm_context->connection_info.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    status = libspdm_get_csr(spdm_context, NULL, NULL, 0, NULL, 0, (void *)&csr_form_get,
                             &csr_len);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(csr_len, global_csr_len);
    assert_memory_equal(csr_form_get, csr_data_pointer, global_csr_len);
}

/**
 * Test 4: Send correct req_info and opaque_data
 * Expected Behavior: get a RETURN_SUCCESS return code and determine if req_info and opaque_data are correct
 **/
void libspdm_test_requester_get_csr_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    uint8_t csr_form_get[LIBSPDM_MAX_CSR_SIZE] = {0};
    size_t csr_len;

    csr_len = LIBSPDM_MAX_CSR_SIZE;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->connection_info.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_0;

    status = libspdm_get_csr(spdm_context, NULL,
                             right_req_info, right_req_info_size,
                             m_csr_opaque_data, m_csr_opaque_data_size,
                             (void *)&csr_form_get, &csr_len);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(csr_len, global_csr_len);
    assert_memory_equal(csr_form_get, csr_data_pointer, global_csr_len);
}

/**
 * Test 5: Successful response to libspdm_get_csr_ex,
 * with a reset required
 * Expected Behavior: get a LIBSPDM_STATUS_RESET_REQUIRED_PEER return code and available csr_tracking_tag
 **/
void libspdm_test_requester_get_csr_case5(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX
    libspdm_return_t status;
    uint8_t csr_form_get[LIBSPDM_MAX_CSR_SIZE] = {0};
    size_t csr_len;
    uint8_t reset_csr_tracking_tag;

    csr_len = LIBSPDM_MAX_CSR_SIZE;
    reset_csr_tracking_tag = 0;
#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX*/
    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP |
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX
    status = libspdm_get_csr_ex(spdm_context, NULL, NULL, 0, NULL, 0, (void *)&csr_form_get,
                                &csr_len, 0, 0, &reset_csr_tracking_tag);

    assert_int_equal(status, LIBSPDM_STATUS_RESET_REQUIRED_PEER);
    assert_int_equal(reset_csr_tracking_tag, 1);
#endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX*/
}

/**
 * Test 6: A 1.3 Responder returns ResetRequired when its CERT_INSTALL_RESET_CAP is 0.
 * Expected Behavior: libspdm returns LIBSPDM_STATUS_ERROR_PEER since Responder should
 *                    not produce that error message unless CERT_INSTALL_RESET_CAP is 1.
 **/
void libspdm_test_requester_get_csr_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;

    uint8_t csr_form_get[LIBSPDM_MAX_CSR_SIZE] = {0};
    size_t csr_len;

    csr_len = LIBSPDM_MAX_CSR_SIZE;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    /* Don't set CERT_INSTALL_RESET_CAP. */
    spdm_context->connection_info.capability.flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;

    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_0;

    status = libspdm_get_csr(spdm_context, NULL,
                             right_req_info, right_req_info_size,
                             m_csr_opaque_data, m_csr_opaque_data_size,
                             (void *)&csr_form_get, &csr_len);

    assert_int_equal(status, LIBSPDM_STATUS_ERROR_PEER);
}


libspdm_test_context_t m_libspdm_requester_get_csr_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    libspdm_requester_get_csr_test_send_message,
    libspdm_requester_get_csr_test_receive_message,
};

int libspdm_requester_get_csr_test_main(void)
{
    const struct CMUnitTest spdm_requester_get_csr_tests[] = {
        /* SendRequest failed*/
        cmocka_unit_test(libspdm_test_requester_get_csr_case1),
        /* Successful response to get csr*/
        cmocka_unit_test(libspdm_test_requester_get_csr_case2),
        /* Successful response to get csr with a reset required */
        cmocka_unit_test(libspdm_test_requester_get_csr_case3),
        /* Send req_info and opaque_data Successful response to get csr */
        cmocka_unit_test(libspdm_test_requester_get_csr_case4),
        /* Successful response to libspdm_get_csr_ex with a reset required */
        cmocka_unit_test(libspdm_test_requester_get_csr_case5),
        /* Illegal ResetRequired error response. */
        cmocka_unit_test(libspdm_test_requester_get_csr_case6),
    };

    libspdm_setup_test_context(
        &m_libspdm_requester_get_csr_test_context);

    /*ensure that cached.csr exists in test_csr at the beginning*/
    libspdm_clear_cached_csr();

    return cmocka_run_group_tests(spdm_requester_get_csr_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP*/
