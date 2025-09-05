/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP

#define LIBSPDM_MAX_CSR_SIZE 0x1000

/*refer to https://github.com/Mbed-TLS/mbedtls/blob/3048c8c90654eb116a6b17c0d2d27c3ccbe6782c/programs/x509/cert_req.c#L119-L129*/
#define LIBSPDM_MAX_REQ_INFO_BUFFER_SIZE 4096

uint8_t m_csr_opaque_data[8] = "libspdm";

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
uint8_t right_req_info_string[] = {0x74, 0x65, 0x73, 0x74, 0x31, 0x32, 0x33};
/*the default subject without req_info*/
uint8_t default_subject1[] = {
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4E, 0x4C,
};

uint8_t default_subject2[] = {
    0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08, 0x50, 0x6F, 0x6C, 0x61, 0x72, 0x53, 0x53, 0x4C,
};
uint8_t default_subject3[] = {
    0x0C, 0x11, 0x50, 0x6F, 0x6C, 0x61, 0x72, 0x53, 0x53, 0x4C, 0x20, 0x53, 0x65, 0x72, 0x76,
    0x65, 0x72, 0x20, 0x31
};

static uint8_t right_req_info[LIBSPDM_MAX_REQ_INFO_BUFFER_SIZE];
static uint8_t wrong_req_info[LIBSPDM_MAX_REQ_INFO_BUFFER_SIZE];
static uint16_t req_info_len;

/*gen right_req_info and wrong_req_info*/
void libspdm_gen_req_info()
{
    uint8_t *req_info_p;
    void *req_info_pkinfo;
    size_t req_info_pkinfo_len;

    libspdm_zero_mem(right_req_info, sizeof(right_req_info));
    libspdm_zero_mem(wrong_req_info, sizeof(wrong_req_info));

    req_info_p = right_req_info;
    req_info_len = sizeof(right_req_info);

    libspdm_read_responder_public_key(m_libspdm_use_asym_algo,
                                      &req_info_pkinfo, &req_info_pkinfo_len);

    /*concat right_req_info*/
    libspdm_copy_mem(req_info_p, req_info_len, req_info_sequence, sizeof(req_info_sequence));
    req_info_p += sizeof(req_info_sequence);
    req_info_len -= sizeof(req_info_sequence);

    libspdm_copy_mem(req_info_p, req_info_len, req_info_version, sizeof(req_info_version));
    req_info_p += sizeof(req_info_version);
    req_info_len -= sizeof(req_info_version);

    libspdm_copy_mem(req_info_p, req_info_len, req_info_subject, sizeof(req_info_subject));
    req_info_p += sizeof(req_info_subject);
    req_info_len -= sizeof(req_info_subject);

    libspdm_copy_mem(req_info_p, req_info_len, req_info_pkinfo, req_info_pkinfo_len);
    req_info_p += req_info_pkinfo_len;
    req_info_len = (uint16_t)(req_info_len - req_info_pkinfo_len);

    libspdm_copy_mem(req_info_p, req_info_len,
                     req_info_right_attributes, sizeof(req_info_right_attributes));
    req_info_p += sizeof(req_info_right_attributes);
    req_info_len -= sizeof(req_info_right_attributes);

    req_info_len = sizeof(right_req_info) - req_info_len;

    /*concat wrong_req_info*/
    libspdm_copy_mem(wrong_req_info, sizeof(wrong_req_info), right_req_info, req_info_len);
    /*make the wrong_req_info is wrong*/
    *wrong_req_info = '1';

    free(req_info_pkinfo);
}

/*find destination buffer from source buffer*/
bool libspdm_find_buffer(uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_len)
{
    size_t index;

    if ((src == NULL) || (dst == NULL)) {
        return false;
    }

    if (src_len < dst_len) {
        return false;
    }

    for (index = 0; index < src_len - dst_len; index++) {
        if ((*(src + index) == *dst) &&
            libspdm_consttime_is_mem_equal(src + index, dst, dst_len)) {
            return true;
        }
    }

    return false;
}

/*get the cached csr*/
bool libspdm_test_read_cached_csr(uint8_t **csr_pointer, size_t *csr_len)
{
    bool res;
    char *file;

    file = "test_csr/cached.csr";

    res = libspdm_read_input_file(file, (void **)csr_pointer, csr_len);
    return res;
}

/*
 * If device need reset to set csr, the function simulates the CSR state before device reset.
 * The returned status indicates whether the setting was successful or unsuccessful.
 **/
bool libspdm_set_csr_before_reset()
{
    char *file_name = "test_csr/cached.csr";
    char *new_name = "test_csr/cached.staging";

    if (rename(file_name, new_name) != 0) {
        return false;
    }

    return true;
}

/*
 * If device need reset to set csr, the function simulates the CSR state after device reset.
 * The returned status indicates whether the setting was successful or unsuccessful.
 **/
bool libspdm_set_csr_after_reset()
{
    char *file_name = "test_csr/cached.csr";
    char *new_name = "test_csr/cached.staging";

    if (rename(new_name, file_name) != 0) {
        return false;
    }

    return true;
}

/*ensure that cached.csr exists in test_csr at the beginning*/
void libspdm_clear_cached_csr()
{
    char *new_name = "test_csr/cached.csr";
    char *file_name = "test_csr/cached.staging";

    rename(file_name, new_name);
}

/*clean the cached last SPDM csr request*/
void libspdm_test_clear_cached_last_request()
{
    uint8_t index;

    char file[] = "cached_last_csr_x_request";

    for (index = 1; index <= SPDM_MAX_CSR_TRACKING_TAG; index++) {
        file[16] = (char)(index + '0');
        libspdm_write_output_file(file, NULL, 0);
    }
}

/*check the csr is consistent with the is_device_cert_model*/
bool libspdm_check_csr_basic_constraints(uint8_t *csr, uint16_t csr_len, bool is_device_cert_model)
{
    bool result;
    uint8_t *ptr;
    uint16_t length;
    size_t obj_len;
    uint8_t *end;

    /*basic_constraints: CA: false */
    #define BASIC_CONSTRAINTS_STRING_FALSE {0x30, 0x00}
    uint8_t basic_constraints_false[] = BASIC_CONSTRAINTS_STRING_FALSE;

    /*basic_constraints: CA: true */
    #define BASIC_CONSTRAINTS_STRING_TRUE {0x30, 0x03, 0x01, 0x01, 0xFF}
    uint8_t basic_constraints_true[] = BASIC_CONSTRAINTS_STRING_TRUE;

    length = csr_len;
    ptr = (uint8_t*)csr;
    obj_len = 0;
    end = ptr + length;

    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!result) {
        return false;
    }

    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!result) {
        return false;
    }

    end = ptr + obj_len;

    /*version*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_INTEGER);
    if (!result) {
        return false;
    }
    ptr += obj_len;

    /*subject*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!result) {
        return false;
    }
    ptr += obj_len;

    /*PKinfo*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!result) {
        return false;
    }
    ptr += obj_len;

    /*attribute*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_CONTEXT_SPECIFIC |
                                  LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!result) {
        return false;
    }

    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!result) {
        return false;
    }
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_OID);
    if (!result) {
        return false;
    }
    ptr += obj_len;

    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_SET | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!result) {
        return false;
    }
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!result) {
        return false;
    }
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len,
                                  LIBSPDM_CRYPTO_ASN1_SEQUENCE | LIBSPDM_CRYPTO_ASN1_CONSTRUCTED);
    if (!result) {
        return false;
    }
    /*basic constriants oid*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_OID);
    if (!result) {
        return false;
    }
    ptr += obj_len;

    /*basic constriants*/
    result = libspdm_asn1_get_tag(&ptr, end, &obj_len, LIBSPDM_CRYPTO_ASN1_OCTET_STRING);
    if (!result) {
        return false;
    }

    if (is_device_cert_model) {
        result = libspdm_consttime_is_mem_equal(
            ptr, basic_constraints_false, sizeof(basic_constraints_false));
    } else {
        result = libspdm_consttime_is_mem_equal(
            ptr, basic_constraints_true, sizeof(basic_constraints_true));
    }

    return result;
}

/**
 * Test 1: receives a valid GET_CSR request message from Requester
 * Expected Behavior: produces a valid CSR response message with device_cert mode
 **/
void libspdm_test_responder_csr_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t wrong_csr[LIBSPDM_MAX_CSR_SIZE];
    bool result;
    bool is_device_cert_model;

    libspdm_zero_mem(wrong_csr, LIBSPDM_MAX_CSR_SIZE);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    is_device_cert_model = true;
    spdm_context->local_context.capability.flags &=
        ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t));

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = 0;

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t);

    /*init req_info*/
    libspdm_gen_req_info();

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(response_size, sizeof(spdm_csr_response_t) + spdm_response->csr_length);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CSR);

    /*check returned CSR not zero */
    assert_memory_not_equal(spdm_response + 1, wrong_csr, spdm_response->csr_length);

    /*check the resulting CSR shall be for a Device Certificate*/
    result = libspdm_check_csr_basic_constraints((uint8_t *)(spdm_response + 1),
                                                 spdm_response->csr_length, is_device_cert_model);
    assert_true(result);

    /*check that returned CSR contains default subject*/
    assert_true(libspdm_find_buffer((uint8_t *)(spdm_response + 1), spdm_response->csr_length,
                                    default_subject1, sizeof(default_subject1)));
    assert_true(libspdm_find_buffer((uint8_t *)(spdm_response + 1), spdm_response->csr_length,
                                    default_subject2, sizeof(default_subject2)));
    assert_true(libspdm_find_buffer((uint8_t *)(spdm_response + 1), spdm_response->csr_length,
                                    default_subject3, sizeof(default_subject3)));
    free(m_libspdm_get_csr_request);
}

/**
 * Test 2: Wrong GET_CSR message size (larger than expected)
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
 **/
void libspdm_test_responder_csr_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;


    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t));

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = 0;

    /* Bad request size*/
    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) - 1;

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    free(m_libspdm_get_csr_request);
}

/**
 * Test 3: receives a valid GET_CSR request message from Requester with non-null right req_info
 * Expected Behavior: produces a valid CSR response message
 **/
void libspdm_test_responder_csr_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t wrong_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(wrong_csr, LIBSPDM_MAX_CSR_SIZE);
    uint8_t *csr;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t) +
                                       req_info_len);

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;

    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) +
                                            req_info_len;

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(response_size, sizeof(spdm_csr_response_t) + spdm_response->csr_length);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CSR);

    /*check returned CSR not zero */
    assert_memory_not_equal(spdm_response + 1, wrong_csr, spdm_response->csr_length);

    csr = (uint8_t *)(spdm_response + 1);
    /*check that returned CSR contains req_info attribute*/
    assert_true(libspdm_find_buffer(csr, spdm_response->csr_length,
                                    right_req_info_string, sizeof(right_req_info_string)));

    /*check that returned CSR contains req_info subject*/
    assert_true(libspdm_find_buffer(csr, spdm_response->csr_length,
                                    req_info_subject, sizeof(req_info_subject)));

    free(m_libspdm_get_csr_request);
}

/**
 * Test 4: receives a valid GET_CSR request message from Requester with non-null opaque_data
 * Expected Behavior: produces a valid CSR response message
 **/
void libspdm_test_responder_csr_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t wrong_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(wrong_csr, LIBSPDM_MAX_CSR_SIZE);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo = m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_0;

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t) +
                                       sizeof(m_csr_opaque_data));

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = sizeof(m_csr_opaque_data);
    m_libspdm_get_csr_request->requester_info_length = 0;

    libspdm_copy_mem(m_libspdm_get_csr_request + 1, sizeof(m_csr_opaque_data),
                     m_csr_opaque_data, sizeof(m_csr_opaque_data));

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) +
                                            sizeof(m_csr_opaque_data);

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(response_size, sizeof(spdm_csr_response_t) + spdm_response->csr_length);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CSR);

    /*check returned CSR not zero */
    assert_memory_not_equal(spdm_response + 1, wrong_csr, spdm_response->csr_length);

    free(m_libspdm_get_csr_request);
}

/**
 * Test 5: receives a valid GET_CSR request message from Requester with non-null wrong req_info
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
 **/
void libspdm_test_responder_csr_case5(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t wrong_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(wrong_csr, LIBSPDM_MAX_CSR_SIZE);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t) +
                                       req_info_len);

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;

    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     wrong_req_info, req_info_len);

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) +
                                            req_info_len;

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    free(m_libspdm_get_csr_request);
}

/**
 * Test 6: receives a valid GET_CSR request message from Requester with need_reset
 * Expected Behavior: the first get_csr: responder return need reset;
 *                    the second get_csr after device reset: get the cached valid csr;
 **/
void libspdm_test_responder_csr_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t cached_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(cached_csr, LIBSPDM_MAX_CSR_SIZE);

    uint8_t *csr_pointer;
    size_t csr_len;

    if (!libspdm_test_read_cached_csr(&csr_pointer, &csr_len)) {
        assert_false(true);
    }

    libspdm_copy_mem(cached_csr, LIBSPDM_MAX_CSR_SIZE, csr_pointer, csr_len);
    free(csr_pointer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;

    /*set responder need reset*/
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    /*set csr before reset*/
    assert_true(libspdm_set_csr_before_reset());

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t) +
                                       req_info_len);

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;

    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) +
                                            req_info_len;

    response_size = sizeof(response);

    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    /*first get_csr: the responder need reset*/
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);

    /*set csr after reset*/
    assert_true(libspdm_set_csr_after_reset());

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;
    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    /*second get_csr after device reset: get the responder cached csr*/
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(response_size, sizeof(spdm_csr_response_t) + spdm_response->csr_length);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CSR);

    /*check returned CSR is equal the cached CSR */
    assert_memory_equal(spdm_response + 1, cached_csr, spdm_response->csr_length);

    /*clear cached req_info*/
    libspdm_test_clear_cached_last_request();
    free(m_libspdm_get_csr_request);
}

/**
 * Test 7: receives a valid GET_CSR request message from Requester with non-null right req_info and opaque_data
 * Expected Behavior: produces a valid CSR response message
 **/
void libspdm_test_responder_csr_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *libspdm_get_csr_request;
    uint8_t wrong_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(wrong_csr, LIBSPDM_MAX_CSR_SIZE);
    uint8_t *csr;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t) +
                                     sizeof(m_csr_opaque_data) +
                                     req_info_len);

    libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    libspdm_get_csr_request->header.param1 = 0;
    libspdm_get_csr_request->header.param2 = 0;
    libspdm_get_csr_request->opaque_data_length = sizeof(m_csr_opaque_data);
    libspdm_get_csr_request->requester_info_length = req_info_len;

    libspdm_copy_mem(libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    libspdm_copy_mem((uint8_t *)(libspdm_get_csr_request + 1) + req_info_len,
                     sizeof(m_csr_opaque_data),
                     m_csr_opaque_data, sizeof(m_csr_opaque_data));

    size_t libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) +
                                          sizeof(m_csr_opaque_data) +
                                          req_info_len;

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      libspdm_get_csr_request_size,
                                      libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(response_size, sizeof(spdm_csr_response_t) + spdm_response->csr_length);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CSR);

    /*check returned CSR not zero */
    assert_memory_not_equal(spdm_response + 1, wrong_csr, spdm_response->csr_length);

    csr = (uint8_t *)(spdm_response + 1);
    assert_true(libspdm_find_buffer(csr, spdm_response->csr_length,
                                    right_req_info_string, sizeof(right_req_info_string)));
    /*check that returned CSR contains req_info subject*/
    assert_true(libspdm_find_buffer(csr, spdm_response->csr_length,
                                    req_info_subject, sizeof(req_info_subject)));

    free(libspdm_get_csr_request);
}

/**
 * Test 8: receives a invalid GET_CSR request message from Requester With chaotic req_info and opaque_data
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
 **/
void libspdm_test_responder_csr_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *libspdm_get_csr_request;
    uint8_t wrong_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(wrong_csr, LIBSPDM_MAX_CSR_SIZE);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags = 0;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    libspdm_get_csr_request = malloc(LIBSPDM_RECEIVER_BUFFER_SIZE);
    libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    libspdm_get_csr_request->header.param1 = 0;
    libspdm_get_csr_request->header.param2 = 0;

    /* Swap right_req_info and m_csr_opaque_data */
    libspdm_get_csr_request->opaque_data_length = req_info_len;
    libspdm_get_csr_request->requester_info_length = sizeof(m_csr_opaque_data);
    libspdm_copy_mem(libspdm_get_csr_request + 1, sizeof(m_csr_opaque_data),
                     m_csr_opaque_data, sizeof(m_csr_opaque_data));
    libspdm_copy_mem((uint8_t *)(libspdm_get_csr_request + 1) + req_info_len,
                     req_info_len,
                     right_req_info, req_info_len);

    size_t libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) +
                                          sizeof(m_csr_opaque_data) +
                                          req_info_len;

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      libspdm_get_csr_request_size,
                                      libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    free(libspdm_get_csr_request);
}

/**
 * Test 9: receives a valid GET_CSR request message from Requester with non-null opaque_data
 * the OpaqueDataFmt1 bit is selected in OtherParamsSelection of ALGORITHMS ,
 * Expected Behavior: produces a valid CSR response message
 **/
void libspdm_test_responder_csr_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t wrong_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(wrong_csr, LIBSPDM_MAX_CSR_SIZE);
    spdm_general_opaque_data_table_header_t
    *spdm_general_opaque_data_table_header;
    opaque_element_table_header_t
    *opaque_element_table_header;
    uint8_t *ptr;
    size_t opaque_data_size;
    uint8_t element_num;
    uint8_t element_index;
    size_t current_element_len;
    uint16_t opaque_element_data_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t) + SPDM_MAX_OPAQUE_DATA_SIZE);

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    spdm_general_opaque_data_table_header = (void *)(m_libspdm_get_csr_request + 1);
    spdm_general_opaque_data_table_header->total_elements = 1;
    opaque_element_table_header = (void *)(spdm_general_opaque_data_table_header + 1);

    element_num = spdm_general_opaque_data_table_header->total_elements;
    opaque_data_size = sizeof(spdm_general_opaque_data_table_header_t);

    for (element_index = 0; element_index < element_num; element_index++) {
        opaque_element_table_header->id = SPDM_REGISTRY_ID_MAX;
        opaque_element_table_header->vendor_len = 0;
        opaque_element_data_len = 8;

        ptr = (void *)(opaque_element_table_header + 1);
        ptr += opaque_element_table_header->vendor_len;

        libspdm_copy_mem((uint16_t *)ptr,
                         sizeof(opaque_element_data_len),
                         &opaque_element_data_len,
                         sizeof(opaque_element_data_len));

        libspdm_copy_mem(ptr + sizeof(opaque_element_data_len),
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

        opaque_data_size += current_element_len;
    }

    m_libspdm_get_csr_request->opaque_data_length = (uint16_t)opaque_data_size;
    m_libspdm_get_csr_request->requester_info_length = 0;

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) + opaque_data_size;

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(response_size, sizeof(spdm_csr_response_t) + spdm_response->csr_length);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CSR);

    /*check returned CSR not zero */
    assert_memory_not_equal(spdm_response + 1, wrong_csr, spdm_response->csr_length);

    free(m_libspdm_get_csr_request);
}

/**
 * Test 10: receives a invalid GET_CSR request message from Requester with non-null alignPadding in opaque_data is not zero
 * the OpaqueDataFmt1 bit is selected in OtherParamsSelection of ALGORITHMS
 * Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
 **/
void libspdm_test_responder_csr_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t wrong_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(wrong_csr, LIBSPDM_MAX_CSR_SIZE);
    spdm_general_opaque_data_table_header_t
    *spdm_general_opaque_data_table_header;
    opaque_element_table_header_t
    *opaque_element_table_header;
    uint8_t *ptr;
    size_t opaque_data_size;
    uint8_t element_num;
    uint8_t element_index;
    size_t current_element_len;
    uint16_t opaque_element_data_len;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;
    spdm_context->connection_info.algorithm.other_params_support =
        SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t) + SPDM_MAX_OPAQUE_DATA_SIZE);

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    spdm_general_opaque_data_table_header = (void *)(m_libspdm_get_csr_request + 1);
    spdm_general_opaque_data_table_header->total_elements = 1;
    opaque_element_table_header = (void *)(spdm_general_opaque_data_table_header + 1);

    element_num = spdm_general_opaque_data_table_header->total_elements;
    opaque_data_size = sizeof(spdm_general_opaque_data_table_header_t);

    for (element_index = 0; element_index < element_num; element_index++) {
        opaque_element_table_header->id = SPDM_REGISTRY_ID_MAX;
        opaque_element_table_header->vendor_len = 0;
        opaque_element_data_len = (uint16_t)strlen("libspdm");

        ptr = (void *)(opaque_element_table_header + 1);
        ptr += opaque_element_table_header->vendor_len;

        libspdm_copy_mem((uint16_t *)ptr,
                         sizeof(opaque_element_data_len),
                         &opaque_element_data_len,
                         sizeof(opaque_element_data_len));

        libspdm_copy_mem(ptr + sizeof(opaque_element_data_len),
                         SPDM_MAX_OPAQUE_DATA_SIZE -
                         sizeof(opaque_element_table_header_t), "libspdm",
                         strlen("libspdm"));

        current_element_len = sizeof(opaque_element_table_header_t) +
                              opaque_element_table_header->vendor_len +
                              sizeof(opaque_element_data_len) +
                              opaque_element_data_len;

        *(uint8_t *)((size_t)(opaque_element_table_header) + current_element_len) = 0xFF;

        current_element_len += 1;
        current_element_len = (current_element_len + 3) & ~3;

        /*move to next element*/
        opaque_element_table_header =
            (opaque_element_table_header_t *)
            ((uint8_t *)opaque_element_table_header +
             current_element_len);

        opaque_data_size += current_element_len;
    }

    m_libspdm_get_csr_request->opaque_data_length = (uint16_t)opaque_data_size;
    m_libspdm_get_csr_request->requester_info_length = 0;

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) + opaque_data_size;

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    free(m_libspdm_get_csr_request);
}

/**
 * Test 11: receives a valid GET_CSR request message from Requester
 * Expected Behavior: produces a valid CSR response message with alias_cert mode
 **/
void libspdm_test_responder_csr_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t wrong_csr[LIBSPDM_MAX_CSR_SIZE];
    bool result;
    bool is_device_cert_model;

    libspdm_zero_mem(wrong_csr, LIBSPDM_MAX_CSR_SIZE);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;
    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    /*set alias cert mode*/
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
    is_device_cert_model = false;

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t));

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = 0;

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t);

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(response_size, sizeof(spdm_csr_response_t) + spdm_response->csr_length);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CSR);

    /*check returned CSR not zero */
    assert_memory_not_equal(spdm_response + 1, wrong_csr, spdm_response->csr_length);

    /*check the resulting CSR shall be for a Device Certificate CA.*/
    result = libspdm_check_csr_basic_constraints((uint8_t *)(spdm_response + 1),
                                                 spdm_response->csr_length, is_device_cert_model);
    assert_true(result);

    free(m_libspdm_get_csr_request);
}

/**
 * Test 12: receives a valid GET_CSR request message from Requester with need_reset
 * Expected Behavior: the first get_csr: responder return need reset;
 *                    the second get_csr without device reset: responder return need reset;
 **/
void libspdm_test_responder_csr_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t cached_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(cached_csr, LIBSPDM_MAX_CSR_SIZE);

    uint8_t *csr_pointer;
    size_t csr_len;

    if (!libspdm_test_read_cached_csr(&csr_pointer, &csr_len)) {
        assert_false(true);
    }

    libspdm_copy_mem(cached_csr, LIBSPDM_MAX_CSR_SIZE, csr_pointer, csr_len);
    free(csr_pointer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;

    /*set responder need reset*/
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    /*set csr before reset*/
    assert_true(libspdm_set_csr_before_reset());

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t) +
                                       req_info_len);

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;

    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) +
                                            req_info_len;

    response_size = sizeof(response);

    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    /*first get_csr: the responder need reset*/
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_12;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 0;
    m_libspdm_get_csr_request->header.param2 = 0;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;
    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    response_size = sizeof(response);

    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    /*second get_csr without device reset: get the responder cached csr*/
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 0);

    /*clear cached req_info*/
    libspdm_test_clear_cached_last_request();
    free(m_libspdm_get_csr_request);

    /*set csr to the origin state*/
    assert_true(libspdm_set_csr_after_reset());
}

/**
 * Test 13: receives a valid GET_CSR request message from Requester with need_reset for SPDM 1.3
 * Expected Behavior: the first get_csr with csr_tracking_tag 0: responder return need reset and available csr_tracking_tag;
 *                    After reset, the second get_csr with returned available csr_tracking_tag: after device reset: get the cached valid csr;
 **/
void libspdm_test_responder_csr_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t cached_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(cached_csr, LIBSPDM_MAX_CSR_SIZE);

    uint8_t *csr_pointer;
    size_t csr_len;
    uint8_t csr_tracking_tag;

    csr_tracking_tag = 0;

    if (!libspdm_test_read_cached_csr(&csr_pointer, &csr_len)) {
        assert_false(true);
    }

    libspdm_copy_mem(cached_csr, LIBSPDM_MAX_CSR_SIZE, csr_pointer, csr_len);
    free(csr_pointer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;

    spdm_context->connection_info.multi_key_conn_rsp = true;
    /*set responder need reset*/
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    /*set csr before reset*/
    assert_true(libspdm_set_csr_before_reset());

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t) +
                                       req_info_len);

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 1;
    m_libspdm_get_csr_request->header.param2 =
        csr_tracking_tag << SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;

    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) +
                                            req_info_len;

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);

    /*set csr after reset*/
    assert_true(libspdm_set_csr_after_reset());
#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX
    /*first get_csr: the responder need reset*/
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 1);

    csr_tracking_tag = spdm_response->header.param2;
    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 1;
    m_libspdm_get_csr_request->header.param2 =
        csr_tracking_tag << SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;
    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    /*second get_csr after device reset: get the responder cached csr*/
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    spdm_response = (void *)response;
    assert_int_equal(response_size, sizeof(spdm_csr_response_t) + spdm_response->csr_length);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CSR);

    /*check returned CSR is equal the cached CSR */
    assert_memory_equal(spdm_response + 1, cached_csr, spdm_response->csr_length);
#else
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
#endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX*/
    /*clear cached req_info*/
    libspdm_test_clear_cached_last_request();
    free(m_libspdm_get_csr_request);
}

/**
 * Test 14: receives a valid GET_CSR request message from Requester with need_reset for SPDM 1.3
 * Expected Behavior: the first get_csr with csr_tracking_tag 0: responder return need reset and available csr_tracking_tag;
 *                    Afer reset, then send get_csr with csr_tracking_tag 0 six times: responder return need reset and available csr_tracking_tag;
 *                    Then send get_csr with csr_tracking_tag 0: responder return busy error;
 **/
void libspdm_test_responder_csr_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t cached_csr[LIBSPDM_MAX_CSR_SIZE];
#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX
    uint8_t index;
#endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX*/
    libspdm_zero_mem(cached_csr, LIBSPDM_MAX_CSR_SIZE);

    uint8_t *csr_pointer;
    size_t csr_len;
    uint8_t csr_tracking_tag;

    csr_tracking_tag = 0;

    if (!libspdm_test_read_cached_csr(&csr_pointer, &csr_len)) {
        assert_false(true);
    }

    libspdm_copy_mem(cached_csr, LIBSPDM_MAX_CSR_SIZE, csr_pointer, csr_len);
    free(csr_pointer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;

    spdm_context->connection_info.multi_key_conn_rsp = true;
    /*set responder need reset*/
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    /*set csr before reset*/
    assert_true(libspdm_set_csr_before_reset());

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t) +
                                       req_info_len);

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 1;
    m_libspdm_get_csr_request->header.param2 =
        csr_tracking_tag << SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;

    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) +
                                            req_info_len;

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);

    /*set csr after reset*/
    assert_true(libspdm_set_csr_after_reset());
#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX
    /*first get_csr: the responder need reset*/
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 1);

    for (index = 1; index < SPDM_MAX_CSR_TRACKING_TAG; index++) {
        csr_tracking_tag = 0;
        m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
        m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
        m_libspdm_get_csr_request->header.param1 = 1;
        m_libspdm_get_csr_request->header.param2 =
            csr_tracking_tag << SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET;

        m_libspdm_get_csr_request->opaque_data_length = 0;
        m_libspdm_get_csr_request->requester_info_length = req_info_len;
        libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                         right_req_info, req_info_len);

        response_size = sizeof(response);
        status = libspdm_get_response_csr(spdm_context,
                                          m_libspdm_get_csr_request_size,
                                          m_libspdm_get_csr_request,
                                          &response_size, response);
        /*second get_csr after device reset: get the responder cached csr*/
        assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
        assert_int_equal(response_size, sizeof(spdm_error_response_t));
        spdm_response = (void *)response;
        assert_int_equal(spdm_response->header.request_response_code,
                         SPDM_ERROR);
        assert_int_equal(spdm_response->header.param1,
                         SPDM_ERROR_CODE_RESET_REQUIRED);
        assert_int_equal(spdm_response->header.param2, index + 1);
    }

    csr_tracking_tag = 0;
    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 1;
    m_libspdm_get_csr_request->header.param2 =
        csr_tracking_tag << SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;
    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    /*second get_csr after device reset: get the responder cached csr*/
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_BUSY);
    assert_int_equal(spdm_response->header.param2, 0);
#else
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
#endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX*/
    /*clear cached req_info*/
    libspdm_test_clear_cached_last_request();
    free(m_libspdm_get_csr_request);
}

/**
 * Test 15: receives a valid GET_CSR request message from Requester with need_reset for SPDM 1.3
 * Expected Behavior: the first get_csr with csr_tracking_tag 0: responder return need reset and available csr_tracking_tag;
 *                    Without reset, then send get_csr with unmatched csr_tracking_tag：responder return unexpected error;
 *                    Without reset, then send get_csr with matched csr_tracking_tag：responder return busy error;
 *                    Without reset, then send get_csr with non-0 csr_tracking_tag, and overwrite is set：responder return invalid error;
 *                    After reset, then send get_csr with unmatched csr_tracking_tag：responder return unexpected error;
 *                    After reset, then send get_csr with csr_tracking_tag 0, and overwrite is set：responder return need reset and available csr_tracking_tag;
 **/
void libspdm_test_responder_csr_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_csr_response_t *spdm_response;
    spdm_get_csr_request_t *m_libspdm_get_csr_request;
    uint8_t cached_csr[LIBSPDM_MAX_CSR_SIZE];
    libspdm_zero_mem(cached_csr, LIBSPDM_MAX_CSR_SIZE);

    uint8_t *csr_pointer;
    size_t csr_len;
    uint8_t csr_tracking_tag;

    csr_tracking_tag = 0;

    if (!libspdm_test_read_cached_csr(&csr_pointer, &csr_len)) {
        assert_false(true);
    }

    libspdm_copy_mem(cached_csr, LIBSPDM_MAX_CSR_SIZE, csr_pointer, csr_len);
    free(csr_pointer);

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;
    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_13 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NEGOTIATED;
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP;

    spdm_context->connection_info.multi_key_conn_rsp = true;
    /*set responder need reset*/
    spdm_context->local_context.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP;

    spdm_context->connection_info.algorithm.base_hash_algo =
        m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo =
        m_libspdm_use_asym_algo;

    /*set csr before reset*/
    assert_true(libspdm_set_csr_before_reset());

    m_libspdm_get_csr_request = malloc(sizeof(spdm_get_csr_request_t) +
                                       req_info_len);

    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 1;
    m_libspdm_get_csr_request->header.param2 =
        csr_tracking_tag << SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;

    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    size_t m_libspdm_get_csr_request_size = sizeof(spdm_get_csr_request_t) +
                                            req_info_len;

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX
    /*first get_csr: the responder need reset*/
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 1);

    /*unmatched csr_tracking_tag*/
    csr_tracking_tag = 3;
    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 1;
    m_libspdm_get_csr_request->header.param2 =
        csr_tracking_tag << SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;
    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    /*second get_csr after device reset: get the responder cached csr*/
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    /*matched csr_tracking_tag without overwrite*/
    csr_tracking_tag = 1;
    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 1;
    m_libspdm_get_csr_request->header.param2 =
        csr_tracking_tag << SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;
    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    /*second get_csr after device reset: get the responder cached csr*/
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_BUSY);
    assert_int_equal(spdm_response->header.param2, 0);


    /*matched csr_tracking_tag with overwrite*/
    csr_tracking_tag = 1;
    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 1;
    m_libspdm_get_csr_request->header.param2 =
        (csr_tracking_tag << SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET) |
        SPDM_GET_CSR_REQUEST_ATTRIBUTES_OVERWRITE;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;
    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    /*second get_csr after device reset: get the responder cached csr*/
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    /*set csr after reset*/
    assert_true(libspdm_set_csr_after_reset());

    /*unmatched csr_tracking_tag*/
    csr_tracking_tag = 3;
    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 1;
    m_libspdm_get_csr_request->header.param2 =
        csr_tracking_tag << SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;
    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);

    /*csr_tracking_tag 0 and overwrite*/
    csr_tracking_tag = 0;
    m_libspdm_get_csr_request->header.spdm_version = SPDM_MESSAGE_VERSION_13;
    m_libspdm_get_csr_request->header.request_response_code = SPDM_GET_CSR;
    m_libspdm_get_csr_request->header.param1 = 1;
    m_libspdm_get_csr_request->header.param2 =
        (csr_tracking_tag << SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET) |
        SPDM_GET_CSR_REQUEST_ATTRIBUTES_OVERWRITE;

    m_libspdm_get_csr_request->opaque_data_length = 0;
    m_libspdm_get_csr_request->requester_info_length = req_info_len;
    libspdm_copy_mem(m_libspdm_get_csr_request + 1, req_info_len,
                     right_req_info, req_info_len);

    response_size = sizeof(response);
    status = libspdm_get_response_csr(spdm_context,
                                      m_libspdm_get_csr_request_size,
                                      m_libspdm_get_csr_request,
                                      &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_RESET_REQUIRED);
    assert_int_equal(spdm_response->header.param2, 1);

#else
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
    /*set csr after reset*/
    assert_true(libspdm_set_csr_after_reset());
#endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX*/
    /*clear cached req_info*/
    libspdm_test_clear_cached_last_request();
    free(m_libspdm_get_csr_request);
}

libspdm_test_context_t m_libspdm_responder_csr_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_csr_test_main(void)
{
    const struct CMUnitTest spdm_responder_csr_tests[] = {
        /* Success Case for csr response with device_cert mode */
        cmocka_unit_test(libspdm_test_responder_csr_case1),
        /* Bad request size*/
        cmocka_unit_test(libspdm_test_responder_csr_case2),
        /* Success Case for csr response with non-null right req_info */
        cmocka_unit_test(libspdm_test_responder_csr_case3),
        /* Success Case for csr response with non-null opaque_data */
        cmocka_unit_test(libspdm_test_responder_csr_case4),
        /* Failed Case for csr response with non-null wrong req_info */
        cmocka_unit_test(libspdm_test_responder_csr_case5),
        /* Responder need reset to gen csr, the second send after device reset*/
        cmocka_unit_test(libspdm_test_responder_csr_case6),
        /* Success Case for csr response with non-null right req_info and opaque_data */
        cmocka_unit_test(libspdm_test_responder_csr_case7),
        /* Failed Case for csr response  With chaotic req_info and opaque_data */
        cmocka_unit_test(libspdm_test_responder_csr_case8),
        /* the OpaqueDataFmt1 bit is selected in OtherParamsSelection of ALGORITHMS*/
        cmocka_unit_test(libspdm_test_responder_csr_case9),
        /* Failed Case  OpaqueDataFmt1, When AlignPadding is not zero*/
        cmocka_unit_test(libspdm_test_responder_csr_case10),
        /* Success Case for csr response with alias_cert mode */
        cmocka_unit_test(libspdm_test_responder_csr_case11),
        /* Responder need reset to gen csr, the second send without device reset*/
        cmocka_unit_test(libspdm_test_responder_csr_case12),
        /* Success Case: Responder need reset to gen csr for SPDM1.3, the second send with matched csr_tracking_tag after device reset*/
        cmocka_unit_test(libspdm_test_responder_csr_case13),
        /* Failed Case: Responder need reset to gen csr for SPDM1.3, test for busy error*/
        cmocka_unit_test(libspdm_test_responder_csr_case14),
        /* Failed Case: Responder need reset to gen csr for SPDM1.3, test for unmatched csr_tracking_tag and overwrite*/
        cmocka_unit_test(libspdm_test_responder_csr_case15),
    };

    libspdm_setup_test_context(&m_libspdm_responder_csr_test_context);

    /*ensure that cached.csr exists in test_csr at the beginning*/
    libspdm_clear_cached_csr();

    return cmocka_run_group_tests(spdm_responder_csr_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}

#endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP*/
