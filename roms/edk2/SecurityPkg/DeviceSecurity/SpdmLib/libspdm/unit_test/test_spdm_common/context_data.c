/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"
#include "internal/libspdm_responder_lib.h"
#include "internal/libspdm_secured_message_lib.h"

libspdm_return_t spdm_device_acquire_sender_buffer (
    void *context, void **msg_buf_ptr);

void spdm_device_release_sender_buffer (void *context, const void *msg_buf_ptr);

libspdm_return_t spdm_device_acquire_receiver_buffer (
    void *context, void **msg_buf_ptr);

void spdm_device_release_receiver_buffer (void *context, const void *msg_buf_ptr);

static uint32_t libspdm_opaque_data = 0xDEADBEEF;

/**
 * This function verifies peer certificate chain buffer including spdm_cert_chain_t header.
 *
 * @param  spdm_context            A pointer to the SPDM context.
 * @param  cert_chain_buffer       Certificate chain buffer including spdm_cert_chain_t header.
 * @param  cert_chain_buffer_size  Size in bytes of the certificate chain buffer.
 * @param  trust_anchor            A buffer to hold the trust_anchor which is used to validate the
 *                                 peer certificate, if not NULL.
 * @param  trust_anchor_size       A buffer to hold the trust_anchor_size, if not NULL.
 *
 * @retval true  Peer certificate chain buffer verification passed.
 * @retval false Peer certificate chain buffer verification failed.
 **/
static bool libspdm_verify_peer_cert_chain_buffer(void *spdm_context,
                                                  const void *cert_chain_buffer,
                                                  size_t cert_chain_buffer_size,
                                                  const void **trust_anchor,
                                                  size_t *trust_anchor_size)
{
    bool result;

    /*verify peer cert chain integrity*/
    result = libspdm_verify_peer_cert_chain_buffer_integrity(spdm_context, cert_chain_buffer,
                                                             cert_chain_buffer_size);
    if (!result) {
        return false;
    }

    /*verify peer cert chain authority*/
    result = libspdm_verify_peer_cert_chain_buffer_authority(spdm_context, cert_chain_buffer,
                                                             cert_chain_buffer_size, trust_anchor,
                                                             trust_anchor_size);
    if (!result) {
        return false;
    }

    return true;
}

/**
 * Return the size in bytes of multi element opaque data supported version.
 *
 * @param  version_count                 Secure version count.
 *
 * @return the size in bytes of opaque data supported version.
 **/
size_t libspdm_get_multi_element_opaque_data_supported_version_data_size(
    libspdm_context_t *spdm_context, uint8_t version_count, uint8_t element_num)
{
    size_t size;
    uint8_t element_index;

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        size = sizeof(spdm_general_opaque_data_table_header_t);
        for (element_index = 0; element_index < element_num; element_index++) {
            size += sizeof(secured_message_opaque_element_table_header_t) +
                    sizeof(secured_message_opaque_element_supported_version_t) +
                    sizeof(spdm_version_number_t) * version_count;
            /* Add Padding*/
            size = (size + 3) & ~3;
        }
    } else {
        size = sizeof(secured_message_general_opaque_data_table_header_t);
        for (element_index = 0; element_index < element_num; element_index++) {
            size += sizeof(secured_message_opaque_element_table_header_t) +
                    sizeof(secured_message_opaque_element_supported_version_t) +
                    sizeof(spdm_version_number_t) * version_count;
            /* Add Padding*/
            size = (size + 3) & ~3;
        }
    }

    return size;
}

/**
 * Build opaque data supported version test.
 *
 * @param  data_out_size[in]                 size in bytes of the data_out.
 *                                           On input, it means the size in bytes of data_out buffer.
 *                                           On output, it means the size in bytes of copied data_out buffer if RETURN_SUCCESS is returned,
 *                                           and means the size in bytes of desired data_out buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  data_out[in]                      A pointer to the desination buffer to store the opaque data supported version.
 * @param  element_num[in]                   in this test function, the element number < 9 is right. because element id is changed with element_index
 *
 * @retval RETURN_SUCCESS               The opaque data supported version is built successfully.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 **/
libspdm_return_t
libspdm_build_multi_element_opaque_data_supported_version_test(libspdm_context_t *spdm_context,
                                                               size_t *data_out_size,
                                                               void *data_out,
                                                               uint8_t element_num)
{
    size_t final_data_size;
    secured_message_general_opaque_data_table_header_t
    *general_opaque_data_table_header;
    spdm_general_opaque_data_table_header_t
    *spdm_general_opaque_data_table_header;
    secured_message_opaque_element_table_header_t
    *opaque_element_table_header;
    secured_message_opaque_element_supported_version_t
    *opaque_element_support_version;
    spdm_version_number_t *versions_list;
    void *end;
    uint8_t element_index;

    if (spdm_context->local_context.secured_message_version
        .spdm_version_count == 0) {
        *data_out_size = 0;
        return LIBSPDM_STATUS_SUCCESS;
    }

    final_data_size =
        libspdm_get_multi_element_opaque_data_supported_version_data_size(
            spdm_context,
            spdm_context->local_context.secured_message_version.spdm_version_count,
            element_num);
    if (*data_out_size < final_data_size) {
        *data_out_size = final_data_size;
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header = data_out;
        spdm_general_opaque_data_table_header->total_elements = element_num;
        libspdm_write_uint24(spdm_general_opaque_data_table_header->reserved, 0);
        opaque_element_table_header =
            (void *)(spdm_general_opaque_data_table_header + 1);
    } else {
        general_opaque_data_table_header = data_out;
        general_opaque_data_table_header->spec_id =
            SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID;
        general_opaque_data_table_header->opaque_version =
            SECURED_MESSAGE_OPAQUE_VERSION;
        general_opaque_data_table_header->total_elements = element_num;
        general_opaque_data_table_header->reserved = 0;
        opaque_element_table_header =
            (void *)(general_opaque_data_table_header + 1);
    }

    for (element_index = 0; element_index < element_num; element_index++) {
        /*id is changed with element_index*/
        opaque_element_table_header->id = element_index;
        opaque_element_table_header->vendor_len = 0;
        opaque_element_table_header->opaque_element_data_len =
            sizeof(secured_message_opaque_element_supported_version_t) +
            sizeof(spdm_version_number_t) *
            spdm_context->local_context.secured_message_version.spdm_version_count;

        opaque_element_support_version =
            (void *)(opaque_element_table_header + 1);
        opaque_element_support_version->sm_data_version =
            SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
        opaque_element_support_version->sm_data_id =
            SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION;
        opaque_element_support_version->version_count =
            spdm_context->local_context.secured_message_version.spdm_version_count;

        versions_list = (void *)(opaque_element_support_version + 1);

        libspdm_copy_mem(versions_list,
                         *data_out_size - ((uint8_t*)versions_list - (uint8_t*)data_out),
                         spdm_context->local_context.secured_message_version.spdm_version,
                         spdm_context->local_context.secured_message_version.spdm_version_count *
                         sizeof(spdm_version_number_t));

        /*move to next element*/
        if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
            opaque_element_table_header =
                (secured_message_opaque_element_table_header_t *)(
                    (uint8_t *)opaque_element_table_header +
                    libspdm_get_multi_element_opaque_data_supported_version_data_size(
                        spdm_context,
                        spdm_context->local_context.secured_message_version.spdm_version_count,
                        1) -
                    sizeof(spdm_general_opaque_data_table_header_t));
        } else {
            opaque_element_table_header =
                (secured_message_opaque_element_table_header_t *)(
                    (uint8_t *)opaque_element_table_header +
                    libspdm_get_multi_element_opaque_data_supported_version_data_size(
                        spdm_context,
                        spdm_context->local_context.secured_message_version.spdm_version_count,
                        1) -
                    sizeof(secured_message_general_opaque_data_table_header_t));
        }

        /* Zero Padding. *data_out_size does not need to be changed, because data is 0 padded */
        end = versions_list +
              spdm_context->local_context.secured_message_version.spdm_version_count;
        libspdm_zero_mem(end, (size_t)data_out + final_data_size - (size_t)end);
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "successful build multi element opaque data supported version! \n"));
    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Return the size in bytes of multi element opaque data selection version.
 *
 * @param  version_count                 Secure version count.
 *
 * @return the size in bytes of opaque data selection version.
 **/
size_t libspdm_get_multi_element_opaque_data_version_selection_data_size(
    const libspdm_context_t *spdm_context, uint8_t element_num)
{
    size_t size;
    uint8_t element_index;

    if (spdm_context->local_context.secured_message_version
        .spdm_version_count == 0) {
        return 0;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        size = sizeof(spdm_general_opaque_data_table_header_t);
        for (element_index = 0; element_index < element_num; element_index++) {
            size += sizeof(secured_message_opaque_element_table_header_t) +
                    sizeof(secured_message_opaque_element_version_selection_t);
            /* Add Padding*/
            size = (size + 3) & ~3;
        }
    } else {
        size = sizeof(secured_message_general_opaque_data_table_header_t);
        for (element_index = 0; element_index < element_num; element_index++) {
            size += sizeof(secured_message_opaque_element_table_header_t) +
                    sizeof(secured_message_opaque_element_version_selection_t);
            /* Add Padding*/
            size = (size + 3) & ~3;
        }
    }

    return size;
}

/**
 * Build opaque data selection version test.
 *
 * @param  data_out_size[in]                 size in bytes of the data_out.
 *                                           On input, it means the size in bytes of data_out buffer.
 *                                           On output, it means the size in bytes of copied data_out buffer if RETURN_SUCCESS is returned,
 *                                           and means the size in bytes of desired data_out buffer if RETURN_BUFFER_TOO_SMALL is returned.
 * @param  data_out[in]                      A pointer to the desination buffer to store the opaque data selection version.
 * @param  element_num[in]                   in this test function, the element number < 9 is right. because element id is changed with element_index
 *
 * @retval RETURN_SUCCESS               The opaque data selection version is built successfully.
 * @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
 **/
libspdm_return_t
libspdm_build_opaque_data_version_selection_data_test(const libspdm_context_t *spdm_context,
                                                      size_t *data_out_size,
                                                      void *data_out,
                                                      uint8_t element_num)
{
    size_t final_data_size;
    secured_message_general_opaque_data_table_header_t
    *general_opaque_data_table_header;
    spdm_general_opaque_data_table_header_t
    *spdm_general_opaque_data_table_header;
    secured_message_opaque_element_table_header_t
    *opaque_element_table_header;
    secured_message_opaque_element_version_selection_t
    *opaque_element_version_section;
    void *end;
    uint8_t element_index;
    size_t current_element_len;

    if (spdm_context->local_context.secured_message_version
        .spdm_version_count == 0) {
        *data_out_size = 0;
        return LIBSPDM_STATUS_SUCCESS;
    }

    final_data_size =
        libspdm_get_multi_element_opaque_data_version_selection_data_size(spdm_context,
                                                                          element_num);
    if (*data_out_size < final_data_size) {
        *data_out_size = final_data_size;
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    }

    if (libspdm_get_connection_version (spdm_context) >= SPDM_MESSAGE_VERSION_12) {
        spdm_general_opaque_data_table_header = data_out;
        spdm_general_opaque_data_table_header->total_elements = element_num;
        libspdm_write_uint24(spdm_general_opaque_data_table_header->reserved, 0);

        opaque_element_table_header =
            (void *)(spdm_general_opaque_data_table_header + 1);
    } else {
        general_opaque_data_table_header = data_out;
        general_opaque_data_table_header->spec_id =
            SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID;
        general_opaque_data_table_header->opaque_version =
            SECURED_MESSAGE_OPAQUE_VERSION;
        general_opaque_data_table_header->total_elements = element_num;
        general_opaque_data_table_header->reserved = 0;

        opaque_element_table_header =
            (void *)(general_opaque_data_table_header + 1);
    }

    for (element_index = 0; element_index < element_num; element_index++) {
        /*id is changed with element_index*/
        opaque_element_table_header->id = element_index;
        opaque_element_table_header->vendor_len = 0;
        opaque_element_table_header->opaque_element_data_len =
            sizeof(secured_message_opaque_element_version_selection_t);

        opaque_element_version_section = (void *)(opaque_element_table_header + 1);
        opaque_element_version_section->sm_data_version =
            SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
        opaque_element_version_section->sm_data_id =
            SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION;
        opaque_element_version_section->selected_version =
            spdm_context->connection_info.secured_message_version;

        /*move to next element*/
        current_element_len = sizeof(secured_message_opaque_element_table_header_t) +
                              opaque_element_table_header->opaque_element_data_len;
        /* Add Padding*/
        current_element_len = (current_element_len + 3) & ~3;

        opaque_element_table_header =
            (secured_message_opaque_element_table_header_t *)(
                (uint8_t *)opaque_element_table_header + current_element_len);
    }

    /* Zero Padding*/
    end = opaque_element_version_section + 1;
    libspdm_zero_mem(end, (size_t)data_out + final_data_size - (size_t)end);

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO,
                   "successful build multi element opaque data selection version! \n"));

    return LIBSPDM_STATUS_SUCCESS;
}


/**
 * Test 1: Basic test - tests happy path of setting and getting opaque data from
 * context successfully.
 **/
static void libspdm_test_common_context_data_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data = (void *)&libspdm_opaque_data;
    void *return_data = NULL;
    size_t data_return_size = 0;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;

    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &data, sizeof(data));
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    data_return_size = sizeof(return_data);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &return_data, &data_return_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    assert_memory_equal(data, return_data, sizeof(data));
    assert_int_equal(data_return_size, sizeof(void*));

    /* check that nothing changed at the data location */
    assert_int_equal(libspdm_opaque_data, 0xDEADBEEF);
}

/**
 * Test 2: Test failure paths of setting opaque data in context. libspdm_set_data
 * should fail when an invalid size is passed.
 **/
static void libspdm_test_common_context_data_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data = (void *)&libspdm_opaque_data;
    void *return_data = NULL;
    void *current_return_data = NULL;
    size_t data_return_size = 0;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;

    /**
     * Get current opaque data in context. May have been set in previous
     * tests. This will be used to compare later to ensure the value hasn't
     * changed after a failed set data.
     */
    data_return_size = sizeof(current_return_data);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &current_return_data, &data_return_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(data_return_size, sizeof(void*));

    /* Ensure nothing has changed between subsequent calls to get data */
    assert_ptr_equal(current_return_data, &libspdm_opaque_data);

    /*
     * Set data with invalid size, it should fail. Read back to ensure that
     * no data was set.
     */
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &data, 500);
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);

    data_return_size = sizeof(return_data);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &return_data, &data_return_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(return_data, current_return_data);
    assert_int_equal(data_return_size, sizeof(void*));

    /* check that nothing changed at the data location */
    assert_int_equal(libspdm_opaque_data, 0xDEADBEEF);
}

/**
 * Test 3: Test failure paths of setting opaque data in context. libspdm_set_data
 * should fail when data contains NULL value.
 **/
static void libspdm_test_common_context_data_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data = NULL;
    void *return_data = NULL;
    void *current_return_data = NULL;
    size_t data_return_size = 0;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;

    /**
     * Get current opaque data in context. May have been set in previous
     * tests. This will be used to compare later to ensure the value hasn't
     * changed after a failed set data.
     */
    data_return_size = sizeof(current_return_data);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &current_return_data, &data_return_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(data_return_size, sizeof(void*));

    /* Ensure nothing has changed between subsequent calls to get data */
    assert_ptr_equal(current_return_data, &libspdm_opaque_data);


    /*
     * Set data with NULL data, it should fail. Read back to ensure that
     * no data was set.
     */
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &data, sizeof(void *));
    assert_int_equal(status, LIBSPDM_STATUS_INVALID_PARAMETER);

    data_return_size = sizeof(return_data);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &return_data, &data_return_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_ptr_equal(return_data, current_return_data);
    assert_int_equal(data_return_size, sizeof(void*));

    /* check that nothing changed at the data location */
    assert_int_equal(libspdm_opaque_data, 0xDEADBEEF);

}

/**
 * Test 4: Test failure paths of getting opaque data in context. libspdm_get_data
 * should fail when the size of buffer to get is too small.
 **/
static void libspdm_test_common_context_data_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data = (void *)&libspdm_opaque_data;
    void *return_data = NULL;
    size_t data_return_size = 0;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;

    /*
     * Set data successfully.
     */
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &data, sizeof(void *));
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);

    /*
     * Fail get data due to insufficient buffer for return value. returned
     * data size must return required buffer size.
     */
    data_return_size = sizeof(void*) - 1;
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              NULL, &return_data, &data_return_size);
    assert_int_equal(status, LIBSPDM_STATUS_BUFFER_TOO_SMALL);
    assert_int_equal(data_return_size, sizeof(void*));

    /* check that nothing changed at the data location */
    assert_int_equal(libspdm_opaque_data, 0xDEADBEEF);
}

/**
 * Test 5: There is no root cert.
 * Expected Behavior: Return true result.
 **/
void libspdm_test_verify_peer_cert_chain_buffer_case5(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    const void *trust_anchor;
    size_t trust_anchor_size;
    bool result;
    uint8_t root_cert_index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x5;
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

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo= m_libspdm_use_asym_algo;
    spdm_context->local_context.is_requester = true;

    /*clear root cert array*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] = 0;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = NULL;
    }
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, true);

    free(data);
}

/**
 * Test 6: There is one root cert. And the root cert has two case: match root cert, mismatch root cert.
 *
 * case                                              Expected Behavior
 * there is one match root cert;                     return false
 * there is one mismatch root cert;                  return true, and the return trust_anchor is root cert.
 **/
void libspdm_test_verify_peer_cert_chain_buffer_case6(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    void *data_test;
    size_t data_size_test;
    void *hash_test;
    size_t hash_size_test;
    const uint8_t *root_cert_test;
    size_t root_cert_size_test;
    uint32_t m_libspdm_use_asym_algo_test =SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;

    const void *trust_anchor;
    size_t trust_anchor_size;
    bool result;
    uint8_t root_cert_index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.is_requester = true;

    /* Loading Root certificate and saving its hash*/
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    /* Loading Other test Root certificate and saving its hash*/
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo_test, &data_test,
                                                    &data_size_test, &hash_test, &hash_size_test);
    libspdm_x509_get_cert_from_cert_chain(
        (uint8_t *)data_test + sizeof(spdm_cert_chain_t) + hash_size_test,
        data_size_test - sizeof(spdm_cert_chain_t) - hash_size_test, 0,
        &root_cert_test, &root_cert_size_test);

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo= m_libspdm_use_asym_algo;

    /*clear root cert array*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] = 0;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = NULL;
    }

    /*case: match root cert case*/
    spdm_context->local_context.peer_root_cert_provision_size[0] =root_cert_size_test;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert_test;
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, false);

    /*case: mismatch root cert case*/
    spdm_context->local_context.peer_root_cert_provision_size[0] =root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[0] = root_cert;
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, true);
    assert_ptr_equal (trust_anchor, root_cert);

    free(data);
    free(data_test);
}

/**
 * Test 7: There are LIBSPDM_MAX_ROOT_CERT_SUPPORT/2 root cert.
 *
 * case                                              Expected Behavior
 * there is no match root cert;                      return false
 * there is one match root cert in the end;          return true, and the return trust_anchor is root cert.
 * there is one match root cert in the middle;       return true, and the return trust_anchor is root cert.
 **/
void libspdm_test_verify_peer_cert_chain_buffer_case7(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    void *data_test;
    size_t data_size_test;
    void *hash_test;
    size_t hash_size_test;
    const uint8_t *root_cert_test;
    size_t root_cert_size_test;
    uint32_t m_libspdm_use_asym_algo_test =SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;

    const void *trust_anchor;
    size_t trust_anchor_size;
    bool result;
    uint8_t root_cert_index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.is_requester = true;
    /* Loading Root certificate and saving its hash*/
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    /* Loading Other test Root certificate and saving its hash*/
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo_test, &data_test,
                                                    &data_size_test, &hash_test, &hash_size_test);
    libspdm_x509_get_cert_from_cert_chain(
        (uint8_t *)data_test + sizeof(spdm_cert_chain_t) + hash_size_test,
        data_size_test - sizeof(spdm_cert_chain_t) - hash_size_test, 0,
        &root_cert_test, &root_cert_size_test);

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo= m_libspdm_use_asym_algo;

    /*clear root cert array*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] = 0;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = NULL;
    }

    /*case: there is no match root cert*/
    for (root_cert_index = 0; root_cert_index < (LIBSPDM_MAX_ROOT_CERT_SUPPORT / 2);
         root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] =
            root_cert_size_test;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = root_cert_test;
    }
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, false);

    /*case: there is no match root cert in the end*/
    spdm_context->local_context.peer_root_cert_provision_size[LIBSPDM_MAX_ROOT_CERT_SUPPORT / 2 -
                                                              1] =root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[LIBSPDM_MAX_ROOT_CERT_SUPPORT / 2 -
                                                         1] = root_cert;
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, true);
    assert_ptr_equal (trust_anchor, root_cert);

    /*case: there is no match root cert in the middle*/
    spdm_context->local_context.peer_root_cert_provision_size[LIBSPDM_MAX_ROOT_CERT_SUPPORT /
                                                              4] =root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[LIBSPDM_MAX_ROOT_CERT_SUPPORT /
                                                         4] = root_cert;
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, true);
    assert_ptr_equal (trust_anchor, root_cert);

    free(data);
    free(data_test);
}


/**
 * Test 8: There are full(LIBSPDM_MAX_ROOT_CERT_SUPPORT - 1) root cert.
 *
 * case                                              Expected Behavior
 * there is no match root cert;                      return false
 * there is one match root cert in the end;          return true, and the return trust_anchor is root cert.
 * there is one match root cert in the middle;       return true, and the return trust_anchor is root cert.
 **/
void libspdm_test_verify_peer_cert_chain_buffer_case8(void **state)
{
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    size_t root_cert_size;

    void *data_test;
    size_t data_size_test;
    void *hash_test;
    size_t hash_size_test;
    const uint8_t *root_cert_test;
    size_t root_cert_size_test;
    uint32_t m_libspdm_use_asym_algo_test =SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;

    const void *trust_anchor;
    size_t trust_anchor_size;
    bool result;
    uint8_t root_cert_index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    /* Setting SPDM context as the first steps of the protocol has been accomplished*/
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS;
    spdm_context->connection_info.capability.flags |=
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
    spdm_context->local_context.is_requester = true;
    /* Loading Root certificate and saving its hash*/
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    /* Loading Other test Root certificate and saving its hash*/
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo_test, &data_test,
                                                    &data_size_test, &hash_test, &hash_size_test);
    libspdm_x509_get_cert_from_cert_chain(
        (uint8_t *)data_test + sizeof(spdm_cert_chain_t) + hash_size_test,
        data_size_test - sizeof(spdm_cert_chain_t) - hash_size_test, 0,
        &root_cert_test, &root_cert_size_test);

    spdm_context->connection_info.algorithm.base_hash_algo = m_libspdm_use_hash_algo;
    spdm_context->connection_info.algorithm.base_asym_algo= m_libspdm_use_asym_algo;

    /*case: there is no match root cert*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] =
            root_cert_size_test;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = root_cert_test;
    }
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, false);

    /*case: there is no match root cert in the end*/
    spdm_context->local_context.peer_root_cert_provision_size[LIBSPDM_MAX_ROOT_CERT_SUPPORT -
                                                              1] =root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[LIBSPDM_MAX_ROOT_CERT_SUPPORT -
                                                         1] = root_cert;
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, true);
    assert_ptr_equal (trust_anchor, root_cert);

    /*case: there is no match root cert in the middle*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] =
            root_cert_size_test;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = root_cert_test;
    }
    spdm_context->local_context.peer_root_cert_provision_size[LIBSPDM_MAX_ROOT_CERT_SUPPORT /
                                                              2] =root_cert_size;
    spdm_context->local_context.peer_root_cert_provision[LIBSPDM_MAX_ROOT_CERT_SUPPORT /
                                                         2] = root_cert;
    result = libspdm_verify_peer_cert_chain_buffer(spdm_context, data, data_size, &trust_anchor,
                                                   &trust_anchor_size);
    assert_int_equal (result, true);
    assert_ptr_equal (trust_anchor, root_cert);

    free(data);
    free(data_test);
}

/**
 * Test 9: test set data for root cert.
 *
 * case                                              Expected Behavior
 * there is null root cert;                          return RETURN_SUCCESS, and the root cert is set successfully.
 * there is full root cert;                          return RETURN_OUT_OF_RESOURCES.
 **/
static void libspdm_test_set_data_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_data_parameter_t parameter;

    void *data;
    size_t data_size;
    void *hash;
    size_t hash_size;
    const uint8_t *root_cert;
    uint8_t root_cert_buffer[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t root_cert_size;

    uint8_t root_cert_index;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;

    /* Loading Root certificate and saving its hash*/
    libspdm_read_responder_public_certificate_chain(m_libspdm_use_hash_algo,
                                                    m_libspdm_use_asym_algo, &data,
                                                    &data_size, &hash, &hash_size);
    libspdm_x509_get_cert_from_cert_chain((uint8_t *)data + sizeof(spdm_cert_chain_t) + hash_size,
                                          data_size - sizeof(spdm_cert_chain_t) - hash_size, 0,
                                          &root_cert, &root_cert_size);
    memcpy(root_cert_buffer, root_cert, root_cert_size);

    /*case: there is null root cert*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] = 0;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = NULL;
    }
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                              &parameter, root_cert_buffer, root_cert_size);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal (spdm_context->local_context.peer_root_cert_provision_size[0], root_cert_size);
    assert_ptr_equal (spdm_context->local_context.peer_root_cert_provision[0], root_cert_buffer);

    /*case: there is full root cert*/
    for (root_cert_index = 0; root_cert_index < LIBSPDM_MAX_ROOT_CERT_SUPPORT; root_cert_index++) {
        spdm_context->local_context.peer_root_cert_provision_size[root_cert_index] = root_cert_size;
        spdm_context->local_context.peer_root_cert_provision[root_cert_index] = root_cert_buffer;
    }
    status = libspdm_set_data(spdm_context, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                              &parameter, root_cert_buffer, root_cert_size);
    assert_int_equal (status, LIBSPDM_STATUS_BUFFER_FULL);

    free(data);
}


/**
 * Test 10: There is no root cert.
 * Expected Behavior: Return true result.
 **/
void libspdm_test_process_opaque_data_supported_version_data_case10(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xA;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;

    element_num = 2;
    opaque_data_size =
        libspdm_get_multi_element_opaque_data_supported_version_data_size(
            spdm_context,
            spdm_context->local_context.secured_message_version.spdm_version_count,
            element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_multi_element_opaque_data_supported_version_test(
        spdm_context, &opaque_data_size, opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_supported_version_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr);

    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);

    free(opaque_data_ptr);
}

void libspdm_test_process_opaque_data_supported_version_data_case11(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xB;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;

    /*make element id wrong*/
    element_num = SPDM_REGISTRY_ID_MAX + 2;
    opaque_data_size =
        libspdm_get_multi_element_opaque_data_supported_version_data_size(
            spdm_context,
            spdm_context->local_context.secured_message_version.spdm_version_count,
            element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_multi_element_opaque_data_supported_version_test(
        spdm_context, &opaque_data_size, opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_supported_version_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr);

    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    free(opaque_data_ptr);
}

void libspdm_test_process_opaque_data_supported_version_data_case12(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xC;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;

    element_num = 2;
    opaque_data_size =
        libspdm_get_multi_element_opaque_data_supported_version_data_size(
            spdm_context,
            spdm_context->local_context.secured_message_version.spdm_version_count,
            element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_multi_element_opaque_data_supported_version_test(
        spdm_context, &opaque_data_size, opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_supported_version_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr);

    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);

    free(opaque_data_ptr);
}

void libspdm_test_process_opaque_data_supported_version_data_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xD;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;

    /*make element id wrong*/
    element_num = SPDM_REGISTRY_ID_MAX + 2;
    opaque_data_size =
        libspdm_get_multi_element_opaque_data_supported_version_data_size(
            spdm_context,
            spdm_context->local_context.secured_message_version.spdm_version_count,
            element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_multi_element_opaque_data_supported_version_test(
        spdm_context, &opaque_data_size, opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_supported_version_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr);

    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    free(opaque_data_ptr);
}


void libspdm_test_process_opaque_data_selection_version_data_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xE;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->connection_info.secured_message_version =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    element_num = 2;
    opaque_data_size =
        libspdm_get_multi_element_opaque_data_version_selection_data_size(
            spdm_context,
            element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_opaque_data_version_selection_data_test(
        spdm_context, &opaque_data_size, opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_version_selection_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr);

    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);

    free(opaque_data_ptr);
}


void libspdm_test_process_opaque_data_selection_version_data_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xF;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_11 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->connection_info.secured_message_version =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    /*make element id wrong*/
    element_num = SPDM_REGISTRY_ID_MAX + 2;
    opaque_data_size =
        libspdm_get_multi_element_opaque_data_version_selection_data_size(
            spdm_context,
            element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_opaque_data_version_selection_data_test(
        spdm_context, &opaque_data_size, opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_version_selection_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr);

    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    free(opaque_data_ptr);
}


void libspdm_test_process_opaque_data_selection_version_data_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->connection_info.secured_message_version =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    element_num = 2;
    opaque_data_size =
        libspdm_get_multi_element_opaque_data_version_selection_data_size(
            spdm_context,
            element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_opaque_data_version_selection_data_test(
        spdm_context, &opaque_data_size, opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_version_selection_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr);

    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);

    free(opaque_data_ptr);
}

void libspdm_test_process_opaque_data_selection_version_data_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t opaque_data_size;
    uint8_t element_num;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;

    spdm_context->connection_info.version = SPDM_MESSAGE_VERSION_12 <<
                                            SPDM_VERSION_NUMBER_SHIFT_BIT;

    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->connection_info.secured_message_version =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SECURED_SPDM_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT;

    /*make element id wrong*/
    element_num = SPDM_REGISTRY_ID_MAX + 2;
    opaque_data_size =
        libspdm_get_multi_element_opaque_data_version_selection_data_size(
            spdm_context,
            element_num);

    uint8_t *opaque_data_ptr;
    opaque_data_ptr = malloc(opaque_data_size);

    libspdm_build_opaque_data_version_selection_data_test(
        spdm_context, &opaque_data_size, opaque_data_ptr, element_num);

    status = libspdm_process_opaque_data_version_selection_data(spdm_context,
                                                                opaque_data_size,
                                                                opaque_data_ptr);

    assert_int_equal (status, LIBSPDM_STATUS_INVALID_MSG_FIELD);

    free(opaque_data_ptr);
}

void libspdm_test_secured_message_context_location_selection_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    void *secured_message_contexts[LIBSPDM_MAX_SESSION_COUNT];
    size_t index;

    spdm_test_context = *state;
    spdm_test_context->case_id = 0x12;

    spdm_context = (libspdm_context_t *)malloc(libspdm_get_context_size_without_secured_context());

    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++)
    {
        secured_message_contexts[index] =
            (void *)malloc(libspdm_secured_message_get_context_size());
    }

    status = libspdm_init_context_with_secured_context(spdm_context, secured_message_contexts,
                                                       LIBSPDM_MAX_SESSION_COUNT);
    assert_int_equal (status, LIBSPDM_STATUS_SUCCESS);

    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++)
    {
        /* Ensure the SPDM context points to the specified memory. */
        assert_ptr_equal(spdm_context->session_info[index].secured_message_context,
                         secured_message_contexts[index]);
    }

    free(spdm_context);
    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++)
    {
        free(secured_message_contexts[index]);
    }
}

static void libspdm_test_export_master_secret_case19(void **state)
{
    uint8_t target_buffer[LIBSPDM_MAX_HASH_SIZE];
    bool result;
    libspdm_secured_message_context_t secured_message_context;
    size_t export_master_secret_size;

    /* Get the entire EMS when the reported size of the target buffer is larger than the size of the
     * EMS. */
    for (int index = 0; index < LIBSPDM_MAX_HASH_SIZE; index++) {
        secured_message_context.export_master_secret[index] = (uint8_t)index;
        target_buffer[index] = 0x00;
    }

    secured_message_context.hash_size = LIBSPDM_MAX_HASH_SIZE;
    export_master_secret_size = LIBSPDM_MAX_HASH_SIZE + 0x100;

    result = libspdm_secured_message_export_master_secret(&secured_message_context,
                                                          &target_buffer,
                                                          &export_master_secret_size);
    assert_int_equal(result, true);

    libspdm_secured_message_clear_export_master_secret(&secured_message_context);

    for (int index = 0; index < LIBSPDM_MAX_HASH_SIZE; index++) {
        assert_int_equal(target_buffer[index], index);
        assert_int_equal(secured_message_context.export_master_secret[index], 0x00);
    }
    assert_int_equal(export_master_secret_size, LIBSPDM_MAX_HASH_SIZE);

    /* Get the entire EMS when the size of the target buffer is the same size as the EMS. */
    for (int index = 0; index < LIBSPDM_MAX_HASH_SIZE; index++) {
        secured_message_context.export_master_secret[index] = (uint8_t)index;
        target_buffer[index] = 0x00;
    }

    secured_message_context.hash_size = LIBSPDM_MAX_HASH_SIZE;
    export_master_secret_size = LIBSPDM_MAX_HASH_SIZE;

    result = libspdm_secured_message_export_master_secret(&secured_message_context,
                                                          &target_buffer,
                                                          &export_master_secret_size);
    assert_int_equal(result, true);

    for (int index = 0; index < LIBSPDM_MAX_HASH_SIZE; index++) {
        assert_int_equal(target_buffer[index], index);
    }
    assert_int_equal(export_master_secret_size, LIBSPDM_MAX_HASH_SIZE);

    /* Get the truncated EMS when the size of the target buffer is less than the size of the EMS. */
    for (int index = 0; index < LIBSPDM_MAX_HASH_SIZE; index++) {
        secured_message_context.export_master_secret[index] = (uint8_t)index;
        target_buffer[index] = 0x00;
    }

    secured_message_context.hash_size = LIBSPDM_MAX_HASH_SIZE;
    export_master_secret_size = LIBSPDM_MAX_HASH_SIZE - 4;

    result = libspdm_secured_message_export_master_secret(&secured_message_context,
                                                          &target_buffer,
                                                          &export_master_secret_size);
    assert_int_equal(result, true);

    for (int index = 0; index < LIBSPDM_MAX_HASH_SIZE; index++) {
        if (index < LIBSPDM_MAX_HASH_SIZE - 4) {
            assert_int_equal(target_buffer[index], index);
        } else {
            assert_int_equal(target_buffer[index], 0x00);
        }
    }
    assert_int_equal(export_master_secret_size, LIBSPDM_MAX_HASH_SIZE - 4);
}

static void libspdm_test_check_context_case20(void **state)
{
    void *context;
    bool result;

    context = (void *)malloc (libspdm_get_context_size());

    libspdm_init_context (context);

    result = libspdm_check_context (context);
    assert_int_equal(false, result);

    libspdm_register_transport_layer_func(context,
                                          LIBSPDM_MAX_SPDM_MSG_SIZE,
                                          LIBSPDM_TEST_TRANSPORT_HEADER_SIZE,
                                          LIBSPDM_TEST_TRANSPORT_TAIL_SIZE,
                                          libspdm_transport_test_encode_message,
                                          libspdm_transport_test_decode_message);

    libspdm_register_device_buffer_func(context,
                                        LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE,
                                        LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE,
                                        spdm_device_acquire_sender_buffer,
                                        spdm_device_release_sender_buffer,
                                        spdm_device_acquire_receiver_buffer,
                                        spdm_device_release_receiver_buffer);

    result = libspdm_check_context (context);
    assert_int_equal(true, result);

    libspdm_register_transport_layer_func(context,
                                          SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_12,
                                          LIBSPDM_TEST_TRANSPORT_HEADER_SIZE,
                                          LIBSPDM_TEST_TRANSPORT_TAIL_SIZE,
                                          libspdm_transport_test_encode_message,
                                          libspdm_transport_test_decode_message);

    result = libspdm_check_context (context);
    assert_int_equal(false, result);
}

static void libspdm_test_max_session_count_case21(void **state)
{
    libspdm_context_t *spdm_context;
    libspdm_data_parameter_t parameter;
    size_t index;
    size_t round;
    uint16_t req_id;
    uint16_t rsp_id;
    uint32_t session_id;
    void *session_info;
    uint32_t dhe_session_count;
    uint32_t psk_session_count;

    for (round = 0; round <= 5; round++) {
        /* prepare parameter */
        switch (round) {
        case 0:
            dhe_session_count = 1;
            psk_session_count = 1;
            break;
        case 1:
            dhe_session_count = LIBSPDM_MAX_SESSION_COUNT / 2;
            psk_session_count = LIBSPDM_MAX_SESSION_COUNT - dhe_session_count;
            break;
        case 2:
            dhe_session_count = 1;
            psk_session_count = LIBSPDM_MAX_SESSION_COUNT - 1;
            break;
        case 3:
            dhe_session_count = LIBSPDM_MAX_SESSION_COUNT - 1;
            psk_session_count = 1;
            break;
        case 4:
            dhe_session_count = 0;
            psk_session_count = LIBSPDM_MAX_SESSION_COUNT;
            break;
        case 5:
            dhe_session_count = LIBSPDM_MAX_SESSION_COUNT;
            psk_session_count = 0;
            break;
        default:
            dhe_session_count = 0;
            psk_session_count = 0;
            break;
        }

        /* test */
        spdm_context = (libspdm_context_t *)malloc(libspdm_get_context_size());
        libspdm_init_context (spdm_context);
        spdm_context->connection_info.capability.flags =
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
            SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
        spdm_context->local_context.capability.flags =
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
        spdm_context->connection_info.algorithm.base_hash_algo =
            SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
        spdm_context->connection_info.algorithm.dhe_named_group =
            SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;
        spdm_context->connection_info.algorithm.aead_cipher_suite =
            SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
        spdm_context->connection_info.algorithm.key_schedule =
            SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;

        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        if (dhe_session_count != 0) {
            libspdm_set_data (spdm_context, LIBSPDM_DATA_MAX_DHE_SESSION_COUNT, &parameter,
                              &dhe_session_count, sizeof(dhe_session_count));
        }
        if (psk_session_count != 0) {
            libspdm_set_data (spdm_context, LIBSPDM_DATA_MAX_PSK_SESSION_COUNT, &parameter,
                              &psk_session_count, sizeof(psk_session_count));
        }

        if (dhe_session_count != 0) {
            for (index = 0; index < dhe_session_count; index++)
            {
                req_id = libspdm_allocate_req_session_id (spdm_context, false);
                assert_int_not_equal (req_id, INVALID_SESSION_ID & 0xFFFF);

                rsp_id = libspdm_allocate_rsp_session_id (spdm_context, false);
                assert_int_not_equal (rsp_id, (INVALID_SESSION_ID & 0xFFFF0000) >> 16);

                session_id = libspdm_generate_session_id (req_id, rsp_id);
                session_info = libspdm_assign_session_id (spdm_context, session_id, false);
                assert_ptr_not_equal (session_info, NULL);
            }
            req_id = libspdm_allocate_req_session_id (spdm_context, false);
            assert_int_equal (req_id, INVALID_SESSION_ID & 0xFFFF);

            rsp_id = libspdm_allocate_rsp_session_id (spdm_context, false);
            assert_int_equal (rsp_id, (INVALID_SESSION_ID & 0xFFFF0000) >> 16);
        }

        if (psk_session_count != 0) {
            for (index = 0; index < psk_session_count; index++)
            {
                req_id = libspdm_allocate_req_session_id (spdm_context, true);
                assert_int_not_equal (req_id, INVALID_SESSION_ID & 0xFFFF);

                rsp_id = libspdm_allocate_rsp_session_id (spdm_context, true);
                assert_int_not_equal (rsp_id, (INVALID_SESSION_ID & 0xFFFF0000) >> 16);

                session_id = libspdm_generate_session_id (req_id, rsp_id);
                session_info = libspdm_assign_session_id (spdm_context, session_id, true);
                assert_ptr_not_equal (session_info, NULL);
            }
            req_id = libspdm_allocate_req_session_id (spdm_context, true);
            assert_int_equal (req_id, INVALID_SESSION_ID & 0xFFFF);

            rsp_id = libspdm_allocate_rsp_session_id (spdm_context, true);
            assert_int_equal (rsp_id, (INVALID_SESSION_ID & 0xFFFF0000) >> 16);
        }

        free(spdm_context);
    }
}

static libspdm_test_context_t m_libspdm_common_context_data_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    true,
    NULL,
    NULL,
};

int libspdm_common_context_data_test_main(void)
{
    const struct CMUnitTest spdm_common_context_data_tests[] = {
        cmocka_unit_test(libspdm_test_common_context_data_case1),
        cmocka_unit_test(libspdm_test_common_context_data_case2),
        cmocka_unit_test(libspdm_test_common_context_data_case3),
        cmocka_unit_test(libspdm_test_common_context_data_case4),

        cmocka_unit_test(libspdm_test_verify_peer_cert_chain_buffer_case5),
        cmocka_unit_test(libspdm_test_verify_peer_cert_chain_buffer_case6),
        cmocka_unit_test(libspdm_test_verify_peer_cert_chain_buffer_case7),
        cmocka_unit_test(libspdm_test_verify_peer_cert_chain_buffer_case8),

        cmocka_unit_test(libspdm_test_set_data_case9),

        /* Successful response V1.1 for multi element opaque data supported vesion, element number is 2*/
        cmocka_unit_test(libspdm_test_process_opaque_data_supported_version_data_case10),
        /* Failed response V1.1 for multi element opaque data supported vesion, element id is wrong*/
        cmocka_unit_test(libspdm_test_process_opaque_data_supported_version_data_case11),
        /* Successful response V1.2 for multi element opaque data supported vesion, element number is 2*/
        cmocka_unit_test(libspdm_test_process_opaque_data_supported_version_data_case12),
        /* Failed response V1.2 for multi element opaque data supported vesion, element id is wrong*/
        cmocka_unit_test(libspdm_test_process_opaque_data_supported_version_data_case13),
        /* Successful response V1.1 for multi element opaque data selecetion vesion, element number is 2*/
        cmocka_unit_test(libspdm_test_process_opaque_data_selection_version_data_case14),
        /* Failed response V1.1 for multi element opaque data selecetion vesion, element number is wrong*/
        cmocka_unit_test(libspdm_test_process_opaque_data_selection_version_data_case15),
        /* Successful response V1.2 for multi element opaque data selecetion vesion, element number is 2*/
        cmocka_unit_test(libspdm_test_process_opaque_data_selection_version_data_case16),
        /* Failed response V1.2 for multi element opaque data selecetion vesion, element number is wrong*/
        cmocka_unit_test(libspdm_test_process_opaque_data_selection_version_data_case17),

        /* Successful initialization and setting of secured message context location. */
        cmocka_unit_test(libspdm_test_secured_message_context_location_selection_case18),

        /* Test that the Export Master Secret can be exported and cleared. */
        cmocka_unit_test(libspdm_test_export_master_secret_case19),
        cmocka_unit_test(libspdm_test_check_context_case20),

        /* Test the max DHE/PSK session count */
        cmocka_unit_test(libspdm_test_max_session_count_case21),
    };

    libspdm_setup_test_context(&m_libspdm_common_context_data_test_context);

    return cmocka_run_group_tests(spdm_common_context_data_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
