/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_fuzzing.h"

libspdm_test_context_t *m_libspdm_test_context;

bool m_send_receive_buffer_acquired = false;
uint8_t m_send_receive_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
size_t m_send_receive_buffer_size;

libspdm_return_t spdm_device_acquire_sender_buffer (
    void *context, void **msg_buf_ptr)
{
    LIBSPDM_ASSERT (!m_send_receive_buffer_acquired);
    *msg_buf_ptr = m_send_receive_buffer;
    libspdm_zero_mem (m_send_receive_buffer, sizeof(m_send_receive_buffer));
    m_send_receive_buffer_acquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdm_device_release_sender_buffer (
    void *context, const void *msg_buf_ptr)
{
    LIBSPDM_ASSERT (m_send_receive_buffer_acquired);
    LIBSPDM_ASSERT (msg_buf_ptr == m_send_receive_buffer);
    m_send_receive_buffer_acquired = false;
    return;
}

libspdm_return_t spdm_device_acquire_receiver_buffer (
    void *context, void **msg_buf_ptr)
{
    LIBSPDM_ASSERT (!m_send_receive_buffer_acquired);
    *msg_buf_ptr = m_send_receive_buffer;
    libspdm_zero_mem (m_send_receive_buffer, sizeof(m_send_receive_buffer));
    m_send_receive_buffer_acquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdm_device_release_receiver_buffer (
    void *context, const void *msg_buf_ptr)
{
    LIBSPDM_ASSERT (m_send_receive_buffer_acquired);
    LIBSPDM_ASSERT (msg_buf_ptr == m_send_receive_buffer);
    m_send_receive_buffer_acquired = false;
    return;
}

libspdm_test_context_t *libspdm_get_test_context(void)
{
    return m_libspdm_test_context;
}

void libspdm_setup_test_context(libspdm_test_context_t *spdm_test_context)
{
    m_libspdm_test_context = spdm_test_context;
}

size_t libspdm_unit_test_group_setup(void **State)
{
    libspdm_test_context_t *spdm_test_context;
    void *spdm_context;

    spdm_test_context = m_libspdm_test_context;
    spdm_test_context->spdm_context =
        (void *)malloc(libspdm_get_context_size());
    if (spdm_test_context->spdm_context == NULL) {
        return (size_t)-1;
    }
    spdm_context = spdm_test_context->spdm_context;

    libspdm_init_context(spdm_context);

    libspdm_register_device_io_func(spdm_context,
                                    spdm_test_context->send_message,
                                    spdm_test_context->receive_message);
    libspdm_register_transport_layer_func(spdm_context,
                                          LIBSPDM_MAX_SPDM_MSG_SIZE,
                                          LIBSPDM_TEST_TRANSPORT_HEADER_SIZE,
                                          LIBSPDM_TEST_TRANSPORT_TAIL_SIZE,
                                          libspdm_transport_test_encode_message,
                                          libspdm_transport_test_decode_message);
    libspdm_register_device_buffer_func(spdm_context,
                                        LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE,
                                        LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE,
                                        spdm_device_acquire_sender_buffer,
                                        spdm_device_release_sender_buffer,
                                        spdm_device_acquire_receiver_buffer,
                                        spdm_device_release_receiver_buffer);

    spdm_test_context->scratch_buffer_size =
        libspdm_get_sizeof_required_scratch_buffer(spdm_context);
    spdm_test_context->scratch_buffer = (void *)malloc(spdm_test_context->scratch_buffer_size);
    libspdm_set_scratch_buffer (spdm_context,
                                spdm_test_context->scratch_buffer,
                                spdm_test_context->scratch_buffer_size);

    *State = spdm_test_context;
    return 0;
}

size_t libspdm_unit_test_group_teardown(void **State)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = *State;
    free(spdm_test_context->spdm_context);
    free(spdm_test_context->scratch_buffer);
    spdm_test_context->spdm_context = NULL;
    return 0;
}

bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size)
{
    FILE *fp_in;
    size_t temp_result;

    if ((fp_in = fopen(file_name, "rb")) == NULL) {
        printf("Unable to open file %s\n", file_name);
        *file_data = NULL;
        return false;
    }

    fseek(fp_in, 0, SEEK_END);
    *file_size = ftell(fp_in);

    *file_data = (void *)malloc(*file_size);
    if (NULL == *file_data) {
        printf("No sufficient memory to allocate %s\n", file_name);
        fclose(fp_in);
        return false;
    }

    fseek(fp_in, 0, SEEK_SET);
    temp_result = fread(*file_data, 1, *file_size, fp_in);
    if (temp_result != *file_size) {
        printf("Read input file error %s", file_name);
        free((void *)*file_data);
        fclose(fp_in);
        return false;
    }

    fclose(fp_in);

    return true;
}

bool libspdm_write_output_file(const char *file_name, const void *file_data,
                               size_t file_size)
{
    FILE *fp_out;

    if ((fp_out = fopen(file_name, "w+b")) == NULL) {
        printf("Unable to open file %s\n", file_name);
        return false;
    }

    if ((fwrite(file_data, 1, file_size, fp_out)) != file_size) {
        printf("Write output file error %s\n", file_name);
        fclose(fp_out);
        return false;
    }

    fclose(fp_out);

    return true;
}

void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size)
{
    size_t index;

    for (index = 0; index < buffer_size; index++) {
        printf("%02x", buffer[index]);
    }
}

void libspdm_dump_data(const uint8_t *buffer, size_t buffer_size)
{
    size_t index;

    for (index = 0; index < buffer_size; index++) {
        printf("%02x ", buffer[index]);
    }
}

void libspdm_dump_hex(const uint8_t *data, size_t size)
{
    size_t index;
    size_t count;
    size_t left;

#define COLUME_SIZE (16 * 2)

    count = size / COLUME_SIZE;
    left = size % COLUME_SIZE;
    for (index = 0; index < count; index++) {
        printf("%04x: ", (uint32_t)(index * COLUME_SIZE));
        libspdm_dump_data(data + index * COLUME_SIZE, COLUME_SIZE);
        printf("\n");
    }

    if (left != 0) {
        printf("%04x: ", (uint32_t)(index * COLUME_SIZE));
        libspdm_dump_data(data + index * COLUME_SIZE, left);
        printf("\n");
    }
}
