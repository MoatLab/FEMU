/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_requester.h"

libspdm_return_t spdm_requester_send_message(void *spdm_context,
                                             size_t message_size, const void *message,
                                             uint64_t timeout)
{
    /* Dummy*/
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdm_requester_receive_message(void *spdm_context,
                                                size_t *message_size,
                                                void **message,
                                                uint64_t timeout)
{
    /* Dummy*/
    return LIBSPDM_STATUS_SUCCESS;
}

uint8_t m_scratch_buffer[LIBSPDM_SCRATCH_BUFFER_SIZE];

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

void *spdm_client_init(void)
{
    void *spdm_context;
    libspdm_return_t status;
    libspdm_data_parameter_t parameter;
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    bool has_rsp_pub_cert;

    spdm_context = (void *)allocate_pool(libspdm_get_context_size());
    if (spdm_context == NULL) {
        return NULL;
    }
    libspdm_init_context(spdm_context);

    libspdm_set_scratch_buffer (spdm_context, m_scratch_buffer, sizeof(m_scratch_buffer));

    libspdm_register_device_io_func(spdm_context, spdm_requester_send_message,
                                    spdm_requester_receive_message);
    libspdm_register_transport_layer_func(spdm_context,
                                          LIBSPDM_MAX_SPDM_MSG_SIZE,
                                          LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
                                          LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE,
                                          libspdm_transport_mctp_encode_message,
                                          libspdm_transport_mctp_decode_message);
    libspdm_register_device_buffer_func(spdm_context,
                                        LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE,
                                        LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE,
                                        spdm_device_acquire_sender_buffer,
                                        spdm_device_release_sender_buffer,
                                        spdm_device_acquire_receiver_buffer,
                                        spdm_device_release_receiver_buffer);

    has_rsp_pub_cert = false;

    data8 = 0;
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                     &parameter, &data8, sizeof(data8));

    data32 = /*SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
              *  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |*/
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
             /*           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |*/
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
             /*           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |*/
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
             SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP /* |
                                                                             * SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP*/
    ;
    if (!has_rsp_pub_cert) {
        data32 &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
    } else {
        data32 |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
    }
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &data32, sizeof(data32));

    data32 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &data32, sizeof(data32));
    data32 = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &data32, sizeof(data32));
    data16 = SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                     &data16, sizeof(data16));
    data16 = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                     &data16, sizeof(data16));
    data16 = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16,
                     sizeof(data16));

    status = libspdm_init_connection(spdm_context, false);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "libspdm_init_connection - %xu\n", status));
        free_pool(spdm_context);
        return NULL;
    }

    return spdm_context;
}
