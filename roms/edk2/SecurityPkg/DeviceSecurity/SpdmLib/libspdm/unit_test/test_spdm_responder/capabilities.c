/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request1 = {
    {
        SPDM_MESSAGE_VERSION_10,
        SPDM_GET_CAPABILITIES,
    },
};
/* version 1.0 message consists of only header (size 0x04).
 * However, spdm_get_capabilities_request_t has a size of 0x0c.
 * Therefore, sending a v1.0 request with this structure results in a wrong size request.
 * size information was corrected to reflect the actual size of a get_capabilities 1.0 message.*/
size_t m_libspdm_get_capabilities_request1_size = sizeof(spdm_message_header_t);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request2 = {
    {
        SPDM_MESSAGE_VERSION_10,
        SPDM_GET_CAPABILITIES,
    },
};
size_t m_libspdm_get_capabilities_request2_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request4 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request4_size =
    sizeof(m_libspdm_get_capabilities_request4) -
    sizeof(m_libspdm_get_capabilities_request4.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request4.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request5 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (0x01 | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request5_size =
    sizeof(m_libspdm_get_capabilities_request5) -
    sizeof(m_libspdm_get_capabilities_request5.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request5.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request6 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request6_size =
    sizeof(m_libspdm_get_capabilities_request6) -
    sizeof(m_libspdm_get_capabilities_request6.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request6.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request7 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    LIBSPDM_MAX_CT_EXPONENT + 1, /*Illegal ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (0x100000 | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request7_size =
    sizeof(m_libspdm_get_capabilities_request7) -
    sizeof(m_libspdm_get_capabilities_request7.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request7.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request8 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (0x100000 | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request8_size =
    sizeof(m_libspdm_get_capabilities_request8) -
    sizeof(m_libspdm_get_capabilities_request8.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request8.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request9 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request9_size =
    sizeof(m_libspdm_get_capabilities_request9) -
    sizeof(m_libspdm_get_capabilities_request9.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request9.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request10 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |

     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |


     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request10_size =
    sizeof(m_libspdm_get_capabilities_request10) -
    sizeof(m_libspdm_get_capabilities_request10.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request10.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request11 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |

     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |


     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request11_size =
    sizeof(m_libspdm_get_capabilities_request11) -
    sizeof(m_libspdm_get_capabilities_request11.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request11.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request12 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |


     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |

     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP

    )
};
size_t m_libspdm_get_capabilities_request12_size =
    sizeof(m_libspdm_get_capabilities_request12) -
    sizeof(m_libspdm_get_capabilities_request12.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request12.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request13 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |


     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |

     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP

    )
};
size_t m_libspdm_get_capabilities_request13_size =
    sizeof(m_libspdm_get_capabilities_request13) -
    sizeof(m_libspdm_get_capabilities_request13.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request13.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request14 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |

     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request14_size =
    sizeof(m_libspdm_get_capabilities_request14) -
    sizeof(m_libspdm_get_capabilities_request14.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request14.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request15 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP)
};
size_t m_libspdm_get_capabilities_request15_size =
    sizeof(m_libspdm_get_capabilities_request15) -
    sizeof(m_libspdm_get_capabilities_request15.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request15.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request16 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |

     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request16_size =
    sizeof(m_libspdm_get_capabilities_request16) -
    sizeof(m_libspdm_get_capabilities_request16.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request16.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request17 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /*flags*/
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |


     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
};
size_t m_libspdm_get_capabilities_request17_size =
    sizeof(m_libspdm_get_capabilities_request17) -
    sizeof(m_libspdm_get_capabilities_request17.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request17.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request18 = {
    {
        SPDM_MESSAGE_VERSION_11,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    ( /*flags*/
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP)
};
size_t m_libspdm_get_capabilities_request18_size =
    sizeof(m_libspdm_get_capabilities_request18) -
    sizeof(m_libspdm_get_capabilities_request18.data_transfer_size) -
    sizeof(m_libspdm_get_capabilities_request18.max_spdm_msg_size);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request19 = {
    {
        SPDM_MESSAGE_VERSION_12,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP|
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP),
    LIBSPDM_DATA_TRANSFER_SIZE,
    LIBSPDM_MAX_SPDM_MSG_SIZE,
};
size_t m_libspdm_get_capabilities_request19_size = sizeof(m_libspdm_get_capabilities_request19);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request25 = {
    {
        SPDM_MESSAGE_VERSION_12,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    0,
    LIBSPDM_DATA_TRANSFER_SIZE - 1,
    LIBSPDM_MAX_SPDM_MSG_SIZE,
};
size_t m_libspdm_get_capabilities_request25_size = sizeof(m_libspdm_get_capabilities_request25);

spdm_get_capabilities_request_t m_libspdm_get_capabilities_request26 = {
    {
        SPDM_MESSAGE_VERSION_12,
        SPDM_GET_CAPABILITIES,
    }, /*header*/
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP|
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP),
    LIBSPDM_DATA_TRANSFER_SIZE,
    LIBSPDM_DATA_TRANSFER_SIZE - 1,
};
size_t m_libspdm_get_capabilities_request26_size = sizeof(m_libspdm_get_capabilities_request26);


spdm_get_capabilities_request_t m_libspdm_get_capabilities_request27 = {
    {
        SPDM_MESSAGE_VERSION_13,
        SPDM_GET_CAPABILITIES,
    },
    0x00, /*reserved*/
    0x01, /*ct_exponent*/
    0x0000, /*reserved, 2 bytes*/
    SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY,
    LIBSPDM_DATA_TRANSFER_SIZE,
    LIBSPDM_MAX_SPDM_MSG_SIZE,
};
size_t m_libspdm_get_capabilities_request27_size = sizeof(m_libspdm_get_capabilities_request27);

void libspdm_test_responder_capabilities_case1(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request1_size,
        &m_libspdm_get_capabilities_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t) -
                     sizeof(spdm_response->data_transfer_size) -
                     sizeof(spdm_response->max_spdm_msg_size));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request1.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CAPABILITIES);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

void libspdm_test_responder_capabilities_case2(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x2;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_m.buffer_size =
        spdm_context->transcript.message_m.max_buffer_size;
#endif

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request2_size,
        &m_libspdm_get_capabilities_request2, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t) -
                     sizeof(spdm_response->data_transfer_size) -
                     sizeof(spdm_response->max_spdm_msg_size));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request2.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CAPABILITIES);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    assert_int_equal(spdm_context->transcript.message_m.buffer_size, 0);
#endif
}

void libspdm_test_responder_capabilities_case3(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x3;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_BUSY;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request1_size,
        &m_libspdm_get_capabilities_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request1.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_BUSY);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_BUSY);
}

void libspdm_test_responder_capabilities_case4(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x4;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NEED_RESYNC;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request1_size,
        &m_libspdm_get_capabilities_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request1.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_REQUEST_RESYNCH);
    assert_int_equal(spdm_response->header.param2, 0);
    assert_int_equal(spdm_context->response_state,
                     LIBSPDM_RESPONSE_STATE_NEED_RESYNC);
}

void libspdm_test_responder_capabilities_case6(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x6;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_NOT_STARTED;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request1_size,
        &m_libspdm_get_capabilities_request1, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request1.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

/**
 * Test 7: Requester sets a CTExponent value that is larger than LIBSPDM_MAX_CT_EXPONENT.
 * Expected behavior: returns with error code SPDM_ERROR_CODE_INVALID_REQUEST.
 **/
void libspdm_test_responder_capabilities_case7(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x7;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request7_size,
        &m_libspdm_get_capabilities_request7, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request7.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_capabilities_case8(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x8;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request4_size,
        &m_libspdm_get_capabilities_request4, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t) -
                     sizeof(spdm_response->data_transfer_size) -
                     sizeof(spdm_response->max_spdm_msg_size));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request4.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CAPABILITIES);
}

void libspdm_test_responder_capabilities_case9(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x9;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request5_size,
        &m_libspdm_get_capabilities_request5, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t) -
                     sizeof(spdm_response->data_transfer_size) -
                     sizeof(spdm_response->max_spdm_msg_size));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request4.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CAPABILITIES);
}

void libspdm_test_responder_capabilities_case10(void **state)
{
}

void libspdm_test_responder_capabilities_case11(void **state)
{
}

void libspdm_test_responder_capabilities_case12(void **state)
{
}

void libspdm_test_responder_capabilities_case13(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xd;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request9_size,
        &m_libspdm_get_capabilities_request9, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request9.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_capabilities_case14(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xe;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request10_size,
        &m_libspdm_get_capabilities_request10, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request10.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_capabilities_case15(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xf;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request11_size,
        &m_libspdm_get_capabilities_request11, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request11.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_capabilities_case16(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x10;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request12_size,
        &m_libspdm_get_capabilities_request12, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request12.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_capabilities_case17(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x11;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request13_size,
        &m_libspdm_get_capabilities_request13, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request13.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_capabilities_case18(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x12;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    libspdm_reset_message_a(spdm_context);

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request14_size,
        &m_libspdm_get_capabilities_request14, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request14.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_capabilities_case19(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x13;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request15_size,
        &m_libspdm_get_capabilities_request15, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request15.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_capabilities_case20(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x14;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request16_size,
        &m_libspdm_get_capabilities_request16, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request16.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_capabilities_case21(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x15;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request17_size,
        &m_libspdm_get_capabilities_request17, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request17.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_capabilities_case22(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x16;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request18_size,
        &m_libspdm_get_capabilities_request18, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t) -
                     sizeof(spdm_response->data_transfer_size) -
                     sizeof(spdm_response->max_spdm_msg_size));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request18.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CAPABILITIES);
}

void libspdm_test_responder_capabilities_case23(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;
    size_t arbitrary_size;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x17;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    /*filling A with arbitrary data*/
    arbitrary_size = 10;
    libspdm_set_mem(spdm_context->transcript.message_a.buffer, arbitrary_size, (uint8_t) 0xFF);
    spdm_context->transcript.message_a.buffer_size = arbitrary_size;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request4_size,
        &m_libspdm_get_capabilities_request4, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t) -
                     sizeof(spdm_response->data_transfer_size) -
                     sizeof(spdm_response->max_spdm_msg_size));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request4.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code, SPDM_CAPABILITIES);

    assert_int_equal(spdm_context->transcript.message_a.buffer_size,
                     arbitrary_size + m_libspdm_get_capabilities_request4_size + response_size);
    assert_memory_equal(spdm_context->transcript.message_a.buffer + arbitrary_size,
                        &m_libspdm_get_capabilities_request4,
                        m_libspdm_get_capabilities_request4_size);
    assert_memory_equal(spdm_context->transcript.message_a.buffer + arbitrary_size +
                        m_libspdm_get_capabilities_request4_size,
                        response, response_size);
}

void libspdm_test_responder_capabilities_case24(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x18;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request19_size,
        &m_libspdm_get_capabilities_request19, &response_size, response);
    assert_int_equal(spdm_context->connection_info.capability.max_spdm_msg_size,
                     m_libspdm_get_capabilities_request19.max_spdm_msg_size);
    assert_int_equal(spdm_context->connection_info.capability.data_transfer_size,
                     m_libspdm_get_capabilities_request19.data_transfer_size);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_12);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CAPABILITIES);
    assert_int_equal(spdm_response->data_transfer_size, LIBSPDM_DATA_TRANSFER_SIZE);
    assert_int_equal(spdm_response->max_spdm_msg_size, LIBSPDM_MAX_SPDM_MSG_SIZE);
}

void libspdm_test_responder_capabilities_case25(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x19;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request25_size,
        &m_libspdm_get_capabilities_request25, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request25.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_capabilities_case26(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1A;
    spdm_context->connection_info.connection_state =
        LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request26_size,
        &m_libspdm_get_capabilities_request26, &response_size, response);
    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_error_response_t));
    spdm_response = (void *)response;
    assert_int_equal(m_libspdm_get_capabilities_request26.header.spdm_version,
                     spdm_response->header.spdm_version);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_ERROR);
    assert_int_equal(spdm_response->header.param1,
                     SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal(spdm_response->header.param2, 0);
}

void libspdm_test_responder_capabilities_case27(void **state)
{
    libspdm_return_t status;
    libspdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    size_t response_size;
    uint8_t response[LIBSPDM_MAX_SPDM_MSG_SIZE];
    spdm_capabilities_response_t *spdm_response;

    spdm_test_context = *state;
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0x1B;
    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    response_size = sizeof(response);
    status = libspdm_get_response_capabilities(
        spdm_context, m_libspdm_get_capabilities_request27_size,
        &m_libspdm_get_capabilities_request27, &response_size, response);

    assert_int_equal(status, LIBSPDM_STATUS_SUCCESS);
    assert_int_equal(response_size, sizeof(spdm_capabilities_response_t));
    spdm_response = (void *)response;
    assert_int_equal(spdm_response->header.spdm_version, SPDM_MESSAGE_VERSION_13);
    assert_int_equal(spdm_response->header.request_response_code,
                     SPDM_CAPABILITIES);
    assert_int_equal(spdm_response->data_transfer_size, LIBSPDM_DATA_TRANSFER_SIZE);
    assert_int_equal(spdm_response->max_spdm_msg_size, LIBSPDM_MAX_SPDM_MSG_SIZE);
    assert_int_equal(spdm_context->connection_info.capability.flags,
                     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY);
}

libspdm_test_context_t m_libspdm_responder_capabilities_test_context = {
    LIBSPDM_TEST_CONTEXT_VERSION,
    false,
};

int libspdm_responder_capabilities_test_main(void)
{
    const struct CMUnitTest spdm_responder_capabilities_tests[] = {
        /* Success Case*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case1),
        /* Success case where request size is larger than actual message. */
        cmocka_unit_test(libspdm_test_responder_capabilities_case2),
        /* response_state: LIBSPDM_RESPONSE_STATE_BUSY*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case3),
        /* response_state: LIBSPDM_RESPONSE_STATE_NEED_RESYNC*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case4),
        /* connection_state Check*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case6),
        /* Invalid requester capabilities flag (random flag)*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case7),
        /* V1.1 Success case, all possible flags set*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case8),
        /* Requester capabilities flag bit 0 is set. reserved value should ne ignored*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case9),
        /* Can be populated with new test. */
        cmocka_unit_test(libspdm_test_responder_capabilities_case10),
        /* Can be populated with new test. */
        cmocka_unit_test(libspdm_test_responder_capabilities_case11),
        /* Can be populated with new test. */
        cmocka_unit_test(libspdm_test_responder_capabilities_case12),
        /* pub_key_id_cap and cert_cap set (flags are mutually exclusive)*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case13),
        /* encrypt_cap set and key_ex_cap and psk_cap cleared (encrypt_cap demands key_ex_cap or psk_cap to be set)*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case14),
        /* mac_cap set and key_ex_cap and psk_cap cleared (mac_cap demands key_ex_cap or psk_cap to be set)*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case15),
        /* key_ex_cap set and encrypt_cap and mac_cap cleared (key_ex_cap demands encrypt_cap or mac_cap to be set)*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case16),
        /* psk_cap set and encrypt_cap and mac_cap cleared (psk_cap demands encrypt_cap or mac_cap to be set)*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case17),
        /* encap_cap cleared and MUT_AUTH set (MUT_AUTH demands encap_cap to be set)*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case18),
        /* cert_cap set and pub_key_id_cap set (pub_key_id_cap demands cert_cap to be cleared)*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case19),
        /* key_ex_cap cleared and handshake_in_the_clear_cap set (handshake_in_the_clear_cap demands key_ex_cap to be set)*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case20),
        /* encrypt_cap and mac_cap cleared and handshake_in_the_clear_cap set (handshake_in_the_clear_cap shall be cleared if encrypt_cap and mac_cap are cleared)*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case21),
        /* cert_cap cleared and pub_key_id_cap set (pub_key_id_cap demands cert_cap to be cleared)*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case22),
        /* Buffer verification*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case23),
        /* V1.2 Success case, all possible flags set*/
        cmocka_unit_test(libspdm_test_responder_capabilities_case24),
        /* CHUNK_CAP == 0 and data_transfer_size != max_spdm_msg_size should result in error. */
        cmocka_unit_test(libspdm_test_responder_capabilities_case25),
        /* MaxSPDMmsgSize is less than DataTransferSize, then should result in error. */
        cmocka_unit_test(libspdm_test_responder_capabilities_case26),
        /* Success Case , capability supports MULTI_KEY_CAP */
        cmocka_unit_test(libspdm_test_responder_capabilities_case27),
    };

    libspdm_setup_test_context(&m_libspdm_responder_capabilities_test_context);

    return cmocka_run_group_tests(spdm_responder_capabilities_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
