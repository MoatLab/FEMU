/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_responder_lib.h"

int libspdm_responder_version_test_main(void);
int libspdm_responder_capabilities_test_main(void);
int libspdm_responder_algorithms_test_main(void);

#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
int libspdm_responder_digests_test_main(void);
int libspdm_responder_certificate_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
int libspdm_responder_challenge_auth_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
int libspdm_responder_measurements_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

#if LIBSPDM_RESPOND_IF_READY_SUPPORT
#if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP || LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP || \
     LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP || LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || \
     LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
int libspdm_responder_respond_if_ready_test_main (void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_*_CAP */
#endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
int libspdm_responder_key_exchange_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

int libspdm_responder_finish_test_main(void);

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
int libspdm_responder_psk_exchange_test_main(void);
int libspdm_responder_psk_finish_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
int libspdm_responder_heartbeat_test_main(void);
int libspdm_responder_key_update_test_main(void);
int libspdm_responder_end_session_test_main(void);
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
int spdm_responder_encap_get_digests_test_main(void);
int spdm_responder_encap_get_certificate_test_main(void);
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
#if LIBSPDM_SEND_CHALLENGE_SUPPORT
int libspdm_responder_encap_challenge_auth_test_main(void);
#endif /* LIBSPDM_SEND_CHALLENGE_SUPPORT */
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */
int libspdm_responder_encapsulated_response_test_main(void);
int libspdm_responder_encap_key_update_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP*/

int libspdm_responder_set_certificate_rsp_test_main(void);
int libspdm_responder_csr_test_main(void);

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
int libspdm_responder_chunk_get_rsp_test_main(void);
int libspdm_responder_receive_send_test_main(void);
int libspdm_responder_chunk_send_ack_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
int libspdm_responder_supported_event_types_test_main(void);
int libspdm_responder_supported_event_types_error_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */

#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
int libspdm_responder_vendor_cmds_test_main(void);
int libspdm_responder_vendor_cmds_error_test_main(void);
#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */

int main(void)
{
    int return_value = 0;

    if (libspdm_responder_version_test_main() != 0) {
        return_value = 1;
    }

    if (libspdm_responder_capabilities_test_main() != 0) {
        return_value = 1;
    }

    if (libspdm_responder_algorithms_test_main() != 0) {
        return_value = 1;
    }

    #if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
    if (libspdm_responder_digests_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_responder_certificate_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
    if (libspdm_responder_challenge_auth_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    if (libspdm_responder_measurements_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

    #if LIBSPDM_RESPOND_IF_READY_SUPPORT
    #if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP || LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP || \
         LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP || LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP || \
         LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    if (libspdm_responder_respond_if_ready_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_*_CAP */
    #endif /* LIBSPDM_RESPOND_IF_READY_SUPPORT */

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    if (libspdm_responder_key_exchange_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    if (libspdm_responder_finish_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
    if (libspdm_responder_psk_exchange_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
    if (libspdm_responder_psk_finish_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/

    #if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    if (libspdm_responder_heartbeat_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_responder_key_update_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_responder_end_session_test_main() != 0) {
        return_value = 1;
    }
    #endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */

    #if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
    #if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    #if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
    if (spdm_responder_encap_get_digests_test_main() != 0) {
        return_value = 1;
    }
    if (spdm_responder_encap_get_certificate_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */
    #if LIBSPDM_SEND_CHALLENGE_SUPPORT
    if (libspdm_responder_encap_challenge_auth_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_SEND_CHALLENGE_SUPPORT */
    #endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */
    if (libspdm_responder_encapsulated_response_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_responder_encap_key_update_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
    if (libspdm_responder_set_certificate_rsp_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

    #if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
    if (libspdm_responder_csr_test_main() != 0) {
        return_value = 1;
    }
    #endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
    if (libspdm_responder_chunk_get_rsp_test_main() != 0) {
        return_value = 1;
    }

    if (libspdm_responder_receive_send_test_main() != 0) {
        return_value = 1;
    }

    if (libspdm_responder_chunk_send_ack_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

    #if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
    if (libspdm_responder_supported_event_types_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_responder_supported_event_types_error_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */

    #if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
    if (libspdm_responder_vendor_cmds_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_responder_vendor_cmds_error_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */

    return return_value;
}
