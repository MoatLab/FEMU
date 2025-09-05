/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

int libspdm_requester_get_version_test_main(void);
int libspdm_requester_get_version_error_test_main(void);
int libspdm_requester_get_capabilities_test_main(void);
int libspdm_requester_get_capabilities_error_test_main(void);
int libspdm_requester_negotiate_algorithms_test_main(void);
int libspdm_requester_negotiate_algorithms_error_test_main(void);

#if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
int libspdm_requester_get_digests_test_main(void);
int libspdm_requester_get_digests_error_test_main(void);
int libspdm_requester_get_certificate_test_main(void);
#endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
int libspdm_requester_challenge_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
int libspdm_requester_get_measurements_test_main(void);
int libspdm_requester_get_measurements_error_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
int libspdm_requester_key_exchange_test_main(void);
int libspdm_requester_key_exchange_error_test_main(void);
int libspdm_requester_finish_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
int libspdm_requester_psk_exchange_test_main(void);
int libspdm_requester_psk_finish_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
int libspdm_requester_heartbeat_test_main(void);
int libspdm_requester_key_update_test_main(void);
int libspdm_requester_end_session_test_main(void);
#endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */

#if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
int libspdm_requester_encap_request_test_main(void);
#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
#if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
int libspdm_requester_encap_digests_test_main(void);
int libspdm_requester_encap_certificate_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP */
#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
int libspdm_requester_encap_challenge_auth_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP */
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */
int libspdm_requester_encap_key_update_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */

int libspdm_requester_set_certificate_test_main(void);
int libspdm_requester_get_csr_test_main(void);

#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
int libspdm_requester_chunk_get_test_main(void);
int libspdm_requester_chunk_send_test_main(void);
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

#if LIBSPDM_EVENT_RECIPIENT_SUPPORT
int libspdm_requester_get_event_types_test_main(void);
int libspdm_requester_get_event_types_error_test_main(void);
#endif /* LIBSPDM_EVENT_RECIPIENT_SUPPORT */

#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
int libspdm_requester_vendor_cmds_test_main(void);
int libspdm_requester_vendor_cmds_error_test_main(void);
#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */

int main(void)
{
    int return_value = 0;
    if (libspdm_requester_get_version_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_requester_get_version_error_test_main() != 0) {
        return_value = 1;
    }

    if (libspdm_requester_get_capabilities_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_requester_get_capabilities_error_test_main() != 0) {
        return_value = 1;
    }

    if (libspdm_requester_negotiate_algorithms_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_requester_negotiate_algorithms_error_test_main() != 0) {
        return_value = 1;
    }

    #if LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT
    if (libspdm_requester_get_digests_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_requester_get_digests_error_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_requester_get_certificate_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT */

    #if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
    if (libspdm_requester_challenge_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
    if (libspdm_requester_get_measurements_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_requester_get_measurements_error_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    if (libspdm_requester_key_exchange_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_requester_key_exchange_error_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP
    if (libspdm_requester_finish_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
    if (libspdm_requester_psk_exchange_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
    if (libspdm_requester_psk_finish_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP*/

    #if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP)
    if (libspdm_requester_heartbeat_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_requester_key_update_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_requester_end_session_test_main() != 0) {
        return_value = 1;
    }
    #endif /* (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_CAP) */

    #if LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP
    if (libspdm_requester_encap_request_test_main() != 0) {
        return_value = 1;
    }
    #if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
    #if LIBSPDM_ENABLE_CAPABILITY_CERT_CAP
    if (libspdm_requester_encap_digests_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_requester_encap_certificate_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP */
    #if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
    if (libspdm_requester_encap_challenge_auth_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CERT_CAP */
    #endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */
    if (libspdm_requester_encap_key_update_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP */

    #if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
    if (libspdm_requester_set_certificate_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

    #if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
    if (libspdm_requester_get_csr_test_main() != 0) {
        return_value = 1;
    }
    #endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP*/

    #if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP
    if (libspdm_requester_chunk_get_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_requester_chunk_send_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP */

    #if LIBSPDM_EVENT_RECIPIENT_SUPPORT
    if (libspdm_requester_get_event_types_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_requester_get_event_types_error_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_EVENT_RECIPIENT_SUPPORT */

    #if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
    if (libspdm_requester_vendor_cmds_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_requester_vendor_cmds_error_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */

    return return_value;
}
