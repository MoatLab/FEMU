# libspdm 2.3 -> 3.0 Change Log

## New Features
- Support for FIPS 140-3 including known-answer-tests (KAT).
- Raw public keys are now ASN.1 DER encoded.
- Support for OpenSSL 3.0.
- Initial draft for API documentation.

## Library API Changes
- `/include/hal/library` libraries have been broken out into multiple headers.
    - `spdm_device_secret_lib.h` is split to `requester/psklib.h`, `requester/reqasymsignlib.h`, `responder/asymsignlib.h`, `responder/csrlib.h`, `responder/measlib.h`, `responder/psklib.h`, and `responder/setcertlib.h`.
    - `platform_lib.h` is split to `requester/timelib.h` and `responder/watchdoglib.h`
- Registered APIs with changes:
    - `libspdm_device_acquire_sender_buffer_func`
    - `libspdm_device_acquire_receiver_buffer_func`
    - `libspdm_register_transport_layer_func`
    - `libspdm_register_device_buffer_func`
- Library APIs with changes
    - All of the functions in `memlib.h`.
    - `libspdm_write_certificate_to_nvm`
    - `libspdm_challenge_ex`
    - `libspdm_get_measurement_ex`
    - `libspdm_get_csr`
    - `libspdm_set_certificate`
- Data Set/Get removed:
    - `LIBSPDM_DATA_LOCAL_SLOT_COUNT` - deprecated.
    - `LIBSPDM_DATA_PEER_PUBLIC_CERT_CHAIN` - unsupported.
    - `LIBSPDM_DATA_LOCAL_USED_CERT_CHAIN_BUFFER` - unsupported.
    - `LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN_DEFAULT_SLOT_ID` - replaced by new public key solution.
    - `LIBSPDM_DATA_PSK_HINT` - The Integrator needs to input `psk_hint` to `libspdm_start_session`.
- Data Set/Get added:
    - `LIBSPDM_DATA_CAPABILITY_SENDER_DATA_TRANSFER_SIZE` - split from `LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE` that means the size for receiver.
    - `LIBSPDM_DATA_PEER_PUBLIC_KEY` - for new raw public key solution.
    - `LIBSPDM_DATA_LOCAL_PUBLIC_KEY` - for new raw public key solution.
    - `LIBSPDM_DATA_REQUEST_RETRY_TIMES` - replace `LIBSPDM_MAX_REQUEST_RETRY_TIMES` macro.
    - `LIBSPDM_DATA_REQUEST_RETRY_DELAY_TIME` - work with `LIBSPDM_DATA_REQUEST_RETRY_TIMES`.
    - `LIBSPDM_DATA_MAX_DHE_SESSION_COUNT` - maximum allowed DHE session count.
    - `LIBSPDM_DATA_MAX_PSK_SESSION_COUNT` - maximum allowed PSK session count.
    - `LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER` - maximum allowed sequence number for AEAD limit.

## Configuration Macro Changes
- Configuration macros removed:
    - `LIBSPDM_SCRATCH_BUFFER_SIZE` - The Integrator may calculate the `scratch_buffer_size` according to the `max_spdm_msg_size` value input to `libspdm_register_transport_layer_func()`, according to `libspdm_get_scratch_buffer_capacity()` API implementation in [libspdm_com_context_data.c](https://github.com/DMTF/libspdm/blob/main/library/spdm_common_lib/libspdm_com_context_data.c). NOTE: The size requirement depends on `LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP` and `LIBSPDM_RESPOND_IF_READY_SUPPORT`.
    - `LIBSPDM_MAX_SPDM_MSG_SIZE` - The Integrator needs to input `max_spdm_msg_size` to `libspdm_register_transport_layer_func()`.
    - `LIBSPDM_DATA_TRANSFER_SIZE` - It is no longer needed.
    - `LIBSPDM_TRANSPORT_ADDITIONAL_SIZE` - The Integrator needs to inpuit `transport_header_size` and `transport_tail_size` to `libspdm_register_transport_layer_func()`. For example, `LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE` and `LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE`, or `LIBSPDM_PCI_DOE_TRANSPORT_HEADER_SIZE` and `LIBSPDM_PCI_DOE_TRANSPORT_TAIL_SIZE`.
    - `LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE` - The Integrator needs to input `sender_buffer_size` and `receiver_buffer_size` to `libspdm_register_device_buffer_func()`.
    - `LIBSPDM_MAX_MESSAGE_BUFFER_SIZE`, `LIBSPDM_MAX_MESSAGE_SMALL_BUFFER_SIZE`, `LIBSPDM_MAX_MESSAGE_MEDIUM_BUFFER_SIZE` - They are no longer needed. The managed buffer is defined individually, such as cert chain buffer, VCA transcript buffer, L1/L2 transcript buffer, M1/M2 transcript buffer, TH transcript buffer, etc.
    - `LIBSPDM_MAX_REQUEST_RETRY_TIMES` - The Integrator needs to input `LIBSPDM_DATA_REQUEST_RETRY_TIMES`.
    - `LIBSPDM_MAX_SESSION_STATE_CALLBACK_NUM` - The Integrator can only register one `libspdm_session_state_callback_func`.
    - `LIBSPDM_MAX_CONNECTION_STATE_CALLBACK_NUM` - The Integrator can only regsiter one `libspdm_connection_state_callback_func`.
    - `LIBSPDM_MAX_KEY_UPDATE_CALLBACK_NUM` - The Integrator can only register one `libspdm_key_update_callback_func`.
    - `LIBSPDM_MAX_CSR_SIZE` - The real max CSR size is determined by the max SPDM message size.
    - define fine granularity control of crypto algo.
        - `LIBSPDM_RSA_SSA_SUPPORT` is split to `LIBSPDM_RSA_SSA_2048_SUPPORT`, `LIBSPDM_RSA_SSA_3072_SUPPORT` and `LIBSPDM_RSA_SSA_4096_SUPPORT`.
        - `LIBSPDM_RSA_PSS_SUPPORT` is split to `LIBSPDM_RSA_PSS_2048_SUPPORT`, `LIBSPDM_RSA_PSS_3072_SUPPORT` and `LIBSPDM_RSA_PSS_4096_SUPPORT`.
        - `LIBSPDM_ECDSA_SUPPORT` is split to `LIBSPDM_ECDSA_P256_SUPPORT`, `LIBSPDM_ECDSA_P384_SUPPORT` and `LIBSPDM_ECDSA_P521_SUPPORT`.
        - `LIBSPDM_SM2_DSA_SUPPORT` is renamed to `LIBSPDM_SM2_DSA_P256_SUPPORT`.
        - `LIBSPDM_FFDHE_SUPPORT` is slit to `LIBSPDM_FFDHE_2048_SUPPORT`, `LIBSPDM_FFDHE_3072_SUPPORT` and `LIBSPDM_FFDHE_4096_SUPPORT`.
        - `LIBSPDM_ECDHE_SUPPORT` is split to `LIBSPDM_ECDHE_P256_SUPPORT`, `LIBSPDM_ECDHE_P384_SUPPORT` and `LIBSPDM_ECDHE_P521_SUPPORT`.
        - `LIBSPDM_SM2_KEY_EXCHANGE_SUPPORT` is renamed to `LIBSPDM_SM2_KEY_EXCHANGE_P256_SUPPORT`.
        - `LIBSPDM_AEAD_GCM_SUPPORT` is split to `LIBSPDM_AEAD_AES_128_GCM_SUPPORT` and `LIBSPDM_AEAD_AES_256_GCM_SUPPORT`.
        - `LIBSPDM_AEAD_SM4_SUPPORT` is renamed to `LIBSPDM_AEAD_SM4_128_GCM_SUPPORT`.
    - `LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP` is renamed to `LIBSPDM_ENABLE_CAPABILITY_CSR_CAP`.
    - `LIBSPDM_ENABLE_CAPABILITY_SET_CERTIFICATE_CAP` is renamed to `LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP`.
    - `LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP` is renamed to `LIBSPDM_ENABLE_CAPABILITY_PSK_CAP`.
- Configuration macros added:
    - `LIBSPDM_FIPS_MODE` - support FIPS.
    - `LIBSPDM_CERT_PARSE_SUPPORT` - support X.509 parsing enable/disable for responder.
    - `LIBSPDM_SEND_GET_CERTIFICATE_SUPPORT` - split from `LIBSPDM_ENABLE_CAPABILITY_CERT_CAP` that means to receive.
    - `LIBSPDM_SEND_CHALLENGE_SUPPORT` - split from `LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP` that means to receive.
    - `LIBSPDM_RESPOND_IF_READY_SUPPORT` - support RESPOND_IF_READY.
    - `LIBSPDM_CHECK_SPDM_CONTEXT` - optional check to see if SPDM context is setup correctly.

## Additional Changes
- Many bug fixes and further alignment with the SPDM specifications.
