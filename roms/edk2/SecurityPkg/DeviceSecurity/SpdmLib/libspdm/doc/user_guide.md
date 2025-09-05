# SPDM Requester and Responder User Guide

This document provides the general information on how to construct an SPDM Requester or an SPDM Responder.

Please refer to [FIPS support](fips.md) for FIPS related enabling.

## SPDM Requester

Refer to spdm_client_init() in [spdm_requester.c](https://github.com/DMTF/spdm-emu/blob/main/spdm_emu/spdm_requester_emu/spdm_requester_spdm.c)

0. Choose proper SPDM libraries.

   0.0, choose proper macros in [spdm_lib_config](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_lib_config.h), including:
    - Cryptography Configuration, such as `LIBSPDM_RSA_SSA_2048_SUPPORT`, `LIBSPDM_ECDHE_P256_SUPPORT`.
    - Capability Configuration, such as `LIBSPDM_ENABLE_CAPABILITY_PSK_CAP`, `LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP`, `LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP`.
    - Data Size Configuration, such as `LIBSPDM_MAX_CERT_CHAIN_SIZE`, `LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE`.

   0.1, implement [requester library](https://github.com/DMTF/libspdm/tree/main/include/hal/requester).

   Implement [timelib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/requester/timelib.h).

   If the Requester supports mutual authentication, implement [reqasymsignlib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/requester/reqasymsignlib.h) in a secure environment.

   If the Requester supports PSK exchange, implement [psklib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/requester/psklib.h) in a secure environment.

   0.2, choose a proper [spdm_secured_message_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_secured_message_lib.h).

   If SPDM session key requires confidentiality, implement spdm_secured_message_lib in a secure environment.

   0.3, choose a proper crypto engine [cryptlib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/cryptlib.h).

   0.4, choose required SPDM transport libs, such as [spdm_transport_mctp_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_mctp_lib.h) and [spdm_transport_pcidoe_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_pcidoe_lib.h)

   0.5, implement required SPDM device IO functions - `libspdm_device_send_message_func` and `libspdm_device_receive_message_func` according to [spdm_common_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_common_lib.h). The `timeout`, in microseconds (us) units, is for the execution of the message. For a Requester, the timeout value to send a message is `RTT` and the timeout value to receive a message is `T1 = RTT + ST1` or `T2 = RTT + CT = RTT + 2^ct_exponent`.

1. Initialize SPDM context

   1.1, allocate buffer for the spdm_context, initialize it, and setup scratch_buffer.
   The spdm_context may include the decrypted secured message or session key.
   The scratch buffer may include the decrypted secured message.
   The spdm_context and scratch buffer shall be zeroed before freed or reused.

   ```
   spdm_context = (void *)malloc (libspdm_get_context_size());
   libspdm_init_context (spdm_context);

   scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(m_spdm_context);
   scratch_buffer = (void *)malloc(scratch_buffer_size);
   libspdm_set_scratch_buffer (spdm_context, m_scratch_buffer, scratch_buffer_size);
   ```

   Optionally, the Integrator can calculate the `scratch_buffer_size` according to the `max_spdm_msg_size` value input to `libspdm_register_transport_layer_func()`, according to `libspdm_get_scratch_buffer_capacity()` API implementation in [libspdm_com_context_data.c](https://github.com/DMTF/libspdm/blob/main/library/spdm_common_lib/libspdm_com_context_data.c). NOTE: The size requirement depends on `LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP` and `LIBSPDM_RESPOND_IF_READY_SUPPORT`.

   The location of session keys can be separated from spdm_context if desired.
   Each session holds keys in a secured context, and the location of each can be
   directly specified.

   ```
   spdm_secured_context_size = libspdm_secured_message_get_context_size();
   spdm_secured_contexts[0] = (void *)pointer_to_secured_memory_0;
   spdm_secured_contexts[1] = (void *)pointer_to_secured_memory_1;
   [...]
   spdm_secured_contexts[num_sessions] = (void *)pointer_to_secured_memory_num_sessions;
   spdm_context = (void *)malloc (libspdm_get_context_size_without_secured_context());
   libspdm_init_context_with_secured_context(spdm_context, spdm_secured_contexts, num_sessions);
   ```

   Optionally, the Integrator may use `LIBSPDM_CONTEXT_SIZE_ALL`, or `LIBSPDM_CONTEXT_SIZE_WITHOUT_SECURED_CONTEXT` together with `LIBSPDM_SECURED_MESSAGE_CONTEXT_SIZE`, to preallocate the context buffer from a fixed memory region. In this case, the Integrator needs to include the following internal header files.
   ```
   #include "internal/libspdm_common_lib.h"
   #include "internal/libspdm_secured_message_lib.h"
   ```

   1.2, register the device io functions, transport layer functions, and device buffer functions.
   The libspdm provides the default [spdm_transport_mctp_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_mctp_lib.h) and [spdm_transport_pcidoe_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_pcidoe_lib.h).
   The SPDM device driver need provide device IO send/receive function.
   The final sent and received message will be in the sender buffer and receiver buffer.
   Refer to [design](https://github.com/DMTF/libspdm/blob/main/doc/design.md) for the usage of those APIs.

   ```
   libspdm_register_device_io_func (
     spdm_context,
     spdm_device_send_message,
     spdm_device_receive_message);
   libspdm_register_transport_layer_func (
     spdm_context,
     LIBSPDM_MAX_SPDM_MSG_SIZE, // defined by the Integrator
     LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
     LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE,
     libspdm_transport_mctp_encode_message,
     libspdm_transport_mctp_decode_message);
   libspdm_register_device_buffer_func (
     spdm_context,
     LIBSPDM_SENDER_BUFFER_SIZE, // defined by the Integrator
     LIBSPDM_RECEIVER_BUFFER_SIZE, // defined by the Integrator
     spdm_device_acquire_sender_buffer,
     spdm_device_release_sender_buffer,
     spdm_device_acquire_receiver_buffer,
     spdm_device_release_receiver_buffer);
   ```

   1.3, set capabilities and choose algorithms, based upon need.
   ```
   parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
   libspdm_set_data (spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, &parameter, &ct_exponent, sizeof(ct_exponent));
   libspdm_set_data (spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter, &cap_flags, sizeof(cap_flags));

   libspdm_set_data (spdm_context, LIBSPDM_DATA_CAPABILITY_RTT_US, &parameter, &rtt, sizeof(rtt));

   libspdm_set_data (spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter, &measurement_spec, sizeof(measurement_spec));
   libspdm_set_data (spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &base_asym_algo, sizeof(base_asym_algo));
   libspdm_set_data (spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &base_hash_algo, sizeof(base_hash_algo));
   libspdm_set_data (spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter, &dhe_named_group, sizeof(dhe_named_group));
   libspdm_set_data (spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter, &aead_cipher_suite, sizeof(aead_cipher_suite));
   libspdm_set_data (spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter, &req_base_asym_alg, sizeof(req_base_asym_alg));
   libspdm_set_data (spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &key_schedule, sizeof(key_schedule));
   ```

   1.4, if Responder verification is required, deploy the peer public root certificate based upon need.
   ```
   parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
   libspdm_set_data (spdm_context, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT, &parameter, peer_root_cert, peer_root_cert_size);
   ```
   If there are many peer root certs to set, you can set the peer root certs in order. Note: the max number of peer root certs is LIBSPDM_MAX_ROOT_CERT_SUPPORT.
   ```
   parameter.location = SPDM_DATA_LOCATION_LOCAL;
   libspdm_set_data (spdm_context, SPDM_DATA_PEER_PUBLIC_ROOT_CERT, &parameter, peer_root_cert1, peer_root_cert_size1);
   libspdm_set_data (spdm_context, SPDM_DATA_PEER_PUBLIC_ROOT_CERT, &parameter, peer_root_cert2, peer_root_cert_size2);
   libspdm_set_data (spdm_context, SPDM_DATA_PEER_PUBLIC_ROOT_CERT, &parameter, peer_root_cert3, peer_root_cert_size3);
   ```

   1.5, if mutual authentication is supported, deploy slot number, public certificate chain.
   ```
   parameter.additional_data[0] = slot_id;
   libspdm_set_data (spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter, my_public_cert_chains, my_public_cert_chains_size);
   ```

   1.6, if raw public key is provisioned for Responder verification or mutual authentication, deploy the public key.
        The public key is ASN.1 DER-encoded as [RFC7250](https://www.rfc-editor.org/rfc/rfc7250) describes,
        namely, the `SubjectPublicKeyInfo` structure of a X.509 certificate.
   ```
   parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
   libspdm_set_data (spdm_context, LIBSPDM_DATA_PEER_PUBLIC_KEY, &parameter, peer_public_key, peer_public_key_size);
   libspdm_set_data (spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_KEY, &parameter, local_public_key, local_public_key_size);
   ```

   1.7, if PSK is required, optionally deploy PSK Hint in the call to libspdm_start_session().
   See section 5.1 below.

2. Create connection with the Responder

   Send GET_VERSION, GET_CAPABILITIES and NEGOTIATE_ALGORITHM.
   ```
   libspdm_init_connection (spdm_context, FALSE);
   ```

3. Authentication the Responder

   Send GET_DIGESTS, GET_CERTIFICATES and CHALLENGE.
   ```
   libspdm_get_digest (spdm_context, session_id, slot_mask, total_digest_buffer);
   libspdm_get_certificate (spdm_context, session_id, slot_id, cert_chain_size, cert_chain);
   libspdm_challenge (spdm_context, NULL, slot_id, measurement_hash_type, measurement_hash, &slot_mask);
   ```

4. Get the measurement from the Responder

   4.1, Send GET_MEASUREMENT to query the total number of measurements available.
   ```
   libspdm_get_measurement (
       spdm_context,
       session_id,
       request_attribute,
       SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
       slot_id,
       &content_changed,
       &number_of_blocks,
       NULL,
       NULL
       );
   ```

   4.2, Send GET_MEASUREMENT to get measurement one by one.
   ```
   for (index = 1; index <= number_of_blocks; index++) {
     if (index == number_of_blocks) {
       request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
     }
     libspdm_get_measurement (
       spdm_context,
       session_id,
       request_attribute,
       index,
       slot_id,
       &content_changed,
       &number_of_block,
       &measurement_record_length,
       &measurement_record
       );
   }
   ```

5. Manage an SPDM session

   5.1, Without PSK, send KEY_EXCHANGE/FINISH to create a session.
   ```
   libspdm_start_session (
       spdm_context,
       FALSE, // KeyExchange
       NULL, 0,
       SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH,
       slot_id,
       session_policy,
       &session_id,
       &heartbeat_period,
       &measurement_hash
       );
   ```

   Or with PSK, send PSK_EXCHANGE/PSK_FINISH to create a session.
   ```
   libspdm_start_session (
       spdm_context,
       TRUE, // KeyExchange
       psk_hint, psk_hint_size,
       SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH,
       slot_id,
       session_policy,
       &session_id,
       &heartbeat_period,
       &measurement_hash
       );
   ```

   5.2, Send END_SESSION to close the session.
   ```
   libspdm_stop_session (spdm_context, session_id, end_session_attributes);
   ```

   5.3, Send HEARTBEAT, when it is required.
   ```
   libspdm_heartbeat (spdm_context, session_id);
   ```

   5.4, Send KEY_UPDATE, when it is required.
   ```
   libspdm_key_update (spdm_context, session_id, single_direction);
   ```

6. Send and receive message in an SPDM session

   6.1, Use the SPDM vendor defined request. In libspdm, libspdm_init_connection call is needed first, so NEGOTIATE_ALGORITHMS step is done before sending a vendor defined request. Also, for each VENDOR_DEFINED_REQUEST, a VENDOR_DEFINED_RESPONSE message is expected, even if it has a data payload field of size zero.
   ```
   libspdm_vendor_send_request_receive_response (spdm_context, session_id,
      req_standard_id, req_vendor_id_len, req_vendor_id, req_size, req_data, 
      &resp_standard_id, &resp_vendor_id_len, resp_vendor_id, &resp_size, resp_data);
   ```

   6.2, Use the transport layer application message.
   ```
   libspdm_send_receive_data (spdm_context, &session_id, TRUE, &request, request_size, &response, &response_size);
   ```

7. Free the memory of contexts within the SPDM context when all flow is over.
   This function doesn't free the SPDM context itself.
   ```
   libspdm_deinit_context(spdm_context);
   ```

## SPDM Responder

Refer to spdm_server_init() in [spdm_responder.c](https://github.com/DMTF/spdm-emu/blob/main/spdm_emu/spdm_responder_emu/spdm_responder_spdm.c)

0. Choose proper SPDM libraries.

   0.0, choose proper macros in [spdm_lib_config](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_lib_config.h), including:
    - Cryptography Configuration, such as `LIBSPDM_RSA_SSA_2048_SUPPORT`, `LIBSPDM_ECDHE_P256_SUPPORT`.
    - Capability Configuration, such as `LIBSPDM_ENABLE_CAPABILITY_PSK_CAP`, `LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP`, `LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP`.
    - Data Size Configuration, such as `LIBSPDM_MAX_CERT_CHAIN_SIZE`, `LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE`.

   0.1, implement [responder library](https://github.com/DMTF/libspdm/tree/main/include/hal/responder).

   Implement [watchdoglib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/responder/watchdoglib.h).

   If the Responder supports signing, implement [asymsignlib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/responder/asymsignlib.h) in a secure environment.

   If the Responder supports PSK exchange, implement [psklib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/responder/psklib.h) in a secure environment.

   If the Responder supports measurement, implement [measlib](https://github.com/DMTF/libspdm/blob/main/include/library/responder/measlib.h).

   If the Responder supports CSR signing, implement [csrlib](https://github.com/DMTF/libspdm/blob/main/include/library/responder/csrlib.h) in a secure environment.

   If the Responder supports certificate chain setting, implement [setcertlib](https://github.com/DMTF/libspdm/blob/main/include/library/responder/setcertlib.h).

   0.2, choose a proper [spdm_secured_message_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_secured_message_lib.h).

   If SPDM session key requires confidentiality, implement spdm_secured_message_lib in a secure environment.

   0.3, choose a proper crypto engine [cryptlib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/cryptlib.h).

   0.4, choose required SPDM transport libs, such as [spdm_transport_mctp_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_mctp_lib.h) and [spdm_transport_pcidoe_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_pcidoe_lib.h)

   0.5, implement required SPDM device IO functions - `libspdm_device_send_message_func` and `libspdm_device_receive_message_func` according to [spdm_common_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_common_lib.h).

   0.6, if the device does not have access to a real-time clock and if the device uses OpenSSL or Mbed TLS then undefine `OPENSSL_CHECK_TIME` or `MBEDTLS_HAVE_TIME_DATE`.

0. Implement a proper spdm_device_secret_lib.

1. Initialize SPDM context (similar to SPDM Requester)

   1.1, allocate buffer for the spdm_context, initialize it, and setup scratch_buffer.
   The spdm_context may include the decrypted secured message or session key.
   The scratch buffer may include the decrypted secured message.
   The spdm_context and scratch buffer shall be zeroed before freed or reused.

   ```
   spdm_context = (void *)malloc (spdm_get_context_size());
   libspdm_init_context (spdm_context);

   scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(m_spdm_context);
   libspdm_set_scratch_buffer (spdm_context, m_scratch_buffer, scratch_buffer_size);
   ```

   Optionally, the Integrator can calculate the `scratch_buffer_size` according to the `max_spdm_msg_size` value input to `libspdm_register_transport_layer_func()`, according to `libspdm_get_scratch_buffer_capacity()` API implementation in [libspdm_com_context_data.c](https://github.com/DMTF/libspdm/blob/main/library/spdm_common_lib/libspdm_com_context_data.c). NOTE: The size requirement depends on `LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP` and `LIBSPDM_RESPOND_IF_READY_SUPPORT`.

   The location of session keys can be separated from spdm_context if desired.
   Each session holds keys in a secured context, and the location of each can be
   directly specified.

   ```
   spdm_secured_context_size = libspdm_secured_message_get_context_size();
   spdm_secured_contexts[0] = (void *)pointer_to_secured_memory_0;
   spdm_secured_contexts[1] = (void *)pointer_to_secured_memory_1;
   [...]
   spdm_secured_contexts[num_sessions] = (void *)pointer_to_secured_memory_num_sessions;
   spdm_context = (void *)malloc (libspdm_get_context_size_without_secured_context());
   libspdm_init_context_with_secured_context(spdm_context, spdm_secured_contexts, num_sessions);
   ```

   Optionally, the Integrator may use `LIBSPDM_CONTEXT_SIZE_ALL`, or `LIBSPDM_CONTEXT_SIZE_WITHOUT_SECURED_CONTEXT` together with `LIBSPDM_SECURED_MESSAGE_CONTEXT_SIZE`, to preallocate the context buffer from a fixed memory region. In this case, the Integrator needs to include the following internal header files.
   ```
   #include "internal/libspdm_common_lib.h"
   #include "internal/libspdm_secured_message_lib.h"
   ```

   1.2, register the device io functions, transport layer functions, and device buffer functions.
   The libspdm provides the default [spdm_transport_mctp_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_mctp_lib.h) and [spdm_transport_pcidoe_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_transport_pcidoe_lib.h).
   The SPDM device driver need provide device IO send/receive function.
   The final sent and received message will be in the sender buffer and receiver buffer.
   Refer to [design](https://github.com/DMTF/libspdm/blob/main/doc/design.md) for the usage of those APIs.

   ```
   libspdm_register_device_io_func (
     spdm_context,
     spdm_device_send_message,
     spdm_device_receive_message);
   libspdm_register_transport_layer_func (
     spdm_context,
     LIBSPDM_MAX_SPDM_MSG_SIZE, // defined by the Integrator
     LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
     LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE,
     libspdm_transport_mctp_encode_message,
     libspdm_transport_mctp_decode_message);
   libspdm_register_device_buffer_func (
     spdm_context,
     LIBSPDM_SENDER_BUFFER_SIZE, // defined by the Integrator
     LIBSPDM_RECEIVER_BUFFER_SIZE, // defined by the Integrator
     spdm_device_acquire_sender_buffer,
     spdm_device_release_sender_buffer,
     spdm_device_acquire_receiver_buffer,
     spdm_device_release_receiver_buffer);
   ```

   1.3, set capabilities and choose algorithms, based upon need.
   ```
   parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
   libspdm_set_data (spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, &parameter, &ct_exponent, sizeof(ct_exponent));
   libspdm_set_data (spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter, &cap_flags, sizeof(cap_flags));

   libspdm_set_data (spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter, &measurement_spec, sizeof(measurement_spec));
   libspdm_set_data (spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter, &measurement_hash_algo, sizeof(measurement_hash_algo));
   libspdm_set_data (spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &base_asym_algo, sizeof(base_asym_algo));
   libspdm_set_data (spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &base_hash_algo, sizeof(base_hash_algo));
   libspdm_set_data (spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter, &dhe_named_group, sizeof(dhe_named_group));
   libspdm_set_data (spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter, &aead_cipher_suite, sizeof(aead_cipher_suite));
   libspdm_set_data (spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter, &req_base_asym_alg, sizeof(req_base_asym_alg));
   libspdm_set_data (spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &key_schedule, sizeof(key_schedule));
   ```

   1.4, deploy slot number, public certificate chain.
   ```
   parameter.additional_data[0] = slot_id;
   libspdm_set_data (spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter, my_public_cert_chains, my_public_cert_chains_size);
   ```

   1.5, if mutual authentication (Requester verification) through certificates is required, provide a buffer to store the Requester's certificate chain and deploy the peer public root certificate based upon need.
   ```
   libspdm_register_cert_chain_buffer(spdm_context, cert_chain_buffer, cert_chain_buffer_max_size);

   parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
   libspdm_set_data (spdm_context, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT, &parameter, peer_root_cert, peer_root_cert_size);
   ```
   The maximum size of an SPDM certificate chain is SPDM_MAX_CERTIFICATE_CHAIN_SIZE, which is approximately 64 KiB. However most certificate chains are smaller than that.

   If there are many peer root certs to set, you can set the peer root certs in order. Note: the max number of peer root certs is LIBSPDM_MAX_ROOT_CERT_SUPPORT.
   ```
   parameter.location = SPDM_DATA_LOCATION_LOCAL;
   libspdm_set_data (spdm_context, SPDM_DATA_PEER_PUBLIC_ROOT_CERT, &parameter, peer_root_cert1, peer_root_cert_size1);
   libspdm_set_data (spdm_context, SPDM_DATA_PEER_PUBLIC_ROOT_CERT, &parameter, peer_root_cert2, peer_root_cert_size2);
   libspdm_set_data (spdm_context, SPDM_DATA_PEER_PUBLIC_ROOT_CERT, &parameter, peer_root_cert3, peer_root_cert_size3);
   ```

   If Requester's raw public key is needed for mutual authentication, deploy the public key.
   The public key is ASN.1 DER-encoded as [RFC7250](https://www.rfc-editor.org/rfc/rfc7250) describes,
   namely, the `SubjectPublicKeyInfo` structure of a X.509 certificate.
   ```
   parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
   libspdm_set_data (spdm_context, LIBSPDM_DATA_PEER_PUBLIC_KEY, &parameter, peer_public_key, peer_public_key_size);
   libspdm_set_data (spdm_context, LIBSPDM_DATA_LOCAL_PUBLIC_KEY, &parameter, local_public_key, local_public_key_size);
   ```

   1.7, if PSK is required, optionally deploy PSK Hint in the call to libspdm_start_session().

2. Dispatch SPDM messages.

   ```
   while (true) {
     status = libspdm_responder_dispatch_message (m_spdm_context);
     if (status != RETURN_UNSUPPORTED) {
       continue;
     }
     // handle non SPDM message
     ......
   }
   ```

3. Register message process callback

   3.1 This callback handles transport layer application message.
    ```
    return_status libspdm_get_response (
      void           *spdm_context,
      const uint32_t *session_id,
      bool            is_app_message,
      size_t          request_size,
      const void     *request,
      size_t         *response_size,
      void           *response
    )
    {
      if (is_app_message) {
        // this is a transport layer application message
      } else {
        // other SPDM message
      }
    }

    libspdm_register_get_response_func (spdm_context, libspdm_get_response);
    ```
    3.2 This callbacks handle SPDM Vendor Defined Commands
    ```
    libspdm_return_t libspdm_vendor_get_id_func(
      void *spdm_context,
      uint16_t *resp_standard_id,
      uint8_t *resp_vendor_id_len,
      void *resp_vendor_id)
    {
      // return responder vendor id
      ...

      return LIBSPDM_STATUS_SUCCESS;
    }

    vendor_response_get_id
    libspdm_return_t libspdm_vendor_response_func(
      void *spdm_context,
      uint16_t req_standard_id,
      uint8_t req_vendor_id_len,
      const void *req_vendor_id,
      uint16_t req_size,
      const void *req_data,
      uint16_t *resp_size,
      void *resp_data)
      {
      // process request and create response
      ...
      // populate response header and payload
      ...

      return LIBSPDM_STATUS_SUCCESS;
    }

    libspdm_register_vendor_get_id_callback_func(spdm_context, libspdm_vendor_get_id_func);
    libspdm_register_vendor_callback_func(spdm_context, libspdm_vendor_response_func);
    ```

4. Free the memory of contexts within the SPDM context when all flow is over.
   This function doesn't free the SPDM context itself.
   ```
   libspdm_deinit_context(spdm_context);
   ```

## Message Logging
libspdm allows an Integrator to log request and response messages to an Integrator-provided buffer.
Message logging enables independent verification of message transcripts by a Verifier entity,
and also aids in debugging. Message logging is enabled at compile time by setting the
`LIBSPDM_ENABLE_MSG_LOG` macro to a value of `1`. Message logging is enabled at run time through the
`libspdm_set_msg_log_mode` function, and its status is checked with the `libspdm_get_msg_log_status`
function. When enabled both request messages and response messages are written to the buffer.
Writing to the message log buffer may fill the buffer after which subsequent writes to the
buffer will be ignored. Once the desired messages have been captured in the message log buffer the
`libspdm_get_msg_log_size` returns the size, in bytes, of all the concatenated messages.
```
libspdm_init_msg_log (spdm_context, msg_log_buffer, sizeof(msg_log_buffer));
libspdm_set_msg_log_mode (spdm_context, LIBSPDM_MSG_LOG_MODE_ENABLE);

/* Send requests and receive responses that will be logged to the buffer. */

buffer_size = libspdm_get_msg_log_size (spdm_context);

/* Send msg_log_buffer and buffer_size to the Verifier for independent verification. */
```
Currently message logging is only supported within a Requester, and only for the `GET_VERSION`,
`GET_CAPABILITIES`, `NEGOTIATE_ALGORITHMS`, and `GET_MEASUREMENTS` requests and their associated
responses. More messages will be added in a subsequent release. Message logging can also be added to
the Responder if there is interest.
