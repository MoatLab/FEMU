# libspdm Requester API (DRAFT)

## Introduction
This document details the public API available to Integrators when constructing an SPDM Requester
using libspdm.

## SPDM Messages

---
### libspdm_init_connection
---

### Description
Sends the `GET_VERSION`, `GET_CAPABILITIES`, and `NEGOTIATE_ALGORITHM` to start a connection with
an SPDM Responder.

### Parameters

**spdm_context**<br/>
The SPDM context.

**get_version_only**<br/>
If `true` then only `GET_VERSION` is sent. If `false` then all three messages are sent.

### Details
Before calling this function the Integrator should have initialized the SPDM context and populated
it with configuration parameters, such as the Requester's capabilities and supported cryptography
algorithms. When this function returns with value `LIBSPDM_STATUS_SUCCESS` then the SPDM context can
be queried to determine the capabilities and algorithms supported by the Responder. If this function
returns early with value not equal to `LIBSPDM_STATUS_SUCCESS` then the SPDM context should be reset
before attempting establish a new connection.
<br/><br/>


---
### libspdm_get_digest
---

### Description
Sends `GET_DIGEST` to determine which certificate chain slots are populated and to retrieve the
digest of each populated slot.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
Indicates if it is a secured message (non-NULL) or an unsecured message (NULL).

**slot_mask**<br/>
If non-NULL, a bitmask that indicates if a certificate chain slot is populated, where the least
significant bit corresponds to slot 0 and the most significant bit corresponds to slot 7.

**total_digest_buffer**<br/>
If non-NULL, a pointer to a buffer to store the digests.

### Details
Before calling this function the Requester should have established a connection with the Responder
through the `libspdm_init_connection` function.
<br/><br/>


---
### libspdm_get_certificate
---

### Description
Sends `GET_CERTIFICATE` and retrieves a certificate chain from the specified certificate chain slot.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
Indicates if it is a secured message (non-NULL) or an unsecured message (NULL).

**slot_id**<br/>
The certificate chain slot number.

**cert_chain_size**<br/>
On input, indicates the size, in bytes, of the buffer in which the certificate chain will be stored.
The maximum size of an SPDM certificate chain is given by `SPDM_MAX_CERTIFICATE_CHAIN_SIZE` and is
65535 bytes.
On output, indicates the size, in bytes, of the certificate chain.

**cert_chain**<br/>
A pointer to a buffer of size `cert_chain_size` in which the certificate chain will be stored.

### Details
Before calling this function the Integrator should have determined which certificate chain slots are
populated through `libspdm_get_digest`, although that is not strictly required. Once the certificate
chain has been retrieved libspdm will validate the chain and its leaf certificate. In particular
libspdm will perform the following checks over the leaf certificate.
- Check that the x.509 version is 3 (encoded as 2).
- Check that the `CertificateSerialNumber`, `subject`, `Issuer` fields exist.
- Verify that the asymmetric key algorithm matches the negotiated asymmetric key algorithm of the
  connection.
- Check that the `KeyUsage` field exists and that it supports `digitalSignature`.
- If the `BasicConstraints` field exists then verify that the `cA` is false.
<br/><br/>

---
### libspdm_challenge
---

### Description
Sends `CHALLENGE` and verifies the signature in the `CHALLENGE_AUTH` response.

### Parameters

**spdm_context**<br/>
The SPDM context.

**reserved**<br/>
Reserved for a session id in the case that SPDM supports this message inside a session.

**slot_id**<br/>
The certificate chain slot number.

**measurement_hash_type**<br/>
Specifies the type of measurement summary hash to be returned by the Responder. Its value is one of
- `SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH`
    - No measurement summary hash. This value must be selected if the Responder does not support
      measurements.
- `SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH`
    - TCB measurements only.
- `SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH`
    - All measurements.

**measurement_hash**<br/>
If non-NULL, a pointer to a buffer to store the measurement summary hash. The size of the buffer
should be at least as large as the negotiated hash algorithm.

**slot_mask**<br/>
A bitmask that indicates if a certificate chain slot is populated, where the least
significant bit corresponds to slot 0 and the most significant bit corresponds to slot 7. If the
pointer provided is NULL then this parameter is not populated.

### Details
This function is used to authenticate the Responder and to verify that the messages sent from and
received by the Requester are the same as the messages received by and sent from the Responder.
These messages form a transcript that includes
- The `GET_VERSION`, `VERSION`, `GET_CAPABILITIES`, `CAPABILITIES`, `NEGOTIATE_ALGORITHMS`, and
  `ALGORITHMS` messages that were exchanged through `libspdm_init_connection`.
- If issued, the `GET_DIGESTS`, `DIGESTS`, `GET_CERTIFICATE`, and `CERTIFICATE` messages
- The `CHALLENGE` and `CHALLENGE_AUTH` messages.

libspdm verifies that the signature provided by the Responder matches the signature over the message
transcript.


---
### libspdm_get_measurement
---

### Description
Sends `GET_MEASUREMENTS` to retrieve measurement values from the Responder. If requested, libspdm
will also verify the signature over the measurements.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
Indicates if it is a secured message (non-NULL) or an unsecured message (NULL).

**request_attribute**<br/>
Specifies directives to the Responder. It is a bitmask and its value can contain any combination of
- `SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE`
    - If set then Responder will provide a signature.
- `SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED`
    - If set then, when possible, the Responder will provide measurements as raw bit streams instead
      of hashes.
    - Only supported in SPDM version 1.2 and later.

**measurement_operation**<br/>
Specifies the measurement operation to be performed by the Responder. Its value is one of
- `SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS`
    - Returns the total number of measurement blocks available through the `number_of_blocks`
      parameter.
- `SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS`
    - Returns measurements for all measurement blocks.
- A value between `1` and `254` inclusive that specifies the measurement for an individual block
  index.

**slot_id**<br/>
The certificate chain slot number. This parameter is only used if
`SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE` is set in `request_attribute`.

**content_changed** (SPDM 1.2 and later)<br/>
When `SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE` in `request_attribute` is set,
this indicates whether measurements have changed for those `GET_MEASUREMENTS` requests where
`SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE` was cleared. Its value can be one of
- `SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_NO_DETECTION`
    - Either the Responder cannot detect changes in measurements between requests, or
      `SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE` was cleared.
- `SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_DETECTED`
    - The Responder detected changes in measurements between requests.
- `SPDM_MEASUREMENTS_RESPONSE_CONTENT_NO_CHANGE_DETECTED`
    - The Responder did not detect a change in measurements between requests.

**number_of_blocks**<br/>
If `measurement_operation` equals
`SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS` then this value
is the total number of measurements blocks available. If `measurement_operation` equals
`SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS` then this value is the total
number of measurement blocks in the `measurement_record` buffer. For any other value of
`measurement_operation` this value is equal to `1`.

**measurement_record_length**<br/>
On input, specifies the size, in bytes, of the buffer to hold the measurement record. On output,
this value gives the size, in bytes, of the measurement record stored in the `measurement_record`
buffer. If the measurement record returned by the Responder is too large for the buffer then this
function will return an error.

**measurement_record**<br/>
A buffer to store the measurement record returned by the Responder.

### Details
TBD


---
### libspdm_start_session
---

### Description
Sends either `KEY_EXCHANGE` or `PSK_EXCHANGE` to establish a secure session with the Responder. If
the Requester supports mutual authentication then this function will also perform that if requested
by the Responder.

### Parameters

**spdm_context**<br/>
The SPDM context.

**use_psk**<br/>
If `true` then `PSK_EXCHANGE` will be sent. If `false` then `KEY_EXCHANGE` will be sent.

**measurement_hash_type**<br/>
Specifies the type of measurement summary hash to be returned by the Responder. Its value is one of
- `SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH`
    - No measurement summary hash. This value must be selected if the Responder does not support
      measurements.
- `SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH`
    - TCB measurements only.
- `SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH`
    - All measurements.

**slot_id**<br/>
The certificate chain slot number.

**session_policy**<br/>
Specifies the session policy for the session. It is a bitmask and its value can contain
- SPDM_KEY_EXCHANGE_REQUEST_SESSION_POLICY_TERMINATION_POLICY_RUNTIME_UPDATE
    - If not set then, if the Responder detects a change in its code or configuration (or other
      measurements), then it will terminate the session. If set then, if the Responder detects a
      change in its code or configuration (or other measurements), it will use its policy to
      determine if the session is terminated.
    - Only supported in SPDM version 1.2 and later.

**session_id**<br/>
Once a session has been established the value of this parameter is used to identify the session in
subsequent messages. For example `libspdm_get_measurement` takes `session_id` as an input.

**heartbeat_period** (SPDM 1.2 and later)<br/>
For a Responder that supports the heartbeat capability the value of this parameter specifies the
amount of time the Requester has to send an in-session message before the Responder terminates the
session. It is in units of seconds and the timeout value is `2 * heartbeat_period`.

**measurement_hash**<br/>
If non-NULL, a pointer to a buffer to store the measurement summary hash. The size of the buffer
should be at least as large as the negotiated hash algorithm.

### Details
TBD


---
### libspdm_heartbeat
---

### Description
Sends `HEARTBEAT` to keep a session alive.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
The session to be kept alive.

### Details
TBD


---
### libspdm_key_update
---

### Description
Sends `KEY_UPDATE` to update and verify secrets for an SPDM session.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
The session whose secrets will be updated.

**single_direction**<br/>
If `true` then only the Responder direction secrets will updated. If `false` then both Responder
direction and Requester direction secrets will be updated.

### Details
Before calling this function a secure session must first be established via `libspdm_start_session`.


---
### libspdm_stop_session
---

### Description
Sends `END_SESSION` to terminate a session.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
The session to be terminated.

**end_session_attributes**<br/>
Specifies actions to be performed by the Responder at the end of the session. It is a bitmask and
its value can contain
- `SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE_CLEAR`
    - Only used if the Responder supports caching its negotiated state.
    - If set then Responder will clear its negotiated state.
    - If not set then Responder's negotiated state is preserved.

### Details
TBD
<br/><br/>

---
### libspdm_get_csr
---

### Description
Sends `GET_CSR` to retrieve a Certificate Signing Request (CSR) from the Responder.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
Indicates if it is a secured message (non-NULL) or an unsecured message (NULL).

**requester_info**<br/>
Data that conforms to the `CertificationRequestInfo` format specified in RFC2986.

**requester_info_length**<br/>
The size, in bytes, of the `requester_info` buffer.

**opaque_data**<br/>
A pointer to a buffer that contains any opaque data to be sent to the Responder.

**opaque_data_length**<br/>
The size, in bytes, of the `opaque_data` buffer.

**csr**<br/>
A pointer to a buffer to store the CSR from the Responder.

**csr_len**<br/>
On input, indicates the size, in bytes, of the buffer in which the CSR will be stored.
On output, indicates the size, in bytes, of the CSR.

### Details
TBD
<br/><br/>


---
### libspdm_set_certificate
---

### Description
Sends `SET_CERTIFICATE` to deposit a certificate chain into a Responder.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
Indicates if it is a secured message (non-NULL) or an unsecured message (NULL).

**slot_id**<br/>
The certificate chain slot number.

**cert_chain**<br/>
A pointer to a buffer that contains the certificate chain.

**cert_chain_size**<br/>
The size, in bytes, of the `cert_chain` buffer.

### Details
TBD
<br/><br/>


---
### libspdm_get_event_types
---

### Description
Sends `GET_SUPPORTED_EVENT_TYPES` to retrieve the event types supported by the Responder.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
The session through which the event types will be retrieved.

**event_group_count**<br/>
The number of event groups in `supported_event_groups_list`.

**supported_event_groups_list_len**<br/>
On input, indicates the size, in bytes, of the buffer in which the event groups list will be stored.
On output, indicates the size, in bytes, of the event groups list.

**supported_event_groups_list**<br/>
A pointer to a buffer to store the supported event groups list.

### Details
Before calling this function a secure session must first be established via `libspdm_start_session`.
<br/><br/>


## Message Logging
libspdm allows an Integrator to log request and response messages to an Integrator-provided buffer.
It is currently only supported by a Requester. In the future it may be supported by a Responder, in
which case these functions will move to the common library.
<br/><br/>

---
### libspdm_init_msg_log
---

### Description
Initializes message logging.

### Parameters

**spdm_context**<br/>
The SPDM context.

**msg_buffer**<br/>
A pointer to a buffer to store the messages.

**msg_buffer_size**<br/>
The size, in bytes, of the `msg_buffer` buffer.

### Details
TBD
<br/><br/>


---
### libspdm_set_msg_log_mode
---

### Description
Sets the mode in which message logging operates.

### Parameters

**spdm_context**<br/>
The SPDM context.

**mode**<br/>
Sets the mode in which the message logger operates. It is a bitmask and its value can contain
- `LIBSPDM_MSG_LOG_MODE_ENABLE`
    - If set then message logger is enabled.
    - If not set then message logger is disabled.

### Details
TBD
<br/><br/>


---
### libspdm_get_msg_log_status
---

### Description
Returns the status of the message logger.

### Parameters

**spdm_context**<br/>
The SPDM context.

### Details
TBD
<br/><br/>


---
### libspdm_get_msg_log_size
---

### Description
Returns the size of the message log.

### Parameters

**spdm_context**<br/>
The SPDM context.

### Details
TBD
<br/><br/>


---
### libspdm_reset_msg_log
---

### Description
Resets the state of the message log.

### Parameters

**spdm_context**<br/>
The SPDM context.

### Details
TBD
<br/><br/>
