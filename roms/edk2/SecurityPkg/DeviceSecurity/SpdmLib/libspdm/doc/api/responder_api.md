# libspdm Responder API (DRAFT)

## Introduction
This document details the public API available to Integrators when constructing an SPDM Responder
using libspdm.

## SPDM Messages

---
### libspdm_responder_dispatch_message
---

### Description
Waits for a request message from the Requester. Once a message is received it processes the request,
forms a response message, and sends the response to the Requester.

### Parameters

**spdm_context**<br/>
The SPDM context.

### Details
Before calling this function the Integrator should have initialized the SPDM context and populated
it with configuration parameters, such as the Responder's capabilities and supported cryptography
algorithms.
<br/><br/>

---
### libspdm_get_response_func
---

### Description
Is called if libspdm receives an application (non-SPDM) message.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
Indicates if it is a secured message (non-NULL) or an unsecured message (NULL).

**is_app_message**<br/>
Indicates if the message is an application (non-SPDM) or SPDM message.

**request_size**<br/>
The size, in bytes, of the request message.

**request**<br/>
A pointer to a buffer that stores the request message.

**response_size**<br/>
On input, indicates the size, in bytes, of the buffer in which the response message will be stored.
On output, indicates the size, in bytes, of the response message.

**response**<br/>
A pointer to a buffer that will store the response message.

### Details
TBD
<br/><br/>


---
### libspdm_register_get_response_func
---

### Description
Registers the location of the `libspdm_get_response_func` function into the context.

### Parameters

**spdm_context**<br/>
The SPDM context.

**get_response_func**<br/>
A function pointer to the `libspdm_get_response_func` function.

### Details
TBD
<br/><br/>


---
### libspdm_generate_error_response
---

### Description
Generates an `ERROR` response message from the provided error code and error data.

### Parameters

**spdm_context**<br/>
The SPDM context.

**error_code**<br/>
The error code that will be used in `Param1` of the `ERROR` response message. This parameter is not
validated.

**error_data**<br/>
The error data that will be used in `Param2` of the `ERROR` response message. This parameter is not
validated.

**spdm_response_size**<br/>
On input, indicates the size, in bytes, of the buffer in which the response message will be stored.
On output, indicates the size, in bytes, of the response message.

**spdm_response**<br/>
A pointer to a buffer that will store the response message.

### Details
TBD
<br/><br/>


---
### libspdm_generate_extended_error_response
---

### Description
Generates an `ERROR` response message from the provided error code, error data, and extended error
data.

### Parameters

**spdm_context**<br/>
The SPDM context.

**error_code**<br/>
The error code that will be used in `Param1` of the `ERROR` response message. This parameter is not
validated.

**error_data**<br/>
The error data that will be used in `Param2` of the `ERROR` response message. This parameter is not
validated.

**extended_error_data_size**<br/>
The size, in bytes, of the `extended_error_data` buffer.

**extended_error_data**<br/>
The extended error data that will be used in `ExtendedErrorData` of the `ERROR` response message.
This parameter is not validated.

**spdm_response_size**<br/>
On input, indicates the size, in bytes, of the buffer in which the response message will be stored.
On output, indicates the size, in bytes, of the response message.

**spdm_response**<br/>
A pointer to a buffer that will store the response message.

### Details
TBD
<br/><br/>


---
### libspdm_session_state_callback_func
---

### Description
Is called whenever, for a given session ID, a session changes state.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
The session whose state has changed.

**session_state**<br/>
Specifies the state the session has transitioned to. Its value is one of
- LIBSPDM_SESSION_STATE_NOT_STARTED
    - The initial state.
- LIBSPDM_SESSION_STATE_HANDSHAKING
    - The Requester and Responder have started the handshake phase of session establishment.
- LIBSPDM_SESSION_STATE_ESTABLISHED
    - The Requester and Responder have established a session.

### Details
TBD
<br/><br/>


---
### libspdm_register_session_state_callback_func
---

### Description
Registers the location of the `libspdm_session_state_callback_func` function into the context.

### Parameters

**spdm_context**<br/>
The SPDM context.

**spdm_session_state_callback**<br/>
A function pointer to the `libspdm_session_state_callback_func` function.

### Details
TBD
<br/><br/>


---
### libspdm_connection_state_callback_func
---

### Description
Is called whenever a connection changes state.

### Parameters

**spdm_context**<br/>
The SPDM context.

**connection_state**<br/>
Specifies the state the connection has transitioned to. Its value is one of
- `LIBSPDM_CONNECTION_STATE_NOT_STARTED`
    - The initial state after the SPDM context has been initialized or reset.
- `LIBSPDM_CONNECTION_STATE_AFTER_VERSION`
    - The state immediately after a successful `GET_VERSION` request and `VERSION` response.
- `LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES`
    - The state immediately after a successful `GET_CAPABILITIES` request and `CAPABILITIES`
      response.
- `LIBSPDM_CONNECTION_STATE_NEGOTIATED`
    - The state immediately after a successful `NEGOTIATE_ALGORITHMS` request and `ALGORITHMS`
      response.
- `LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS`
    - The state immediately after a successful `GET_DIGESTS` request and `DIGESTS` response.
- `LIBSPDM_CONNECTION_STATE_AFTER_CERTIFICATE`
    - The state immediately after a successful `GET_CERTIFICATE` request and `CERTIFICATE` response.
- `LIBSPDM_CONNECTION_STATE_AUTHENTICATED`
    - The state immediately after a successful `CHALLENGE` request and `CHALLENGE_AUTH` response.

### Details
TBD
<br/><br/>


---
### libspdm_register_connection_state_callback_func
---

### Description
Registers the location of the `libspdm_connection_state_callback_func` function into the context.

### Parameters

**spdm_context**<br/>
The SPDM context.

**spdm_connection_state_callback**<br/>
A function pointer to the `libspdm_connection_state_callback_func` function.

### Details
TBD
<br/><br/>


---
### libspdm_key_update_callback_func
---

### Description
Is called whenever, for a given session ID, a session's secret is updated.

### Parameters

**spdm_context**<br/>
The SPDM context.

**session_id**<br/>
The session whose secret has changed.

**key_update_op**<br/>
Specifies the key exchange or update operation that caused the secret to change value. Its value is
one of
- LIBSPDM_KEY_UPDATE_OPERATION_CREATE_UPDATE
- LIBSPDM_KEY_UPDATE_OPERATION_COMMIT_UPDATE
- LIBSPDM_KEY_UPDATE_OPERATION_DISCARD_UPDATE

### Details
TBD
<br/><br/>


---
### libspdm_register_key_update_callback_func
---

### Description
Registers the location of the `libspdm_key_update_callback_func` function into the context.

### Parameters

**spdm_context**<br/>
The SPDM context.

**spdm_key_update_callback**<br/>
A function pointer to the `libspdm_key_update_callback_func` function.

### Details
TBD
<br/><br/>