# libspdm Secured Message API (DRAFT)

## Introduction
This document details the public API available to Integrators when working with SPDM secured
messages. Once a session has been established the `spdm_secured_message_context` can be retrieved
through the `libspdm_get_secured_message_context_via_session_id()` function.

## SPDM Secured Messages

---
### libspdm_secured_message_get_context_size
---

### Description
Returns the size, in bytes, of a a single secured message context.

### Details
A secured message context contains sensitive cryptographic material such as secret keys.
<br/><br/>


---
### libspdm_secured_message_get_session_state
---

### Description
Returns the session state that is tracked through a secured message context.

### Parameters

**spdm_secured_message_context**<br/>
The secured message context.

### Return Value
Its value is one of
- `LIBSPDM_SESSION_STATE_NOT_STARTED`
    - Either the secured message context has not been used to establish a session or a session has
      ended.
- `LIBSPDM_SESSION_STATE_HANDSHAKING`
    - The initial session has been established and is in the handshaking phase where a Responder may
      authenticate a Requester.
- `LIBSPDM_SESSION_STATE_ESTABLISHED`
    - The session has been established and the Requester and Responder are communicating securely
      within the session.

### Details
TBD<br/><br/>


---
### libspdm_secured_message_export_master_secret
---

### Description
Copies the Export Master Secret from the secured message context to a buffer.

### Parameters

**spdm_secured_message_context**<br/>
The secured message context.

**export_master_secret**<br/>
A pointer to a buffer to store the Export Master Secret.

**export_master_secret_size**<br/>
On input, the size, in bytes, of the destination buffer.
On output, the lesser of either the size of the destination buffer or the size of the Export Master
secret.

### Return Value
- `true`
    - The operation was successful.
- `false`
    - The operation was not successful.

### Details
The size of the Export Master Secret is the size of the digest of the negotiated hash algorithm.
If the size of the destination buffer is less than the size of the Export Master Secret then the
first `export_master_secret_size` bytes are copied.<br/><br/>


---
### libspdm_secured_message_clear_export_master_secret
---

### Description
Erases the Export Master Secret from a secured message context.

### Parameters

**spdm_secured_message_context**<br/>
The secured message context.

### Details
This is typically called after `libspdm_secured_message_export_master_secret`.
<br/><br/>


---
### libspdm_secured_message_export_session_keys
---

### Description
Copies session keys, salts, and sequence numbers to a buffer.

### Parameters

**spdm_secured_message_context**<br/>
The secured message context.

**session_keys**<br/>
A pointer to a buffer to store the session keys, salts, and sequence numbers.

**session_keys_size**<br/>
Returns the size, in bytes, of the session keys, salts, and sequence numbers copied to the
destination buffer.

### Return Value
- `true`
    - The operation was successful.
- `false`
    - The operation was not successful.

### Details
This function should only be called after the session has been fully established and
`libspdm_secured_message_get_session_state()` returns `LIBSPDM_SESSION_STATE_ESTABLISHED`.

The structure is packed and is layed out as
- Struct Version (4 bytes)
- AEAD Key Size (4 bytes)
- AEAD IV Size (4 bytes)
- Requester Direction Encryption Key (AEAD Key Size bytes)
- Requester Direction Salt (AEAD IV Size bytes)
- Requester Direction Sequence Number (8 bytes)
- Responder Direction Encryption Key (AEAD Key Size bytes)
- Responder Direction Salt (AEAD IV Size bytes)
- Responder Direction Sequence Number (8 bytes)
<br/><br/>


---
### libspdm_encode_secured_message
---

### Description
Encodes a message into a secured message.

### Parameters

**spdm_secured_message_context**<br/>
The secured message context.

**session_id**<br/>
The session ID that is bound to the secured message context.

**is_requester**<br/>
- `true`
    - The function is called by a Requester endpoint.
- `false`
    - The function is called by a Responder endpoint.

**app_message_size**<br/>
The size, in bytes, of the message to be encoded.

**app_message**<br/>
A pointer to a buffer, whose size is `app_message_size`, that stores the message to be encoded.

**secured_message_size**<br/>
On input, indicates the size, in bytes, of the destination buffer to store the encoded message.
On output, indicates the size, in bytes, of the encoded message.

**secured_message**<br/>
A pointer to a buffer to store the encoded message.

**spdm_secured_message_callbacks**<br/>
A pointer to a secured message callback functions structure.

### Details
TBD<br/><br/>


---
### libspdm_decode_secured_message
---

### Description
Decodes a secured message.

### Parameters

**spdm_secured_message_context**<br/>
The secured message context.

**session_id**<br/>
The session ID that is bound to the secured message context.

**is_requester**<br/>
- `true`
    - The function is called by a Requester endpoint.
- `false`
    - The function is called by a Responder endpoint.

**secured_message_size**<br/>
The size, in bytes, of the message to be decoded.

**secured_message**<br/>
A pointer to a buffer that stores the message to be decoded.

**app_message_size**<br/>
On input, indicates the size, in bytes, of the destination buffer to store the decoded message.
On output, indicates the size, in bytes, of the decoded message.

### Details
TBD<br/><br/>