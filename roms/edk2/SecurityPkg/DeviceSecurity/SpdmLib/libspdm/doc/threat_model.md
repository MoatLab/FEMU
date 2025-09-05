# libspdm threat model.

## Trust Domain

### Level 1 - Persistent Secret Handling

  (req)asymsignlib / psklib. (Device Specific)a

  It can access the device private key and sign the message.
  It can access the PSK and HMAC the message.

  API: Sign the data with private key. HMAC the data with PSK.

  External Input: None.

  Internal Input: Data to be signed. Data to be HMACed.

  Threat: Information disclosure, Elevation of privilege, Tampering with data.

### Level 2 - Ephemeral Secret Handling

  spdm_secured_message_lib. (Crypto engine Specific or Common)

  It can generate DH secret and derive the session key. (The keys can be imported and exported as an option.)
  It can handle key update.
  It can encrypt and decrypt the message.

  API: Generate DH secret. Manage the SPDM session. Encrypt and decrypt the SPDM secured message.

  External Input: Cipher message to be decrypted. (Malicious)

  Internal Input: Plain message to be encrypted. Internal SPDM session context.

  Threat: Information disclosure, Elevation of privilege, Tampering with data, Denial of service.

### Level 3 - SPDM message process

  spdm_common_lib / spdm_requester_lib / spdm_responder_lib (Common)

  It can build an SPDM message or process an SPDM messages.

  API: Build SPDM messages. Process SPDM messages.

  External Input: Received SPDM message. (Malicious)

  Internal Input: SPDM message to be sent. Internal SPDM context.

  Threat: Tampering with data, Denial of service.

### Level 4 - Transport Layer message process

  SpdmTransportXXXLib (XXX = Mctp, PciDoe) (Transport Layer Specific)

  It can build an SPDM transport layer message or process an SPDM transport layer messages.

  API: Build SPDM transport layer messages. Process SPDM transport layer messages.

  External Input: Received SPDM transport layer message. (Malicious)

  Internal Input: SPDM transport layer message to be sent. 

  Threat: Tampering with data, Denial of service.

### Level 5 - Device Input/Output

  SPDM_DEVICE_SEND / RECEIVE_MESSAGE_FUNC (Device Specific)

  It can send SPDM messages to the device or receive SPDM messages from the device.

  API: Send SPDM messages to the device. Receive SPDM messages from the device.

  External Input: Hardware Device IO. (Malicious)

  Internal Input: None.

  Threat: Denial of service.


