# AEAD limit

## Documents

[RFC 5116](https://www.rfc-editor.org/rfc/rfc5116) defines AEAD algorithms.
[IETF AEAD Limits (Draft)](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aead-limits)
describes how to limit the use of keys in order to bound the advantage given to an attacker.

NOTE: This is irrelevant to the plaintext bit length limitation (2^39 - 256), which is already
defined in [AES-GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final) 5.2.1.1.

## Sequence number based limitation

[DSP0277](https://www.dmtf.org/dsp/DSP0277) defines a 64-bit sequence number. The default value is
the maximum 64-bit value: 0xFFFFFFFFFFFFFFFF.

The Integrator can set `LIBSPDM_DATA_MAX_SPDM_SESSION_SEQUENCE_NUMBER` to override the default
value, such as 0xFFFFFFFF (32-bit) or 0xFFFFFF (24-bit).

The Integrator may query `LIBSPDM_DATA_SESSION_SEQUENCE_NUMBER_REQ_DIR` and
`LIBSPDM_DATA_SESSION_SEQUENCE_NUMBER_RSP_DIR` to get the current number of messages that have been
encrypted / decrypted in the request and response directions, and trigger may trigger a `KEY_UPDATE`
accordingly.

If `KEY_UPDATE` is not sent before the maximum sequence number is reached, the SPDM session will be
terminated.
