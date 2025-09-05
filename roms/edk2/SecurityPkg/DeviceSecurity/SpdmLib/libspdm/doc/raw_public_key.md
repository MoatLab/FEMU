# Raw Public Key

## Specification

A libspdm raw public key follows the format as defined by
[RFC 7250](https://www.rfc-editor.org/rfc/rfc7250).

## Cryptography Library

libspdm calls the cryptography library directly to parse the raw public key.
- For OpenSSL, libspdm calls `d2i_RSA_PUBKEY_bio` for RSA, `d2i_EC_PUBKEY_bio` for ECDSA, and
  `d2i_PUBKEY_bio` for EdDSA and SM2DSA.
- For MbedTLS, libspdm calls `mbedtls_pk_parse_public_key` for RSA and ECDSA. EdDSA and SM2DSA are
  not supported.

## Generation

OpenSSL can be used to generate the DER-based raw public key.
```
openssl pkey -in end_point.key.priv.pem -inform PEM -pubout -outform DER -out end_point.key.pub.der
```

## Registration

The Integrator can use `LIBSPDM_DATA_PEER_PUBLIC_KEY` and `LIBSPDM_DATA_LOCAL_PUBLIC_KEY` to
register the raw public key.
