# Cryptography Endianness

## Endianness of digital signatures

SPDM 1.2 and later define the endianness of digital signatures for RSA, ECDSA, SM2_DSA, and EdDSA.
* RSA: big endian for s.
* ECDSA and SMD2_DSA: big endian for r and s.
* EdDSA: big endian for R and little endian for S.

When the negotiated SPDM version is 1.2 or later libspdm follows these definitions.

SPDM 1.0 and 1.1 did not specify the endianness of the RSA and ECDSA digital signatures. libspdm
allows an Integrator to specify the endianness when verifying RSA and ECDSA signatures through
`LIBSPDM_DATA_SPDM_VERSION_10_11_VERIFY_SIGNATURE_ENDIAN` when the negotiated SPDM version is 1.0 or
1.1. The default value is `LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_ONLY`.
Please refer to [common_api](https://github.com/DMTF/libspdm/blob/main/doc/api/common_api.md).

## Endianness of key exchange data

SPDM 1.1 and later defines the endianness of key exchange data for FFDHE, ECDHE, and SM2_KeyExchange.
* FFDHE: big endian for Y.
* ECDHE and SM2_KeyExchange: big endian for X and Y.

libspdm follows that for SPDM 1.1+. Because the definition aligns with existing crypto library such as openssl and mbedtls, no swap is required.

## Endianness of AEAD IV

Versions 1.0 and 1.1 of the Secured Messages using SPDM specification do not explicitly specify how
the AEAD IV is formed. In particular the endianness of the sequence number is either missing (1.0)
or ill-defined (1.1). libspdm allows an Integrator to specify the endianness encoding of the
sequence number through `LIBSPDM_DATA_SEQUENCE_NUMBER_ENDIAN` when the negotiated Secured SPDM
version is 1.0 or 1.1. The default value is `LIBSPDM_DATA_SESSION_SEQ_NUM_ENC_LITTLE_DEC_LITTLE`.
Please refer to [common_api](https://github.com/DMTF/libspdm/blob/main/doc/api/common_api.md).
