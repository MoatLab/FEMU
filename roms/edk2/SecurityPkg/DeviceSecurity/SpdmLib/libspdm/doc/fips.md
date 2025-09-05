# FIPS 140-3 support

libspdm 3.0.0 starts adding [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final) support.

NOTE: The SPDM WG does not plan to obtain FIPS 140-3 [Cryptographic Module Validation Program (CMVP)](https://csrc.nist.gov/Projects/cryptographic-module-validation-program) or [Cryptographic Algorithm Validation Program (CAVP)](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program) certification for libspdm.

libspdm integrator is expected to choose crypto module and support CMVP.

## Design

### Cryptographic Algorithm Self-Test

| SPDM Algorithm      | Specification                             | Type | Test Attributes      |
| ------------------- | ----------------------------------------- | ---- | -------------------- |
| SHA-256/384/512     | [NIST.FIPS.180-4](https://doi.org/10.6028/NIST.FIPS.180-4)   | KAT  | SHA-256/384/512 |
| SHA3-256/384/512    | [NIST.FIPS.202](https://doi.org/10.6028/NIST.FIPS.202)     | KAT  | SHA3-256/384/512 |
| RSA-SSA             | [NIST.FIPS.186-5](https://doi.org/10.6028/NIST.FIPS.186-5), [rfc8017](https://tools.ietf.org/html/rfc8017)   | KAT  | RSA-SSA2048 + SHA256 |
| RSA-PSS             | [NIST.FIPS.186-5](https://doi.org/10.6028/NIST.FIPS.186-5), [rfc8017](https://tools.ietf.org/html/rfc8017)   | KAT  | RSA-PSS2048 + SHA256 |
| ECDSA               | [NIST.FIPS.186-5](https://doi.org/10.6028/NIST.FIPS.186-5), [NIST.SP.800-186](https://doi.org/10.6028/NIST.SP.800-186)  | KAT with fixed random | ECDSA-P256+SHA256    |
| EdDSA               | [NIST.FIPS.186-5](https://doi.org/10.6028/NIST.FIPS.186-5), [NIST.SP.800-186](https://doi.org/10.6028/NIST.SP.800-186), [rfc8032](https://www.rfc-editor.org/rfc/rfc8032)  | KAT  | EdDSA-25519,EdDSA-448 |
| HMAC                | [NIST.FIPS.198-1](https://doi.org/10.6028/NIST.FIPS.198-1), [rfc2104](https://tools.ietf.org/html/rfc2104)   | KAT  | HMAC-SHA-256/384/512 |
| AES-GCM             | [NIST.FIPS.197](https://doi.org/10.6028/NIST.FIPS.197), [NIST.SP.800-38D](https://doi.org/10.6028/NIST.SP.800-38D)   | KAT  | AES-GCM-256          |
| FFDHE               | [NIST.SP.800-56Ar3](https://doi.org/10.6028/NIST.SP.800-56Ar3), [rfc7919](https://www.rfc-editor.org/rfc/rfc7919) | PCT  | FFDHE-2048           |
| ECDHE               | [NIST.SP.800-56Ar3](https://doi.org/10.6028/NIST.SP.800-56Ar3), [rfc8446](https://www.rfc-editor.org/rfc/rfc8446) | KAT  | ECDHE-P256           |
| HKDF                | [NIST.SP.800-56Cr2](https://doi.org/10.6028/NIST.SP.800-56Cr2), [rfc5869](https://tools.ietf.org/html/rfc5869) | KAT  | HKDF-HMAC-SHA-256    |
| ChaCha-Poly (*) | [rfc8439](https://www.rfc-editor.org/rfc/rfc8439) | KAT | not FIPS approved yet |
| SM3 (*) | [GB/T 32905-2016,GM/T 0004-2012](http://www.gmbz.org.cn/upload/2018-07-24/1532401392982079739.pdf), [ISO/IEC 10118-3:2018](https://www.iso.org/standard/67116.html) | KAT | not FIPS approved yet |
| SM4-GCM (*) | [GB/T 32907-2016,GM/T 0002-2012](http://www.gmbz.org.cn/upload/2018-04-04/1522788048733065051.pdf), [ISO/IEC 18033-3:2010/Amd 1:2021](https://www.iso.org/standard/81564.html), [rfc8998](https://tools.ietf.org/html/rfc8998) | KAT | not FIPS approved yet |
| SM2-digital-signature (\*) <br> SM2-key-exchange (\*) | [GB/T 32918.1-2016,GM/T 0003.1-2012](http://www.gmbz.org.cn/upload/2018-07-24/1532401673134070738.pdf), [GB/T 32918.2-2016,GM/T 0003.2-2012](http://www.gmbz.org.cn/upload/2018-07-24/1532401673138056311.pdf), [GB/T 32918.3-2016,GM/T 0003.3-2012](http://www.gmbz.org.cn/upload/2018-07-24/1532401673149005052.pdf), <br> [GB/T 32918.4-2016,GM/T 0003.4-2012](http://www.gmbz.org.cn/upload/2018-07-24/1532401673367034870.pdf), [GB/T 32918.5-2016,GM/T 0003.5-2012](http://www.gmbz.org.cn/upload/2018-07-24/1532401863206085511.pdf), [ISO/IEC 14888-3:2018](https://www.iso.org/standard/76382.html) | KAT | not FIPS approved yet |
| SPDM-Key-Schedule (*) | [DMTF-DSP0274](https://www.dmtf.org/dsp/DSP0274)          | KAT  | not FIPS approved yet |

The test maybe Known Answer Test (KAT) or Pairwise Consistency Test (PCT).

The Test Vector (KAT) can be found at [CAVP-Testing](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Component-Testing) and [Cryptographic Standards and Guidelines](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values).

Reference:
 * [NIST.SP.800-140Cr1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-140Cr1.pdf): CMVP Approved Security Functions
 * [NIST.SP.800-140Dr1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-140Dr1.pdf): CMVP Approved Sensitive Security Parameter Generation and Establishment Methods
 * [FIPS 140-3 Implementation Guide](https://csrc.nist.gov/CSRC/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf)
 * [FIPS 140-Compliant SPDM](https://icmconference.org/wp-content/uploads/C22b-RuanX.pdf), ICMC 2022.

### Software Integrity Self-Test

Not implemented in the libspdm. The integrator may build libspdm as a binary and do self test.

## Implementation

Please refer to [FIPS discussion](https://github.com/DMTF/libspdm/discussions/1406) for detail.

### FIPS configuration

The integrator can define `LIBSPDM_FIPS_MODE=1` according to [spdm_lib_config.h](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_lib_config.h) to enable FIPS mode.

`libspdm_get_fips_mode()` in [spdm_common_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_common_lib.h) can return FIPS mode.

`LIBSPDM_FIPS_MODE` will only allow below algorithms in [spdm_lib_config.h](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_lib_config.h):
 * `LIBSPDM_RSA_SSA_2048_SUPPORT`, `LIBSPDM_RSA_SSA_3072_SUPPORT`, `LIBSPDM_RSA_SSA_4096_SUPPORT`
 * `LIBSPDM_RSA_PSS_2048_SUPPORT`, `LIBSPDM_RSA_PSS_3072_SUPPORT`, `LIBSPDM_RSA_PSS_4096_SUPPORT`
 * `LIBSPDM_ECDSA_P256_SUPPORT`, `LIBSPDM_ECDSA_P384_SUPPORT`, `LIBSPDM_ECDSA_P521_SUPPORT`
 * `LIBSPDM_EDDSA_ED25519_SUPPORT`, `LIBSPDM_EDDSA_ED448_SUPPORT`
 * `LIBSPDM_FFDHE_2048_SUPPORT`, `LIBSPDM_FFDHE_3072_SUPPORT`, `LIBSPDM_FFDHE_4096_SUPPORT`
 * `LIBSPDM_ECDHE_P256_SUPPORT`, `LIBSPDM_ECDHE_P384_SUPPORT`, `LIBSPDM_ECDHE_P521_SUPPORT`
 * `LIBSPDM_AEAD_AES_128_GCM_SUPPORT`, `LIBSPDM_AEAD_AES_256_GCM_SUPPORT`
 * `LIBSPDM_SHA256_SUPPORT`, `LIBSPDM_SHA384_SUPPORT`, `LIBSPDM_SHA512_SUPPORT`
 * `LIBSPDM_SHA3_256_SUPPORT`, `LIBSPDM_SHA3_384_SUPPORT`, `LIBSPDM_SHA3_512_SUPPORT`

Below algorithms will be disabled:
 * `LIBSPDM_SM2_DSA_P256_SUPPORT`
 * `LIBSPDM_SM2_KEY_EXCHANGE_P256_SUPPORT`
 * `LIBSPDM_AEAD_CHACHA20_POLY1305_SUPPORT`
 * `LIBSPDM_AEAD_SM4_128_GCM_SUPPORT`
 * `LIBSPDM_SM3_256_SUPPORT`

### FIPS approved algorithm

If FIPS mode is enabled, then only FIPS-approved algorithms will be enabled, which is listed in [NIST.SP.800-140Cr1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-140Cr1.pdf).

### Key zeroization

If a key is not used, then the variable to hold the key must be explictly zeroized. This is done in the libspdm.

The private key for signing is managed by the [requester-asymsignlib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/requester/reqasymsignlib.h) and [responder-asymlib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/responder/asymsignlib.h). The library provider shall guarantee the key is zeroized after use.

The pre-shared key (PSK) is managed by the [requester-psklib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/requester/psklib.h) and [responder-psklib](https://github.com/DMTF/libspdm/blob/main/include/hal/library/responder/psklib.h). The library provider shall guarantee the key is zeroized after use.

### module version API

`libspdm_module_version()` in [spdm_common_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_common_lib.h) can return libspdm version information.

### self-test API

`libspdm_fips_run_selftest()` in [spdm_crypt_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_crypt_lib.h) can be used to run FIPS selftest, including
 * `libspdm_fips_selftest_hmac_sha256()`
 * `libspdm_fips_selftest_hmac_sha384()`
 * `libspdm_fips_selftest_hmac_sha512()`
 * `libspdm_fips_selftest_aes_gcm()`
 * `libspdm_fips_selftest_rsa_ssa()`
 * `libspdm_fips_selftest_rsa_pss()`
 * `libspdm_fips_selftest_hkdf()`
 * `libspdm_fips_selftest_ecdh()`
 * `libspdm_fips_selftest_sha256()`
 * `libspdm_fips_selftest_sha384()`
 * `libspdm_fips_selftest_sha512()`
 * `libspdm_fips_selftest_sha3_256()`
 * `libspdm_fips_selftest_sha3_384()`
 * `libspdm_fips_selftest_sha3_512()`
 * `libspdm_fips_selftest_ffdh()`
 * `libspdm_fips_selftest_ecdsa()`
 * `libspdm_fips_selftest_eddsa()`

If any test failed, then `libspdm_fips_run_selftest()` will return false.

`libspdm_fips_run_selftest()` requires `fips_selftest_context` parameter, which is initialized by `libspdm_get_fips_selftest_context_size()`, `libspdm_init_fips_selftest_context()` in [spdm_common_lib](https://github.com/DMTF/libspdm/blob/main/include/library/spdm_common_lib.h).

The expected step is as follows:
1) The integrator invokes `libspdm_get_fips_selftest_context_size()` and `libspdm_init_fips_selftest_context()` to create the FIPS selftest context.
2) The integrator invokes `libspdm_fips_run_selftest()` to trigger self-test.
3) If fail, then return.

```
#if LIBSPDM_FIPS_MODE
    m_fips_selftest_context = (void *)malloc(libspdm_get_fips_selftest_context_size());
    if (m_fips_selftest_context == NULL) {
        return NULL;
    }
    fips_selftest_context = m_fips_selftest_context;
    libspdm_init_fips_selftest_context(fips_selftest_context);
    result = libspdm_fips_run_selftest(fips_selftest_context);
    if (!result) {
        return NULL;
    }
#endif
```

NOTE: If a crypto library does not support a FIPS algorithm, then the algorithm must be disabled explictly. Otherwise `libspdm_fips_run_selftest()` will fail. For example, if the integrator links libspdm with mbedtls, then SHA3 and RdDSA related algorithms must be disabled via `LIBSPDM_SHA3_256_SUPPORT=0`, `LIBSPDM_SHA3_384_SUPPORT=0`, `LIBSPDM_SHA3_512_SUPPORT=0`, `LIBSPDM_EDDSA_ED25519_SUPPORT=0`, `LIBSPDM_EDDSA_ED448_SUPPORT=0`, because they are not supported by mbedtls yet.
