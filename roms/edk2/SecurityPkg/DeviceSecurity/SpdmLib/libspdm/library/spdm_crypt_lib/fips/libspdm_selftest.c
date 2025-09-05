/**
 *  Copyright Notice:
 *  Copyright 2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"
#include "internal/libspdm_fips_lib.h"
#include "internal/libspdm_common_lib.h"

#if LIBSPDM_FIPS_MODE

/*run all of the self-tests and returns the results.*/
bool libspdm_fips_run_selftest(void *fips_selftest_context)
{
    libspdm_fips_selftest_context *context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    context = fips_selftest_context;

    libspdm_fips_selftest_hmac_sha256(context);
    libspdm_fips_selftest_hmac_sha384(context);
    libspdm_fips_selftest_hmac_sha512(context);

    libspdm_fips_selftest_aes_gcm(context);

    libspdm_fips_selftest_rsa_ssa(context);
    libspdm_fips_selftest_rsa_pss(context);

    libspdm_fips_selftest_hkdf(context);

    libspdm_fips_selftest_ecdh(context);

    libspdm_fips_selftest_sha256(context);
    libspdm_fips_selftest_sha384(context);
    libspdm_fips_selftest_sha512(context);

    libspdm_fips_selftest_sha3_256(context);
    libspdm_fips_selftest_sha3_384(context);
    libspdm_fips_selftest_sha3_512(context);

    libspdm_fips_selftest_ffdh(context);

    libspdm_fips_selftest_ecdsa(context);

    libspdm_fips_selftest_eddsa(context);

    return (context->tested_algo == context->self_test_result);
}

#endif/*LIBSPDM_FIPS_MODE*/
