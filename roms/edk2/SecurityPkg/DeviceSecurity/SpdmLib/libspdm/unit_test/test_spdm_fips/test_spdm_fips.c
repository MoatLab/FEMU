/**
 *  Copyright Notice:
 *  Copyright 2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "library/spdm_crypt_lib.h"
#include "internal/libspdm_common_lib.h"

void libspdm_test_fips(void **state)
{
    bool status;
    status = false;

#if LIBSPDM_FIPS_MODE

    libspdm_fips_selftest_context fips_selftest_context;
    fips_selftest_context.tested_algo = 0;
    fips_selftest_context.self_test_result = 0;

    status = libspdm_fips_run_selftest(&fips_selftest_context);
    assert_true(status);
#else
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "test is valid only when LIBSPDM_FIPS_MODE is open.\n"));
    assert_true(status);
#endif
}

int libspdm_crypt_lib_setup(void **state)
{
    return 0;
}

int libspdm_crypt_lib_teardown(void **state)
{
    return 0;
}

int libspdm_crypt_lib_test_main(void)
{
    const struct CMUnitTest spdm_crypt_lib_tests[] = {
        cmocka_unit_test(libspdm_test_fips),
    };

    return cmocka_run_group_tests(spdm_crypt_lib_tests,
                                  libspdm_crypt_lib_setup,
                                  libspdm_crypt_lib_teardown);
}

int main(void)
{
    int return_value = 0;

    if (libspdm_crypt_lib_test_main() != 0) {
        return_value = 1;
    }

    return return_value;
}
