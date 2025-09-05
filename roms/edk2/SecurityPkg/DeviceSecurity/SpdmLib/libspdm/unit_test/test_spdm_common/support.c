#include "spdm_unit_test.h"
#include "internal/libspdm_common_lib.h"

/**
 * Test 1: Test support functions.
 **/
static void libspdm_test_common_context_data_case1(void **state)
{
    assert_int_equal(0x0001020304050607, libspdm_le_to_be_64(UINT64_C(0x0706050403020100)));
}

int libspdm_common_support_test_main(void)
{
    const struct CMUnitTest spdm_common_context_data_tests[] = {
        cmocka_unit_test(libspdm_test_common_context_data_case1),

    };

    return cmocka_run_group_tests(spdm_common_context_data_tests,
                                  libspdm_unit_test_group_setup,
                                  libspdm_unit_test_group_teardown);
}
