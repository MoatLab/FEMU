/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/


extern int libspdm_common_context_data_test_main(void);
extern int libspdm_common_support_test_main(void);

int main(void)
{
    int return_value = 0;

    if (libspdm_common_context_data_test_main() != 0) {
        return_value = 1;
    }

    if (libspdm_common_support_test_main() != 0) {
        return_value = 1;
    }

    return return_value;
}
