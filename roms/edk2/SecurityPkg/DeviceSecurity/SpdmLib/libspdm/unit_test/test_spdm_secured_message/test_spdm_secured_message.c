/**
 *  Copyright Notice:
 *  Copyright 2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

extern int libspdm_secured_message_encode_decode_test_main(void);

int main(void)
{
    int return_value = 0;

    if (libspdm_secured_message_encode_decode_test_main() != 0) {
        return_value = 1;
    }

    return return_value;
}
