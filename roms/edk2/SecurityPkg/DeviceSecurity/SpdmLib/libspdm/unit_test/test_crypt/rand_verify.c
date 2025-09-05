/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

#define LIBSPDM_RANDOM_NUMBER_SIZE 256

uint8_t m_libspdm_previous_random_buffer[LIBSPDM_RANDOM_NUMBER_SIZE] = { 0x0 };
uint8_t m_libspdm_random_buffer[LIBSPDM_RANDOM_NUMBER_SIZE] = { 0x0 };

/**
 * Validate Crypto pseudorandom number generator interfaces.
 *
 * @retval  true   Validation succeeded.
 * @retval  false  Validation failed.
 **/
bool libspdm_validate_crypt_prng(void)
{
    size_t index;
    bool status;

    libspdm_my_print(" \nCrypto PRNG Engine Testing:\n");

    libspdm_my_print("- Random Generation...");

    for (index = 0; index < 10; index++) {
        status = libspdm_random_bytes(m_libspdm_random_buffer, LIBSPDM_RANDOM_NUMBER_SIZE);
        if (!status) {
            libspdm_my_print("[Fail]");
            return false;
        }

        if (memcmp(m_libspdm_previous_random_buffer, m_libspdm_random_buffer,
                   LIBSPDM_RANDOM_NUMBER_SIZE) == 0) {
            libspdm_my_print("[Fail]");
            return false;
        }

        libspdm_copy_mem(m_libspdm_previous_random_buffer, sizeof(m_libspdm_previous_random_buffer),
                         m_libspdm_random_buffer, LIBSPDM_RANDOM_NUMBER_SIZE);
    }

    libspdm_my_print("[Pass]\n");

    return true;
}
