/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Pseudorandom Number generator Wrapper Implementation.
 **/

#include "internal_crypt_lib.h"
#include <openssl/rand.h>
#include <openssl/evp.h>

/**
 * Generates a random byte stream of the specified size.
 *
 * If output is NULL, then return false.
 * If this interface is not supported, then return false.
 *
 * @param[out]  output  Pointer to buffer to receive random value.
 * @param[in]   size    Size of random bytes to generate.
 *
 * @retval true   Random byte stream generated successfully.
 * @retval false  Generation of random byte stream failed.
 **/
bool libspdm_random_bytes(uint8_t *output, size_t size)
{
    /* Check input parameters. */
    if (output == NULL || size > INT_MAX) {
        return false;
    }

    /* Generate random data. */
    if (RAND_bytes(output, size) != 1) {
        return false;
    }

    return true;
}
