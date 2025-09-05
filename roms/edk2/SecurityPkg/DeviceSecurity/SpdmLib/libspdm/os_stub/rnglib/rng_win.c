/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <base.h>
#include <stdlib.h>
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <assert.h>

#pragma comment(lib, "Bcrypt")

/**
 * Generates a 64-bit random number.
 *
 * if rand is NULL, then LIBSPDM_ASSERT().
 *
 * @param[out] rand_data     buffer pointer to store the 64-bit random value.
 *
 * @retval true         Random number generated successfully.
 * @retval false        Failed to generate the random number.
 *
 **/
bool libspdm_get_random_number_64(uint64_t *rand_data)
{
    BCRYPT_ALG_HANDLE Prov;

    assert(rand_data != NULL);

    if(!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&Prov, BCRYPT_RNG_ALGORITHM,
                                                   NULL, 0))) {
        return false;
    }
    if(!BCRYPT_SUCCESS(BCryptGenRandom(Prov, (PUCHAR)rand_data,
                                       sizeof(*rand_data), 0))) {
        BCryptCloseAlgorithmProvider(Prov, 0);
        return false;
    }
    BCryptCloseAlgorithmProvider(Prov, 0);

    return true;
}
