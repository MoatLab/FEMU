/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <base.h>
#include <stdlib.h>
#include "stdio.h"
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

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
    int fd;

    assert(rand_data != NULL);

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        printf("cannot open /dev/urandom\n");
        return false;
    }
    if (read(fd, rand_data, sizeof(*rand_data)) != sizeof(*rand_data)) {
        printf("Cannot read /dev/urandom\n");
        close(fd);
        return false;
    }
    close(fd);

    return true;
}
