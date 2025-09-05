/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <base.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void *allocate_pool(size_t AllocationSize)
{
    return malloc(AllocationSize);
}

void *allocate_zero_pool(size_t AllocationSize)
{
    void *buffer;
    buffer = malloc(AllocationSize);
    if (buffer == NULL) {
        return NULL;
    }
    memset(buffer, 0, AllocationSize);
    return buffer;
}

void free_pool(void *buffer)
{
    free(buffer);
}
