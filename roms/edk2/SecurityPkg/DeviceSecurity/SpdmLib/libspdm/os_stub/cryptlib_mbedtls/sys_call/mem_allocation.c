/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Base Memory Allocation Routines Wrapper.
 **/

#include <base.h>
#include "library/debuglib.h"
#include "library/malloclib.h"
#include <stddef.h>


/* Extra header to record the memory buffer size from malloc routine.*/

#define CRYPTMEM_HEAD_VERSION 0x1
typedef struct {
    uint32_t version;
    uint32_t reserved;
    size_t size;
} CRYPTMEM_HEAD;

#define CRYPTMEM_OVERHEAD sizeof(CRYPTMEM_HEAD)


/* -- Memory-Allocation Routines --*/


/* Allocates memory blocks */
void *my_calloc(size_t num, size_t size)
{
    CRYPTMEM_HEAD *pool_hdr;
    size_t new_size;
    void *data;


    /* Adjust the size by the buffer header overhead*/

    new_size = (size_t)(size * num) + CRYPTMEM_OVERHEAD;

    data = allocate_zero_pool(new_size);
    if (data != NULL) {
        pool_hdr = (CRYPTMEM_HEAD *)data;

        /* Record the memory brief information*/

        pool_hdr->version = CRYPTMEM_HEAD_VERSION;
        pool_hdr->size = size;

        return (void *)(pool_hdr + 1);
    } else {

        /* The buffer allocation failed.*/

        return NULL;
    }
}

/* De-allocates or frees a memory block */
void my_free(void *ptr)
{
    CRYPTMEM_HEAD *pool_hdr;


    /* In Standard C, free() handles a null pointer argument transparently. This
     * is not true of free_pool() below, so protect it.*/

    if (ptr != NULL) {
        pool_hdr = (CRYPTMEM_HEAD *)ptr - 1;
        LIBSPDM_ASSERT(pool_hdr->version == CRYPTMEM_HEAD_VERSION);
        free_pool(pool_hdr);
    }
}
