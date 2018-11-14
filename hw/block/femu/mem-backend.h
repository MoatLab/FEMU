#ifndef __FEMU_MEM_BACKEND__
#define __FEMU_MEM_BACKEND__

#include <stdint.h>


/* Coperd: FEMU memory backend structure */
struct femu_mbe {
    void *mem_backend;
    int64_t size; /* in bytes */
};


#endif
