#ifndef __FEMU_MEM_BACKEND
#define __FEMU_MEM_BACKEND

#include <stdint.h>

/* DRAM backend SSD address space */
typedef struct SsdDramBackend {
    void    *logical_space;
    int64_t size; /* in bytes */
    int64_t parity_start; // used only if stripesize > 1
    int     stripesize;
    int     pagesize; // used only if stripesize > 1
    int     femu_mode;
} SsdDramBackend;

int init_dram_backend(SsdDramBackend** mbe, int64_t nbytes, int stripesize, int pagesize);
void free_dram_backend(SsdDramBackend *);

int backend_rw(SsdDramBackend*, QEMUSGList*, uint64_t*, bool);

#endif
