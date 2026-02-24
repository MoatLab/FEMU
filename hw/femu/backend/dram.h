#ifndef __FEMU_MEM_BACKEND
#define __FEMU_MEM_BACKEND

#include <stdint.h>

struct FemuCtrl;

/* DRAM backend SSD address space */
typedef struct SsdDramBackend {
    void    *logical_space;
    int64_t size;         /* in bytes */
    int     femu_mode;
} SsdDramBackend;

/* Initialize backend from controller; sets n->mbe */
int init_dram_backend(struct FemuCtrl *n);
void free_dram_backend(SsdDramBackend *);

int backend_rw(SsdDramBackend *, QEMUSGList *, uint64_t *, bool);

#endif
