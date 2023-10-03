#ifndef __FEMU_MEM_BACKEND
#define __FEMU_MEM_BACKEND

#include <stdint.h>

/* DRAM backend SSD address space */
typedef struct SsdDramBackend {
    void    **logical_space;
    int64_t *sizes; /* in bytes */
    int     femu_mode;
    uint32_t num_namespaces;
} SsdDramBackend;

void init_dram_backend_logical_space(SsdDramBackend **mbe, int idx, int64_t nbytes);
int init_dram_backend(SsdDramBackend **mbe, int64_t nbytes, uint32_t num_namespaces);
void free_dram_backend(SsdDramBackend *);

int backend_rw_namespace(SsdDramBackend *b, QEMUSGList *qsg, uint64_t *lbal, bool is_write, uint32_t nsid);
int backend_rw(SsdDramBackend *, QEMUSGList *, uint64_t *, bool);

#endif
