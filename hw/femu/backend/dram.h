#ifndef __FEMU_MEM_BACKEND
#define __FEMU_MEM_BACKEND

#include <stdint.h>

/*
 * Pollers copy data in parallel, so an access holds the locks of the 4 KiB
 * granules it touches. Granules share BACKEND_RANGE_LOCKS locks, granule g
 * taking lock g % BACKEND_RANGE_LOCKS.
 */
#define BACKEND_RANGE_SHIFT     12
#define BACKEND_RANGE_LOCKS     1024

/* DRAM backend SSD address space */
typedef struct SsdDramBackend {
    void    *logical_space;
    int64_t size; /* in bytes */
    int     femu_mode;
    QemuMutex *range_locks; /* NULL: accesses take no lock */
    uint64_t range_waits;   /* lock takes that found the lock held */
} SsdDramBackend;

int init_dram_backend(SsdDramBackend **mbe, int64_t nbytes);
void free_dram_backend(SsdDramBackend *);

int backend_rw(SsdDramBackend *, QEMUSGList *, uint64_t *, bool);
void backend_init_range_locks(SsdDramBackend *b);
void backend_free_range_locks(SsdDramBackend *b);
void backend_lock_range(SsdDramBackend *b, uint64_t off, uint64_t len);
void backend_unlock_range(SsdDramBackend *b, uint64_t off, uint64_t len);

#endif
