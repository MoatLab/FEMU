/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_CCA_H
#define FEMU_CXL_CCA_H

#include "qemu/bitops.h"
#include "qemu/thread.h"
#include "system/memory.h"
#include "cca-ring.h"

typedef struct FemuCxlMedia FemuCxlMedia;

/*
 * Device side of the caching API. The BQL protects everything here except
 * @kick and @stop, which @lock protects; nothing takes the BQL while
 * holding @lock. Cache changes also hold the device's operation gate.
 */
typedef struct FemuCxlCca {
    MemoryRegion bar;
    MemoryRegion regs;
    MemoryRegion shm;
    CcaRingHost ring;
    Object *owner;
    bool (*media_enabled)(FemuCxlMedia *s);
    uint32_t status;
    uint32_t epoch;             /* changes on every reset */
    uint32_t reset_pending;     /* CCA_RESET_*, applied by the thread */
    uint64_t completed;
    unsigned long *bypass;      /* one bit per media page, or NULL */
    uint64_t bypassed;
    uint64_t pinned_set_misses;
    uint64_t commands;
    uint64_t errors;
    uint64_t pin_fills;
    uint64_t writebacks;
    uint64_t dropped;
    QemuThread thread;
    QemuMutex lock;
    QemuCond cond;
    bool kick;
    bool stop;
    bool running;
} FemuCxlCca;

void femu_cxl_cca_init(FemuCxlCca *cca);
void femu_cxl_cca_finalize(FemuCxlCca *cca);
bool femu_cxl_cca_alloc(FemuCxlMedia *s, Object *owner, Error **errp);
void femu_cxl_cca_start(FemuCxlMedia *s, PCIDevice *pci, Object *owner,
                        bool (*media_enabled)(FemuCxlMedia *s));
void femu_cxl_cca_reset(FemuCxlMedia *s, uint32_t kind);
void femu_cxl_cca_stop(FemuCxlMedia *s);
void femu_cxl_cca_stats_reset(FemuCxlCca *cca);

static inline bool femu_cxl_cca_bypassed(FemuCxlCca *cca, uint64_t lpn)
{
    return cca->bypass && test_bit(lpn, cca->bypass);
}

#endif
