/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_QEMU_ADAPTER_H
#define FEMU_CXL_QEMU_ADAPTER_H

#include "../bbssd/ftl.h"
#include "cache.h"
#include "der.h"

typedef struct FemuCxlWork {
    NvmeRequest req;
    uint64_t latency;
    bool done;
} FemuCxlWork;

typedef struct FemuCxlMedia {
    FemuCtrl *ctrl;
    NvmeNamespace ns;
    SsdDramBackend backend;
    FemuCxlCache cache;
    uint32_t cache_pages;
    uint32_t cache_ways;
    char *cache_policy;
    bool ftl;
    char *der;
    bool cylon_kernel_ack;
    bool busy;
    bool closing;
    uint64_t invalidation_waiters;
    QemuCond idle;
    FemuCxlDer direct;
    uint64_t read_ns;
    uint64_t program_ns;
    uint64_t erase_ns;
    uint64_t media_ns;
    uint64_t media_reads;
    uint64_t media_writes;
    uint64_t access_ns;
    QemuMutex lock;
    QemuCond wake;
    QemuThread worker;
    FemuCxlWork *work;
    bool stopping;
    bool started;
} FemuCxlMedia;

void femu_cxl_enter(FemuCxlMedia *s);
void femu_cxl_leave(FemuCxlMedia *s);
void femu_cxl_delay(uint64_t ns);
bool femu_cxl_evict(void *opaque, FemuCxlEntry *e);
MemTxResult femu_cxl_access(FemuCxlMedia *s, uint64_t hpa, uint64_t dpa,
                            uint64_t *data, unsigned size, bool write);
void femu_cxl_start(FemuCxlMedia *s, void *payload, uint64_t size,
                     FemuCxlPolicy policy);
void femu_cxl_stop(FemuCxlMedia *s);

#endif
