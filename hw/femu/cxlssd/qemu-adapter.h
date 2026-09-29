/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_QEMU_ADAPTER_H
#define FEMU_CXL_QEMU_ADAPTER_H

#include "../bbssd/ftl.h"
#include "cache.h"
#include "der.h"
#include "cca.h"

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
    uint32_t prefetch_degree;
    uint32_t prefetch_stride;
    uint64_t prefetch_inserts;
    uint64_t read_hits;
    uint64_t read_misses;
    uint64_t write_hits;
    uint64_t write_misses;
    uint64_t cache_entries;
    bool lsa_control;
    uint8_t *labels;
    char *log_dir;
    char *tracefs_dir;
    FILE *io_log;
    GHashTable *log_warned;
    uint32_t log_sequence;
    uint64_t control_argument;
    uint64_t control_status;
    uint64_t control_command;
    bool tracing;
    uint64_t snapshot[8];
    bool ftl;
    bool first_touch_program;
    bool free_writeback;
    uint32_t channels;
    uint32_t luns_per_channel;
    uint32_t blocks_per_plane;
    uint32_t pages_per_block;
    uint32_t gc_threshold;
    uint32_t gc_threshold_high;
    uint64_t channel_ns;
    char *der;
    bool cylon_kernel_ack;
    bool busy;
    /* Threads waiting for the gate, and how often it has been taken. */
    uint32_t waiters;
    uint64_t entries;
    bool closing;
    /* Set when unplug found the gate held; run by the holder as it leaves. */
    void (*release)(struct FemuCxlMedia *s);
    uint64_t invalidations;
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
    bool cca_enabled;
    FemuCxlCca cca;
    /* A linked NVMe controller and its namespace; BQL. */
    FemuCtrl *nvme;
    NvmeNamespace *nvme_ns;
    Error *nvme_blocker;
    /* The device went away first and left its FTL to the controller. */
    bool nvme_owns_ftl;
} FemuCxlMedia;

void femu_cxl_enter(FemuCxlMedia *s);
void femu_cxl_leave(FemuCxlMedia *s);
void femu_cxl_delay(uint64_t ns);
bool femu_cxl_media(FemuCxlMedia *s, uint64_t lpn, bool write);
bool femu_cxl_evict(void *opaque, FemuCxlEntry *e);
MemTxResult femu_cxl_access(FemuCxlMedia *s, uint64_t hpa, uint64_t dpa,
                            uint64_t *data, unsigned size, bool write);
bool femu_cxl_geometry(FemuCxlMedia *s, uint64_t size, Error **errp);
void femu_cxl_start(FemuCxlMedia *s, void *payload, uint64_t size,
                     FemuCxlPolicy policy);
void femu_cxl_stop(FemuCxlMedia *s);
uint64_t femu_cxl_nvme_ftl(FemuCtrl *n, NvmeNamespace *ns, NvmeRequest *req);

#endif
