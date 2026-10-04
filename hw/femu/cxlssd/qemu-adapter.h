/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_QEMU_ADAPTER_H
#define FEMU_CXL_QEMU_ADAPTER_H

#include "qapi/qapi-types-common.h"
#include "../bbssd/ftl.h"
#include "cache.h"
#include "der.h"
#include "cca.h"

typedef struct FemuCxlWork {
    NvmeRequest req;
    uint64_t latency;
    bool done;
    /* Signalled by the worker alone when this request is done. */
    QemuCond *done_cond;
    QSIMPLEQ_ENTRY(FemuCxlWork) next;
} FemuCxlWork;

/* One access, flush or eviction chain: the media time it has accumulated. */
typedef struct FemuCxlOp {
    FemuCxlMedia *s;
    uint64_t ns;
    bool held;
    /* Pages this operation holds itself; its prefetch may evict them. */
    const uint64_t *own;
    unsigned nown;
} FemuCxlOp;

/* Pages a linked NVMe command replaced. */
typedef struct FemuCxlRange {
    uint64_t first;
    uint64_t last;
} FemuCxlRange;

struct FemuCxlMedia {
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
    /* Guests drive the log files: bytes each may reach, and what was cut. */
    uint64_t log_limit;
    uint64_t io_log_bytes;
    uint64_t log_dropped;
    int64_t stats_last;
    uint64_t stats_tokens;
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
    /* Enable KVM_CAP_CYLON_FAULT_EXIT when the slot is installed. */
    bool cylon_emul_exit;
    OnOffAuto concurrent;
    bool busy;
    /* Accesses sharing the gate, and operations waiting to take it alone. */
    uint64_t accesses;
    uint64_t exclusive_waiters;
    /* Pages held by accesses and write-backs in progress. */
    GHashTable *pages;
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
    uint64_t media_full;
    /*
     * Accesses skip their completion wait; the NAND timelines still advance.
     * Changed only under the gate held alone. BQL.
     */
    bool fast_load;
    /* How long the last switch back to the full model waited for NAND. */
    uint64_t fast_load_drain_ns;
    QemuMutex lock;
    /* Wakes the worker for new requests; no request waits on it. */
    QemuCond worker_cond;
    QemuThread worker;
    QSIMPLEQ_HEAD(, FemuCxlWork) work;
    bool stopping;
    bool started;
    bool cca_enabled;
    FemuCxlCca cca;
    /* A linked NVMe controller and its namespace; BQL. */
    FemuCtrl *nvme;
    NvmeNamespace *nvme_ns;
    Error *nvme_blocker;
    /*
     * The NVMe FTL thread appends what its writes replaced under @lock,
     * tagging each request with the batch number @nvme_taken + 1. @nvme_bh
     * takes the batch under @lock, drops those pages from the cache under
     * the BQL and the gate, then publishes its number in @nvme_done, which
     * the NVMe completions wait for.
     */
    GArray *nvme_ranges;
    uint64_t nvme_taken;
    uint64_t nvme_done;
    QEMUBH *nvme_bh;
    bool nvme_kick;
    /* The device went away first and left its FTL to the controller. */
    bool nvme_owns_ftl;
    uint64_t nvme_drops;
};

void femu_cxl_enter(FemuCxlMedia *s);
void femu_cxl_leave(FemuCxlMedia *s);
bool femu_cxl_concurrent(FemuCxlMedia *s);
void femu_cxl_enter_access(FemuCxlMedia *s);
void femu_cxl_leave_access(FemuCxlMedia *s);
void femu_cxl_delay(uint64_t ns);
bool femu_cxl_media(FemuCxlOp *op, uint64_t lpn, bool write);
bool femu_cxl_evict(void *opaque, FemuCxlEntry *e);
MemTxResult femu_cxl_access(FemuCxlMedia *s, uint64_t hpa, uint64_t dpa,
                            uint64_t *data, unsigned size, bool write);
MemTxResult femu_cxl_fill(FemuCxlMedia *s, uint64_t hpa, uint64_t dpa,
                          bool *mapped);
uint64_t femu_cxl_drain(FemuCxlMedia *s);
bool femu_cxl_geometry(FemuCxlMedia *s, uint64_t size, Error **errp);
void femu_cxl_start(FemuCxlMedia *s, void *payload, uint64_t size,
                     FemuCxlPolicy policy);
void femu_cxl_stop(FemuCxlMedia *s);
uint64_t femu_cxl_nvme_ftl(FemuCtrl *n, NvmeNamespace *ns, NvmeRequest *req);
void femu_cxl_nvme_bh(void *opaque);
void femu_cxl_nvme_mark(FemuCxlMedia *s, uint64_t dpa, uint64_t len);
void femu_cxl_nvme_mark_ratio(FemuCxlMedia *s, uint64_t first, uint64_t last);
void femu_cxl_nvme_flip(FemuCtrl *n, int64_t cdw10);

#endif
