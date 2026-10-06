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
    /*
     * Signalled by the worker alone when this request is done. NULL for a
     * posted request, which nobody waits for and the worker frees.
     */
    QemuCond *done_cond;
    QSIMPLEQ_ENTRY(FemuCxlWork) next;
} FemuCxlWork;

/* One access, flush or eviction chain: the media time it has accumulated. */
typedef struct FemuCxlOp {
    FemuCxlMedia *s;
    uint64_t ns;
    /*
     * Realtime the media time counts from, which the access sleeps against;
     * 0 counts each request from its submission.
     */
    int64_t start;
    /* Pages this operation holds itself; its prefetch may evict them. */
    const uint64_t *own;
    unsigned nown;
    /* A demand access, for @owner (a vCPU index, or -1). */
    bool demand;
    int owner;
    /* A fill for a Cylon fault: its prefetch must not evict its own page. */
    bool fill;
    /* A fill that must not evict pages its own vCPU protects. */
    bool keep_own;
    /* The next media read ends the fill's media time; see cxl_fold(). */
    bool fold;
} FemuCxlOp;

/* One vCPU's protection of a page; see femu_cxl_protect(). */
typedef struct FemuCxlGuard {
    int owner;
    unsigned count;
    /* When @owner last protected the page, QEMU_CLOCK_REALTIME ns. */
    int64_t since;
} FemuCxlGuard;

/* Pages a linked NVMe command replaced. */
typedef struct FemuCxlRange {
    uint64_t first;
    uint64_t last;
} FemuCxlRange;

struct FemuCxlMedia {
    /* The device, for references that bottom halves hold. */
    Object *owner;
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
    /*
     * Version 2 of the Cylon fault exit (no emulation of cold pages): on,
     * off, or auto, which takes it when the host kernel offers it.
     */
    OnOffAuto cylon_never_emulate;
    /* Enable KVM_CAP_CYLON_FAULT_EXIT when the slot is installed. */
    bool cylon_emul_exit;
    /* Repeated exits at one RIP that stop the VM; 0 only warns. */
    uint32_t cylon_fault_stop;
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
    /* A thread without the BQL left @release to a bottom half. */
    bool release_scheduled;
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
     * Media requests that waited for forced collection, how long in all,
     * and the longest wait.
     */
    uint64_t gc_stalls;
    uint64_t gc_stall_ns;
    uint64_t gc_stall_max_ns;
    /* The FTL threads count into these under @lock; CXL lock copies follow. */
    uint64_t ftl_gc_stalls;
    uint64_t ftl_gc_stall_ns;
    uint64_t ftl_gc_stall_max_ns;
    /*
     * The first stall over one second, set under @lock and read
     * atomically; and whether @posted_bh reported it, under the CXL lock.
     */
    uint64_t gc_stall_long_ns;
    bool gc_stall_warned;
    /*
     * Accesses made inside a device's re-entrancy guard, which never wait
     * (femu_cxl_access_nowait()), and the media operations they queued,
     * under the CXL lock; and those operations' modelled time, which the
     * worker adds up atomically.
     */
    uint64_t dma_accesses;
    uint64_t dma_media_ops;
    uint64_t dma_media_ns;
    /*
     * The last run of such accesses: its guarded section, direction, end,
     * and the page it last queued an operation for. CXL lock.
     */
    uint64_t dma_run_section;
    bool dma_run_write;
    uint64_t dma_run_end;
    uint64_t dma_run_posted;
    /*
     * Such operations wait in @post until the worker takes them, after the
     * waited requests in @work. @post_lock is held only to add or take one
     * and to count, so a guarded access never waits for @lock, which the
     * FTL holds for a whole request, garbage collection included. Order:
     * @lock, then @post_lock. @posted counts them, written under @post_lock
     * and read atomically; @posted_taken counts those taken, under both;
     * @posted_done counts those run, under @post_lock, which the worker
     * wakes @posted_cond for.
     */
    QemuMutex post_lock;
    QSIMPLEQ_HEAD(, FemuCxlWork) post;
    uint64_t posted;
    uint64_t posted_taken;
    uint64_t posted_done;
    QemuCond posted_cond;
    /*
     * After each one the worker publishes the FTL program and collection
     * counts and the programs NAND refused, atomically, for @posted_bh,
     * which must not wait for @lock either. The refusals already counted in
     * media-full are under the CXL lock.
     */
    uint64_t posted_writes;
    uint64_t posted_stalls;
    uint64_t posted_stall_ns;
    uint64_t posted_stall_max_ns;
    uint64_t posted_failures;
    uint64_t posted_failures_seen;
    QEMUBH *posted_bh;
    /*
     * Accesses skip their completion wait; the NAND timelines still advance.
     * Changed only under the gate held alone. BQL and CXL lock.
     */
    bool fast_load;
    /* How long the last switch back to the full model waited for NAND. */
    uint64_t fast_load_drain_ns;
    QemuMutex lock;
    /*
     * Threads that found @lock taken, and waited requests that are done but
     * whose callers have not taken @lock back (under @lock); both read
     * atomically by the worker, which lets them in before device DMA work.
     */
    unsigned lock_wanted;
    unsigned done_unclaimed;
    /* Wakes the worker for new requests; no request waits on it. */
    QemuEvent worker_event;
    QemuThread worker;
    QSIMPLEQ_HEAD(, FemuCxlWork) work;
    bool stopping;
    bool started;
    bool cca_enabled;
    FemuCxlCca cca;
    /* A linked NVMe controller and its namespace; BQL and CXL lock. */
    FemuCtrl *nvme;
    NvmeNamespace *nvme_ns;
    Error *nvme_blocker;
    /*
     * The NVMe FTL thread appends what its writes replaced under @lock,
     * tagging each request with the batch number @nvme_taken + 1. @nvme_bh
     * takes the batch under @lock, drops those pages from the cache under
     * the locks and the gate, then publishes its number in @nvme_done, which
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
    /*
     * Pages that an instruction stopped at a Cylon fault still needs (lpn
     * to an array of per-vCPU FemuCxlGuard), so that vCPU's demand accesses
     * do not evict them, and other vCPUs' fills only after
     * @protect_window_ns. CXL lock.
     */
    GHashTable *protect;
    uint64_t protect_window_ns;
    /*
     * Pages mapped without a cache way for an instruction the emulator
     * cannot run (lpn to the number of vCPUs holding it). CXL lock.
     */
    GHashTable *overflow;
    /*
     * qtest only: the next fill protects every page of its set just before
     * it takes a way, as another vCPU could while a media wait drops the
     * locks.
     */
    bool test_fill_race;
    /*
     * qtest only: a fill reports its page mapped when it is resident, and a
     * page handed to the emulator counts as handed, so the fault service
     * runs without a Cylon slot.
     */
    bool test_map;
    /* qtest only: the RIP of test-fault exits. */
    uint64_t test_rip;
    /*
     * The vCPU that accesses from threads without one act for: -1 (none),
     * or in qtest the vCPU that test-owner names for hooks and accesses.
     */
    int test_owner;
    /*
     * qtest only: page + 1 that another access starts to fill (hold and
     * cache entry, media read pending) at the point where a prefetch of it
     * could drop the locks; test-prefetch-race-end then fails that fill.
     */
    uint64_t test_prefetch_race;
    uint64_t test_race_lpn;
    bool test_race_active;
    /*
     * qtest only, atomic: the worker holds @lock in its next request until
     * this is 0 again or this many ms passed, and @test_ftl_holding says
     * whether it holds; each device DMA operation takes @test_ftl_delay_ms
     * more under @lock. Both act as a long garbage collection does.
     */
    uint64_t test_ftl_hold_ms;
    bool test_ftl_holding;
    uint64_t test_ftl_delay_ms;
};

/*
 * How long another vCPU's fill passes over a page that a vCPU protected.
 * A vCPU usually runs the instruction again microseconds after its exit
 * returns, so this normally outlasts the retry (a heuristic: host
 * preemption can exceed it), while a vCPU that stops faulting closes a set
 * to the others for no longer than this.
 */
#define FEMU_CXL_PROTECT_WINDOW_NS (1000 * 1000)

/*
 * The CXL lock: one lock for the state of every femu-cxl-ssd, the adapter's
 * window list and the per-vCPU Cylon fault records. The BQL protected all of
 * it before; the lock lets a Cylon fault exit run without the BQL. Order:
 * BQL, then this lock, then a medium's FTL @lock, then a CCA @lock. A thread
 * that holds it never takes the BQL; femu_cxl_drop() lets go of both first.
 * It is recursive within a thread. See "Locking" in cxlssd.md.
 */
void femu_cxl_lock(void);
void femu_cxl_unlock(void);
bool femu_cxl_locked(void);
/*
 * Until femu_cxl_lock_bql_free() runs, every holder of the CXL lock holds
 * the BQL too, and the lock costs nothing; after it, it is a mutex.
 */
bool femu_cxl_lock_is_bql_free(void);
void femu_cxl_lock_bql_free(void);

/* What femu_cxl_drop() let go of, for femu_cxl_retake(). */
typedef struct FemuCxlHeld {
    unsigned depth;
    bool bql;
} FemuCxlHeld;

/*
 * Let go of the CXL lock completely, and of the BQL if this thread holds it,
 * for a wait; take them back in lock order. These are the points where the
 * BQL was dropped before, so the protected regions are unchanged.
 */
void femu_cxl_drop(FemuCxlHeld *held);
void femu_cxl_retake(const FemuCxlHeld *held);
/* Wait on @cond, which is signalled under the CXL lock, as above. */
void femu_cxl_wait(QemuCond *cond);
void femu_cxl_timedwait(QemuCond *cond, int ms);

static inline void *femu_cxl_guard_enter(void)
{
    femu_cxl_lock();
    return (void *)1;
}

static inline void femu_cxl_guard_exit(void **guard)
{
    if (*guard) {
        femu_cxl_unlock();
    }
}

/* Hold the CXL lock until the end of the enclosing scope. */
#define FEMU_CXL_LOCK_GUARD() \
    __attribute__((cleanup(femu_cxl_guard_exit))) G_GNUC_UNUSED void * \
    glue(femu_cxl_guard, __COUNTER__) = femu_cxl_guard_enter()

#define WITH_FEMU_CXL_LOCK_(var) \
    for (__attribute__((cleanup(femu_cxl_guard_exit))) void *var = \
             femu_cxl_guard_enter(); \
         var; femu_cxl_unlock(), var = NULL)

/* Hold the CXL lock for the statement or block that follows. */
#define WITH_FEMU_CXL_LOCK() \
    WITH_FEMU_CXL_LOCK_(glue(femu_cxl_with, __COUNTER__))

/*
 * A BQL-free thread reached an operation that needs the BQL. The operation
 * refused or deferred itself and set this flag; the Cylon fault exit then
 * serves the fault again under the BQL. Thread-local.
 */
bool femu_cxl_bql_needed(void);
void femu_cxl_need_bql(void);
void femu_cxl_clear_need_bql(void);

void femu_cxl_enter(FemuCxlMedia *s);
void femu_cxl_leave(FemuCxlMedia *s);
bool femu_cxl_concurrent(FemuCxlMedia *s);
void femu_cxl_enter_access(FemuCxlMedia *s);
void femu_cxl_leave_access(FemuCxlMedia *s);
void femu_cxl_release_later(FemuCxlMedia *s);
void femu_cxl_delay(uint64_t ns);
bool femu_cxl_media(FemuCxlOp *op, uint64_t lpn, bool write);
bool femu_cxl_evict(void *opaque, FemuCxlEntry *e);
MemTxResult femu_cxl_access(FemuCxlMedia *s, uint64_t hpa, uint64_t dpa,
                            uint64_t *data, unsigned size, bool write);
MemTxResult femu_cxl_access_nowait(FemuCxlMedia *s, uint64_t dpa,
                                   uint64_t *data, unsigned size, bool write);
/* femu_cxl_fill() flags. */
#define FEMU_CXL_FILL_KEEP_OWN 1
#define FEMU_CXL_FILL_OVERFLOW 2
MemTxResult femu_cxl_fill(FemuCxlMedia *s, uint64_t hpa, uint64_t dpa,
                          bool *mapped, unsigned flags);
bool femu_cxl_fill_conflict(FemuCxlMedia *s, uint64_t lpn);
void femu_cxl_overflow_add(FemuCxlMedia *s, uint64_t lpn);
void femu_cxl_overflow_release(FemuCxlMedia *s, uint64_t lpn);
void femu_cxl_overflow_drop(FemuCxlMedia *s, uint64_t first, uint64_t last);
bool femu_cxl_admissible(FemuCxlMedia *s, uint64_t lpn);
void femu_cxl_fill_failed(FemuCxlMedia *s, uint64_t lpn, FemuCxlEntry *e);
bool femu_cxl_fill_wait(FemuCxlMedia *s, uint64_t lpn, int64_t deadline,
                        bool keep_own);
void femu_cxl_protect(FemuCxlMedia *s, int owner, uint64_t lpn);
bool femu_cxl_revoke_ahead_ok(FemuCxlMedia *s, FemuCxlOp *op, uint64_t lpn,
                              int64_t now);
void femu_cxl_protect_renew(FemuCxlMedia *s, int owner, uint64_t lpn);
void femu_cxl_unprotect(FemuCxlMedia *s, int owner, uint64_t lpn);
bool femu_cxl_protected_by(FemuCxlMedia *s, int owner, uint64_t lpn);
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
