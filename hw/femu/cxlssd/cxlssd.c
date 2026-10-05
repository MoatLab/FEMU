/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "hw/core/cpu.h"
#include "qemu-adapter.h"

static FemuCxlGuard *cxl_guard(FemuCxlMedia *s, int owner, uint64_t lpn)
{
    GArray *guards = s->protect ? g_hash_table_lookup(s->protect, &lpn) : NULL;
    unsigned i;

    for (i = 0; guards && i < guards->len; i++) {
        FemuCxlGuard *g = &g_array_index(guards, FemuCxlGuard, i);

        if (g->owner == owner) {
            return g;
        }
    }
    return NULL;
}

static bool cxl_protected(FemuCxlMedia *s, int owner, uint64_t lpn)
{
    return cxl_guard(s, owner, lpn);
}

bool femu_cxl_protected_by(FemuCxlMedia *s, int owner, uint64_t lpn)
{
    return cxl_protected(s, owner, lpn);
}

/*
 * Whether a vCPU other than @owner protected @lpn less than the protection
 * window ago. Lowers @until to the earliest time such a protection expires.
 */
static bool cxl_protected_recently(FemuCxlMedia *s, int owner, uint64_t lpn,
                                   int64_t now, int64_t *until)
{
    GArray *guards = s->protect ? g_hash_table_lookup(s->protect, &lpn) : NULL;
    bool recent = false;
    unsigned i;

    for (i = 0; guards && i < guards->len; i++) {
        FemuCxlGuard *g = &g_array_index(guards, FemuCxlGuard, i);
        int64_t end = g->since > INT64_MAX - (int64_t)s->protect_window_ns ?
                      INT64_MAX : g->since + (int64_t)s->protect_window_ns;

        if (g->owner != owner && now < end) {
            recent = true;
            *until = MIN(*until, end);
        }
    }
    return recent;
}

/* The vCPU an access acts for; qtest accesses act for test-owner. */
static int cxl_owner(FemuCxlMedia *s)
{
    return current_cpu ? current_cpu->cpu_index : s->test_owner;
}

static QemuMutex cxl_lock;
/* How many times this thread holds @cxl_lock. */
static __thread unsigned cxl_lock_depth;
static __thread bool cxl_need_bql;

/*
 * Holds are a few microseconds and a sleeping handoff costs about as much,
 * so let a contender spin briefly before it sleeps (glibc adaptive mutex).
 */
static void __attribute__((constructor)) cxl_lock_init(void)
{
    qemu_mutex_init(&cxl_lock);
#ifdef PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
    {
        pthread_mutexattr_t attr;

        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
        pthread_mutex_destroy(&cxl_lock.lock);
        pthread_mutex_init(&cxl_lock.lock, &attr);
        pthread_mutexattr_destroy(&attr);
    }
#endif
}

void femu_cxl_lock(void)
{
    if (!cxl_lock_depth++) {
        qemu_mutex_lock(&cxl_lock);
    }
}

void femu_cxl_unlock(void)
{
    assert(cxl_lock_depth);
    if (!--cxl_lock_depth) {
        qemu_mutex_unlock(&cxl_lock);
    }
}

bool femu_cxl_locked(void)
{
    return cxl_lock_depth;
}

void femu_cxl_drop(FemuCxlHeld *held)
{
    assert(cxl_lock_depth);
    held->depth = cxl_lock_depth;
    held->bql = bql_locked();
    cxl_lock_depth = 0;
    qemu_mutex_unlock(&cxl_lock);
    if (held->bql) {
        bql_unlock();
    }
}

void femu_cxl_retake(const FemuCxlHeld *held)
{
    assert(!cxl_lock_depth);
    if (held->bql) {
        bql_lock();
    }
    qemu_mutex_lock(&cxl_lock);
    cxl_lock_depth = held->depth;
}

/*
 * The condition wait releases @cxl_lock atomically. A thread that also holds
 * the BQL lets it go first and takes it back before the CXL lock, in lock
 * order; its caller rechecks its condition in a loop either way.
 */
static void cxl_wait(QemuCond *cond, int ms)
{
    unsigned depth = cxl_lock_depth;
    bool bql = bql_locked();

    assert(depth);
    if (bql) {
        bql_unlock();
    }
    cxl_lock_depth = 0;
    if (ms < 0) {
        qemu_cond_wait(cond, &cxl_lock);
    } else {
        qemu_cond_timedwait(cond, &cxl_lock, ms);
    }
    if (bql) {
        qemu_mutex_unlock(&cxl_lock);
        bql_lock();
        qemu_mutex_lock(&cxl_lock);
    }
    cxl_lock_depth = depth;
}

void femu_cxl_wait(QemuCond *cond)
{
    cxl_wait(cond, -1);
}

void femu_cxl_timedwait(QemuCond *cond, int ms)
{
    cxl_wait(cond, MAX(ms, 0));
}

bool femu_cxl_bql_needed(void)
{
    return cxl_need_bql;
}

void femu_cxl_need_bql(void)
{
    cxl_need_bql = true;
}

void femu_cxl_clear_need_bql(void)
{
    cxl_need_bql = false;
}

/*
 * The CXL lock protects the gate. Accesses share it, so misses to different
 * pages wait for the media together; flush, invalidation and teardown take
 * it alone, after the accesses in progress, and new accesses wait for them.
 */
void femu_cxl_enter(FemuCxlMedia *s)
{
    assert(femu_cxl_locked());
    s->waiters++;
    s->exclusive_waiters++;
    while (s->busy || s->accesses) {
        femu_cxl_wait(&s->idle);
    }
    s->exclusive_waiters--;
    s->waiters--;
    s->entries++;
    s->busy = true;
}

/*
 * Teardown that a fault exit without the BQL left to the main loop. It takes
 * the gate alone, which waits only for accesses in progress: those see
 * @closing and leave without waiting for the main loop.
 */
static void cxl_release_bh(void *opaque)
{
    FemuCxlMedia *s = opaque;

    WITH_FEMU_CXL_LOCK() {
        s->release_scheduled = false;
        if (s->release) {
            femu_cxl_enter(s);
            femu_cxl_leave(s);
        }
    }
    object_unref(s->owner);
}

/* The last one out of the gate runs what was deferred to it. */
static void cxl_gate_idle(FemuCxlMedia *s)
{
    /*
     * Teardown deferred by an unplug runs while the gate is still held. It
     * stops threads and deletes the memory listener, which needs the BQL. A
     * thread without it leaves the gate open and the teardown to a bottom
     * half: holding the gate for the main loop would make a vCPU wait for
     * it, and the main loop may be pausing vCPUs.
     */
    if (s->release && !bql_locked()) {
        if (!s->release_scheduled) {
            s->release_scheduled = true;
            object_ref(s->owner);
            aio_bh_schedule_oneshot(qemu_get_aio_context(), cxl_release_bh,
                                    s);
        }
    } else if (s->release) {
        void (*release)(FemuCxlMedia *) = s->release;

        s->release = NULL;
        s->busy = true;
        release(s);
    }
    s->busy = false;
    /* Invalidation found the gate taken and did not wait for it. */
    if (s->nvme_kick && s->nvme_bh) {
        s->nvme_kick = false;
        qemu_bh_schedule(s->nvme_bh);
    }
}

void femu_cxl_leave(FemuCxlMedia *s)
{
    cxl_gate_idle(s);
    qemu_cond_broadcast(&s->idle);
}

/*
 * With der=off a guest's lock-prefixed read-modify-write reaches the device as
 * a read and a separate write, so it is never atomic. Serializing accesses
 * keeps other vCPUs out from between the two most of the time; overlapping
 * misses make it common. A direct mode resolves the write on the mapped page,
 * where KVM exchanges and retries, so by default misses overlap only while
 * direct mapping is active.
 */
bool femu_cxl_concurrent(FemuCxlMedia *s)
{
    return s->concurrent == ON_OFF_AUTO_ON ||
           (s->concurrent == ON_OFF_AUTO_AUTO && s->direct.available);
}

void femu_cxl_enter_access(FemuCxlMedia *s)
{
    assert(femu_cxl_locked());
    s->waiters++;
    while (s->busy || s->exclusive_waiters) {
        femu_cxl_wait(&s->idle);
    }
    s->waiters--;
    s->entries++;
    s->accesses++;
}

void femu_cxl_leave_access(FemuCxlMedia *s)
{
    if (!--s->accesses) {
        cxl_gate_idle(s);
    }
    qemu_cond_broadcast(&s->idle);
}

/* Spin only this close to the deadline; sleeps can overshoot by this much. */
#define FEMU_CXL_SPIN_NS (100 * SCALE_US)

/* Sleep, then spin, until @deadline (QEMU_CLOCK_REALTIME ns); no locks. */
static void cxl_sleep_until(int64_t deadline)
{
    int64_t remaining = deadline - qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

    if (remaining > FEMU_CXL_SPIN_NS) {
        g_usleep((remaining - FEMU_CXL_SPIN_NS) / SCALE_US);
    }
    while (qemu_clock_get_ns(QEMU_CLOCK_REALTIME) < deadline) {
        cpu_relax();
    }
}

void femu_cxl_delay(uint64_t ns)
{
    int64_t deadline = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + ns;
    FemuCxlHeld held;

    femu_cxl_drop(&held);
    cxl_sleep_until(deadline);
    femu_cxl_retake(&held);
}

/*
 * A write that finds free lines at the forced threshold blocks until
 * collection has freed one, as a real SSD's foreground collection does. The
 * FTL frees the line in its metadata at once and books the copies and erases
 * on the LUNs, so the request ends no earlier than the last of those erases.
 * Caller holds @lock.
 */
static uint64_t cxl_ftl_request(FemuCxlMedia *s, FemuCtrl *n,
                                NvmeNamespace *ns, NvmeRequest *req)
{
    struct ssd *ssd = ns->ssd;
    uint64_t timed = ssd->forced_gc_timed;
    uint64_t lat = bb_ftl_process_req(n, ns, req);
    uint64_t wait;

    /* Collection without GC delay books no NAND time to wait for. */
    if (ssd->forced_gc_timed == timed || ssd->forced_gc_end <= req->stime) {
        return lat;
    }
    wait = ssd->forced_gc_end - req->stime;
    s->ftl_gc_stalls++;
    s->ftl_gc_stall_ns += wait;
    return MAX(lat, wait);
}

/* Only metadata reaches the worker; the vCPU owns all payload access. */
static void *cxl_worker(void *opaque)
{
    FemuCxlMedia *s = opaque;

    qemu_mutex_lock(&s->lock);
    while (!s->stopping) {
        FemuCxlWork *work = QSIMPLEQ_FIRST(&s->work);

        if (!work) {
            qemu_cond_wait(&s->worker_cond, &s->lock);
            continue;
        }
        QSIMPLEQ_REMOVE_HEAD(&s->work, next);
        if (s->first_touch_program &&
            work->req.cmd.opcode == NVME_CMD_READ &&
            s->ns.ssd->maptbl[work->req.slba / 8].ppa == UNMAPPED_PPA) {
            work->req.cmd.opcode = NVME_CMD_WRITE;
        }
        work->latency = cxl_ftl_request(s, s->ctrl, &s->ns, &work->req);
        work->done = true;
        /* The waiter rechecks done under @lock, so its cond outlives this. */
        qemu_cond_signal(work->done_cond);
    }
    qemu_mutex_unlock(&s->lock);
    return NULL;
}

/*
 * Realize refuses NAND whose spare lines do not exceed the forced collection
 * reserve, so collection always frees a line and no program should fail. If
 * one still does, only its timing is lost. The payload is in host memory, so
 * the failure never vetoes an eviction or an insert.
 */
static void cxl_media_full(FemuCxlMedia *s)
{
    if (!s->media_full++) {
        error_report("femu-cxl-ssd: garbage collection freed no NAND page; "
                     "a program was not timed and media-full counts it");
    }
}

/*
 * Requests from different accesses queue for the worker in arrival order; the
 * NAND model overlaps them where they reach different LUNs.
 */
bool femu_cxl_media(FemuCxlOp *op, uint64_t lpn, bool write)
{
    FemuCxlMedia *s = op->s;
    FemuCxlWork work = {
        .req = {
            .cmd.opcode = write ? NVME_CMD_WRITE : NVME_CMD_READ,
            .ns = &s->ns,
            .slba = lpn * 8,
            .nlb = 8,
            .stime = (op->start ? op->start :
                      qemu_clock_get_ns(QEMU_CLOCK_REALTIME)) + op->ns,
        },
    };
    QemuCond done_cond;
    FemuCxlHeld held;
    uint64_t writes;
    uint64_t stalls;
    uint64_t stall_ns;

    if (!s->ftl) {
        return true;
    }
    work.done_cond = &done_cond;
    qemu_cond_init(&done_cond);
    femu_cxl_drop(&held);
    qemu_mutex_lock(&s->lock);
    QSIMPLEQ_INSERT_TAIL(&s->work, &work, next);
    qemu_cond_signal(&s->worker_cond);
    while (!work.done) {
        qemu_cond_wait(&done_cond, &s->lock);
    }
    /* A linked controller's FTL thread updates this under @lock. */
    writes = ssd_nand_write_pages(s->ns.ssd);
    stalls = s->ftl_gc_stalls;
    stall_ns = s->ftl_gc_stall_ns;
    qemu_mutex_unlock(&s->lock);
    qemu_cond_destroy(&done_cond);
    /*
     * A fill's last media read: check the frame it will map and wait out its
     * media time here, so the fill takes the locks once more instead of
     * twice. The time counts from @op->start, as the access sleep does.
     */
    if (op->fold && work.req.status == NVME_SUCCESS) {
        femu_cxl_der_precheck_run();
        cxl_sleep_until(op->start + op->ns + work.latency);
    }
    op->fold = false;
    femu_cxl_retake(&held);
    s->media_ns += work.latency;
    op->ns += work.latency;
    /* Another caller may have published a later snapshot first. */
    s->media_writes = MAX(s->media_writes, writes);
    s->gc_stalls = MAX(s->gc_stalls, stalls);
    s->gc_stall_ns = MAX(s->gc_stall_ns, stall_ns);
    if (work.req.cmd.opcode == NVME_CMD_READ) {
        s->media_reads++;
    }
    /* A fill that first touch made a program fails only as a program. */
    if (!write && work.req.cmd.opcode == NVME_CMD_WRITE &&
        work.req.status != NVME_SUCCESS) {
        cxl_media_full(s);
        return true;
    }
    return work.req.status == NVME_SUCCESS;
}

static bool cxl_op_holds(FemuCxlOp *op, uint64_t lpn)
{
    unsigned i;

    for (i = 0; i < op->nown; i++) {
        if (op->own[i] == lpn) {
            return true;
        }
    }
    return false;
}

/*
 * Entries a fill's eviction passes over: pages a stopped instruction of the
 * same vCPU still needs (see femu_cxl_protect()), the page it brings in,
 * which its own prefetch must not push out again, pages another access
 * holds, so the fill takes the victim cxl_fill_room() found, and pages
 * another vCPU protected within the protection window, whose instruction
 * may not have run again yet. If no victim is left, the fill keeps
 * nothing. The vCPU's own pages are passed over only by a fill with
 * keep_own: a page the vCPU faults on again at one RIP, so its instruction
 * may need both. Emulated accesses pass over nothing: each completes in its
 * exit, as in version 1, and keeping a page for an instruction would only
 * make them uncached.
 */
static bool cxl_keep(void *opaque, uint64_t lpn)
{
    FemuCxlOp *op = opaque;
    FemuCxlMedia *s = op->s;
    int64_t until = INT64_MAX;

    if (cxl_op_holds(op, lpn)) {
        return op->fill;
    }
    return (op->keep_own && cxl_protected(s, op->owner, lpn)) ||
           (op->fill && g_hash_table_contains(s->pages, &lpn)) ||
           (op->fill && cxl_protected_recently(s, op->owner, lpn,
                            qemu_clock_get_ns(QEMU_CLOCK_REALTIME), &until));
}

/*
 * Whether a fill of @lpn can insert it without charging media time for a
 * page that then cannot stay: a free way, or a victim that is neither kept
 * nor held by another access.
 */
static bool cxl_fill_room(FemuCxlMedia *s, FemuCxlOp *op, uint64_t lpn)
{
    FemuCxlSet *set = femu_cxl_cache_set(&s->cache, lpn);
    GQueue *queues[2];
    unsigned i;

    if (!set || set->small.length + set->main.length + set->pinned.length <
        s->cache.ways) {
        return true;
    }
    queues[0] = &set->small;
    queues[1] = &set->main;
    for (i = 0; i < 2; i++) {
        GList *l;

        for (l = queues[i]->head; l; l = l->next) {
            FemuCxlEntry *e = l->data;

            if (!cxl_keep(op, e->lpn) &&
                !g_hash_table_contains(s->pages, &e->lpn)) {
                return true;
            }
        }
    }
    return false;
}

/*
 * Whether a revocation for @op may take the mapping of @lpn before its
 * eviction: only where eviction itself could take the page now (see
 * cxl_keep()). Not a page that an access holds, that the operation holds,
 * that another vCPU protected within the protection window, or, for a
 * refault fill, that the operation's own vCPU protects. A vCPU keeps up to
 * 64 protection records for one RIP until it faults at another, so a loop
 * at one RIP would otherwise keep most of the cache out of every batch.
 */
bool femu_cxl_revoke_ahead_ok(FemuCxlMedia *s, FemuCxlOp *op, uint64_t lpn,
                              int64_t now)
{
    int64_t until = INT64_MAX;

    return !cxl_op_holds(op, lpn) &&
           !g_hash_table_contains(s->pages, &lpn) &&
           !(op->keep_own && cxl_protected(s, op->owner, lpn)) &&
           !cxl_protected_recently(s, op->owner, lpn, now, &until) &&
           !femu_cxl_ratio_selected(s->direct.ratio, lpn);
}

/*
 * Revoke the direct mapping of the victim @e. When that takes TLB flushes
 * and the direct mapping layer can share them (femu_cxl_der_batch()), it
 * also revokes the mappings of the pages the policy evicts next. Those stay
 * cached; an access maps them again as a hit. The mapping layer takes the
 * first of these candidates that are mapped and need the flushes.
 */
static void cxl_revoke(FemuCxlOp *op, FemuCxlEntry *e)
{
    FemuCxlMedia *s = op->s;
    unsigned room = femu_cxl_der_batch(&s->direct, e->lpn);
    FemuCxlEntry *next[2 * FEMU_CXL_REVOKE_BATCH_MAX];
    uint64_t ahead[2 * FEMU_CXL_REVOKE_BATCH_MAX];
    int64_t now = 0;
    unsigned found = 0;
    unsigned n = 0;
    unsigned i;

    room = MIN(room, FEMU_CXL_REVOKE_BATCH_MAX);
    if (room) {
        found = femu_cxl_cache_next_victims(&s->cache, e, next, 2 * room);
        now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    }
    for (i = 0; i < found; i++) {
        if (femu_cxl_revoke_ahead_ok(s, op, next[i]->lpn, now)) {
            ahead[n++] = next[i]->lpn;
        }
    }
    femu_cxl_der_remove_batch(&s->direct, e->lpn, ahead, n);
}

bool femu_cxl_evict(void *opaque, FemuCxlEntry *e)
{
    FemuCxlOp *op = opaque;
    FemuCxlMedia *s = op->s;
    bool own = cxl_op_holds(op, e->lpn);
    bool ok;

    /* Another access holds the page; keep it and let the caller go uncached. */
    if (!own && g_hash_table_contains(s->pages, &e->lpn)) {
        return false;
    }
    if (!femu_cxl_ratio_selected(s->direct.ratio, e->lpn)) {
        cxl_revoke(op, e);
    } else if (femu_cxl_der_sample(&s->direct, e->lpn)) {
        /* The ratio keeps the page mapped; charge writes made through it. */
        e->dirty = true;
    }
    if (!e->dirty || s->free_writeback) {
        return true;
    }
    /* The write-back drops the locks; accesses to the page wait for it. */
    if (own) {
        ok = femu_cxl_media(op, e->lpn, true);
    } else {
        g_hash_table_add(s->pages, &e->lpn);
        ok = femu_cxl_media(op, e->lpn, true);
        g_hash_table_remove(s->pages, &e->lpn);
        qemu_cond_broadcast(&s->idle);
    }
    /* A full NAND never keeps a page resident or sends an access uncached. */
    if (!ok) {
        cxl_media_full(s);
    }
    return true;
}

/*
 * Linked NVMe reads check these bits for DULBE and LBA status; a CXL store
 * writes those blocks too. Pollers read the bitmap concurrently.
 */
void femu_cxl_nvme_mark(FemuCxlMedia *s, uint64_t dpa, uint64_t len)
{
    NvmeNamespace *ns = s->nvme_ns;
    uint64_t lba;
    uint64_t end;

    if (!ns || !ns->util || !len || !ns->ns_blks) {
        return;
    }
    lba = dpa >> ns->lbaf.lbads;
    end = MIN((dpa + len - 1) >> ns->lbaf.lbads, ns->ns_blks - 1);
    if (lba <= end) {
        bitmap_set_atomic(ns->util, lba, end - lba + 1);
    }
}

/* Mark the ratio-selected pages in [first, last], one run at a time. */
void femu_cxl_nvme_mark_ratio(FemuCxlMedia *s, uint64_t first, uint64_t last)
{
    uint64_t period = femu_cxl_ratio_period(s->direct.ratio);
    uint64_t lpn = first;

    while (period && s->nvme_ns && lpn <= last) {
        uint64_t end = last;

        if (period != 1) {
            if (lpn % period == 0) {
                lpn++;
                continue;
            }
            end = MIN(last, lpn - lpn % period + period - 1);
        }
        femu_cxl_nvme_mark(s, lpn * 4096, (end - lpn + 1) * 4096);
        lpn = end + 1;
    }
}

/* The media delay drops the locks, so a decoder change may have intervened. */
static bool cxl_map(FemuCxlMedia *s, uint64_t generation, uint64_t hpa,
                    uint64_t dpa, FemuCxlEntry *e)
{
    if (s->invalidations != generation || s->closing ||
        !femu_cxl_der_map(&s->direct, hpa, dpa, e)) {
        return false;
    }
    /* Stores through the mapping never reach this device. */
    femu_cxl_nvme_mark(s, dpa & ~4095ULL, 4096);
    return true;
}

/*
 * A one-page fill without prefetch does nothing after its media read that
 * takes media time, so femu_cxl_media() may end its delay and check the frame
 * it maps while it is without the locks. An access that moves data inserts
 * its page after the read, which overlaps the delay instead.
 */
static void cxl_fold(FemuCxlMedia *s, FemuCxlOp *op, uint64_t lpn)
{
    op->fold = !s->fast_load && !s->prefetch_degree;
    if (op->fold) {
        femu_cxl_der_precheck(&s->direct, lpn);
    }
}

/*
 * A NULL @data fills the page without a transfer. @mapped, when given, says
 * whether the page is now mapped directly. @flags (FEMU_CXL_FILL_*) apply
 * to a fill: with KEEP_OWN it does not evict pages its vCPU protects; with
 * OVERFLOW a fill that cannot keep a way charges a read and maps the page
 * without one.
 */
static MemTxResult cxl_access(FemuCxlMedia *s, uint64_t hpa, uint64_t dpa,
                              uint64_t *data, unsigned size, bool write,
                              bool *mapped, unsigned flags)
{
    FemuCxlOp op = {
        .s = s, .demand = true, .fill = !data, .owner = cxl_owner(s),
        .keep_own = !data && (flags & FEMU_CXL_FILL_KEEP_OWN),
    };
    MemTxResult result = MEMTX_ERROR;
    uint64_t generation = s->invalidations;
    uint64_t pages[2];
    uint64_t first = dpa / 4096;
    uint64_t last;
    uint64_t lpn;
    int64_t start = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    int64_t remaining;
    unsigned holds = 0;
    bool over = false;
    unsigned i;

    assert(femu_cxl_locked());
    if (mapped) {
        *mapped = false;
    }
    if (!size || size > sizeof(*data) || dpa >= s->backend.size ||
        size > s->backend.size - dpa) {
        return MEMTX_ERROR;
    }
    last = (dpa + size - 1) / 4096;
    /*
     * Hold the pages, in ascending order, so accesses to a page stay ordered
     * and a second miss to it waits for the first fill instead of repeating it.
     */
    for (lpn = first; lpn <= last; lpn++) {
        pages[holds] = lpn;
        while (g_hash_table_contains(s->pages, &pages[holds])) {
            femu_cxl_wait(&s->idle);
        }
        g_hash_table_add(s->pages, &pages[holds++]);
    }
    op.own = pages;
    op.nown = holds;
    /* Media time starts once the pages are held, not while waiting for them. */
    op.start = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    /*
     * Checked again inside the gate: a fill authorised before a cache
     * disable or pin that it waited behind must not charge a read for a
     * page that cannot stay.
     */
    if (!data && !femu_cxl_admissible(s, first)) {
        result = MEMTX_OK;
        goto out;
    }
    /*
     * A fill that could not keep its page charges and counts nothing: the
     * caller hands the page to the emulator, which charges each access.
     */
    if (!data && s->cache.nsets &&
        !g_hash_table_contains(s->cache.entries, &first) &&
        !femu_cxl_ratio_selected(s->direct.ratio, first) &&
        !femu_cxl_cca_uncached(&s->cca, first) &&
        !femu_cxl_cache_all_pinned(&s->cache, first) &&
        !cxl_fill_room(s, &op, first)) {
        if (!(flags & FEMU_CXL_FILL_OVERFLOW) ||
            (!s->direct.cylon && !s->test_map)) {
            result = MEMTX_OK;
            goto out;
        }
        over = true;
    }
    if (!data && s->test_fill_race && s->cache.nsets) {
        FemuCxlSet *set = femu_cxl_cache_set(&s->cache, first);
        GList *l;

        s->test_fill_race = false;
        for (l = set->small.head; l; l = l->next) {
            femu_cxl_protect(s, op.owner, ((FemuCxlEntry *)l->data)->lpn);
        }
        for (l = set->main.head; l; l = l->next) {
            femu_cxl_protect(s, op.owner, ((FemuCxlEntry *)l->data)->lpn);
        }
    }
    for (lpn = first; lpn <= last; lpn++) {
        FemuCxlEntry *e = femu_cxl_cache_find(&s->cache, lpn);

        bool miss = !e;

        if (write) {
            s->write_hits += !miss;
            s->write_misses += miss;
        } else {
            s->read_hits += !miss;
            s->read_misses += miss;
        }
        if (!e) {
            /*
             * Without a cache, for an uncached page, or when every way of
             * the set is pinned, each access goes to the media.
             */
            bool uncached = femu_cxl_cca_uncached(&s->cca, lpn);
            bool to_media = !s->cache.nsets || uncached ||
                            femu_cxl_cache_all_pinned(&s->cache, lpn);

            if (s->cache.nsets && to_media && !uncached) {
                s->cca.pinned_set_misses++;
            }
            /*
             * A fill takes its way before the media read, which drops the
             * locks: nothing can take the victim meanwhile, and a page it
             * cannot keep is neither charged nor counted. The caller hands
             * that page to the emulator, which charges each access.
             */
            if (over) {
                /* Charged as a fill; writes through the mapping are not. */
                cxl_fold(s, &op, lpn);
                if (!femu_cxl_media(&op, lpn, false)) {
                    goto out;
                }
            } else if (!data && !to_media) {
                e = femu_cxl_cache_insert_keep(&s->cache, lpn, femu_cxl_evict,
                                               cxl_keep, &op);
                /* A ratio page maps without a cache entry. */
                if (!e && !femu_cxl_ratio_selected(s->direct.ratio, lpn)) {
                    s->read_misses--;
                    s->cache.misses--;
                    result = MEMTX_OK;
                    goto out;
                }
                cxl_fold(s, &op, lpn);
                if (!femu_cxl_media(&op, lpn, false)) {
                    femu_cxl_fill_failed(s, lpn, e);
                    goto out;
                }
            } else if (!femu_cxl_media(&op, lpn, write && to_media)) {
                /* Report failed reads; a failed program only loses timing. */
                if (!(write && to_media)) {
                    goto out;
                }
                cxl_media_full(s);
            }
            if (!to_media && data) {
                e = femu_cxl_cache_insert_keep(&s->cache, lpn, femu_cxl_evict,
                                               cxl_keep, &op);
                /* Only a held victim refuses the insert: go uncached. */
                if (!e && write && !femu_cxl_media(&op, lpn, true)) {
                    cxl_media_full(s);
                }
            }
        }
        if (e && write) {
            e->dirty = true;
        }
        if (e && miss) {
            uint64_t next;
            /* More than the cache holds only evicts what was just fetched. */
            uint64_t degree = MIN(s->prefetch_degree, s->cache_pages);
            uint64_t end = MIN(s->backend.size / 4096,
                              lpn + s->prefetch_stride + degree);

            for (next = lpn + s->prefetch_stride; next < end; next++) {
                FemuCxlEntry *prefetched;
                uint64_t next_hpa = hpa - dpa + next * 4096;
                /* The prefetch's own hold on @next; see below. */
                uint64_t held = next;

                /* A held page is being filled or written back. */
                if (g_hash_table_contains(s->cache.entries, &next) ||
                    g_hash_table_contains(s->pages, &next) ||
                    femu_cxl_cca_uncached(&s->cca, next) ||
                    femu_cxl_cache_all_pinned(&s->cache, next)) {
                    continue;
                }
                /*
                 * Hold @next across insertion, whose eviction write-back can
                 * drop the locks, and mapping: a demand fill of it waits, so a
                 * prefetch never maps a page another access is filling.
                 */
                g_hash_table_add(s->pages, &held);
                if (s->test_prefetch_race == next + 1) {
                    s->test_prefetch_race = 0;
                    if (!g_hash_table_contains(s->pages, &next)) {
                        s->test_race_lpn = next;
                        g_hash_table_add(s->pages, &s->test_race_lpn);
                        femu_cxl_cache_insert(&s->cache, next, NULL, NULL);
                        s->test_race_active = true;
                    }
                }
                prefetched = femu_cxl_cache_insert_keep(&s->cache, next,
                                                        femu_cxl_evict,
                                                        cxl_keep, &op);
                /* A prefetch is optional; never fail the demand access. */
                if (!prefetched) {
                    g_hash_table_remove(s->pages, &held);
                    qemu_cond_broadcast(&s->idle);
                    break;
                }
                s->prefetch_inserts++;
                if (cxl_map(s, generation, next_hpa, next * 4096, NULL) &&
                    !s->direct.cylon) {
                    prefetched->dirty = true;
                }
                g_hash_table_remove(s->pages, &held);
                qemu_cond_broadcast(&s->idle);
            }
        }
        s->cache_entries = g_hash_table_size(s->cache.entries);
    }
    remaining = op.ns - (qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - op.start);
    /* Fast load leaves the media time on the NAND timelines, not the vCPU. */
    if (remaining > 0 && !s->fast_load) {
        femu_cxl_delay(remaining);
    }
    /* Unplugged during the wait: the backend may already serve a new device. */
    if (s->closing) {
        goto out;
    }
    if (!data) {
        /* A fill moves no data. */
    } else if (write) {
        memcpy((uint8_t *)s->backend.logical_space + dpa, data, size);
        femu_cxl_nvme_mark(s, dpa, size);
    } else {
        memcpy(data, (uint8_t *)s->backend.logical_space + dpa, size);
    }
    if (first == last && (s->cache.nsets || s->direct.ratio)) {
        FemuCxlEntry *e = g_hash_table_lookup(s->cache.entries, &first);
        bool direct = (e || over ||
                       femu_cxl_ratio_selected(s->direct.ratio, first)) &&
                      !femu_cxl_cca_uncached(&s->cca, first) &&
                      cxl_map(s, generation, hpa, dpa, e);

        if (direct && !s->direct.cylon && e) {
            /* Direct writes cannot update metadata, so charge on eviction. */
            e->dirty = true;
        }
        if (mapped) {
            *mapped = direct || (s->test_map && (e || over) &&
                                 !femu_cxl_cca_uncached(&s->cca, first));
        }
    }
    if (s->io_log) {
        /* A fill logs as a read of size 0. */
        int n = fprintf(s->io_log, "%" PRId64 ",%c,%" PRIu64 ",%u,%" PRIu64
                        "\n", start, write ? 'W' : 'R', dpa,
                        data ? size : 0, op.ns);

        s->io_log_bytes += MAX(n, 0);
        /* Close at the limit; the guest can open a new file. */
        if (s->io_log_bytes >= s->log_limit) {
            fclose(s->io_log);
            s->io_log = NULL;
            s->log_dropped++;
        }
    }
    result = MEMTX_OK;
out:
    femu_cxl_der_precheck_drop();
    /* A failed fill may have evicted or removed an entry. */
    if (s->cache.entries) {
        s->cache_entries = g_hash_table_size(s->cache.entries);
    }
    for (i = 0; i < holds; i++) {
        g_hash_table_remove(s->pages, &pages[i]);
    }
    qemu_cond_broadcast(&s->idle);
    return result;
}

MemTxResult femu_cxl_access(FemuCxlMedia *s, uint64_t hpa, uint64_t dpa,
                            uint64_t *data, unsigned size, bool write)
{
    return cxl_access(s, hpa, dpa, data, size, write, NULL, 0);
}

/*
 * Bring the page at @dpa in as a read miss would (cache insert, media time,
 * delay, counters) and map it directly, without moving data to a register.
 * The guest then repeats the access natively. The fill counts as a read:
 * a store through the new mapping shows up in the EPT dirty bit when the
 * page is revoked.
 */
MemTxResult femu_cxl_fill(FemuCxlMedia *s, uint64_t hpa, uint64_t dpa,
                          bool *mapped, unsigned flags)
{
    return cxl_access(s, hpa & ~4095ULL, dpa & ~4095ULL, NULL, 1, false,
                      mapped, flags);
}

/*
 * A fill whose media read failed drops the entry it took, and first revokes
 * any direct mapping of the page, so none outlives the entry.
 */
void femu_cxl_fill_failed(FemuCxlMedia *s, uint64_t lpn, FemuCxlEntry *e)
{
    if (e) {
        femu_cxl_der_remove(&s->direct, lpn);
        femu_cxl_cache_remove(&s->cache, e, NULL, NULL);
    }
}

/*
 * Whether a fill of @lpn can end with a direct mapping, before any media
 * time is charged. A held victim shows only during a fill.
 */
bool femu_cxl_admissible(FemuCxlMedia *s, uint64_t lpn)
{
    assert(femu_cxl_locked());
    if (femu_cxl_cca_uncached(&s->cca, lpn)) {
        return false;
    }
    if (g_hash_table_contains(s->cache.entries, &lpn) ||
        femu_cxl_ratio_selected(s->direct.ratio, lpn)) {
        return true;
    }
    return s->cache.nsets && !femu_cxl_cache_all_pinned(&s->cache, lpn);
}

typedef enum FemuCxlFillState {
    FEMU_CXL_FILL_READY,
    FEMU_CXL_FILL_WAIT,
    FEMU_CXL_FILL_BLOCKED,
} FemuCxlFillState;

/*
 * Whether a fill of @lpn by vCPU @owner can keep its page now (a free way or
 * an evictable victim), only after other accesses end or recent protections
 * of other vCPUs expire (lowering @until to the earliest expiry), or not at
 * all (every candidate victim is protected by @owner, or the set is pinned).
 */
static FemuCxlFillState cxl_fill_state(FemuCxlMedia *s, int owner,
                                       uint64_t lpn, int64_t now,
                                       int64_t *until, bool keep_own)
{
    FemuCxlSet *set = femu_cxl_cache_set(&s->cache, lpn);
    GQueue *queues[2];
    bool wait = false;
    unsigned i;

    if (!set || femu_cxl_cache_all_pinned(&s->cache, lpn)) {
        return FEMU_CXL_FILL_BLOCKED;
    }
    if (g_hash_table_contains(s->cache.entries, &lpn) ||
        set->small.length + set->main.length + set->pinned.length <
        s->cache.ways) {
        return FEMU_CXL_FILL_READY;
    }
    queues[0] = &set->small;
    queues[1] = &set->main;
    for (i = 0; i < 2; i++) {
        GList *l;

        for (l = queues[i]->head; l; l = l->next) {
            FemuCxlEntry *e = l->data;

            if (keep_own && cxl_protected(s, owner, e->lpn)) {
                continue;
            }
            if (g_hash_table_contains(s->pages, &e->lpn) ||
                cxl_protected_recently(s, owner, e->lpn, now, until)) {
                wait = true;
                continue;
            }
            return FEMU_CXL_FILL_READY;
        }
    }
    return wait ? FEMU_CXL_FILL_WAIT : FEMU_CXL_FILL_BLOCKED;
}

/*
 * Whether a fill of @lpn by the current vCPU keeps nothing because pages
 * that the same vCPU protects hold every way of the set that is not pinned:
 * the instruction's own pages do not fit. CXL lock.
 */
bool femu_cxl_fill_conflict(FemuCxlMedia *s, uint64_t lpn)
{
    FemuCxlSet *set = femu_cxl_cache_set(&s->cache, lpn);
    int64_t until = INT64_MAX;

    return set && s->started && !s->closing &&
           !femu_cxl_cache_all_pinned(&s->cache, lpn) &&
           set->small.length + set->main.length > 0 &&
           cxl_fill_state(s, cxl_owner(s), lpn,
                          qemu_clock_get_ns(QEMU_CLOCK_REALTIME), &until,
                          true) == FEMU_CXL_FILL_BLOCKED;
}

/*
 * A fill of @lpn kept nothing. Wait, at most until @deadline
 * (QEMU_CLOCK_REALTIME ns), while the only obstacles are other accesses
 * holding the set's pages or recent protections of other vCPUs. Returns
 * true when a new fill can keep the page, false when it cannot, the wait
 * timed out, or the device was reset, invalidated or closed meanwhile.
 * CXL lock; the caller holds no page and is outside the gate.
 */
bool femu_cxl_fill_wait(FemuCxlMedia *s, uint64_t lpn, int64_t deadline,
                        bool keep_own)
{
    uint64_t generation = s->invalidations;
    int owner = cxl_owner(s);

    assert(femu_cxl_locked());
    for (;;) {
        int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        int64_t until = deadline;

        /* Teardown frees the cache while this waits outside the gate. */
        if (s->closing || !s->started || s->invalidations != generation) {
            return false;
        }
        switch (cxl_fill_state(s, owner, lpn, now, &until, keep_own)) {
        case FEMU_CXL_FILL_READY:
            return true;
        case FEMU_CXL_FILL_BLOCKED:
            return false;
        default:
            break;
        }
        if (now >= deadline) {
            return false;
        }
        /* A holder broadcasts when it ends; an expiry needs the timeout. */
        femu_cxl_timedwait(&s->idle,
            MAX(1, DIV_ROUND_UP(MIN(until, deadline) - now, SCALE_MS)));
    }
}

/*
 * Keep @lpn in the cache while an instruction of vCPU @owner that faulted on
 * it may still need it: a fill for another page of the same instruction must
 * not evict it, or the instruction never completes. The protection lasts
 * until @owner exits again, which for an idle vCPU can be much later, and
 * with one way it would close the set to every other vCPU. So other vCPUs'
 * fills pass over it only within the protection window, which usually
 * outlasts @owner's retry of the instruction (best effort, not a proof of
 * retirement), and their emulated accesses not at all (they complete in one
 * exit). Counted, for repeated protection.
 */
void femu_cxl_protect(FemuCxlMedia *s, int owner, uint64_t lpn)
{
    FemuCxlGuard *g;

    assert(femu_cxl_locked());
    if (!s->protect) {
        s->protect = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                           g_free,
                                           (GDestroyNotify)g_array_unref);
    }
    g = cxl_guard(s, owner, lpn);
    if (!g) {
        GArray *guards = g_hash_table_lookup(s->protect, &lpn);
        FemuCxlGuard fresh = { .owner = owner };

        if (!guards) {
            guards = g_array_new(false, false, sizeof(FemuCxlGuard));
            g_hash_table_insert(s->protect, g_memdup2(&lpn, sizeof(lpn)),
                                guards);
        }
        g_array_append_val(guards, fresh);
        g = &g_array_index(guards, FemuCxlGuard, guards->len - 1);
    }
    g->count++;
    g->since = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
}

/*
 * Overflow mappings: a page mapped without a cache way, held by one or more
 * vCPUs for an instruction. The last holder unmaps it, unless a fill has
 * since given it a cache way or a ratio maps it: the mapping then belongs
 * to them.
 */
void femu_cxl_overflow_add(FemuCxlMedia *s, uint64_t lpn)
{
    gpointer count;

    if (!s->overflow) {
        s->overflow = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                            g_free, NULL);
    }
    count = g_hash_table_lookup(s->overflow, &lpn);
    g_hash_table_replace(s->overflow, g_memdup2(&lpn, sizeof(lpn)),
                         GUINT_TO_POINTER(GPOINTER_TO_UINT(count) + 1));
}

static void cxl_overflow_unmap(FemuCxlMedia *s, uint64_t lpn)
{
    if (s->started && !s->closing &&
        !g_hash_table_contains(s->cache.entries, &lpn) &&
        !femu_cxl_ratio_selected(s->direct.ratio, lpn)) {
        femu_cxl_der_remove(&s->direct, lpn);
    }
}

void femu_cxl_overflow_release(FemuCxlMedia *s, uint64_t lpn)
{
    guint count = s->overflow ?
        GPOINTER_TO_UINT(g_hash_table_lookup(s->overflow, &lpn)) : 0;

    if (count > 1) {
        g_hash_table_replace(s->overflow, g_memdup2(&lpn, sizeof(lpn)),
                             GUINT_TO_POINTER(count - 1));
    } else if (count) {
        g_hash_table_remove(s->overflow, &lpn);
        cxl_overflow_unmap(s, lpn);
    }
}

/*
 * Range invalidation (CACHE_DISABLE, INVALIDATE, a linked NVMe write) finds
 * mappings through cache entries; overflow pages have none, so unmap them
 * here. Their holders still release them later.
 */
void femu_cxl_overflow_drop(FemuCxlMedia *s, uint64_t first, uint64_t last)
{
    GHashTableIter it;
    gpointer key;

    if (!s->overflow) {
        return;
    }
    g_hash_table_iter_init(&it, s->overflow);
    while (g_hash_table_iter_next(&it, &key, NULL)) {
        uint64_t lpn = *(uint64_t *)key;

        if (lpn >= first && lpn <= last) {
            cxl_overflow_unmap(s, lpn);
        }
    }
}

/* @owner filled @lpn again for the same instruction: restart its window. */
void femu_cxl_protect_renew(FemuCxlMedia *s, int owner, uint64_t lpn)
{
    FemuCxlGuard *g = cxl_guard(s, owner, lpn);

    if (g) {
        g->since = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    }
}

void femu_cxl_unprotect(FemuCxlMedia *s, int owner, uint64_t lpn)
{
    GArray *guards = s->protect ? g_hash_table_lookup(s->protect, &lpn) : NULL;
    unsigned i;

    for (i = 0; guards && i < guards->len; i++) {
        FemuCxlGuard *g = &g_array_index(guards, FemuCxlGuard, i);

        if (g->owner != owner) {
            continue;
        }
        if (--g->count == 0) {
            g_array_remove_index_fast(guards, i);
        }
        if (!guards->len) {
            g_hash_table_remove(s->protect, &lpn);
        }
        return;
    }
}

/*
 * When the modelled NAND goes idle: the latest LUN and channel busy-until
 * time and the end of every booked data-out window. Caller holds @lock.
 */
static uint64_t cxl_timing_horizon(struct ssd *ssd)
{
    uint64_t end = 0;
    int i;
    int j;

    for (i = 0; i < ssd->sp.nchs; i++) {
        struct ssd_channel *ch = &ssd->ch[i];

        end = MAX(end, ch->next_ch_avail_time);
        for (j = 0; j < ch->nluns; j++) {
            end = MAX(end, ch->lun[j].next_lun_avail_time);
        }
        if (ssd->media.bus_res) {
            NandBusResList *l = &ssd->media.bus_res[i];

            for (j = 0; j < l->n; j++) {
                end = MAX(end, l->r[j].end);
            }
        }
    }
    return end;
}

/*
 * Wait out the NAND work that accesses left queued while they skipped their
 * completion wait, and return how long that took. The caller holds the gate
 * alone, so no access adds to it; a linked controller still can.
 */
uint64_t femu_cxl_drain(FemuCxlMedia *s)
{
    uint64_t end;
    int64_t now;

    if (!s->ftl) {
        return 0;
    }
    qemu_mutex_lock(&s->lock);
    end = cxl_timing_horizon(s->ns.ssd);
    qemu_mutex_unlock(&s->lock);
    now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    if (end <= now) {
        return 0;
    }
    femu_cxl_delay(end - now);
    return qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - now;
}

/*
 * Whether @blocks lines leave at least two spare lines more than forced
 * collection keeps free. Collection then always finds a line with an invalid
 * page and room to move its valid ones, so a write never finds NAND full.
 * With less, the spare space would sit in the reserve: every write would copy
 * a nearly full line, and with none every program after the first fill fails.
 * The reserve is computed as bb_gc_forced_lines() computes it.
 */
static bool cxl_spare_enough(FemuCxlMedia *s, uint64_t size, uint64_t line,
                             uint32_t blocks)
{
    uint64_t reserve = (uint64_t)((1 - s->gc_threshold_high / 100.0) * blocks);

    return line * blocks >= size / 4096 + (reserve + 2) * line;
}

bool femu_cxl_geometry(FemuCxlMedia *s, uint64_t size, Error **errp)
{
    uint64_t pages;
    uint64_t line;
    uint64_t limit;
    uint32_t need;

    if (!s->channels || s->channels > (1 << CH_BITS) ||
        !s->luns_per_channel || s->luns_per_channel > (1 << LUN_BITS) ||
        !s->pages_per_block || s->pages_per_block > (1 << PG_BITS) ||
        s->blocks_per_plane > (1 << BLK_BITS) ||
        !s->gc_threshold || s->gc_threshold > 100 ||
        s->gc_threshold_high < s->gc_threshold || s->gc_threshold_high > 100 ||
        s->channel_ns > NANOSECONDS_PER_SECOND) {
        error_setg(errp, "invalid NAND geometry, GC thresholds or timing");
        return false;
    }
    line = (uint64_t)s->channels * s->luns_per_channel * s->pages_per_block;
    if (!s->blocks_per_plane) {
        s->blocks_per_plane = DIV_ROUND_UP(size / 4096 * 5 / 4, line) + 4;
        while (s->ftl && s->blocks_per_plane < (1 << BLK_BITS) &&
               line * (s->blocks_per_plane + 1) <= INT_MAX / 8 &&
               !cxl_spare_enough(s, size, line, s->blocks_per_plane)) {
            s->blocks_per_plane++;
        }
    }
    pages = line * s->blocks_per_plane;
    if (s->blocks_per_plane > (1 << BLK_BITS) || pages > INT_MAX / 8 ||
        pages < size / 4096 || s->blocks_per_plane < 2) {
        error_setg(errp, "NAND geometry must cover media and fit FTL limits");
        return false;
    }
    if (!s->ftl || cxl_spare_enough(s, size, line, s->blocks_per_plane)) {
        return true;
    }
    /* The smallest count that also stays within the FTL page limit. */
    limit = MIN(1 << BLK_BITS, INT_MAX / 8 / line);
    need = s->blocks_per_plane;
    while (need < limit && !cxl_spare_enough(s, size, line, need)) {
        need++;
    }
    if (!cxl_spare_enough(s, size, line, need)) {
        error_setg(errp, "NAND geometry leaves too little over-provisioning "
                   "for garbage collection at any blocks-per-plane; raise "
                   "gc-threshold-high or use fewer pages per line");
        return false;
    }
    error_setg(errp, "NAND geometry leaves too little over-provisioning for "
               "garbage collection: blocks-per-plane must be at least %u "
               "with gc-threshold-high=%u", need, s->gc_threshold_high);
    return false;
}

/* Queue [slba, slba + nlb) of @ns for dropping; called under @lock. */
static bool cxl_nvme_record(FemuCxlMedia *s, NvmeNamespace *ns, uint64_t slba,
                            uint64_t nlb)
{
    uint64_t off = slba << ns->lbaf.lbads;
    FemuCxlRange r = {
        .first = off / 4096,
        .last = (off + (nlb << ns->lbaf.lbads) - 1) / 4096,
    };

    if (nlb) {
        g_array_append_val(s->nvme_ranges, r);
    }
    return nlb;
}

/*
 * Run a linked NVMe request on the medium's FTL. The medium's worker holds
 * @lock for each of its requests, so the two never interleave. The pollers'
 * pause waits for this thread, so it must never need the BQL; the cache is
 * updated later by a main-loop bottom half instead.
 */
uint64_t femu_cxl_nvme_ftl(FemuCtrl *n, NvmeNamespace *ns, NvmeRequest *req)
{
    FemuCxlMedia *s = n->cxl_media;
    const NvmeRwCmd *rw = (const NvmeRwCmd *)&req->cmd;
    bool recorded = false;
    uint64_t lat;
    int i;

    assert(!bql_locked());
    qemu_mutex_lock(&s->lock);
    /*
     * The poller already changed the payload, whatever the FTL decides.
     * Record from the command: the FTL frees DSM ranges as it trims.
     */
    switch (req->status == NVME_SUCCESS ? req->cmd.opcode : 0) {
    case NVME_CMD_WRITE:
    case NVME_CMD_WRITE_ZEROES:
        recorded = cxl_nvme_record(s, ns, le64_to_cpu(rw->slba),
                                   le16_to_cpu(rw->nlb) + 1);
        break;
    case NVME_CMD_COPY:
        recorded = cxl_nvme_record(s, ns, le32_to_cpu(req->cmd.cdw10) |
                                   (uint64_t)le32_to_cpu(req->cmd.cdw11) << 32,
                                   req->nlb);
        break;
    case NVME_CMD_DSM:
        for (i = 0; req->dsm_ranges && i < req->dsm_nr_ranges; i++) {
            recorded |= cxl_nvme_record(s, ns,
                                        le64_to_cpu(req->dsm_ranges[i].slba),
                                        le32_to_cpu(req->dsm_ranges[i].nlb));
        }
        break;
    default:
        break;
    }
    /* The request completes once the bottom half took this batch. */
    if (recorded) {
        req->cxl_seq = s->nvme_taken + 1;
    }
    lat = cxl_ftl_request(s, n, ns, req);
    qemu_mutex_unlock(&s->lock);
    if (req->cxl_seq) {
        qemu_bh_schedule(s->nvme_bh);
    }
    return lat;
}

/* Revoking page by page costs two VM-wide flushes each under Cylon. */
#define FEMU_CXL_NVME_CLEAR 64

/*
 * The NVMe command already programmed or unmapped these pages, so a cached
 * copy must not be written back: that would program them twice, or map a
 * deallocated page again. Revoke direct mappings first so Cylon's dirty
 * sample is discarded with the entry. Pinned pages stay resident and pinned,
 * as the caching API promised, but clean.
 */
static void cxl_nvme_drop(FemuCxlMedia *s, uint64_t first, uint64_t last)
{
    g_autoptr(GPtrArray) victims = g_ptr_array_new();
    uint64_t pages = s->backend.size / 4096;
    FemuCxlEntry *e;
    uint64_t lpn;
    bool clear;
    guint i;

    if (first >= pages) {
        return;
    }
    last = MIN(last, pages - 1);
    /* A clear would also revoke ratio mappings, which rule 1 keeps. */
    clear = last - first + 1 > FEMU_CXL_NVME_CLEAR && s->direct.mapped &&
            !s->direct.ratio;
    if (clear) {
        femu_cxl_der_clear(&s->direct);
    } else {
        femu_cxl_overflow_drop(s, first, last);
    }
    if (last - first + 1 <= g_hash_table_size(s->cache.entries)) {
        for (lpn = first; lpn <= last; lpn++) {
            e = g_hash_table_lookup(s->cache.entries, &lpn);
            if (e) {
                g_ptr_array_add(victims, e);
            }
        }
    } else {
        GHashTableIter it;
        gpointer value;

        g_hash_table_iter_init(&it, s->cache.entries);
        while (g_hash_table_iter_next(&it, NULL, &value)) {
            e = value;
            if (e->lpn >= first && e->lpn <= last) {
                g_ptr_array_add(victims, e);
            }
        }
    }
    /*
     * Stores through a ratio alias never trap, so a Deallocate cannot learn
     * that selected pages are written again; keep them marked written.
     */
    femu_cxl_nvme_mark_ratio(s, first, last);
    for (i = 0; i < victims->len; i++) {
        e = g_ptr_array_index(victims, i);
        if (!clear && !femu_cxl_ratio_selected(s->direct.ratio, e->lpn)) {
            femu_cxl_der_remove(&s->direct, e->lpn);
        }
        s->nvme_drops++;
        if (e->queue == FEMU_CXL_PINNED) {
            e->dirty = false;
        } else {
            femu_cxl_cache_remove(&s->cache, e, NULL, NULL);
        }
    }
}

/*
 * Apply what linked NVMe writes replaced. Invalidation never waits for the
 * gate: when it is taken, the holder reschedules this as it leaves.
 */
void femu_cxl_nvme_bh(void *opaque)
{
    FemuCxlMedia *s = opaque;
    GArray *ranges;
    uint64_t done;
    guint i;
    FEMU_CXL_LOCK_GUARD();

    if (s->busy || s->accesses) {
        s->nvme_kick = true;
        return;
    }
    femu_cxl_enter(s);
    qemu_mutex_lock(&s->lock);
    ranges = s->nvme_ranges;
    s->nvme_ranges = g_array_new(false, false, sizeof(FemuCxlRange));
    done = ++s->nvme_taken;
    qemu_mutex_unlock(&s->lock);
    if (!s->direct.cylon) {
        memory_region_transaction_begin();
    }
    for (i = 0; i < ranges->len; i++) {
        FemuCxlRange *r = &g_array_index(ranges, FemuCxlRange, i);

        cxl_nvme_drop(s, r->first, r->last);
    }
    if (!s->direct.cylon) {
        memory_region_transaction_commit();
    }
    g_array_free(ranges, true);
    s->cache_entries = g_hash_table_size(s->cache.entries);
    qemu_mutex_lock(&s->lock);
    s->media_writes = ssd_nand_write_pages(s->ns.ssd);
    s->gc_stalls = s->ftl_gc_stalls;
    s->gc_stall_ns = s->ftl_gc_stall_ns;
    qemu_mutex_unlock(&s->lock);
    qatomic_store_release(&s->nvme_done, done);
    femu_cxl_leave(s);
}

/*
 * Flip from the linked controller. The timings are shared with the medium's
 * worker, which reads them under @lock. Restoring delays uses the values this
 * device was configured with, not the compile-time defaults.
 */
void femu_cxl_nvme_flip(FemuCtrl *n, int64_t cdw10)
{
    FemuCxlMedia *s = n->cxl_media;
    struct ssdparams *sp = &s->ns.ssd->sp;
    bool zero = cdw10 == FEMU_DISABLE_DELAY_EMU;

    qemu_mutex_lock(&s->lock);
    switch (cdw10) {
    case FEMU_ENABLE_GC_DELAY:
    case FEMU_DISABLE_GC_DELAY:
        sp->enable_gc_delay = cdw10 == FEMU_ENABLE_GC_DELAY;
        break;
    case FEMU_ENABLE_DELAY_EMU:
    case FEMU_DISABLE_DELAY_EMU:
        sp->pg_rd_lat = zero ? 0 : s->read_ns;
        sp->pg_wr_lat = zero ? 0 : s->program_ns;
        sp->blk_er_lat = zero ? 0 : s->erase_ns;
        sp->ch_xfer_lat = zero ? 0 : s->channel_ns;
        bb_nand_media_refresh_timing(s->ns.ssd);
        break;
    default:
        break;
    }
    qemu_mutex_unlock(&s->lock);
}

void femu_cxl_start(FemuCxlMedia *s, void *payload, uint64_t size,
                     FemuCxlPolicy policy)
{
    FemuCtrl *n;
    BbCtrlParams *p;

    s->backend.size = size;
    s->backend.logical_space = payload;
    /*
     * A linked controller copies through backend_rw(), which takes a zero
     * mode for OCSSD and reads one offset per scatter entry: every transfer
     * past one page then read its offsets from beyond the caller's one.
     */
    s->backend.femu_mode = FEMU_BBSSD_MODE;
    femu_cxl_cache_init(&s->cache, s->cache_pages, s->cache_ways, policy);
    if (!s->ftl) {
        return;
    }
    s->ctrl = n = g_new0(FemuCtrl, 1);
    n->mbe = &s->backend;
    p = &n->bb_params;
    p->secsz = 512;
    p->secs_per_pg = 8;
    p->pgs_per_blk = s->pages_per_block;
    p->blks_per_pl = s->blocks_per_plane;
    p->pls_per_lun = 1;
    p->luns_per_ch = s->luns_per_channel;
    p->nchs = s->channels;
    p->pg_rd_lat = s->read_ns;
    p->pg_wr_lat = s->program_ns;
    p->blk_er_lat = s->erase_ns;
    p->ch_xfer_lat = s->channel_ns;
    p->gc_thres_pcent = s->gc_threshold;
    p->gc_thres_pcent_high = s->gc_threshold_high;
    s->ns.ctrl = n;
    s->ns.lbaf.lbads = 9;
    s->ns.ssd = g_new0(struct ssd, 1);
    pstrcpy(n->devname, sizeof(n->devname), "femu-cxl-ssd");
    s->ns.ssd->ssdname = n->devname;
    ssd_init(n, &s->ns);
    qemu_mutex_init(&s->lock);
    qemu_cond_init(&s->worker_cond);
    QSIMPLEQ_INIT(&s->work);
    s->nvme_ranges = g_array_new(false, false, sizeof(FemuCxlRange));
    s->stopping = false;
    qemu_thread_create(&s->worker, "femu-cxl-ftl", cxl_worker, s,
                       QEMU_THREAD_JOINABLE);
}

void femu_cxl_stop(FemuCxlMedia *s)
{
    FemuCtrl *nvme = s->nvme;
    bool resume = false;

    if (!s->ftl) {
        s->started = false;
        femu_cxl_cache_destroy(&s->cache);
        return;
    }
    /*
     * A guest can power the slot off without asking management, which
     * skips the unplug blocker. Quiesce a linked controller so nothing is
     * in the FTL, then leave the FTL and payload to it.
     */
    if (nvme) {
        resume = nvme_pause_pollers(nvme);
    }
    /*
     * Each request waits on a condition variable on its caller's stack,
     * which stop cannot reach, so no request may be outstanding here. The
     * gate guarantees it: teardown leaves the media to the last holder.
     */
    qemu_mutex_lock(&s->lock);
    assert(QSIMPLEQ_EMPTY(&s->work));
    s->stopping = true;
    qemu_cond_signal(&s->worker_cond);
    qemu_mutex_unlock(&s->lock);
    qemu_thread_join(&s->worker);
    qemu_cond_destroy(&s->worker_cond);
    qemu_mutex_destroy(&s->lock);
    g_clear_pointer(&s->nvme_bh, qemu_bh_delete);
    g_array_free(s->nvme_ranges, true);
    s->nvme_ranges = NULL;
    s->started = false;
    femu_cxl_cache_destroy(&s->cache);
    if (nvme) {
        qatomic_set(&nvme->cxl_done, NULL);
        nvme->cxl_media = NULL;
        s->nvme_ns = NULL;
        s->nvme_owns_ftl = true;
        nvme_resume_pollers(nvme, resume);
        return;
    }
    ssd_free(s->ns.ssd);
    g_free(s->ns.ssd);
    g_free(s->ctrl);
}
