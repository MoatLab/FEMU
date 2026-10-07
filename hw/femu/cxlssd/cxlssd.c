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
/*
 * Whether a thread may take the CXL lock without the BQL: set under the BQL
 * by femu_cxl_lock_bql_free(), never cleared. Until then every holder also
 * holds the BQL, which already serializes them, so a hold only counts its
 * depth and a wait sleeps on the BQL, as before the lock existed. Version 1
 * accesses, which always arrive under the BQL, then pay nothing for it.
 */
static bool cxl_lock_live;
/* How many times this thread holds the CXL lock. */
static __thread unsigned cxl_lock_depth;
/* Whether this thread's hold owns @cxl_lock or only the BQL. */
static __thread bool cxl_lock_owned;
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

/* Take the mutex if threads without the BQL can hold the lock. */
static void cxl_lock_own(void)
{
    cxl_lock_owned = qatomic_load_acquire(&cxl_lock_live);
    if (cxl_lock_owned) {
        qemu_mutex_lock(&cxl_lock);
    } else {
        assert(bql_locked());
    }
}

static void cxl_lock_disown(void)
{
    if (cxl_lock_owned) {
        cxl_lock_owned = false;
        qemu_mutex_unlock(&cxl_lock);
    }
}

void femu_cxl_lock(void)
{
    if (!cxl_lock_depth++) {
        cxl_lock_own();
    }
}

void femu_cxl_unlock(void)
{
    assert(cxl_lock_depth);
    if (!--cxl_lock_depth) {
        cxl_lock_disown();
    }
}

bool femu_cxl_locked(void)
{
    return cxl_lock_depth;
}

bool femu_cxl_lock_is_bql_free(void)
{
    return qatomic_load_acquire(&cxl_lock_live);
}

/*
 * From now on the CXL lock is a mutex, so a thread without the BQL can take
 * it. Called under the BQL, so no other thread holds the lock (its holders
 * hold the BQL) and none is about to wait on the BQL for a condition. A
 * thread already asleep in such a wait wakes on the caller's broadcast of
 * the condition (see femu_cxl_wait()) and owns the mutex after it.
 */
void femu_cxl_lock_bql_free(void)
{
    assert(bql_locked());
    if (cxl_lock_live) {
        return;
    }
    qatomic_store_release(&cxl_lock_live, true);
    if (cxl_lock_depth) {
        cxl_lock_own();
    }
}

/*
 * A wait releases the BQL. Inside a device's re-entrancy guard the device
 * would then refuse other threads' accesses as re-entrant, so such accesses
 * never wait (femu_cxl_access_nowait()). Debug builds check that no path
 * breaks this; the check costs a call, so release builds skip it.
 */
static inline void cxl_wait_check(void)
{
#ifdef FEMU_FTL_ASSERT
    if (qemu_in_guarded_io()) {
        error_report("femu-cxl-ssd: a wait inside a device's re-entrancy "
                     "guard");
        abort();
    }
#endif
}

void femu_cxl_drop(FemuCxlHeld *held)
{
    assert(cxl_lock_depth);
    cxl_wait_check();
    held->depth = cxl_lock_depth;
    held->bql = bql_locked();
    cxl_lock_depth = 0;
    cxl_lock_disown();
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
    cxl_lock_own();
    cxl_lock_depth = held->depth;
}

/*
 * The condition wait releases the lock it sleeps on atomically: @cxl_lock,
 * or the BQL while the CXL lock is not a mutex yet. A thread that holds both
 * lets the BQL go first and takes it back before the CXL lock, in lock
 * order. Its caller rechecks its condition in a loop either way.
 */
static void cxl_wait(QemuCond *cond, int ms)
{
    unsigned depth = cxl_lock_depth;
    bool bql = bql_locked();

    assert(depth);
    cxl_wait_check();
    cxl_lock_depth = 0;
    if (!cxl_lock_owned) {
        assert(bql);
        if (ms < 0) {
            qemu_cond_wait_bql(cond);
        } else {
            qemu_cond_timedwait_bql(cond, ms);
        }
        cxl_lock_own();
        cxl_lock_depth = depth;
        return;
    }
    if (bql) {
        bql_unlock();
    }
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

/*
 * Leave the teardown in @release to a bottom half, which takes the gate
 * alone. Teardown stops the worker, which can be in a long collection, and
 * a thread inside a device's re-entrancy guard must not wait for that.
 */
void femu_cxl_release_later(FemuCxlMedia *s)
{
    assert(femu_cxl_locked() && s->release);
    if (!s->release_scheduled) {
        s->release_scheduled = true;
        object_ref(s->owner);
        aio_bh_schedule_oneshot(qemu_get_aio_context(), cxl_release_bh, s);
    }
}

/* The last one out of the gate runs what was deferred to it. */
static void cxl_gate_idle(FemuCxlMedia *s)
{
    /*
     * Teardown deferred by an unplug runs while the gate is still held. It
     * stops threads and deletes the memory listener, which needs the BQL. A
     * thread without it leaves the gate open and the teardown to a bottom
     * half: holding the gate for the main loop would make a vCPU wait for
     * it, and the main loop may be pausing vCPUs. So does a thread inside
     * a device's re-entrancy guard (see femu_cxl_release_later()).
     */
    if (s->release && (!bql_locked() || qemu_in_guarded_io())) {
        femu_cxl_release_later(s);
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

/* Over-provisioning that keeps forced collection stalls short. */
#define FEMU_CXL_OP_PERCENT 7

/*
 * Report the first stall over a second, once per device. Such stalls
 * usually mean little spare NAND: nearly every line that collection takes
 * is still full of valid pages. With enough spare NAND, the NAND timing or
 * queued NAND work sets them. Under the CXL lock and the BQL, from the main
 * loop: the FTL threads must not report while they hold @lock.
 */
static void cxl_gc_stall_warn(FemuCxlMedia *s)
{
    uint64_t wait = qatomic_read(&s->gc_stall_long_ns);
    uint64_t line = (uint64_t)s->channels * s->luns_per_channel *
                    s->pages_per_block;
    uint64_t want = DIV_ROUND_UP(s->backend.size / 4096 *
                                 (100 + FEMU_CXL_OP_PERCENT), 100 * line);

    if (!wait || s->gc_stall_warned) {
        return;
    }
    s->gc_stall_warned = true;
    if (s->blocks_per_plane < want) {
        warn_report("femu-cxl-ssd: a media request was charged %" PRIu64
                    " ms for forced garbage collection; blocks-per-plane=%"
                    PRIu32 " leaves little spare NAND, and about %u%% "
                    "over-provisioning (blocks-per-plane=%" PRIu64 ") "
                    "usually keeps such stalls short (gc-stall-max-ns)",
                    wait / SCALE_MS, s->blocks_per_plane,
                    FEMU_CXL_OP_PERCENT, want);
    } else {
        warn_report("femu-cxl-ssd: a media request was charged %" PRIu64
                    " ms for forced garbage collection with "
                    "blocks-per-plane=%" PRIu32 " (at least %u%% "
                    "over-provisioning); the NAND timing or queued NAND "
                    "work sets this stall (gc-stall-max-ns)",
                    wait / SCALE_MS, s->blocks_per_plane,
                    FEMU_CXL_OP_PERCENT);
    }
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
    s->ftl_gc_stall_max_ns = MAX(s->ftl_gc_stall_max_ns, wait);
    if (wait > NANOSECONDS_PER_SECOND && !s->gc_stall_long_ns) {
        qatomic_set(&s->gc_stall_long_ns, wait);
        qemu_bh_schedule(s->posted_bh);
    }
    return MAX(lat, wait);
}

/*
 * Take @lock as every thread but the worker does. One that finds it taken
 * says so, so that the worker lets it in before its next device DMA
 * operation (cxl_worker_yield()).
 */
static void cxl_ftl_lock(FemuCxlMedia *s)
{
    if (qemu_mutex_trylock(&s->lock)) {
        qatomic_inc(&s->lock_wanted);
        qemu_mutex_lock(&s->lock);
        qatomic_dec(&s->lock_wanted);
    }
}

/*
 * Whether device DMA queued operations that the worker has not taken. The
 * count needs no lock, so a worker that serves only waited requests takes
 * no other lock for each one. Under @lock.
 */
static bool cxl_posted_pending(FemuCxlMedia *s)
{
    return qatomic_read(&s->posted) != s->posted_taken;
}

/* Take the oldest operation that device DMA queued; under @lock. */
static FemuCxlWork *cxl_take_posted(FemuCxlMedia *s)
{
    FemuCxlWork *work;

    qemu_mutex_lock(&s->post_lock);
    work = QSIMPLEQ_FIRST(&s->post);
    if (work) {
        QSIMPLEQ_REMOVE_HEAD(&s->post, next);
        s->posted_taken++;
    }
    qemu_mutex_unlock(&s->post_lock);
    return work;
}

/* qtest hooks that keep the worker in a request, under @lock. */
static void cxl_test_hold(FemuCxlMedia *s, FemuCxlWork *work)
{
    uint64_t ms = qatomic_read(&s->test_ftl_hold_ms);

    if (unlikely(ms)) {
        int64_t end = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + ms * SCALE_MS;

        qatomic_set(&s->test_ftl_holding, true);
        while (qatomic_read(&s->test_ftl_hold_ms) &&
               qemu_clock_get_ns(QEMU_CLOCK_REALTIME) < end) {
            g_usleep(1000);
        }
        qatomic_set(&s->test_ftl_hold_ms, 0);
        qatomic_set(&s->test_ftl_holding, false);
    }
    ms = qatomic_read(&s->test_ftl_delay_ms);
    if (unlikely(ms) && !work->done_cond) {
        g_usleep(ms * SCALE_MS / SCALE_US);
    }
}

/* How long the worker waits for threads it lets in before device DMA work. */
#define FEMU_CXL_YIELD_NS (1000 * SCALE_US)

/*
 * The worker holds @lock while it has work. Waited requests need @lock to
 * be queued, so they cannot keep it busy, but device DMA queues without
 * it. So before each device DMA operation, let in the threads that wait
 * for @lock: callers whose requests are done and that must take @lock
 * back, and threads that want to queue or run a request. The wait is
 * bounded, so a thread that the host does not run cannot stop the worker.
 * Under @lock.
 */
static void cxl_worker_yield(FemuCxlMedia *s)
{
    int64_t deadline;

    if (!s->done_unclaimed && !qatomic_read(&s->lock_wanted)) {
        return;
    }
    qemu_mutex_unlock(&s->lock);
    deadline = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + FEMU_CXL_YIELD_NS;
    while ((qatomic_read(&s->done_unclaimed) ||
            qatomic_read(&s->lock_wanted)) &&
           qemu_clock_get_ns(QEMU_CLOCK_REALTIME) < deadline) {
        cpu_relax();
    }
    qemu_mutex_lock(&s->lock);
}

static uint64_t cxl_timing_horizon(struct ssd *ssd);

/*
 * Once the device DMA operations queued before fast load went off are
 * booked, the NAND horizon includes them: report the backlog from the
 * switch in fast-load-drain-ns. Under @lock.
 */
static void cxl_drain_settle(FemuCxlMedia *s)
{
    uint64_t end;

    if (!qatomic_read(&s->drain_from) ||
        s->posted_taken < qatomic_read(&s->post_barrier)) {
        return;
    }
    end = cxl_timing_horizon(s->ns.ssd);
    qatomic_set(&s->nand_horizon, end);
    qemu_mutex_lock(&s->post_lock);
    /* A later switch may have moved the barrier meanwhile. */
    if (s->drain_from && s->posted_taken >= s->post_barrier) {
        qatomic_set(&s->fast_load_drain_ns,
                    end > s->drain_from ? end - s->drain_from : 0);
        qatomic_set(&s->drain_from, 0);
        qemu_cond_broadcast(&s->posted_cond);
    }
    qemu_mutex_unlock(&s->post_lock);
}

/*
 * Only metadata reaches the worker; the vCPU owns all payload access.
 * Device DMA operations queued before fast load last went off run first,
 * so no later access books its NAND time ahead of them; a linked NVMe
 * request waits for them (cxl_ftl_lock_after_barrier()). Then waited
 * requests run, in arrival order; other device DMA operations run when
 * none is queued.
 */
static void *cxl_worker(void *opaque)
{
    FemuCxlMedia *s = opaque;
    struct ssd *ssd = s->ns.ssd;

    qemu_mutex_lock(&s->lock);
    for (;;) {
        FemuCxlWork *work = NULL;

        cxl_drain_settle(s);
        if (s->posted_taken < qatomic_read(&s->post_barrier)) {
            cxl_worker_yield(s);
            work = cxl_take_posted(s);
        }
        if (!work && !QSIMPLEQ_EMPTY(&s->work)) {
            work = QSIMPLEQ_FIRST(&s->work);
            QSIMPLEQ_REMOVE_HEAD(&s->work, next);
        } else if (!work && cxl_posted_pending(s)) {
            cxl_worker_yield(s);
            /* A thread let in may have queued a waited request. */
            if (!QSIMPLEQ_EMPTY(&s->work)) {
                continue;
            }
            work = cxl_take_posted(s);
        }
        /* Posted requests may remain at stop; run them before leaving. */
        if (!work) {
            if (s->stopping) {
                break;
            }
            /* Reset before the last look: work queued after it wakes us. */
            qemu_event_reset(&s->worker_event);
            if (QSIMPLEQ_EMPTY(&s->work) && !cxl_posted_pending(s) &&
                !s->stopping) {
                qemu_mutex_unlock(&s->lock);
                qemu_event_wait(&s->worker_event);
                qemu_mutex_lock(&s->lock);
            }
            continue;
        }
        if (s->first_touch_program &&
            work->req.cmd.opcode == NVME_CMD_READ &&
            ssd->maptbl[work->req.slba / 8].ppa == UNMAPPED_PPA) {
            work->req.cmd.opcode = NVME_CMD_WRITE;
        }
        cxl_test_hold(s, work);
        work->latency = cxl_ftl_request(s, s->ctrl, &s->ns, &work->req);
        if (!work->done_cond) {
            qatomic_set(&s->dma_media_ns, s->dma_media_ns + work->latency);
            qatomic_set(&s->posted_failures, s->posted_failures +
                        (work->req.status != NVME_SUCCESS));
            qatomic_set(&s->posted_writes, ssd_nand_write_pages(ssd));
            qatomic_set(&s->posted_stalls, s->ftl_gc_stalls);
            qatomic_set(&s->posted_stall_ns, s->ftl_gc_stall_ns);
            qatomic_set(&s->posted_stall_max_ns, s->ftl_gc_stall_max_ns);
            qemu_mutex_lock(&s->post_lock);
            s->posted_done++;
            qemu_cond_broadcast(&s->posted_cond);
            qemu_mutex_unlock(&s->post_lock);
            qemu_bh_schedule(s->posted_bh);
            g_free(work);
            continue;
        }
        work->done = true;
        qatomic_set(&s->done_unclaimed, s->done_unclaimed + 1);
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
    uint64_t stall_max_ns;

    if (!s->ftl) {
        return true;
    }
    work.done_cond = &done_cond;
    qemu_cond_init(&done_cond);
    femu_cxl_drop(&held);
    cxl_ftl_lock(s);
    QSIMPLEQ_INSERT_TAIL(&s->work, &work, next);
    qemu_event_set(&s->worker_event);
    while (!work.done) {
        qemu_cond_wait(&done_cond, &s->lock);
    }
    qatomic_set(&s->done_unclaimed, s->done_unclaimed - 1);
    /* A linked controller's FTL thread updates this under @lock. */
    writes = ssd_nand_write_pages(s->ns.ssd);
    stalls = s->ftl_gc_stalls;
    stall_ns = s->ftl_gc_stall_ns;
    stall_max_ns = s->ftl_gc_stall_max_ns;
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
    s->gc_stall_max_ns = MAX(s->gc_stall_max_ns, stall_max_ns);
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
    e->writeback = true;
    if (own) {
        ok = femu_cxl_media(op, e->lpn, true);
    } else {
        g_hash_table_add(s->pages, &e->lpn);
        ok = femu_cxl_media(op, e->lpn, true);
        g_hash_table_remove(s->pages, &e->lpn);
        qemu_cond_broadcast(&s->idle);
    }
    e->writeback = false;
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
 * Publish what queued operations did, once the worker has run them: the FTL
 * program and collection counts, and programs NAND refused, reported as
 * accesses report theirs. The worker cannot take the CXL lock, which comes
 * before @lock, so this runs from the main loop. It reads what the worker
 * published instead of taking @lock, which a collection can hold for long.
 */
static void cxl_posted_bh(void *opaque)
{
    FemuCxlMedia *s = opaque;
    uint64_t failures = qatomic_read(&s->posted_failures);
    FEMU_CXL_LOCK_GUARD();

    s->media_writes = MAX(s->media_writes, qatomic_read(&s->posted_writes));
    s->gc_stalls = MAX(s->gc_stalls, qatomic_read(&s->posted_stalls));
    s->gc_stall_ns = MAX(s->gc_stall_ns, qatomic_read(&s->posted_stall_ns));
    s->gc_stall_max_ns = MAX(s->gc_stall_max_ns,
                             qatomic_read(&s->posted_stall_max_ns));
    cxl_gc_stall_warn(s);
    while (s->posted_failures_seen < failures) {
        s->posted_failures_seen++;
        cxl_media_full(s);
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
        /*
         * A guest page walk or an event delivery cannot be emulated: map
         * the page outside the cache for the instruction, as an overflow.
         */
        if (!(flags & FEMU_CXL_FILL_FORCE) ||
            (!s->direct.cylon && !s->test_map)) {
            result = MEMTX_OK;
            goto out;
        }
        over = true;
    }
    /*
     * A fill that could not keep its page charges and counts nothing: the
     * caller maps it outside the cache (version 2) or hands it to the
     * emulator, which charges each access.
     */
    if (!over && !data && s->cache.nsets &&
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
    if (first == last && (s->cache.nsets || s->direct.ratio || over)) {
        FemuCxlEntry *e = g_hash_table_lookup(s->cache.entries, &first);
        /* Only a forced overflow maps an uncached page. */
        bool direct = (e || over ||
                       femu_cxl_ratio_selected(s->direct.ratio, first)) &&
                      (over || !femu_cxl_cca_uncached(&s->cca, first)) &&
                      cxl_map(s, generation, hpa, dpa, e);

        if (direct && !s->direct.cylon && e) {
            /* Direct writes cannot update metadata, so charge on eviction. */
            e->dirty = true;
        }
        if (mapped) {
            *mapped = direct || (s->test_map && (e || over) &&
                                 (over ||
                                  !femu_cxl_cca_uncached(&s->cca, first)));
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
 * Queue a media operation on @lpn that nobody waits for. Its time still
 * occupies the NAND timelines, so later accesses meet it as contention.
 */
static void cxl_media_post(FemuCxlMedia *s, uint64_t lpn, bool write)
{
    FemuCxlWork *work;

    if (!s->ftl) {
        return;
    }
    work = g_new0(FemuCxlWork, 1);
    work->req.cmd.opcode = write ? NVME_CMD_WRITE : NVME_CMD_READ;
    work->req.ns = &s->ns;
    work->req.slba = lpn * 8;
    work->req.nlb = 8;
    work->req.stime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    qemu_mutex_lock(&s->post_lock);
    QSIMPLEQ_INSERT_TAIL(&s->post, work, next);
    qatomic_set(&s->posted, s->posted + 1);
    qemu_mutex_unlock(&s->post_lock);
    qemu_event_set(&s->worker_event);
    s->dma_media_ops++;
}

/*
 * Serve an access made inside a device's re-entrancy guard, typically that
 * device's DMA from its MMIO handler or bottom half. The guard is a flag on
 * the device, and its MMIO needs the BQL. A wait for the gate, a held page
 * or the media releases the BQL, and while it is released the device
 * refuses every other access as re-entrant: a vCPU's doorbell write would be
 * dropped. The main loop's other accesses, such as a block layer
 * completion's copy, come here too, so that no media wait stops the main
 * loop. So nothing here waits or releases a lock; the caller holds the
 * BQL and the CXL lock throughout. The payload moves at once. A cached page
 * is a hit, and a write marks it dirty. Any other page queues one media
 * operation, which nobody waits for, for each run of consecutive accesses
 * to it within one guarded section: a DMA transfer arrives as one access
 * per 8 bytes. Accesses outside a guard all share section 0, so for them a
 * run is only consecutive accesses in one direction. The cache, direct
 * mappings and the I/O log are left as they are.
 */
MemTxResult femu_cxl_access_nowait(FemuCxlMedia *s, uint64_t dpa,
                                   uint64_t *data, unsigned size, bool write)
{
    uint64_t section = qemu_guarded_io_section();
    uint64_t lpn;
    bool cont;

    assert(femu_cxl_locked() && bql_locked());
    if (!size || size > sizeof(*data) || dpa >= s->backend.size ||
        size > s->backend.size - dpa) {
        return MEMTX_ERROR;
    }
    cont = s->dma_run_section == section && s->dma_run_write == write &&
           s->dma_run_end == dpa;
    /* A new run has queued nothing yet. */
    if (!cont) {
        s->dma_run_posted = UINT64_MAX;
    }
    s->dma_accesses++;
    for (lpn = dpa / 4096; lpn <= (dpa + size - 1) / 4096; lpn++) {
        FemuCxlEntry *e = g_hash_table_lookup(s->cache.entries, &lpn);

        if (e && write) {
            e->dirty = true;
        }
        /*
         * A write-back in progress already took its snapshot and will
         * clean or drop the entry, so a write to it programs on its own.
         */
        if (e && !(write && e->writeback)) {
            continue;
        }
        if (cont && lpn == s->dma_run_posted) {
            continue;
        }
        cxl_media_post(s, lpn, write);
        s->dma_run_posted = lpn;
    }
    s->dma_run_section = section;
    s->dma_run_write = write;
    s->dma_run_end = dpa + size;
    if (write) {
        memcpy((uint8_t *)s->backend.logical_space + dpa, data, size);
        femu_cxl_nvme_mark(s, dpa, size);
    } else {
        memcpy(data, (uint8_t *)s->backend.logical_space + dpa, size);
    }
    return MEMTX_OK;
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
 * Nanoseconds from now until the NAND timelines go idle, 0 once they are.
 * Never waits for @lock: while another thread holds it, or device DMA
 * operations are queued, report the last horizon seen, and at least 1.
 * Under the CXL lock.
 */
uint64_t femu_cxl_nand_idle(FemuCxlMedia *s)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    uint64_t end;
    bool busy;

    if (!s->ftl || !s->started) {
        return 0;
    }
    if (qemu_mutex_trylock(&s->lock)) {
        end = qatomic_read(&s->nand_horizon);
        busy = true;
    } else {
        end = cxl_timing_horizon(s->ns.ssd);
        busy = !QSIMPLEQ_EMPTY(&s->work) || cxl_posted_pending(s);
        qatomic_set(&s->nand_horizon, end);
        qemu_mutex_unlock(&s->lock);
    }
    if (end > now) {
        return end - now;
    }
    return busy;
}

/* How long the switch off fast load waits for queued device DMA work. */
#define FEMU_CXL_BACKLOG_WAIT_MS 100

/*
 * Report in fast-load-drain-ns the NAND work that accesses left queued
 * while they skipped their completion wait, in ns from the switch. It stays
 * on the NAND timelines, so later accesses queue behind it in their own
 * threads; the caller, often the main loop, must not sleep it out. Device
 * DMA operations book their NAND time only once the worker runs them. The
 * worker runs those queued now before any later access and then settles
 * the report (cxl_drain_settle()). Wait for that, but only for a bounded
 * time; if it has not happened, report what is booked, and at least 1, and
 * the worker settles the report later. Device DMA queues them with the BQL
 * and the CXL lock held, so let go of both. Never waits for @lock.
 */
void femu_cxl_backlog(FemuCxlMedia *s)
{
    int64_t start = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    int64_t deadline = start + FEMU_CXL_BACKLOG_WAIT_MS * SCALE_MS;
    int64_t now;
    uint64_t end;
    FemuCxlHeld held;

    if (!s->ftl) {
        qatomic_set(&s->fast_load_drain_ns, 0);
        return;
    }
    femu_cxl_drop(&held);
    qemu_mutex_lock(&s->post_lock);
    qatomic_set(&s->post_barrier, s->posted);
    qatomic_set(&s->drain_from, start);
    qemu_mutex_unlock(&s->post_lock);
    qemu_event_set(&s->worker_event);
    qemu_mutex_lock(&s->post_lock);
    while (s->drain_from == start &&
           (now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME)) < deadline) {
        qemu_cond_timedwait(&s->posted_cond, &s->post_lock,
                            DIV_ROUND_UP(deadline - now, SCALE_MS));
    }
    qemu_mutex_unlock(&s->post_lock);
    /*
     * The worker holds @lock for a whole request, a forced collection
     * included, so never wait for it: report the last horizon seen.
     */
    if (qemu_mutex_trylock(&s->lock)) {
        end = qatomic_read(&s->nand_horizon);
    } else {
        cxl_drain_settle(s);
        end = cxl_timing_horizon(s->ns.ssd);
        qatomic_set(&s->nand_horizon, end);
        qemu_mutex_unlock(&s->lock);
    }
    qemu_mutex_lock(&s->post_lock);
    if (s->drain_from == start) {
        qatomic_set(&s->fast_load_drain_ns,
                    MAX(end > start ? end - start : 0, 1));
    }
    qemu_mutex_unlock(&s->post_lock);
    femu_cxl_retake(&held);
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
 * Take @lock once the device DMA operations queued before fast load last
 * went off are booked, so this request books its NAND time after them, as
 * a later CXL access does. The worker books them without waiting for
 * anything, so the wait is bounded; a later switch can only move the
 * barrier over operations already queued.
 */
static void cxl_ftl_lock_after_barrier(FemuCxlMedia *s)
{
    uint64_t barrier;

    cxl_ftl_lock(s);
    while (s->posted_taken < (barrier = qatomic_read(&s->post_barrier))) {
        qemu_mutex_unlock(&s->lock);
        qemu_mutex_lock(&s->post_lock);
        while (s->posted_done < barrier) {
            qemu_cond_wait(&s->posted_cond, &s->post_lock);
        }
        qemu_mutex_unlock(&s->post_lock);
        cxl_ftl_lock(s);
    }
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
    cxl_ftl_lock_after_barrier(s);
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
    qatomic_set(&s->nvme_after_posted, s->posted_taken);
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
    cxl_ftl_lock(s);
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
    cxl_ftl_lock(s);
    s->media_writes = ssd_nand_write_pages(s->ns.ssd);
    s->gc_stalls = s->ftl_gc_stalls;
    s->gc_stall_ns = s->ftl_gc_stall_ns;
    s->gc_stall_max_ns = s->ftl_gc_stall_max_ns;
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

    cxl_ftl_lock(s);
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
    qemu_mutex_init(&s->post_lock);
    qemu_event_init(&s->worker_event, false);
    qemu_cond_init(&s->posted_cond);
    s->posted_bh = qemu_bh_new(cxl_posted_bh, s);
    QSIMPLEQ_INIT(&s->work);
    QSIMPLEQ_INIT(&s->post);
    s->nvme_ranges = g_array_new(false, false, sizeof(FemuCxlRange));
    s->stopping = false;
    qemu_thread_create(&s->worker, "femu-cxl-ftl", cxl_worker, s,
                       QEMU_THREAD_JOINABLE);
}

void femu_cxl_stop(FemuCxlMedia *s)
{
    FemuCtrl *nvme = s->nvme;
    bool resume = false;

    /* Stopping waits for the worker and the pollers: never in a guard. */
    cxl_wait_check();
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
     * A waited request waits on a condition variable on its caller's stack,
     * which stop cannot reach, so none may be outstanding here. The gate
     * guarantees it: teardown leaves the media to the last holder. Posted
     * requests may be queued; the worker runs them before it exits.
     */
    cxl_ftl_lock(s);
    s->stopping = true;
    qemu_event_set(&s->worker_event);
    qemu_mutex_unlock(&s->lock);
    qemu_thread_join(&s->worker);
    /* Publish what the last queued operations did before the BH goes. */
    cxl_posted_bh(s);
    qemu_event_destroy(&s->worker_event);
    qemu_mutex_destroy(&s->post_lock);
    qemu_cond_destroy(&s->posted_cond);
    g_clear_pointer(&s->posted_bh, qemu_bh_delete);
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
