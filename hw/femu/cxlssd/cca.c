/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * CXL caching API (CCA) on BAR5 of femu-cxl-ssd. A doorbell wakes a device
 * thread that executes commands one at a time, in chunks that hold the
 * operation gate like a guest access does, so a long invalidation never
 * keeps a vCPU in an MMIO exit or stalls the main loop.
 */
#include "qemu/osdep.h"
#include <sched.h>
#include "qemu/bitmap.h"
#include "qemu/bswap.h"
#include "qemu/main-loop.h"
#include "qemu/rcu.h"
#include "qapi/error.h"
#include "hw/pci/pci.h"
#include "qemu-adapter.h"

/* Pages acted on, and pages looked up, per hold of the gate and the locks. */
#define CCA_CHUNK       256
#define CCA_SCAN        4096
/* Above this many candidates, revoke every direct mapping at once. */
#define CCA_CLEAR       64
/* Longest sleep between checks for reset or unplug during a delay. */
#define CCA_NAP_US      10000
/* Commands per pass before the thread lets go of the BQL and CXL lock. */
#define CCA_BATCH       64
#define CCA_SPIN_NS     (100 * SCALE_US)

typedef struct CcaOp CcaOp;
typedef int (*CcaPage)(CcaOp *op, uint64_t lpn);

static int cca_drop_batch(CcaOp *op);

struct CcaOp {
    FemuCxlMedia *s;
    /* Media time of the chunk under way. */
    FemuCxlOp media;
    struct cca_ctrl_cmd_s cmd;
    uint64_t start;
    uint64_t end;
    uint32_t epoch;
    uint64_t generation;
    uint64_t acted;
    unsigned work;
    /* Candidates: the range itself, or a sorted snapshot of it. */
    uint64_t pos;
    GArray *list;
    guint index;
    /* Resident pages a chunk of INVALIDATE or CACHE_DISABLE will drop. */
    GArray *batch;
    uint64_t resident;
    uint64_t dirty;
    uint64_t pinned;
    uint64_t uncached;
};

static bool cca_abandoned(FemuCxlMedia *s, uint32_t epoch)
{
    return qatomic_read(&s->cca.stop) || qatomic_read(&s->closing) ||
           qatomic_read(&s->cca.epoch) != epoch;
}

/* The media delay of a chunk, cut short once the command is abandoned. */
static void cca_delay(FemuCxlMedia *s, uint64_t ns, uint32_t epoch)
{
    int64_t deadline = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + ns;
    int64_t remaining;
    FemuCxlHeld held;

    femu_cxl_drop(&held);
    while ((remaining = deadline -
            qemu_clock_get_ns(QEMU_CLOCK_REALTIME)) > 0 &&
           !cca_abandoned(s, epoch)) {
        if (remaining > CCA_SPIN_NS) {
            g_usleep(MIN((remaining - CCA_SPIN_NS) / SCALE_US, CCA_NAP_US));
        } else {
            cpu_relax();
        }
    }
    femu_cxl_retake(&held);
}

/*
 * A waiter woken by the last leave may not get the locks before this thread
 * takes them back; let one take the gate first.
 */
static void cca_yield(FemuCxlMedia *s, uint32_t epoch)
{
    uint64_t entries = s->entries;

    while (s->waiters && s->entries == entries && !s->busy &&
           !cca_abandoned(s, epoch)) {
        FemuCxlHeld held;

        femu_cxl_drop(&held);
        sched_yield();
        femu_cxl_retake(&held);
    }
}

static bool cca_enter(CcaOp *op)
{
    FemuCxlMedia *s = op->s;

    cca_yield(s, op->epoch);
    femu_cxl_enter(s);
    if (!s->started || s->closing || qatomic_read(&s->cca.stop) ||
        s->cca.epoch != op->epoch) {
        femu_cxl_leave(s);
        return false;
    }
    op->media = (FemuCxlOp) { .s = s };
    return true;
}

/* Let vCPUs and the main loop have the locks between bounded pieces of work. */
static void cca_breathe(void)
{
    FemuCxlHeld held;

    femu_cxl_drop(&held);
    sched_yield();
    femu_cxl_retake(&held);
}

static void cca_leave(CcaOp *op)
{
    FemuCxlMedia *s = op->s;

    if (op->media.ns) {
        cca_delay(s, op->media.ns, op->epoch);
    }
    s->cache_entries = g_hash_table_size(s->cache.entries);
    femu_cxl_leave(s);
    cca_breathe();
}

static gint cca_compare(gconstpointer a, gconstpointer b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;

    return x < y ? -1 : x > y;
}

/*
 * Walk the range when it is no larger than the population, else take a
 * sorted snapshot of the resident (or pinned) pages inside it.
 */
static void cca_candidates(CcaOp *op, bool pinned_only)
{
    FemuCxlCache *c = &op->s->cache;
    uint64_t population = pinned_only ? c->pinned :
                                        g_hash_table_size(c->entries);
    GHashTableIter iter;
    gpointer value;

    op->pos = op->start;
    if (op->end - op->start <= population) {
        return;
    }
    op->list = g_array_new(false, false, sizeof(uint64_t));
    g_hash_table_iter_init(&iter, c->entries);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        FemuCxlEntry *e = value;

        if (e->lpn >= op->start && e->lpn < op->end &&
            (!pinned_only || e->queue == FEMU_CXL_PINNED)) {
            g_array_append_val(op->list, e->lpn);
        }
    }
    g_array_sort(op->list, cca_compare);
}

static bool cca_next(CcaOp *op, uint64_t *lpn)
{
    if (op->list) {
        if (op->index >= op->list->len) {
            return false;
        }
        *lpn = g_array_index(op->list, uint64_t, op->index++);
        return true;
    }
    if (op->pos >= op->end) {
        return false;
    }
    *lpn = op->pos++;
    return true;
}

/*
 * Run @page over the candidates, a chunk per gate hold. Returns false if
 * the command was abandoned, else sets *status.
 */
static bool cca_walk(CcaOp *op, CcaPage page, int *status)
{
    for (;;) {
        unsigned scanned = 0;
        bool done = false;
        uint64_t lpn;

        if (!cca_enter(op)) {
            return false;
        }
        op->work = 0;
        while (scanned < CCA_SCAN && op->work < CCA_CHUNK) {
            if (!cca_next(op, &lpn)) {
                done = true;
                break;
            }
            scanned++;
            *status = page(op, lpn);
            if (*status) {
                done = true;
                break;
            }
            /* Unplug or reset: stop issuing media work for a dead command. */
            if (cca_abandoned(op->s, op->epoch)) {
                cca_leave(op);
                return false;
            }
        }
        if (!*status && op->batch && op->batch->len) {
            *status = cca_drop_batch(op);
            done |= *status != 0;
        }
        if (cca_abandoned(op->s, op->epoch)) {
            cca_leave(op);
            return false;
        }
        cca_leave(op);
        if (done) {
            return true;
        }
    }
}

/* Whether some page in [start, end) is pinned. */
static bool cca_any_pinned(FemuCxlMedia *s, uint64_t start, uint64_t end)
{
    FemuCxlCache *c = &s->cache;
    GHashTableIter iter;
    gpointer value;
    uint64_t lpn;

    if (!c->pinned) {
        return false;
    }
    if (end - start <= g_hash_table_size(c->entries)) {
        for (lpn = start; lpn < end; lpn++) {
            FemuCxlEntry *e = g_hash_table_lookup(c->entries, &lpn);

            if (e && e->queue == FEMU_CXL_PINNED) {
                return true;
            }
        }
        return false;
    }
    g_hash_table_iter_init(&iter, c->entries);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        FemuCxlEntry *e = value;

        if (e->queue == FEMU_CXL_PINNED && e->lpn >= start && e->lpn < end) {
            return true;
        }
    }
    return false;
}

/* All or nothing: every set must have room for its unpinned pages. */
static bool cca_pins_fit(FemuCxlMedia *s, uint64_t start, uint64_t end)
{
    FemuCxlCache *c = &s->cache;
    g_autoptr(GHashTable) need = NULL;
    uint64_t lpn;

    if (!c->nsets || end - start > (uint64_t)c->nsets * c->ways) {
        return false;
    }
    need = g_hash_table_new(g_direct_hash, g_direct_equal);
    for (lpn = start; lpn < end; lpn++) {
        FemuCxlEntry *e = g_hash_table_lookup(c->entries, &lpn);
        gpointer key = GUINT_TO_POINTER((uint32_t)(lpn % c->nsets));
        uint32_t n;

        if (e && e->queue == FEMU_CXL_PINNED) {
            continue;
        }
        n = GPOINTER_TO_UINT(g_hash_table_lookup(need, key)) + 1;
        if (n > femu_cxl_cache_pin_room(c, lpn)) {
            return false;
        }
        g_hash_table_insert(need, key, GUINT_TO_POINTER(n));
    }
    return true;
}

/* Eviction that also counts the programs it issues. */
static bool cca_evict(void *opaque, FemuCxlEntry *e)
{
    FemuCxlOp *op = opaque;
    FemuCxlMedia *s = op->s;

    if (!femu_cxl_evict(op, e)) {
        return false;
    }
    /* femu_cxl_evict samples direct-mapped dirty state before programming. */
    if (e->dirty && s->ftl && !s->free_writeback) {
        s->cca.writebacks++;
    }
    return true;
}

static int cca_pin_page(CcaOp *op, uint64_t lpn)
{
    FemuCxlMedia *s = op->s;
    FemuCxlCache *c = &s->cache;
    FemuCxlEntry *e;

    /* A way change between chunks rebuilt the cache; recheck the rest. */
    if (c->generation != op->generation) {
        if (!cca_pins_fit(s, lpn, op->end)) {
            return -EAGAIN;
        }
        op->generation = c->generation;
    }
    e = g_hash_table_lookup(c->entries, &lpn);
    if (!e) {
        /* Fill as a demand miss would, without counting a guest miss. */
        if (!femu_cxl_media(&op->media, lpn, false)) {
            return -EIO;
        }
        e = femu_cxl_cache_insert(c, lpn, cca_evict, &op->media);
        if (!e) {
            return -EIO;
        }
        s->cca.pin_fills++;
        op->work++;
    }
    femu_cxl_cache_pin(c, e);
    op->acted++;
    return 0;
}

static int cca_unpin_page(CcaOp *op, uint64_t lpn)
{
    FemuCxlCache *c = &op->s->cache;
    FemuCxlEntry *e = g_hash_table_lookup(c->entries, &lpn);

    if (e && e->queue == FEMU_CXL_PINNED) {
        femu_cxl_cache_unpin(c, e);
        op->acted++;
    }
    return 0;
}

/* INVALIDATE and CACHE_DISABLE: collect resident pages for the chunk. */
static int cca_drop_page(CcaOp *op, uint64_t lpn)
{
    if (g_hash_table_contains(op->s->cache.entries, &lpn)) {
        g_array_append_val(op->batch, lpn);
        op->work++;
    }
    return 0;
}

/*
 * Revoke the chunk's direct mappings in one memory transaction, then write
 * back if dirty and drop. Writeback can drop the locks, which must not
 * happen with a transaction open.
 */
static int cca_drop_batch(CcaOp *op)
{
    FemuCxlMedia *s = op->s;
    FemuCxlCache *c = &s->cache;
    int status = 0;
    guint i;

    if (!s->direct.cylon) {
        memory_region_transaction_begin();
    }
    for (i = 0; i < op->batch->len; i++) {
        uint64_t lpn = g_array_index(op->batch, uint64_t, i);

        if (!femu_cxl_ratio_selected(s->direct.ratio, lpn)) {
            femu_cxl_der_remove(&s->direct, lpn);
        }
    }
    if (!s->direct.cylon) {
        memory_region_transaction_commit();
    }
    for (i = 0; i < op->batch->len && !cca_abandoned(s, op->epoch); i++) {
        uint64_t lpn = g_array_index(op->batch, uint64_t, i);
        FemuCxlEntry *e = g_hash_table_lookup(c->entries, &lpn);

        if (!e) {
            continue;
        }
        if (!femu_cxl_cache_remove(c, e, cca_evict, &op->media)) {
            /* NAND refused the write; it stays resident, dirty and pinned. */
            status = -EIO;
            break;
        }
        s->cca.dropped++;
        if (op->cmd.cmd == CCA_CTRL_INVALIDATE) {
            op->acted++;
        }
    }
    g_array_set_size(op->batch, 0);
    return status;
}

static int cca_query_page(CcaOp *op, uint64_t lpn)
{
    FemuCxlEntry *e = g_hash_table_lookup(op->s->cache.entries, &lpn);

    if (e) {
        op->resident++;
        op->dirty += e->dirty;
        op->pinned += e->queue == FEMU_CXL_PINNED;
    }
    return 0;
}

static uint64_t cca_uncached_count(FemuCxlCca *cca, uint64_t start,
                                   uint64_t end)
{
    return cca->uncached_map ?
           bitmap_count_one_with_offset(cca->uncached_map, start,
                                        end - start) : 0;
}

static int cca_validate(FemuCxlMedia *s, CcaOp *op)
{
    const struct cca_ctrl_cmd_s *c = &op->cmd;
    uint64_t pages = s->backend.size / 4096;
    uint32_t allowed = CCA_F_ALL;
    unsigned i;

    if (c->cmd >= CCA_CTRL_MAX) {
        return -EINVAL;
    }
    for (i = 0; i < ARRAY_SIZE(c->rsvd); i++) {
        if (c->rsvd[i]) {
            return -EINVAL;
        }
    }
    if (c->cmd == CCA_CTRL_NOP) {
        return c->flags ? -EINVAL : 0;
    }
    if (c->cmd == CCA_CTRL_INVALIDATE || c->cmd == CCA_CTRL_CACHE_DISABLE) {
        allowed |= CCA_F_FORCE;
    }
    if (c->flags & ~allowed) {
        return -EINVAL;
    }
    if (c->flags & CCA_F_ALL) {
        if (c->lpn_start || c->lpn_count) {
            return -EINVAL;
        }
        op->start = 0;
        op->end = pages;
        return 0;
    }
    if (!c->lpn_count) {
        return -EINVAL;
    }
    if (c->lpn_start >= pages || c->lpn_count > pages - c->lpn_start) {
        return -ERANGE;
    }
    op->start = c->lpn_start;
    op->end = c->lpn_start + c->lpn_count;
    return 0;
}

/*
 * Checks that must see the cache under the gate, before any change. Returns
 * 0 to go on to the page walk, 1 when the command is complete, or -errno.
 */
static int cca_prepare(CcaOp *op)
{
    FemuCxlMedia *s = op->s;
    FemuCxlCca *cca = &s->cca;
    FemuCxlCache *c = &s->cache;
    uint64_t count = op->end - op->start;
    uint64_t before;

    if (cca->media_enabled && !cca->media_enabled(s)) {
        return -ENODEV;
    }
    switch (op->cmd.cmd) {
    case CCA_CTRL_PIN:
        if (!c->nsets) {
            return -EOPNOTSUPP;
        }
        if (cca->uncached_map &&
            find_next_bit(cca->uncached_map, op->end, op->start) < op->end) {
            return -EBUSY;
        }
        if (!cca_pins_fit(s, op->start, op->end)) {
            return -ENOSPC;
        }
        op->generation = c->generation;
        op->pos = op->start;
        return 0;
    case CCA_CTRL_UNPIN:
        if (!c->nsets) {
            return -EOPNOTSUPP;
        }
        cca_candidates(op, true);
        return 0;
    case CCA_CTRL_CACHE_DISABLE:
        /* A ratio mapping would serve an uncached page at DRAM speed. */
        if (s->direct.ratio) {
            return -EBUSY;
        }
        /* fall through */
    case CCA_CTRL_INVALIDATE:
        if (!(op->cmd.flags & CCA_F_FORCE) &&
            cca_any_pinned(s, op->start, op->end)) {
            return -EBUSY;
        }
        op->batch = g_array_new(false, false, sizeof(uint64_t));
        if (op->cmd.cmd == CCA_CTRL_CACHE_DISABLE) {
            if (!cca->uncached_map) {
                cca->uncached_map = bitmap_new(s->backend.size / 4096);
            }
            /* Set first, so no access re-inserts a page as it is dropped. */
            before = cca_uncached_count(cca, op->start, op->end);
            bitmap_set(cca->uncached_map, op->start, count);
            op->acted = count - before;
            cca->uncached += op->acted;
        }
        cca_candidates(op, false);
        if (op->end > op->start) {
            femu_cxl_overflow_drop(s, op->start, op->end - 1);
        }
        /*
         * Page by page, Cylon flushes the whole VM twice per page. Many
         * pages revoke everything at once; later accesses map again.
         */
        if ((op->list ? op->list->len : op->end - op->start) > CCA_CLEAR &&
            s->direct.mapped) {
            femu_cxl_der_clear(&s->direct);
        }
        return 0;
    case CCA_CTRL_CACHE_ENABLE:
        before = cca_uncached_count(cca, op->start, op->end);
        if (before) {
            bitmap_clear(cca->uncached_map, op->start, count);
            cca->uncached -= before;
        }
        op->acted = before;
        if (cca->uncached_map &&
            (!cca->uncached || (op->cmd.flags & CCA_F_ALL))) {
            g_clear_pointer(&cca->uncached_map, g_free);
            cca->uncached = 0;
        }
        if (before) {
            femu_cxl_der_unmark(&s->direct);
        }
        return 1;
    case CCA_CTRL_QUERY:
        op->uncached = cca_uncached_count(cca, op->start, op->end);
        op->acted = count;
        cca_candidates(op, false);
        return 0;
    }
    return -EINVAL;
}

/*
 * A CACHE_DISABLE that failed or was abandoned has set bits over pages it
 * could not drop. Clear those, so an uncached page is never resident and
 * never served from DRAM.
 */
static void cca_disable_undo(CcaOp *op)
{
    FemuCxlMedia *s = op->s;
    FemuCxlCca *cca = &s->cca;
    FemuCxlCache *c = &s->cache;
    GHashTableIter iter;
    gpointer value;
    uint64_t lpn;
    uint64_t cleared = 0;

    femu_cxl_enter(s);
    if (!s->started || s->closing || !cca->uncached_map) {
        femu_cxl_leave(s);
        return;
    }
    if (op->end - op->start <= g_hash_table_size(c->entries)) {
        for (lpn = op->start; lpn < op->end; lpn++) {
            if (g_hash_table_contains(c->entries, &lpn) &&
                test_and_clear_bit(lpn, cca->uncached_map)) {
                cleared++;
            }
        }
    } else {
        g_hash_table_iter_init(&iter, c->entries);
        while (g_hash_table_iter_next(&iter, NULL, &value)) {
            FemuCxlEntry *e = value;

            if (e->lpn >= op->start && e->lpn < op->end &&
                test_and_clear_bit(e->lpn, cca->uncached_map)) {
                cleared++;
            }
        }
    }
    cca->uncached -= cleared;
    op->acted -= MIN(op->acted, cleared);
    if (!cca->uncached) {
        g_clear_pointer(&cca->uncached_map, g_free);
    }
    femu_cxl_leave(s);
}

/* Execute one command; false if it was abandoned and must not complete. */
static bool cca_exec(FemuCxlMedia *s, CcaOp *op, struct cca_ctrl_resp_s *resp)
{
    static const CcaPage pages[CCA_CTRL_MAX] = {
        [CCA_CTRL_PIN] = cca_pin_page,
        [CCA_CTRL_UNPIN] = cca_unpin_page,
        [CCA_CTRL_INVALIDATE] = cca_drop_page,
        [CCA_CTRL_CACHE_DISABLE] = cca_drop_page,
        [CCA_CTRL_QUERY] = cca_query_page,
    };
    int status = cca_validate(s, op);

    if (!status && op->cmd.cmd != CCA_CTRL_NOP) {
        if (!cca_enter(op)) {
            return false;
        }
        status = cca_prepare(op);
        cca_leave(op);
        if (status == 1) {
            status = 0;
        } else if (!status) {
            bool done = cca_walk(op, pages[op->cmd.cmd], &status);

            if (op->cmd.cmd == CCA_CTRL_CACHE_DISABLE && (!done || status)) {
                cca_disable_undo(op);
            }
            if (!done) {
                return false;
            }
            /* Unpinned sets take fills again: once per command. */
            if (op->cmd.cmd == CCA_CTRL_UNPIN && op->acted &&
                cca_enter(op)) {
                femu_cxl_der_unmark(&s->direct);
                cca_leave(op);
            }
        }
    }
    resp->status = status;
    resp->lpn_start = op->cmd.lpn_start;
    resp->lpn_count = op->acted;
    resp->tag = op->cmd.tag;
    if (op->cmd.cmd == CCA_CTRL_QUERY && !status) {
        resp->resident = op->resident;
        resp->dirty = op->dirty;
        resp->pinned = op->pinned;
        resp->uncached = op->uncached;
    }
    return true;
}

static void cca_fatal(FemuCxlCca *cca)
{
    cca->status |= CCA_STATUS_FATAL;
}

/* A device-wide reset clears pins and uncached ranges under the gate. */
static void cca_apply_reset(FemuCxlMedia *s)
{
    FemuCxlCca *cca = &s->cca;
    uint32_t kind = cca->reset_pending;

    cca->reset_pending = 0;
    if (kind == CCA_RESET_ALL) {
        femu_cxl_enter(s);
        if (s->started && !s->closing) {
            femu_cxl_cache_unpin_all(&s->cache);
            g_clear_pointer(&cca->uncached_map, g_free);
            cca->uncached = 0;
        }
        femu_cxl_leave(s);
    }
    /* Another reset may have arrived while waiting for the gate. */
    if (!cca->reset_pending) {
        cca->status |= CCA_STATUS_READY;
    }
}

/*
 * Run up to CCA_BATCH commands with the BQL and the CXL lock held. Returns
 * true if more may be pending, so a guest that keeps the ring full cannot
 * hold them.
 */
static bool cca_run(FemuCxlMedia *s)
{
    FemuCxlCca *cca = &s->cca;
    unsigned n;

    for (n = 0; !qatomic_read(&cca->stop); n++) {
        struct cca_ctrl_resp_s resp = { 0 };
        CcaOp op = { .s = s };
        uint32_t slot;
        bool complete;
        int rc;

        if (n == CCA_BATCH) {
            return true;
        }
        if (n) {
            cca_breathe();
        }
        if (cca->reset_pending) {
            cca_apply_reset(s);
            continue;
        }
        if (cca->status & CCA_STATUS_FATAL) {
            return false;
        }
        rc = cca_ring_pop(&cca->ring, &slot, &op.cmd);
        if (rc < 0) {
            cca_fatal(cca);
            return false;
        }
        if (!rc) {
            return false;
        }
        op.epoch = cca->epoch;
        cca->status |= CCA_STATUS_BUSY;
        complete = cca_exec(s, &op, &resp);
        cca->status &= ~CCA_STATUS_BUSY;
        if (op.list) {
            g_array_free(op.list, true);
        }
        if (op.batch) {
            g_array_free(op.batch, true);
        }
        /* A reset reformatted the rings while the command ran. */
        if (!complete || cca->epoch != op.epoch) {
            continue;
        }
        if (!cca_ring_complete(&cca->ring, slot, &resp)) {
            cca_fatal(cca);
            return false;
        }
        cca->completed++;
        cca->commands++;
        cca->errors += resp.status != 0;
    }
    return false;
}

static void cca_kick(FemuCxlCca *cca)
{
    qemu_mutex_lock(&cca->lock);
    cca->kick = true;
    qemu_cond_signal(&cca->cond);
    qemu_mutex_unlock(&cca->lock);
}

/*
 * The thread holds a reference to the device for its whole life, as an
 * access in flight does, so unplug never has to wait for it.
 */
static void *cca_thread(void *opaque)
{
    FemuCxlMedia *s = opaque;
    FemuCxlCca *cca = &s->cca;
    Object *owner = cca->owner;

    rcu_register_thread();
    for (;;) {
        bool more;
        bool stop;

        qemu_mutex_lock(&cca->lock);
        while (!cca->kick && !cca->stop) {
            qemu_cond_wait(&cca->cond, &cca->lock);
        }
        cca->kick = false;
        stop = cca->stop;
        qemu_mutex_unlock(&cca->lock);
        if (stop) {
            break;
        }
        bql_lock();
        femu_cxl_lock();
        more = cca_run(s);
        femu_cxl_unlock();
        bql_unlock();
        if (more) {
            sched_yield();
            cca_kick(cca);
        }
    }
    bql_lock();
    object_unref(owner);
    bql_unlock();
    rcu_unregister_thread();
    return NULL;
}

/*
 * Runs under the locks and never waits, like any invalidation. Slots are
 * cleared too, so entries a guest posts against stale indices are NOPs.
 */
void femu_cxl_cca_reset(FemuCxlMedia *s, uint32_t kind)
{
    FemuCxlCca *cca = &s->cca;

    if (!cca->running) {
        return;
    }
    cca_ring_format(&cca->ring, memory_region_get_ram_ptr(&cca->shm));
    cca->completed = 0;
    qatomic_set(&cca->epoch, cca->epoch + 1);
    cca->status &= ~(CCA_STATUS_READY | CCA_STATUS_FATAL);
    cca->reset_pending = MAX(cca->reset_pending, kind);
    cca_kick(cca);
}

static uint64_t cca_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    FemuCxlMedia *s = opaque;
    FemuCxlCca *cca = &s->cca;
    uint8_t regs[CCA_REG_END] = { 0 };

    if ((size != 4 && size != 8) || addr % size ||
        addr + size > CCA_REG_END) {
        return 0;
    }
    stl_le_p(regs + CCA_REG_MAGIC, CCA_SHMEM_MAGIC);
    stl_le_p(regs + CCA_REG_VERSION, CCA_LAYOUT_VERSION);
    stl_le_p(regs + CCA_REG_STATUS, cca->status |
             (s->cache_pages ? CCA_STATUS_CACHE : 0));
    stl_le_p(regs + CCA_REG_FATAL_REASON,
             cca->status & CCA_STATUS_FATAL ? cca->ring.fatal : 0);
    stq_le_p(regs + CCA_REG_MEDIA_PAGES, s->backend.size / 4096);
    stl_le_p(regs + CCA_REG_CACHE_PAGES, s->cache_pages);
    stl_le_p(regs + CCA_REG_CACHE_WAYS, s->cache_ways);
    /* Every way of a set may be pinned; its misses then stay uncached. */
    stl_le_p(regs + CCA_REG_PIN_LIMIT, s->cache_pages ? s->cache_ways : 0);
    stq_le_p(regs + CCA_REG_COMPLETED, cca->completed);
    stl_le_p(regs + CCA_REG_EPOCH, cca->epoch);
    return size == 4 ? ldl_le_p(regs + addr) : ldq_le_p(regs + addr);
}

static void cca_reg_write(void *opaque, hwaddr addr, uint64_t value,
                          unsigned size)
{
    FemuCxlMedia *s = opaque;

    if ((size != 4 && size != 8) || !s->cca.running) {
        return;
    }
    if (addr == CCA_REG_DOORBELL) {
        cca_kick(&s->cca);
    } else if (addr == CCA_REG_RESET &&
               ((uint32_t)value == CCA_RESET_RINGS ||
                (uint32_t)value == CCA_RESET_ALL)) {
        FEMU_CXL_LOCK_GUARD();

        femu_cxl_cca_reset(s, value);
    }
}

static const MemoryRegionOps cca_reg_ops = {
    .read = cca_reg_read,
    .write = cca_reg_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 8 },
    .impl = { .min_access_size = 1, .max_access_size = 8 },
};

void femu_cxl_cca_init(FemuCxlCca *cca)
{
    qemu_mutex_init(&cca->lock);
    qemu_cond_init(&cca->cond);
}

void femu_cxl_cca_finalize(FemuCxlCca *cca)
{
    g_clear_pointer(&cca->uncached_map, g_free);
    qemu_cond_destroy(&cca->cond);
    qemu_mutex_destroy(&cca->lock);
}

/* The one step that can fail, done before the parent realizes. */
bool femu_cxl_cca_alloc(FemuCxlMedia *s, Object *owner, Error **errp)
{
    return memory_region_init_ram_nomigrate(&s->cca.shm, owner,
                                            "femu-cxl-cca-shm", CCA_SHM_SIZE,
                                            errp);
}

/* Register BAR5 and start the thread; realize cannot fail after this. */
void femu_cxl_cca_start(FemuCxlMedia *s, PCIDevice *pci, Object *owner,
                        bool (*media_enabled)(FemuCxlMedia *s))
{
    FemuCxlCca *cca = &s->cca;

    memory_region_init(&cca->bar, owner, "femu-cxl-cca", CCA_BAR_SIZE);
    memory_region_init_io(&cca->regs, owner, &cca_reg_ops, s,
                          "femu-cxl-cca-regs", CCA_REG_SIZE);
    /* The handlers never wait and never touch other devices. */
    cca->regs.disable_reentrancy_guard = true;
    memory_region_add_subregion(&cca->bar, 0, &cca->regs);
    memory_region_add_subregion(&cca->bar, CCA_SHM_OFFSET, &cca->shm);
    pci_register_bar(pci, CCA_BAR_INDEX, PCI_BASE_ADDRESS_SPACE_MEMORY,
                     &cca->bar);
    cca->owner = owner;
    cca->media_enabled = media_enabled;
    cca_ring_format(&cca->ring, memory_region_get_ram_ptr(&cca->shm));
    cca->status = CCA_STATUS_READY;
    cca->stop = false;
    cca->running = true;
    object_ref(owner);
    qemu_thread_create(&cca->thread, "femu-cxl-cca", cca_thread, s,
                       QEMU_THREAD_DETACHED);
}

/* Unplug: stop accepting work and let the thread leave on its own. */
void femu_cxl_cca_stop(FemuCxlMedia *s)
{
    FemuCxlCca *cca = &s->cca;

    if (!cca->running) {
        return;
    }
    cca->running = false;
    qemu_mutex_lock(&cca->lock);
    qatomic_set(&cca->stop, true);
    qemu_cond_signal(&cca->cond);
    qemu_mutex_unlock(&cca->lock);
}

void femu_cxl_cca_stats_reset(FemuCxlCca *cca)
{
    cca->commands = 0;
    cca->errors = 0;
    cca->pin_fills = 0;
    cca->writebacks = 0;
    cca->dropped = 0;
    cca->pinned_set_misses = 0;
}
