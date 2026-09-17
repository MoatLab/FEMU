/*
 * Uniform NAND media-layer timing implementation. The op math here reproduces the
 * bbssd staged model (the richest superset): channel-bus phases + LUN/plane array
 * gating + page-type program latency + ECC-wear-on-read + cache-read pipeline +
 * multi-plane + copyback. ZNS/OCSSD use strict config subsets of the same code.
 *
 * Bit-identical contract for the channel-off modes: the max() ordering and the
 * per-op phase sequence below mirror hw/femu/bbssd/ftl.c ssd_advance_status /
 * ssd_advance_multiplane / ssd_advance_copyback exactly. The staged channel
 * model books a read's data-out for the window in which it happens (see the
 * bus_* helpers); it is opt-in and was never on by default.
 */

#include "qemu/osdep.h"
#include "nand-media.h"

void nand_media_init(NandMedia *m, const NandMediaConfig *cfg)
{
    m->cfg = *cfg;
    m->bus_res = NULL;
    m->susp = NULL;
    if (cfg->policy.channel_mode == NAND_CH_STAGED && cfg->nchs) {
        m->bus_res = calloc(cfg->nchs, sizeof(*m->bus_res));
    }
    /* suspend needs the geometry to keep its per-position state */
    if (cfg->policy.pe_suspend &&
        cfg->nchs && cfg->luns_per_ch && cfg->planes_per_lun) {
        m->susp = calloc((size_t)cfg->nchs * cfg->luns_per_ch *
                         cfg->planes_per_lun, sizeof(*m->susp));
    }
}

/*
 * Release what nand_media_init() took. The staged channel model keeps a
 * per-channel reservation list; without this it is leaked for the lifetime of
 * the process, which a device that is unplugged and replaced does notice.
 * Safe to call on a media that was never initialised for a staged bus, and
 * safe to call twice.
 */
void nand_media_destroy(NandMedia *m)
{
    if (!m) {
        return;
    }
    free(m->bus_res);
    m->bus_res = NULL;
    free(m->susp);
    m->susp = NULL;
}

static inline uint64_t mx(uint64_t a, uint64_t b) { return a > b ? a : b; }

/*
 * Channel bus bookkeeping. Two kinds of phase share one bus:
 *
 *  - phases that happen when the op reaches them: command/address, a program's
 *    data-in, and any status read. These queue FIFO behind the bus's busy-until
 *    accumulator (the controller's ch_avail) and advance it.
 *  - a read's data-out, which happens only once the array has finished (tR
 *    later) and is therefore booked as a window in the future. It does not
 *    advance busy-until: the bus is idle until the window opens and another
 *    die's phase may use it in the gap.
 *
 * Both kinds avoid every booked window. A zero-length phase touches nothing;
 * booking it was what made a read's command wait for another read's transfer.
 */
static void bus_prune(NandBusResList *l, uint64_t now)
{
    int i, j = 0;
    for (i = 0; i < l->n; i++) {
        if (l->r[i].end > now) {
            l->r[j++] = l->r[i];
        }
    }
    l->n = j;
}

/* earliest s >= start such that [s, s + len) overlaps no booked window */
static uint64_t bus_fit(const NandBusResList *l, uint64_t start, uint64_t len)
{
    int i;
    for (i = 0; i < l->n; i++) {          /* windows are kept sorted by start */
        if (l->r[i].end <= start) {
            continue;
        }
        if (l->r[i].start >= start + len) {
            break;
        }
        start = l->r[i].end;
    }
    return start;
}

static bool bus_book(NandBusResList *l, uint64_t start, uint64_t end)
{
    int i;
    if (l->n == NAND_BUS_RES_MAX) {
        return false;
    }
    for (i = l->n; i > 0 && l->r[i - 1].start > start; i--) {
        l->r[i] = l->r[i - 1];
    }
    l->r[i].start = start;
    l->r[i].end = end;
    l->n++;
    return true;
}

/*
 * Windows that ended before the op now being timed started can no longer be
 * hit: every later op starts no earlier than this one. Pruning on the op's
 * own start time is what keeps the list short; the accumulator cannot be used
 * for that because it does not move when the immediate phases are zero.
 */

/* a phase that happens now: FIFO on the bus, around any booked window */
static uint64_t bus_now(NandMedia *m, uint32_t ch, uint64_t now,
                        uint64_t earliest, uint64_t len)
{
    uint64_t *cha = m->cfg.timeline->ch_avail(m->cfg.timeline_opaque, ch);
    uint64_t start;

    if (!len) {
        return earliest;
    }
    start = mx(earliest, *cha);
    if (m->bus_res) {
        bus_prune(&m->bus_res[ch], now);
        start = bus_fit(&m->bus_res[ch], start, len);
    }
    *cha = start + len;
    return *cha;
}

/* a phase that happens later (a read's data-out): booked, busy-until untouched */
static uint64_t bus_later(NandMedia *m, uint32_t ch, uint64_t now,
                          uint64_t earliest, uint64_t len)
{
    uint64_t *cha = m->cfg.timeline->ch_avail(m->cfg.timeline_opaque, ch);
    uint64_t start;

    if (!len) {
        return earliest;
    }
    start = mx(earliest, *cha);
    if (m->bus_res) {
        bus_prune(&m->bus_res[ch], now);
        start = bus_fit(&m->bus_res[ch], start, len);
        if (bus_book(&m->bus_res[ch], start, start + len)) {
            return start + len;
        }
    }
    *cha = start + len;   /* no room to book: bus held from now, as before */
    return *cha;
}

/*
 * Extra read time spent on error correction. Both wear and retention age push a
 * block towards more correction work, so their tiers add and are capped
 * together. Returns 0 unless the caller enabled the model and gave a step.
 */
static uint64_t ecc_extra_ns(NandMedia *m, const NandLoc *loc)
{
    const NandMediaTiming *t = &m->cfg.timing;
    uint64_t tiers = 0;

    if (!m->cfg.policy.ecc_on_read || !t->ecc_step_ns) {
        return 0;
    }
    if (t->ecc_pe_per_tier) {
        tiers += loc->pe_cycles / (uint32_t)t->ecc_pe_per_tier;
    }
    if (t->ecc_retention_per_tier_sec) {
        tiers += loc->age_sec / (uint32_t)t->ecc_retention_per_tier_sec;
    }
    if (tiers > (uint64_t)t->ecc_max_tiers) {
        tiers = t->ecc_max_tiers;
    }
    return (uint64_t)t->ecc_step_ns * tiers;
}

/* per-op array latency, honoring flat vs table + bbssd page-type multiplier */
static uint64_t array_lat(NandMedia *m, const NandLoc *loc, NandMediaOp op)
{
    const NandMediaTiming *t = &m->cfg.timing;
    uint64_t lat;

    if (op == NAND_MEDIA_ERASE) {
        return m->cfg.policy.use_flat_timing ? t->er_ns : t->er_table_ns[loc->flash_type];
    }
    if (op == NAND_MEDIA_READ) {
        lat = m->cfg.policy.use_flat_timing ?
              t->rd_ns : t->rd_table_ns[loc->flash_type][loc->page_type];
        lat += ecc_extra_ns(m, loc);
        return lat;
    }
    /* program */
    lat = m->cfg.policy.use_flat_timing ?
          t->wr_ns : t->wr_table_ns[loc->flash_type][loc->page_type];
    if (m->cfg.policy.use_flat_timing && t->pgtype_lat) {
        lat = lat * t->pgtype_mult[loc->page_type] / 1000;
    }
    return lat;
}

/* gate the array start on the configured resources (exact bbssd ordering) */
static uint64_t array_gate_start(NandMedia *m, const NandLoc *loc, uint64_t t)
{
    uint64_t s = t;
    if (m->cfg.policy.array_gate == NAND_GATE_LUN_ONLY ||
        m->cfg.policy.array_gate == NAND_GATE_LUN_AND_PLANE) {
        uint64_t *lun = m->cfg.timeline->lun_avail(m->cfg.timeline_opaque, loc);
        s = mx(s, *lun);
    }
    if (m->cfg.policy.array_gate == NAND_GATE_PLANE_ONLY ||
        m->cfg.policy.array_gate == NAND_GATE_LUN_AND_PLANE) {
        uint64_t *pl = m->cfg.timeline->plane_avail(m->cfg.timeline_opaque, loc);
        s = mx(s, *pl);
    }
    return s;
}

/*
 * A read that preempted an in-flight P/E: push back every gated timeline that
 * was busy at t by the read's occupancy, so the suspended operation finishes
 * that much later. Timelines that were already idle at t are left alone.
 */
static void array_suspend_extend(NandMedia *m, const NandLoc *loc, uint64_t t,
                                 uint64_t shift)
{
    if (m->cfg.policy.array_gate == NAND_GATE_LUN_ONLY ||
        m->cfg.policy.array_gate == NAND_GATE_LUN_AND_PLANE) {
        uint64_t *lun = m->cfg.timeline->lun_avail(m->cfg.timeline_opaque, loc);
        if (*lun > t) {
            *lun += shift;
        }
    }
    if (m->cfg.policy.array_gate == NAND_GATE_PLANE_ONLY ||
        m->cfg.policy.array_gate == NAND_GATE_LUN_AND_PLANE) {
        uint64_t *pl = m->cfg.timeline->plane_avail(m->cfg.timeline_opaque, loc);
        if (*pl > t) {
            *pl += shift;
        }
    }
}

static void array_commit(NandMedia *m, const NandLoc *loc, uint64_t done)
{
    if (m->cfg.policy.array_gate == NAND_GATE_LUN_ONLY ||
        m->cfg.policy.array_gate == NAND_GATE_LUN_AND_PLANE) {
        *m->cfg.timeline->lun_avail(m->cfg.timeline_opaque, loc) = done;
    }
    if (m->cfg.policy.array_gate == NAND_GATE_PLANE_ONLY ||
        m->cfg.policy.array_gate == NAND_GATE_LUN_AND_PLANE) {
        *m->cfg.timeline->plane_avail(m->cfg.timeline_opaque, loc) = done;
    }
}

/*
 * The suspend state for an array position: the plane under a plane-only gate,
 * otherwise the LUN, since a LUN gate makes the whole LUN one position.
 */
static NandSuspendState *suspend_state(NandMedia *m, const NandLoc *loc)
{
    const NandMediaConfig *c = &m->cfg;
    uint64_t idx;

    if (!m->susp || loc->ch >= c->nchs || loc->lun >= c->luns_per_ch ||
        loc->pl >= c->planes_per_lun) {
        return NULL;
    }
    idx = (uint64_t)loc->ch * c->luns_per_ch + loc->lun;
    if (c->policy.array_gate == NAND_GATE_PLANE_ONLY) {
        idx = idx * c->planes_per_lun + loc->pl;
    }

    return &m->susp[idx];
}

/* record what an operation that went through the ordinary gate occupies */
static void suspend_note(NandMedia *m, const NandLoc *loc, NandMediaOp op,
                         uint64_t done)
{
    NandSuspendState *st = suspend_state(m, loc);

    if (!st) {
        return;
    }
    if (op == NAND_MEDIA_READ) {
        st->rd_end = mx(st->rd_end, done);
    } else {
        st->pe_end = mx(st->pe_end, done);
    }
}

/*
 * Where a read starts under program/erase suspend, given the time the array is
 * busy until. Only a program or erase is suspended: a read that finds the array
 * busy with other reads queues behind them, and one that finds a suspension
 * already open joins it behind the reads in it without paying the overhead a
 * second time. Returns false to leave the read to the ordinary gate; otherwise
 * sets *start, and *shift, how far the suspended work slides.
 *
 * The state is read and written without a lock, so the caller must serialize
 * the operations on a position -- bbssd and ZNS run them on one FTL thread.
 */
static bool suspend_read_start(NandMedia *m, const NandLoc *loc, uint64_t t,
                               uint64_t busy_until, uint64_t alat,
                               uint64_t *start, uint64_t *shift)
{
    NandSuspendState *st = suspend_state(m, loc);

    if (!st || t >= busy_until || t >= st->pe_end) {
        return false;
    }
    if (st->rd_end > t) {
        *start = st->rd_end;
        *shift = alat;
    } else {
        *start = t + m->cfg.timing.tsusp_ns;
        *shift = alat + m->cfg.timing.tsusp_ns;
    }
    st->pe_end += *shift;
    st->rd_end = *start + alat;

    return true;
}

NandOpCompletion nand_media_op(NandMedia *m, const NandLoc *loc,
                               NandMediaOp op, uint64_t stime)
{
    NandOpCompletion c;
    uint64_t t = stime;
    uint64_t alat = array_lat(m, loc, op);

    if (m->cfg.policy.channel_mode != NAND_CH_STAGED) {
        /*
         * Plane-only / lun-only model (ZNS, bbssd legacy, OCSSD): array gate only.
         * OCSSD adds (a) busy-extend semantics (avail += lat when busy) and (b) an
         * optional per-LUN lock for its multi-threaded Open-Channel datapath.
         */
        uint64_t done;
        /*
         * Lock-free fast path for the single-word LUN-only gate (array_gate ==
         * LUN_ONLY, no plane accumulator, no busy-extend). The whole critical
         * section is one word's read-max-add-store on next_lun_avail_time. A CAS
         * loop reproduces the EXACT same value sequence a lock would: each op
         * commits done = max(t, lun_at_commit) + alat, recomputed from the value
         * it actually observed, so the result matches some valid serial ordering
         * and is bit-identical to a plain locked read-max-add-store, without the
         * mutex. Falls through to the locked path for LUN_AND_PLANE, which is
         * two words and not atomically CAS-able.
         */
        /*
         * Suspend keeps state beside the timeline that one CAS cannot update
         * with it, so a device with suspend on takes the general path below.
         */
        if (m->cfg.policy.array_gate == NAND_GATE_LUN_ONLY && !m->susp) {
            uint64_t *lun = m->cfg.timeline->lun_avail(m->cfg.timeline_opaque, loc);
            uint64_t old = __atomic_load_n(lun, __ATOMIC_RELAXED);
            for (;;) {
                uint64_t s = (t > old) ? t : old;
                done = s + alat;
                /*
                 * x86-64: inlines to `lock cmpxchg` (no libatomic call). On
                 * success `old` is unchanged and we stop; on failure the
                 * builtin writes the observed value back into `old` and we
                 * retry with it (recomputing done from what we actually saw).
                 */
                if (__atomic_compare_exchange_n(lun, &old, done, false,
                                                __ATOMIC_ACQ_REL,
                                                __ATOMIC_RELAXED)) {
                    break;
                }
            }
            c.done_ns = done;
            c.latency_ns = done - stime;
            return c;
        }
        if (m->cfg.timeline->lock_lun) {
            m->cfg.timeline->lock_lun(m->cfg.timeline_opaque, loc);
        }
        {
            uint64_t s = array_gate_start(m, loc, t);
            uint64_t rs, shift;

            if (op == NAND_MEDIA_READ &&
                suspend_read_start(m, loc, t, s, alat, &rs, &shift)) {
                /*
                 * The read goes ahead of the program or erase, and every gated
                 * timeline that was busy resumes its work after it.
                 */
                done = rs + alat;
                array_suspend_extend(m, loc, t, shift);
            } else {
                done = s + alat;
                array_commit(m, loc, done);
                suspend_note(m, loc, op, done);
            }
        }
        if (m->cfg.timeline->unlock_lun) {
            m->cfg.timeline->unlock_lun(m->cfg.timeline_opaque, loc);
        }
        c.done_ns = done;
        c.latency_ns = done - stime;
        return c;
    }

    /*
     * staged channel-bus model (bbssd). This path does several channel-timeline RMWs
     * (advance_chnl) plus the array gate, so under multiple FTL threads it must be
     * serialized per channel. lock_lun/unlock_lun (when provided) take the channel
     * lock; they are NULL for the single-FTL-thread default, leaving this lock-free.
     */
    if (m->cfg.timeline->lock_lun) {
        m->cfg.timeline->lock_lun(m->cfg.timeline_opaque, loc);
    }
    if (op == NAND_MEDIA_READ) {
        t = bus_now(m, loc->ch, stime, t, m->cfg.timing.cmd_addr_ns);
        /*
         * Program/erase suspend: a read that finds its array mid-program or
         * mid-erase starts after a small suspend overhead instead of waiting
         * the operation out, and the suspended operation resumes after it.
         * Default off (pe_suspend=false) => identical to the plain gate.
         */
        {
            uint64_t busy = array_gate_start(m, loc, t);
            uint64_t rs, shift;

            if (suspend_read_start(m, loc, t, busy, alat, &rs, &shift)) {
                uint64_t done = rs + alat;

                array_suspend_extend(m, loc, t, shift);
                if (m->cfg.policy.cache_read && m->cfg.timeline->page_reg_ready) {
                    uint64_t *prr =
                        m->cfg.timeline->page_reg_ready(m->cfg.timeline_opaque, loc);
                    uint64_t dout = mx(*prr, done);
                    t = bus_later(m, loc->ch, stime, dout, m->cfg.timing.page_xfer_ns);
                    *prr = t;
                } else {
                    t = bus_later(m, loc->ch, stime, done, m->cfg.timing.page_xfer_ns);
                }
                t = bus_later(m, loc->ch, stime, t, m->cfg.timing.status_ns);
                c.done_ns = t;
                c.latency_ns = c.done_ns - stime;
                if (m->cfg.timeline->unlock_lun) {
                    m->cfg.timeline->unlock_lun(m->cfg.timeline_opaque, loc);
                }
                return c;
            }
        }
        uint64_t s = array_gate_start(m, loc, t);
        uint64_t done = s + alat;
        array_commit(m, loc, done);
        suspend_note(m, loc, op, done);
        if (m->cfg.policy.cache_read && m->cfg.timeline->page_reg_ready) {
            uint64_t rcbsy = m->cfg.timing.trcbsy_ns ? m->cfg.timing.trcbsy_ns : alat;
            *m->cfg.timeline->lun_avail(m->cfg.timeline_opaque, loc) = s + rcbsy;
            uint64_t *prr = m->cfg.timeline->page_reg_ready(m->cfg.timeline_opaque, loc);
            uint64_t dout = mx(*prr, done);
            t = bus_later(m, loc->ch, stime, dout, m->cfg.timing.page_xfer_ns);
            *prr = t;
        } else {
            t = bus_later(m, loc->ch, stime, done, m->cfg.timing.page_xfer_ns);
        }
        t = bus_later(m, loc->ch, stime, t, m->cfg.timing.status_ns);
        c.done_ns = t;
    } else if (op == NAND_MEDIA_PROGRAM) {
        t = bus_now(m, loc->ch, stime, t, m->cfg.timing.cmd_addr_ns);
        t = bus_now(m, loc->ch, stime, t, m->cfg.timing.page_xfer_ns);
        uint64_t s = array_gate_start(m, loc, t);
        uint64_t done = s + alat;
        array_commit(m, loc, done);
        suspend_note(m, loc, op, done);
        c.done_ns = done;
    } else { /* erase */
        t = bus_now(m, loc->ch, stime, t, m->cfg.timing.cmd_addr_ns);
        uint64_t s = array_gate_start(m, loc, t);
        uint64_t done = s + alat;
        array_commit(m, loc, done);
        suspend_note(m, loc, op, done);
        t = bus_later(m, loc->ch, stime, done, m->cfg.timing.status_ns);
        c.done_ns = t;
    }
    if (m->cfg.timeline->unlock_lun) {
        m->cfg.timeline->unlock_lun(m->cfg.timeline_opaque, loc);
    }
    c.latency_ns = c.done_ns - stime;
    return c;
}

NandOpCompletion nand_media_multiplane(NandMedia *m, const NandLoc *locs, int nlocs,
                                       NandMediaOp op, uint64_t stime)
{
    NandOpCompletion c;
    uint64_t t = stime;
    uint32_t ch = locs[0].ch;
    int plbusy = (op == NAND_MEDIA_PROGRAM) ? m->cfg.timing.tplpbsy_ns :
                 (op == NAND_MEDIA_ERASE)   ? m->cfg.timing.tplebsy_ns :
                                              m->cfg.timing.tplrbsy_ns;
    int i;

    /* per-plane command/address (+ data-in for programs) serialized on the bus */
    for (i = 0; i < nlocs; i++) {
        t = bus_now(m, ch, stime, t, m->cfg.timing.cmd_addr_ns);
        if (op == NAND_MEDIA_PROGRAM) {
            t = bus_now(m, ch, stime, t, m->cfg.timing.page_xfer_ns);
        }
        if (i < nlocs - 1) {
            t += plbusy;
        }
    }

    /*
     * One array op in parallel across all planes, gated on every resource the
     * configured gate covers. Going through array_gate_start/array_commit rather
     * than reaching for the accumulators directly is what lets a LUN-only caller
     * (bbssd) use this: it leaves plane_avail untouched when the gate excludes it.
     */
    uint64_t start = t;
    for (i = 0; i < nlocs; i++) {
        start = mx(start, array_gate_start(m, &locs[i], start));
    }
    uint64_t alat;
    if (op == NAND_MEDIA_READ) {
        alat = m->cfg.policy.use_flat_timing ?
               m->cfg.timing.rd_ns :
               m->cfg.timing.rd_table_ns[locs[0].flash_type][locs[0].page_type];
        /* the plane needing the most correction paces the whole operation */
        uint64_t worst = 0;
        for (i = 0; i < nlocs; i++) {
            uint64_t extra = ecc_extra_ns(m, &locs[i]);
            if (extra > worst) worst = extra;
        }
        alat += worst;
    } else {
        alat = array_lat(m, &locs[0], op);
    }
    uint64_t done = start + alat;
    for (i = 0; i < nlocs; i++) {
        array_commit(m, &locs[i], done);
        suspend_note(m, &locs[i], op, done);
    }

    t = done;
    if (op == NAND_MEDIA_READ) {
        if (m->cfg.timing.status_ns)
            t = bus_later(m, ch, stime, t, m->cfg.timing.status_ns);
        for (i = 0; i < nlocs; i++) {
            t = bus_later(m, ch, stime, t, m->cfg.timing.cmd_addr_ns);
            t = bus_later(m, ch, stime, t, m->cfg.timing.page_xfer_ns);
        }
    } else if (m->cfg.timing.status_ns) {
        t = bus_later(m, ch, stime, t, m->cfg.timing.status_ns);
    }

    c.done_ns = t;
    c.latency_ns = t - stime;
    return c;
}

NandOpCompletion nand_media_copyback(NandMedia *m, const NandLoc *src,
                                     const NandLoc *dst, uint64_t stime)
{
    NandOpCompletion c;
    uint64_t s;

    /*
     * On-chip read then program; no bus phases. Gated like
     * every other op here: an operation cannot begin before it was requested,
     * and it goes through the configured gate rather than the accumulators
     * directly, so a LUN-only caller's unset plane_avail is never read.
     */
    s = array_gate_start(m, src, stime) + array_lat(m, src, NAND_MEDIA_READ);
    array_commit(m, src, s);
    /* the on-chip read is part of the program, so it is suspended with it */
    suspend_note(m, src, NAND_MEDIA_PROGRAM, s);
    s = array_gate_start(m, dst, s) + array_lat(m, dst, NAND_MEDIA_PROGRAM);
    array_commit(m, dst, s);
    suspend_note(m, dst, NAND_MEDIA_PROGRAM, s);

    c.done_ns = s;
    c.latency_ns = 0; /* GC-internal; host effect is via freed channel + LUN busy */
    return c;
}
