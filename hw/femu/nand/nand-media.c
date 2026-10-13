/*
 * Uniform NAND media-layer timing implementation. The op math here reproduces the
 * bbssd staged model (the richest superset): channel-bus phases + LUN/plane array
 * contention rules + page-type program latency + ECC-wear-on-read + multi-plane +
 * copyback. ZNS and OCSSD use strict config subsets of the
 * same code.
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
        /* Without its lists an unbounded bus would silently hold the bus. */
        if (!m->bus_res && cfg->policy.bus_res_unbounded) {
            abort();
        }
        if (m->bus_res && cfg->policy.bus_res_unbounded) {
            uint32_t ch;

            for (ch = 0; ch < cfg->nchs; ch++) {
                m->bus_res[ch].cap = NAND_BUS_RES_MAX;
                m->bus_res[ch].grown = malloc(NAND_BUS_RES_MAX *
                                              sizeof(NandBusRes));
                if (!m->bus_res[ch].grown) {
                    abort();
                }
            }
        }
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
    if (m->bus_res) {
        uint32_t ch;

        for (ch = 0; ch < m->cfg.nchs; ch++) {
            free(m->bus_res[ch].grown);
        }
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
static NandBusRes *bus_windows(const NandBusResList *l)
{
    return l->grown ? l->grown : (NandBusRes *)l->r;
}

static void bus_prune(NandBusResList *l, uint64_t now)
{
    NandBusRes *r = bus_windows(l);
    int i, j = 0;
    for (i = 0; i < l->n; i++) {
        if (r[i].end > now) {
            r[j++] = r[i];
        }
    }
    l->n = j;
}

/* earliest s >= start such that [s, s + len) overlaps no booked window */
static uint64_t bus_fit(const NandBusResList *l, uint64_t start, uint64_t len)
{
    const NandBusRes *r = bus_windows(l);
    int i;
    for (i = 0; i < l->n; i++) {          /* windows are kept sorted by start */
        if (r[i].end <= start) {
            continue;
        }
        if (r[i].start >= start + len) {
            break;
        }
        start = r[i].end;
    }
    return start;
}

static bool bus_book(NandBusResList *l, uint64_t start, uint64_t end)
{
    NandBusRes *r;
    int i;

    if (l->grown && l->n == l->cap) {
        r = realloc(l->grown, 2 * (size_t)l->cap * sizeof(*r));
        if (!r) {
            abort();
        }
        l->grown = r;
        l->cap *= 2;
    } else if (!l->grown && l->n == NAND_BUS_RES_MAX) {
        return false;
    }
    r = bus_windows(l);
    for (i = l->n; i > 0 && r[i - 1].start > start; i--) {
        r[i] = r[i - 1];
    }
    r[i].start = start;
    r[i].end = end;
    l->n++;
    return true;
}

/*
 * A data phase's bus time: the whole page, or rounded up for the sectors of
 * it the controller moves, as OC 1.2 charged partial pages.
 */
static uint64_t bus_xfer_ns(const NandMedia *m, const NandLoc *loc)
{
    uint64_t page = m->cfg.timing.page_xfer_ns;
    uint64_t spp = m->cfg.secs_per_page;

    if (!loc->xfer_secs || !spp) {
        return page;
    }
    return (page * loc->xfer_secs + spp - 1) / spp;
}

/* the command phase of @op: the profile's own field, else cmd_addr_ns */
static uint64_t cmd_phase_ns(const NandMedia *m, NandMediaOp op)
{
    const NandMediaTiming *t = &m->cfg.timing;
    int64_t v = op == NAND_MEDIA_READ ? t->rd_cmd_ns :
                op == NAND_MEDIA_PROGRAM ? t->wr_cmd_ns :
                op == NAND_MEDIA_ERASE ? t->er_cmd_ns : 0;

    return v ? v : t->cmd_addr_ns;
}

/* a read's data out: the page plus what goes before and after it */
static uint64_t dout_ns(const NandMedia *m, const NandLoc *loc)
{
    return m->cfg.timing.dout_pre_ns + bus_xfer_ns(m, loc) +
           m->cfg.timing.dout_post_ns;
}

/* a program's data in: the page plus its burst edges and confirm cycle */
static uint64_t din_ns(const NandMedia *m, const NandLoc *loc)
{
    return m->cfg.timing.din_burst_ns + bus_xfer_ns(m, loc) +
           m->cfg.timing.wr_post_ns;
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
 * Extra read time spent on error correction. Wear, retention age and the
 * caller's extra tiers (program disturb) push a block towards more correction
 * work, so their tiers add and are capped together. Returns 0 unless the
 * caller enabled the model and gave a step.
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
    tiers += loc->extra_tiers;
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

/* bind the array start to the configured resources (exact bbssd ordering) */
static uint64_t array_contend_start(NandMedia *m, const NandLoc *loc, uint64_t t)
{
    uint64_t s = t;
    if (m->cfg.policy.array_contend == NAND_CONTEND_LUN_ONLY ||
        m->cfg.policy.array_contend == NAND_CONTEND_LUN_AND_PLANE) {
        uint64_t *lun = m->cfg.timeline->lun_avail(m->cfg.timeline_opaque, loc);
        s = mx(s, *lun);
    }
    if (m->cfg.policy.array_contend == NAND_CONTEND_PLANE_ONLY ||
        m->cfg.policy.array_contend == NAND_CONTEND_LUN_AND_PLANE) {
        uint64_t *pl = m->cfg.timeline->plane_avail(m->cfg.timeline_opaque, loc);
        s = mx(s, *pl);
    }
    return s;
}

/*
 * A read that preempted an in-flight P/E: push back every guarded timeline that
 * was busy at t by the read's occupancy, so the suspended operation finishes
 * that much later. Timelines that were already idle at t are left alone.
 */
static void array_suspend_extend(NandMedia *m, const NandLoc *loc, uint64_t t,
                                 uint64_t shift)
{
    if (m->cfg.policy.array_contend == NAND_CONTEND_LUN_ONLY ||
        m->cfg.policy.array_contend == NAND_CONTEND_LUN_AND_PLANE) {
        uint64_t *lun = m->cfg.timeline->lun_avail(m->cfg.timeline_opaque, loc);
        if (*lun > t) {
            *lun += shift;
        }
    }
    if (m->cfg.policy.array_contend == NAND_CONTEND_PLANE_ONLY ||
        m->cfg.policy.array_contend == NAND_CONTEND_LUN_AND_PLANE) {
        uint64_t *pl = m->cfg.timeline->plane_avail(m->cfg.timeline_opaque, loc);
        if (*pl > t) {
            *pl += shift;
        }
    }
}

static void array_commit(NandMedia *m, const NandLoc *loc, uint64_t done)
{
    if (m->cfg.policy.array_contend == NAND_CONTEND_LUN_ONLY ||
        m->cfg.policy.array_contend == NAND_CONTEND_LUN_AND_PLANE) {
        *m->cfg.timeline->lun_avail(m->cfg.timeline_opaque, loc) = done;
    }
    if (m->cfg.policy.array_contend == NAND_CONTEND_PLANE_ONLY ||
        m->cfg.policy.array_contend == NAND_CONTEND_LUN_AND_PLANE) {
        *m->cfg.timeline->plane_avail(m->cfg.timeline_opaque, loc) = done;
    }
}

/*
 * The suspend state for an array position: the plane under a plane-only rule,
 * otherwise the LUN, since a LUN rule makes the whole LUN one position.
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
    if (c->policy.array_contend == NAND_CONTEND_PLANE_ONLY) {
        idx = idx * c->planes_per_lun + loc->pl;
    }

    return &m->susp[idx];
}

/* record what an operation that went through the ordinary rule occupies */
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
 * second time. Returns false to leave the read to the ordinary rule; otherwise
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

/*
 * The prune time of an ONFI op. Op times are not monotonic (a copy's write
 * starts at its read's end), and a command that waits for its LUN leaves
 * ch_avail behind. The channel floor keeps the latest start time seen, and
 * no phase starts before it (onfi_earliest()), so windows that end before
 * the floor can go. Without a staged list there is nothing to prune.
 */
static uint64_t onfi_prune_now(NandMedia *m, uint32_t ch, uint64_t stime)
{
    if (m->bus_res && stime > m->bus_res[ch].floor) {
        m->bus_res[ch].floor = stime;
    }
    return m->bus_res ? m->bus_res[ch].floor : stime;
}

/* the earliest start of an ONFI phase: never before the channel floor */
static uint64_t onfi_earliest(const NandMedia *m, uint32_t ch, uint64_t t)
{
    return m->bus_res ? mx(t, m->bus_res[ch].floor) : t;
}

/*
 * A phase that waits for its LUN: at @a, when the LUN was free at the op's
 * start @stime, it happens now; when the LUN frees later, it is a future
 * window, so another die can use the bus before @a. @pnow prunes the
 * windows (onfi_prune_now()).
 */
static uint64_t bus_at(NandMedia *m, uint32_t ch, uint64_t stime,
                       uint64_t pnow, uint64_t a, uint64_t len)
{
    a = onfi_earliest(m, ch, a);
    return a > stime ? bus_later(m, ch, pnow, a, len) :
                       bus_now(m, ch, pnow, a, len);
}

static bool onfi_path(const NandMedia *m)
{
    return m->cfg.policy.onfi_order || m->cfg.policy.page_reg_hold;
}

/*
 * One op under the ONFI ordering bits (see NandMediaPolicy). The array and
 * ECC math are those of the staged path; only the phase order and the time
 * the LUN is held change. Suspend is refused with these bits.
 */
static NandOpCompletion onfi_op(NandMedia *m, const NandLoc *loc,
                                NandMediaOp op, uint64_t stime)
{
    const NandMediaTiming *tm = &m->cfg.timing;
    bool hold = m->cfg.policy.page_reg_hold;
    bool order = m->cfg.policy.onfi_order;
    uint64_t alat = array_lat(m, loc, op);
    uint64_t a = hold ? array_contend_start(m, loc, stime) : stime;
    uint64_t pnow = onfi_prune_now(m, loc->ch, stime);
    uint64_t d, end, held;
    NandOpCompletion c;

    if (op == NAND_MEDIA_READ) {
        uint64_t out;

        d = array_contend_start(m, loc,
                                bus_at(m, loc->ch, stime, pnow, a,
                                       cmd_phase_ns(m, op))) + alat;
        if (order) {
            end = bus_later(m, loc->ch, pnow, d, tm->status_ns);
            out = end = bus_later(m, loc->ch, pnow, end, dout_ns(m, loc));
        } else {
            out = bus_later(m, loc->ch, pnow, d, dout_ns(m, loc));
            end = bus_later(m, loc->ch, pnow, out, tm->status_ns);
        }
        held = out;
    } else if (op == NAND_MEDIA_PROGRAM) {
        uint64_t in;

        if (hold) {
            in = bus_at(m, loc->ch, stime, pnow, a,
                        cmd_phase_ns(m, op) + din_ns(m, loc));
        } else {
            in = bus_now(m, loc->ch, pnow, a, cmd_phase_ns(m, op));
            in = bus_now(m, loc->ch, pnow, in, din_ns(m, loc));
        }
        d = array_contend_start(m, loc, in) + alat;
        end = order ? bus_later(m, loc->ch, pnow, d, tm->status_ns) : d;
        held = end;
    } else {
        d = array_contend_start(m, loc,
                                bus_at(m, loc->ch, stime, pnow, a,
                                       cmd_phase_ns(m, op))) + alat;
        end = bus_later(m, loc->ch, pnow, d, tm->status_ns);
        held = end;
    }
    held = hold ? held : d;
    array_commit(m, loc, held);
    suspend_note(m, loc, op, held);
    c.done_ns = end;
    c.latency_ns = end - stime;
    return c;
}

NandOpCompletion nand_media_op(NandMedia *m, const NandLoc *loc,
                               NandMediaOp op, uint64_t stime)
{
    NandOpCompletion c;
    uint64_t t = stime;
    uint64_t alat = array_lat(m, loc, op);

    if (m->cfg.policy.channel_mode != NAND_CH_STAGED) {
        /*
         * Plane-only / lun-only model (ZNS, bbssd without bus phases): array
         * rule only; OCSSD 2.0, and 1.2 without channel timing.
         */
        uint64_t done;
        /*
         * Lock-free fast path for the single-word LUN-only rule (array_contend ==
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
        if (m->cfg.policy.array_contend == NAND_CONTEND_LUN_ONLY && !m->susp) {
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
            uint64_t s = array_contend_start(m, loc, t);
            uint64_t rs, shift;

            if (op == NAND_MEDIA_READ &&
                suspend_read_start(m, loc, t, s, alat, &rs, &shift)) {
                /*
                 * The read goes ahead of the program or erase, and every guarded
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
     * (advance_chnl) plus the array rule, so under multiple FTL threads it must be
     * serialized per channel. lock_lun/unlock_lun (when provided) take the channel
     * lock; they are NULL for the single-FTL-thread default, leaving this lock-free.
     */
    if (m->cfg.timeline->lock_lun) {
        m->cfg.timeline->lock_lun(m->cfg.timeline_opaque, loc);
    }
    if (onfi_path(m)) {
        c = onfi_op(m, loc, op, stime);
        if (m->cfg.timeline->unlock_lun) {
            m->cfg.timeline->unlock_lun(m->cfg.timeline_opaque, loc);
        }
        return c;
    }
    if (op == NAND_MEDIA_READ) {
        t = bus_now(m, loc->ch, stime, t, cmd_phase_ns(m, op));
        /*
         * Program/erase suspend: a read that finds its array mid-program or
         * mid-erase starts after a small suspend overhead instead of waiting
         * the operation out, and the suspended operation resumes after it.
         * Default off (pe_suspend=false) => identical to the plain rule.
         */
        {
            uint64_t busy = array_contend_start(m, loc, t);
            uint64_t rs, shift;

            if (suspend_read_start(m, loc, t, busy, alat, &rs, &shift)) {
                uint64_t done = rs + alat;

                array_suspend_extend(m, loc, t, shift);
                t = bus_later(m, loc->ch, stime, done, dout_ns(m, loc));
                t = bus_later(m, loc->ch, stime, t, m->cfg.timing.status_ns);
                c.done_ns = t;
                c.latency_ns = c.done_ns - stime;
                if (m->cfg.timeline->unlock_lun) {
                    m->cfg.timeline->unlock_lun(m->cfg.timeline_opaque, loc);
                }
                return c;
            }
        }
        uint64_t s = array_contend_start(m, loc, t);
        uint64_t done = s + alat;
        array_commit(m, loc, done);
        suspend_note(m, loc, op, done);
        t = bus_later(m, loc->ch, stime, done, dout_ns(m, loc));
        t = bus_later(m, loc->ch, stime, t, m->cfg.timing.status_ns);
        c.done_ns = t;
    } else if (op == NAND_MEDIA_PROGRAM) {
        t = bus_now(m, loc->ch, stime, t, cmd_phase_ns(m, op));
        t = bus_now(m, loc->ch, stime, t, din_ns(m, loc));
        uint64_t s = array_contend_start(m, loc, t);
        uint64_t done = s + alat;
        array_commit(m, loc, done);
        suspend_note(m, loc, op, done);
        c.done_ns = done;
    } else { /* erase */
        t = bus_now(m, loc->ch, stime, t, cmd_phase_ns(m, op));
        uint64_t s = array_contend_start(m, loc, t);
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

/*
 * A multi-plane group under the ONFI ordering bits. A program sends every
 * plane's command and data with the tPLPBSY gaps as one bus window, so no
 * other phase enters between planes (Section 3.1.3). A read or erase books
 * each later plane command as a future window after the gap. With
 * mp_status_per_plane a program or erase reads one status per plane.
 */
static NandOpCompletion onfi_multiplane(NandMedia *m, const NandLoc *locs,
                                        int nlocs, NandMediaOp op,
                                        uint64_t stime)
{
    const NandMediaTiming *tm = &m->cfg.timing;
    bool hold = m->cfg.policy.page_reg_hold;
    uint32_t ch = locs[0].ch;
    uint64_t plbusy = op == NAND_MEDIA_PROGRAM ? tm->tplpbsy_ns :
                      op == NAND_MEDIA_ERASE ? tm->tplebsy_ns :
                                               tm->tplrbsy_ns;
    uint64_t a = stime;
    uint64_t pnow = onfi_prune_now(m, ch, stime);
    uint64_t t, start, alat, done, held;
    NandOpCompletion c;
    int i;

    if (hold) {
        for (i = 0; i < nlocs; i++) {
            a = mx(a, array_contend_start(m, &locs[i], stime));
        }
    }
    if (op == NAND_MEDIA_PROGRAM) {
        uint64_t plane = cmd_phase_ns(m, op) + tm->din_burst_ns +
                         tm->page_xfer_ns + tm->wr_post_ns;

        t = bus_at(m, ch, stime, pnow, a,
                   nlocs * plane + (nlocs - 1) * plbusy);
    } else {
        t = bus_at(m, ch, stime, pnow, a, cmd_phase_ns(m, op));
        for (i = 1; i < nlocs; i++) {
            t = bus_later(m, ch, pnow, t + plbusy, cmd_phase_ns(m, op));
        }
    }

    start = t;
    for (i = 0; i < nlocs; i++) {
        start = mx(start, array_contend_start(m, &locs[i], start));
    }
    if (op == NAND_MEDIA_READ) {
        uint64_t worst = 0;

        alat = m->cfg.policy.use_flat_timing ? tm->rd_ns :
               tm->rd_table_ns[locs[0].flash_type][locs[0].page_type];
        for (i = 0; i < nlocs; i++) {
            worst = mx(worst, ecc_extra_ns(m, &locs[i]));
        }
        alat += worst;
    } else {
        alat = array_lat(m, &locs[0], op);
    }
    done = start + alat;

    t = done;
    if (op == NAND_MEDIA_READ) {
        uint64_t sel = tm->dout_mp_pre_ns ? (uint64_t)tm->dout_mp_pre_ns :
                       (uint64_t)tm->cmd_addr_ns;

        t = bus_later(m, ch, pnow, t, tm->status_ns);
        /*
         * A plane's column select and its page form one window: traffic of
         * another LUN between them would change the selected output.
         */
        for (i = 0; i < nlocs; i++) {
            t = bus_later(m, ch, pnow, t, sel + tm->page_xfer_ns +
                          tm->dout_post_ns);
        }
    } else {
        int nst = m->cfg.policy.mp_status_per_plane ? nlocs : 1;

        for (i = 0; i < nst; i++) {
            t = bus_later(m, ch, pnow, t, tm->status_ns);
        }
    }
    held = hold ? t : done;
    for (i = 0; i < nlocs; i++) {
        array_commit(m, &locs[i], held);
        suspend_note(m, &locs[i], op, held);
    }
    c.done_ns = t;
    c.latency_ns = t - stime;
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

    if (m->cfg.policy.channel_mode == NAND_CH_STAGED && onfi_path(m)) {
        return onfi_multiplane(m, locs, nlocs, op, stime);
    }

    /* per-plane command/address (+ data-in for programs) serialized on the bus */
    for (i = 0; i < nlocs; i++) {
        t = bus_now(m, ch, stime, t, cmd_phase_ns(m, op));
        if (op == NAND_MEDIA_PROGRAM) {
            t = bus_now(m, ch, stime, t, m->cfg.timing.din_burst_ns +
                        m->cfg.timing.page_xfer_ns + m->cfg.timing.wr_post_ns);
        }
        if (i < nlocs - 1) {
            t += plbusy;
        }
    }

    /*
     * One array op in parallel across all planes, bound by every resource the
     * configured rule covers. Going through array_contend_start/array_commit rather
     * than reaching for the accumulators directly is what lets a LUN-only caller
     * (bbssd) use this: it leaves plane_avail untouched when the rule excludes it.
     */
    uint64_t start = t;
    for (i = 0; i < nlocs; i++) {
        start = mx(start, array_contend_start(m, &locs[i], start));
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
        /* each plane's column select, then its page */
        uint64_t sel = m->cfg.timing.dout_mp_pre_ns ?
                       (uint64_t)m->cfg.timing.dout_mp_pre_ns :
                       (uint64_t)m->cfg.timing.cmd_addr_ns;

        for (i = 0; i < nlocs; i++) {
            t = bus_later(m, ch, stime, t, sel);
            t = bus_later(m, ch, stime, t, m->cfg.timing.page_xfer_ns +
                          m->cfg.timing.dout_post_ns);
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
    bool staged = m->cfg.policy.channel_mode == NAND_CH_STAGED;
    uint64_t t = stime;
    uint64_t s;

    /*
     * On-chip read then program. The page stays in the die's page register,
     * so neither step moves data over the channel. In the staged model the
     * read sends its command and address, and its status poll and the
     * program's command and address follow back to back as one booking; the
     * program ends at the array, as an ordinary program does. The read gets
     * no ECC adder: the controller never sees the data. As for every other
     * op here, an operation cannot begin before it was requested, and its
     * start comes from array_contend_start() rather than the accumulators
     * directly, so a LUN-only caller's unset plane_avail is never read.
     */
    if (m->cfg.timeline->lock_lun) {
        m->cfg.timeline->lock_lun(m->cfg.timeline_opaque, src);
    }
    if (staged && onfi_path(m)) {
        /*
         * ONFI ordering: the command waits for the die, the program ends at
         * its status, and the die is held to the end of the whole sequence.
         */
        bool hold = m->cfg.policy.page_reg_hold;
        uint64_t a = hold ? array_contend_start(m, src, stime) : stime;
        uint64_t pnow = onfi_prune_now(m, src->ch, stime);
        uint64_t r, p, end;

        t = bus_at(m, src->ch, stime, pnow, a, m->cfg.timing.cb_rd_cmd_ns ?
                   m->cfg.timing.cb_rd_cmd_ns : m->cfg.timing.cmd_addr_ns);
        r = array_contend_start(m, src, t) +
            array_lat(m, src, NAND_MEDIA_READ) - ecc_extra_ns(m, src);
        t = bus_later(m, src->ch, pnow, r, m->cfg.timing.status_ns +
                      (m->cfg.timing.cb_wr_cmd_ns ?
                       m->cfg.timing.cb_wr_cmd_ns :
                       m->cfg.timing.cmd_addr_ns));
        p = array_contend_start(m, dst, t) +
            array_lat(m, dst, NAND_MEDIA_PROGRAM);
        end = m->cfg.policy.onfi_order ?
              bus_later(m, src->ch, pnow, p, m->cfg.timing.status_ns) : p;
        array_commit(m, src, hold ? end : r);
        suspend_note(m, src, NAND_MEDIA_PROGRAM, hold ? end : r);
        array_commit(m, dst, hold ? end : p);
        suspend_note(m, dst, NAND_MEDIA_PROGRAM, hold ? end : p);
        if (m->cfg.timeline->unlock_lun) {
            m->cfg.timeline->unlock_lun(m->cfg.timeline_opaque, src);
        }
        c.done_ns = end;
        c.latency_ns = end - stime;
        return c;
    }
    if (staged) {
        t = bus_now(m, src->ch, stime, t, m->cfg.timing.cb_rd_cmd_ns ?
                    m->cfg.timing.cb_rd_cmd_ns : m->cfg.timing.cmd_addr_ns);
    }
    s = array_contend_start(m, src, t) + array_lat(m, src, NAND_MEDIA_READ) -
        ecc_extra_ns(m, src);
    array_commit(m, src, s);
    /* the on-chip read is part of the program, so it is suspended with it */
    suspend_note(m, src, NAND_MEDIA_PROGRAM, s);
    if (staged) {
        s = bus_later(m, src->ch, stime, s, m->cfg.timing.status_ns +
                      (m->cfg.timing.cb_wr_cmd_ns ?
                       m->cfg.timing.cb_wr_cmd_ns :
                       m->cfg.timing.cmd_addr_ns));
    }
    s = array_contend_start(m, dst, s) + array_lat(m, dst, NAND_MEDIA_PROGRAM);
    array_commit(m, dst, s);
    suspend_note(m, dst, NAND_MEDIA_PROGRAM, s);
    if (m->cfg.timeline->unlock_lun) {
        m->cfg.timeline->unlock_lun(m->cfg.timeline_opaque, src);
    }

    c.done_ns = s;
    c.latency_ns = s - stime;
    return c;
}

uint64_t nand_media_read_ecc_ns(NandMedia *m, const NandLoc *loc)
{
    return ecc_extra_ns(m, loc);
}

/* the fallbacks below are the ones cmd_phase_ns() and the op paths take */
void nand_media_phases(const NandMedia *m, NandMediaPhases *out)
{
    const NandMediaTiming *t = &m->cfg.timing;
    const NandMediaPolicy *p = &m->cfg.policy;
    uint64_t ca = t->cmd_addr_ns;

    memset(out, 0, sizeof(*out));
    out->tplrbsy_ns = t->tplrbsy_ns;
    out->tplpbsy_ns = t->tplpbsy_ns;
    out->tplebsy_ns = t->tplebsy_ns;
    out->staged = p->channel_mode == NAND_CH_STAGED;
    if (!out->staged) {
        return;
    }
    out->onfi_order = p->onfi_order;
    out->page_reg_hold = p->page_reg_hold;
    out->mp_status_per_plane = p->mp_status_per_plane;
    out->page_xfer_ns = t->page_xfer_ns;
    out->rd_cmd_ns = cmd_phase_ns(m, NAND_MEDIA_READ);
    out->wr_cmd_ns = cmd_phase_ns(m, NAND_MEDIA_PROGRAM);
    out->er_cmd_ns = cmd_phase_ns(m, NAND_MEDIA_ERASE);
    out->cb_rd_cmd_ns = t->cb_rd_cmd_ns ? (uint64_t)t->cb_rd_cmd_ns : ca;
    out->cb_wr_cmd_ns = t->cb_wr_cmd_ns ? (uint64_t)t->cb_wr_cmd_ns : ca;
    out->status_ns = t->status_ns;
    out->dout_pre_ns = t->dout_pre_ns;
    out->dout_post_ns = t->dout_post_ns;
    out->dout_mp_pre_ns = t->dout_mp_pre_ns ? (uint64_t)t->dout_mp_pre_ns : ca;
    out->din_burst_ns = t->din_burst_ns;
    out->wr_post_ns = t->wr_post_ns;
}
