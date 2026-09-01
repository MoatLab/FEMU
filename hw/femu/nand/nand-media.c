/*
 * Uniform NAND media-layer timing implementation. The op math here reproduces the
 * bbssd staged model (the richest superset): channel-bus phases + LUN/plane array
 * gating + page-type program latency + ECC-wear-on-read + cache-read pipeline +
 * multi-plane + copyback. ZNS/OCSSD use strict config subsets of the same code.
 *
 * Bit-identical contract: the max() ordering and the per-op phase sequence below
 * mirror hw/femu/bbssd/ftl.c ssd_advance_status / ssd_advance_multiplane /
 * ssd_advance_copyback exactly. Do not reorder the gate/reservation steps.
 */

#include "qemu/osdep.h"
#include "nand-media.h"

void nand_media_init(NandMedia *m, const NandMediaConfig *cfg)
{
    m->cfg = *cfg;
}

static inline uint64_t mx(uint64_t a, uint64_t b) { return a > b ? a : b; }

/* one typed bus phase on the channel (shared per-channel timeline) */
static uint64_t advance_chnl(NandMedia *m, uint32_t ch, uint64_t earliest,
                             uint64_t xfer_ns)
{
    uint64_t *cha = m->cfg.timeline->ch_avail(m->cfg.timeline_opaque, ch);
    uint64_t start = mx(earliest, *cha);
    *cha = start + xfer_ns;
    return *cha;
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
        if (m->cfg.policy.ecc_on_read && t->ecc_step_ns) {
            uint64_t tiers = loc->pe_cycles / t->ecc_pe_per_tier;
            if (tiers > (uint64_t)t->ecc_max_tiers) tiers = t->ecc_max_tiers;
            lat += (uint64_t)t->ecc_step_ns * tiers;
        }
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
         * mutex. Falls through to the locked path for LUN_AND_PLANE (two words,
         * not atomically CAS-able) and busy-extend.
         */
        if (m->cfg.policy.array_gate == NAND_GATE_LUN_ONLY &&
            !m->cfg.policy.array_busy_extends) {
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
        if (m->cfg.policy.array_busy_extends) {
            /* gate is the LUN only in this mode (OCSSD has no plane accumulator) */
            uint64_t *lun = m->cfg.timeline->lun_avail(m->cfg.timeline_opaque, loc);
            if (t < *lun) {
                *lun += alat;
            } else {
                *lun = t + alat;
            }
            done = *lun;
        } else {
            uint64_t s = array_gate_start(m, loc, t);
            done = s + alat;
            array_commit(m, loc, done);
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
        t = advance_chnl(m, loc->ch, t, m->cfg.timing.cmd_addr_ns);
        /*
         * Program/erase suspend: if the LUN is mid-P/E when this read arrives, real NAND
         * lets the read preempt the slow operation. Model it by starting the read after a
         * small suspend overhead (tsusp) instead of waiting out the whole P/E, then pushing
         * the suspended op's completion back by the read's array occupancy (it resumes after
         * the read). Default off (pe_suspend=false) => identical to the plain gate.
         */
        if (m->cfg.policy.pe_suspend) {
            uint64_t *lun = m->cfg.timeline->lun_avail(m->cfg.timeline_opaque, loc);
            if (t < *lun) {
                uint64_t s = t + m->cfg.timing.tsusp_ns;
                uint64_t done = s + alat;
                /* suspended P/E resumes after the read: its remaining work shifts later */
                *lun += (alat + m->cfg.timing.tsusp_ns);
                if (m->cfg.policy.cache_read && m->cfg.timeline->page_reg_ready) {
                    uint64_t *prr =
                        m->cfg.timeline->page_reg_ready(m->cfg.timeline_opaque, loc);
                    uint64_t dout = mx(*prr, done);
                    t = advance_chnl(m, loc->ch, dout, m->cfg.timing.page_xfer_ns);
                    *prr = t;
                } else {
                    t = advance_chnl(m, loc->ch, done, m->cfg.timing.page_xfer_ns);
                }
                t = advance_chnl(m, loc->ch, t, m->cfg.timing.status_ns);
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
        if (m->cfg.policy.cache_read && m->cfg.timeline->page_reg_ready) {
            uint64_t rcbsy = m->cfg.timing.trcbsy_ns ? m->cfg.timing.trcbsy_ns : alat;
            *m->cfg.timeline->lun_avail(m->cfg.timeline_opaque, loc) = s + rcbsy;
            uint64_t *prr = m->cfg.timeline->page_reg_ready(m->cfg.timeline_opaque, loc);
            uint64_t dout = mx(*prr, done);
            t = advance_chnl(m, loc->ch, dout, m->cfg.timing.page_xfer_ns);
            *prr = t;
        } else {
            t = advance_chnl(m, loc->ch, done, m->cfg.timing.page_xfer_ns);
        }
        t = advance_chnl(m, loc->ch, t, m->cfg.timing.status_ns);
        c.done_ns = t;
    } else if (op == NAND_MEDIA_PROGRAM) {
        t = advance_chnl(m, loc->ch, t, m->cfg.timing.cmd_addr_ns);
        t = advance_chnl(m, loc->ch, t, m->cfg.timing.page_xfer_ns);
        uint64_t s = array_gate_start(m, loc, t);
        uint64_t done = s + alat;
        array_commit(m, loc, done);
        c.done_ns = done;
    } else { /* erase */
        t = advance_chnl(m, loc->ch, t, m->cfg.timing.cmd_addr_ns);
        uint64_t s = array_gate_start(m, loc, t);
        uint64_t done = s + alat;
        array_commit(m, loc, done);
        t = advance_chnl(m, loc->ch, done, m->cfg.timing.status_ns);
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
        t = advance_chnl(m, ch, t, m->cfg.timing.cmd_addr_ns);
        if (op == NAND_MEDIA_PROGRAM) {
            t = advance_chnl(m, ch, t, m->cfg.timing.page_xfer_ns);
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
        if (m->cfg.policy.ecc_on_read && m->cfg.timing.ecc_step_ns) {
            uint64_t worst = 0;
            for (i = 0; i < nlocs; i++) {
                uint64_t tiers = locs[i].pe_cycles / m->cfg.timing.ecc_pe_per_tier;
                if (tiers > (uint64_t)m->cfg.timing.ecc_max_tiers)
                    tiers = m->cfg.timing.ecc_max_tiers;
                uint64_t extra = (uint64_t)m->cfg.timing.ecc_step_ns * tiers;
                if (extra > worst) worst = extra;
            }
            alat += worst;
        }
    } else {
        alat = array_lat(m, &locs[0], op);
    }
    uint64_t done = start + alat;
    for (i = 0; i < nlocs; i++) {
        array_commit(m, &locs[i], done);
    }

    t = done;
    if (op == NAND_MEDIA_READ) {
        if (m->cfg.timing.status_ns)
            t = advance_chnl(m, ch, t, m->cfg.timing.status_ns);
        for (i = 0; i < nlocs; i++) {
            t = advance_chnl(m, ch, t, m->cfg.timing.cmd_addr_ns);
            t = advance_chnl(m, ch, t, m->cfg.timing.page_xfer_ns);
        }
    } else if (m->cfg.timing.status_ns) {
        t = advance_chnl(m, ch, t, m->cfg.timing.status_ns);
    }

    c.done_ns = t;
    c.latency_ns = t - stime;
    return c;
}

NandOpCompletion nand_media_copyback(NandMedia *m, const NandLoc *src,
                                     const NandLoc *dst, uint64_t stime)
{
    NandOpCompletion c;
    uint64_t *slun = m->cfg.timeline->lun_avail(m->cfg.timeline_opaque, src);
    uint64_t *spl  = m->cfg.timeline->plane_avail(m->cfg.timeline_opaque, src);
    uint64_t *dlun = m->cfg.timeline->lun_avail(m->cfg.timeline_opaque, dst);
    uint64_t *dpl  = m->cfg.timeline->plane_avail(m->cfg.timeline_opaque, dst);
    uint64_t s;

    /* on-chip read then program; no bus phases (copyback_skips_bus) */
    s = mx(*slun, *spl) + array_lat(m, src, NAND_MEDIA_READ);
    *slun = s; *spl = s;
    s = mx(s, mx(*dlun, *dpl)) + array_lat(m, dst, NAND_MEDIA_PROGRAM);
    *dlun = s; *dpl = s;

    c.done_ns = s;
    c.latency_ns = 0; /* GC-internal; host effect is via freed channel + LUN busy */
    return c;
}
