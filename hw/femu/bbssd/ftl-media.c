/*
 * bbssd FTL <-> uniform NAND media-layer bridge.
 *
 * Decodes the bbssd ppa into the media's normalized NandLoc, builds the media
 * config from ssdparams, and provides the ssd_advance_status wrapper the datapath
 * and GC call. The timing math lives in hw/femu/nand/nand-media.c; this file only
 * adapts bbssd's geometry and per-resource state to that API.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "../nand/onfi.h"
#include "ftl-internal.h"

/*
 * Program disturb ECC tiers for a read of @ppa: an opt-in sensitivity model,
 * with tier counts the user picks rather than ones fitted to measured error
 * rates. The bottom wordlines of a block take pd_edge_tiers, and a block that
 * is only part programmed takes pd_open_tiers.
 */
static uint8_t bb_pd_tiers(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_block *blk;
    int tiers = 0;

    if (spp->pd_edge_wls &&
        ppa->g.pg / spp->pd_wl_pages < spp->pd_edge_wls) {
        tiers += spp->pd_edge_tiers;
    }
    if (spp->pd_open_tiers) {
        blk = get_blk(ssd, ppa);
        if (blk->wp > 0 && blk->wp < spp->pgs_per_blk) {
            tiers += spp->pd_open_tiers;
        }
    }
    return (uint8_t)tiers;
}

/*
 * Decode a bbssd ppa into the media's normalized NandLoc. @data is false for a
 * translation page access, which addresses a placeholder block: it keeps the
 * wear and close-time age and takes no program disturb term.
 */
static NandLoc bb_decode_loc(struct ssd *ssd, struct ppa *ppa, uint64_t stime,
                             bool data)
{
    int ct = (ssd->n) ? ssd->n->nand_cell_type : 0;
    NandLoc loc = {
        .ch = ppa->g.ch, .lun = ppa->g.lun, .pl = ppa->g.pl,
        .blk = ppa->g.blk, .pg = ppa->g.pg,
        /*
         * With a cell type set, the media layer uses table timing, so report the
         * real flash type and the paired page type. Otherwise flash_type is 0
         * (flat timing) and page_type is the pg-modulo-bits-per-cell value, which
         * only the optional pgtype_lat program-latency model consumes.
         */
        .flash_type = (uint8_t)ct,
        .page_type = ct ? get_page_type(ct, ppa->g.pg) :
                     (uint8_t)(ppa->g.pg % (ssd->sp.cell_pages ?
                                            ssd->sp.cell_pages : 3)),
        /*
         * pe_cycles feeds only the wear-dependent ECC-on-read latency tier, which
         * is active when ecc_step_ns is set. Read the block erase count lazily so
         * the common path does not chase block metadata on every op.
         */
        .pe_cycles = ssd->sp.ecc_step_ns ?
                     (uint32_t)get_blk(ssd, ppa)->erase_cnt : 0,
        .age_sec = 0,
    };

    /*
     * Charge leaks with time as well as with wear, so how long the data has sat
     * programmed feeds the same correction model. close_time is when the line
     * filled; a line still being written has none yet.
     */
    if (ssd->sp.ecc_step_ns && ssd->sp.ecc_retention_sec) {
        struct line *line = get_line(ssd, ppa);
        /*
         * With pd_open_age the age starts at the line's first program, so data
         * in a line still being written ages too, and a close does not start
         * it again. One time per line makes later pages look older than they
         * are.
         */
        uint64_t from = data && ssd->sp.pd_open_age ? line->open_time :
                        line->close_time;
        uint64_t age = ssd_data_age_ns(ssd, from, stime) /
                       NANOSECONDS_PER_SECOND;

        loc.age_sec = (uint32_t)MIN(age, UINT32_MAX);
    }
    if (data && ssd->sp.ecc_step_ns) {
        loc.extra_tiers = bb_pd_tiers(ssd, ppa);
    }
    return loc;
}

/* timeline-vtable thunks: return pointers into bbssd's own per-resource state */
static uint64_t *bb_ch_avail(void *opaque, uint32_t ch)
{
    struct ssd *ssd = opaque;
    return &ssd->ch[ch].next_ch_avail_time;
}
static uint64_t *bb_lun_avail(void *opaque, const NandLoc *loc)
{
    struct ssd *ssd = opaque;
    return &ssd->ch[loc->ch].lun[loc->lun].next_lun_avail_time;
}

/*
 * plane_avail / lock_lun / unlock_lun are left unset: bbssd runs the flat
 * per-LUN rule under a single FTL thread, so the media never reaches for
 * plane-level state or a lock.
 */
static const NandTimelineOps bb_timeline_ops = {
    .ch_avail = bb_ch_avail,
    .lun_avail = bb_lun_avail,
};

/*
 * Build the media config from bbssd ssdparams: flat per-LUN read/program/erase
 * timing bound by the LUN only, with no channel-bus accounting. This reproduces
 * the historical ssd_advance_status latency exactly.
 */
void bb_nand_media_init(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;
    NandMediaConfig cfg = {0};

    cfg.nchs = spp->nchs;
    cfg.luns_per_ch = spp->luns_per_ch;
    cfg.planes_per_lun = spp->pls_per_lun;
    cfg.timing.rd_ns = spp->pg_rd_lat;
    cfg.timing.wr_ns = spp->pg_wr_lat;
    cfg.timing.er_ns = spp->blk_er_lat;

    /* optional finer NAND timing; every knob defaults to 0, leaving these zero
     * and the behavior bit-identical to the flat model. */
    cfg.timing.cmd_addr_ns = spp->cmd_addr_lat;
    /* ch_xfer_lat is the older name for the data transfer phase */
    cfg.timing.page_xfer_ns = spp->pg_xfer_lat ? spp->pg_xfer_lat :
                                                 spp->ch_xfer_lat;
    cfg.timing.status_ns = spp->status_lat;
    cfg.timing.tplpbsy_ns = spp->tplpbsy;
    cfg.timing.tplrbsy_ns = spp->tplrbsy;
    cfg.timing.tplebsy_ns = spp->tplebsy;
    cfg.policy.pe_suspend = (spp->pe_suspend != 0);
    cfg.timing.tsusp_ns = spp->tsusp_ns;
    cfg.timing.ecc_step_ns = spp->ecc_step_ns;
    cfg.timing.ecc_pe_per_tier = FEMU_ECC_PE_PER_TIER;
    cfg.timing.ecc_max_tiers = FEMU_ECC_MAX_TIERS;
    cfg.timing.ecc_retention_per_tier_sec = spp->ecc_retention_sec;
    /*
     * The media layer ties the ECC read adder to this as well as on
     * ecc_step_ns. Nothing ever set it, so ecc_step_ns has been inert; the
     * adder itself is still off unless ecc_step_ns is given a value.
     */
    cfg.policy.ecc_on_read = true;
    cfg.timing.pgtype_lat = (spp->pgtype_lat != 0);
    /* page-type program multipliers (x1000): SLC..PLC rows, picked by cell_pages.
     * Only consulted when pgtype_lat is set, so this is inert by default. */
    {
        static const int32_t mult[5][NAND_MEDIA_MAX_PGTYPE] = {
            {1000,    0,    0,    0,    0, 0},
            { 600, 1400,    0,    0,    0, 0},
            { 600, 1000, 1400,    0,    0, 0},
            { 500,  850, 1150, 1500,    0, 0},
            { 400,  750, 1000, 1250, 1600, 0},
        };
        int cp = spp->cell_pages < 1 ? 1 : (spp->cell_pages > 5 ? 5 : spp->cell_pages);
        for (int i = 0; i < NAND_MEDIA_MAX_PGTYPE; i++) {
            cfg.timing.pgtype_mult[i] = mult[cp - 1][i];
        }
    }

    cfg.policy.use_flat_timing = true;
    /*
     * Cell type: when nand_cell_type is set (1 SLC .. 4 QLC), drive true per-type
     * NAND timing from the shared flash-type table (per-type read/program/erase
     * plus page pairing) instead of the flat latencies. Default (0) keeps the flat
     * path bit-identical.
     */
    if (ssd->n && ssd->n->nand_cell_type) {
        int ft = ssd->n->nand_cell_type;
        init_nand_flash(ssd->n); /* ensure the shared flash tables are populated */
        for (int p = 0; p < NAND_MEDIA_MAX_PGTYPE; p++) {
            cfg.timing.rd_table_ns[ft][p] = get_page_read_latency(ft, p);
            cfg.timing.wr_table_ns[ft][p] = get_page_write_latency(ft, p);
        }
        cfg.timing.er_table_ns[ft] = get_blk_erase_latency(ft);
        cfg.policy.use_flat_timing = false;
        cfg.timing.pgtype_lat = false; /* the table path already carries pairing */
    }

    /*
     * ONFI 6.0 profile: the timing mode gives every bus phase, and the array
     * times stay as set above. Realize refuses the hand-set phase knobs with
     * it, so none of them is overwritten here. A tPL*BSY left at 0 takes the
     * Table 4-30 typical value.
     */
    if (spp->onfi_mode >= 0) {
        OnfiInput in = {
            .mode = spp->onfi_mode,
            .mts = spp->onfi_mts,
            .page_bytes = (uint64_t)spp->secsz * spp->secs_per_pg +
                          spp->onfi_spare_bytes,
            .col_cycles = spp->onfi_col_cycles,
            .row_cycles = spp->onfi_row_cycles,
            .multi_lun = spp->luns_per_ch > 1,
            .tccs_ns = spp->onfi_tccs_ns,
        };
        OnfiTiming ot;

        if (onfi_derive(&in, &ot) == 0) {
            cfg.timing.page_xfer_ns = ot.page_xfer_ns;
            cfg.timing.status_ns = ot.status_ns;
            cfg.timing.rd_cmd_ns = ot.rd_cmd_ns;
            cfg.timing.wr_cmd_ns = ot.wr_cmd_ns;
            cfg.timing.er_cmd_ns = ot.er_cmd_ns;
            cfg.timing.cb_rd_cmd_ns = ot.cb_rd_cmd_ns;
            cfg.timing.cb_wr_cmd_ns = ot.cb_wr_cmd_ns;
            cfg.timing.din_burst_ns = ot.din_burst_ns;
            cfg.timing.wr_post_ns = ot.wr_post_ns;
            cfg.timing.dout_pre_ns = ot.dout_pre_ns;
            cfg.timing.dout_post_ns = ot.dout_post_ns;
            cfg.timing.dout_mp_pre_ns = ot.dout_mp_pre_ns;
            if (!cfg.timing.tplpbsy_ns) {
                cfg.timing.tplpbsy_ns = ot.plbusy_ns;
            }
            if (!cfg.timing.tplrbsy_ns) {
                cfg.timing.tplrbsy_ns = ot.plbusy_ns;
            }
            if (!cfg.timing.tplebsy_ns) {
                cfg.timing.tplebsy_ns = ot.plbusy_ns;
            }
            /*
             * A full bounded window list books the bus from now instead,
             * which would close the gaps the profile's later phases leave.
             */
            cfg.policy.bus_res_unbounded = true;
            /*
             * ONFI order: status before a read's data out and after a
             * program. A page register holds its LUN to the end of the op,
             * and with several LUNs a multi-plane program or erase reads one
             * 78h status per plane.
             */
            cfg.policy.onfi_order = true;
            cfg.policy.page_reg_hold = true;
            cfg.policy.mp_status_per_plane = in.multi_lun;
        }
    }

    cfg.policy.array_contend = NAND_CONTEND_LUN_ONLY;
    /*
     * The channel bus phases only exist in the staged model. Select it when
     * a phase has a duration, so the unset default keeps the plain array rule
     * and its exact timing.
     */
    cfg.policy.channel_mode = (cfg.timing.cmd_addr_ns || cfg.timing.page_xfer_ns ||
                               cfg.timing.status_ns) ? NAND_CH_STAGED : NAND_CH_OFF;
    cfg.timeline = &bb_timeline_ops;
    cfg.timeline_opaque = ssd;
    nand_media_init(&ssd->media, &cfg);
}

/*
 * Refresh only the flat per-op latencies after a runtime change to the device
 * parameters (the delay-emulation toggle rewrites pg_rd_lat/pg_wr_lat/blk_er_lat).
 * Three aligned scalar stores, matching the concurrency profile of the previous
 * inline code, which read those same ssd->sp scalars live per op. This avoids
 * rewriting the whole media config under the FTL thread, which would be a wide
 * non-atomic copy racing the datapath's per-op config reads.
 */
void bb_nand_media_refresh_timing(struct ssd *ssd)
{
    ssd->media.cfg.timing.rd_ns = ssd->sp.pg_rd_lat;
    ssd->media.cfg.timing.wr_ns = ssd->sp.pg_wr_lat;
    ssd->media.cfg.timing.er_ns = ssd->sp.blk_er_lat;
}

/*
 * NAND op timing lives in the uniform media layer (hw/femu/nand/nand-media.c).
 * This wrapper maps a bbssd read/program/erase onto nand_media_op; the timing math
 * and per-LUN accumulator update are identical to the historical
 * ssd_advance_status (same max() ordering). The signature is unchanged so every
 * caller (read, write, GC) is untouched.
 */
uint64_t ssd_advance_status(struct ssd *ssd, struct ppa *ppa,
                            struct nand_cmd *ncmd)
{
    uint64_t stime = (ncmd->stime == 0) ?
        qemu_clock_get_ns(QEMU_CLOCK_REALTIME) : ncmd->stime;
    NandLoc loc;
    NandMediaOp op;

    switch (ncmd->cmd) {
    case NAND_READ:  op = NAND_MEDIA_READ;    break;
    case NAND_WRITE: op = NAND_MEDIA_PROGRAM; break;
    case NAND_ERASE: op = NAND_MEDIA_ERASE;   break;
    default:
        ftl_err("Unsupported NAND command: 0x%x\n", ncmd->cmd);
        return 0;
    }
    /*
     * Count the read against its block. Every bbssd NAND read passes through
     * here, host or collection, and a read stresses the other pages in the
     * block -- so this is the pressure a device watches to decide when data
     * must be rewritten. Reads answered from the write buffer or the read cache
     * never reach the media and correctly do not count, and a translation-page
     * read is only charged for time: it addresses a placeholder block, whose
     * data pages it does not disturb.
     */
    if (op == NAND_MEDIA_READ && ncmd->type != MAP_IO) {
        get_blk(ssd, ppa)->read_cnt++;
    }

    ssd->media_ops[op]++;
    /* the thermal model reads these from the main loop */
    qatomic_set(&ssd->media_plane_ops[op],
                qatomic_read(&ssd->media_plane_ops[op]) + 1);
    loc = bb_decode_loc(ssd, ppa, stime, ncmd->type != MAP_IO);
    return nand_media_op(&ssd->media, &loc, op, stime).latency_ns;
}

/*
 * Multi-plane variant: one command sequence addressing the same block on every
 * plane of a LUN, which real NAND runs as a single array operation rather than
 * one erase after another. GC erase reclaims the same block index on every
 * plane, exactly the shape the die can batch; with mp_program and mp_read the
 * host datapath sends programs and reads of one page on several planes here.
 *
 * With one plane there is nothing to batch, so this is the ordinary single-op
 * path and the default configuration is untouched.
 */
uint64_t ssd_advance_status_multiplane(struct ssd *ssd, struct ppa *ppas,
                                       int nppas, struct nand_cmd *ncmd)
{
    NandLoc locs[1 << PL_BITS];
    uint64_t stime;
    NandMediaOp op;
    int i;

    if (nppas <= 1) {
        return ssd_advance_status(ssd, &ppas[0], ncmd);
    }
    ftl_assert(nppas <= (1 << PL_BITS));

    switch (ncmd->cmd) {
    case NAND_READ:  op = NAND_MEDIA_READ;    break;
    case NAND_WRITE: op = NAND_MEDIA_PROGRAM; break;
    case NAND_ERASE: op = NAND_MEDIA_ERASE;   break;
    default:
        ftl_err("Unsupported NAND command: 0x%x\n", ncmd->cmd);
        return 0;
    }

    stime = (ncmd->stime == 0) ?
        qemu_clock_get_ns(QEMU_CLOCK_REALTIME) : ncmd->stime;

    for (i = 0; i < nppas; i++) {
        if (op == NAND_MEDIA_READ) {
            get_blk(ssd, &ppas[i])->read_cnt++;
        }
        locs[i] = bb_decode_loc(ssd, &ppas[i], stime, ncmd->type != MAP_IO);
    }

    ssd->media_ops[op]++;
    qatomic_set(&ssd->media_plane_ops[op],
                qatomic_read(&ssd->media_plane_ops[op]) + nppas);
    return nand_media_multiplane(&ssd->media, locs, nppas, op, stime).latency_ns;
}

/**
 * ssd_copyback_ok - may collection move @src to @dst on the die?
 * @ssd: the device
 * @src: the valid page collection moves
 * @dst: the destination page collection chose
 *
 * Copyback keeps the page in the die's page register, so source and
 * destination must share a channel, a LUN and a plane. The controller never
 * sees the data and cannot correct it, so a page whose read needs correction
 * goes off-chip instead.
 */
bool ssd_copyback_ok(struct ssd *ssd, struct ppa *src, struct ppa *dst)
{
    NandLoc loc;

    if (!ssd->sp.gc_copyback || src->g.ch != dst->g.ch ||
        src->g.lun != dst->g.lun || src->g.pl != dst->g.pl) {
        return false;
    }
    /* a parameter page without odd to even copyback (bytes 6-7 bit 4) */
    if (ssd->sp.onfi_cb_parity && ((src->g.pg ^ dst->g.pg) & 1)) {
        return false;
    }
    loc = bb_decode_loc(ssd, src, qemu_clock_get_ns(QEMU_CLOCK_REALTIME),
                        true);
    return nand_media_read_ecc_ns(&ssd->media, &loc) == 0;
}

/**
 * ssd_advance_copyback - time a collection move done on the die
 * @ssd: the device
 * @src: the page read into the page register
 * @dst: the page programmed from it
 *
 * Counts as one read of the source block and one program, like the off-chip
 * move it replaces, and returns the latency of both steps.
 */
uint64_t ssd_advance_copyback(struct ssd *ssd, struct ppa *src,
                              struct ppa *dst)
{
    uint64_t stime = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    NandLoc sloc;
    NandLoc dloc;

    get_blk(ssd, src)->read_cnt++;
    ssd->media_ops[NAND_MEDIA_READ]++;
    ssd->media_ops[NAND_MEDIA_PROGRAM]++;
    qatomic_set(&ssd->media_plane_ops[NAND_MEDIA_READ],
                qatomic_read(&ssd->media_plane_ops[NAND_MEDIA_READ]) + 1);
    qatomic_set(&ssd->media_plane_ops[NAND_MEDIA_PROGRAM],
                qatomic_read(&ssd->media_plane_ops[NAND_MEDIA_PROGRAM]) + 1);
    sloc = bb_decode_loc(ssd, src, stime, true);
    dloc = bb_decode_loc(ssd, dst, stime, true);
    return nand_media_copyback(&ssd->media, &sloc, &dloc, stime).latency_ns;
}
