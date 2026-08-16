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
#include "ftl-internal.h"

/* Decode a bbssd ppa into the media's normalized NandLoc. */
static NandLoc bb_decode_loc(struct ssd *ssd, struct ppa *ppa)
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
    };
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
 * plane_avail / page_reg_ready / lock_lun / unlock_lun are left unset: bbssd runs
 * the flat per-LUN gate under a single FTL thread, so the media never reaches for
 * plane-level state, a page register, or a lock.
 */
static const NandTimelineOps bb_timeline_ops = {
    .ch_avail = bb_ch_avail,
    .lun_avail = bb_lun_avail,
};

/*
 * Build the media config from bbssd ssdparams: flat per-LUN read/program/erase
 * timing gated on the LUN only, with no channel-bus accounting. This reproduces
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
    cfg.timing.page_xfer_ns = spp->pg_xfer_lat;
    cfg.timing.status_ns = spp->status_lat;
    cfg.timing.tplpbsy_ns = spp->tplpbsy;
    cfg.timing.tplrbsy_ns = spp->tplrbsy;
    cfg.timing.tplebsy_ns = spp->tplebsy;
    cfg.timing.trcbsy_ns = spp->trcbsy;
    cfg.timing.ecc_step_ns = spp->ecc_step_ns;
    cfg.timing.ecc_pe_per_tier = FEMU_ECC_PE_PER_TIER;
    cfg.timing.ecc_max_tiers = FEMU_ECC_MAX_TIERS;
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

    cfg.policy.array_gate = NAND_GATE_LUN_ONLY;
    cfg.policy.channel_mode = NAND_CH_OFF;
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
    loc = bb_decode_loc(ssd, ppa);
    return nand_media_op(&ssd->media, &loc, op, stime).latency_ns;
}
