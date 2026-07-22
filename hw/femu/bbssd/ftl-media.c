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

/* Decode a bbssd ppa into the media's normalized NandLoc. */
static NandLoc bb_decode_loc(struct ssd *ssd, struct ppa *ppa)
{
    NandLoc loc = {
        .ch = ppa->g.ch, .lun = ppa->g.lun, .pl = ppa->g.pl,
        .blk = ppa->g.blk, .pg = ppa->g.pg,
        .flash_type = 0, .page_type = 0, .pe_cycles = 0,
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
    cfg.policy.use_flat_timing = true;
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
