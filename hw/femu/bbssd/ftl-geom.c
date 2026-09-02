/*
 * bbssd FTL geometry setup: derive the ssdparams from the device parameters and
 * allocate the channel / LUN / plane / block / page array that backs the FTL.
 * Split out of the ftl.c monolith; the timing and datapath live elsewhere.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"

/*
 * Validate the configured geometry before any of it is used to size an
 * allocation or drive the datapath.
 *
 * Two independent failure modes are reachable from the device parameters. An
 * axis of zero or less divides by zero on the datapath -- an LBA becomes a page
 * by dividing by secs_per_pg -- or allocates an empty array the FTL still
 * indexes. Separately, an axis that fits its own PPA field can still overflow
 * the derived totals: those are held in int, and the sector count is the
 * product of every axis, so per-axis values that are each legal can push the
 * aggregate past INT_MAX and wrap negative. Compute the aggregate in 64-bit
 * here and reject it, rather than letting ssd_init() allocate from a wrapped
 * count.
 */
int bb_check_geometry(FemuCtrl *n, Error **errp)
{
    const BbCtrlParams *p = &n->bb_params;
    const struct {
        const char *name;
        int value;
        int max;              /* 0 = no PPA field bound, only positivity */
    } axes[] = {
        { "secsz",       p->secsz,       0 },
        { "secs_per_pg", p->secs_per_pg, 1 << SEC_BITS },
        { "pgs_per_blk", p->pgs_per_blk, 1 << PG_BITS  },
        { "blks_per_pl", p->blks_per_pl, 1 << BLK_BITS },
        { "pls_per_lun", p->pls_per_lun, 1 << PL_BITS  },
        { "luns_per_ch", p->luns_per_ch, 1 << LUN_BITS },
        { "nchs",        p->nchs,        1 << CH_BITS  },
    };
    uint64_t tt_secs;
    int i;

    for (i = 0; i < (int)ARRAY_SIZE(axes); i++) {
        if (axes[i].value <= 0) {
            error_setg(errp, "FEMU bbssd: %s must be greater than 0, got %d",
                       axes[i].name, axes[i].value);
            return -1;
        }
        /*
         * An index runs 0..value-1, so a count equal to the field's capacity
         * still addresses within the field; only a larger count aliases.
         */
        if (axes[i].max && axes[i].value > axes[i].max) {
            error_setg(errp, "FEMU bbssd: %s value %d exceeds the %d addressable "
                       "by its PPA field", axes[i].name, axes[i].value,
                       axes[i].max);
            return -1;
        }
    }

    if (p->read_reclaim_limit < 0) {
        error_setg(errp, "FEMU bbssd: read_reclaim_limit must not be negative");
        return -1;
    }

    if (p->retention_limit_sec < 0) {
        error_setg(errp, "FEMU bbssd: retention_limit_sec must not be negative");
        return -1;
    }
    if (p->buffer_size < 0) {
        error_setg(errp, "FEMU bbssd: buffer_size must not be negative");
        return -1;
    }
    /*
     * The write buffer starts writing pages back once it reaches
     * buffer_thres_pcent of its size, so a level above 100 would never be
     * reached and the buffer would grow without bound.
     */
    if (p->buffer_size > 0 &&
        (p->buffer_thres_pcent <= 0 || p->buffer_thres_pcent > 100)) {
        error_setg(errp, "FEMU bbssd: buffer_thres_pcent must be between 1 and "
                   "100, got %d", p->buffer_thres_pcent);
        return -1;
    }

    tt_secs = (uint64_t)p->secs_per_pg * p->pgs_per_blk * p->blks_per_pl *
              p->pls_per_lun * p->luns_per_ch * p->nchs;
    if (tt_secs > INT_MAX) {
        error_setg(errp, "FEMU bbssd: the geometry describes %" PRIu64 " sectors, "
                   "which exceeds the %d the FTL can address; reduce one of "
                   "secs_per_pg, pgs_per_blk, blks_per_pl, pls_per_lun, "
                   "luns_per_ch or nchs", tt_secs, INT_MAX);
        return -1;
    }

    return 0;
}

static void check_params(struct ssdparams *spp)
{
    /*
     * we are using a general write pointer increment method now, no need to
     * force luns_per_ch and nchs to be power of 2
     */

    //ftl_assert(is_power_of_2(spp->luns_per_ch));
    //ftl_assert(is_power_of_2(spp->nchs));
}

void ssd_init_params(struct ssdparams *spp, FemuCtrl *n)
{
    spp->secsz = n->bb_params.secsz; // 512
    spp->secs_per_pg = n->bb_params.secs_per_pg; // 8
    spp->pgs_per_blk = n->bb_params.pgs_per_blk; //256
    spp->blks_per_pl = n->bb_params.blks_per_pl; /* 256 16GB */
    spp->pls_per_lun = n->bb_params.pls_per_lun; // 1
    spp->luns_per_ch = n->bb_params.luns_per_ch; // 8
    spp->nchs = n->bb_params.nchs; // 8

    spp->pg_rd_lat = n->bb_params.pg_rd_lat;
    spp->pg_wr_lat = n->bb_params.pg_wr_lat;
    spp->blk_er_lat = n->bb_params.blk_er_lat;
    spp->ch_xfer_lat = n->bb_params.ch_xfer_lat;

    /* optional richer NAND timing model (all 0 = off, flat per-page latency) */
    spp->cell_pages = n->bb_params.cell_pages;
    spp->pgtype_lat = n->bb_params.pgtype_lat;
    spp->ecc_step_ns = n->bb_params.ecc_step_ns;
    spp->cmd_addr_lat = n->bb_params.cmd_addr_lat;
    spp->pg_xfer_lat = n->bb_params.pg_xfer_lat;
    spp->status_lat = n->bb_params.status_lat;
    spp->tplpbsy = n->bb_params.tplpbsy;
    spp->tplrbsy = n->bb_params.tplrbsy;
    spp->tplebsy = n->bb_params.tplebsy;
    spp->trcbsy = n->bb_params.trcbsy;
    spp->trim_lat_ns = n->bb_params.trim_lat_ns;

    /* DRAM write buffer */
    spp->buffer_size = n->bb_params.buffer_size;
    spp->buffer_thres_pcent = n->bb_params.buffer_thres_pcent / 100.0;
    spp->hot_cold_sep = n->bb_params.hot_cold_sep;
    spp->read_reclaim_limit = n->bb_params.read_reclaim_limit;
    spp->retention_limit_sec = n->bb_params.retention_limit_sec;
    spp->read_hit_cnt = 0;
    spp->read_cnt = 0;
    spp->write_hit_cnt = 0;
    spp->write_cnt = 0;

    /* calculated values */
    spp->secs_per_blk = spp->secs_per_pg * spp->pgs_per_blk;
    spp->secs_per_pl = spp->secs_per_blk * spp->blks_per_pl;
    spp->secs_per_lun = spp->secs_per_pl * spp->pls_per_lun;
    spp->secs_per_ch = spp->secs_per_lun * spp->luns_per_ch;
    spp->tt_secs = spp->secs_per_ch * spp->nchs;

    spp->pgs_per_pl = spp->pgs_per_blk * spp->blks_per_pl;
    spp->pgs_per_lun = spp->pgs_per_pl * spp->pls_per_lun;
    spp->pgs_per_ch = spp->pgs_per_lun * spp->luns_per_ch;
    spp->tt_pgs = spp->pgs_per_ch * spp->nchs;

    spp->blks_per_lun = spp->blks_per_pl * spp->pls_per_lun;
    spp->blks_per_ch = spp->blks_per_lun * spp->luns_per_ch;
    spp->tt_blks = spp->blks_per_ch * spp->nchs;

    spp->pls_per_ch =  spp->pls_per_lun * spp->luns_per_ch;
    spp->tt_pls = spp->pls_per_ch * spp->nchs;

    spp->tt_luns = spp->luns_per_ch * spp->nchs;

    /*
     * A line is one block index taken across every channel, LUN and plane, so
     * there are as many lines as a plane has blocks. With one plane per LUN
     * these are the same numbers as before: blks_per_lun == blks_per_pl.
     */
    spp->blks_per_line = spp->tt_luns * spp->pls_per_lun;
    spp->pgs_per_line = spp->blks_per_line * spp->pgs_per_blk;
    spp->secs_per_line = spp->pgs_per_line * spp->secs_per_pg;
    spp->tt_lines = spp->blks_per_pl;

    spp->gc_thres_pcent = n->bb_params.gc_thres_pcent/100.0;
    spp->gc_thres_lines = (int)((1 - spp->gc_thres_pcent) * spp->tt_lines);
    spp->gc_thres_pcent_high = n->bb_params.gc_thres_pcent_high/100.0;
    spp->gc_thres_lines_high = (int)((1 - spp->gc_thres_pcent_high) * spp->tt_lines);
    spp->enable_gc_delay = true;


    check_params(spp);
}

static void ssd_init_nand_page(struct nand_page *pg, struct ssdparams *spp)
{
    pg->nsecs = spp->secs_per_pg;
    pg->sec = g_malloc0(sizeof(nand_sec_status_t) * pg->nsecs);
    for (int i = 0; i < pg->nsecs; i++) {
        pg->sec[i] = SEC_FREE;
    }
    pg->status = PG_FREE;
}

static void ssd_init_nand_blk(struct nand_block *blk, struct ssdparams *spp)
{
    blk->npgs = spp->pgs_per_blk;
    blk->pg = g_malloc0(sizeof(struct nand_page) * blk->npgs);
    for (int i = 0; i < blk->npgs; i++) {
        ssd_init_nand_page(&blk->pg[i], spp);
    }
    blk->ipc = 0;
    blk->vpc = 0;
    blk->erase_cnt = 0;
    blk->wp = 0;
}

static void ssd_init_nand_plane(struct nand_plane *pl, struct ssdparams *spp)
{
    pl->nblks = spp->blks_per_pl;
    pl->blk = g_malloc0(sizeof(struct nand_block) * pl->nblks);
    for (int i = 0; i < pl->nblks; i++) {
        ssd_init_nand_blk(&pl->blk[i], spp);
    }
}

static void ssd_init_nand_lun(struct nand_lun *lun, struct ssdparams *spp)
{
    lun->npls = spp->pls_per_lun;
    lun->pl = g_malloc0(sizeof(struct nand_plane) * lun->npls);
    for (int i = 0; i < lun->npls; i++) {
        ssd_init_nand_plane(&lun->pl[i], spp);
    }
    lun->next_lun_avail_time = 0;
    lun->busy = false;
}

void ssd_init_ch(struct ssd_channel *ch, struct ssdparams *spp)
{
    ch->nluns = spp->luns_per_ch;
    ch->lun = g_malloc0(sizeof(struct nand_lun) * ch->nluns);
    for (int i = 0; i < ch->nluns; i++) {
        ssd_init_nand_lun(&ch->lun[i], spp);
    }
    ch->next_ch_avail_time = 0;
    ch->busy = 0;
}
