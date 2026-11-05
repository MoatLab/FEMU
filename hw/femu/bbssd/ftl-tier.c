/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * bbssd pSLC tier: a pool of lines that the FTL programs one bit per NAND
 * unit, in front of the dense (MLC, TLC or QLC) lines. Host writes go to
 * the pool first. A fold moves the valid pages of the oldest full pool line
 * to the dense frontier and erases the pool line.
 *
 * Off by default: ssd->tier is NULL and every hook in the FTL returns at
 * once. The static lines leave the dense free list at start and never enter
 * the full list or the victim queue:
 *
 *   free --host write--> open --last usable page--> closed (FIFO)
 *     ^                                                  |
 *     +-------- fold: read, program dense, erase --------+
 *
 * A dynamic pool also borrows free dense lines while the dense lines keep
 * room for every valid page. A borrowed line goes back to the dense free
 * list after its fold:
 *
 *   dense free --borrow--> open --> closed (FIFO) --fold--> dense free
 *
 * A fold charges each move as a pSLC read, then a dense program that starts
 * when the read data is ready. The erase of the pool line waits for the last
 * program. Folds charge their time with or without enable_gc_delay.
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "ftl.h"
#include "ftl-internal.h"
#include "ftl-tier-math.h"

/* the largest pSLC operation time realize accepts: 10 s */
#define FTL_TIER_MAX_NS     10000000000ULL

static int ftl_tier_density(int cell_type)
{
    switch (cell_type) {
    case MLC:
        return 2;
    case TLC:
        return 3;
    case QLC:
        return 4;
    default:
        return 0;
    }
}

static bool ftl_tier_static(const BbCtrlParams *p)
{
    return p->tier_mode && !strcmp(p->tier_mode, "static");
}

static bool ftl_tier_dynamic(const BbCtrlParams *p)
{
    return p->tier_mode && !strcmp(p->tier_mode, "dynamic");
}

static bool ftl_tier_on(const BbCtrlParams *p)
{
    return ftl_tier_static(p) || ftl_tier_dynamic(p);
}

static bool ftl_tier_through(const BbCtrlParams *p)
{
    return p->tier_full_policy && !strcmp(p->tier_full_policy, "through");
}

/* usable pages of one pSLC line of the geometry of @n; 0 without a tier */
static uint64_t bb_tier_line_pgs(FemuCtrl *n)
{
    const BbCtrlParams *p = &n->bb_params;
    uint64_t dies = (uint64_t)p->nchs * p->luns_per_ch * p->pls_per_lun;

    return dies * tier_blk_pgs(p->pgs_per_blk,
                               ftl_tier_density(n->nand_cell_type));
}

/**
 * bb_tier_pool_lines - lines the static pSLC pool takes
 * @n: the controller
 *
 * Enough lines to hold tier_static_mb of host data at the usable pSLC size
 * of a line. They hold no dense data, so the capacity check counts them as
 * a reserve. Borrowed lines are not in this count. Returns 0 with the tier
 * off.
 */
uint64_t bb_tier_pool_lines(FemuCtrl *n)
{
    const BbCtrlParams *p = &n->bb_params;

    if (!ftl_tier_on(p)) {
        return 0;
    }
    return tier_pool_lines(p->tier_static_mb,
                           (uint64_t)p->secs_per_pg * p->secsz,
                           bb_tier_line_pgs(n));
}

/*
 * The settings the tier does not cover yet. Each one has its own write
 * path, allocator or line walk that does not know the pool lines.
 */
static const char *bb_tier_refused(FemuCtrl *n)
{
    const BbCtrlParams *p = &n->bb_params;
    const char *map = p->mapping_scheme;

    if (!BBSSD(n)) {
        return "a mode other than bbssd";
    }
    if (n->subsys && n->subsys->params.fdp.enabled) {
        return "FDP";
    }
    if (n->num_namespaces > 1 || n->namespace_modes) {
        return "more than one namespace";
    }
    if (nvme_ns_shared(n) || n->ns_mgmt) {
        return "namespace management or shared namespaces";
    }
    if (n->cxl_dev) {
        return "cxl_ssd";
    }
    if (map && *map && strcmp(map, "page")) {
        return "a mapping other than page";
    }
    if (n->power_loss) {
        return "power_loss";
    }
    if (p->buffer_size > 0) {
        return "buffer_size";
    }
    if (n->streams) {
        return "Streams";
    }
    if (p->hot_cold_sep) {
        return "hot_cold_sep";
    }
    if (p->gc_pace) {
        return "gc_pace";
    }
    if (p->gc_copyback) {
        return "gc_copyback";
    }
    if (n->blk_pe_limit) {
        return "blk_pe_limit";
    }
    if (p->wl_spread) {
        return "wl_spread";
    }
    if (p->read_reclaim_limit || p->retention_limit_sec) {
        return "read_reclaim_limit or retention_limit_sec";
    }
    if (p->pd_edge_wls || p->pd_edge_tiers || p->pd_open_tiers ||
        p->pd_open_age || p->pd_open_read_limit || p->pd_open_close_sec) {
        return "the pd_* properties";
    }
    if (p->mp_program) {
        return "mp_program";
    }
    if (p->onfi_cache_read) {
        return "onfi_cache_read";
    }
    /* a suspended program ends later than the fold fence holds */
    if (p->pe_suspend) {
        return "pe_suspend";
    }
    /* the ECC wear tiers count a pSLC erase as a dense one */
    if (p->ecc_step_ns) {
        return "ecc_step_ns";
    }
    return NULL;
}

/**
 * bb_tier_check_props - refuse a tier configuration that cannot work
 * @n: the controller
 * @errp: set with the reason on failure
 *
 * Runs at realize. With tier_mode off it only warns about tier knobs that
 * have no effect, and checks none of their values. Returns false with
 * @errp set to refuse the device.
 */
bool bb_tier_check_props(FemuCtrl *n, Error **errp)
{
    const BbCtrlParams *p = &n->bb_params;
    const char *mode = p->tier_mode;
    const char *pol = p->tier_full_policy;
    const char *why;
    int density;

    if (mode && *mode && strcmp(mode, "off") && strcmp(mode, "static") &&
        strcmp(mode, "dynamic")) {
        error_setg(errp, "femu: tier_mode must be off, static or dynamic, "
                   "got %s", mode);
        return false;
    }
    if (!ftl_tier_on(p)) {
        if (p->tier_static_mb || (pol && *pol) || p->tier_pslc_pe_cycles ||
            p->tier_pslc_read_ns != FTL_TIER_READ_NS ||
            p->tier_pslc_prog_ns != FTL_TIER_PROG_NS ||
            p->tier_pslc_erase_ns != FTL_TIER_ERASE_NS ||
            p->tier_max_mb || p->tier_shrink_pct != FTL_TIER_SHRINK_PCT) {
            warn_report("femu: the tier_* properties have no effect unless "
                        "tier_mode is static or dynamic");
        }
        return true;
    }
    if (!ftl_tier_dynamic(p) &&
        (p->tier_max_mb || p->tier_shrink_pct != FTL_TIER_SHRINK_PCT)) {
        warn_report("femu: tier_max_mb and tier_shrink_pct have no effect "
                    "unless tier_mode=dynamic");
    }
    if (ftl_tier_dynamic(p) && p->tier_shrink_pct > 99) {
        error_setg(errp, "femu: tier_shrink_pct must be 0 to 99, got %u",
                   p->tier_shrink_pct);
        return false;
    }
    if (pol && *pol && strcmp(pol, "direct") && strcmp(pol, "through")) {
        error_setg(errp, "femu: tier_full_policy must be direct or through, "
                   "got %s", pol);
        return false;
    }
    if (p->tier_pslc_read_ns > FTL_TIER_MAX_NS ||
        p->tier_pslc_prog_ns > FTL_TIER_MAX_NS ||
        p->tier_pslc_erase_ns > FTL_TIER_MAX_NS) {
        error_setg(errp, "femu: tier_pslc_read_ns, tier_pslc_prog_ns and "
                   "tier_pslc_erase_ns must be at most %llu ns",
                   FTL_TIER_MAX_NS);
        return false;
    }

    why = bb_tier_refused(n);
    if (why) {
        error_setg(errp, "femu: tier_mode=%s is not supported with %s",
                   mode, why);
        return false;
    }
    density = ftl_tier_density(n->nand_cell_type);
    if (!density) {
        error_setg(errp, "femu: tier_mode=%s needs nand_cell_type 2 "
                   "(MLC), 3 (TLC) or 4 (QLC): the pool programs dense "
                   "blocks one bit per NAND unit", mode);
        return false;
    }
    if (!p->tier_static_mb && (ftl_tier_static(p) || ftl_tier_through(p))) {
        error_setg(errp, "femu: tier_mode=%s needs tier_static_mb above "
                   "0%s", mode, ftl_tier_through(p) ? ": tier_full_policy="
                   "through writes every host page through the pool" : "");
        return false;
    }
    if (!tier_blk_pgs(p->pgs_per_blk, density)) {
        error_setg(errp, "femu: tier_mode=%s needs pgs_per_blk of at "
                   "least %d at nand_cell_type %u", mode, density,
                   n->nand_cell_type);
        return false;
    }
    if (ftl_tier_dynamic(p) && p->tier_max_mb &&
        !tier_cap_lines(p->tier_max_mb, (uint64_t)p->secs_per_pg * p->secsz,
                        bb_tier_line_pgs(n))) {
        error_setg(errp, "femu: tier_max_mb=%u holds no whole pSLC line of "
                   "%" PRIu64 " KiB", p->tier_max_mb,
                   bb_tier_line_pgs(n) * p->secs_per_pg * p->secsz >> 10);
        return false;
    }
    return true;
}

/**
 * ftl_tier_init - build the tier state of @ssd
 * @ssd: the FTL, with its geometry and wear rating set
 * @n: the controller
 *
 * Leaves ssd->tier NULL unless tier_mode is static or dynamic, so every
 * hook stays inert.
 * Runs before the media layer, which takes the pSLC timing row from here.
 */
void ftl_tier_init(struct ssd *ssd, FemuCtrl *n)
{
    const BbCtrlParams *p = &n->bb_params;
    struct ssdparams *spp = &ssd->sp;
    struct ftl_tier *t;
    int density;

    ssd->tier = NULL;
    if (!ftl_tier_on(p) || !ssd->ns || !NS_BBSSD(ssd->ns)) {
        return;
    }
    density = ftl_tier_density(n->nand_cell_type);
    if (!density) {
        return;
    }

    t = g_new0(struct ftl_tier, 1);
    t->mode = ftl_tier_dynamic(p) ? FTL_TIER_DYNAMIC : FTL_TIER_STATIC;
    t->policy = ftl_tier_through(p) ? FTL_TIER_THROUGH : FTL_TIER_DIRECT;
    t->density = density;
    t->blk_pgs = tier_blk_pgs(spp->pgs_per_blk, density);
    t->line_pgs = t->blk_pgs * spp->blks_per_line;
    t->nlines = (int)bb_tier_pool_lines(n);
    t->state = g_new0(uint8_t, spp->tt_lines);
    t->ready = g_new0(uint64_t, spp->tt_lines);
    t->dyn = g_new0(uint8_t, spp->tt_lines);
    /* a cap holds whole lines; with none, every line is the bound */
    t->dyn_max = p->tier_max_mb ?
                 tier_cap_lines(p->tier_max_mb,
                                (uint64_t)p->secs_per_pg * p->secsz,
                                t->line_pgs) : (uint64_t)spp->tt_lines;
    t->shrink_pct = p->tier_shrink_pct;
    t->user_pgs = DIV_ROUND_UP(ssd->ns->size,
                               (uint64_t)p->secs_per_pg * p->secsz);
    QTAILQ_INIT(&t->free_lines);
    QTAILQ_INIT(&t->closed);
    t->read_ns = p->tier_pslc_read_ns;
    t->prog_ns = p->tier_pslc_prog_ns;
    t->erase_ns = p->tier_pslc_erase_ns;
    t->slc_erases = g_new0(uint32_t, spp->tt_blks);
    t->dense_limit = ssd->rated_pe_cycles;
    t->slc_limit = tier_slc_limit(p->tier_pslc_pe_cycles,
                                  ssd->rated_pe_cycles);
    ssd->tier = t;
}

/**
 * ftl_tier_take_lines - move the pool lines out of the dense free list
 * @ssd: the FTL, right after ssd_init_lines()
 *
 * The pool takes the lines with the highest ids, so the dense frontier
 * still starts at line 0. Realize kept room for them.
 */
void ftl_tier_take_lines(struct ssd *ssd)
{
    struct ftl_tier *t = ssd->tier;
    struct line_mgmt *lm = &ssd->lm;

    for (int i = 0; i < t->nlines; i++) {
        struct line *line = QTAILQ_LAST(&lm->free_line_list);

        if (!line) {
            break;
        }
        QTAILQ_REMOVE(&lm->free_line_list, line, entry);
        lm->free_line_cnt--;
        t->state[line->id] = FTL_TIER_LINE_FREE;
        QTAILQ_INSERT_HEAD(&t->free_lines, line, entry);
        t->free_cnt++;
    }
}

void ftl_tier_free(struct ssd *ssd)
{
    struct ftl_tier *t = ssd->tier;

    if (!t) {
        return;
    }
    g_free(t->slc_erases);
    g_free(t->dyn);
    g_free(t->ready);
    g_free(t->state);
    g_free(t);
    ssd->tier = NULL;
}

/*
 * pSLC operations use the SLC row of the media table. A device with the
 * tier is MLC, TLC or QLC, so the row is free, and the built-in SLC times
 * of nand_cell_type=1 do not change.
 */
void ftl_tier_media_cfg(struct ssd *ssd, NandMediaConfig *cfg)
{
    struct ftl_tier *t = ssd->tier;

    cfg->timing.rd_table_ns[SLC][SLC_PAGE] = (int64_t)t->read_ns;
    cfg->timing.wr_table_ns[SLC][SLC_PAGE] = (int64_t)t->prog_ns;
    cfg->timing.er_table_ns[SLC] = (int64_t)t->erase_ns;
}

/* a page of a pool line takes pSLC timing: one page per word line */
void ftl_tier_decode(struct ssd *ssd, struct ppa *ppa, NandLoc *loc)
{
    if (ssd->tier->state[get_line(ssd, ppa)->id] != FTL_TIER_LINE_DENSE) {
        loc->flash_type = SLC;
        loc->page_type = SLC_PAGE;
    }
}

/*
 * A page of a pool line became invalid. Only the counts change: the line
 * stays where the tier keeps it. Returns false for a dense line, after the
 * dense count drops.
 */
bool ftl_tier_invalidate(struct ssd *ssd, struct line *line)
{
    struct ftl_tier *t = ssd->tier;

    if (t->state[line->id] == FTL_TIER_LINE_DENSE) {
        t->dense_valid--;
        return false;
    }
    line->ipc++;
    line->vpc--;
    t->valid--;
    return true;
}

/* a page of a dense line became valid */
void ftl_tier_validate(struct ssd *ssd, struct line *line)
{
    if (ssd->tier->state[line->id] == FTL_TIER_LINE_DENSE) {
        ssd->tier->dense_valid++;
    }
}

/* valid host pages, in dense and pool lines */
static uint64_t ftl_tier_live(struct ftl_tier *t)
{
    return t->dense_valid + t->valid;
}

/*
 * The dense pages that may hold host data while the pool has @k borrowed
 * lines: the dense lines less the static pool, the reserves, the forced
 * collection threshold and the dense frontier.
 */
static uint64_t ftl_tier_cap(struct ssd *ssd, int k)
{
    struct line_mgmt *lm = &ssd->lm;
    int64_t dense = (int64_t)lm->tt_lines - ssd->tier->nlines - k -
                    ssd->spare_lines - ssd->eol_reserve_lines -
                    lm->retired_line_cnt - ssd->sp.gc_thres_lines_high - 1;

    return dense > 0 ? (uint64_t)dense * ssd->sp.pgs_per_line : 0;
}

/* the borrowed lines the fill allows now; 0 for a static pool */
static uint64_t ftl_tier_allowed(struct ssd *ssd)
{
    struct ftl_tier *t = ssd->tier;

    if (t->mode != FTL_TIER_DYNAMIC) {
        return 0;
    }
    return tier_allowed(t->dyn_max, ftl_tier_live(t), t->user_pgs,
                        t->shrink_pct);
}

/*
 * Whether the pool may borrow one more free dense line. The fill must allow
 * it, the dense lines must still hold every valid page with a full pool
 * line more, and the dense side must stay above forced collection.
 */
static bool ftl_tier_may_borrow(struct ssd *ssd)
{
    struct ftl_tier *t = ssd->tier;

    return t->mode == FTL_TIER_DYNAMIC &&
           (uint64_t)t->dyn_cnt + 1 <= ftl_tier_allowed(ssd) &&
           ftl_tier_live(t) + t->line_pgs <= ftl_tier_cap(ssd, t->dyn_cnt + 1) &&
           ssd->lm.free_line_cnt - 1 > ssd->sp.gc_thres_lines_high;
}

/* open @line as the pSLC frontier */
static void ftl_tier_open(struct ssd *ssd, struct line *line)
{
    ssd->tier->state[line->id] = FTL_TIER_LINE_OPEN;
    ssd_wp_reset(&ssd->tier->wp, line);
}

/* take the oldest free dense line into the pool, if the rule allows it */
static bool ftl_tier_borrow(struct ssd *ssd)
{
    struct ftl_tier *t = ssd->tier;
    struct line *line;

    if (!ftl_tier_may_borrow(ssd)) {
        return false;
    }
    line = get_next_free_line(ssd);
    if (!line) {
        return false;
    }
    t->dyn[line->id] = 1;
    t->dyn_cnt++;
    ftl_tier_open(ssd, line);
    return true;
}

/*
 * The frontier holds a line with a free page. It takes the oldest free
 * static line once its erase ended, then a borrowed line. A static line
 * whose erase ends after @now is taken only with @wait, which then gets
 * the end of the erase.
 */
static bool ftl_tier_frontier(struct ssd *ssd, uint64_t now, uint64_t *wait)
{
    struct ftl_tier *t = ssd->tier;
    struct line *line;

    if (t->wp.curline) {
        return true;
    }
    line = QTAILQ_FIRST(&t->free_lines);
    if (line && t->ready[line->id] <= now) {
        goto take;
    }
    if (ftl_tier_borrow(ssd)) {
        return true;
    }
    if (!line || !wait) {
        return false;
    }
    *wait = t->ready[line->id];
take:
    QTAILQ_REMOVE(&t->free_lines, line, entry);
    t->free_cnt--;
    ftl_tier_open(ssd, line);
    return true;
}

static void ftl_tier_mark_valid(struct ssd *ssd, struct ppa *ppa, void *dest)
{
    (void)dest;
    mark_page_valid(ssd, ppa);
}

static const struct ssd_gc_move_ops ftl_tier_move_ops = {
    .mark_valid   = ftl_tier_mark_valid,
    .mark_invalid = mark_page_invalid,
};

/*
 * Move one valid pool page @src to the dense frontier. The read starts at
 * @now, and the program starts when the read data is ready. *@fence becomes
 * the end of the latest program. The destination is secured before the
 * mapping changes. Returns false, with the page not moved, when the dense
 * lines have no page.
 */
static bool ftl_tier_fold_page(struct ssd *ssd, struct ppa *src, uint64_t now,
                               uint64_t *fence)
{
    struct ftl_tier *t = ssd->tier;
    uint64_t lpn = get_rmap_ent(ssd, src);
    struct nand_cmd rd = { .type = GC_IO, .cmd = NAND_READ, .stime = now };
    struct nand_cmd wr = { .type = GC_IO, .cmd = NAND_WRITE };
    struct nand_lun *lun;
    struct ppa map;
    struct ppa dst;
    uint64_t ready;
    uint64_t lat;

    /* a valid page that no mapping names holds nothing: drop it */
    map.ppa = UNMAPPED_PPA;
    if (lpn != INVALID_LPN && !rmap_is_tp(lpn) && valid_lpn(ssd, lpn)) {
        map = get_maptbl_ent(ssd, lpn);
    }
    if (map.ppa != src->ppa) {
        mark_page_invalid(ssd, src);
        set_rmap_ent(ssd, INVALID_LPN, src);
        t->fold_stale++;
        return true;
    }

    /* make room as a host write does, then take the dense page */
    while (should_gc_high(ssd)) {
        if (do_gc(ssd, true) == -1) {
            break;
        }
    }
    if (ssd_out_of_lines(ssd)) {
        return false;
    }
    dst = get_new_page(ssd);
    if (!mapped_ppa(&dst)) {
        return false;
    }

    /* each end counts from the start the command got */
    lat = ssd_advance_status(ssd, src, &rd);
    ready = rd.stime + lat;
    wr.stime = ready;
    lat = ssd_advance_status(ssd, &dst, &wr);
    *fence = MAX(*fence, wr.stime + lat);

    ssd_gc_move_page(ssd, lpn, src, &dst, &ftl_tier_move_ops, NULL);
    ssd_advance_write_pointer(ssd);
    lun = get_lun(ssd, &dst);
    lun->gc_endtime = lun->next_lun_avail_time;
    t->fold_pages++;
    return true;
}

/* index of block @blk of plane @pl of LUN @lun of channel @ch */
static size_t ftl_tier_blk_index(struct ssdparams *spp, int ch, int lun,
                                 int pl, int blk)
{
    return (((size_t)ch * spp->luns_per_ch + lun) * spp->pls_per_lun + pl) *
           spp->blks_per_pl + blk;
}

/*
 * x-tier-fold-stop: qtest stops a fold after @moved pages, once, as if the
 * dense lines had no page left. Rules A and B keep a workload from that,
 * so only this reaches the retry of a stopped fold.
 */
static bool ftl_tier_test_stop(struct ssd *ssd, uint32_t moved)
{
    uint32_t *stop = ssd->n ? &ssd->n->test_tier_fold_stop : NULL;

    if (!stop || !qatomic_read(stop) || qatomic_read(stop) != moved) {
        return false;
    }
    qatomic_set(stop, 0);
    return true;
}

/* the oldest closed borrowed line, or NULL */
static struct line *ftl_tier_oldest_dyn(struct ssd *ssd)
{
    struct ftl_tier *t = ssd->tier;
    struct line *line;

    QTAILQ_FOREACH(line, &t->closed, entry) {
        if (t->dyn[line->id]) {
            return line;
        }
    }
    return NULL;
}

/*
 * Fold the closed pool line @victim, starting at @now: move its valid
 * pages, then erase its blocks once the last program ends. A fold that
 * stopped early takes its line again, whatever @victim is. Returns when
 * the erase ends, or 0 when the line could not be emptied. A line that is
 * not empty stays closed, with the pages moved so far and the end of their
 * latest program kept for the retry. A static line goes back to the tier
 * free list; a borrowed line goes back to the dense free list.
 */
static uint64_t ftl_tier_fold(struct ssd *ssd, struct line *victim,
                              uint64_t now)
{
    struct ftl_tier *t = ssd->tier;
    struct ssdparams *spp = &ssd->sp;
    uint64_t first = UINT64_MAX;
    uint64_t fence;
    uint64_t start;
    uint64_t done;
    struct ppa ppa = { .ppa = 0 };
    uint32_t moved = 0;

    if (t->fold_line) {
        victim = t->fold_line;
    }
    if (!victim) {
        return 0;
    }
    t->fold_line = victim;
    if (!t->fold_start) {
        t->fold_start = now;
    }
    fence = MAX(t->fold_fence, now);
    ppa.g.blk = victim->id;
    for (int ch = 0; ch < spp->nchs; ch++) {
        ppa.g.ch = ch;
        for (int lun = 0; lun < spp->luns_per_ch; lun++) {
            ppa.g.lun = lun;
            for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                ppa.g.pl = pl;
                for (int pg = 0; pg < t->blk_pgs && victim->vpc; pg++) {
                    ppa.g.pg = pg;
                    if (get_pg(ssd, &ppa)->status != PG_VALID) {
                        continue;
                    }
                    if (ftl_tier_test_stop(ssd, moved) ||
                        !ftl_tier_fold_page(ssd, &ppa, now, &fence)) {
                        t->fold_fence = fence;
                        return 0;
                    }
                    moved++;
                }
            }
        }
    }
    if (victim->vpc) {
        ftl_err("pSLC line %d counts %d valid pages it does not hold\n",
                victim->id, victim->vpc);
        t->fold_fence = fence;
        return 0;
    }

    /*
     * The line is still closed, so the erase takes pSLC timing. It starts
     * after the latest program, so each moved page is durable first.
     */
    start = fence;
    done = fence;
    for (int ch = 0; ch < spp->nchs; ch++) {
        for (int lun = 0; lun < spp->luns_per_ch; lun++) {
            uint64_t lat = ssd_erase_lun_block(ssd, ch, lun, victim->id, true,
                                               start);

            done = MAX(done, start + lat);
            first = MIN(first, start + lat - MIN(lat, t->erase_ns));
            for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                uint32_t *cnt = &t->slc_erases[ftl_tier_blk_index(spp, ch, lun,
                                                                  pl,
                                                                  victim->id)];

                /* saturate, as mark_block_free() does with erase_cnt */
                if (*cnt < UINT32_MAX) {
                    (*cnt)++;
                }
                t->slc_erase_total++;
            }
        }
    }

    QTAILQ_REMOVE(&t->closed, victim, entry);
    t->closed_cnt--;
    victim->ipc = 0;
    victim->vpc = 0;
    victim->close_time = 0;
    victim->open_time = 0;
    victim->stream_tag = 0;
    victim->kind = LINE_DATA;
    if (t->dyn[victim->id]) {
        struct ppa lp = { .ppa = 0 };

        /* the erase advanced each LUN, so a dense program waits for it */
        t->dyn[victim->id] = 0;
        t->dyn_cnt--;
        t->state[victim->id] = FTL_TIER_LINE_DENSE;
        lp.g.blk = victim->id;
        mark_line_free(ssd, &lp);
    } else {
        t->state[victim->id] = FTL_TIER_LINE_FREE;
        t->ready[victim->id] = done;
        QTAILQ_INSERT_TAIL(&t->free_lines, victim, entry);
        t->free_cnt++;
    }
    t->fold_line = NULL;
    t->folds++;
    t->last_fold_ns = done - t->fold_start;
    t->last_fold_prog_ns = fence - t->fold_start;
    t->last_fold_erase_ns = first - t->fold_start;
    t->fold_start = 0;
    t->fold_fence = 0;
    return done;
}

/*
 * A dynamic pool must leave the dense lines room for every valid page
 * after each host page. Rule B keeps this true before each page, so a
 * break seen here stays counted in cap_fail even when a later fold heals
 * it. Runs before each host page and after each request.
 */
static void ftl_tier_check_cap(struct ssd *ssd)
{
    struct ftl_tier *t = ssd->tier;

    if (t->mode == FTL_TIER_DYNAMIC &&
        ftl_tier_live(t) > ftl_tier_cap(ssd, t->dyn_cnt)) {
        t->cap_fail++;
    }
}

/**
 * ftl_tier_host_page - place a host page in the pool
 * @ssd: the FTL
 * @ppa: set to the pool page on success
 * @stime: the program start; moved past a fold the page waits for
 * @base: the request start, set to now when it was 0 and a fold ran
 *
 * Takes a pool page when an erased one is free. tier_full_policy=direct
 * sends the page dense while the free lines still erase. tier_full_policy=
 * through waits for that erase, or folds the oldest pool line first and
 * waits for its erase. Returns false when the page goes to the dense
 * frontier, which the caller has secured unless a through fold took it.
 */
bool ftl_tier_host_page(struct ssd *ssd, struct ppa *ppa, uint64_t *stime,
                        uint64_t *base)
{
    struct ftl_tier *t = ssd->tier;
    struct write_pointer *wp = &t->wp;
    bool through = t->policy == FTL_TIER_THROUGH;
    uint64_t now = *stime ? *stime : ssd_now(ssd);
    uint64_t wait = 0;

    ftl_tier_check_cap(ssd);
    /*
     * Rule B: the page may add a valid page. While the dense lines could
     * not hold every valid page then, give borrowed lines back first. A
     * fold that ends a stopped static fold frees no dense room, so check
     * again after each one.
     */
    while (t->dyn_cnt &&
           ftl_tier_live(t) + 1 > ftl_tier_cap(ssd, t->dyn_cnt)) {
        struct line *dyn = ftl_tier_oldest_dyn(ssd);
        int before = t->dyn_cnt;

        if (!dyn || !ftl_tier_fold(ssd, dyn, now)) {
            t->cap_fail++;
            break;
        }
        t->rule_b_folds += t->dyn_cnt < before;
    }
    /*
     * With through, fold until a pool line is free. A folded borrowed line
     * goes back to the dense lines and frees no pool line, so one fold may
     * not be enough. The static floor makes this end.
     */
    if (!ftl_tier_frontier(ssd, now, through ? &wait : NULL) && through) {
        for (int tries = t->closed_cnt; tries > 0 && t->closed_cnt; tries--) {
            if (!ftl_tier_fold(ssd, QTAILQ_FIRST(&t->closed), now) ||
                ftl_tier_frontier(ssd, now, &wait)) {
                break;
            }
        }
    }
    if (!wp->curline) {
        t->host_dense++;
        return false;
    }
    if (wait > now) {
        if (!*base) {
            *base = now;
        }
        *stime = wait;
    }
    ppa->ppa = 0;
    ppa->g.ch = wp->ch;
    ppa->g.lun = wp->lun;
    ppa->g.pl = wp->pl;
    ppa->g.pg = wp->pg;
    ppa->g.blk = wp->blk;
    t->host_pslc++;
    return true;
}

/*
 * The page ftl_tier_host_page() gave is programmed and valid: step the
 * frontier, and close a full line into the FIFO. The next write takes a
 * new line.
 */
void ftl_tier_advance(struct ssd *ssd)
{
    struct ftl_tier *t = ssd->tier;
    struct line *line = t->wp.curline;

    t->valid++;
    if (!ssd_wp_step_lim(&ssd->sp, &t->wp, t->blk_pgs)) {
        return;
    }
    line->close_time = ssd_now(ssd);
    t->state[line->id] = FTL_TIER_LINE_CLOSED;
    QTAILQ_INSERT_TAIL(&t->closed, line, entry);
    t->closed_cnt++;
    t->wp.curline = NULL;
}

/*
 * A through fold took the last dense page and left no pool page: the host
 * page keeps its old mapping. Realize sizes the dense lines so that this
 * does not happen, so x-tier-check counts it as a broken rule.
 */
void ftl_tier_place_failed(struct ssd *ssd)
{
    if (!ssd->tier->place_fail++) {
        ftl_err("pSLC tier: no pool page and no dense page for a host page\n");
    }
}

/*
 * After each request. Rule C: a dynamic pool that holds more closed
 * borrowed lines than the fill allows gives the oldest ones back until it
 * does not. Otherwise, with
 * tier_full_policy=direct, fold one line when the pool has no free line
 * left and may borrow none, so later host writes find the pool again. A
 * free line whose erase has not ended yet counts as free. The through
 * policy folds in the write that needs the room.
 */
void ftl_tier_tick(struct ssd *ssd)
{
    struct ftl_tier *t = ssd->tier;
    uint64_t now = ssd_now(ssd);
    bool shrunk = false;

    ftl_tier_check_cap(ssd);
    /* the open borrowed line cannot fold yet, so it does not count */
    while (t->dyn_cnt) {
        int open = t->wp.curline && t->dyn[t->wp.curline->id];
        struct line *dyn;

        if ((uint64_t)(t->dyn_cnt - open) <= ftl_tier_allowed(ssd)) {
            break;
        }
        dyn = ftl_tier_oldest_dyn(ssd);
        if (!dyn || !ftl_tier_fold(ssd, dyn, now)) {
            break;
        }
        t->rule_c_folds++;
        shrunk = true;
    }
    if (shrunk) {
        return;
    }
    if (t->policy != FTL_TIER_DIRECT || t->wp.curline || t->free_cnt ||
        !t->closed_cnt || ftl_tier_may_borrow(ssd)) {
        return;
    }
    ftl_tier_fold(ssd, QTAILQ_FIRST(&t->closed), now);
}

/* add 1 to the count of @line in @seen, and 1 to *@bad if it is not @want */
static void ftl_tier_see(struct ssd *ssd, uint8_t *seen, struct line *line,
                         int want, uint64_t *bad)
{
    seen[line->id]++;
    *bad += ssd->tier->state[line->id] != want;
}

/* tier rules about where a line is; each broken one adds 1 */
static uint64_t ftl_tier_check_queues(struct ssd *ssd)
{
    struct ftl_tier *t = ssd->tier;
    struct line_mgmt *lm = &ssd->lm;
    pqueue_t *pq = lm->victim_line_pq;
    g_autofree uint8_t *seen = g_new0(uint8_t, lm->tt_lines);
    struct line *line;
    uint64_t bad = 0;
    int nfree = 0;
    int nclosed = 0;
    int npool = 0;
    int nfree_dense = 0;
    int nfull_dense = 0;
    struct write_pointer *wps[] = {
        &ssd->wp, &ssd->stream_gc_wp, &ssd->log_wp, &ssd->hot_wp, &ssd->tp_wp,
    };

    QTAILQ_FOREACH(line, &t->free_lines, entry) {
        ftl_tier_see(ssd, seen, line, FTL_TIER_LINE_FREE, &bad);
        /* a borrowed line goes back to the dense free list, not here */
        bad += t->dyn[line->id];
        nfree++;
    }
    QTAILQ_FOREACH(line, &t->closed, entry) {
        ftl_tier_see(ssd, seen, line, FTL_TIER_LINE_CLOSED, &bad);
        nclosed++;
    }
    if (t->wp.curline) {
        ftl_tier_see(ssd, seen, t->wp.curline, FTL_TIER_LINE_OPEN, &bad);
    }
    bad += nfree != t->free_cnt;
    bad += nclosed != t->closed_cnt;

    /* a pool line in a dense list or on a dense frontier */
    QTAILQ_FOREACH(line, &lm->free_line_list, entry) {
        ftl_tier_see(ssd, seen, line, FTL_TIER_LINE_DENSE, &bad);
        nfree_dense++;
    }
    QTAILQ_FOREACH(line, &lm->full_line_list, entry) {
        ftl_tier_see(ssd, seen, line, FTL_TIER_LINE_DENSE, &bad);
        nfull_dense++;
    }
    /* a borrow or a return that missed a dense count */
    bad += nfree_dense != lm->free_line_cnt;
    bad += nfull_dense != lm->full_line_cnt;
    for (size_t i = 1; i < pq->size; i++) {
        ftl_tier_see(ssd, seen, pq->d[i], FTL_TIER_LINE_DENSE, &bad);
    }
    for (size_t i = 0; i < ARRAY_SIZE(wps); i++) {
        if (wps[i]->curline) {
            ftl_tier_see(ssd, seen, wps[i]->curline, FTL_TIER_LINE_DENSE,
                         &bad);
        }
    }

    /*
     * Every line has exactly one owner: a tier place, or a dense list, the
     * victim queue or a dense frontier. A line with none was lost.
     */
    for (int i = 0; i < lm->tt_lines; i++) {
        bad += seen[i] != 1;
        if (t->state[i] != FTL_TIER_LINE_DENSE) {
            npool++;
            bad += lm->lines[i].pos != 0;
        }
    }
    bad += npool != t->nlines + t->dyn_cnt;
    return bad;
}

/*
 * Rules of the borrowed lines: each mark is on a pool line, the marks add
 * up to dyn_cnt, and a static pool borrows none. Returns the broken ones.
 */
static uint64_t ftl_tier_check_dyn(struct ssd *ssd)
{
    struct ftl_tier *t = ssd->tier;
    uint64_t bad = 0;
    int marks = 0;

    for (int i = 0; i < ssd->lm.tt_lines; i++) {
        marks += t->dyn[i];
        bad += t->dyn[i] && t->state[i] == FTL_TIER_LINE_DENSE;
    }
    bad += marks != t->dyn_cnt;
    bad += t->mode != FTL_TIER_DYNAMIC && t->dyn_cnt;
    return bad;
}

/*
 * The broken rules of the live count: the dense valid count against the
 * pages of the dense lines, and the live count against the mapping table.
 */
static uint64_t ftl_tier_check_live(struct ssd *ssd)
{
    struct ftl_tier *t = ssd->tier;
    uint64_t dense = 0;
    uint64_t mapped = 0;

    for (int i = 0; i < ssd->lm.tt_lines; i++) {
        if (t->state[i] == FTL_TIER_LINE_DENSE) {
            dense += ssd->lm.lines[i].vpc;
        }
    }
    for (uint64_t lpn = 0; lpn < (uint64_t)ssd->sp.tt_pgs; lpn++) {
        mapped += mapped_ppa(&ssd->maptbl[lpn]);
    }
    return (dense != t->dense_valid) + (mapped != ftl_tier_live(t));
}

/*
 * Page rules of the pool lines: *@range counts programmed pages past the
 * usable ones, *@count counts lines whose counts disagree with their pages,
 * and *@map counts valid pages whose mapping is not that page.
 */
static void ftl_tier_check_pages(struct ssd *ssd, uint64_t *range,
                                 uint64_t *count, uint64_t *map)
{
    struct ftl_tier *t = ssd->tier;
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;
    uint64_t valid = 0;
    struct ppa ppa = { .ppa = 0 };

    *range = *count = *map = 0;
    for (int id = 0; id < lm->tt_lines; id++) {
        struct line *line = &lm->lines[id];
        int lvpc = 0;
        int lipc = 0;

        if (t->state[id] == FTL_TIER_LINE_DENSE) {
            continue;
        }
        ppa.g.blk = id;
        for (int ch = 0; ch < spp->nchs; ch++) {
            ppa.g.ch = ch;
            for (int lun = 0; lun < spp->luns_per_ch; lun++) {
                ppa.g.lun = lun;
                for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                    struct nand_block *blk;
                    int bvpc = 0;
                    int bipc = 0;

                    ppa.g.pl = pl;
                    blk = get_blk(ssd, &ppa);
                    for (int pg = 0; pg < spp->pgs_per_blk; pg++) {
                        int st;

                        ppa.g.pg = pg;
                        st = get_pg(ssd, &ppa)->status;
                        if (pg >= t->blk_pgs) {
                            *range += st != PG_FREE;
                            continue;
                        }
                        if (st == PG_VALID) {
                            uint64_t lpn = get_rmap_ent(ssd, &ppa);

                            bvpc++;
                            *map += !valid_lpn(ssd, lpn) ||
                                    get_maptbl_ent(ssd, lpn).ppa != ppa.ppa;
                        } else if (st == PG_INVALID) {
                            bipc++;
                        }
                    }
                    *count += blk->vpc != bvpc || blk->ipc != bipc;
                    lvpc += bvpc;
                    lipc += bipc;
                }
            }
        }
        *count += line->vpc != lvpc || line->ipc != lipc;
        valid += lvpc;
    }
    *count += valid != t->valid;
}

/* the largest wear of a block, in millionths of its life */
static uint64_t ftl_tier_damage_max(struct ssd *ssd)
{
    struct ftl_tier *t = ssd->tier;
    struct ssdparams *spp = &ssd->sp;
    uint64_t most = 0;

    for (int ch = 0; ch < spp->nchs; ch++) {
        for (int lun = 0; lun < spp->luns_per_ch; lun++) {
            for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                struct nand_plane *plane = &ssd->ch[ch].lun[lun].pl[pl];

                for (int b = 0; b < spp->blks_per_pl; b++) {
                    uint32_t slc = t->slc_erases[ftl_tier_blk_index(spp, ch,
                                                                    lun, pl,
                                                                    b)];
                    uint32_t all = plane->blk[b].erase_cnt;
                    uint64_t d = tier_damage_ppm(all - MIN(slc, all),
                                                 t->dense_limit, slc,
                                                 t->slc_limit);

                    most = MAX(most, d);
                }
            }
        }
    }
    return most;
}

/*
 * The space rule: the dense lines left by the static pool and the borrowed
 * lines must hold every mapped page, a fold of every valid pool page
 * included, with the forced reserve and the dense frontier left over.
 * Realize checked this for the exported capacity of a static pool. The
 * mapping table is counted here, not the live count, so an error in that
 * count does not hide a break. Returns 1 when they cannot.
 */
static uint64_t ftl_tier_check_reserve(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t mapped = 0;

    for (uint64_t lpn = 0; lpn < (uint64_t)spp->tt_pgs; lpn++) {
        mapped += mapped_ppa(&ssd->maptbl[lpn]);
    }
    return mapped > ftl_tier_cap(ssd, ssd->tier->dyn_cnt);
}

/**
 * ssd_tier_report - the pSLC tier state of @ssd, for tests
 * @ssd: the FTL; the caller has paused the FTL thread
 *
 * Space-separated numbers: pool lines, usable pages per pool line, free,
 * closed and open pool lines, valid pool pages, host pages to the pool and
 * to dense, fold pages, folds, pSLC block erases; then the broken rules of
 * usable ranges, line places, counts, mappings and the dense reserve, all
 * 0 when the state is right; then host pages with no place, stale pages
 * folds dropped, the largest block wear in millionths, and three times of
 * the last fold in ns from its start: the end of its last erase, the end
 * of its latest program and the start of its first erase. Then the free
 * lines whose erase has not ended. Last, for a dynamic pool: borrowed
 * lines, the borrowed lines the fill allows, the broken rules of the dense
 * valid count and of the borrowed lines, host pages the dense room could
 * not hold, and the folds that rules B and C made. Returns NULL with the
 * tier off.
 */
char *ssd_tier_report(struct ssd *ssd)
{
    struct ftl_tier *t = ssd->tier;
    uint64_t now = ssd_now(ssd);
    struct line *line;
    uint64_t range;
    uint64_t count;
    uint64_t map;
    int busy = 0;

    if (!t) {
        return NULL;
    }
    QTAILQ_FOREACH(line, &t->free_lines, entry) {
        busy += t->ready[line->id] > now;
    }
    ftl_tier_check_pages(ssd, &range, &count, &map);
    return g_strdup_printf("%d %d %d %d %d %" PRIu64 " %" PRIu64 " %" PRIu64
                           " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
                           " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
                           " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
                           " %" PRIu64 " %" PRIu64 " %d %d %" PRIu64
                           " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
                           " %" PRIu64,
                           t->nlines, t->line_pgs, t->free_cnt, t->closed_cnt,
                           t->wp.curline != NULL, t->valid, t->host_pslc,
                           t->host_dense, t->fold_pages, t->folds,
                           t->slc_erase_total, range,
                           ftl_tier_check_queues(ssd), count, map,
                           ftl_tier_check_reserve(ssd), t->place_fail,
                           t->fold_stale, ftl_tier_damage_max(ssd),
                           t->last_fold_ns, t->last_fold_prog_ns,
                           t->last_fold_erase_ns, busy, t->dyn_cnt,
                           ftl_tier_allowed(ssd), ftl_tier_check_live(ssd),
                           ftl_tier_check_dyn(ssd), t->cap_fail,
                           t->rule_b_folds, t->rule_c_folds);
}
