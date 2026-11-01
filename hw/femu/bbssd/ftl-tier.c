/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * bbssd pSLC tier: a static pool of lines that the FTL programs one bit per
 * NAND unit, in front of the dense (MLC, TLC or QLC) lines. Host writes go
 * to the pool first. A fold moves the valid pages of the oldest full pool
 * line to the dense frontier and erases the pool line.
 *
 * Off by default: ssd->tier is NULL and every hook in the FTL returns at
 * once. The pool lines leave the dense free list at start and never enter
 * the full list or the victim queue:
 *
 *   free --host write--> open --last usable page--> closed (FIFO)
 *     ^                                                  |
 *     +-------- fold: read, program dense, erase --------+
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
 * a reserve. Returns 0 with the tier off.
 */
uint64_t bb_tier_pool_lines(FemuCtrl *n)
{
    const BbCtrlParams *p = &n->bb_params;

    if (!ftl_tier_static(p)) {
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

    if (mode && *mode && strcmp(mode, "off") && strcmp(mode, "static")) {
        error_setg(errp, "femu: tier_mode must be off or static, got %s",
                   mode);
        return false;
    }
    if (!ftl_tier_static(p)) {
        if (p->tier_static_mb || (pol && *pol) || p->tier_pslc_pe_cycles ||
            p->tier_pslc_read_ns != FTL_TIER_READ_NS ||
            p->tier_pslc_prog_ns != FTL_TIER_PROG_NS ||
            p->tier_pslc_erase_ns != FTL_TIER_ERASE_NS) {
            warn_report("femu: the tier_* properties have no effect unless "
                        "tier_mode=static");
        }
        return true;
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
        error_setg(errp, "femu: tier_mode=static is not supported with %s",
                   why);
        return false;
    }
    density = ftl_tier_density(n->nand_cell_type);
    if (!density) {
        error_setg(errp, "femu: tier_mode=static needs nand_cell_type 2 "
                   "(MLC), 3 (TLC) or 4 (QLC): the pool programs dense "
                   "blocks one bit per NAND unit");
        return false;
    }
    if (!p->tier_static_mb) {
        error_setg(errp, "femu: tier_mode=static needs tier_static_mb above "
                   "0%s", ftl_tier_through(p) ? ": tier_full_policy=through "
                   "writes every host page through the pool" : "");
        return false;
    }
    if (!tier_blk_pgs(p->pgs_per_blk, density)) {
        error_setg(errp, "femu: tier_mode=static needs pgs_per_blk of at "
                   "least %d at nand_cell_type %u", density,
                   n->nand_cell_type);
        return false;
    }
    return true;
}

/**
 * ftl_tier_init - build the tier state of @ssd
 * @ssd: the FTL, with its geometry and wear rating set
 * @n: the controller
 *
 * Leaves ssd->tier NULL unless tier_mode=static, so every hook stays inert.
 * Runs before the media layer, which takes the pSLC timing row from here.
 */
void ftl_tier_init(struct ssd *ssd, FemuCtrl *n)
{
    const BbCtrlParams *p = &n->bb_params;
    struct ssdparams *spp = &ssd->sp;
    struct ftl_tier *t;
    int density;

    ssd->tier = NULL;
    if (!ftl_tier_static(p) || !ssd->ns || !NS_BBSSD(ssd->ns)) {
        return;
    }
    density = ftl_tier_density(n->nand_cell_type);
    if (!density) {
        return;
    }

    t = g_new0(struct ftl_tier, 1);
    t->mode = FTL_TIER_STATIC;
    t->policy = ftl_tier_through(p) ? FTL_TIER_THROUGH : FTL_TIER_DIRECT;
    t->density = density;
    t->blk_pgs = tier_blk_pgs(spp->pgs_per_blk, density);
    t->line_pgs = t->blk_pgs * spp->blks_per_line;
    t->nlines = (int)bb_tier_pool_lines(n);
    t->state = g_new0(uint8_t, spp->tt_lines);
    t->ready = g_new0(uint64_t, spp->tt_lines);
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
 * stays where the tier keeps it. Returns false for a dense line.
 */
bool ftl_tier_invalidate(struct ssd *ssd, struct line *line)
{
    struct ftl_tier *t = ssd->tier;

    if (t->state[line->id] == FTL_TIER_LINE_DENSE) {
        return false;
    }
    line->ipc++;
    line->vpc--;
    t->valid--;
    return true;
}

/*
 * The frontier holds a line with a free page; it takes the oldest free line
 * if it can. A line whose erase ends after @now is taken only with @wait,
 * which then gets the end of the erase.
 */
static bool ftl_tier_frontier(struct ssd *ssd, uint64_t now, uint64_t *wait)
{
    struct ftl_tier *t = ssd->tier;
    struct line *line;

    if (t->wp.curline) {
        return true;
    }
    line = QTAILQ_FIRST(&t->free_lines);
    if (!line) {
        return false;
    }
    if (t->ready[line->id] > now) {
        if (!wait) {
            return false;
        }
        *wait = t->ready[line->id];
    }
    QTAILQ_REMOVE(&t->free_lines, line, entry);
    t->free_cnt--;
    t->state[line->id] = FTL_TIER_LINE_OPEN;
    ssd_wp_reset(&t->wp, line);
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
 * Fold the oldest closed pool line, starting at @now: move its valid pages,
 * then erase its blocks once the last program ends. Returns when the erase
 * ends, or 0 when the line could not be emptied. A line that is not empty
 * stays at the head of the FIFO, with the pages moved so far and the end of
 * their latest program kept for the retry.
 */
static uint64_t ftl_tier_fold(struct ssd *ssd, uint64_t now)
{
    struct ftl_tier *t = ssd->tier;
    struct ssdparams *spp = &ssd->sp;
    struct line *victim = QTAILQ_FIRST(&t->closed);
    uint64_t first = UINT64_MAX;
    uint64_t fence;
    uint64_t start;
    uint64_t done;
    struct ppa ppa = { .ppa = 0 };

    if (!victim) {
        return 0;
    }
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
                    if (!ftl_tier_fold_page(ssd, &ppa, now, &fence)) {
                        t->fold_fence = fence;
                        return 0;
                    }
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
    t->state[victim->id] = FTL_TIER_LINE_FREE;
    t->ready[victim->id] = done;
    QTAILQ_INSERT_TAIL(&t->free_lines, victim, entry);
    t->free_cnt++;
    t->folds++;
    t->last_fold_ns = done - t->fold_start;
    t->last_fold_prog_ns = fence - t->fold_start;
    t->last_fold_erase_ns = first - t->fold_start;
    t->fold_start = 0;
    t->fold_fence = 0;
    return done;
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

    if (!ftl_tier_frontier(ssd, now, through ? &wait : NULL) && through &&
        t->closed_cnt && ftl_tier_fold(ssd, now)) {
        ftl_tier_frontier(ssd, now, &wait);
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
 * After each request: with tier_full_policy=direct, fold one line when the
 * pool has no free line left, so later host writes find the pool again. A
 * free line whose erase has not ended yet counts as free. The through
 * policy folds in the write that needs the room.
 */
void ftl_tier_tick(struct ssd *ssd)
{
    struct ftl_tier *t = ssd->tier;

    if (t->policy != FTL_TIER_DIRECT || t->wp.curline || t->free_cnt ||
        !t->closed_cnt) {
        return;
    }
    ftl_tier_fold(ssd, ssd_now(ssd));
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

    QTAILQ_FOREACH(line, &t->free_lines, entry) {
        ftl_tier_see(ssd, seen, line, FTL_TIER_LINE_FREE, &bad);
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

    /* a pool line in a dense list or on the dense frontier */
    QTAILQ_FOREACH(line, &lm->free_line_list, entry) {
        bad += t->state[line->id] != FTL_TIER_LINE_DENSE;
    }
    QTAILQ_FOREACH(line, &lm->full_line_list, entry) {
        bad += t->state[line->id] != FTL_TIER_LINE_DENSE;
    }
    for (size_t i = 1; i < pq->size; i++) {
        bad += t->state[((struct line *)pq->d[i])->id] != FTL_TIER_LINE_DENSE;
    }
    if (ssd->wp.curline) {
        bad += t->state[ssd->wp.curline->id] != FTL_TIER_LINE_DENSE;
    }

    /* every pool line in exactly one tier place, no dense line in one */
    for (int i = 0; i < lm->tt_lines; i++) {
        if (t->state[i] == FTL_TIER_LINE_DENSE) {
            bad += seen[i] != 0;
            continue;
        }
        npool++;
        bad += seen[i] != 1;
        bad += lm->lines[i].pos != 0;
    }
    bad += npool != t->nlines;
    return bad;
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
 * The static pool form of the space rule: the dense lines must hold every
 * mapped page, a fold of every valid pool page included, with the forced
 * reserve and the dense frontier left over. Realize checked this for the
 * exported capacity. Returns 1 when they cannot. The free line form of the
 * rule comes with a pool that takes lines at run time.
 */
static uint64_t ftl_tier_check_reserve(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;
    int64_t dense = (int64_t)lm->tt_lines - ssd->tier->nlines -
                    ssd->spare_lines - ssd->eol_reserve_lines -
                    lm->retired_line_cnt - spp->gc_thres_lines_high - 1;
    uint64_t mapped = 0;

    for (uint64_t lpn = 0; lpn < (uint64_t)spp->tt_pgs; lpn++) {
        mapped += mapped_ppa(&ssd->maptbl[lpn]);
    }
    return dense < 0 || mapped > (uint64_t)dense * spp->pgs_per_line;
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
 * of its latest program and the start of its first erase. Last, the free
 * lines whose erase has not ended. Returns NULL with the tier off.
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
                           " %" PRIu64 " %" PRIu64 " %d",
                           t->nlines, t->line_pgs, t->free_cnt, t->closed_cnt,
                           t->wp.curline != NULL, t->valid, t->host_pslc,
                           t->host_dense, t->fold_pages, t->folds,
                           t->slc_erase_total, range,
                           ftl_tier_check_queues(ssd), count, map,
                           ftl_tier_check_reserve(ssd), t->place_fail,
                           t->fold_stale, ftl_tier_damage_max(ssd),
                           t->last_fold_ns, t->last_fold_prog_ns,
                           t->last_fold_erase_ns, busy);
}
