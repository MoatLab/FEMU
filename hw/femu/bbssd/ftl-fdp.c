/*
 * bbssd FTL: Flexible Data Placement (FDP) implementation. Owns the reclaim
 * group / reclaim unit / RU handle machinery, the FDP-aware write, GC, and trim
 * paths, and their initialization. Split out of ftl.c last so the public FDP
 * behavior is preserved verbatim; the FTL thread dispatch, mapping, line/GC, and
 * media interfaces come from ftl-internal.h and the media layer.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"

/* internal FDP forward declarations (the exported ones live in ftl-internal.h) */
static void mark_page_valid_fdp(struct ssd *ssd, struct ppa *ppa,
                                FemuReclaimUnit *ru);
static void mark_page_invalid_fdp(struct ssd *ssd, struct ppa *ppa);
static void ssd_reset_maptbl(struct ssd *ssd);
static void fdp_ru_sync_ruamw(struct ssd *ssd, FemuReclaimUnit *ru);

/* FDP: victim RU priority queue callbacks (greedy by vpc) */
static inline int victim_ru_cmp_pri(pqueue_pri_t next, pqueue_pri_t curr)
{
    return (next > curr);
}

static inline pqueue_pri_t victim_ru_get_pri(void *a)
{
    return ((FemuReclaimUnit *)a)->vpc;
}

static inline void victim_ru_set_pri(void *a, pqueue_pri_t pri)
{
    ((FemuReclaimUnit *)a)->vpc = pri;
}

static inline size_t victim_ru_get_pos(void *a)
{
    return ((FemuReclaimUnit *)a)->pos;
}

static inline void victim_ru_set_pos(void *a, size_t pos)
{
    ((FemuReclaimUnit *)a)->pos = pos;
}

/*
 * A PI-type RUH keeps its full RUs in BOTH the per-RG (global) victim pqueue
 * and its own per-RUH victim pqueue simultaneously. The two heaps must track
 * each RU's index independently, so the per-RUH queues use ruh_pos via these
 * callbacks. Sharing the single `pos` field across both heaps (issue #189)
 * corrupted whichever heap was touched second and crashed in
 * victim_ru_get_pri(NULL).
 */
static inline size_t victim_ru_get_pos_ruh(void *a)
{
    return ((FemuReclaimUnit *)a)->ruh_pos;
}

static inline void victim_ru_set_pos_ruh(void *a, size_t pos)
{
    ((FemuReclaimUnit *)a)->ruh_pos = pos;
}

/* FDP: victim RU priority queue callbacks (cost-benefit by my_cb) */
static inline int victim_ru_cmp_pri_by_cb(pqueue_pri_t next, pqueue_pri_t curr)
{
    return (next > curr);
}

static inline pqueue_pri_t victim_ru_get_pri_by_cb(void *a)
{
    /* cast float to pqueue_pri_t for ordering */
    return (pqueue_pri_t)((FemuReclaimUnit *)a)->my_cb;
}

static inline void victim_ru_set_pri_by_cb(void *a, pqueue_pri_t pri)
{
    ((FemuReclaimUnit *)a)->my_cb = (float)pri;
}

/* ========== FDP FTL Implementation ========== */

/*
 * get_next_free_ru - dequeue a free RU from a reclaim group
 */
static FemuReclaimUnit *get_next_free_ru(struct ssd *ssd,
                                         FemuReclaimGroup *rg)
{
    struct ru_mgmt *rm = rg->ru_mgmt;
    FemuReclaimUnit *ru;

    ru = QTAILQ_FIRST(&rm->free_ru_list);
    if (!ru) {
        ftl_err("No free RUs left in rg[%d]\n", rg->rgidx);
        return NULL;
    }

    QTAILQ_REMOVE(&rm->free_ru_list, ru, entry);
    rm->free_ru_cnt--;
    return ru;
}

/*
 * fdp_set_ru_write_pointer - reset RU write pointer to first line
 */
static void fdp_set_ru_write_pointer(struct ssd *ssd, FemuReclaimUnit *ru)
{
    struct write_pointer *wptr = ru->ssd_wptr;

    ftl_assert(wptr != NULL);
    ssd_wp_reset(wptr, ru->lines[0]);
}

/*
 * fdp_get_new_ru - allocate a fresh free RU for a given RUH
 */
static FemuReclaimUnit *fdp_get_new_ru(struct ssd *ssd, uint16_t rgidx,
                                       uint16_t ruhid)
{
    FemuRuHandle *eruh = &ssd->ruhs[ruhid];
    FemuReclaimGroup *rg = &ssd->rg[rgidx];
    FemuReclaimUnit *new_ru;

    new_ru = get_next_free_ru(ssd, rg);
    if (!new_ru) {
        ftl_err("No reclaim unit available for ruh %d\n", ruhid);
        return NULL;
    }
    new_ru->rgidx = rgidx;
    new_ru->ruh = eruh;
    new_ru->last_invalidated_time = 0;
    new_ru->my_cb = 0.0f;
    /* RUAMW counts in the blocks of the handle the unit now serves */
    fdp_ru_sync_ruamw(ssd, new_ru);

    fdp_set_ru_write_pointer(ssd, new_ru);
    eruh->ru_in_use_cnt++;
    if (eruh->ru_mgmt) {
        eruh->ru_mgmt[rgidx].in_use++;
    }

    /*
     * The host-visible active RU (NvmeRuHandle.rus) is published by the
     * caller that makes this the handle's current RU; a collection
     * destination allocated here must not replace it.
     */
    ftl_assert(new_ru->ruh == eruh);
    return new_ru;
}

/*
 * Make @ru the unit @ruh writes in group @rg, for the FTL and for the host,
 * or no unit with NULL. RUH Status reads the host's pointer on a poller, so
 * it is published whole.
 */
static void fdp_set_active(FemuRuHandle *ruh, uint16_t rg, FemuReclaimUnit *ru)
{
    ruh->rus[rg] = ru;
    qatomic_set(&ruh->ruh->rus[rg], ru ? ru->nvme_ru : &ruh->no_ru);
}

/*
 * The handle's active unit filled with nothing free to follow it. Point both
 * views away from the retired unit: collection can free it and hand it to
 * another handle, whose remaining room the host would then be shown here.
 */
static void fdp_drop_active_ru(FemuRuHandle *ruh, uint16_t rgidx)
{
    fdp_set_active(ruh, rgidx, NULL);
}

/*
 * The pages one collection or refresh pass moved out of @victim. @pages
 * counts them all, for MBMW; the rest describes the moves event 80h has not
 * reported yet: the written blocks they hold, and the first of those.
 */
struct fdp_moves {
    FemuReclaimUnit *victim;
    int pages;
    int unreported;
    uint64_t nlb;
    uint64_t lba;
    bool lbav;
    /* the namespace the unreported moves hold blocks of */
    NvmeNamespace *ns;
};

#define FDP_WRITTEN_SHIFT 9     /* fdp_written tracks 512-byte pieces */

/* the 512-byte pieces of page @lpn that blocks [@slba, @slba + @nlb) cover */
static void fdp_page_pieces(struct ssd *ssd, NvmeRequest *req, uint64_t slba,
                            uint64_t nlb, uint64_t lpn, uint64_t *b,
                            uint64_t *e)
{
    uint8_t lbads = req->ns ? req->ns->lbaf.lbads : BDRV_SECTOR_BITS;
    uint64_t pg = (uint64_t)ssd->sp.secsz * ssd->sp.secs_per_pg;
    uint64_t beg = ssd_lba_byte_offset(ssd, req, slba);

    *b = MAX(beg, lpn * pg) >> FDP_WRITTEN_SHIFT;
    *e = MIN(beg + (nlb << lbads), lpn * pg + pg) >> FDP_WRITTEN_SHIFT;
}

/*
 * Note which blocks of page @lpn the write of blocks [@slba, @slba + @nlb)
 * programs, as the FTL programs the page. The FTL maps whole pages and a write
 * can cover part of one, so this tells the moves of a page which of its blocks
 * hold data. The namespace's own bitmap will not do: it changes before the
 * FTL takes the write, and a move the write runs first would count it.
 */
static void fdp_mark_written(struct ssd *ssd, NvmeRequest *req, uint64_t slba,
                             uint64_t nlb, uint64_t lpn)
{
    uint64_t b, e;

    fdp_page_pieces(ssd, req, slba, nlb, lpn, &b, &e);
    e = MIN(e, ssd->fdp_written_bits);
    if (ssd->fdp_written && b < e) {
        bitmap_set(ssd->fdp_written, b, e - b);
    }
}

/*
 * The namespace whose slice holds page @lpn. Every namespace of an FDP
 * controller places into this FTL; a page past every slice, which no write
 * makes, is put down to the namespace that built the FTL.
 */
static NvmeNamespace *fdp_lpn_ns(struct ssd *ssd, uint64_t lpn)
{
    uint64_t at = lpn * ssd->sp.secsz * ssd->sp.secs_per_pg;
    FemuCtrl *n = ssd->n;

    for (int i = 0; n->namespaces && i < n->namespace_limit; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        uint64_t base;

        if (!ns->allocated || ns->ssd != ssd) {
            continue;
        }
        base = ssd_ns_byte_base(ssd, ns);
        if (at >= base && at < base + ns->size) {
            return ns;
        }
    }
    return ssd->ns;
}

static void fdp_report_moves(struct ssd *ssd, struct fdp_moves *mv);

/*
 * Count the move of page @lpn, and the blocks of it the FTL holds as written.
 * A block counts in the page that holds its first byte. An event names one
 * namespace, so the moves of another namespace's page are reported apart.
 */
static void fdp_moves_add(struct ssd *ssd, struct fdp_moves *mv, uint64_t lpn)
{
    NvmeNamespace *ns = fdp_lpn_ns(ssd, lpn);
    uint64_t pg = (uint64_t)ssd->sp.secsz * ssd->sp.secs_per_pg;
    uint64_t base, bs, lba, end;

    if (mv->unreported && mv->ns != ns) {
        fdp_report_moves(ssd, mv);
    }
    mv->ns = ns;
    mv->pages++;
    mv->unreported++;
    if (!ns || !ssd->fdp_written) {
        return;
    }
    base = ssd_ns_byte_base(ssd, ns);
    bs = 1ULL << ns->lbaf.lbads;
    if (lpn * pg + pg <= base) {
        return;
    }
    lba = lpn * pg < base ? 0 : DIV_ROUND_UP(lpn * pg - base, bs);
    end = MIN(DIV_ROUND_UP(lpn * pg + pg - base, bs),
              le64_to_cpu(ns->id_ns.nsze));
    for (; lba < end; lba++) {
        uint64_t piece = (base + (lba << ns->lbaf.lbads)) >> FDP_WRITTEN_SHIFT;

        if (piece < ssd->fdp_written_bits &&
            test_bit(piece, ssd->fdp_written)) {
            if (!mv->lbav) {
                mv->lba = lba;
                mv->lbav = true;
            }
            mv->nlb++;
        }
    }
}

/*
 * Report the moves not yet reported, as event 80h when the victim's handle is
 * initially isolated. A persistently isolated handle keeps its data apart for
 * good, so moving it is no news to the host.
 */
static void fdp_report_moves(struct ssd *ssd, struct fdp_moves *mv)
{
    FemuReclaimUnit *ru = mv->victim;

    if (mv->unreported &&
        ru->ruh->ruh_type == NVME_RUHT_INITIALLY_ISOLATED) {
        nvme_fdp_note_media_realloc(ssd->n, mv->ns, ru->rgidx,
                                    ru->ruh->ruhid, mv->nlb, mv->lbav,
                                    mv->lba);
    }
    mv->unreported = 0;
    mv->nlb = 0;
    mv->lbav = false;
}

/*
 * A move, not the host, gave initially isolated handle @ruh a new unit in
 * group @rgidx: event 81h. The moves before it are reported first, so the log
 * keeps the order in which things happened. A persistently isolated handle
 * moves into a unit the host never sees, so it never gets here.
 */
static void fdp_note_ruh_modified(struct ssd *ssd, FemuRuHandle *ruh,
                                  uint16_t rgidx, struct fdp_moves *mv)
{
    fdp_report_moves(ssd, mv);
    nvme_fdp_note_ruh_modified(ssd->n, mv->ns, rgidx, ruh->ruhid);
}

/*
 * fdp_get_new_page - get next PPA from an RU's write pointer
 */
static struct ppa fdp_get_new_page(struct ssd *ssd, FemuReclaimUnit *ru)
{
    struct write_pointer *wpp = ru->ssd_wptr;
    struct ppa ppa;

    ftl_assert(ru != NULL);
    ftl_assert(wpp != NULL);

    ppa.ppa = 0;
    ppa.g.ch = wpp->ch;
    ppa.g.lun = wpp->lun;
    ppa.g.pg = wpp->pg;
    ppa.g.blk = wpp->blk;
    ppa.g.pl = wpp->pl;

    return ppa;
}

/*
 * The group heap that holds @rm's victims. Cost-benefit keeps them in its own
 * heap, every other strategy in the vpc one; the other heap stays empty.
 */
static pqueue_t *fdp_victim_heap(struct ru_mgmt *rm)
{
    return rm->mgmt_type == GC_GLOBAL_CB ? rm->victim_ru_cb : rm->victim_ru_pq;
}

/*
 * The per-handle policy also queues a victim on its handle, whose heap it
 * consults first. Only Persistently Isolated handles have one.
 */
static struct ru_mgmt *fdp_victim_ruh_mgmt(struct ssd *ssd,
                                           FemuReclaimUnit *ru)
{
    struct ru_mgmt *rm = ssd->rg[ru->rgidx].ru_mgmt;

    if (rm->mgmt_type != GC_NOISY_RUH_CUSTOM || !ru->ruh ||
        !ru->ruh->ru_mgmt) {
        return NULL;
    }
    return &ru->ruh->ru_mgmt[ru->rgidx];
}

/* queue @ru as a victim of its own reclaim group, and of its handle */
static void fdp_victim_enqueue(struct ssd *ssd, FemuReclaimUnit *ru)
{
    struct ru_mgmt *rm = ssd->rg[ru->rgidx].ru_mgmt;
    struct ru_mgmt *hm = fdp_victim_ruh_mgmt(ssd, ru);

    pqueue_insert(fdp_victim_heap(rm), ru);
    if (hm) {
        pqueue_insert(hm->victim_ru_pq, ru);
    }
}

/*
 * Take @ru off every victim heap it is on. The heaps are separate arrays, so
 * the order of the two removals does not change either layout.
 */
static void fdp_victim_dequeue(struct ssd *ssd, FemuReclaimUnit *ru)
{
    struct ru_mgmt *rm = ssd->rg[ru->rgidx].ru_mgmt;

    if (ru->pos) {
        pqueue_remove(fdp_victim_heap(rm), ru);
    }
    if (ru->ruh_pos && ru->ruh && ru->ruh->ru_mgmt) {
        pqueue_remove(ru->ruh->ru_mgmt[ru->rgidx].victim_ru_pq, ru);
    }
}

/* reorder @ru on each heap it is on after its vpc or my_cb changed */
static void fdp_victim_reprioritize(struct ssd *ssd, FemuReclaimUnit *ru)
{
    struct ru_mgmt *rm = ssd->rg[ru->rgidx].ru_mgmt;
    struct ru_mgmt *hm = fdp_victim_ruh_mgmt(ssd, ru);

    if (rm->mgmt_type == GC_GLOBAL_CB) {
        if (ru->pos) {
            pqueue_change_priority(rm->victim_ru_cb, (pqueue_pri_t)ru->my_cb,
                                   ru);
        }
        return;
    }
    if (ru->pos) {
        pqueue_change_priority(rm->victim_ru_pq, ru->vpc, ru);
    }
    if (hm && ru->ruh_pos) {
        pqueue_change_priority(hm->victim_ru_pq, ru->vpc, ru);
    }
}

/*
 * fdp_retire_ru - file a unit that takes no more writes: on the full list if
 * every page it holds is valid, otherwise as a collection victim. Returns
 * whether it went on the full list.
 */
static bool fdp_retire_ru(struct ssd *ssd, FemuReclaimUnit *ru)
{
    struct ru_mgmt *rm = ssd->rg[ru->rgidx].ru_mgmt;
    bool is_full = true;
    uint64_t now = ssd_now(ssd);

    ru->vpc = 0;
    ru->close_seq = ++ssd->ru_close_seq;
    for (int i = 0; i < ru->n_lines; i++) {
        /* the data age of ecc_retention_sec counts from here */
        ru->lines[i]->close_time = now;
        if (ru->lines[i]->vpc != ru->npages / ru->n_lines) {
            is_full = false;
        }
        ru->vpc += ru->lines[i]->vpc;
    }

    if (is_full) {
        QTAILQ_INSERT_TAIL(&rm->full_ru_list, ru, entry);
        return true;
    }

    ru->utilization = (float)ru->vpc / ru->npages;
    /*
     * Cost-benefit ages a unit from its last invalidation. A unit retired
     * with none, which a handle update can leave part written, would count
     * from time zero and outscore every other unit; age it from now.
     */
    if (ru->last_invalidated_time == 0) {
        ru->last_invalidated_time = ssd_now_us(ssd);
    }
    if (rm->mgmt_type == GC_GLOBAL_CB) {
        if (ru->utilization < 1.0f && ru->last_invalidated_time > 0) {
            ru->my_cb = (uint64_t)(100000.0f * ru->utilization /
                ((1.0f - ru->utilization + 0.001f) *
                (float)ru->last_invalidated_time));
        }
    }
    fdp_victim_enqueue(ssd, ru);
    return false;
}

/*
 * fdp_advance_ru_pointer - advance RU write pointer. When RU fills up,
 * move it to victim/full list and allocate a new RU for the RUH.
 * Returns the (possibly new) current RU.
 */
static FemuReclaimUnit *fdp_advance_ru_pointer(struct ssd *ssd,
                                               FemuReclaimGroup *rg,
                                               FemuRuHandle *ruh,
                                               FemuReclaimUnit *ru)
{
    struct ssdparams *spp = &ssd->sp;
    struct ru_mgmt *rm = rg->ru_mgmt;
    struct write_pointer *wpp = ru->ssd_wptr;
    FemuReclaimUnit *new_ru = NULL;
    bool is_full;

    /* mid-RU: the same RU keeps taking pages */
    if (!ssd_wp_step(spp, wpp)) {
        return ru;
    }
    is_full = fdp_retire_ru(ssd, ru);

    /* the unit is full: take a free one of its group for the handle */
    if (ruh != NULL) {
        check_addr(wpp->blk, spp->blks_per_pl);
        new_ru = fdp_get_new_ru(ssd, ru->rgidx, ruh->ruhid);
        if (!new_ru) {
            ftl_err("No free RU for ruh %d: device full - point %s L:%d\n",
                    ruh->ruhid, __FILE__, __LINE__);
            /*
             * A full device is an ordinary outcome: the caller drops the
             * frontier it advanced and turns this into a capacity error.
             */
            return NULL;
        }
        FDP_TRACE(ssd, "RU_ROTATE ruhid=%u old_ru=%u "
                  "new_ru=%u reason=%s victims %zu\n",
                  ruh->ruhid, ru->ruidx, new_ru->ruidx,
                  is_full ? "full_valid" : "full_victim",
                  pqueue_size(fdp_victim_heap(rm)));
        wpp = new_ru->ssd_wptr;
        wpp->blk = wpp->curline->id;
        check_addr(wpp->blk, spp->blks_per_pl);
        ftl_assert(wpp->pg == 0);
        ftl_assert(wpp->lun == wpp->lun0);
        ftl_assert(wpp->ch == wpp->ch0);
        ftl_assert(wpp->pl == 0);
    }

    /*
     * The RU is retired (in full_ru_list or the victim queue): return the RU
     * that replaces it, or NULL without a handle or when the device is full.
     */
    return new_ru;
}

/*
 * mark_page_valid_fdp - mark page valid and update RU/line statistics
 */
static void mark_page_valid_fdp(struct ssd *ssd, struct ppa *ppa,
                                FemuReclaimUnit *ru)
{
    struct nand_block *blk = NULL;
    struct nand_page *pg = NULL;
    struct line *line;

    pg = get_pg(ssd, ppa);
    ftl_assert(pg->status == PG_FREE);
    pg->status = PG_VALID;

    blk = get_blk(ssd, ppa);
    ftl_assert(blk->vpc >= 0 && blk->vpc < ssd->sp.pgs_per_blk);
    blk->vpc++;
    blk->wp++; /* a program; invalidation never takes it back */

    line = get_line(ssd, ppa);
    ftl_assert(line->vpc >= 0 && line->vpc < ru->npages / ru->n_lines);
    line->vpc++;
    if ((ssd->sp.pd_open_age || ssd->sp.pd_open_close_sec) &&
        !line->open_time) {
        line->open_time = ssd_now(ssd);
    }

    /* update RU vpc from its line (single-line RU fast path) */
    ftl_assert(line->my_ru == ru);
    if (ru->n_lines == 1) {
        ru->vpc = line->vpc;
    } else {
        ru->vpc = 0;
        for (int i = 0; i < ru->n_lines; i++) {
            ru->vpc += ru->lines[i]->vpc;
        }
    }

    ru->ruh->ruh_live_pages_cnt++;
}

/*
 * mark_page_invalid_fdp - invalidate a page and update RU/line/victim state
 */
static void mark_page_invalid_fdp(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_block *blk = NULL;
    struct nand_page *pg = NULL;
    struct line *line;
    FemuReclaimUnit *ru;
    struct ru_mgmt *rm;
    bool was_full_ru = false;

    pg = get_pg(ssd, ppa);
    if (pg->status == PG_INVALID) {
        return;  /* already invalidated */
    }
    ftl_assert(pg->status == PG_VALID);
    pg->status = PG_INVALID;

    blk = get_blk(ssd, ppa);
    ftl_assert(blk->ipc >= 0 && blk->ipc < ssd->sp.pgs_per_blk);
    blk->ipc++;
    ftl_assert(blk->vpc > 0 && blk->vpc <= ssd->sp.pgs_per_blk);
    blk->vpc--;

    line = get_line(ssd, ppa);
    /* update RU state; a line of a group holds pages of the group's dies */
    ru = line->my_ru;
    ftl_assert(ru != NULL);
    ftl_assert(line->ipc >= 0 && line->ipc < ru->npages / ru->n_lines);
    if (line->vpc == ru->npages / ru->n_lines) {
        ftl_assert(line->ipc == 0);
    }
    line->ipc++;
    ftl_assert(line->vpc > 0 && line->vpc <= ru->npages / ru->n_lines);
    line->vpc--;

    rm = ssd->rg[ru->rgidx].ru_mgmt;
    /* aggregate ipc across all lines in this RU (n_lines=1 in typical config) */
    ru->ipc = 0;
    for (int li = 0; li < ru->n_lines; li++) {
        ru->ipc += ru->lines[li]->ipc;
    }

    /* check if RU was full and needs to move to victim */
    if (ru->vpc == ru->npages) {
        was_full_ru = true;
    }

    /* update RU vpc and victim queue priority based on GC strategy */
    ru->vpc--;
    /*
     * The share of the unit a collection copies, as at retirement: pages
     * never written are freed by the erase too, so they count as reclaimable.
     */
    ru->utilization = (float)ru->vpc / ru->npages;
    ru->last_invalidated_time = ssd_now_us(ssd);

    if (rm->mgmt_type == GC_GLOBAL_CB && ru->utilization < 1.0f &&
        ru->last_invalidated_time > 0) {
        ru->my_cb = (uint64_t)(100000.0f * ru->utilization /
            ((1.0f - ru->utilization + 0.001f) *
             (float)ru->last_invalidated_time));
    }
    fdp_victim_reprioritize(ssd, ru);
    /* a unit a refresh is moving is on no list until the move ends */
    if (was_full_ru && !ru->reclaiming) {
        QTAILQ_REMOVE(&rm->full_ru_list, ru, entry);
        fdp_victim_enqueue(ssd, ru);
    }
    if (ru->ruh->ruh_live_pages_cnt > 0)
        ru->ruh->ruh_live_pages_cnt -=1 ;
    
}

/*
 * The unit collection relocates into for @ruh, taking a free one from @rgidx
 * when the frontier has none. A persistently isolated handle collects into a
 * unit of its own; the initially isolated one shares its active unit with the
 * host. Either is dropped when it fills with no free unit to follow it, and is
 * picked up again here once collection has freed one, without looking at the
 * handle's active unit: that may be the one dropped.
 */
static FemuReclaimUnit *fdp_gc_frontier(struct ssd *ssd, FemuRuHandle *ruh,
                                        uint16_t rgidx, struct fdp_moves *mv)
{
    FemuReclaimUnit *ru;

    if (ruh->ruh_type == NVME_RUHT_PERSISTENTLY_ISOLATED) {
        if (!ruh->gc_rus[rgidx]) {
            ruh->gc_rus[rgidx] = fdp_get_new_ru(ssd, rgidx, ruh->ruhid);
        }
        return ruh->gc_rus[rgidx];
    }

    ftl_assert(ruh->ruh_type == NVME_RUHT_INITIALLY_ISOLATED);
    if (!ruh->rus[rgidx]) {
        ru = fdp_get_new_ru(ssd, rgidx, ruh->ruhid);
        if (!ru) {
            return NULL;
        }
        fdp_set_active(ruh, rgidx, ru);
        fdp_note_ruh_modified(ssd, ruh, rgidx, mv);
    }
    return ruh->rus[rgidx];
}

/*
 * Whether a background pass may take @ru: its erase must give back at least
 * an eighth of the unit. Count every page the erase gives back. A unit that a
 * handle update retired part written also frees the pages it never wrote;
 * judged by ipc alone it is refused on every pass, while its low vpc keeps
 * it at the heap top.
 */
static bool fdp_bg_worth_collecting(FemuReclaimUnit *ru)
{
    return ru->vpc == 0 || ru->npages - ru->vpc >= ru->npages / 8;
}

/* units the d-choice policy samples, as FEMU_DCHOICE_D does for lines */
#define FDP_DCHOICE_D 4

/*
 * select_victim_ru - pick best victim RU based on configured GC strategy
 */
static FemuReclaimUnit *select_victim_ru(struct ssd *ssd, uint16_t rgid,
                                         bool force)
{
    struct ru_mgmt *rm = ssd->rg[rgid].ru_mgmt;
    FemuReclaimUnit *victim_ru = NULL;

    switch (rm->mgmt_type) {
    case GC_GLOBAL_GREEDY:
        victim_ru = pqueue_peek(rm->victim_ru_pq);
        break;

    case GC_GLOBAL_CB: {
        /*
         * Cost-benefit weighs the space a reclaim frees against the copying
         * it costs, by how long the data has sat: (1 - u) * age / u. The age
         * only means something at selection time, so scan the heap here as
         * the line GC does rather than trust a priority fixed at insertion.
         */
        pqueue_t *pq = rm->victim_ru_cb;
        uint64_t now = ssd_now_us(ssd);
        double best = -1.0;
        double best_bg = -1.0;
        bool best_free = false;
        FemuReclaimUnit *bg_ru = NULL;

        for (size_t i = 1; i < pq->size; i++) {
            FemuReclaimUnit *ru = pq->d[i];
            double u = ru->utilization;
            double age = (double)(now - ru->last_invalidated_time) + 1.0;
            double score = (1.0 - u) * age / (u + 1e-6);

            if (ru->vpc == 0) {
                if (!best_free) {
                    best_free = true;
                    victim_ru = ru;
                }
            } else if (!best_free) {
                if (score > best) {
                    best = score;
                    victim_ru = ru;
                }
                if (score > best_bg && fdp_bg_worth_collecting(ru)) {
                    best_bg = score;
                    bg_ru = ru;
                }
            }
        }
        /*
         * An old unit with little to free can outscore every unit a
         * background pass would take. Refusing it then stalls background
         * collection until the others age past it, so take the best unit
         * the pass accepts. With none, the refusal below still runs.
         */
        if (!force && !best_free && bg_ru) {
            victim_ru = bg_ru;
        }
        break;
    }

    case GC_GLOBAL_RAND: {
        /* the slot pqueue_randpop() would take; draw even from an empty heap */
        uint64_t r = ftl_gc_rand(ssd);
        size_t n = pqueue_size(rm->victim_ru_pq);

        victim_ru = n ? rm->victim_ru_pq->d[r % n + 1] : NULL;
        break;
    }

    case GC_GLOBAL_FIFO: {
        /*
         * The unit retired first. An empty unit goes before it: it needs no
         * destination, so a full device can always collect it, while the
         * oldest unit may have pages that no free unit can take. A
         * background pass takes the oldest unit it would accept, so an old
         * unit with little to free does not hold back the younger ones.
         */
        pqueue_t *pq = rm->victim_ru_pq;
        FemuReclaimUnit *bg_ru = NULL;

        for (size_t i = 1; i < pq->size; i++) {
            FemuReclaimUnit *ru = pq->d[i];

            if (!ru->vpc) {
                victim_ru = ru;
                break;
            }
            if (!victim_ru || ru->close_seq < victim_ru->close_seq) {
                victim_ru = ru;
            }
            if (fdp_bg_worth_collecting(ru) &&
                (!bg_ru || ru->close_seq < bg_ru->close_seq)) {
                bg_ru = ru;
            }
        }
        if (!force && victim_ru && victim_ru->vpc && bg_ru) {
            victim_ru = bg_ru;
        }
        break;
    }

    case GC_GLOBAL_DCHOICE: {
        /*
         * The fewest valid pages among FDP_DCHOICE_D draws, with replacement;
         * the first of equal counts wins. An empty heap draws nothing, as in
         * line mode, and an empty unit goes first, as for fifo.
         */
        pqueue_t *pq = rm->victim_ru_pq;
        size_t n = pqueue_size(pq);
        FemuReclaimUnit *top = pqueue_peek(pq);

        if (top && !top->vpc) {
            victim_ru = top;
            break;
        }
        for (int s = 0; n && s < FDP_DCHOICE_D; s++) {
            FemuReclaimUnit *ru = pq->d[ftl_gc_rand(ssd) % n + 1];

            if (!victim_ru || ru->vpc < victim_ru->vpc) {
                victim_ru = ru;
            }
        }
        break;
    }

    case GC_NOISY_RUH_CUSTOM: {
        /*
         * Cross-RUH selection: find lowest vpc across all RUHs
         * that exceed their custom GC threshold.
         */
        FemuReclaimUnit *ru = NULL;
        int best_ruh = -1;
        int i;
        for (i = 0; i < (int)ssd->nruhs; i++) {
            struct ru_mgmt *hm = ssd->ruhs[i].ru_mgmt;

            if (!hm) {
                continue;
            }
            /* the handle's units and victims in this group only */
            hm = &hm[rgid];
            if (hm->in_use <= hm->custom_gc_threshold) {
                continue;
            }
            ru = pqueue_peek(hm->victim_ru_pq);
            if (!ru) {
                continue;
            }
            if (!victim_ru || ru->vpc < victim_ru->vpc) {
                best_ruh = i;
                victim_ru = ru;
            }
        }
        if (best_ruh < 0) {
            /* no handle is over its threshold: greedy over the group */
            victim_ru = pqueue_peek(rm->victim_ru_pq);
        }
        break;
    }

    default:
        /* realize refuses every other gc_strategy */
        g_assert_not_reached();
    }

    if (!victim_ru) {
        /*
         * victim_ru_pq is empty: all in-use RUs are still fully written
         * with no invalidations yet (e.g., during sequential fill). There is
         * no victim to reclaim, so returning NULL is the correct behavior.
         */
        return NULL;
    }

    /*
     * Detach before the check. Inserting a refused victim back reorders the
     * heap, so checking first would break later ties differently.
     */
    fdp_victim_dequeue(ssd, victim_ru);

    if (!force && !fdp_bg_worth_collecting(victim_ru)) {
        FDP_TRACE(ssd, "GC_BACK_RESERT triggered but delay GC "
                  "(ru %d ipc %d threshold %d full %d)\n",
                  victim_ru->ruidx, victim_ru->ipc, victim_ru->npages / 8,
                  victim_ru->npages);
        fdp_victim_enqueue(ssd, victim_ru);
        return NULL;
    }

    return victim_ru;
}

static void fdp_gc_mark_valid(struct ssd *ssd, struct ppa *ppa, void *dest)
{
    mark_page_valid_fdp(ssd, ppa, dest);
}

static const struct ssd_gc_move_ops fdp_gc_move_ops = {
    .mark_valid   = fdp_gc_mark_valid,
    .mark_invalid = mark_page_invalid_fdp,
};

/*
 * The RUAMW of @ru from the bytes programmed into it, in the blocks of the
 * namespaces that use its handle. The remaining bytes round down to whole
 * logical blocks, so a page smaller than a block and a page of any program
 * path count the same way.
 */
static uint64_t fdp_ru_ruamw(struct ssd *ssd, FemuReclaimUnit *ru)
{
    uint64_t runs = ssd->n->subsys->endgrp.fdp.runs;

    return (runs - MIN(runs, ru->prog_bytes)) >> ru->ruh->ruh->lbads;
}

/* A unit that never served a handle has no block size to count in. */
static void fdp_ru_sync_ruamw(struct ssd *ssd, FemuReclaimUnit *ru)
{
    if (ru->nvme_ru && ru->ruh && ru->ruh->ruh) {
        ru->nvme_ru->ruamw = fdp_ru_ruamw(ssd, ru);
    }
}

/*
 * @pages were programmed into @ru. Every program counts, also a relocation:
 * collection writes into the active unit of an Initially Isolated handle,
 * which the host sees.
 */
static void fdp_ru_programmed(struct ssd *ssd, FemuReclaimUnit *ru,
                              uint64_t pages)
{
    ru->prog_bytes += pages * ssd->sp.secsz * ssd->sp.secs_per_pg;
    fdp_ru_sync_ruamw(ssd, ru);
}

/*
 * The page collection writes next for @dest_ruh, or INVALID_PPA with
 * *@dest_ru NULL when no unit can take it.
 */
static struct ppa fdp_gc_dest_page(struct ssd *ssd, FemuRuHandle *dest_ruh,
                                   uint16_t rgidx, FemuReclaimUnit **dest_ru,
                                   struct fdp_moves *mv)
{
    struct ppa ppa = { .ppa = INVALID_PPA };

    ftl_assert(dest_ruh != NULL);
    /* the frontier may have been dropped by this or an earlier pass */
    *dest_ru = fdp_gc_frontier(ssd, dest_ruh, rgidx, mv);
    if (*dest_ru) {
        ppa = fdp_get_new_page(ssd, *dest_ru);
    }
    return ppa;
}

/* relocate @old_ppa to @new_ppa, which fdp_gc_dest_page() chose */
static void fdp_gc_move_to(struct ssd *ssd, struct ppa *old_ppa,
                           struct ppa *new_ppa, FemuReclaimUnit *dest_ru,
                           FemuRuHandle *dest_ruh, bool copyback,
                           struct fdp_moves *mv)
{
    uint64_t lpn = get_rmap_ent(ssd, old_ppa);
    FemuReclaimUnit *ret_ru = NULL;

    ftl_assert(valid_lpn(ssd, lpn));
    ssd_gc_move_page(ssd, lpn, old_ppa, new_ppa, &fdp_gc_move_ops, dest_ru);
    fdp_moves_add(ssd, mv, lpn);
    fdp_ru_programmed(ssd, dest_ru, 1);

    /*
     * fdp_advance_ru_pointer() only advances the write pointer of the given
     * unit, so the frontier of the handle in the unit's group is set here,
     * by handle type. Advancing hands back NULL when the group has no free
     * unit left: the frontier is then dropped, and the caller runs out of
     * room. Kept, the next relocation would program a written page of a
     * retired unit.
     */
    if (dest_ruh->ruh_type == NVME_RUHT_PERSISTENTLY_ISOLATED) {
        ret_ru = fdp_advance_ru_pointer(ssd, &ssd->rg[dest_ru->rgidx],
                                        dest_ru->ruh, dest_ru);
        if (ret_ru && ret_ru != dest_ru) {
            dest_ruh->gc_rus[dest_ru->rgidx] = ret_ru;
        } else if (!ret_ru) {
            dest_ruh->gc_rus[dest_ru->rgidx] = NULL;
        }
    } else if (dest_ruh->ruh_type == NVME_RUHT_INITIALLY_ISOLATED) {
        int gcruh_id = ssd->nruhs - 1;

        ftl_assert(dest_ruh->ruhid == gcruh_id);
        ret_ru = fdp_advance_ru_pointer(ssd, &ssd->rg[dest_ru->rgidx],
                                        dest_ruh, dest_ru);
        if (ret_ru && ret_ru != dest_ru) {
            fdp_set_active(&ssd->ruhs[gcruh_id], dest_ru->rgidx, ret_ru);
            fdp_note_ruh_modified(ssd, dest_ruh, dest_ru->rgidx, mv);
        } else if (!ret_ru) {
            /* no unit follows yet: the one taken later is the change */
            fdp_drop_active_ru(dest_ruh, dest_ru->rgidx);
        }
    }

    if (!ret_ru) {
        ftl_err("FDP: no free reclaim unit while relocating; device is full\n");
    }

    if (copyback) {
        ssd_gc_charge_copyback(ssd, old_ppa, new_ppa);
    } else {
        ssd_gc_charge_move(ssd, new_ppa);
    }
}

/*
 * gc_write_page_fdp_style - relocate a valid page to a GC destination RU.
 * Returns false when there is nowhere to put it, which leaves the page where it
 * is: the caller must then not erase the block it came from.
 */
static bool gc_write_page_fdp_style(struct ssd *ssd, struct ppa *old_ppa,
                                    FemuRuHandle *dest_ruh, uint16_t rgidx,
                                    struct fdp_moves *mv)
{
    FemuReclaimUnit *dest_ru;
    struct ppa new_ppa = fdp_gc_dest_page(ssd, dest_ruh, rgidx, &dest_ru, mv);

    if (!dest_ru) {
        return false;
    }
    fdp_gc_move_to(ssd, old_ppa, &new_ppa, dest_ru, dest_ruh, false, mv);

    /* this page is relocated; whether the next one can be is the next call */
    return true;
}

/*
 * Empty @victim_ru for copyback, as reclaim_line_copyback() does for a line:
 * before each move, look where @dest_ruh's collection unit writes next and
 * take a valid page of the victim on that die and plane; when none is left
 * there, take the next valid page in reclaim order and move it off-chip.
 * Counts the moves in @mv. Returns false, with the moves kept, when there
 * is no room.
 */
static bool fdp_reclaim_ru_copyback(struct ssd *ssd,
                                    FemuReclaimUnit *victim_ru,
                                    FemuRuHandle *dest_ruh,
                                    struct fdp_moves *mv)
{
    struct ssdparams *spp = &ssd->sp;
    FemuReclaimGroup *rg = &ssd->rg[victim_ru->rgidx];
    int npos = spp->nchs * spp->luns_per_ch * spp->pls_per_lun;
    int nlines = spp->lines_per_ru;
    g_autofree int *next = g_new0(int, nlines * npos);
    /* the pages of the victim: its blocks on the dies of its group */
    int total = victim_ru->npages;
    int seq = 0;

    while (victim_ru->vpc) {
        FemuReclaimUnit *dest_ru;
        struct ppa dst = fdp_gc_dest_page(ssd, dest_ruh, victim_ru->rgidx,
                                          &dest_ru, mv);
        struct ppa src;
        bool found = false;
        bool copyback;
        int pos;

        if (!dest_ru) {
            return false;
        }
        pos = (dst.g.ch * spp->luns_per_ch + dst.g.lun) * spp->pls_per_lun +
              dst.g.pl;
        src.ppa = 0;
        src.g.ch = dst.g.ch;
        src.g.lun = dst.g.lun;
        src.g.pl = dst.g.pl;
        for (int i = 0; i < nlines && !found; i++) {
            int *cur = &next[i * npos + pos];

            src.g.blk = victim_ru->lines[i]->id;
            while (!found && *cur < spp->pgs_per_blk) {
                src.g.pg = (*cur)++;
                found = get_pg(ssd, &src)->status == PG_VALID;
            }
        }
        while (!found && seq < total) {
            int i = seq;

            seq++;
            src.ppa = 0;
            src.g.pg = i % spp->pgs_per_blk;
            i /= spp->pgs_per_blk;
            src.g.pl = i % spp->pls_per_lun;
            i /= spp->pls_per_lun;
            src.g.lun = rg->lun0 + i % rg->nlun;
            i /= rg->nlun;
            src.g.ch = rg->ch0 + i % rg->nch;
            src.g.blk = victim_ru->lines[i / rg->nch]->id;
            found = get_pg(ssd, &src)->status == PG_VALID;
        }
        if (!found) {
            /* a valid count with no valid page: never erase such a unit */
            ftl_err("FDP: RU %u counts %d valid pages it does not hold\n",
                    victim_ru->ruidx, victim_ru->vpc);
            return false;
        }
        copyback = ssd_copyback_ok(ssd, &src, &dst);
        if (!copyback) {
            gc_read_page(ssd, &src);
        }
        fdp_gc_move_to(ssd, &src, &dst, dest_ru, dest_ruh, copyback, mv);
    }
    return true;
}

/*
 * clean_one_block_fdp_style - GC one block: read valid pages and write to new_ru
 * @params 
 *  ppa : identifies the block we want to clean
 *  dest_ruh : destination ruh.
 *          ru based mechanism can cause pointer error when gc write page allocates new ru to ruh->gc. 
 *          Replace ru based parameter which leaves a frontier dangling
 *          
 */
static bool clean_one_block_fdp_style(struct ssd *ssd, struct ppa *ppa,
                                      FemuRuHandle *dest_ruh, uint16_t rgidx,
                                      struct fdp_moves *mv)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_page *pg_iter;

    for (int pg = 0; pg < spp->pgs_per_blk; pg++) {
        ppa->g.pg = pg;
        pg_iter = get_pg(ssd, ppa);
        /* a unit a handle update closed early has pages never written */
        if (pg_iter->status == PG_VALID) {
            gc_read_page(ssd, ppa);
            /*
             * Nowhere to put this one. Stop here and say so: the pages already
             * moved keep their new home, and the ones still in this block have
             * to keep theirs, so the block must not be erased.
             */
            if (!gc_write_page_fdp_style(ssd, ppa, dest_ruh, rgidx, mv)) {
                return false;
            }
        }
    }

    ftl_assert(get_blk(ssd, ppa)->vpc == 0);
    return true;
}

/*
 * Charge relocated pages to MBMW and report them, also when a pass stops part
 * way, since the moves stay.
 */
static void fdp_count_gc_writes(struct ssd *ssd, FemuReclaimUnit *victim_ru,
                                struct fdp_moves *mv)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t gc_bytes = (uint64_t)mv->pages * spp->secsz * spp->secs_per_pg;

    nvme_fdp_eg_add(&ssd->n->subsys->endgrp,
                    ssd->n->subsys->endgrp.fdp.mbmw, gc_bytes);
    nvme_fdp_stat_inc(&victim_ru->ruh->mbmw, gc_bytes);
    nvme_fdp_stat_inc(&victim_ru->ruh->ruh->mbmw, gc_bytes);
    fdp_report_moves(ssd, mv);
}

/*
 * fdp_ru_reset - reset an erased RU to the state of a free one, without
 * putting it on the free list
 */
static void fdp_ru_reset(struct ssd *ssd, FemuReclaimUnit *ru)
{
    ftl_assert(ru != NULL);

    /*
     * The blocks are already erased. Every caller walks them itself first,
     * with the erase timing the die owes, and this ran the same walk again:
     * resetting page state a second time is harmless, but each block was
     * counted as erased twice, which is what wears the media in the model.
     */
    for (int i = 0; i < ru->n_lines; i++) {
        ru->lines[i]->ipc = 0;
        ru->lines[i]->vpc = 0;
        ru->lines[i]->close_time = 0;
        ru->lines[i]->open_time = 0;
    }

    ru->vpc = 0;
    ru->ipc = 0;
    ru->pos = 0;
    ru->ruh_pos = 0;
    ru->utilization = 0.0f;
    ru->my_cb = 0.0f;
    ru->close_seq = 0;
    ru->prog_bytes = 0;
    ru->reclaiming = false;

    /* a refresh queued for this unit has nothing left to move */
    if (ssd->read_reclaim_line && ssd->read_reclaim_line->my_ru == ru) {
        ssd->read_reclaim_line = NULL;
        ssd->reclaim_why = RECLAIM_READS;
    }

    fdp_set_ru_write_pointer(ssd, ru);

    /* erased: a full unit again */
    ftl_assert(ru->nvme_ru != NULL);
    ftl_assert(ru->ruh != NULL);
    ftl_assert(ru->ruh->ruh != NULL);
    fdp_ru_sync_ruamw(ssd, ru);
}

/*
 * mark_ru_free - reset a victim RU to free state after GC
 */
static void mark_ru_free(struct ssd *ssd, uint16_t rgid,
                         FemuReclaimUnit *ru)
{
    struct ru_mgmt *rm = ssd->rg[rgid].ru_mgmt;

    fdp_ru_reset(ssd, ru);
    QTAILQ_INSERT_TAIL(&rm->free_ru_list, ru, entry);
    rm->free_ru_cnt++;
}

/*
 * After the erase of @ru, deal with each of its blocks that has reached its
 * erase limit (blk_pe_limit), as ssd_wear_out_line() does for a line. The
 * unit holds no data now. It retires only while its group keeps
 * wear_floor_lines units and one free unit besides it, so collection still
 * has a unit to move pages into. Otherwise the worn-out blocks stay in
 * service, overworn, each counted once. With eol_read_only a worn-out
 * block is never written again: the unit always retires, and when that
 * cuts into the floor the media must go read-only (*@read_only). Units
 * held for the end of life do not count as usable. Called with wear_lock
 * held. Returns true when the unit was retired.
 */
static bool fdp_wear_out_ru(struct ssd *ssd, FemuReclaimUnit *ru,
                            bool *read_only)
{
    struct ssdparams *spp = &ssd->sp;
    FemuReclaimGroup *rg = &ssd->rg[ru->rgidx];
    struct ru_mgmt *rm = rg->ru_mgmt;
    int64_t usable = (int64_t)rg->tt_nru - (int64_t)rm->retired_ru_cnt -
                     (int64_t)ssd->fdp_eol_reserve;
    bool retire = false;
    int dead = 0;

    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < ru->n_lines; i++) {
            for (int ch = rg->ch0; ch < rg->ch0 + rg->nch; ch++) {
                for (int lun = rg->lun0; lun < rg->lun0 + rg->nlun; lun++) {
                    for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                        struct nand_block *blk = &ssd->ch[ch].lun[lun].
                                                 pl[pl].blk[ru->lines[i]->id];
                        bool worn = blk->pe_limit &&
                                    blk->erase_cnt >= blk->pe_limit;

                        if (!pass) {
                            dead += worn;
                        } else if (!retire) {
                            if (worn && !blk->overworn) {
                                blk->overworn = true;
                                ssd->overworn_blocks++;
                            }
                        } else {
                            if (blk->overworn) {
                                blk->overworn = false;
                                ssd->overworn_blocks--;
                            }
                            if (worn) {
                                ssd->grown_bad_blocks++;
                            } else {
                                ssd->sacrificed_blocks++;
                            }
                        }
                    }
                }
            }
        }
        if (!pass && !dead) {
            return false;
        }
        if (ssd->eol_ro_mode) {
            *read_only = usable - 1 < ssd->wear_floor_lines;
            retire = true;
        } else {
            retire = usable - 1 >= ssd->wear_floor_lines &&
                     rm->free_ru_cnt >= 1;
        }
    }
    if (!retire) {
        return false;
    }

    fdp_ru_reset(ssd, ru);
    ru->retired = true;
    rm->retired_ru_cnt++;
    ssd->lm.retired_line_cnt += ru->n_lines;
    return true;
}

/*
 * The wear-out step of a collected unit: retire it, or leave it to be
 * freed. The warnings this crosses go to the host as for a line.
 */
static bool fdp_wear_out(struct ssd *ssd, FemuReclaimUnit *ru)
{
    uint8_t spare = ssd_available_spare(ssd);
    uint64_t overworn = ssd->overworn_blocks;
    bool read_only = false;
    bool retired;

    qemu_mutex_lock(&ssd->wear_lock);
    retired = fdp_wear_out_ru(ssd, ru, &read_only);
    qemu_mutex_unlock(&ssd->wear_lock);
    ssd_wear_events(ssd, spare, overworn);
    if (read_only) {
        ssd_enter_read_only(ssd);
    }
    return retired;
}

/*
 * SMART Available Spare under FDP, with wear_lock held: in each group, the
 * units retirement may still take against those it could take at start;
 * the group with the least left speaks for the endurance group. No room to
 * retire at start means nothing is used up.
 */
uint8_t ssd_fdp_wear_spare(struct ssd *ssd)
{
    uint8_t spare = 100;

    for (uint64_t g = 0; ssd->rg && g < ssd->nrg; g++) {
        int64_t start = (int64_t)ssd->rg[g].tt_nru -
                        (int64_t)ssd->fdp_eol_reserve - ssd->wear_floor_lines;
        int64_t left = start - (int64_t)ssd->rg[g].ru_mgmt->retired_ru_cnt;

        if (start > 0) {
            spare = MIN(spare, MAX(left, 0) * 100 / start);
        }
    }
    return spare;
}

/*
 * The handle a unit's valid pages move to: a persistently isolated handle
 * keeps its own data (gc_rus), and the initially isolated ones share the last
 * handle's active unit.
 */
static FemuRuHandle *fdp_dest_ruh(struct ssd *ssd, FemuReclaimUnit *ru)
{
    if (ru->ruh->ruh_type == NVME_RUHT_PERSISTENTLY_ISOLATED) {
        return ru->ruh;
    }
    ftl_assert(ru->ruh->ruh_type == NVME_RUHT_INITIALLY_ISOLATED);
    return &ssd->ruhs[ssd->nruhs - 1];
}

/*
 * File a unit a pass could not empty back where a collection finds it: on
 * the full list while every page is valid, otherwise as a victim.
 */
static void fdp_file_back(struct ssd *ssd, FemuReclaimUnit *ru)
{
    struct ru_mgmt *rm = ssd->rg[ru->rgidx].ru_mgmt;

    if (ru->vpc == ru->npages) {
        QTAILQ_INSERT_TAIL(&rm->full_ru_list, ru, entry);
    } else {
        fdp_victim_enqueue(ssd, ru);
    }
}

/*
 * Empty @victim_ru into @dest_ruh's collection frontier, erase it and free it.
 * The caller has taken it off every list. @copyback lets pages move on their
 * die. Returns -1, with the unit filed back and the moves kept, when there is
 * no room.
 */
static int fdp_collect_ru(struct ssd *ssd, FemuReclaimUnit *victim_ru,
                          FemuRuHandle *dest_ruh, bool copyback)
{
    struct ssdparams *spp = &ssd->sp;
    FemuRuHandle *victim_ruh = victim_ru->ruh;
    FemuReclaimGroup *rg = &ssd->rg[victim_ru->rgidx];
    struct fdp_moves mv = { .victim = victim_ru };
    struct ppa ppa;
    int blk_cnt = 0;

    /*
     * A victim with pages to move needs somewhere to put them; with no free
     * unit for the frontier, put it back and fail the pass, and the caller
     * degrades to a device-full write. One with none needs nowhere, and must
     * be collected even then: it is what gives the frontier a unit again.
     */
    if (victim_ru->vpc &&
        !fdp_gc_frontier(ssd, dest_ruh, victim_ru->rgidx, &mv)) {
        fdp_file_back(ssd, victim_ru);
        return -1;
    }
    /* sanity: don't GC an active RU */
    if (victim_ru == victim_ru->ruh->rus[victim_ru->rgidx]) {
        ftl_err("Victim RU %d is active, skipping GC\n", victim_ru->ruidx);
        //This is a bug.
        ftl_assert(false && __LINE__);
        return -1;
    }

    ftl_note_victim(ssd, (uint64_t)victim_ru->rgidx << 16 | victim_ru->ruidx);
    FDP_TRACE(ssd, "GC_START victim_ru=%u victim_vpc=%d isolation=%s\n",
              victim_ru->ruidx, victim_ru->vpc,
              (victim_ruh->ruh_type == NVME_RUHT_PERSISTENTLY_ISOLATED) ?
              "PI" : "II");

    /*
     * Migrate every valid page before erasing any block. If the destination
     * runs out part way, the victim goes back on the queue holding what was
     * not moved; a block erased before that point would be counted erased
     * again when the unit is next collected.
     */
    if (copyback) {
        if (!fdp_reclaim_ru_copyback(ssd, victim_ru, dest_ruh, &mv)) {
            fdp_count_gc_writes(ssd, victim_ru, &mv);
            fdp_file_back(ssd, victim_ru);
            return -1;
        }
    }
    /* the unit's blocks are on the dies of its group only */
    for (int i = 0; i < spp->lines_per_ru && !copyback; i++) {
        ppa.g.blk = victim_ru->lines[i]->id;
        for (int ch = rg->ch0; ch < rg->ch0 + rg->nch; ch++) {
            for (int lun = rg->lun0; lun < rg->lun0 + rg->nlun; lun++) {
                ppa.g.ch = ch;
                ppa.g.lun = lun;
                for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                    ppa.g.pl = pl;
                    if (!clean_one_block_fdp_style(ssd, &ppa, dest_ruh,
                                                   victim_ru->rgidx, &mv)) {
                        fdp_count_gc_writes(ssd, victim_ru, &mv);
                        fdp_file_back(ssd, victim_ru);
                        return -1;
                    }
                }
            }
        }
    }

    for (int i = 0; i < spp->lines_per_ru; i++) {
        struct line *victim_line = victim_ru->lines[i];
        ppa.g.blk = victim_line->id;
        for (int ch = rg->ch0; ch < rg->ch0 + rg->nch; ch++) {
            for (int lun = rg->lun0; lun < rg->lun0 + rg->nlun; lun++) {
                ssd_erase_lun_block(ssd, ch, lun, ppa.g.blk,
                                    spp->enable_gc_delay, 0);
                blk_cnt += spp->pls_per_lun;
            }
        }
    }

    /* update FDP statistics: media bytes written (GC writes) */
    uint64_t gc_bytes = (uint64_t)mv.pages * spp->secsz * spp->secs_per_pg;
    uint64_t erase_bytes = (uint64_t)blk_cnt * spp->secsz * spp->secs_per_pg
                           * spp->pgs_per_blk;

    FDP_TRACE(ssd, "GC_DONE victim_ru=%u pages_migrated=%d "
              "blocks_erased=%d mbmw_delta=%lu mbe_delta=%lu\n",
              victim_ru->ruidx, mv.pages, blk_cnt, gc_bytes, erase_bytes);
    fdp_count_gc_writes(ssd, victim_ru, &mv);
    nvme_fdp_eg_add(&ssd->n->subsys->endgrp,
                    ssd->n->subsys->endgrp.fdp.mbe, erase_bytes);
    nvme_fdp_stat_inc(&victim_ru->ruh->mbe, erase_bytes);
    nvme_fdp_stat_inc(&victim_ru->ruh->ruh->mbe, erase_bytes);

    if (ssd->ruhs[victim_ru->ruh->ruhid].ru_in_use_cnt > 0) {
        ssd->ruhs[victim_ru->ruh->ruhid].ru_in_use_cnt--;
    }
    if (victim_ruh->ru_mgmt &&
        victim_ruh->ru_mgmt[victim_ru->rgidx].in_use > 0) {
        victim_ruh->ru_mgmt[victim_ru->rgidx].in_use--;
    }

    /* a worn-out block can take the unit out of service instead */
    if (ssd->wear_on && fdp_wear_out(ssd, victim_ru)) {
        return 0;
    }

    /*
     * Free the victim into its OWN reclaim group. A cross-RG NOISY victim can
     * differ from the caller's rgid; freeing it into rgid would corrupt the
     * per-RG free list and later hand a foreign RU out from the wrong group.
     * For every non-NOISY path victim_ru->rgidx == rgid, so this is a no-op.
     */
    mark_ru_free(ssd, victim_ru->rgidx, victim_ru);
    return 0;
}

/*
 * do_gc_fdp_style - FDP garbage collection: select victim RU, migrate valid
 * pages to GC RU, then free the victim
 *  gaurantees one RU to be reclaimed, if victim is valid.
 */
int do_gc_fdp_style(struct ssd *ssd, uint16_t rgid, uint16_t ruhid,
                           bool force)
{
    FemuReclaimUnit *victim_ru;
    struct line *queued = ssd->read_reclaim_line;
    bool copyback;

    /*
     * Read-only media erases nothing: the admitted writes finish from the
     * free units and the reserve, with no collection.
     */
    if (ssd->media_ro) {
        return -1;
    }
    victim_ru = select_victim_ru(ssd, rgid, force);
    if (!victim_ru) {
        //FDP_TRACE(ssd,"GC_SKIP Unable to find victim RU, gc skip\n");
        return -1;
    }

    /*
     * A unit queued for a refresh holds data the refresh must pass through
     * the controller's ECC, so collecting it first must not copy it on die.
     */
    copyback = ssd->sp.gc_copyback && !(queued && queued->my_ru == victim_ru);
    return fdp_collect_ru(ssd, victim_ru, fdp_dest_ruh(ssd, victim_ru),
                          copyback);
}

/* the first program in @ru since it was freed, 0 if none */
static uint64_t fdp_ru_open_time(FemuReclaimUnit *ru)
{
    uint64_t t = 0;

    for (int i = 0; i < ru->n_lines; i++) {
        uint64_t o = ru->lines[i]->open_time;

        if (o && (!t || o < t)) {
            t = o;
        }
    }
    return t;
}

/*
 * Take @ru out of the frontier of the handle that writes it, with no free
 * unit the controller cannot spare. A host frontier gets a fresh unit, and
 * the host is told why: event 01h after a pad (@pad, the active time limit),
 * 81h otherwise. A collection frontier is dropped; fdp_gc_frontier() takes a
 * new one when collection next needs it. With @pad the free pages are
 * programmed first; without, they stay free, as a handle update leaves them.
 * The unit is then retired like a full one. Returns false if nothing changed.
 */
static bool fdp_pd_leave_ru(struct ssd *ssd, FemuReclaimUnit *ru, bool pad,
                            uint64_t stime)
{
    struct ru_mgmt *rm = ssd->rg[ru->rgidx].ru_mgmt;
    uint16_t rg = ru->rgidx;
    FemuRuHandle *host = NULL;
    FemuRuHandle *gc = NULL;
    FemuReclaimUnit *fresh = NULL;

    for (int i = 0; i < (int)ssd->nruhs; i++) {
        if (ssd->ruhs[i].rus[rg] == ru) {
            host = &ssd->ruhs[i];
        } else if (ssd->ruhs[i].gc_rus[rg] == ru) {
            gc = &ssd->ruhs[i];
        }
    }
    if ((!host && !gc) || rm->free_ru_cnt < 2 || fdp_rg_short(ssd, rg)) {
        return false;
    }
    if (host) {
        fresh = fdp_get_new_ru(ssd, rg, host->ruhid);
        if (!fresh) {
            return false;
        }
    }
    if (pad) {
        uint64_t pads = 0;
        uint64_t bytes;

        for (int i = 0; i < ru->n_lines; i++) {
            pads += ssd_pad_line(ssd, ru->lines[i], stime);
        }
        fdp_ru_programmed(ssd, ru, pads);
        ru->ipc = 0;
        for (int i = 0; i < ru->n_lines; i++) {
            ru->ipc += ru->lines[i]->ipc;
        }
        /* pads are media writes: MBMW counts them, HBMW does not */
        bytes = pads * ssd->sp.secsz * ssd->sp.secs_per_pg;
        nvme_fdp_eg_add(&ssd->n->subsys->endgrp,
                        ssd->n->subsys->endgrp.fdp.mbmw, bytes);
        nvme_fdp_stat_inc(&ru->ruh->mbmw, bytes);
        nvme_fdp_stat_inc(&ru->ruh->ruh->mbmw, bytes);
    }
    fdp_retire_ru(ssd, ru);
    if (gc) {
        gc->gc_rus[rg] = NULL;
        return true;
    }
    fdp_set_active(host, rg, fresh);
    /* no data moved, so the event names a namespace that uses the handle */
    if (pad) {
        nvme_fdp_note_ru_time_limit(ssd->n, NULL, rg, host->ruhid);
    } else {
        nvme_fdp_note_ruh_modified(ssd->n, NULL, rg, host->ruhid);
    }
    return true;
}

/*
 * Pad and close each frontier unit that has stayed open pd_open_close_sec
 * since its first program, the FDP reclaim unit active time limit. Like
 * ssd_pd_close_aged(), it runs when the FTL takes a request.
 */
void ssd_fdp_pd_close_aged(struct ssd *ssd, uint64_t stime)
{
    uint64_t limit = (uint64_t)ssd->sp.pd_open_close_sec *
                     NANOSECONDS_PER_SECOND;

    /* after the end of life only the admitted writes may take pages */
    if (ssd->media_ro) {
        return;
    }

    for (int i = 0; i < (int)ssd->nruhs; i++) {
        FemuRuHandle *ruh = &ssd->ruhs[i];

        for (uint64_t g = 0; g < ssd->nrg; g++) {
            FemuReclaimUnit *rus[2] = { ruh->rus[g], ruh->gc_rus[g] };

            for (int r = 0; r < 2; r++) {
                if (rus[r] && ssd_data_age_ns(ssd, fdp_ru_open_time(rus[r]),
                                              stime) >= limit) {
                    fdp_pd_leave_ru(ssd, rus[r], true, stime);
                }
            }
        }
    }
}

/*
 * Refresh the unit holding the line the read path queued, for read stress or
 * retention age, as do_read_reclaim() does for a line. One unit per write,
 * and only when no group is short of free units. The pages move through the
 * controller (no copyback), to where collection would move them, and report
 * the same FDP events.
 */
static void fdp_do_read_reclaim(struct ssd *ssd)
{
    struct line *line = ssd->read_reclaim_line;
    FemuReclaimUnit *ru;
    struct ru_mgmt *rm;
    enum ssd_reclaim_why why;
    int ok;

    /* no refresh, and no frontier seal, on read-only media */
    if (!line || ssd->media_ro) {
        return;
    }
    /* the refresh moves data inside the group, so its room counts */
    ru = line->my_ru;
    rm = ssd->rg[ru->rgidx].ru_mgmt;
    if (rm->free_ru_cnt < 2 || fdp_rg_short(ssd, ru->rgidx)) {
        /*
         * With several groups, the one queued line must not hold back the
         * refresh of another group; the next read of the block queues it
         * again.
         */
        if (ssd->nrg > 1) {
            ssd->read_reclaim_line = NULL;
            ssd->reclaim_why = RECLAIM_READS;
        }
        return;
    }

    ssd->read_reclaim_line = NULL;
    why = ssd->reclaim_why;
    ssd->reclaim_why = RECLAIM_READS;

    /* an open unit read past pd_open_read_limit leaves its frontier first */
    if (why == RECLAIM_OPEN) {
        fdp_pd_leave_ru(ssd, ru, false, 0);
    }

    /* data still being written: leave it alone, as line mode does */
    for (int i = 0; i < (int)ssd->nruhs; i++) {
        if (ssd->ruhs[i].rus[ru->rgidx] == ru ||
            ssd->ruhs[i].gc_rus[ru->rgidx] == ru) {
            return;
        }
    }
    if (ru->pos || ru->ruh_pos) {
        fdp_victim_dequeue(ssd, ru);
    } else if (ru->vpc == ru->npages) {
        QTAILQ_REMOVE(&rm->full_ru_list, ru, entry);
    } else {
        /* on no list: free, so there is nothing to move */
        return;
    }

    ru->reclaiming = true;
    ok = fdp_collect_ru(ssd, ru, fdp_dest_ruh(ssd, ru), false);
    ru->reclaiming = false;
    if (ok < 0) {
        /* filed back with pages still on it: try again on a later write */
        if (ru->vpc && !ssd->read_reclaim_line) {
            ssd->read_reclaim_line = line;
            ssd->reclaim_why = why;
        }
        return;
    }
    if (why == RECLAIM_AGE) {
        ssd->retention_refreshes++;
    } else if (why == RECLAIM_OPEN) {
        ssd->pd_open_reclaims++;
    } else {
        ssd->read_reclaims++;
    }
}

/* collect in group @rgid until it is no longer short of free units */
static void fdp_gc_until_clear(struct ssd *ssd, uint16_t rgid, uint16_t ruhid)
{
    uint64_t fg_gc_iters = 0;
    uint64_t max_fg_gc = (uint64_t)ssd->nrg * ssd->rg[0].ru_mgmt->tt_rus +
                         ssd->nrg;

    while (fdp_rg_short(ssd, rgid) && fg_gc_iters < max_fg_gc) {
        if (do_gc_fdp_style(ssd, rgid, ruhid, true) == -1) {
            break;
        }
        fg_gc_iters++;
        ssd->gc_stall_passes++;
    }
}

/*
 * The group a write takes when its placement names none (Base 2.3, 8.1.11:
 * the controller selects it): the one with the most free units, so data
 * spreads over the groups as they empty. Ties go to the first group after
 * the one taken last. With one group it is always 0.
 */
static uint16_t fdp_select_rg(struct ssd *ssd)
{
    uint16_t best = ssd->rg_next % ssd->nrg;

    for (uint64_t k = 1; k < ssd->nrg; k++) {
        uint16_t g = (ssd->rg_next + k) % ssd->nrg;

        if (ssd->rg[g].ru_mgmt->free_ru_cnt >
            ssd->rg[best].ru_mgmt->free_ru_cnt) {
            best = g;
        }
    }
    ssd->rg_next = (best + 1) % ssd->nrg;
    return best;
}

/*
 * The handle and group request @req places into. A placement that names no
 * valid handle falls back to placement handle 0 in a group the controller
 * selects, and logs Invalid Placement Identifier if the host tried one.
 */
static void fdp_place(struct ssd *ssd, NvmeRequest *req, uint16_t *rgid,
                      uint16_t *ruhid)
{
    NvmeNamespace *ns = req->ns;
    uint16_t pid = req->fdp_dspec;
    uint8_t dtype = req->fdp_dtype;
    uint16_t ph;

    if (dtype != NVME_DIRECTIVE_DATA_PLACEMENT ||
        !nvme_parse_pid(ns, pid, &ph, rgid)) {
        ph = 0;
        *rgid = fdp_select_rg(ssd);
        if (dtype == NVME_DIRECTIVE_DATA_PLACEMENT) {
            nvme_fdp_note_invalid_pid(ssd->n, ns, pid, *rgid);
        }
    }

    *ruhid = ns->fdp.phs[ph];
    /* safety: ruhid must be within bounds (nvme_parse_pid ensures ph is valid) */
    if (unlikely(*ruhid >= (uint16_t)ssd->nruhs)) {
        ftl_err("ssd_stream_write: ruhid %u >= nruhs %lu, clamping to 0\n",
                (unsigned)*ruhid, (unsigned long)ssd->nruhs);
        *ruhid = 0;
    }
}

/*
 * Give @ruh an active unit in group @rgid if it has none. After a fill
 * fdp_advance_ru_pointer() can leave it without one when no unit was free;
 * collection may have freed one since. Returns false when none is free.
 */
static bool fdp_ruh_ready(struct ssd *ssd, FemuRuHandle *ruh, uint16_t rgid)
{
    FemuReclaimUnit *fresh;

    if (likely(ruh->rus[rgid])) {
        return true;
    }
    fresh = fdp_get_new_ru(ssd, rgid, ruh->ruhid);
    if (!fresh) {
        ftl_err("ssd_stream_write: device full, no RU for ruh %d\n",
                ruh->ruhid);
        return false;
    }
    fdp_set_active(ruh, rgid, fresh);
    return true;
}

/*
 * The host write path's test for a unit to program. With eol_read_only, a
 * write the poller admitted has changed data already, so it must not fail
 * for room: when collection cannot give the handle a unit, the media
 * cannot take more writes, which ends its life. The write then goes on
 * from the reserve units. Without it, the handle's own unit or none.
 */
static bool fdp_host_frontier(struct ssd *ssd, FemuRuHandle *ruh,
                              uint16_t rgid)
{
    if (!ssd->eol_ro_mode) {
        return ruh->rus[rgid] != NULL;
    }
    if (fdp_ruh_ready(ssd, ruh, rgid)) {
        return true;
    }
    if (!ssd->media_ro) {
        fdp_gc_until_clear(ssd, rgid, ruh->ruhid);
        if (fdp_ruh_ready(ssd, ruh, rgid)) {
            return true;
        }
        ssd_enter_read_only(ssd);
    }
    return fdp_ruh_ready(ssd, ruh, rgid);
}

/*
 * Program host page @lpn into @ruh's active unit, which the caller has made
 * sure exists. The written pieces are those of blocks [@slba, @slba + @nlb)
 * of @req, if given, and those of @held, the mask a buffer entry kept.
 * Returns the program time.
 */
static uint64_t fdp_program_page(struct ssd *ssd, FemuReclaimGroup *rg,
                                 FemuRuHandle *ruh, uint64_t lpn,
                                 uint64_t stime, NvmeRequest *req,
                                 uint64_t slba, uint64_t nlb,
                                 const unsigned long *held)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t pg = (uint64_t)spp->secsz * spp->secs_per_pg;
    uint64_t per = pg >> FDP_WRITTEN_SHIFT;
    FemuReclaimUnit *ru = ruh->rus[rg->rgidx];
    struct nand_cmd swr;
    struct ppa ppa;

    ppa = get_maptbl_ent(ssd, lpn);
    if (mapped_ppa(&ppa)) {
        mark_page_invalid_fdp(ssd, &ppa);
        set_rmap_ent(ssd, INVALID_LPN, &ppa);
    }
    /* the page content changes: drop any stale read-cache entry for it */
    rcache_invalidate(ssd, lpn);
    /* new write */
    ppa = fdp_get_new_page(ssd, ru);
    set_maptbl_ent(ssd, lpn, &ppa);
    set_rmap_ent(ssd, lpn, &ppa);
    mark_page_valid_fdp(ssd, &ppa, ru);
    if (req) {
        fdp_mark_written(ssd, req, slba, nlb, lpn);
    }
    if (held && ssd->fdp_written) {
        for (uint64_t i = 0; i < per && lpn * per + i < ssd->fdp_written_bits;
             i++) {
            if (test_bit(i, held)) {
                set_bit(lpn * per + i, ssd->fdp_written);
            }
        }
    }
    ssd->nand_write_pages++; /* a user page programmed into NAND */
    fdp_ru_programmed(ssd, ru, 1);

    /* advance RU write pointer; may allocate new RU */
    FemuReclaimUnit *ret = fdp_advance_ru_pointer(ssd, rg, ruh, ru);
    if (ret && ret != ru) {
        fdp_set_active(ruh, rg->rgidx, ret);
    } else if (!ret) {
        /* no free unit; the next page or command fails for it */
        fdp_drop_active_ru(ruh, rg->rgidx);
    }

    swr.type = USER_IO;
    swr.cmd = NAND_WRITE;
    swr.stime = stime;
    return ssd_advance_status(ssd, &ppa, &swr);
}

/*
 * ssd_stream_write - FDP write path: placement-aware page allocation
 */
/*
 * Program [start_lpn, end_lpn], the pages of blocks [slba, slba + nlb), into
 * the reclaim unit the request places into. Write and Write Zeroes both land
 * here: the second hands over no data, but the pages it leaves holding zeros
 * are programmed and counted the same way. A page the write buffer holds is
 * superseded: its entry goes when this write programs the page, and the
 * pieces it covered stay written.
 */
static uint64_t ssd_stream_write_lpns(FemuCtrl *n, struct ssd *ssd,
                                      NvmeRequest *req, uint64_t slba,
                                      uint64_t nlb, uint64_t start_lpn,
                                      uint64_t end_lpn)
{
    uint64_t passes;
    struct ssdparams *spp = &ssd->sp;
    FemuReclaimGroup *rg;
    FemuRuHandle *ruh;
    uint64_t lpn;
    uint64_t curlat = 0, maxlat = 0;
    uint64_t written = 0;
    uint16_t rgid, ruhid;

    fdp_place(ssd, req, &rgid, &ruhid);
    rg = &ssd->rg[rgid];
    ruh = &ssd->ruhs[ruhid];

    /*
     * Genuinely out of reclaimable space: no unit is free for the handle.
     * Fail the command with a capacity error instead of completing it as
     * success with no data written.
     */
    if (!(ssd->eol_ro_mode ? fdp_host_frontier(ssd, ruh, rgid) :
          fdp_ruh_ready(ssd, ruh, rgid))) {
        req->status = NVME_CAP_EXCEEDED | NVME_DNR;
        return 0;
    }

    if (end_lpn >= spp->tt_pgs) {
        ftl_err("write past device geometry: end_lpn=%" PRIu64 " tt_pgs=%d\n",
                end_lpn, spp->tt_pgs);
        req->status = NVME_LBA_RANGE | NVME_DNR;
        return 0;
    }

    /*
     * Foreground GC backpressure: reclaim until write pressure clears rather
     * than for a fixed number of passes. Each pass frees at most one reclaim
     * unit, so the old fixed cap (nrg) let the free-RU pool drain to zero under
     * sustained overwrites and the write then failed with a spurious device-full.
     * Running until the write's group is no longer short holds its pool
     * above the threshold -- the host write effectively waits on GC, which
     * is the intended backpressure. do_gc_fdp_style() returns -1 when no victim
     * remains (nothing left to reclaim); that is the normal exit. The counter is
     * only a guard against an unexpected non-terminating condition, bounded by
     * the total reclaim-unit population so it never trips during real progress.
     */
    passes = ssd->gc_stall_passes;
    fdp_gc_until_clear(ssd, rgid, ruhid);
    /* refresh at most one read-stressed or aged unit per write */
    fdp_do_read_reclaim(ssd);

    /* a disabled write cache may not keep pages back: write them out first */
    if (ssd->write_buffer_cnt && !ssd_buffer_enabled(ssd)) {
        curlat = fdp_buffer_destage(ssd, 0, req->stime);
        maxlat = MAX(maxlat, curlat);
    }

    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        struct buffer_entry *held;

        /*
         * And per page: one command can take more units than the watermark
         * keeps free, and once the handle's last unit is gone collection has
         * nowhere to move pages to.
         */
        fdp_gc_until_clear(ssd, rgid, ruhid);

        /*
         * A previous iteration may have exhausted the last free reclaim unit
         * of the group: the handle then has no unit there.
         * Writing into a NULL RU would dereference it in fdp_get_new_page(); stop
         * and fail the command with a capacity error rather than crashing or
         * reporting a silent success for pages that were never written.
         */
        if (unlikely(!ruh->rus[rgid]) && !fdp_host_frontier(ssd, ruh, rgid)) {
            req->status = NVME_CAP_EXCEEDED | NVME_DNR;
            break;
        }

        /* dftl: the translation page of this lpn, as a line-mode write */
        if (ssd->cmt.capacity) {
            curlat = cmt_touch(ssd, lpn, req->stime, true);
            maxlat = MAX(maxlat, curlat);
        }

        held = ssd->write_buffer_cnt ? ssd_buffer_lookup(ssd, lpn) : NULL;
        curlat = fdp_program_page(ssd, rg, ruh, lpn, req->stime, req, slba,
                                  nlb, held ? held->written : NULL);
        maxlat = MAX(maxlat, curlat);
        if (held) {
            ssd_buffer_discard(ssd, lpn);
        }
        /*
         * Counted here rather than for the whole command before the loop: the
         * loop stops when the device runs out of room, so a command that wrote
         * part of itself used to add all of its pages to the denominator the
         * amplification figure divides by.
         */
        ssd->host_write_pages++;
        written++;
    }

    /* what the caller charges its byte counters with */
    req->xfer_bytes = written * (uint64_t)spp->secs_per_pg * spp->secsz;

    ssd_note_gc_stall(ssd, passes);
    return maxlat;
}

/* the held page of @e is one @want names: index ruhid x nrg + rgid */
static bool fdp_buffer_wanted(struct ssd *ssd, const bool *want,
                              const struct buffer_entry *e)
{
    return !want || want[e->ruhid * ssd->nrg + e->rgid];
}

/*
 * Write the oldest pages of the write buffer to the media, at most @budget
 * of them, or all with 0, of the (handle, group) pairs @want names, or of
 * all with NULL. Each goes to the active unit of the handle and group its
 * last write placed it with, so no unit takes another handle's pages. A
 * page whose handle has no unit in its group, and no free one, stays held;
 * the write-back goes on with the pages of the other groups. Returns the
 * modelled time of the programs.
 */
static uint64_t fdp_buffer_destage_some(struct ssd *ssd, int budget,
                                        uint64_t stime, const bool *want)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t pg = (uint64_t)spp->secsz * spp->secs_per_pg;
    uint64_t curlat, maxlat = 0;
    g_autofree bool *blocked = g_new0(bool, ssd->nrg);
    struct buffer_entry *e, *next;
    int done = 0;

    for (e = QTAILQ_FIRST(&ssd->write_buffer);
         e && (budget <= 0 || done < budget); e = next) {
        FemuRuHandle *ruh;

        if (blocked[e->rgid] || !fdp_buffer_wanted(ssd, want, e)) {
            next = QTAILQ_NEXT(e, b_entry);
            continue;
        }
        ruh = &ssd->ruhs[e->ruhid];
        fdp_gc_until_clear(ssd, e->rgid, e->ruhid);
        /* the entry after this one, once collection has run */
        next = QTAILQ_NEXT(e, b_entry);
        if (!fdp_ruh_ready(ssd, ruh, e->rgid)) {
            /* the group is out of room; later pages of it wait too */
            blocked[e->rgid] = true;
            continue;
        }
        if (ssd->cmt.capacity) {
            curlat = cmt_touch(ssd, e->lpn, stime, true);
            maxlat = MAX(maxlat, curlat);
        }
        curlat = fdp_program_page(ssd, &ssd->rg[e->rgid], ruh, e->lpn, stime,
                                  NULL, 0, 0, e->written);
        maxlat = MAX(maxlat, curlat);
        nvme_fdp_eg_add(&ssd->n->subsys->endgrp,
                        ssd->n->subsys->endgrp.fdp.mbmw, pg);
        nvme_fdp_stat_inc(&ruh->mbmw, pg);
        nvme_fdp_stat_inc(&ruh->ruh->mbmw, pg);
        ssd_buffer_discard(ssd, e->lpn);
        done++;
    }
    return maxlat;
}

uint64_t fdp_buffer_destage(struct ssd *ssd, int budget, uint64_t stime)
{
    return fdp_buffer_destage_some(ssd, budget, stime, NULL);
}

/*
 * Before RUH Update @req, write back the held pages of the (handle, group)
 * pairs it names: data written before the update belongs in the units the
 * handles reference until it (Base 2.3, 7.4.1.1). Pages of other pairs may
 * stay. Returns the modelled time; *@held is true when a named pair still
 * has a held page.
 */
uint64_t fdp_buffer_destage_update(struct ssd *ssd, NvmeRequest *req,
                                   bool *held)
{
    NvmeNamespace *ns = req->ns;
    g_autofree bool *want = g_new0(bool, ssd->nruhs * ssd->nrg);
    struct buffer_entry *e;
    uint64_t lat;

    for (uint32_t i = 0; i < req->nr_fdp_pids; i++) {
        uint16_t ph, rg;

        /* the poller refused the command if any of these was invalid */
        if (nvme_parse_pid(ns, req->fdp_pids[i], &ph, &rg)) {
            want[ns->fdp.phs[ph] * ssd->nrg + rg] = true;
        }
    }
    lat = fdp_buffer_destage_some(ssd, 0, req->stime, want);
    *held = false;
    QTAILQ_FOREACH(e, &ssd->write_buffer, b_entry) {
        *held |= fdp_buffer_wanted(ssd, want, e);
    }
    return lat;
}

/*
 * The bytes of blocks [@slba, @slba + @nlb) of @req that lie in the first
 * @pages pages the write reached: what the host wrote, for HBMW. A write
 * that covers part of a page counts its own blocks, not the whole page.
 */
static uint64_t fdp_host_bytes(struct ssd *ssd, NvmeRequest *req,
                               uint64_t slba, uint64_t nlb, uint64_t pages)
{
    uint64_t pg = (uint64_t)ssd->sp.secsz * ssd->sp.secs_per_pg;
    uint8_t lbads = req->ns ? req->ns->lbaf.lbads : BDRV_SECTOR_BITS;
    uint64_t beg = ssd_lba_byte_offset(ssd, req, slba);
    uint64_t end = MIN(beg + (nlb << lbads), (beg / pg + pages) * pg);

    return end > beg ? end - beg : 0;
}

/*
 * Accept a placed write into the write buffer. Each page keeps the handle
 * and group of this write, and the pieces it covers; the page goes to that
 * handle's unit when it is written back. Pages past the watermark first
 * write back a batch of the oldest ones, as without FDP. Host bytes count
 * here, media bytes when the page reaches the media.
 */
static uint64_t fdp_buffered_write(struct ssd *ssd, NvmeRequest *req)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t pg = (uint64_t)spp->secsz * spp->secs_per_pg;
    uint64_t per = pg >> FDP_WRITTEN_SHIFT;
    uint64_t start_lpn, end_lpn, lpn;
    uint64_t curlat, maxlat = 0;
    uint64_t passes, accepted = 0, direct = 0;
    uint64_t host;
    uint16_t rgid, ruhid;
    bool full = false;
    int batch = ssd_buffer_batch(ssd);

    ssd_lpn_range(ssd, req, req->slba, req->nlb, &start_lpn, &end_lpn);
    ssd_count_partial_pages(ssd, req, req->slba, req->nlb);
    fdp_place(ssd, req, &rgid, &ruhid);
    if (end_lpn >= spp->tt_pgs) {
        ftl_err("write past device geometry: end_lpn=%" PRIu64 " tt_pgs=%d\n",
                end_lpn, spp->tt_pgs);
        req->status = NVME_LBA_RANGE | NVME_DNR;
        return 0;
    }

    passes = ssd->gc_stall_passes;
    fdp_gc_until_clear(ssd, rgid, ruhid);
    fdp_do_read_reclaim(ssd);

    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        struct buffer_entry *e;
        uint64_t b, end;
        bool held;

        /*
         * Admission per page, so a request larger than the buffer cannot
         * push it past its size. A write-back that frees nothing means the
         * handles it serves have no room: tell the host.
         */
        if (!ssd_buffer_hit(ssd, lpn) && ssd_buffer_at_watermark(ssd)) {
            full = true;
            curlat = fdp_buffer_destage(ssd, batch, req->stime);
            maxlat = MAX(maxlat, curlat);
        }
        /*
         * The held pages are all of groups with no room. The page then
         * goes to its own unit at once, when its group has room, so a full
         * group does not stop writes to the others.
         */
        if (!ssd_buffer_hit(ssd, lpn) && ssd_buffer_at_watermark(ssd)) {
            fdp_gc_until_clear(ssd, rgid, ruhid);
            if (!fdp_ruh_ready(ssd, &ssd->ruhs[ruhid], rgid)) {
                req->status = NVME_CAP_EXCEEDED | NVME_DNR;
                break;
            }
            if (ssd->cmt.capacity) {
                curlat = cmt_touch(ssd, lpn, req->stime, true);
                maxlat = MAX(maxlat, curlat);
            }
            curlat = fdp_program_page(ssd, &ssd->rg[rgid], &ssd->ruhs[ruhid],
                                      lpn, req->stime, req, req->slba,
                                      req->nlb, NULL);
            maxlat = MAX(maxlat, curlat);
            direct++;
            accepted++;
            continue;
        }

        e = ssd_buffer_insert(ssd, lpn, &held);
        if (held) {
            spp->write_hit_cnt++;
        }
        e->ruhid = ruhid;
        e->rgid = rgid;
        if (ssd->fdp_written) {
            if (!e->written) {
                e->written = bitmap_new(per);
            }
            fdp_page_pieces(ssd, req, req->slba, req->nlb, lpn, &b, &end);
            if (b < end) {
                bitmap_set(e->written, b - lpn * per, end - b);
            }
        }
        accepted++;
    }

    ssd->host_write_pages += accepted;
    spp->write_cnt += accepted;
    req->xfer_bytes = accepted * pg;
    host = fdp_host_bytes(ssd, req, req->slba, req->nlb, accepted);
    nvme_fdp_eg_add(&ssd->n->subsys->endgrp,
                    ssd->n->subsys->endgrp.fdp.hbmw, host);
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].hbmw, host);
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].ruh->hbmw, host);
    /* pages programmed past the buffer reach the media now */
    nvme_fdp_eg_add(&ssd->n->subsys->endgrp,
                    ssd->n->subsys->endgrp.fdp.mbmw, direct * pg);
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].mbmw, direct * pg);
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].ruh->mbmw, direct * pg);
    ssd->buffer_full_destages += full;

    /* accepting into DRAM is not free, even though it is not a program */
    maxlat = MAX(maxlat, ssd_buffer_hit_lat(ssd));
    ssd_note_gc_stall(ssd, passes);
    return maxlat;
}

static bool fdp_ru_unwritten(FemuReclaimUnit *ru)
{
    struct write_pointer *wpp = ru->ssd_wptr;

    return wpp->curline == ru->lines[0] && wpp->ch == wpp->ch0 &&
           wpp->lun == wpp->lun0 && !wpp->pl && !wpp->pg;
}

/*
 * ssd_fdp_update_ruhs - Reclaim Unit Handle Update: each named handle moves to
 * a fresh unit and the one it leaves is collected like any other. A unit that
 * was never written is as good as a fresh one and is kept. If collection
 * cannot free a unit either, the command fails rather than claim a move.
 */
void ssd_fdp_update_ruhs(FemuCtrl *n, NvmeRequest *req)
{
    NvmeNamespace *ns = req->ns;
    struct ssd *ssd = ns->ssd;

    for (uint32_t i = 0; i < req->nr_fdp_pids; i++) {
        uint16_t pid = req->fdp_pids[i];
        uint16_t ph, rgid;
        FemuRuHandle *ruh;
        FemuReclaimUnit *old, *fresh;

        /*
         * After the end of life no unit takes data, and a move would take a
         * reserve unit from the writes in flight. An update the poller
         * passed before the media went read-only, or whose own collection
         * ended its life, fails as one with no empty unit to give. The
         * handles it moved before that stay moved (Base 2.3, 7.4.1.1).
         */
        if (ssd->media_ro) {
            req->status = NVME_CAP_EXCEEDED | NVME_DNR;
            return;
        }

        /* the poller refused the command if any of these was invalid */
        nvme_parse_pid(ns, pid, &ph, &rgid);
        ruh = &ssd->ruhs[ns->fdp.phs[ph]];
        old = ruh->rus[rgid];
        /* an empty unit stays, so the handle does not move: no event */
        if (old && fdp_ru_unwritten(old)) {
            continue;
        }

        /*
         * Collect first, as a write does. Taking a free unit below the
         * forced watermark leaves collection none to open a unit to move
         * pages into, and then no write can get a unit either. Collection
         * into an initially isolated handle can fill @old and move the
         * handle on, which does the update. @old was full then, and that
         * move logged event 81h; a later pass may have erased @old, so its
         * room now says nothing about the move.
         */
        fdp_gc_until_clear(ssd, rgid, ruh->ruhid);
        if (ssd->media_ro) {
            req->status = NVME_CAP_EXCEEDED | NVME_DNR;
            return;
        }
        /*
         * A handle whose last unit filled with nothing free to follow it
         * references no unit, which is not an empty one: give it one.
         */
        if (!old || ruh->rus[rgid] != old) {
            if (!fdp_ruh_ready(ssd, ruh, rgid)) {
                req->status = NVME_CAP_EXCEEDED | NVME_DNR;
                return;
            }
            continue;
        }

        fresh = fdp_get_new_ru(ssd, rgid, ruh->ruhid);
        if (!fresh && do_gc_fdp_style(ssd, rgid, ruh->ruhid, true) != -1) {
            if (ssd->media_ro) {
                req->status = NVME_CAP_EXCEEDED | NVME_DNR;
                return;
            }
            /*
             * The last handle of an Initially Isolated configuration is also
             * where collection writes. Collection can fill @old and retire
             * it; retiring it again would put it on a list twice.
             */
            if (ruh->rus[rgid] != old) {
                nvme_fdp_note_ru_left(n, ns, pid, old->nvme_ru);
                if (ruh->rus[rgid]) {
                    continue;
                }
                fresh = fdp_get_new_ru(ssd, rgid, ruh->ruhid);
                if (!fresh) {
                    req->status = NVME_CAP_EXCEEDED | NVME_DNR;
                    return;
                }
                fdp_set_active(ruh, rgid, fresh);
                continue;
            }
            fresh = fdp_get_new_ru(ssd, rgid, ruh->ruhid);
        }
        if (!fresh) {
            req->status = NVME_CAP_EXCEEDED | NVME_DNR;
            return;
        }
        nvme_fdp_note_ru_left(n, ns, pid, old->nvme_ru);
        fdp_retire_ru(ssd, old);
        fdp_set_active(ruh, rgid, fresh);
    }
}

static uint64_t ssd_stream_write(FemuCtrl *n, struct ssd *ssd,
                                NvmeRequest *req)
{
    uint64_t start_lpn, end_lpn;

    ssd_lpn_range(ssd, req, req->slba, req->nlb, &start_lpn, &end_lpn);
    ssd_count_partial_pages(ssd, req, req->slba, req->nlb);

    return ssd_stream_write_lpns(n, ssd, req, req->slba, req->nlb, start_lpn,
                                 end_lpn);
}

/*
 * Charge what a placed write of blocks [@slba, @slba + @nlb) actually
 * programmed to the endurance group and to the handle its placement
 * identifier selects: the host's blocks to HBMW, the pages to MBMW.
 */
static void fdp_count_write(NvmeNamespace *ns, struct ssd *ssd,
                            NvmeRequest *req, uint64_t slba, uint64_t nlb)
{
    uint64_t pg = (uint64_t)ssd->sp.secsz * ssd->sp.secs_per_pg;
    uint64_t data_bytes = req->xfer_bytes;
    uint64_t host_bytes;
    uint16_t ph, rg, ruhid;

    if (!data_bytes) {
        return;
    }
    host_bytes = fdp_host_bytes(ssd, req, slba, nlb, data_bytes / pg);
    if (req->fdp_dtype != NVME_DIRECTIVE_DATA_PLACEMENT ||
        !nvme_parse_pid(ns, req->fdp_dspec, &ph, &rg)) {
        ph = 0;
    }
    ruhid = ns->fdp.phs[ph];

    nvme_fdp_eg_add(ns->endgrp, ns->endgrp->fdp.hbmw, host_bytes);
    nvme_fdp_eg_add(ns->endgrp, ns->endgrp->fdp.mbmw, data_bytes);
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].hbmw, host_bytes);
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].ruh->hbmw, host_bytes);
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].mbmw, data_bytes);
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].ruh->mbmw, data_bytes);
}

/*
 * nvme_do_write_fdp - top-level FDP write: stats + stream write
 */
uint64_t nvme_do_write_fdp(FemuCtrl *n, NvmeRequest *req, uint64_t slba,
                           uint32_t nlb)
{
    NvmeNamespace *ns = req->ns;
    struct ssd *ssd = ns->ssd;
    const NvmeRwCmd *rw = (const NvmeRwCmd *)&req->cmd;
    uint64_t lat;

    /* Write and Copy; Force Unit Access goes to the media at once */
    if (ssd_buffer_enabled(ssd) && !(le16_to_cpu(rw->control) & NVME_RW_FUA)) {
        return fdp_buffered_write(ssd, req);
    }

    lat = ssd_stream_write(n, ssd, req);
    /* with a buffer, C0h counts every write page the buffer saw go past */
    if (ssd->sp.buffer_size > 0) {
        ssd->sp.write_cnt += req->xfer_bytes /
                             ((uint64_t)ssd->sp.secsz * ssd->sp.secs_per_pg);
    }

    /*
     * Charged from what the write actually programmed, after the fact: a
     * write the device had no room for must not add its length to either
     * total, or the reported amplification falls below one.
     */
    fdp_count_write(ns, ssd, req, slba, nlb);

    return lat;
}

/* ========== FDP Init Functions ========== */

/*
 * femu_fdp_init_ru_mgmt - initialize RU management for a reclaim group
 */
static void femu_fdp_init_ru_mgmt(struct ssd *ssd, FemuReclaimGroup *rg)
{
    struct ru_mgmt *rm = rg->ru_mgmt;

    rm->tt_rus = rg->tt_nru;
    rm->free_ru_cnt = rg->tt_nru;
    rm->custom_gc_threshold = 0;

    /* default GC strategy */
    rm->mgmt_type = GC_GLOBAL_GREEDY;

    QTAILQ_INIT(&rm->free_ru_list);
    QTAILQ_INIT(&rm->full_ru_list);

    rm->victim_ru_pq = pqueue_init(rm->tt_rus, victim_ru_cmp_pri,
                                   victim_ru_get_pri, victim_ru_set_pri,
                                   victim_ru_get_pos, victim_ru_set_pos);

    rm->victim_ru_cb = pqueue_init(rm->tt_rus, victim_ru_cmp_pri_by_cb,
                                   victim_ru_get_pri_by_cb,
                                   victim_ru_set_pri_by_cb,
                                   victim_ru_get_pos, victim_ru_set_pos);
}

/*
 * femu_fdp_init_ssd_reclaim_unit - initialize one RU with lines and wptr.
 * With one group the unit takes free lines of the whole device. With more,
 * it takes the lines of its group with the block ids in @ids: one block of
 * each plane of each die of the group.
 */
static void femu_fdp_init_ssd_reclaim_unit(struct ssd *ssd,
                                           FemuReclaimUnit *femu_ru,
                                           int rgidx, int index,
                                           const int *ids)
{
    struct ssdparams *spp = &ssd->sp;
    FemuReclaimGroup *rg = &ssd->rg[rgidx];
    struct write_pointer *wpp;

    femu_ru->n_lines = spp->lines_per_ru;
    femu_ru->vpc = 0;
    femu_ru->ipc = 0;
    femu_ru->pos = 0;
    femu_ru->ruh_pos = 0;     /* not yet in any victim pqueue */
    femu_ru->ssd_wptr = g_malloc0(sizeof(struct write_pointer));
    femu_ru->npages = spp->lines_per_ru * (spp->pgs_per_line / ssd->nrg);

    wpp = femu_ru->ssd_wptr;
    femu_ru->lines = g_malloc0(femu_ru->n_lines * sizeof(struct line *));
    for (int i = 0; i < femu_ru->n_lines; i++) {
        if (ssd->rg_lines) {
            femu_ru->lines[i] = &ssd->rg_lines[rgidx * spp->blks_per_pl +
                                               ids[index * femu_ru->n_lines +
                                                   i]];
        } else {
            femu_ru->lines[i] = get_next_free_line(ssd);
        }
        if (!femu_ru->lines[i]) {
            ftl_err("FDP: no free line for RU %d (rg %d, line %d/%d)\n",
                    index, rgidx, i, femu_ru->n_lines);
            abort();
        }
        femu_ru->lines[i]->my_ru = femu_ru;
    }
    /* the pointer steps over the dies of the group only */
    wpp->ch0 = rg->ch0;
    wpp->nch = rg->nch;
    wpp->lun0 = rg->lun0;
    wpp->nlun = rg->nlun;
    ssd_wp_reset(wpp, femu_ru->lines[0]);
}

/*
 * The dies of reclaim group @g of @nrg: in the flat order ch x luns_per_ch +
 * lun, the dies [g x D / nrg, (g + 1) x D / nrg). Realize checked that they
 * form whole channels, or LUNs of one channel.
 */
static void femu_fdp_rg_window(struct ssdparams *spp, int nrg, int g,
                               FemuReclaimGroup *rg)
{
    int per = spp->nchs * spp->luns_per_ch / nrg;
    int d0 = g * per;

    rg->ch0 = d0 / spp->luns_per_ch;
    rg->lun0 = d0 % spp->luns_per_ch;
    if (per >= spp->luns_per_ch) {
        rg->nch = per / spp->luns_per_ch;
        rg->nlun = spp->luns_per_ch;
    } else {
        rg->nch = 1;
        rg->nlun = per;
    }
}

/*
 * femu_fdp_ssd_init_reclaim_group - init all RGs and their RU pools
 */
/*
 * The reclaim unit strategy under FDP. gc_policy names the line policies;
 * each has a unit version, and realize refuses it together with a
 * gc_strategy other than 0. Unset or greedy leaves gc_strategy in charge.
 */
static int femu_fdp_gc_strategy(const BbCtrlParams *p)
{
    static const struct {
        const char *name;
        int strategy;
    } map[] = {
        { "cost-benefit", GC_GLOBAL_CB },
        { "random", GC_GLOBAL_RAND },
        { "fifo", GC_GLOBAL_FIFO },
        { "d-choice", GC_GLOBAL_DCHOICE },
    };

    for (size_t i = 0; p->gc_policy && i < ARRAY_SIZE(map); i++) {
        if (!strcmp(p->gc_policy, map[i].name)) {
            return map[i].strategy;
        }
    }
    return p->gc_strategy;
}

void femu_fdp_ssd_init_reclaim_group(FemuCtrl *n, struct ssd *ssd)
{
    NvmeSubsystem *subsys = n->subsys;
    struct ssdparams *spp = &ssd->sp;
    uint64_t rgs = subsys->endgrp.fdp.nrg;
    FemuReclaimGroup *rg;
    /* units per group: every group has a unit per block id of its dies */
    uint64_t tt_nru = spp->total_ru_cnt;
    g_autofree int *ids = NULL;

    ftl_assert(tt_nru > 0);

    ssd->rg = g_malloc0(rgs * sizeof(FemuReclaimGroup));
    ssd->nrg = rgs;
    ssd->rus = g_malloc0(rgs * sizeof(FemuReclaimUnit *));
    ssd->rg_dies = spp->nchs * spp->luns_per_ch / rgs;

    for (int i = 0; i < (int)rgs; i++) {
        rg = &ssd->rg[i];
        rg->rgidx = i;
        rg->tt_nru = tt_nru;
        femu_fdp_rg_window(spp, rgs, i, rg);
        ssd->rus[i] = g_malloc0(tt_nru * sizeof(FemuReclaimUnit));
        rg->rus = ssd->rus[i];
        rg->ru_mgmt = g_malloc0(sizeof(struct ru_mgmt));
        femu_fdp_init_ru_mgmt(ssd, rg);
        fdp_log("Allocated %lu RUs to rg[%d]\n", tt_nru, i);
    }

    /*
     * With more than one group, the lines of the device give the block ids
     * of the units, in the order line mode would hand them out, and each
     * group gets a line of its own for each id.
     */
    if (rgs > 1) {
        ids = g_new(int, tt_nru * spp->lines_per_ru);
        for (uint64_t j = 0; j < tt_nru * spp->lines_per_ru; j++) {
            struct line *l = get_next_free_line(ssd);

            if (!l) {
                ftl_err("FDP: no free line for block id %" PRIu64 "\n", j);
                abort();
            }
            ids[j] = l->id;
        }
        ssd->rg_lines = g_new0(struct line, rgs * spp->blks_per_pl);
        for (uint64_t g = 0; g < rgs; g++) {
            for (int b = 0; b < spp->blks_per_pl; b++) {
                ssd->rg_lines[g * spp->blks_per_pl + b].id = b;
                ssd->rg_lines[g * spp->blks_per_pl + b].rg = g;
            }
        }
    }

    /* link NvmeReclaimUnit pointers and init each SSD-level RU */
    NvmeReclaimUnit **russ = subsys->endgrp.fdp.rus;
    if (russ) {
        for (int i = 0; i < (int)rgs; i++) {
            rg = &ssd->rg[i];
            rg->ru_mgmt->free_ru_cnt = 0;
            for (int j = 0; j < rg->tt_nru; j++) {
                rg->rus[j].rgidx = i;
                rg->rus[j].nvme_ru = &russ[i][j];
                rg->rus[j].ruidx = j;
                femu_fdp_init_ssd_reclaim_unit(ssd, &rg->rus[j], i, j, ids);
                QTAILQ_INSERT_TAIL(&rg->ru_mgmt->free_ru_list,
                                   &rg->rus[j], entry);
                rg->ru_mgmt->free_ru_cnt++;
            }
            rg->ru_mgmt->gc_thres_pcent =
                n->bb_params.gc_thres_pcent / 100.0;
            rg->ru_mgmt->gc_thres_pcent_high =
                n->bb_params.gc_thres_pcent_high / 100.0;
            rg->ru_mgmt->gc_thres_rus =
                (uint64_t)((1 - rg->ru_mgmt->gc_thres_pcent) *
                           rg->tt_nru);
            rg->ru_mgmt->gc_thres_rus_high =
                bb_fdp_forced_units(n, rg->tt_nru);
            ftl_log("rg[%d] gc threshold (%d%%) %lu/%d RU\n",
                    i, n->bb_params.gc_thres_pcent,
                    rg->ru_mgmt->gc_thres_rus, rg->tt_nru);
            ftl_log("rg[%d] gc threshold_high (%d%%) %lu/%d RU\n",
                    i, n->bb_params.gc_thres_pcent_high,
                    rg->ru_mgmt->gc_thres_rus_high, rg->tt_nru);

            /* apply configured GC strategy */
            rg->ru_mgmt->mgmt_type = femu_fdp_gc_strategy(&n->bb_params);
            ftl_log("rg[%d] gc strategy=%d\n", i,
                    rg->ru_mgmt->mgmt_type);
        }
    }
}

/*
 * femu_fdp_ssd_init_ru_handles - init a FemuRuHandle for every reclaim unit
 * handle of the endurance group, in ID order. The handles belong to the
 * group, not to a namespace: a namespace's list may name any subset of them,
 * and a handle no list names still holds its units.
 */
void femu_fdp_ssd_init_ru_handles(FemuCtrl *n, struct ssd *ssd)
{
    NvmeNamespace *ns = &n->namespaces[0];
    uint64_t bits;
    NvmeSubsystem *subsys = n->subsys;
    NvmeEnduranceGroup *endgrp = &subsys->endgrp;
    uint16_t nruh = subsys->params.fdp.nruh;

    ssd->ruhs = g_malloc0(nruh * sizeof(FemuRuHandle));
    ssd->nruhs = nruh;
    /*
     * The bitmap covers the FTL space up to the end of the last namespace,
     * which no write passes. A piece must not straddle two pages, or
     * unmapping one page would forget a block of the next, and the bitmap
     * calls take a long.
     * Without the bitmap, event 80h reports no count.
     */
    bits = MIN((uint64_t)ssd->sp.tt_pgs * ssd->sp.secsz * ssd->sp.secs_per_pg,
               bb_ftl_bytes(n, ns)) >> FDP_WRITTEN_SHIFT;
    if (!(((uint64_t)ssd->sp.secsz * ssd->sp.secs_per_pg) %
          (1 << FDP_WRITTEN_SHIFT)) && bits <= LONG_MAX) {
        ssd->fdp_written_bits = bits;
        ssd->fdp_written = bitmap_new(bits);
    }

    for (uint16_t i = 0; i < nruh; i++) {
        NvmeRuHandle *nvme_ruh = &endgrp->fdp.ruhs[i];

        ssd->ruhs[i].ruh = nvme_ruh;
        ssd->ruhs[i].ruh_type = nvme_ruh->ruht;
        ssd->ruhs[i].ruhid = i;
        ssd->ruhs[i].ruh_live_pages_cnt = 0;
        ssd->ruhs[i].ru_in_use_cnt = 0;
        ssd->ruhs[i].hbmw = 0;
        ssd->ruhs[i].mbmw = 0;
        ssd->ruhs[i].mbe = 0;

        /* PI type RUHs get their own victim queue in each group */
        if (nvme_ruh->ruht == NVME_RUHT_PERSISTENTLY_ISOLATED) {
            ssd->ruhs[i].ru_mgmt = g_new0(struct ru_mgmt, endgrp->fdp.nrg);
            for (int j = 0; j < (int)endgrp->fdp.nrg; j++) {
                struct ru_mgmt *hm = &ssd->ruhs[i].ru_mgmt[j];

                hm->mgmt_type = femu_fdp_gc_strategy(&n->bb_params);
                hm->custom_gc_threshold = 0;
                QTAILQ_INIT(&hm->free_ru_list);
                QTAILQ_INIT(&hm->full_ru_list);
                /*
                 * Per-RUH queues index via ruh_pos (see victim_ru_*_pos_ruh)
                 * so they do not alias the per-RG queue's pos (issue #189).
                 */
                hm->victim_ru_pq =
                    pqueue_init(ssd->rg[j].tt_nru, victim_ru_cmp_pri,
                                victim_ru_get_pri, victim_ru_set_pri,
                                victim_ru_get_pos_ruh, victim_ru_set_pos_ruh);
            }
        }

        /* an active unit in each group; collection units come on demand */
        ssd->ruhs[i].rus = g_new0(FemuReclaimUnit *, endgrp->fdp.nrg);
        ssd->ruhs[i].gc_rus = g_new0(FemuReclaimUnit *, endgrp->fdp.nrg);
        for (int j = 0; j < (int)endgrp->fdp.nrg; j++) {
            ssd->ruhs[i].rus[j] = fdp_get_new_ru(ssd, j, i);
            ssd->ruhs[i].rus[j]->ruh = &ssd->ruhs[i];
            ssd->ruhs[i].ruh->rus[j] = ssd->ruhs[i].rus[j]->nvme_ru;
        }

        ftl_log("FDP: ruh[%d] type=%d, active ru=%d (line=%d)\n",
                i, ssd->ruhs[i].ruh_type, ssd->ruhs[i].rus[0]->ruidx,
                ssd->ruhs[i].rus[0]->lines[0]->id);
    }
}

/*
 * eol_read_only: hold fdp_eol_reserve erased units of each reclaim group off
 * its free list. Realize counted them out of the group's capacity. They
 * join the free list when the media goes read-only, for the writes in
 * flight then (ssd_fdp_release_eol_reserve()).
 */
void femu_fdp_ssd_init_eol_reserve(struct ssd *ssd)
{
    for (uint64_t g = 0; g < ssd->nrg; g++) {
        struct ru_mgmt *rm = ssd->rg[g].ru_mgmt;

        for (uint64_t k = 0; k < ssd->fdp_eol_reserve; k++) {
            FemuReclaimUnit *ru = QTAILQ_LAST(&rm->free_ru_list);

            if (!ru) {
                ftl_err("FDP: no free unit for the end-of-life reserve\n");
                abort();
            }
            QTAILQ_REMOVE(&rm->free_ru_list, ru, entry);
            rm->free_ru_cnt--;
            ru->reserve = true;
        }
    }
}

/* The end of life: each group's reserve units become free units. */
void ssd_fdp_release_eol_reserve(struct ssd *ssd)
{
    for (uint64_t g = 0; g < ssd->nrg; g++) {
        struct ru_mgmt *rm = ssd->rg[g].ru_mgmt;

        for (uint64_t j = 0; j < ssd->rg[g].tt_nru; j++) {
            FemuReclaimUnit *ru = &ssd->rg[g].rus[j];

            if (ru->reserve) {
                ru->reserve = false;
                QTAILQ_INSERT_TAIL(&rm->free_ru_list, ru, entry);
                rm->free_ru_cnt++;
            }
        }
    }
}

/*
 * ssd_init_fdp_params - compute FDP-specific SSD parameters
 */
void ssd_init_fdp_params(struct ssdparams *spp, FemuCtrl *n)
{
    NvmeSubsystem *subsys = n->subsys;
    NvmeEnduranceGroup *endgrp = &subsys->endgrp;
    uint64_t runs = endgrp->fdp.runs;

    /* lines_per_ru: how many lines (superblocks) per reclaim unit */
    spp->lines_per_ru = 1; /* M1: 1 line per RU for simplicity */

    /*
     * Compute total RU count from device geometry:
     * total_ru = tt_lines / lines_per_ru
     * Clamp to endgrp->fdp.nru to avoid overflowing NvmeReclaimUnit array
     * allocated in nvme_subsys_setup_fdp().
     */
    spp->total_ru_cnt = spp->tt_lines / spp->lines_per_ru;

    if (endgrp->fdp.nru == 0) {
        endgrp->fdp.nru = spp->total_ru_cnt;
    } else if (spp->total_ru_cnt > (int)endgrp->fdp.nru) {
        ftl_log("FDP: clamping total_ru from %d to %lu (endgrp.nru)\n",
                spp->total_ru_cnt, (unsigned long)endgrp->fdp.nru);
        spp->total_ru_cnt = endgrp->fdp.nru;
    }

    ftl_log("FDP params: lines_per_ru=%d, total_ru=%d, runs=%lu\n",
            spp->lines_per_ru, spp->total_ru_cnt, (unsigned long)runs);
}

/*
 * ssd_reset_maptbl - clear entire mapping table (used by FDP trim)
 */
static void ssd_reset_maptbl(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;

    for (int i = 0; i < spp->tt_pgs; i++) {
        ssd->maptbl[i].ppa = UNMAPPED_PPA;
        ssd->rmap[i] = INVALID_LPN;
    }
    if (ssd->fdp_written) {
        bitmap_zero(ssd->fdp_written, ssd->fdp_written_bits);
    }
}

/*
 * Deallocate [start_lpn, end_lpn] under FDP: invalidate through the FDP path so
 * the reclaim unit's valid/invalid counts and victim state stay right, then
 * unmap. Shared by DSM Deallocate and Write Zeroes with the Deallocate bit.
 */
static int ssd_deallocate_fdp_lpns(struct ssd *ssd, uint64_t start_lpn,
                                   uint64_t end_lpn, int *already_invalid)
{
    uint64_t per = ((uint64_t)ssd->sp.secsz * ssd->sp.secs_per_pg) >>
                   FDP_WRITTEN_SHIFT;
    int deallocated = 0;
    uint64_t lpn;

    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        struct ppa ppa = get_maptbl_ent(ssd, lpn);

        /*
         * A held copy goes first: a page the buffer holds may have no
         * mapping yet, and its write-back would bring the data back.
         */
        ssd_buffer_discard(ssd, lpn);

        /* the whole page goes, so none of its blocks holds data now */
        if (ssd->fdp_written && lpn * per < ssd->fdp_written_bits) {
            bitmap_clear(ssd->fdp_written, lpn * per,
                         MIN(per, ssd->fdp_written_bits - lpn * per));
        }

        if (!mapped_ppa(&ppa) || !valid_ppa(ssd, &ppa)) {
            (*already_invalid)++;
            continue;
        }
        mark_page_invalid_fdp(ssd, &ppa);
        set_rmap_ent(ssd, INVALID_LPN, &ppa);
        ppa.ppa = UNMAPPED_PPA;
        set_maptbl_ent(ssd, lpn, &ppa);
        rcache_invalidate(ssd, lpn);
        deallocated++;
    }

    return deallocated;
}

/*
 * Deallocate every page of @ns under FDP; see bbssd_deallocate_all(). The
 * other namespaces of the controller place into the same FTL, so only the
 * pages of this one's slice go. A Format resets the RUAMW of its handles' units
 * to a full unit, but the units keep the pages already programmed, so set
 * RUAMW from them again, in the block size the Format chose.
 */
void ssd_deallocate_fdp_ns(struct ssd *ssd, NvmeNamespace *ns)
{
    uint64_t pg = (uint64_t)ssd->sp.secsz * ssd->sp.secs_per_pg;
    uint64_t base = ssd_ns_byte_base(ssd, ns);
    uint64_t last = MIN(DIV_ROUND_UP(base + ns->size, pg),
                        (uint64_t)ssd->sp.tt_pgs);
    int already_invalid = 0;

    if (last > base / pg) {
        ssd_deallocate_fdp_lpns(ssd, base / pg, last - 1, &already_invalid);
    }
    for (uint64_t g = 0; g < ssd->nrg; g++) {
        for (uint64_t j = 0; j < ssd->rg[g].tt_nru; j++) {
            fdp_ru_sync_ruamw(ssd, &ssd->rg[g].rus[j]);
        }
    }
}

/*
 * ssd_trim_fdp_range - FDP DSM deallocate (default). Invalidate only the logical
 * pages covered by the requested LBA ranges: mark each mapped page invalid via
 * the FDP path (which decrements RU/line vpc and moves the RU onto the victim
 * queue so GC reclaims it), clear the reverse map, and unmap the L2P entry.
 * Erase is left to GC. This matches a normal SSD's deallocate: a host TRIM of a
 * few LBAs must not disturb any other logical data.
 */
static void ssd_trim_fdp_range(FemuCtrl *n, NvmeRequest *req)
{
    struct ssd *ssd = req->ns->ssd;
    struct ssdparams *spp = &ssd->sp;
    NvmeDsmRange *ranges = req->dsm_ranges;
    int nr_ranges = req->dsm_nr_ranges;
    int total_trimmed_pages = 0;
    int total_already_invalid = 0;

    if (!ranges || nr_ranges <= 0) {
        return;
    }

    for (int range_idx = 0; range_idx < nr_ranges; range_idx++) {
        uint64_t start_lpn, end_lpn;

        ssd_lpn_range(ssd, req, le64_to_cpu(ranges[range_idx].slba),
                      le32_to_cpu(ranges[range_idx].nlb), &start_lpn, &end_lpn);

        if (end_lpn >= spp->tt_pgs) {
            ftl_err("FDP TRIM: range %d exceeds capacity (end_lpn=%lu "
                    "tt_pgs=%d)\n", range_idx, end_lpn, spp->tt_pgs);
            continue;
        }

        total_trimmed_pages += ssd_deallocate_fdp_lpns(ssd, start_lpn, end_lpn,
                                                      &total_already_invalid);
    }

    ftl_debug("FDP TRIM: %d pages trimmed, %d already invalid across %d ranges\n",
              total_trimmed_pages, total_already_invalid, nr_ranges);
}

/*
 * FDP Write Zeroes with the Deallocate bit: the blocks become deallocated, so
 * the FTL owes the same unmap DSM Deallocate does. Without the bit they hold
 * written zeros instead and the mapping is left alone.
 */
uint64_t ssd_write_zeroes_fdp_style(FemuCtrl *n, NvmeRequest *req)
{
    struct ssd *ssd = req->ns->ssd;
    struct ssdparams *spp = &ssd->sp;
    const NvmeRwCmd *rw = (const NvmeRwCmd *)&req->cmd;
    uint64_t start_lpn, end_lpn;
    int already_invalid = 0;

    ssd_lpn_range(ssd, req, le64_to_cpu(rw->slba), le16_to_cpu(rw->nlb) + 1,
                  &start_lpn, &end_lpn);
    if (end_lpn >= spp->tt_pgs) {
        return 0;
    }

    /*
     * Without the deallocate bit the blocks hold written zeros, so the device
     * has to put them somewhere: program the range into the handle's reclaim
     * unit, as the non-placement path does, rather than return having neither
     * charged the media nor counted the pages.
     */
    if (!(le16_to_cpu(rw->control) & NVME_WZ_DEAC)) {
        uint64_t lat;

        ssd_count_partial_pages(ssd, req, le64_to_cpu(rw->slba),
                                le16_to_cpu(rw->nlb) + 1);
        lat = ssd_stream_write_lpns(n, ssd, req, le64_to_cpu(rw->slba),
                                    le16_to_cpu(rw->nlb) + 1, start_lpn,
                                    end_lpn);

        fdp_count_write(req->ns, ssd, req, le64_to_cpu(rw->slba),
                        le16_to_cpu(rw->nlb) + 1);
        return lat;
    }

    ssd_deallocate_fdp_lpns(ssd, start_lpn, end_lpn, &already_invalid);
    ssd_fdp_count_unprogrammed(n, req, le16_to_cpu(rw->nlb) + 1);

    return 0;
}

/*
 * Charge HBMW for @nlb blocks a command asked to write but the FTL does not
 * program: Write Zeroes with the Deallocate bit, and Write Uncorrectable. NVM
 * 1.2, 4.1.4.6 counts both commands, and HBMW is what the host asked to
 * write. No page reaches the media, so MBMW and RUAMW stay.
 */
void ssd_fdp_count_unprogrammed(FemuCtrl *n, NvmeRequest *req, uint64_t nlb)
{
    struct ssd *ssd = req->ns->ssd;
    uint64_t bytes = nlb << req->ns->lbaf.lbads;
    uint16_t rgid, ruhid;

    fdp_place(ssd, req, &rgid, &ruhid);
    nvme_fdp_eg_add(&n->subsys->endgrp, n->subsys->endgrp.fdp.hbmw, bytes);
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].hbmw, bytes);
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].ruh->hbmw, bytes);
}

/*
 * ssd_trim_fdp_reset_all - FDP DSM whole-device reset (opt-in via the
 * fdp_trim_erase_all device property, test only). Erases every block, drains all
 * reclaim units, resets all RUH state, and wipes the mapping table. This was the
 * original prototype behavior for a customized non-filesystem fio+trim sweep; it
 * is NOT how DSM-deallocate behaves on a real SSD and ignores the requested LBA
 * range, so it is off by default.
 */
static void ssd_trim_fdp_reset_all(FemuCtrl *n, NvmeRequest *req, uint64_t slba,
                                   uint32_t nlb)
{
    struct ssd *ssd = req->ns->ssd;
    struct ssdparams *spp = &ssd->sp;
    NvmeEnduranceGroup *endgrp = &n->subsys->endgrp;
    FemuReclaimUnit *v_ru;
    NvmeRuHandle *ruh;
    int rg_idx;

    /* erase all blocks */
    for (int ch = 0; ch < spp->nchs; ch++) {
        for (int lun = 0; lun < spp->luns_per_ch; lun++) {
            for (int blk = 0; blk < spp->blks_per_pl; blk++) {
                ssd_erase_lun_block(ssd, ch, lun, blk, spp->enable_gc_delay,
                                    0);
            }
        }
    }

    /* the pages the buffer holds go with everything else */
    while (QTAILQ_FIRST(&ssd->write_buffer)) {
        ssd_buffer_discard(ssd, QTAILQ_FIRST(&ssd->write_buffer)->lpn);
    }

    /* drain victim and full RU queues for all reclaim groups */
    for (rg_idx = 0; rg_idx < (int)ssd->nrg; rg_idx++) {
        struct ru_mgmt *rm = ssd->rg[rg_idx].ru_mgmt;

        while ((v_ru = pqueue_peek(fdp_victim_heap(rm))) != NULL) {
            fdp_victim_dequeue(ssd, v_ru);
            mark_ru_free(ssd, v_ru->rgidx, v_ru);
        }
        while ((v_ru = QTAILQ_FIRST(&rm->full_ru_list)) != NULL) {
            QTAILQ_REMOVE(&rm->full_ru_list, v_ru, entry);
            mark_ru_free(ssd, v_ru->rgidx, v_ru);
        }
    }

    /* reset active RUs and stats for each RUH across all RGs */
    ruh = endgrp->fdp.ruhs;
    for (int i = 0; i < (int)endgrp->fdp.nruh; i++, ruh++) {
        /* the group drain above took every unit off its handle's heaps too */
        for (rg_idx = 0; ssd->ruhs[i].ru_mgmt && rg_idx < (int)ssd->nrg;
             rg_idx++) {
            ftl_assert(pqueue_size(
                       ssd->ruhs[i].ru_mgmt[rg_idx].victim_ru_pq) == 0);
        }
        ruh->hbmw = 0;
        ruh->mbmw = 0;
        ruh->mbe = 0;
        ssd->ruhs[i].hbmw = 0;
        ssd->ruhs[i].mbmw = 0;
        ssd->ruhs[i].mbe = 0;
        /*
         * The collection and host frontiers of each group are on no queue
         * the drain above walks. Left as they were, they point at units this
         * reset has handed back, which the next allocation gives to another
         * handle to write into at the same time.
         */
        for (rg_idx = 0; rg_idx < (int)ssd->nrg; rg_idx++) {
            FemuReclaimUnit *gc = ssd->ruhs[i].gc_rus[rg_idx];
            FemuReclaimUnit *host = ssd->ruhs[i].rus[rg_idx];

            if (gc && gc != host) {
                mark_ru_free(ssd, gc->rgidx, gc);
            }
            if (host) {
                mark_ru_free(ssd, host->rgidx, host);
            }
            ssd->ruhs[i].gc_rus[rg_idx] = NULL;
            ssd->ruhs[i].rus[rg_idx] = NULL;
        }
        /* every unit was handed back above; count only the ones taken below */
        ssd->ruhs[i].ru_in_use_cnt = 0;
        for (rg_idx = 0; ssd->ruhs[i].ru_mgmt && rg_idx < (int)ssd->nrg;
             rg_idx++) {
            ssd->ruhs[i].ru_mgmt[rg_idx].in_use = 0;
        }
        ssd->ruhs[i].ruh_live_pages_cnt = 0;
        for (rg_idx = 0; rg_idx < (int)ssd->nrg; rg_idx++) {
            fdp_set_active(&ssd->ruhs[i], rg_idx,
                           fdp_get_new_ru(ssd, rg_idx, ssd->ruhs[i].ruhid));
        }
    }

    ssd_reset_maptbl(ssd);

    qemu_mutex_lock(&endgrp->fdp.stats_lock);
    memset(endgrp->fdp.hbmw, 0, sizeof(endgrp->fdp.hbmw));
    memset(endgrp->fdp.mbmw, 0, sizeof(endgrp->fdp.mbmw));
    memset(endgrp->fdp.mbe, 0, sizeof(endgrp->fdp.mbe));
    qemu_mutex_unlock(&endgrp->fdp.stats_lock);

    ftl_log("FDP TRIM: all RUs reset\n");
}

/*
 * ssd_trim_fdp_style - dispatch FDP DSM deallocate. Range-honoring by default;
 * whole-device reset only when the fdp_trim_erase_all knob is set. Frees the
 * per-command DSM range list either way (nvme_dsm() allocates it per command and
 * leaves it for the FTL to release, as ssd_trim() does on the non-FDP path).
 * Returns the trim_lat_ns cost per range, the same charge ssd_trim() makes.
 */
uint64_t ssd_trim_fdp_style(FemuCtrl *n, NvmeRequest *req, uint64_t slba,
                            uint32_t nlb)
{
    struct ssd *ssd = req->ns->ssd;
    uint64_t lat = 0;

    if (ssd->sp.trim_lat_ns > 0 && req->dsm_ranges &&
        req->dsm_nr_ranges > 0) {
        lat = (uint64_t)ssd->sp.trim_lat_ns * req->dsm_nr_ranges;
    }

    if (n->bb_params.fdp_trim_erase_all) {
        ssd_trim_fdp_reset_all(n, req, slba, nlb);
    } else {
        ssd_trim_fdp_range(n, req);
    }

    g_free(req->dsm_ranges);
    req->dsm_ranges = NULL;
    req->dsm_nr_ranges = 0;
    req->dsm_attributes = 0;
    return lat;
}

/* count one place that holds @ru */
static void fdp_check_place(struct ssd *ssd, FemuReclaimUnit *ru,
                            uint8_t *seen)
{
    uint64_t i = (uint64_t)ru->rgidx * ssd->rg[0].tt_nru + ru->ruidx;

    if (seen[i] < UINT8_MAX) {
        seen[i]++;
    }
}

/*
 * Heap @pq: each entry is one place, and its stored position must match.
 * Entries sit in d[1] to d[size - 1]; pqueue_size() is size - 1.
 */
static void fdp_check_heap(struct ssd *ssd, pqueue_t *pq, bool ruh_heap,
                           uint8_t *seen, uint64_t *bad)
{
    for (size_t i = 1; i < pq->size; i++) {
        FemuReclaimUnit *ru = pq->d[i];

        fdp_check_place(ssd, ru, seen);
        if ((size_t)(ruh_heap ? ru->ruh_pos : ru->pos) != i) {
            (*bad)++;
        }
    }
}

/* 1 if @ru's programmed bytes or RUAMW disagree with its pages, else 0 */
static int fdp_check_ruamw(struct ssd *ssd, FemuReclaimUnit *ru)
{
    uint64_t pg = (uint64_t)ssd->sp.secsz * ssd->sp.secs_per_pg;

    if (ru->prog_bytes != ((uint64_t)ru->vpc + (uint64_t)ru->ipc) * pg) {
        return 1;
    }
    /* a unit no handle has taken yet holds nothing the host is shown */
    if (!ru->nvme_ru || !ru->ruh || !ru->ruh->ruh) {
        return 0;
    }
    return ru->nvme_ru->ruamw != fdp_ru_ruamw(ssd, ru);
}

/*
 * 1 if the valid pages in the blocks of @ru, on the dies of its group, are
 * not its valid count. A page programmed on a die of another group, or
 * counted in the wrong unit, breaks it.
 */
static int fdp_check_dies(struct ssd *ssd, FemuReclaimUnit *ru)
{
    FemuReclaimGroup *rg = &ssd->rg[ru->rgidx];
    uint64_t valid = 0;

    for (int i = 0; i < ru->n_lines; i++) {
        for (int ch = rg->ch0; ch < rg->ch0 + rg->nch; ch++) {
            for (int lun = rg->lun0; lun < rg->lun0 + rg->nlun; lun++) {
                for (int pl = 0; pl < ssd->sp.pls_per_lun; pl++) {
                    valid += ssd->ch[ch].lun[lun].pl[pl].
                             blk[ru->lines[i]->id].vpc;
                }
            }
        }
    }
    return valid != (uint64_t)ru->vpc;
}

/*
 * Mapped pages in a unit of a handle their namespace's list does not name.
 * A handle keeps the data of the namespaces that use it, so a page of one
 * namespace in another's unit is a write placed through the wrong list.
 */
static uint64_t fdp_check_isolation(struct ssd *ssd)
{
    uint64_t bad = 0;

    for (uint64_t lpn = 0; lpn < (uint64_t)ssd->sp.tt_pgs; lpn++) {
        struct ppa ppa = get_maptbl_ent(ssd, lpn);
        FemuReclaimUnit *ru;
        NvmeNamespace *ns;

        if (!mapped_ppa(&ppa)) {
            continue;
        }
        ru = get_line(ssd, &ppa)->my_ru;
        ns = fdp_lpn_ns(ssd, lpn);
        if (!ru || !ru->ruh || !ns ||
            nvme_ns_ruh_ph(ns, ru->ruh->ruhid) < 0) {
            bad++;
        }
    }
    return bad;
}

/*
 * ssd_fdp_check_units - count reclaim units not held by exactly one place:
 * the free list, the full list, a group victim heap, a handle's write or
 * collection frontier, retirement or the end-of-life reserve, where a unit
 * holds nothing. Under the per-handle strategy a victim of a
 * persistently isolated handle must also sit once in that handle's heap,
 * and no other unit may. Heap entries whose stored position is wrong count
 * too, and so does a unit whose programmed bytes differ from its valid and
 * invalid pages, or whose RUAMW differs from the room they leave, and every
 * page fdp_check_isolation() finds in the wrong handle's unit. A test hook;
 * 0 is consistent.
 */
uint64_t ssd_fdp_check_units(struct ssd *ssd)
{
    uint64_t total = ssd->nrg * ssd->rg[0].tt_nru;
    g_autofree uint8_t *seen = g_new0(uint8_t, total);
    g_autofree uint8_t *in_grp = g_new0(uint8_t, total);
    g_autofree uint8_t *in_ruh = g_new0(uint8_t, total);
    uint64_t bad = 0;
    FemuReclaimUnit *ru;

    for (uint64_t g = 0; g < ssd->nrg; g++) {
        struct ru_mgmt *rm = ssd->rg[g].ru_mgmt;

        QTAILQ_FOREACH(ru, &rm->free_ru_list, entry) {
            fdp_check_place(ssd, ru, seen);
            /* an erased unit has programmed nothing */
            bad += ru->prog_bytes != 0;
        }
        QTAILQ_FOREACH(ru, &rm->full_ru_list, entry) {
            fdp_check_place(ssd, ru, seen);
        }
        fdp_check_heap(ssd, rm->victim_ru_pq, false, in_grp, &bad);
        if (rm->victim_ru_cb != rm->victim_ru_pq && rm->victim_ru_cb) {
            fdp_check_heap(ssd, rm->victim_ru_cb, false, in_grp, &bad);
        }
    }
    for (uint64_t h = 0; h < ssd->nruhs; h++) {
        FemuRuHandle *ruh = &ssd->ruhs[h];

        for (uint64_t g = 0; g < ssd->nrg; g++) {
            FemuReclaimUnit *host = ruh->rus[g];
            FemuReclaimUnit *gc = ruh->gc_rus[g];

            /* a frontier of group g holds a unit of group g */
            if (host) {
                fdp_check_place(ssd, host, seen);
                bad += host->rgidx != g;
            }
            if (gc && gc != host) {
                fdp_check_place(ssd, gc, seen);
                bad += gc->rgidx != g;
            }
            /* a handle's heap repeats victims its group heap holds */
            if (ruh->ru_mgmt && ruh->ru_mgmt[g].victim_ru_pq) {
                pqueue_t *pq = ruh->ru_mgmt[g].victim_ru_pq;

                fdp_check_heap(ssd, pq, true, in_ruh, &bad);
                for (size_t i = 1; i < pq->size; i++) {
                    FemuReclaimUnit *v = pq->d[i];

                    bad += v->ruh != ruh || v->rgidx != g;
                }
            }
        }
    }
    for (uint64_t g = 0; g < ssd->nrg; g++) {
        struct ru_mgmt *rm = ssd->rg[g].ru_mgmt;
        uint64_t retired = 0;
        uint64_t reserve = 0;

        for (uint64_t j = 0; j < ssd->rg[g].tt_nru; j++) {
            FemuReclaimUnit *u = &ssd->rg[g].rus[j];
            uint64_t i = g * ssd->rg[0].tt_nru + j;
            bool want_ruh = in_grp[i] && rm->mgmt_type == GC_NOISY_RUH_CUSTOM &&
                            u->ruh && u->ruh->ru_mgmt;

            /* a retired unit is its own place, and holds nothing */
            if (u->retired) {
                fdp_check_place(ssd, u, seen);
                bad += u->vpc != 0 || u->ipc != 0 || u->prog_bytes != 0;
                retired++;
            }
            /* so is one held erased for the end of life */
            if (u->reserve) {
                fdp_check_place(ssd, u, seen);
                bad += u->vpc != 0 || u->ipc != 0 || u->prog_bytes != 0 ||
                       u->retired;
                reserve++;
            }

            bad += seen[i] + in_grp[i] != 1;
            bad += in_ruh[i] != (want_ruh ? 1 : 0);
            bad += fdp_check_ruamw(ssd, u);
            bad += fdp_check_dies(ssd, u);
        }
        bad += retired != rm->retired_ru_cnt;
        /* the reserve is whole until the media goes read-only, then gone */
        bad += reserve != (ssd->media_ro ? 0 : ssd->fdp_eol_reserve);
    }
    return bad + fdp_check_isolation(ssd);
}

/* Mapped pages in the slice of @ns, which shares this FTL. A test hook. */
uint64_t ssd_fdp_ns_mapped(struct ssd *ssd, NvmeNamespace *ns)
{
    uint64_t pg = (uint64_t)ssd->sp.secsz * ssd->sp.secs_per_pg;
    uint64_t base = ssd_ns_byte_base(ssd, ns);
    uint64_t end = MIN(DIV_ROUND_UP(base + ns->size, pg),
                       (uint64_t)ssd->sp.tt_pgs);
    uint64_t mapped = 0;

    for (uint64_t lpn = base / pg; lpn < end; lpn++) {
        struct ppa ppa = get_maptbl_ent(ssd, lpn);

        mapped += mapped_ppa(&ppa);
    }
    return mapped;
}

/*
 * femu_fdp_ssd_free - release what the two FDP init functions took
 *
 * ssd->rus[i] and rg->rus are the same allocation, and a handle's rus[] holds
 * pointers into those arrays rather than reclaim units of its own, so each is
 * freed exactly once from the side that allocated it.
 */
void femu_fdp_ssd_free(struct ssd *ssd)
{
    uint64_t i;

    g_free(ssd->fdp_written);
    ssd->fdp_written = NULL;
    ssd->fdp_written_bits = 0;

    if (ssd->ruhs) {
        for (i = 0; i < ssd->nruhs; i++) {
            struct ru_mgmt *rm = ssd->ruhs[i].ru_mgmt;
            NvmeRuHandle *nruh = ssd->ruhs[i].ruh;

            /*
             * The subsystem's handle outlives this FTL. Point it back at the
             * unit it had before the FTL took it over, not at the stand-in
             * for no unit, which goes with ssd->ruhs.
             */
            for (uint64_t g = 0; nruh && g < ssd->nrg; g++) {
                nruh->rus[g] = &ssd->n->subsys->endgrp.fdp.rus[g][i];
            }

            for (uint64_t g = 0; rm && g < ssd->nrg; g++) {
                pqueue_free(rm[g].victim_ru_pq);
            }
            g_free(rm);
            g_free(ssd->ruhs[i].rus);
            g_free(ssd->ruhs[i].gc_rus);
        }
        g_free(ssd->ruhs);
        ssd->ruhs = NULL;
        ssd->nruhs = 0;
    }

    if (ssd->rg) {
        for (i = 0; i < ssd->nrg; i++) {
            FemuReclaimGroup *rg = &ssd->rg[i];
            struct ru_mgmt *rm = rg->ru_mgmt;
            uint64_t r;

            /*
             * The array holds total_ru_cnt entries even though a group hands
             * out only its share, and an untouched entry is zeroed, so walk
             * the allocation rather than the group's count.
             */
            for (r = 0; rg->rus && r < ssd->sp.total_ru_cnt; r++) {
                g_free(rg->rus[r].ssd_wptr);
                g_free(rg->rus[r].lines);
            }
            if (rm) {
                pqueue_free(rm->victim_ru_pq);
                pqueue_free(rm->victim_ru_cb);
                g_free(rm);
            }
        }
        g_free(ssd->rg);
        ssd->rg = NULL;
    }

    if (ssd->rus) {
        for (i = 0; i < ssd->nrg; i++) {
            g_free(ssd->rus[i]);
        }
        g_free(ssd->rus);
        ssd->rus = NULL;
    }
    g_free(ssd->rg_lines);
    ssd->rg_lines = NULL;
    ssd->nrg = 0;
}
