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

    fdp_set_ru_write_pointer(ssd, new_ru);
    eruh->ru_in_use_cnt++;

    /*
     * The host-visible active RU (NvmeRuHandle.rus) is published by the
     * caller that makes this the handle's current RU; a collection
     * destination allocated here must not replace it.
     */
    ftl_assert(new_ru->ruh == eruh);
    return new_ru;
}

/*
 * The handle's active unit filled with nothing free to follow it. Point both
 * views away from the retired unit: collection can free it and hand it to
 * another handle, whose remaining room the host would then be shown here.
 */
static void fdp_drop_active_ru(FemuRuHandle *ruh, uint16_t rgidx)
{
    ruh->curr_ru = NULL;
    ruh->rus[rgidx] = NULL;
    ruh->ruh->rus[rgidx] = &ruh->no_ru;
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

    if (rm->mgmt_type != GC_NOISY_RUH_CUSTOM || !ru->ruh) {
        return NULL;
    }
    return ru->ruh->ru_mgmt;
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
        pqueue_remove(ru->ruh->ru_mgmt->victim_ru_pq, ru);
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
    struct ssdparams *spp = &ssd->sp;
    struct ru_mgmt *rm = ssd->rg[ru->rgidx].ru_mgmt;
    bool is_full = true;

    ru->vpc = 0;
    for (int i = 0; i < ru->n_lines; i++) {
        if (ru->lines[i]->vpc != spp->pgs_per_line) {
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
        ru->last_invalidated_time = qemu_clock_get_us(QEMU_CLOCK_REALTIME);
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

    /* allocate a new RU for this RUH cuase ruh->curr_ru is full */
    if (ruh != NULL) {
        check_addr(wpp->blk, spp->blks_per_pl);
        new_ru = fdp_get_new_ru(ssd, ru->rgidx, ruh->ruhid);
        if (!new_ru) {
            ftl_err("No free RU for ruh %d: device full - point %s L:%d\n",
                    ruh->ruhid, __FILE__, __LINE__);
            /*
             * Signal device pressure: clear curr_ru so
             * callers know no active write frontier exists.
             * A full device is an ordinary outcome the callers
             * turn into a capacity error, not a bug -- the
             * assertion that used to stand here aborted the
             * process in the build that arms assertions.
             */
            ruh->curr_ru = NULL;
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
        ftl_assert(wpp->lun == 0);
        ftl_assert(wpp->ch == 0);
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

    line = get_line(ssd, ppa);
    ftl_assert(line->vpc >= 0 && line->vpc < ssd->sp.pgs_per_line);
    line->vpc++;

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
    struct ssdparams *spp = &ssd->sp;
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
    ftl_assert(blk->ipc >= 0 && blk->ipc < spp->pgs_per_blk);
    blk->ipc++;
    ftl_assert(blk->vpc > 0 && blk->vpc <= spp->pgs_per_blk);
    blk->vpc--;

    line = get_line(ssd, ppa);
    ftl_assert(line->ipc >= 0 && line->ipc < spp->pgs_per_line);
    if (line->vpc == spp->pgs_per_line) {
        ftl_assert(line->ipc == 0);
    }
    line->ipc++;
    ftl_assert(line->vpc > 0 && line->vpc <= spp->pgs_per_line);
    line->vpc--;

    /* update RU state */
    ru = line->my_ru;
    ftl_assert(ru != NULL);
    rm = ssd->rg[ru->rgidx].ru_mgmt;
    /* aggregate ipc across all lines in this RU (n_lines=1 in typical config) */
    ru->ipc = 0;
    for (int li = 0; li < ru->n_lines; li++) {
        ru->ipc += ru->lines[li]->ipc;
    }

    /* check if RU was full and needs to move to victim */
    if (ru->vpc == spp->pgs_per_line * ru->n_lines) {
        was_full_ru = true;
    }

    /* update RU vpc and victim queue priority based on GC strategy */
    ru->vpc--;
    /*
     * The share of the unit a collection copies, as at retirement: pages
     * never written are freed by the erase too, so they count as reclaimable.
     */
    ru->utilization = (float)ru->vpc / ru->npages;
    ru->last_invalidated_time = qemu_clock_get_us(QEMU_CLOCK_REALTIME);

    if (rm->mgmt_type == GC_GLOBAL_CB && ru->utilization < 1.0f &&
        ru->last_invalidated_time > 0) {
        ru->my_cb = (uint64_t)(100000.0f * ru->utilization /
            ((1.0f - ru->utilization + 0.001f) *
             (float)ru->last_invalidated_time));
    }
    fdp_victim_reprioritize(ssd, ru);
    if (was_full_ru) {
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
                                        uint16_t rgidx)
{
    FemuReclaimUnit *ru;

    if (ruh->ruh_type == NVME_RUHT_PERSISTENTLY_ISOLATED) {
        if (!ruh->gc_ru) {
            ruh->gc_ru = fdp_get_new_ru(ssd, rgidx, ruh->ruhid);
        }
        return ruh->gc_ru;
    }

    ftl_assert(ruh->ruh_type == NVME_RUHT_INITIALLY_ISOLATED);
    if (!ruh->curr_ru) {
        ru = fdp_get_new_ru(ssd, rgidx, ruh->ruhid);
        if (!ru) {
            return NULL;
        }
        ruh->curr_ru = ru;
        ruh->rus[rgidx] = ru;
        ruh->ruh->rus[rgidx] = ru->nvme_ru;
    }
    return ruh->curr_ru;
}

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
        uint64_t now = qemu_clock_get_us(QEMU_CLOCK_REALTIME);
        double best = -1.0;
        bool best_free = false;

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
            } else if (!best_free && score > best) {
                best = score;
                victim_ru = ru;
            }
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

    case GC_NOISY_RUH_CUSTOM: {
        /*
         * Cross-RUH selection: find lowest vpc across all RUHs
         * that exceed their custom GC threshold.
         */
        FemuReclaimUnit *ru = NULL;
        int best_ruh = -1;
        int i;
        for (i = 0; i < (int)ssd->nruhs; i++) {
            if (!ssd->ruhs[i].ru_mgmt) {
                continue;
            }
            if (ssd->ruhs[i].ru_in_use_cnt <=
                ssd->ruhs[i].ru_mgmt->custom_gc_threshold) {
                continue;
            }
            ru = pqueue_peek(ssd->ruhs[i].ru_mgmt->victim_ru_pq);
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

    if (!force && victim_ru->vpc > 0) {
        int threshold = victim_ru->npages / 8;
        /*
         * Count every page an erase gives back. A unit that a handle update
         * retired part written also gives back the pages it never wrote, which
         * are neither valid nor invalid. Judged by ipc alone it is refused on
         * every pass, and its low vpc keeps it at the heap top, so background
         * collection never reaches the units behind it.
         */
        int reclaimable = victim_ru->npages - victim_ru->vpc;

        if (reclaimable < threshold) {
            FDP_TRACE(ssd, "GC_BACK_RESERT triggered but delay GC "
                      "(ru %d ipc %d threshold %d full %d)\n",
                      victim_ru->ruidx, victim_ru->ipc, threshold,
                      victim_ru->npages);
            fdp_victim_enqueue(ssd, victim_ru);
            return NULL;
        }
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
 * gc_write_page_fdp_style - relocate a valid page to a GC destination RU.
 * Returns false when there is nowhere to put it, which leaves the page where it
 * is: the caller must then not erase the block it came from.
 */
static bool gc_write_page_fdp_style(struct ssd *ssd, struct ppa *old_ppa,
                                    FemuRuHandle *dest_ruh, uint16_t rgidx)
{
    struct ppa new_ppa;
    uint64_t lpn = get_rmap_ent(ssd, old_ppa);
    FemuReclaimUnit *dest_ru=NULL;
    FemuReclaimUnit *ret_ru=NULL;
    ftl_assert(valid_lpn(ssd, lpn));
    ftl_assert(dest_ruh!=NULL);

    /* the frontier may have been dropped by this or an earlier pass */
    dest_ru = fdp_gc_frontier(ssd, dest_ruh, rgidx);
    if (!dest_ru) {
        return false;
    }

    new_ppa = fdp_get_new_page(ssd, dest_ru);
    ssd_gc_move_page(ssd, lpn, old_ppa, &new_ppa, &fdp_gc_move_ops, dest_ru);

    // FDP_TRACE(ssd, "GC_MIGRATE lpn=%lu src(ch=%u/lun=%u/blk=%u/pg=%u) "
    //           "dst(ch=%u/lun=%u/blk=%u/pg=%u) dest_ruhid=%u\n",
    //           lpn, (unsigned)old_ppa->g.ch, (unsigned)old_ppa->g.lun,
    //           (unsigned)old_ppa->g.blk, (unsigned)old_ppa->g.pg,
    //           (unsigned)new_ppa.g.ch, (unsigned)new_ppa.g.lun,
    //           (unsigned)new_ppa.g.blk, (unsigned)new_ppa.g.pg,
    //           dest_ruh->ruhid);

    /*
     * fdp_advance_ru_pointer() can be called from both the foreground write
     * path and GC, and only advances the write pointer of the given RU. The
     * caller is therefore responsible for updating curr_ru / gc_ru by RUH type
     * right after the advance.
     */

    /*
     * Advancing hands back NULL when there is no free reclaim unit left, which
     * is what a full device looks like from here. The initially-isolated arm
     * dereferenced that straight away, and the only thing standing between it
     * and a null pointer was an ftl_assert, which is compiled out. Neither arm
     * can do anything useful without a unit, so leave the write frontier where
     * it is and let the caller run out of room.
     */
    if (dest_ruh->ruh_type == NVME_RUHT_PERSISTENTLY_ISOLATED) {
        FemuReclaimUnit *host_ru = dest_ru->ruh->curr_ru;

        ret_ru = fdp_advance_ru_pointer(ssd, &ssd->rg[dest_ru->rgidx],
                                        dest_ru->ruh, dest_ru);
        if (ret_ru && ret_ru != dest_ru) {
            dest_ruh->gc_ru = ret_ru;
        } else if (!ret_ru) {
            /*
             * Advancing clears the handle's host write frontier when it cannot
             * allocate, but what ran out here is the collection frontier. Put
             * the host's back: cleared, the next host write to this handle
             * would take a null unit into the page allocator. The collection
             * unit is retired and its pointer wrapped to page 0, so drop it:
             * kept, the next relocation would program a written page.
             */
            dest_ru->ruh->curr_ru = host_ru;
            dest_ruh->gc_ru = NULL;
        }
    } else if (dest_ruh->ruh_type == NVME_RUHT_INITIALLY_ISOLATED) {
        int gcruh_id = ssd->nruhs - 1;

        ftl_assert(dest_ruh->ruhid == gcruh_id);
        ret_ru = fdp_advance_ru_pointer(ssd, &ssd->rg[dest_ru->rgidx],
                                        dest_ruh, dest_ru);
        if (ret_ru && ret_ru != dest_ru) {
            ssd->ruhs[gcruh_id].rus[dest_ru->rgidx] = ret_ru;
            ssd->ruhs[gcruh_id].curr_ru = ret_ru;
            ssd->ruhs[gcruh_id].ruh->rus[dest_ru->rgidx] = ret_ru->nvme_ru;
        } else if (!ret_ru) {
            fdp_drop_active_ru(dest_ruh, dest_ru->rgidx);
        }
    }

    if (!ret_ru) {
        ftl_err("FDP: no free reclaim unit while relocating; device is full\n");
    }

    ssd_gc_charge_move(ssd, &new_ppa);

    /* this page is relocated; whether the next one can be is the next call */
    return true;
}

/*
 * clean_one_block_fdp_style - GC one block: read valid pages and write to new_ru
 * @params 
 *  ppa : identifies the block we want to clean
 *  dest_ruh : destination ruh.
 *          ru based mechanism can cause pointer error when gc write page allocates new ru to ruh->gc. 
 *          Replace ru based parameter which makes ruh->curr_ru or ruh->gc_ru dangling
 *          
 */
static bool clean_one_block_fdp_style(struct ssd *ssd, struct ppa *ppa,
                                      FemuRuHandle *dest_ruh, uint16_t rgidx,
                                      int *moved)
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
            if (!gc_write_page_fdp_style(ssd, ppa, dest_ruh, rgidx)) {
                return false;
            }
            (*moved)++;
        }
    }

    ftl_assert(get_blk(ssd, ppa)->vpc == 0);
    return true;
}

/* charge relocated pages to MBMW, also when a pass stops part way */
static void fdp_count_gc_writes(struct ssd *ssd, FemuReclaimUnit *victim_ru,
                                int pages)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t gc_bytes = (uint64_t)pages * spp->secsz * spp->secs_per_pg;

    nvme_fdp_stat_inc(&ssd->n->subsys->endgrp.fdp.mbmw, gc_bytes);
    nvme_fdp_stat_inc(&victim_ru->ruh->mbmw, gc_bytes);
    nvme_fdp_stat_inc(&victim_ru->ruh->ruh->mbmw, gc_bytes);
}

/*
 * mark_ru_free - reset a victim RU to free state after GC
 */
static void mark_ru_free(struct ssd *ssd, uint16_t rgid,
                         FemuReclaimUnit *ru)
{
    struct ru_mgmt *rm = ssd->rg[rgid].ru_mgmt;

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
    }

    ru->vpc = 0;
    ru->ipc = 0;
    ru->pos = 0;
    ru->ruh_pos = 0;
    ru->utilization = 0.0f;
    ru->my_cb = 0.0f;

    fdp_set_ru_write_pointer(ssd, ru);

    /* restore ruamw to initial value */
    ftl_assert(ru->nvme_ru != NULL);
    ftl_assert(ru->ruh != NULL);
    ftl_assert(ru->ruh->ruh != NULL);
    ru->nvme_ru->ruamw = ru->ruh->ruh->ruamw;

    QTAILQ_INSERT_TAIL(&rm->free_ru_list, ru, entry);
    rm->free_ru_cnt++;
}

/*
 * do_gc_fdp_style - FDP garbage collection: select victim RU, migrate valid
 * pages to GC RU, then free the victim
 *  gaurantees one RU to be reclaimed, if victim is valid.
 */
int do_gc_fdp_style(struct ssd *ssd, uint16_t rgid, uint16_t ruhid,
                           bool force)
{
    struct ssdparams *spp = &ssd->sp;
    FemuReclaimUnit *victim_ru;
    //FemuReclaimUnit *new_ru;
    struct ppa ppa;
    int vpc_cnt = 0;
    int blk_cnt = 0;
    victim_ru = select_victim_ru(ssd, rgid, force);
    if (!victim_ru) {
        //FDP_TRACE(ssd,"GC_SKIP Unable to find victim RU, gc skip\n");
        return -1;
    }

    /*
     * Where the victim's pages go depends on its handle's isolation: a
     * persistently isolated handle relocates into a unit of its own (gc_ru),
     * so collected data never mixes with another handle's; the initially
     * isolated one, always the last handle, relocates into its active unit.
     */
    FemuRuHandle *victim_ruh = victim_ru->ruh;
    FemuRuHandle *dest_ruh = NULL;

    if (victim_ruh->ruh_type == NVME_RUHT_PERSISTENTLY_ISOLATED) {
        dest_ruh = victim_ruh;
    } else if (victim_ruh->ruh_type == NVME_RUHT_INITIALLY_ISOLATED) {
        dest_ruh = &ssd->ruhs[ssd->nruhs - 1];
    } else {
        ftl_err("Undefined RUHT.");
        ftl_assert(false && __LINE__);
    }

    /*
     * A victim with pages to move needs somewhere to put them; with no free
     * unit for the frontier, put it back and fail the pass, and the caller
     * degrades to a device-full write. One with none needs nowhere, and must
     * be collected even then: it is what gives the frontier a unit again.
     */
    if (victim_ru->vpc && !fdp_gc_frontier(ssd, dest_ruh, victim_ru->rgidx)) {
        fdp_victim_enqueue(ssd, victim_ru);
        return -1;
    }
    ftl_assert(dest_ruh!=NULL);
    /* sanity: don't GC an active RU */
    if (victim_ru == victim_ru->ruh->curr_ru) {
        ftl_err("Victim RU %d is active, skipping GC\n", victim_ru->ruidx);
        //This is a bug.
        ftl_assert(false && __LINE__);
        return -1;
    }

    ftl_note_victim(ssd, (uint64_t)victim_ru->rgidx << 16 | victim_ru->ruidx);
    FDP_TRACE(ssd, "GC_START rgid=%u ruhid=%u victim_ru=%u "
              "victim_vpc=%d isolation=%s gc_type=%s\n",
              rgid, ruhid, victim_ru->ruidx, victim_ru->vpc,
              (victim_ruh->ruh_type == NVME_RUHT_PERSISTENTLY_ISOLATED) ?
              "PI" : "II", (force) ? "FORCE" : "BACK" );

    /*
     * Migrate every valid page before erasing any block. If the destination
     * runs out part way, the victim goes back on the queue holding what was
     * not moved; a block erased before that point would be counted erased
     * again when the unit is next collected.
     */
    for (int i = 0; i < spp->lines_per_ru; i++) {
        ppa.g.blk = victim_ru->lines[i]->id;
        for (int ch = 0; ch < spp->nchs; ch++) {
            for (int lun = 0; lun < spp->luns_per_ch; lun++) {
                ppa.g.ch = ch;
                ppa.g.lun = lun;
                for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                    ppa.g.pl = pl;
                    if (!clean_one_block_fdp_style(ssd, &ppa, dest_ruh,
                                                   victim_ru->rgidx,
                                                   &vpc_cnt)) {
                        fdp_count_gc_writes(ssd, victim_ru, vpc_cnt);
                        fdp_victim_enqueue(ssd, victim_ru);
                        return -1;
                    }
                }
            }
        }
    }

    for (int i = 0; i < spp->lines_per_ru; i++) {
        struct line *victim_line = victim_ru->lines[i];
        ppa.g.blk = victim_line->id;
        for (int ch = 0; ch < spp->nchs; ch++) {
            for (int lun = 0; lun < spp->luns_per_ch; lun++) {
                ssd_erase_lun_block(ssd, ch, lun, ppa.g.blk,
                                    spp->enable_gc_delay, 0);
                blk_cnt += spp->pls_per_lun;
            }
        }
    }

    /* update FDP statistics: media bytes written (GC writes) */
    uint64_t gc_bytes = (uint64_t)vpc_cnt * spp->secsz * spp->secs_per_pg;
    uint64_t erase_bytes = (uint64_t)blk_cnt * spp->secsz * spp->secs_per_pg
                           * spp->pgs_per_blk;

    FDP_TRACE(ssd, "GC_DONE victim_ru=%u pages_migrated=%d "
              "blocks_erased=%d mbmw_delta=%lu mbe_delta=%lu\n",
              victim_ru->ruidx, vpc_cnt, blk_cnt, gc_bytes, erase_bytes);
    fdp_count_gc_writes(ssd, victim_ru, vpc_cnt);
    nvme_fdp_stat_inc(&ssd->n->subsys->endgrp.fdp.mbe, erase_bytes);
    nvme_fdp_stat_inc(&victim_ru->ruh->mbe, erase_bytes);
    nvme_fdp_stat_inc(&victim_ru->ruh->ruh->mbe, erase_bytes);

    if (ssd->ruhs[victim_ru->ruh->ruhid].ru_in_use_cnt > 0) {
        ssd->ruhs[victim_ru->ruh->ruhid].ru_in_use_cnt--;
    }

    /* generate controller event for RU change due to GC */
    if (ssd->n->subsys) {
        NvmeEnduranceGroup *endgrp = &ssd->n->subsys->endgrp;
        NvmeRuHandle *nvme_ruh = victim_ru->ruh->ruh;
        if (nvme_ruh &&
            (nvme_ruh->event_filter >>
             nvme_fdp_evf_shifts[FDP_EVT_RUH_IMPLICIT_RU_CHANGE]) & 0x1) {
            NvmeFdpEvent e = {
                .type = FDP_EVT_RUH_IMPLICIT_RU_CHANGE,
                .flags = FDPEF_LV,
                .rgid = cpu_to_le16(victim_ru->rgidx),
                .ruhid = victim_ru->ruh->ruhid,
            };

            nvme_fdp_record_event(ssd->n, endgrp, false, &e);
        }
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

static void fdp_gc_until_clear(struct ssd *ssd, uint16_t rgid, uint16_t ruhid)
{
    uint64_t fg_gc_iters = 0;
    uint64_t max_fg_gc = (uint64_t)ssd->nrg * ssd->rg[0].ru_mgmt->tt_rus +
                         ssd->nrg;

    while (should_gc_high_fdp_style(ssd) >= 0 && fg_gc_iters < max_fg_gc) {
        if (do_gc_fdp_style(ssd, rgid, ruhid, true) == -1) {
            break;
        }
        fg_gc_iters++;
    }
}

/*
 * ssd_stream_write - FDP write path: placement-aware page allocation
 */
/*
 * Program [start_lpn, end_lpn] into the reclaim unit the request places into.
 * Write and Write Zeroes both land here: the second hands over no data, but
 * the pages it leaves holding zeros are programmed and counted the same way.
 */
static uint64_t ssd_stream_write_lpns(FemuCtrl *n, struct ssd *ssd,
                                      NvmeRequest *req, uint64_t start_lpn,
                                      uint64_t end_lpn)
{
    NvmeNamespace *ns = req->ns;
    struct ssdparams *spp = &ssd->sp;
    FemuReclaimGroup *rg;
    FemuRuHandle *ruh;
    FemuReclaimUnit *ru;

    uint64_t pg = (uint64_t)spp->secsz * spp->secs_per_pg;
    uint64_t media = 0;
    struct ppa ppa;
    uint64_t lpn;
    uint64_t curlat = 0, maxlat = 0;
    uint64_t written = 0;

    /* parse placement info from request */
    uint16_t pid = req->fdp_dspec;
    uint8_t dtype = req->fdp_dtype;
    uint16_t ph, rgid, ruhid;

    if (dtype != NVME_DIRECTIVE_DATA_PLACEMENT ||
        !nvme_parse_pid(ns, pid, &ph, &rgid)) {
        /* generate INVALID_PID event if placement was attempted */
        if (dtype == NVME_DIRECTIVE_DATA_PLACEMENT && ssd->n->subsys) {
            NvmeEnduranceGroup *endgrp = &ssd->n->subsys->endgrp;
            NvmeRuHandle *def_ruh = &endgrp->fdp.ruhs[ns->fdp.phs[0]];
            if ((def_ruh->event_filter >>
                 nvme_fdp_evf_shifts[FDP_EVT_INVALID_PID]) & 0x1) {
                NvmeFdpEvent e = {
                    .type = FDP_EVT_INVALID_PID,
                    .flags = FDPEF_PIV | FDPEF_NSIDV,
                    .pid = cpu_to_le16(pid),
                    .nsid = cpu_to_le32(ns->id),
                };

                nvme_fdp_record_event(ssd->n, endgrp, true, &e);
            }
        }
        ph = 0;
        rgid = 0;
    }

    ruhid = ns->fdp.phs[ph];
    /* safety: ruhid must be within bounds (nvme_parse_pid ensures ph is valid) */
    if (unlikely(ruhid >= (uint16_t)ssd->nruhs)) {
        ftl_err("ssd_stream_write: ruhid %u >= nruhs %lu, clamping to 0\n",
                (unsigned)ruhid, (unsigned long)ssd->nruhs);
        ruhid = 0;
    }
    rg = &ssd->rg[rgid];
    ruh = &ssd->ruhs[ruhid];

    // FDP_TRACE(ssd, "WRITE lpn=%lu-%lu dtype=%u dspec=0x%x ph=%u "
    //           "ruhid=%u rgid=%u\n", start_lpn, end_lpn, dtype, pid,
    //           ph, ruhid, rgid);

    /*
     * Ensure this RUH has an active RU.  After a sequential fill,
     * curr_ru may be NULL (cleared by fdp_advance_ru_pointer when it
     * enqueued the last RU into full_ru_list and could not allocate a
     * fresh one).  Run foreground GC first so we have a free RU.
     */
    if (unlikely(!ruh->curr_ru)) {
        /* try to free space via GC before allocating */
        //Erase experimental gc behavior
        //int max_fg_gc = (int)(ssd->nrg > 0 ?
        //    ssd->rg[0].ru_mgmt->tt_rus : 64);
        //for (int gi = 0; gi < max_fg_gc && !ruh->curr_ru; gi++) {
        //    r = do_gc_fdp_style(ssd, rgid, ruhid, true);
        //    if (r == -1) break;
            /* GC may have freed a RU; try to grab it */
            FemuReclaimUnit *fresh = fdp_get_new_ru(ssd, rgid, ruhid);
            if (fresh) {
                ruh->rus[rgid] = fresh;
                ruh->ruh->rus[rgid] = fresh->nvme_ru;
                ruh->curr_ru = fresh;
            }else{
                ftl_err("NO reclaim Unit. Device is full error\n");
                //Fallout
            }
        //}
        if (!ruh->curr_ru) {
            /*
             * Genuinely out of reclaimable space: the foreground backpressure
             * GC below could not free a reclaim unit. Fail the command with a
             * capacity error instead of completing it as success with no data
             * written.
             */
            ftl_err("ssd_stream_write: device full, no RU for ruh %d\n", ruhid);
            req->status = NVME_CAP_EXCEEDED | NVME_DNR;
            return 0;
        }
    }
    ru = ruh->rus[rgid];
    ru = ruh->curr_ru;
    ftl_assert(ruh->curr_ru == ruh->rus[rgid]);
    
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
     * Running until should_gc_high_fdp_style() reports no pressure holds the
     * pool above the threshold -- the host write effectively waits on GC, which
     * is the intended backpressure. do_gc_fdp_style() returns -1 when no victim
     * remains (nothing left to reclaim); that is the normal exit. The counter is
     * only a guard against an unexpected non-terminating condition, bounded by
     * the total reclaim-unit population so it never trips during real progress.
     */
    fdp_gc_until_clear(ssd, rgid, ruhid);

    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        /*
         * And per page: one command can take more units than the watermark
         * keeps free, and once the handle's last unit is gone collection has
         * nowhere to move pages to.
         */
        fdp_gc_until_clear(ssd, rgid, ruhid);

        /*
         * Updating curr_ru should be handled by fdp_advance_ru_pointer() naturally.
         */
        ru = ruh->curr_ru;
        /*
         * A previous iteration may have exhausted the last free reclaim unit:
         * fdp_advance_ru_pointer() cleared curr_ru with nothing left to allocate.
         * Writing into a NULL RU would dereference it in fdp_get_new_page(); stop
         * and fail the command with a capacity error rather than crashing or
         * reporting a silent success for pages that were never written.
         */
        if (unlikely(!ru)) {
            req->status = NVME_CAP_EXCEEDED | NVME_DNR;
            break;
        }

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
        ssd->nand_write_pages++; /* a user page programmed into NAND */
        /*
         * Counted here rather than for the whole command before the loop: the
         * loop stops when the device runs out of room, so a command that wrote
         * part of itself used to add all of its pages to the denominator the
         * amplification figure divides by.
         */
        ssd->host_write_pages++;
        written++;

        /* RUAMW counts blocks, and a page may hold several or half of one */
        if (ru->nvme_ru) {
            uint64_t blks = ((media + pg) >> ns->lbaf.lbads) -
                            (media >> ns->lbaf.lbads);

            ru->nvme_ru->ruamw -= MIN(ru->nvme_ru->ruamw, blks);
        }
        media += pg;

        /* advance RU write pointer; may allocate new RU */
        FemuReclaimUnit *ret = fdp_advance_ru_pointer(ssd, rg, ruh, ru);
        if (ret && ret != ruh->curr_ru) {
            ruh->rus[rgid] = ret;
            ruh->curr_ru = ret;
            ruh->ruh->rus[rgid] = ret->nvme_ru;
            ru = ret;
        } else if (!ret) {
            /* no free unit; the next page or command fails for it */
            fdp_drop_active_ru(ruh, rgid);
            ru = NULL;
        }

        struct nand_cmd swr;
        swr.type = USER_IO;
        swr.cmd = NAND_WRITE;
        swr.stime = req->stime;
        curlat = ssd_advance_status(ssd, &ppa, &swr);
        maxlat = (curlat > maxlat) ? curlat : maxlat;
    }

    /* what the caller charges its byte counters with */
    req->xfer_bytes = written * (uint64_t)spp->secs_per_pg * spp->secsz;

    return maxlat;
}

static bool fdp_ru_unwritten(FemuReclaimUnit *ru)
{
    struct write_pointer *wpp = ru->ssd_wptr;

    return wpp->curline == ru->lines[0] && !wpp->ch && !wpp->lun &&
           !wpp->pl && !wpp->pg;
}

/*
 * ssd_fdp_update_ruhs - Reclaim Unit Handle Update: each named handle moves to
 * a fresh unit and the one it leaves is collected like any other. A unit that
 * was never written is as good as a fresh one and is kept. If collection
 * cannot free a unit either, the command fails rather than claim a move.
 */
void ssd_fdp_update_ruhs(FemuCtrl *n, NvmeRequest *req)
{
    struct ssd *ssd = n->ssd;
    NvmeNamespace *ns = req->ns;

    for (uint32_t i = 0; i < req->nr_fdp_pids; i++) {
        uint16_t pid = req->fdp_pids[i];
        uint16_t ph, rgid;
        FemuRuHandle *ruh;
        FemuReclaimUnit *old, *fresh;

        /* the poller refused the command if any of these was invalid */
        nvme_parse_pid(ns, pid, &ph, &rgid);
        ruh = &ssd->ruhs[ns->fdp.phs[ph]];
        old = ruh->curr_ru;
        if (!old) {
            continue;
        }
        if (fdp_ru_unwritten(old)) {
            nvme_fdp_note_ru_left(n, ns, pid, old->nvme_ru);
            continue;
        }

        fresh = fdp_get_new_ru(ssd, rgid, ruh->ruhid);
        if (!fresh && do_gc_fdp_style(ssd, rgid, ruh->ruhid, true) != -1) {
            fresh = fdp_get_new_ru(ssd, rgid, ruh->ruhid);
        }
        if (!fresh) {
            req->status = NVME_CAP_EXCEEDED | NVME_DNR;
            return;
        }
        nvme_fdp_note_ru_left(n, ns, pid, old->nvme_ru);
        fdp_retire_ru(ssd, old);
        ruh->rus[rgid] = fresh;
        ruh->curr_ru = fresh;
        ruh->ruh->rus[rgid] = fresh->nvme_ru;
    }
}

static uint64_t ssd_stream_write(FemuCtrl *n, struct ssd *ssd,
                                NvmeRequest *req)
{
    uint64_t start_lpn, end_lpn;

    ssd_lpn_range(ssd, req, req->slba, req->nlb, &start_lpn, &end_lpn);

    return ssd_stream_write_lpns(n, ssd, req, start_lpn, end_lpn);
}

/*
 * Charge what a placed write actually programmed to the endurance group and
 * to the handle its placement identifier selects.
 */
static void fdp_count_write(NvmeNamespace *ns, struct ssd *ssd,
                            NvmeRequest *req)
{
    uint64_t data_bytes = req->xfer_bytes;
    uint16_t ph, rg, ruhid;

    if (!data_bytes) {
        return;
    }
    if (req->fdp_dtype != NVME_DIRECTIVE_DATA_PLACEMENT ||
        !nvme_parse_pid(ns, req->fdp_dspec, &ph, &rg)) {
        ph = 0;
    }
    ruhid = ns->fdp.phs[ph];

    nvme_fdp_stat_inc(&ns->endgrp->fdp.hbmw, data_bytes);
    nvme_fdp_stat_inc(&ns->endgrp->fdp.mbmw, data_bytes);
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].hbmw, data_bytes);
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].ruh->hbmw, data_bytes);
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
    struct ssd *ssd = n->ssd;
    uint64_t lat;

    (void)slba;
    (void)nlb;

    lat = ssd_stream_write(n, ssd, req);

    /*
     * Charged from what the write actually programmed, after the fact: a
     * write the device had no room for must not add its length to either
     * total, or the reported amplification falls below one.
     */
    fdp_count_write(ns, ssd, req);

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
 * femu_fdp_init_ssd_reclaim_unit - initialize one RU with lines and wptr
 */
static void femu_fdp_init_ssd_reclaim_unit(struct ssd *ssd,
                                           FemuReclaimUnit *femu_ru,
                                           int rgidx, int index)
{
    struct ssdparams *spp = &ssd->sp;
    struct write_pointer *wpp;

    femu_ru->n_lines = spp->lines_per_ru;
    femu_ru->vpc = 0;
    femu_ru->ipc = 0;
    femu_ru->pos = 0;
    femu_ru->ruh_pos = 0;     /* not yet in any victim pqueue */
    femu_ru->ssd_wptr = g_malloc0(sizeof(struct write_pointer));
    femu_ru->npages = spp->lines_per_ru * spp->pgs_per_line;

    wpp = femu_ru->ssd_wptr;
    femu_ru->lines = g_malloc0(femu_ru->n_lines * sizeof(struct line *));
    for (int i = 0; i < femu_ru->n_lines; i++) {
        femu_ru->lines[i] = get_next_free_line(ssd);
        if (!femu_ru->lines[i]) {
            ftl_err("FDP: no free line for RU %d (rg %d, line %d/%d)\n",
                    index, rgidx, i, femu_ru->n_lines);
            abort();
        }
        femu_ru->lines[i]->my_ru = femu_ru;
    }
    wpp->curline = femu_ru->lines[0];
    wpp->ch = 0;
    wpp->lun = 0;
    wpp->pl = 0;
    wpp->blk = wpp->curline->id;
    wpp->pg = 0;
}

/*
 * femu_fdp_ssd_init_reclaim_group - init all RGs and their RU pools
 */
void femu_fdp_ssd_init_reclaim_group(FemuCtrl *n, struct ssd *ssd)
{
    NvmeSubsystem *subsys = n->subsys;
    uint64_t rgs = subsys->params.fdp.nrg;
    FemuReclaimGroup *rg;
    uint64_t tt_nru = ssd->sp.total_ru_cnt;

    ftl_assert(tt_nru > 0);

    ssd->rg = g_malloc0(rgs * sizeof(FemuReclaimGroup));
    ssd->nrg = rgs;
    ssd->rus = g_malloc0(rgs * sizeof(FemuReclaimUnit *));

    for (int i = 0; i < (int)rgs; i++) {
        rg = &ssd->rg[i];
        rg->rgidx = i;
        rg->tt_nru = tt_nru / rgs;
        ssd->rus[i] = g_malloc0(tt_nru * sizeof(FemuReclaimUnit));
        rg->rus = ssd->rus[i];
        rg->ru_mgmt = g_malloc0(sizeof(struct ru_mgmt));
        femu_fdp_init_ru_mgmt(ssd, rg);
        fdp_log("Allocated %lu RUs to rg[%d]\n", tt_nru, i);
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
                femu_fdp_init_ssd_reclaim_unit(ssd, &rg->rus[j], i, j);
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
            rg->ru_mgmt->mgmt_type = n->bb_params.gc_strategy;
            ftl_log("rg[%d] gc strategy=%d\n", i,
                    rg->ru_mgmt->mgmt_type);
        }
    }
}

/*
 * femu_fdp_ssd_init_ru_handles - init FemuRuHandle for each namespace PH
 */
void femu_fdp_ssd_init_ru_handles(FemuCtrl *n, struct ssd *ssd)
{
    NvmeNamespace *ns = &n->namespaces[0];
    NvmeSubsystem *subsys = n->subsys;
    NvmeEnduranceGroup *endgrp = &subsys->endgrp;
    uint16_t nruh = subsys->params.fdp.nruh;
    uint16_t ph, *ruhid;

    ssd->ruhs = g_malloc0(nruh * sizeof(FemuRuHandle));
    ssd->nruhs = nruh;
    ruhid = ns->fdp.phs;

    for (ph = 0; ph < ns->fdp.nphs; ph++, ruhid++) {
        uint16_t i = *ruhid;
        NvmeRuHandle *nvme_ruh = &endgrp->fdp.ruhs[i];

        ssd->ruhs[i].ruh = nvme_ruh;
        ssd->ruhs[i].ruh_type = nvme_ruh->ruht;
        ssd->ruhs[i].ruhid = i;
        ssd->ruhs[i].ruh_live_pages_cnt = 0;
        ssd->ruhs[i].ru_in_use_cnt = 0;
        ssd->ruhs[i].hbmw = 0;
        ssd->ruhs[i].mbmw = 0;
        ssd->ruhs[i].mbe = 0;

        /* allocate per-RG RU pointer array */
        ssd->ruhs[i].rus = g_malloc0(sizeof(FemuReclaimUnit *) *
                                     endgrp->fdp.nrg);
        for (int j = 0; j < (int)endgrp->fdp.nrg; j++) {
            ssd->ruhs[i].rus[j] = fdp_get_new_ru(ssd, j, i);
            ssd->ruhs[i].rus[j]->ruh = &ssd->ruhs[i];
            ssd->ruhs[i].ruh->rus[j] = ssd->ruhs[i].rus[j]->nvme_ru;
        }
        /*
         * The active RU must match the default reclaim group (rgid 0), not
         * the last one allocated by the loop above. A non-placement
         * write uses rgid 0, and the write path advances ruh->curr_ru through
         * ssd->rg[rgid]'s management object. Leaving curr_ru in the last group
         * (nrg-1) made a default write advance an rg[nrg-1] RU through rg[0]'s
         * bookkeeping: the RU was enqueued in one group's victim queue but later
         * looked up via its own group's queue with a stale heap position, a NULL
         * dereference crash under nrg>1. Cross-group placement writes still need
         * a per-(RUH,RG) active-RU model; this repairs the default path.
         */
        ssd->ruhs[i].curr_ru = ssd->ruhs[i].rus[0];

        /* PI type RUHs get their own ru_mgmt for per-RUH victim queues */
        if (nvme_ruh->ruht == NVME_RUHT_PERSISTENTLY_ISOLATED) {
            ssd->ruhs[i].ru_mgmt = g_malloc0(sizeof(struct ru_mgmt));
            ssd->ruhs[i].ru_mgmt->mgmt_type = n->bb_params.gc_strategy;
            ssd->ruhs[i].ru_mgmt->custom_gc_threshold = 0;
            QTAILQ_INIT(&ssd->ruhs[i].ru_mgmt->free_ru_list);
            QTAILQ_INIT(&ssd->ruhs[i].ru_mgmt->full_ru_list);
            /*
             * Per-RUH queues index via ruh_pos (see victim_ru_*_pos_ruh) so
             * they do not alias the per-RG queue's pos (issue #189).
             */
            ssd->ruhs[i].ru_mgmt->victim_ru_pq =
                pqueue_init(ssd->rg[0].tt_nru, victim_ru_cmp_pri,
                            victim_ru_get_pri, victim_ru_set_pri,
                            victim_ru_get_pos_ruh, victim_ru_set_pos_ruh);
        }

        ftl_log("FDP: ruh[%d] type=%d, curr_ru=%d (line=%d)\n",
                i, ssd->ruhs[i].ruh_type, ssd->ruhs[i].curr_ru->ruidx,
                ssd->ruhs[i].curr_ru->lines[0]->id);
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
}

/*
 * Deallocate [start_lpn, end_lpn] under FDP: invalidate through the FDP path so
 * the reclaim unit's valid/invalid counts and victim state stay right, then
 * unmap. Shared by DSM Deallocate and Write Zeroes with the Deallocate bit.
 */
static int ssd_deallocate_fdp_lpns(struct ssd *ssd, uint64_t start_lpn,
                                   uint64_t end_lpn, int *already_invalid)
{
    int deallocated = 0;
    uint64_t lpn;

    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        struct ppa ppa = get_maptbl_ent(ssd, lpn);

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

/* Deallocate every page under FDP; see bbssd_deallocate_all(). */
void ssd_deallocate_fdp_all(struct ssd *ssd)
{
    int already_invalid = 0;

    if (ssd->sp.tt_pgs) {
        ssd_deallocate_fdp_lpns(ssd, 0, ssd->sp.tt_pgs - 1, &already_invalid);
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
    struct ssd *ssd = n->ssd;
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
    struct ssd *ssd = (req->ns && req->ns->ssd) ? req->ns->ssd : n->ssd;
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
        uint64_t lat = ssd_stream_write_lpns(n, ssd, req, start_lpn, end_lpn);

        fdp_count_write(req->ns, ssd, req);
        return lat;
    }

    ssd_deallocate_fdp_lpns(ssd, start_lpn, end_lpn, &already_invalid);

    return 0;
}

/*
 * ssd_trim_fdp_reset_all - FDP DSM whole-device reset (opt-in via the
 * fdp_trim_erase_all device property, test only). Erases every block, drains all
 * reclaim units, resets all RUH state, and wipes the mapping table. This was the
 * original prototype behavior for a customized non-filesystem fio+trim sweep; it
 * is NOT how DSM-deallocate behaves on a real SSD and ignores the requested LBA
 * range, so it is gated off by default.
 */
static void ssd_trim_fdp_reset_all(FemuCtrl *n, NvmeRequest *req, uint64_t slba,
                                   uint32_t nlb)
{
    struct ssd *ssd = n->ssd;
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
        /* the group drain above took every unit off its handle's heap too */
        ftl_assert(!ssd->ruhs[i].ru_mgmt ||
                   pqueue_size(ssd->ruhs[i].ru_mgmt->victim_ru_pq) == 0);
        ruh->hbmw = 0;
        ruh->mbmw = 0;
        ruh->mbe = 0;
        ssd->ruhs[i].hbmw = 0;
        ssd->ruhs[i].mbmw = 0;
        ssd->ruhs[i].mbe = 0;
        /*
         * The collection destination is a frontier like curr_ru, on no queue
         * the drain above walks. Left as it was, it points at a unit this
         * reset has handed back, which the next allocation gives to another
         * handle to write into at the same time.
         */
        if (ssd->ruhs[i].gc_ru && ssd->ruhs[i].gc_ru != ssd->ruhs[i].curr_ru) {
            mark_ru_free(ssd, ssd->ruhs[i].gc_ru->rgidx, ssd->ruhs[i].gc_ru);
        }
        ssd->ruhs[i].gc_ru = NULL;
        if (ssd->ruhs[i].curr_ru) {
            mark_ru_free(ssd, ssd->ruhs[i].curr_ru->rgidx,
                         ssd->ruhs[i].curr_ru);
        }
        ssd->ruhs[i].curr_ru = NULL;
        /* every unit was handed back above; count only the ones taken below */
        ssd->ruhs[i].ru_in_use_cnt = 0;
        ssd->ruhs[i].ruh_live_pages_cnt = 0;
        for (rg_idx = 0; rg_idx < (int)ssd->nrg; rg_idx++) {
            ssd->ruhs[i].rus[rg_idx] =
                fdp_get_new_ru(ssd, rg_idx, ssd->ruhs[i].ruhid);
            ssd->ruhs[i].ruh->rus[rg_idx] =
                ssd->ruhs[i].rus[rg_idx]->nvme_ru;
        }
        /* primary RG (index 0) is the active one */
        ssd->ruhs[i].curr_ru = ssd->ruhs[i].rus[0];
    }

    ssd_reset_maptbl(ssd);

    endgrp->fdp.hbmw = 0;
    endgrp->fdp.mbmw = 0;
    endgrp->fdp.mbe = 0;

    ftl_log("FDP TRIM: all RUs reset\n");
}

/*
 * ssd_trim_fdp_style - dispatch FDP DSM deallocate. Range-honoring by default;
 * whole-device reset only when the fdp_trim_erase_all knob is set. Frees the
 * per-command DSM range list either way (nvme_dsm() allocates it per command and
 * leaves it for the FTL to release, as ssd_trim() does on the non-FDP path).
 */
void ssd_trim_fdp_style(FemuCtrl *n, NvmeRequest *req, uint64_t slba,
                               uint32_t nlb)
{
    if (n->bb_params.fdp_trim_erase_all) {
        ssd_trim_fdp_reset_all(n, req, slba, nlb);
    } else {
        ssd_trim_fdp_range(n, req);
    }

    g_free(req->dsm_ranges);
    req->dsm_ranges = NULL;
    req->dsm_nr_ranges = 0;
    req->dsm_attributes = 0;
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

    if (ssd->ruhs) {
        for (i = 0; i < ssd->nruhs; i++) {
            struct ru_mgmt *rm = ssd->ruhs[i].ru_mgmt;

            if (rm) {
                pqueue_free(rm->victim_ru_pq);
                g_free(rm);
            }
            g_free(ssd->ruhs[i].rus);
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
    ssd->nrg = 0;
}
