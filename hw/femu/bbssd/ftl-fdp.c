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

/*
 * ftl_fdp_alloc_event - allocate an FDP event from the FTL layer
 * Used by GC to generate controller events.
 */
static NvmeFdpEvent *ftl_fdp_alloc_event(struct ssd *ssd,
                                          NvmeFdpEventBuffer *ebuf)
{
    NvmeFdpEvent *ret;
    bool is_full = ebuf->next == ebuf->start && ebuf->nelems;

    ret = &ebuf->events[ebuf->next++];
    if (unlikely(ebuf->next == NVME_FDP_MAX_EVENTS)) {
        ebuf->next = 0;
    }
    if (is_full) {
        ebuf->start = ebuf->next;
    } else {
        ebuf->nelems++;
    }

    memset(ret, 0, sizeof(NvmeFdpEvent));
    return ret;
}




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
    wptr->curline = ru->lines[0];
    wptr->ch = 0;
    wptr->lun = 0;
    wptr->pg = 0;
    wptr->blk = wptr->curline->id;
    wptr->pl = 0;
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
    new_ru->last_init_time = qemu_clock_get_us(QEMU_CLOCK_REALTIME);
    new_ru->last_invalidated_time = 0;
    new_ru->erase_cnt = 0;
    new_ru->my_cb = 0.0f;
    new_ru->chance_token = 0;

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
    bool is_full = true;
    bool ru_exhausted = false; /* set when we cross the RU boundary */

    check_addr(wpp->ch, spp->nchs);
    wpp->ch++;
    if (wpp->ch == spp->nchs) {
        wpp->ch = 0;
        check_addr(wpp->lun, spp->luns_per_ch);
        wpp->lun++;
        if (wpp->lun == spp->luns_per_ch) {
            wpp->lun = 0;
            /* then the next plane of the LUN, before moving down the block */
            check_addr(wpp->pl, spp->pls_per_lun);
            wpp->pl++;
            if (wpp->pl < spp->pls_per_lun) {
                return ru;
            }
            wpp->pl = 0;
            check_addr(wpp->pg, spp->pgs_per_blk);
            wpp->pg++;
            if (wpp->pg == spp->pgs_per_blk) {
                //if (ru->next_line_index == ru->n_lines) { - TODO when ru 1->1..* mutliple lines
                wpp->pg = 0;
                ru_exhausted = true;
                /* RU's line(s) are fully written - classify it */
                for (int i = 0; i < ru->n_lines; i++) {
                    struct line *line = ru->lines[i];
                    if (line->vpc != spp->pgs_per_line) {
                        is_full = false;
                    }
                }

                /* update RU vpc from its lines */
                ru->vpc = 0;
                for (int i = 0; i < ru->n_lines; i++) {
                    ru->vpc += ru->lines[i]->vpc;
                }

                if (is_full) {
                    QTAILQ_INSERT_TAIL(&rm->full_ru_list, ru, entry);
                    rm->full_ru_cnt++;
                } else {
                    ru->utilization = (float)ru->vpc / ru->npages;
                    if (rm->mgmt_type == GC_GLOBAL_CB){ 
                        if (ru->utilization < 1.0f && ru->last_invalidated_time > 0) {
                        ru->my_cb = (uint64_t)(100000.0f * ru->utilization /
                            ((1.0f - ru->utilization + 0.001f) *
                            (float)ru->last_invalidated_time));
                        }
                        pqueue_insert(rm->victim_ru_cb, ru);
                    }else{
                        pqueue_insert(rm->victim_ru_pq, ru);
                        //TODO per ruh victim queue - experimental
                    }
                    rm->victim_ru_cnt++;
                }

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
                         */
                        ruh->curr_ru = NULL;
                        ftl_assert(false && __LINE__ );
                        /* TODO */
                        return NULL;
                    }
                    FDP_TRACE(ssd, "RU_ROTATE ruhid=%u(curr_ru %u) old_ru=%u "
                              "new_ru=%u reason=%s victim_ru_cnt %d\n",
                              ruh->ruhid, ruh->curr_ru->ruidx, ru->ruidx, new_ru->ruidx, (is_full)? "full_valid":"full_victim", rm->victim_ru_cnt);
                    wpp = new_ru->ssd_wptr;
                    wpp->blk = wpp->curline->id;
                    check_addr(wpp->blk, spp->blks_per_pl);
                    ftl_assert(wpp->pg == 0);
                    ftl_assert(wpp->lun == 0);
                    ftl_assert(wpp->ch == 0);
                    ftl_assert(wpp->pl == 0);
                }
            }
        }
    }

    /*
     * Return value semantics:
     *   new_ru non-NULL  → RU boundary crossed, new RU allocated
     *   NULL             → RU exhausted but no free RU (device full)
     *   ru               → mid-RU, no boundary crossed yet
     *
     * We use ru_exhausted to distinguish the "device full" NULL from
     * the "mid-RU, returning same ru" case.
     */
    if (new_ru != NULL) {
        return new_ru;
    }
    if (ru_exhausted) {
        /* RU is now in full_ru_list/victim_pq; signal caller via NULL */
        return NULL;
    }
    return ru;
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

    // FDP_TRACE(ssd, "INVAL ppa(ch=%u/lun=%u/blk=%u/pg=%u) "
    //           "ru=%u vpc=%d->%d pos %d was_full=%d victim_ru_cnt=%d\n",
    //           (unsigned)ppa->g.ch, (unsigned)ppa->g.lun,
    //           (unsigned)ppa->g.blk, (unsigned)ppa->g.pg,
    //           ru->ruidx, ru->vpc, ru->vpc - 1, ru->pos,
    //           (ru->vpc == spp->pgs_per_line * ru->n_lines),
    //           rm->victim_ru_cnt);

    /* check if RU was full and needs to move to victim */
    if (ru->vpc == spp->pgs_per_line * ru->n_lines) {
        was_full_ru = true;
    }

    /* update RU vpc and victim queue priority based on GC strategy */
    ru->vpc--;
    ru->utilization = (ru->vpc + ru->ipc > 0) ?
        (float)ru->vpc / (ru->vpc + ru->ipc) : 0.0f;
    ru->last_invalidated_time = qemu_clock_get_us(QEMU_CLOCK_REALTIME);

    switch (rm->mgmt_type) {
    case GC_GLOBAL_GREEDY:
    case GC_GLOBAL_RAND:
    case GC_NOISY_RUH_CUSTOM:
        if (ru->pos) {
            pqueue_change_priority(rm->victim_ru_pq, ru->vpc, ru);
        }
        /*
         * Only GC_NOISY_RUH_CUSTOM consults the per-RUH victim queue; keep its
         * ordering in sync there. The per-RUH heap indexes via ruh_pos, so it
         * no longer aliases the global queue's pos (issue #189). ruh_pos != 0
         * is a valid "in per-RUH queue" marker here because, for this strategy,
         * every per-RUH pop/remove is paired with a ruh_pos reset.
         */
        if (rm->mgmt_type == GC_NOISY_RUH_CUSTOM && ru->ruh_pos &&
            ru->ruh && ru->ruh->ru_mgmt) {
            pqueue_change_priority(ru->ruh->ru_mgmt->victim_ru_pq, ru->vpc, ru);
        }
        if (was_full_ru) {
            QTAILQ_REMOVE(&rm->full_ru_list, ru, entry);
            rm->full_ru_cnt--;
            pqueue_insert(rm->victim_ru_pq, ru);
            rm->victim_ru_cnt++;
            /*
             * Mirror into the per-RUH queue ONLY for the strategy that reads it
             * (GC_NOISY_RUH_CUSTOM). GREEDY/RAND never pop the per-RUH queue, so
             * a second membership there would just go stale on the global pop
             * and later corrupt that heap (issue #189).
             */
            if (rm->mgmt_type == GC_NOISY_RUH_CUSTOM &&
                ru->ruh && ru->ruh->ru_mgmt) {
               pqueue_insert(ru->ruh->ru_mgmt->victim_ru_pq, ru);
               ru->ruh->ru_mgmt->victim_ru_cnt++;
            }
        }
        break;

    case GC_GLOBAL_CB:
        if (ru->utilization < 1.0f && ru->last_invalidated_time > 0) {
            ru->my_cb = (uint64_t)(100000.0f * ru->utilization /
                ((1.0f - ru->utilization + 0.001f) *
                 (float)ru->last_invalidated_time));
        }
        if (ru->pos) {
            pqueue_change_priority(rm->victim_ru_cb, (pqueue_pri_t)ru->my_cb,
                                   ru);
        }
        if (was_full_ru) {
            QTAILQ_REMOVE(&rm->full_ru_list, ru, entry);
            rm->full_ru_cnt--;
            pqueue_insert(rm->victim_ru_cb, ru);
            rm->victim_ru_cnt++;
        }
        break;

    default:
        //Greedy
        ftl_err( "Undefined rg mgmt type (rm->mgmt_type %d). Fallback to Greedy.\n",
              rm->mgmt_type);
        if (ru->pos) {
            pqueue_change_priority(rm->victim_ru_pq, ru->vpc, ru);
        }
        if (was_full_ru) {
            QTAILQ_REMOVE(&rm->full_ru_list, ru, entry);
            rm->full_ru_cnt--;
            pqueue_insert(rm->victim_ru_pq, ru);
            rm->victim_ru_cnt++;
        }
        break;
    }
    if (ru->ruh->ruh_live_pages_cnt > 0)
        ru->ruh->ruh_live_pages_cnt -=1 ;
    
}

//check ru->gc_write_ptr to check or align. 
static int check_gc_ruh_available(struct ssd *ssd, FemuRuHandle * ruh){
    /*
     * The destination RG is derived from ruh->curr_ru; if this RUH has no active
     * RU (fill exhausted it), there is nothing to derive it from and no space to
     * reclaim into, so report failure instead of dereferencing NULL.
     */
    if (ruh->curr_ru == NULL) {
        return -1;
    }
    if(ruh->ruh_type == NVME_RUHT_INITIALLY_ISOLATED){
        if(ssd->ruhs[ssd->nruhs - 1].curr_ru == NULL){
            ssd->ruhs[ssd->nruhs - 1].curr_ru = fdp_get_new_ru(ssd, ruh->curr_ru->rgidx, ruh->ruhid);
            ssd->ruhs[ssd->nruhs - 1].rus[ssd->ruhs[ssd->nruhs - 1].curr_ru->rgidx] = ssd->ruhs[ssd->nruhs - 1].curr_ru;
            //Not neccesary I think for now
            ssd->ruhs[ssd->nruhs - 1].ruh->rus[ssd->ruhs[ssd->nruhs - 1].curr_ru->rgidx] = ssd->ruhs[ssd->nruhs - 1].curr_ru->nvme_ru;  //qemu-system-x86_64: ../hw/femu/bbssd/ftl.c:2106: select_victim_ru: Assertion `victim_ru != ((void *)0)' failed.
        }
        if (ssd->ruhs[ssd->nruhs - 1].curr_ru == NULL){
            //This means no space left
            return -1;
        }

    }
    else if(ruh->ruh_type == NVME_RUHT_PERSISTENTLY_ISOLATED){
        if(ruh->gc_ru == NULL){
            ruh->gc_ru = fdp_get_new_ru(ssd, ruh->curr_ru->rgidx, ruh->ruhid);
            ftl_debug("check_gc_ruh_available ruh %d gc_ru idx %d , %p call new ru  \n", ruh->ruhid, ruh->gc_ru->ruidx, ruh->gc_ru );
            if (ruh->gc_ru == NULL){
                //assert(ruh->gc_ru != NULL);//This means no space left
                return -1;
            }
        }
    }else{
        ftl_err("Unsupported RUH type : %d\n",ruh->ruh_type);
        ftl_assert(false && __LINE__); 
    }
    return 0;
}

/*
 * select_victim_ru_from_ruh - pick victim from a specific RUH's queue
 */
static FemuReclaimUnit *select_victim_ru_from_ruh(struct ssd *ssd,
                                                   uint16_t rgid,
                                                   uint16_t ruhid)
{
    FemuReclaimUnit *victim_ru = NULL;
    struct ru_mgmt *ru_mgmt = ssd->ruhs[ruhid].ru_mgmt;

    if (!ru_mgmt) {
        return NULL;
    }

    victim_ru = pqueue_pop(ru_mgmt->victim_ru_pq);
    if (victim_ru) {
        /*
         * pqueue_pop does not clear the popped element's stored index, so reset
         * ruh_pos to keep it a truthful "not in per-RUH queue" marker (same
         * discipline as the NOISY path). Without this, a later change_priority
         * or insert could act on a stale per-RUH index -- the issue #189 bug
         * class. Dormant today (no strategy fills the per-RUH queue on this
         * path) but hardened for when one does.
         */
        victim_ru->ruh_pos = 0;
        ru_mgmt->victim_ru_cnt--;
    }
    return victim_ru;
}

/*
 * select_victim_ru - pick best victim RU based on configured GC strategy
 */
static FemuReclaimUnit *select_victim_ru(struct ssd *ssd, uint16_t rgid,
                                         uint16_t ruhid, bool force)
{
    struct ru_mgmt *rm = ssd->rg[rgid].ru_mgmt;
    FemuReclaimUnit *victim_ru = NULL;

    switch (rm->mgmt_type) {
    case GC_GLOBAL_GREEDY:
        victim_ru = pqueue_pop(rm->victim_ru_pq);
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
        if (victim_ru) {
            pqueue_remove(pq, victim_ru);
        }
        break;
    }

    case GC_GLOBAL_RAND:
        victim_ru = pqueue_randpop(rm->victim_ru_pq);
        break;

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
        if (best_ruh >= 0) {
            victim_ru = pqueue_pop(
                ssd->ruhs[best_ruh].ru_mgmt->victim_ru_pq);
            if (victim_ru) {
                /*
                 * pqueue_pop does NOT clear the element's stored index, so reset
                 * ruh_pos explicitly to keep it a truthful "in per-RUH queue"
                 * marker (the change_priority guard relies on it).
                 */
                victim_ru->ruh_pos = 0;
                ssd->ruhs[best_ruh].ru_mgmt->victim_ru_cnt--;
                /*
                 * Also remove from the global queue (uses the still-valid pos);
                 * the global victim_ru_cnt-- and pos=0 happen at the shared
                 * cleanup below, so do not touch them here. With nrg>1 the
                 * per-RUH queue can hold RUs from any RG, so the global twin
                 * lives in the victim's OWN RG queue, not the caller's rgid.
                 */
                if (victim_ru->pos) {
                    pqueue_remove(ssd->rg[victim_ru->rgidx].ru_mgmt->victim_ru_pq,
                                  victim_ru);
                }
            }
        } else {
            /* fallback to global greedy */
            victim_ru = pqueue_pop(rm->victim_ru_pq);
            /*
             * The global-popped RU may still have a per-RUH twin (NOISY mirrors
             * full RUs into both queues). Drop it from the per-RUH queue here,
             * using the still-valid ruh_pos, so it does not linger as a stale
             * entry (later change_priority / duplicate insert on put-back).
             */
            if (victim_ru && victim_ru->ruh_pos &&
                victim_ru->ruh && victim_ru->ruh->ru_mgmt) {
                pqueue_remove(victim_ru->ruh->ru_mgmt->victim_ru_pq, victim_ru);
                victim_ru->ruh_pos = 0;
                victim_ru->ruh->ru_mgmt->victim_ru_cnt--;
            }
        }
        break;
    }

    case GC_SELECTIVE_RUH:
    case GC_EXPLOIT_SEQUENTIAL:
        victim_ru = pqueue_pop(rm->victim_ru_pq);
        break;

    case GC_SELECTIVE_RUH_SOCIAL_WELFARE:
        victim_ru = select_victim_ru_from_ruh(ssd, rgid, ruhid);
        break;

    case GC_BIT_POPULATION:
    case GC_GLOBAL_WARM:
    case GC_SELECTIVE_RUH_ADV:
    case GC_SELECTIVE_MIDAS_OP:
    default:
        /* fallback to greedy */
        victim_ru = pqueue_pop(rm->victim_ru_pq);
        break;
    }

    if (!victim_ru) {
        /*
         * victim_ru_pq is empty: all in-use RUs are still fully written
         * with no invalidations yet (e.g., during sequential fill). There is
         * no victim to reclaim, so returning NULL is the correct behavior.
         */
        return NULL;
    }

    if (!force && victim_ru->vpc > 0) {
        int threshold = victim_ru->npages / 8;
        if (victim_ru->ipc < threshold) {
            /*
             * Delay GC and put the victim back. Cross-RG NOISY selection can
             * return an RU that belongs to a different reclaim group than the
             * caller's rgid, so re-insert it into the victim's OWN RG queue --
             * matching the global removal above and the shared count decrement
             * below. Using the caller's rm here would charge the entry to the
             * wrong heap, and its stored pos would then index that wrong array
             * on a later remove/change_priority, corrupting the queue.
             */
            struct ru_mgmt *victim_rm = ssd->rg[victim_ru->rgidx].ru_mgmt;
            /* put it back */
            FDP_TRACE(ssd, "GC_BACK_RESERT triggered but delay GC (ru %d ipc %d threshold %d full %d)\n",victim_ru->ruidx, victim_ru->ipc, threshold, victim_ru->npages);
            if (victim_rm->mgmt_type == GC_GLOBAL_CB){
                pqueue_insert(victim_rm->victim_ru_cb, victim_ru);
            }else{
                pqueue_insert(victim_rm->victim_ru_pq, victim_ru);
                /*
                 * GC_NOISY_RUH_CUSTOM selection popped this RU from BOTH the
                 * per-RUH and global queues (and zeroed ruh_pos + decremented
                 * the per-RUH count). Restore the per-RUH membership and count
                 * too, or they fall out of sync. pqueue_insert re-sets ruh_pos.
                 */
                if (victim_rm->mgmt_type == GC_NOISY_RUH_CUSTOM &&
                    victim_ru->ruh && victim_ru->ruh->ru_mgmt) {
                    pqueue_insert(victim_ru->ruh->ru_mgmt->victim_ru_pq,
                                  victim_ru);
                    victim_ru->ruh->ru_mgmt->victim_ru_cnt++;
                }
            }
            return NULL;
        }
    }

    victim_ru->pos = 0;
    victim_ru->ruh_pos = 0;
    /*
     * Decrement the count on the victim's OWN reclaim group. For every path
     * except cross-RG NOISY selection this is the caller's rgid; NOISY can pull
     * a victim from another RG, whose global count must be the one adjusted.
     */
    ssd->rg[victim_ru->rgidx].ru_mgmt->victim_ru_cnt--;

    return victim_ru;
}

/*
 * gc_write_page_fdp_style - relocate a valid page to a GC destination RU
 */
static void gc_write_page_fdp_style(struct ssd *ssd, struct ppa *old_ppa,
                                    FemuRuHandle *dest_ruh)
{
    struct ppa new_ppa;
    struct nand_lun *new_lun;
    uint64_t lpn = get_rmap_ent(ssd, old_ppa);
    FemuReclaimUnit *dest_ru=NULL;
    FemuReclaimUnit *ret_ru=NULL;
    ftl_assert(valid_lpn(ssd, lpn));
    ftl_assert(dest_ruh!=NULL);
    /* gc_write_page_fdp_style() guarantees ruh->curr_ru or ->gc_ru wtpr, not new_ru. */
    if (dest_ruh->ruh_type == NVME_RUHT_PERSISTENTLY_ISOLATED)
    {
        dest_ru = dest_ruh->gc_ru;
    }else if( dest_ruh->ruh_type == NVME_RUHT_INITIALLY_ISOLATED && dest_ruh->ruhid == ssd->ruhs[ssd->nruhs-1].ruhid ){
        dest_ru = dest_ruh->curr_ru;
    }else{
        ftl_err("Unidentified ruht. ");
        ftl_assert(false && __LINE__);
    }

    new_ppa = fdp_get_new_page(ssd, dest_ru);
    set_maptbl_ent(ssd, lpn, &new_ppa);
    set_rmap_ent(ssd, lpn, &new_ppa);
    mark_page_valid_fdp(ssd, &new_ppa, dest_ru);
    ssd->gc_write_pages++; /* a page the device relocated itself */

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

    if(dest_ruh->ruh_type == NVME_RUHT_PERSISTENTLY_ISOLATED ){
        // handle ruh->ru pointer after adv
        if( (ret_ru = fdp_advance_ru_pointer(ssd, &ssd->rg[dest_ru->rgidx], dest_ru->ruh, dest_ru)) != dest_ru){
            dest_ruh->gc_ru = ret_ru;
        }
    }else if (dest_ruh->ruh_type == NVME_RUHT_INITIALLY_ISOLATED ){
        int gcruh_id = ssd->nruhs-1;
        ftl_assert( dest_ruh->ruhid == gcruh_id );
        if( (ret_ru = fdp_advance_ru_pointer(ssd, &ssd->rg[dest_ru->rgidx], dest_ruh, dest_ru)) != dest_ru ) {
            //Do ugly updates
            ssd->ruhs[gcruh_id].rus[dest_ru->rgidx] = ret_ru;
            ssd->ruhs[gcruh_id].curr_ru = ret_ru;
            ssd->ruhs[gcruh_id].ruh->rus[dest_ru->rgidx] = ret_ru->nvme_ru;
        } 
    }
    
    ftl_assert((ret_ru != NULL));

    if (ssd->sp.enable_gc_delay) {
        struct nand_cmd gcw;
        gcw.type = GC_IO;
        gcw.cmd = NAND_WRITE;
        gcw.stime = 0;
        ssd_advance_status(ssd, &new_ppa, &gcw);
    }

    new_lun = get_lun(ssd, &new_ppa);
    new_lun->gc_endtime = new_lun->next_lun_avail_time;
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
static int clean_one_block_fdp_style(struct ssd *ssd, struct ppa *ppa,
                                     FemuRuHandle *dest_ruh)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_page *pg_iter;
    int cnt = 0;
    for (int pg = 0; pg < spp->pgs_per_blk; pg++) {
        ppa->g.pg = pg;
        pg_iter = get_pg(ssd, ppa);
        ftl_assert(pg_iter->status != PG_FREE);
        if (pg_iter->status == PG_VALID) {
            gc_read_page(ssd, ppa);
            gc_write_page_fdp_style(ssd, ppa, dest_ruh);
            cnt++;
        }
    }

    ftl_assert(get_blk(ssd, ppa)->vpc == cnt);
    return cnt;
}

/*
 * mark_ru_free - reset a victim RU to free state after GC
 */
static void mark_ru_free(struct ssd *ssd, uint16_t rgid,
                         FemuReclaimUnit *ru)
{
    struct ssdparams *spp = &ssd->sp;
    struct ru_mgmt *rm = ssd->rg[rgid].ru_mgmt;
    struct ppa ppa;

    ftl_assert(ru != NULL);

    for (int i = 0; i < ru->n_lines; i++) {
        ru->lines[i]->ipc = 0;
        ru->lines[i]->vpc = 0;
        ru->lines[i]->pos = 0;
        ppa.g.blk = ru->lines[i]->id;
        for (int ch = 0; ch < spp->nchs; ch++) {
            for (int lun = 0; lun < spp->luns_per_ch; lun++) {
                for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                    ppa.g.ch = ch;
                    ppa.g.lun = lun;
                    ppa.g.pl = pl;
                    mark_block_free(ssd, &ppa);
                }
            }
        }
    }

    ru->vpc = 0;
    ru->ipc = 0;
    ru->pos = 0;
    ru->ruh_pos = 0;
    ru->next_line_index = 1;
    ru->utilization = 0.0f;
    ru->my_cb = 0.0f;
    ru->erase_cnt++;
    ru->chance_token = 0;

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
 * reinsert_victim_ru - return a fully-popped victim RU to its own reclaim
 * group's victim queue. Used when GC cannot proceed (no free destination RU),
 * so the victim is not orphaned. Reverses the bookkeeping select_victim_ru()
 * performed when it returned this victim, always keying off the victim's own
 * reclaim group so a cross-RG NOISY victim goes back to the right heap.
 */
static void reinsert_victim_ru(struct ssd *ssd, FemuReclaimUnit *victim_ru)
{
    struct ru_mgmt *victim_rm = ssd->rg[victim_ru->rgidx].ru_mgmt;

    if (victim_rm->mgmt_type == GC_GLOBAL_CB) {
        pqueue_insert(victim_rm->victim_ru_cb, victim_ru);
    } else {
        pqueue_insert(victim_rm->victim_ru_pq, victim_ru);
        if (victim_rm->mgmt_type == GC_NOISY_RUH_CUSTOM &&
            victim_ru->ruh && victim_ru->ruh->ru_mgmt) {
            pqueue_insert(victim_ru->ruh->ru_mgmt->victim_ru_pq, victim_ru);
            victim_ru->ruh->ru_mgmt->victim_ru_cnt++;
        }
    }
    victim_rm->victim_ru_cnt++;
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
    struct nand_lun *lunp;
    struct ppa ppa;
    int vpc_cnt = 0;
    int blk_cnt = 0;
    int ret = 0;
    victim_ru = select_victim_ru(ssd, rgid, ruhid, force);
    if (!victim_ru) {
        //FDP_TRACE(ssd,"GC_SKIP Unable to find victim RU, gc skip\n");
        return -1;
    }

    /*
     * Select GC destination RU based on RUH isolation type:
     * - Initially Isolated (II): GC writes go to the last RUH (GC RUH)
     * - Persistently Isolated (PI): GC writes go to same RUH's gc_ru
     */
    /*
     * Select GC destination RU.
     *
     * Design principle: GC writes compete for the same write frontier
     * as host writes.  We use the victim RUH's current active RU
     * (curr_ru) as the GC destination.  This avoids allocating a
     * dedicated gc_ru, which would consume a free RU and could cause
     * deadlock when free_ru_cnt is low.
     *
     * For PI (Persistently Isolated) RUHs: write migrated pages back
     * into the same RUH's curr_ru, maintaining stream isolation.
     * For II (Initially Isolated) RUHs: write to the last RUH's curr_ru
     * (the convention for II GC isolation).
     *
     * If curr_ru is the same as victim_ru (the RUH only has one RU),
     * we cannot GC without first getting a free RU.  In that case,
     * if no free RU is available, we skip this victim.
     */
    FemuRuHandle *victim_ruh = victim_ru->ruh;
    FemuRuHandle *dest_ruh = NULL;

    if (victim_ruh->ruh_type == NVME_RUHT_PERSISTENTLY_ISOLATED) {
        dest_ruh = victim_ruh;
        /* PI RUH: GC writes go to a dedicated gc_ru, distinct from curr_ru. */
        if ((ret = check_gc_ruh_available(ssd, dest_ruh)) < 0 ){
            /*
             * No free RU for the GC destination means the device is genuinely
             * out of reclaimable space. Put the victim back and fail the GC pass
             * rather than aborting the emulator; the caller degrades to a normal
             * device-full write outcome.
             */
            reinsert_victim_ru(ssd, victim_ru);
            return -1;
        }

    } else if (victim_ruh->ruh_type == NVME_RUHT_INITIALLY_ISOLATED){
        /* II RUH: GC writes go to the last RUH's curr_ru. */
        dest_ruh = &ssd->ruhs[ssd->nruhs - 1];
        if ((ret = check_gc_ruh_available(ssd, dest_ruh)) < 0 ){
            reinsert_victim_ru(ssd, victim_ru);
            return -1;
        }
    }else {
        ftl_err("Undefined RUHT.");
        ftl_assert(false && __LINE__);
    }
    ftl_assert(dest_ruh!=NULL);
    /* sanity: don't GC an active RU */
    if (victim_ru == victim_ru->ruh->curr_ru) {
        ftl_err("Victim RU %d is active, skipping GC\n", victim_ru->ruidx);
        //This is a bug.
        ftl_assert(false && __LINE__);
        return -1;
    }

    FDP_TRACE(ssd, "GC_START rgid=%u ruhid=%u victim_ru=%u "
              "victim_vpc=%d isolation=%s gc_type=%s\n",
              rgid, ruhid, victim_ru->ruidx, victim_ru->vpc,
              (victim_ruh->ruh_type == NVME_RUHT_PERSISTENTLY_ISOLATED) ?
              "PI" : "II", (force) ? "FORCE" : "BACK" );

    /* migrate valid pages from victim RU */
    for (int i = 0; i < spp->lines_per_ru; i++) {
        struct line *victim_line = victim_ru->lines[i];
        ppa.g.blk = victim_line->id;
        for (int ch = 0; ch < spp->nchs; ch++) {
            for (int lun = 0; lun < spp->luns_per_ch; lun++) {
                struct ppa ppas[1 << PL_BITS];

                ppa.g.ch = ch;
                ppa.g.lun = lun;
                ppa.g.pl = 0;
                lunp = get_lun(ssd, &ppa);

                for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                    ppa.g.pl = pl;
                    vpc_cnt += clean_one_block_fdp_style(ssd, &ppa, dest_ruh);
                    blk_cnt++;
                    mark_block_free(ssd, &ppa);
                    ppas[pl] = ppa;
                }

                /* the die erases the line's planes in one operation */
                if (spp->enable_gc_delay) {
                    struct nand_cmd gce;
                    gce.type = GC_IO;
                    gce.cmd = NAND_ERASE;
                    gce.stime = 0;
                    ssd_advance_status_multiplane(ssd, ppas, spp->pls_per_lun,
                                                  &gce);
                }
                lunp->gc_endtime = lunp->next_lun_avail_time;
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
    nvme_fdp_stat_inc(&ssd->n->subsys->endgrp.fdp.mbmw, gc_bytes);
    nvme_fdp_stat_inc(&victim_ru->ruh->mbmw, gc_bytes);
    nvme_fdp_stat_inc(&victim_ru->ruh->ruh->mbmw, gc_bytes);
    nvme_fdp_stat_inc(&ssd->n->subsys->endgrp.fdp.mbe, erase_bytes);
    nvme_fdp_stat_inc(&victim_ru->ruh->mbe, erase_bytes);
    nvme_fdp_stat_inc(&victim_ru->ruh->ruh->mbe, erase_bytes);

    if (ssd->ruhs[victim_ru->ruh->ruhid].ru_in_use_cnt > 0) {
        ssd->ruhs[victim_ru->ruh->ruhid].ru_in_use_cnt--;
    }
    ssd->ruhs[victim_ru->ruh->ruhid].ruh_live_pages_cnt -= vpc_cnt;

    /* generate controller event for RU change due to GC */
    if (ssd->n->subsys) {
        NvmeEnduranceGroup *endgrp = &ssd->n->subsys->endgrp;
        NvmeRuHandle *nvme_ruh = victim_ru->ruh->ruh;
        if (nvme_ruh &&
            (nvme_ruh->event_filter >>
             nvme_fdp_evf_shifts[FDP_EVT_RUH_IMPLICIT_RU_CHANGE]) & 0x1) {
            NvmeFdpEvent *e = ftl_fdp_alloc_event(ssd,
                                    &endgrp->fdp.ctrl_events);
            e->type = FDP_EVT_RUH_IMPLICIT_RU_CHANGE;
            e->flags = FDPEF_LV;
            e->rgid = cpu_to_le16(victim_ru->rgidx);
            e->ruhid = victim_ru->ruh->ruhid;
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

/*
 * ssd_stream_write - FDP write path: placement-aware page allocation
 */
static uint64_t ssd_stream_write(FemuCtrl *n, struct ssd *ssd,
                                 NvmeRequest *req)
{
    NvmeNamespace *ns = req->ns;
    struct ssdparams *spp = &ssd->sp;
    FemuReclaimGroup *rg;
    FemuRuHandle *ruh;
    FemuReclaimUnit *ru;

    uint64_t lba = req->slba;
    int len = req->nlb;
    uint64_t start_lpn = lba / spp->secs_per_pg;
    uint64_t end_lpn = (lba + len - 1) / spp->secs_per_pg;
    struct ppa ppa;
    uint64_t lpn;
    uint64_t curlat = 0, maxlat = 0;
    int r;

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
                NvmeFdpEvent *e = ftl_fdp_alloc_event(ssd,
                                        &endgrp->fdp.host_events);
                e->type = FDP_EVT_INVALID_PID;
                e->flags = FDPEF_PIV | FDPEF_NSIDV;
                e->pid = cpu_to_le16(pid);
                e->nsid = cpu_to_le32(ns->id);
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
    {
        uint64_t fg_gc_iters = 0;
        uint64_t max_fg_gc = (uint64_t)ssd->nrg * ssd->rg[0].ru_mgmt->tt_rus
                             + ssd->nrg;
        while (should_gc_high_fdp_style(ssd) >= 0 &&
               fg_gc_iters < max_fg_gc) {
            r = do_gc_fdp_style(ssd, rgid, ruhid, true);
            if (r == -1) {
                break;
            }
            fg_gc_iters++;
        }
    }

    /* pages the host wrote; the WAF denominator, as on the non-FDP path */
    ssd->host_write_pages += end_lpn - start_lpn + 1;

    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
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

        /* RUAMW counts logical blocks; a page holds secs_per_pg of them */
        if (ru->nvme_ru) {
            ru->nvme_ru->ruamw -= MIN(ru->nvme_ru->ruamw,
                                      (uint64_t)spp->secs_per_pg);
        }

        /* advance RU write pointer; may allocate new RU */
        FemuReclaimUnit *ret = fdp_advance_ru_pointer(ssd, rg, ruh, ru);
        if (ret && ret != ruh->curr_ru) {
            ruh->rus[rgid] = ret;
            ruh->curr_ru = ret;
            ruh->ruh->rus[rgid] = ret->nvme_ru;
            ru = ret;
        } else if (!ret) {
            /*
             * fdp_advance_ru_pointer cleared curr_ru (no free RU).
             * The while loop at the top of next iteration will handle it.
             */
            ru = NULL;
        }

        struct nand_cmd swr;
        swr.type = USER_IO;
        swr.cmd = NAND_WRITE;
        swr.stime = req->stime;
        curlat = ssd_advance_status(ssd, &ppa, &swr);
        maxlat = (curlat > maxlat) ? curlat : maxlat;
    }

    return maxlat;
}

/*
 * nvme_do_write_fdp - top-level FDP write: stats + stream write
 */
uint64_t nvme_do_write_fdp(FemuCtrl *n, NvmeRequest *req, uint64_t slba,
                           uint32_t nlb)
{
    NvmeNamespace *ns = req->ns;
    struct ssd *ssd = n->ssd;
    struct ssdparams *spp = &ssd->sp;
    uint64_t data_bytes;

    /* update FDP host bytes written stats */
    data_bytes = (uint64_t)nlb * spp->secsz;
    nvme_fdp_stat_inc(&ns->endgrp->fdp.hbmw, data_bytes);
    nvme_fdp_stat_inc(&ns->endgrp->fdp.mbmw, data_bytes);

    /* per-RUH stats */
    uint16_t pid = req->fdp_dspec;
    uint8_t dtype = req->fdp_dtype;
    uint16_t ph, rg, ruhid;

    if (dtype != NVME_DIRECTIVE_DATA_PLACEMENT ||
        !nvme_parse_pid(ns, pid, &ph, &rg)) {
        ph = 0;
        rg = 0;
    }
    ruhid = ns->fdp.phs[ph];
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].hbmw, data_bytes);
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].ruh->hbmw, data_bytes);
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].mbmw, data_bytes);
    nvme_fdp_stat_inc(&ssd->ruhs[ruhid].ruh->mbmw, data_bytes);

    return ssd_stream_write(n, ssd, req);
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
    rm->victim_ru_cnt = 0;
    rm->full_ru_cnt = 0;
    rm->custom_gc_threshold = 0;

    /* default GC strategy */
    rm->mgmt_type = GC_GLOBAL_GREEDY;

    rm->is_gc_triggered = false;
    rm->is_force_gc_triggered = false;
    rm->waf_score_global = 0.0f;
    rm->waf_score_transitory = 0.0f;
    rm->utilization_overall = 0.0f;

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
    femu_ru->next_line_index = 1;
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
                (uint64_t)((1 - rg->ru_mgmt->gc_thres_pcent_high) *
                           rg->tt_nru);
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
        ssd->ruhs[i].curr_rg = 0;
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
         * The active RU must match the default reclaim group (rgid 0, curr_rg
         * 0), not the last one allocated by the loop above. A non-placement
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
            ssd->ruhs[i].ru_mgmt->victim_ru_cnt = 0;
            ssd->ruhs[i].ru_mgmt->full_ru_cnt = 0;
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
            ssd->ruhs[i].ru_mgmt->victim_ru_cb =
                pqueue_init(ssd->rg[0].tt_nru, victim_ru_cmp_pri_by_cb,
                            victim_ru_get_pri_by_cb,
                            victim_ru_set_pri_by_cb,
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
        uint64_t r_slba = le64_to_cpu(ranges[range_idx].slba);
        uint32_t r_nlb = le32_to_cpu(ranges[range_idx].nlb);
        uint64_t start_lpn = r_slba / spp->secs_per_pg;
        uint64_t end_lpn = (r_slba + r_nlb - 1) / spp->secs_per_pg;

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
void ssd_write_zeroes_fdp_style(FemuCtrl *n, NvmeRequest *req)
{
    struct ssd *ssd = (req->ns && req->ns->ssd) ? req->ns->ssd : n->ssd;
    struct ssdparams *spp = &ssd->sp;
    const NvmeRwCmd *rw = (const NvmeRwCmd *)&req->cmd;
    uint64_t lba = le64_to_cpu(rw->slba) + ssd_ns_lba_base(ssd, req);
    uint32_t nlb = le16_to_cpu(rw->nlb) + 1;
    uint64_t start_lpn = lba / spp->secs_per_pg;
    uint64_t end_lpn = (lba + nlb - 1) / spp->secs_per_pg;
    int already_invalid = 0;

    if (!(le16_to_cpu(rw->control) & NVME_WZ_DEAC)) {
        return;
    }
    if (end_lpn >= spp->tt_pgs) {
        return;
    }

    ssd_deallocate_fdp_lpns(ssd, start_lpn, end_lpn, &already_invalid);
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
    struct ppa ppa;
    NvmeEnduranceGroup *endgrp = &n->subsys->endgrp;
    FemuReclaimUnit *v_ru;
    struct nand_lun *lunp;
    NvmeRuHandle *ruh;
    int rg_idx;

    /* erase all blocks */
    for (int ch = 0; ch < spp->nchs; ch++) {
        for (int lun = 0; lun < spp->luns_per_ch; lun++) {
            for (int blk = 0; blk < spp->blks_per_pl; blk++) {
                struct ppa ppas[1 << PL_BITS];

                ppa.g.ch = ch;
                ppa.g.lun = lun;
                ppa.g.pl = 0;
                ppa.g.blk = blk;
                lunp = get_lun(ssd, &ppa);

                for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                    ppa.g.pl = pl;
                    mark_block_free(ssd, &ppa);
                    ppas[pl] = ppa;
                }

                if (spp->enable_gc_delay) {
                    struct nand_cmd gce;
                    gce.type = GC_IO;
                    gce.cmd = NAND_ERASE;
                    gce.stime = 0;
                    ssd_advance_status_multiplane(ssd, ppas, spp->pls_per_lun,
                                                  &gce);
                }
                lunp->gc_endtime = lunp->next_lun_avail_time;
            }
        }
    }

    /* drain victim and full RU queues for all reclaim groups */
    for (rg_idx = 0; rg_idx < (int)ssd->nrg; rg_idx++) {
        struct ru_mgmt *rm = ssd->rg[rg_idx].ru_mgmt;
        while ((v_ru = pqueue_peek(rm->victim_ru_pq)) != NULL) {
            pqueue_remove(rm->victim_ru_pq, v_ru);
            rm->victim_ru_cnt--;
            mark_ru_free(ssd, v_ru->rgidx, v_ru);
        }
        /*
         * GC_GLOBAL_CB keeps its full victims in victim_ru_cb, not
         * victim_ru_pq, so drain it too or those RUs leak with a stale
         * victim_ru_cnt on trim/format. The two queues are mutually exclusive
         * per RG mode (the inactive one is empty here) and victim_ru_cb indexes
         * via the same pos field, so this is safe; guard the shared count
         * against underflow in case it was already inconsistent.
         */
        while ((v_ru = pqueue_peek(rm->victim_ru_cb)) != NULL) {
            pqueue_remove(rm->victim_ru_cb, v_ru);
            if (rm->victim_ru_cnt > 0) {
                rm->victim_ru_cnt--;
            }
            mark_ru_free(ssd, v_ru->rgidx, v_ru);
        }
        while ((v_ru = QTAILQ_FIRST(&rm->full_ru_list)) != NULL) {
            QTAILQ_REMOVE(&rm->full_ru_list, v_ru, entry);
            rm->full_ru_cnt--;
            mark_ru_free(ssd, v_ru->rgidx, v_ru);
        }
    }

    /* reset active RUs and stats for each RUH across all RGs */
    ruh = endgrp->fdp.ruhs;
    for (int i = 0; i < (int)endgrp->fdp.nruh; i++, ruh++) {
        /*
         * Empty this RUH's victim queue too. The per-RG drain above freed the
         * RUs (and zeroed their ruh_pos via mark_ru_free), but the per-RUH heap
         * still physically references them; drop those stale entries so trim
         * leaves the per-RUH queue consistent (PI RUHs only). The RU objects
         * are already freed, so just clear the heap and its counter.
         */
        if (ssd->ruhs[i].ru_mgmt && ssd->ruhs[i].ru_mgmt->victim_ru_pq) {
            FemuReclaimUnit *pru;
            /*
             * pqueue_pop reassigns ruh_pos during percolate_down and never
             * clears the popped element's own index, so zero it explicitly or
             * a drained RU keeps a stale ruh_pos and later looks "in queue".
             */
            while ((pru = pqueue_pop(ssd->ruhs[i].ru_mgmt->victim_ru_pq))) {
                pru->ruh_pos = 0;
            }
            ssd->ruhs[i].ru_mgmt->victim_ru_cnt = 0;
        }
        ruh->hbmw = 0;
        ruh->mbmw = 0;
        ruh->mbe = 0;
        ssd->ruhs[i].hbmw = 0;
        ssd->ruhs[i].mbmw = 0;
        ssd->ruhs[i].mbe = 0;
        if (ssd->ruhs[i].curr_ru) {
            mark_ru_free(ssd, ssd->ruhs[i].curr_ru->rgidx,
                         ssd->ruhs[i].curr_ru);
        }
        ssd->ruhs[i].curr_ru = NULL;
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
