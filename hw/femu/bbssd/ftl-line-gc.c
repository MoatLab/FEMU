/*
 * bbssd FTL line management and garbage collection.
 *
 * Owns the free/victim/full line lists, the write pointer, page/block/line
 * valid-invalid bookkeeping, and the greedy GC (victim selection, valid-page
 * copyback, block erase). Split out of the ftl.c monolith; the FDP-specific
 * reclaim-unit machinery lives separately.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"

/* victim-line priority-queue callbacks */
static inline int victim_line_cmp_pri(pqueue_pri_t next, pqueue_pri_t curr)
{
    return (next > curr);
}

static inline pqueue_pri_t victim_line_get_pri(void *a)
{
    return ((struct line *)a)->vpc;
}

static inline void victim_line_set_pri(void *a, pqueue_pri_t pri)
{
    ((struct line *)a)->vpc = pri;
}

static inline size_t victim_line_get_pos(void *a)
{
    return ((struct line *)a)->pos;
}

static inline void victim_line_set_pos(void *a, size_t pos)
{
    ((struct line *)a)->pos = pos;
}

void ssd_init_lines(struct ssd *ssd)
{
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;
    struct line *line;

    lm->tt_lines = spp->blks_per_pl;
    ftl_assert(lm->tt_lines == spp->tt_lines);
    lm->lines = g_malloc0(sizeof(struct line) * lm->tt_lines);

    QTAILQ_INIT(&lm->free_line_list);
    lm->victim_line_pq = pqueue_init(spp->tt_lines, victim_line_cmp_pri,
            victim_line_get_pri, victim_line_set_pri,
            victim_line_get_pos, victim_line_set_pos);
    QTAILQ_INIT(&lm->full_line_list);

    lm->free_line_cnt = 0;
    for (int i = 0; i < lm->tt_lines; i++) {
        line = &lm->lines[i];
        line->id = i;
        line->ipc = 0;
        line->vpc = 0;
        line->pos = 0;
        line->close_time = 0;
        /* initialize all the lines as free lines */
        QTAILQ_INSERT_TAIL(&lm->free_line_list, line, entry);
        lm->free_line_cnt++;
    }

    ftl_assert(lm->free_line_cnt == lm->tt_lines);
    lm->victim_line_cnt = 0;
    lm->full_line_cnt = 0;
}

void ssd_init_write_pointer(struct ssd *ssd)
{
    struct write_pointer *wpp = &ssd->wp;
    struct line_mgmt *lm = &ssd->lm;
    struct line *curline = NULL;

    curline = QTAILQ_FIRST(&lm->free_line_list);
    QTAILQ_REMOVE(&lm->free_line_list, curline, entry);
    lm->free_line_cnt--;

    /* wpp->curline is always our next-to-write super-block */
    wpp->curline = curline;
    wpp->ch = 0;
    wpp->lun = 0;
    wpp->pg = 0;
    wpp->blk = 0;
    wpp->pl = 0;

    /* DRAM write buffer: LRU queue plus a tree for lookup by page number */
    QTAILQ_INIT(&ssd->write_buffer);
    ssd->write_buffer_cnt = 0;
    ssd->wb_tree = ssd->sp.buffer_size > 0 ? g_tree_new(comp_buffer) : NULL;
}


struct line *get_next_free_line(struct ssd *ssd)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *curline = NULL;

    curline = QTAILQ_FIRST(&lm->free_line_list);
    if (!curline) {
        ftl_err("No free lines left in [%s] !!!!\n", ssd->ssdname);
        return NULL;
    }

    QTAILQ_REMOVE(&lm->free_line_list, curline, entry);
    lm->free_line_cnt--;
    return curline;
}

static void ssd_advance_write_pointer_common(struct ssd *ssd,
                                             struct write_pointer *wpp)
{
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;

    check_addr(wpp->ch, spp->nchs);
    wpp->ch++;
    if (wpp->ch == spp->nchs) {
        wpp->ch = 0;
        check_addr(wpp->lun, spp->luns_per_ch);
        wpp->lun++;
        /* in this case, we should go to next lun */
        if (wpp->lun == spp->luns_per_ch) {
            wpp->lun = 0;
            /* then the next plane of the LUN, before moving down the block */
            check_addr(wpp->pl, spp->pls_per_lun);
            wpp->pl++;
            if (wpp->pl < spp->pls_per_lun) {
                return;
            }
            wpp->pl = 0;
            /* go to next page in the block */
            check_addr(wpp->pg, spp->pgs_per_blk);
            wpp->pg++;
            if (wpp->pg == spp->pgs_per_blk) {
                wpp->pg = 0;
                /* record when the line filled, for age-based GC policies */
                wpp->curline->close_time =
                    qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
                /* move current line to {victim,full} line list */
                if (wpp->curline->vpc == spp->pgs_per_line) {
                    /* all pgs are still valid, move to full line list */
                    ftl_assert(wpp->curline->ipc == 0);
                    QTAILQ_INSERT_TAIL(&lm->full_line_list, wpp->curline, entry);
                    lm->full_line_cnt++;
                } else {
                    ftl_assert(wpp->curline->vpc >= 0 && wpp->curline->vpc < spp->pgs_per_line);
                    /* there must be some invalid pages in this line */
                    ftl_assert(wpp->curline->ipc > 0);
                    pqueue_insert(lm->victim_line_pq, wpp->curline);
                    lm->victim_line_cnt++;
                }
                /* current line is used up, pick another empty line */
                check_addr(wpp->blk, spp->blks_per_pl);
                wpp->curline = NULL;
                wpp->curline = get_next_free_line(ssd);
                if (!wpp->curline) {
                    /* TODO */
                    abort();
                }
                wpp->blk = wpp->curline->id;
                check_addr(wpp->blk, spp->blks_per_pl);
                /* make sure we are starting from page 0 in the super block */
                ftl_assert(wpp->pg == 0);
                ftl_assert(wpp->lun == 0);
                ftl_assert(wpp->ch == 0);
                /* TODO: assume # of pl_per_lun is 1, fix later */
                ftl_assert(wpp->pl == 0);
            }
        }
    }
}

/* take a line for a class that allocates one lazily (LOG, HOT) */
static void ssd_init_class_write_pointer(struct ssd *ssd,
                                         struct write_pointer *wpp,
                                         const char *what)
{
    struct line *curline = get_next_free_line(ssd);

    if (!curline) {
        ftl_err("no free line for the %s class in [%s]\n", what, ssd->ssdname);
        return;
    }

    wpp->curline = curline;
    wpp->ch = 0;
    wpp->lun = 0;
    wpp->pg = 0;
    wpp->blk = curline->id;
    wpp->pl = 0;
}

/* pick the write pointer an allocation class writes through */
static struct write_pointer *ssd_write_pointer_for_class(struct ssd *ssd,
                                                         int klass)
{
    struct write_pointer *wpp = NULL;
    const char *what = NULL;

    if (klass == FEMU_MAP_CLASS_LOG) {
        wpp = &ssd->log_wp;
        what = "log";
    } else if (klass == FEMU_MAP_CLASS_HOT) {
        wpp = &ssd->hot_wp;
        what = "hot";
    }

    if (wpp) {
        if (!wpp->curline) {
            ssd_init_class_write_pointer(ssd, wpp, what);
        }
        if (wpp->curline) {
            return wpp;
        }
    }

    /* no line to be had for the class; fall back to the data pointer */
    return &ssd->wp;
}

void ssd_advance_write_pointer(struct ssd *ssd)
{
    ssd_advance_write_pointer_common(ssd, &ssd->wp);
}

void ssd_advance_write_pointer_class(struct ssd *ssd, int klass)
{
    ssd_advance_write_pointer_common(ssd, ssd_write_pointer_for_class(ssd, klass));
}

struct ppa get_new_page_class(struct ssd *ssd, int klass)
{
    struct write_pointer *wpp = ssd_write_pointer_for_class(ssd, klass);
    struct ppa ppa;

    ppa.ppa = 0;
    ppa.g.ch = wpp->ch;
    ppa.g.lun = wpp->lun;
    ppa.g.pg = wpp->pg;
    ppa.g.blk = wpp->blk;
    ppa.g.pl = wpp->pl;

    return ppa;
}

struct ppa get_new_page(struct ssd *ssd)
{
    struct write_pointer *wpp = &ssd->wp;
    struct ppa ppa;
    ppa.ppa = 0;
    ppa.g.ch = wpp->ch;
    ppa.g.lun = wpp->lun;
    ppa.g.pg = wpp->pg;
    ppa.g.blk = wpp->blk;
    ppa.g.pl = wpp->pl;

    return ppa;
}

/* update SSD status about one page from PG_VALID -> PG_INVALID */
void mark_page_invalid(struct ssd *ssd, struct ppa *ppa)
{
    struct line_mgmt *lm = &ssd->lm;
    struct ssdparams *spp = &ssd->sp;
    struct nand_block *blk = NULL;
    struct nand_page *pg = NULL;
    bool was_full_line = false;
    struct line *line;

    /* update corresponding page status */
    pg = get_pg(ssd, ppa);
    if (unlikely(ssd->debug_ftl) && pg->status != PG_VALID) {
        ftl_err("invalidating a page that is not valid: status=%d " PPA_FMT "\n",
                pg->status, PPA_ARG(ppa));
    }
    ftl_assert(pg->status == PG_VALID);
    pg->status = PG_INVALID;

    /* update corresponding block status */
    blk = get_blk(ssd, ppa);
    ftl_assert(blk->ipc >= 0 && blk->ipc < spp->pgs_per_blk);
    blk->ipc++;
    ftl_assert(blk->vpc > 0 && blk->vpc <= spp->pgs_per_blk);
    blk->vpc--;

    /* update corresponding line status */
    line = get_line(ssd, ppa);
    ftl_assert(line->ipc >= 0 && line->ipc < spp->pgs_per_line);
    if (line->vpc == spp->pgs_per_line) {
        ftl_assert(line->ipc == 0);
        was_full_line = true;
    }
    line->ipc++;
    ftl_assert(line->vpc > 0 && line->vpc <= spp->pgs_per_line);
    /* Adjust the position of the victime line in the pq under over-writes */
    if (line->pos) {
        /* Note that line->vpc will be updated by this call */
        pqueue_change_priority(lm->victim_line_pq, line->vpc - 1, line);
    } else {
        line->vpc--;
    }

    if (was_full_line && !line->reclaiming) {
        /* move line: "full" -> "victim" */
        QTAILQ_REMOVE(&lm->full_line_list, line, entry);
        lm->full_line_cnt--;
        pqueue_insert(lm->victim_line_pq, line);
        lm->victim_line_cnt++;
    }
}

void mark_page_valid(struct ssd *ssd, struct ppa *ppa)
{
    struct nand_block *blk = NULL;
    struct nand_page *pg = NULL;
    struct line *line;

    /* update page status */
    pg = get_pg(ssd, ppa);
    if (unlikely(ssd->debug_ftl) && pg->status != PG_FREE) {
        ftl_err("programming a page that is not free: status=%d " PPA_FMT "\n",
                pg->status, PPA_ARG(ppa));
    }
    ftl_assert(pg->status == PG_FREE);
    pg->status = PG_VALID;

    /* update corresponding block status */
    blk = get_blk(ssd, ppa);
    ftl_assert(blk->vpc >= 0 && blk->vpc < ssd->sp.pgs_per_blk);
    blk->vpc++;

    /* update corresponding line status */
    line = get_line(ssd, ppa);
    ftl_assert(line->vpc >= 0 && line->vpc < ssd->sp.pgs_per_line);
    line->vpc++;
}

void mark_block_free(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_block *blk = get_blk(ssd, ppa);
    struct nand_page *pg = NULL;

    for (int i = 0; i < spp->pgs_per_blk; i++) {
        /* reset page status */
        pg = &blk->pg[i];
        ftl_assert(pg->nsecs == spp->secs_per_pg);
        pg->status = PG_FREE;
    }

    /* reset block status */
    ftl_assert(blk->npgs == spp->pgs_per_blk);
    blk->ipc = 0;
    blk->vpc = 0;
    blk->erase_cnt++;
    blk->read_cnt = 0; /* the stress an erase clears */
    if (exp_watch_blk[ppa->g.blk])
        EXP_LOG("[ERASE] " PPA_FMT " erase_cnt=%d (vpc/ipc reset)\n",
                PPA_ARG(ppa), blk->erase_cnt);
}

void gc_read_page(struct ssd *ssd, struct ppa *ppa)
{
    /* advance ssd status, we don't care about how long it takes */
    if (ssd->sp.enable_gc_delay) {
        struct nand_cmd gcr;
        gcr.type = GC_IO;
        gcr.cmd = NAND_READ;
        gcr.stime = 0;
        ssd_advance_status(ssd, ppa, &gcr);
    }
}

/* move valid page data (already in DRAM) from victim line to a new page */
static uint64_t gc_write_page(struct ssd *ssd, struct ppa *old_ppa)
{
    struct ppa new_ppa;
    struct nand_lun *new_lun;
    uint64_t lpn = get_rmap_ent(ssd, old_ppa);

    ftl_assert(valid_lpn(ssd, lpn));
    new_ppa = get_new_page(ssd);
    /* commit the relocated mapping through the active scheme (maptbl + rmap) */
    ssd->mapping->gc_relocate_commit(ssd, lpn, old_ppa, &new_ppa);
    if (exp_lpn_watched(lpn)) {
        exp_watch_blk[new_ppa.g.blk] = 1; /* track the new block too */
        EXP_LOG("[GC_MOVE] lpn=%lu " PPA_FMT " -> " PPA_FMT "\n",
                lpn, PPA_ARG(old_ppa), PPA_ARG(&new_ppa));
    }

    mark_page_valid(ssd, &new_ppa);
    ssd->gc_write_pages++; /* write amplification: a page the device relocated */

    /* need to advance the write pointer here */
    ssd_advance_write_pointer(ssd);

    if (ssd->sp.enable_gc_delay) {
        struct nand_cmd gcw;
        gcw.type = GC_IO;
        gcw.cmd = NAND_WRITE;
        gcw.stime = 0;
        ssd_advance_status(ssd, &new_ppa, &gcw);
    }

    /* advance per-ch gc_endtime as well */
#if 0
    new_ch = get_ch(ssd, &new_ppa);
    new_ch->gc_endtime = new_ch->next_ch_avail_time;
#endif

    new_lun = get_lun(ssd, &new_ppa);
    new_lun->gc_endtime = new_lun->next_lun_avail_time;

    return 0;
}

static struct line *select_victim_line(struct ssd *ssd, bool force)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *victim_line = NULL;

    victim_line = pqueue_peek(lm->victim_line_pq);
    if (!victim_line) {
        return NULL;
    }

    if (!force && victim_line->ipc < ssd->sp.pgs_per_line / 8) {
        return NULL;
    }

    pqueue_pop(lm->victim_line_pq);
    victim_line->pos = 0;
    lm->victim_line_cnt--;

    /* victim_line is a danggling node now */
    return victim_line;
}

/* Alternative victim policy: pick a random victim (selectable via
 * gc_policy=random). Demonstrates the policy vtable; greedy stays the default. */
static struct line *select_victim_line_random(struct ssd *ssd, bool force)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *victim_line = pqueue_randpop(lm->victim_line_pq);

    if (!victim_line) {
        return NULL;
    }
    if (!force && victim_line->ipc < ssd->sp.pgs_per_line / 8) {
        pqueue_insert(lm->victim_line_pq, victim_line);
        return NULL;
    }
    victim_line->pos = 0;
    lm->victim_line_cnt--;
    return victim_line;
}

/*
 * Cost-benefit victim policy: pick the line maximizing age * (1 - u) / (2u),
 * where u = vpc/pgs_per_line. P cancels, so the rank is age * ipc / (2 * vpc);
 * lines are compared by the cross-multiplied integer form to avoid division and
 * float on the GC path. A line with vpc == 0 is the ideal victim. The victim
 * pqueue is keyed by vpc (greedy), so CB scans its bounded backing heap.
 */
static struct line *select_victim_line_cb(struct ssd *ssd, bool force)
{
    struct line_mgmt *lm = &ssd->lm;
    pqueue_t *pq = lm->victim_line_pq;
    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    struct line *best = NULL;
    uint64_t best_age = 0, best_inv = 0, best_val = 1;

    /* heap is 1-indexed and size is (count + 1), so valid slots are [1, size) */
    for (size_t i = 1; i < pq->size; i++) {
        struct line *ln = pq->d[i];
        uint64_t age = now - ln->close_time;
        uint64_t inv = ln->ipc;
        uint64_t val = ln->vpc;
        bool better;

        if (val == 0) {
            /* fully invalid: ideal victim (free reclaim), always wins */
            better = true;
        } else if (best && best_val == 0) {
            /* incumbent is already a free-reclaim line; keep it */
            better = false;
        } else {
            /* compare age*(1-u)/(2u) ~ age*inv/val via cross-multiply */
            better = !best || (__uint128_t)age * inv * best_val >
                              (__uint128_t)best_age * best_inv * val;
        }
        if (better) {
            best = ln;
            best_age = age;
            best_inv = inv;
            best_val = val;
        }
    }

    if (!best) {
        return NULL;
    }
    if (!force && best->ipc < ssd->sp.pgs_per_line / 8) {
        return NULL;
    }
    pqueue_remove(pq, best);
    best->pos = 0;
    lm->victim_line_cnt--;
    return best;
}

/*
 * FIFO victim selection: reclaim the line that was closed earliest (lowest
 * close_time), regardless of validity -- the simplest age-based policy. Iterates
 * the victim heap like cost-benefit and removes the chosen line.
 */
static struct line *select_victim_line_fifo(struct ssd *ssd, bool force)
{
    struct line_mgmt *lm = &ssd->lm;
    pqueue_t *pq = lm->victim_line_pq;
    struct line *best = NULL;

    for (size_t i = 1; i < pq->size; i++) {
        struct line *ln = pq->d[i];
        if (!best || ln->close_time < best->close_time) {
            best = ln;
        }
    }
    if (!best) {
        return NULL;
    }
    if (!force && best->ipc < ssd->sp.pgs_per_line / 8) {
        return NULL;
    }
    pqueue_remove(pq, best);
    best->pos = 0;
    lm->victim_line_cnt--;
    return best;
}

/*
 * D-Choice victim selection (random d-sample then greedy): sample DCHOICE_D
 * random candidates from the victim heap and pick the one with the fewest valid
 * pages. A cheap O(d) approximation of greedy that avoids full-heap scans; d=4 is
 * the common choice in the literature.
 */
#define FEMU_DCHOICE_D 4
static struct line *select_victim_line_dchoice(struct ssd *ssd, bool force)
{
    struct line_mgmt *lm = &ssd->lm;
    pqueue_t *pq = lm->victim_line_pq;
    struct line *best = NULL;
    size_t n = (pq->size > 1) ? pq->size - 1 : 0; /* heap slots [1, size) */
    int d = FEMU_DCHOICE_D;

    if (n == 0) {
        return NULL;
    }
    for (int s = 0; s < d; s++) {
        size_t idx = 1 + (qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + s * 2654435761u) % n;
        struct line *ln = pq->d[idx];
        if (!best || ln->vpc < best->vpc) {
            best = ln;
        }
    }
    if (!best) {
        return NULL;
    }
    if (!force && best->ipc < ssd->sp.pgs_per_line / 8) {
        return NULL;
    }
    pqueue_remove(pq, best);
    best->pos = 0;
    lm->victim_line_cnt--;
    return best;
}

static const struct femu_ftl_policy_ops femu_ftl_policies[] = {
    { .name = "greedy", .select_victim_line = select_victim_line },
    { .name = "random", .select_victim_line = select_victim_line_random },
    { .name = "cost-benefit", .select_victim_line = select_victim_line_cb },
    { .name = "fifo", .select_victim_line = select_victim_line_fifo },
    { .name = "d-choice", .select_victim_line = select_victim_line_dchoice },
};

/* Resolve a gc_policy name to its ops; default to greedy for NULL/empty/unknown. */
const struct femu_ftl_policy_ops *femu_ftl_policy_lookup(const char *name)
{
    if (name && name[0]) {
        for (size_t i = 0; i < ARRAY_SIZE(femu_ftl_policies); i++) {
            if (strcmp(name, femu_ftl_policies[i].name) == 0) {
                return &femu_ftl_policies[i];
            }
        }
    }
    return &femu_ftl_policies[0]; /* greedy */
}

/* here ppa identifies the block we want to clean */
static void clean_one_block(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_page *pg_iter = NULL;
    int cnt = 0;

    for (int pg = 0; pg < spp->pgs_per_blk; pg++) {
        ppa->g.pg = pg;
        pg_iter = get_pg(ssd, ppa);
        /* there shouldn't be any free page in victim blocks */
        ftl_assert(pg_iter->status != PG_FREE);
        if (pg_iter->status == PG_VALID) {
            gc_read_page(ssd, ppa);
            /* delay the maptbl update until "write" happens */
            gc_write_page(ssd, ppa);
            cnt++;
        }
    }

    ftl_assert(get_blk(ssd, ppa)->vpc == cnt);
}

void mark_line_free(struct ssd *ssd, struct ppa *ppa)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *line = get_line(ssd, ppa);
    /*
     * If the read path had queued this line for a refresh, that request dies
     * with the line: it is about to be erased and recycled, which is exactly
     * what the refresh would have achieved.
     */
    if (ssd->read_reclaim_line == line) {
        ssd->read_reclaim_line = NULL;
    }

    line->ipc = 0;
    line->vpc = 0;
    line->close_time = 0;
    /* move this line to free line list */
    QTAILQ_INSERT_TAIL(&lm->free_line_list, line, entry);
    lm->free_line_cnt++;
}

/* relocate a line's valid pages, erase it, and return it to the free list */
static void reclaim_line(struct ssd *ssd, struct line *victim_line)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_lun *lunp;
    struct ppa ppa;
    int ch, lun;

    ppa.g.blk = victim_line->id;

    /* copy back valid data */
    for (ch = 0; ch < spp->nchs; ch++) {
        for (lun = 0; lun < spp->luns_per_ch; lun++) {
            struct ppa ppas[1 << PL_BITS];
            int pl;

            ppa.g.ch = ch;
            ppa.g.lun = lun;
            ppa.g.pl = 0;
            lunp = get_lun(ssd, &ppa);

            for (pl = 0; pl < spp->pls_per_lun; pl++) {
                ppa.g.pl = pl;
                clean_one_block(ssd, &ppa);
                mark_block_free(ssd, &ppa);
                ppas[pl] = ppa;
            }

            /*
             * A line holds the same block index on every plane, so the die can
             * erase them in one operation instead of one after another.
             */
            if (spp->enable_gc_delay) {
                struct nand_cmd gce;
                gce.type = GC_IO;
                gce.cmd = NAND_ERASE;
                gce.stime = 0;
                ssd_advance_status_multiplane(ssd, ppas, spp->pls_per_lun, &gce);
            }

            lunp->gc_endtime = lunp->next_lun_avail_time;
        }
    }

    /* update line status */
    mark_line_free(ssd, &ppa);
}

int do_gc(struct ssd *ssd, bool force)
{
    struct line *victim_line = ssd->policy->select_victim_line(ssd, force);

    if (!victim_line) {
        return -1;
    }

    ftl_debug("GC-ing line:%d,ipc=%d,victim=%d,full=%d,free=%d\n",
              victim_line->id, victim_line->ipc, ssd->lm.victim_line_cnt,
              ssd->lm.full_line_cnt, ssd->lm.free_line_cnt);

    reclaim_line(ssd, victim_line);

    return 0;
}

/*
 * Rewrite a line whose blocks have taken enough reads to be worth refreshing.
 *
 * Reading a page stresses the others in its block, so a block read many times
 * without being rewritten drifts towards errors. Real devices watch for that
 * and rewrite the data before it decays; the cost is relocation, which is why
 * this shows up as write amplification in a read-heavy workload rather than as
 * anything the host sees directly.
 *
 * The line is chosen by the read path and rewritten here, on a write, because
 * this is where collection already happens and where the cost belongs. Doing it
 * inside the read would stall a read behind a whole line of relocation.
 *
 * Relocation goes through the ordinary data write pointer. An earlier attempt
 * at static wear levelling gave itself a dedicated pointer, which pinned a line
 * out of circulation and drove the device into a collection death spiral; there
 * is no reason to repeat that here.
 */
int do_read_reclaim(struct ssd *ssd)
{
    struct line *line = ssd->read_reclaim_line;

    if (!line) {
        return -1;
    }

    /*
     * Only with lines to spare. The test is the high watermark, not
     * should_gc(): a busy device sits below should_gc() permanently, so testing
     * that would disable this outright.
     */
    if (should_gc_high(ssd) || ssd->lm.free_line_cnt < 2) {
        return -1;
    }

    ssd->read_reclaim_line = NULL;

    /*
     * A heavily read line is usually full, and invalidating the first page of a
     * full line moves it from full_line_list into the victim queue half way
     * through the rewrite. Take it out and mark it so that does not happen;
     * a line from select_victim_line() already arrives in no list.
     */
    if (line->vpc == ssd->sp.pgs_per_line) {
        QTAILQ_REMOVE(&ssd->lm.full_line_list, line, entry);
        ssd->lm.full_line_cnt--;
    } else if (line->pos) {
        pqueue_remove(ssd->lm.victim_line_pq, line);
        line->pos = 0;
        ssd->lm.victim_line_cnt--;
    } else {
        /* being written to right now: leave it alone */
        return -1;
    }

    line->reclaiming = true;
    reclaim_line(ssd, line);
    line->reclaiming = false;
    ssd->read_reclaims++;

    return 0;
}
