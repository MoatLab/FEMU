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

static inline pqueue_pri_t victim_line_get_close_seq(void *a)
{
    return ((struct line *)a)->close_seq;
}

static inline void victim_line_set_close_seq(void *a, pqueue_pri_t pri)
{
    ((struct line *)a)->close_seq = pri;
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
    if (ssd->policy->by_close_order) {
        lm->victim_line_pq = pqueue_init(spp->tt_lines, victim_line_cmp_pri,
                victim_line_get_close_seq, victim_line_set_close_seq,
                victim_line_get_pos, victim_line_set_pos);
    } else {
        lm->victim_line_pq = pqueue_init(spp->tt_lines, victim_line_cmp_pri,
                victim_line_get_pri, victim_line_set_pri,
                victim_line_get_pos, victim_line_set_pos);
    }
    lm->next_close_seq = 0;
    QTAILQ_INIT(&lm->full_line_list);

    lm->free_line_cnt = 0;
    lm->retired_line_cnt = 0;
    for (int i = 0; i < lm->tt_lines; i++) {
        line = &lm->lines[i];
        line->id = i;
        line->retired = false;
        line->spare = i >= lm->tt_lines - ssd->spare_lines;
        if (line->spare) {
            continue;
        }
        line->ipc = 0;
        line->vpc = 0;
        line->pos = 0;
        line->close_time = 0;
        line->close_seq = 0;
        /* initialize all the lines as free lines */
        QTAILQ_INSERT_TAIL(&lm->free_line_list, line, entry);
        lm->free_line_cnt++;
    }

    ftl_assert(lm->free_line_cnt == lm->tt_lines - ssd->spare_lines);
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
    ssd_wp_reset(wpp, curline);

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

    if (!ssd_wp_step(spp, wpp)) {
        return;
    }
    /* record when the line filled, for age-based GC policies */
    wpp->curline->close_time = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    wpp->curline->close_seq = lm->next_close_seq++;
    /* move current line to {victim,full} line list */
    if (wpp->curline->vpc == spp->pgs_per_line) {
        /* all pgs are still valid, move to full line list */
        ftl_assert(wpp->curline->ipc == 0);
        QTAILQ_INSERT_TAIL(&lm->full_line_list, wpp->curline, entry);
        lm->full_line_cnt++;
    } else {
        ftl_assert(wpp->curline->vpc >= 0 &&
                   wpp->curline->vpc < spp->pgs_per_line);
        /* there must be some invalid pages in this line */
        ftl_assert(wpp->curline->ipc > 0);
        pqueue_insert(lm->victim_line_pq, wpp->curline);
    }
    /* current line is used up, pick another empty line */
    check_addr(wpp->blk, spp->blks_per_pl);
    wpp->curline = get_next_free_line(ssd);
    if (!wpp->curline) {
        /*
         * Nothing left to program into, and get_next_free_line() has said so.
         * Leave the pointer without a line rather than taking the process down
         * under a running guest: the write paths test for that and refuse the
         * command.
         */
        return;
    }
    wpp->blk = wpp->curline->id;
    check_addr(wpp->blk, spp->blks_per_pl);
    /* make sure we are starting from page 0 in the super block */
    ftl_assert(wpp->pg == 0 && wpp->lun == 0 && wpp->ch == 0 && wpp->pl == 0);
}

static struct ppa ssd_stream_pointer_page(struct ssd *ssd,
                                          struct write_pointer *wp,
                                          uint64_t tag)
{
    struct ppa ppa = { .ppa = INVALID_PPA };

    if (!wp->curline) {
        wp->curline = get_next_free_line(ssd);
        if (!wp->curline) {
            return ppa;
        }
        wp->ch = wp->lun = wp->pl = wp->pg = 0;
        wp->blk = wp->curline->id;
    }
    wp->curline->stream_tag = tag;
    ppa.ppa = 0;
    ppa.g.ch = wp->ch;
    ppa.g.lun = wp->lun;
    ppa.g.pl = wp->pl;
    ppa.g.pg = wp->pg;
    ppa.g.blk = wp->blk;
    return ppa;
}

bool ssd_out_of_lines(struct ssd *ssd)
{
    /* Format, trim or GC may have freed space since the frontier filled. */
    if (!ssd->wp.curline && ssd->lm.free_line_cnt) {
        ssd_stream_pointer_page(ssd, &ssd->wp, 0);
    }
    return ssd->wp.curline == NULL;
}

static void ssd_stream_close_pointer(struct ssd *ssd, struct write_pointer *wp)
{
    struct line *line = wp->curline;
    struct ssdparams *sp = &ssd->sp;
    struct ppa ppa = { .ppa = 0 };
    int ch;
    int lun;
    int pl;
    int pg;

    if (!line) {
        return;
    }
    if (!line->vpc && !line->ipc) {
        line->stream_tag = 0;
        QTAILQ_INSERT_TAIL(&ssd->lm.free_line_list, line, entry);
        ssd->lm.free_line_cnt++;
    } else {
        /* Seal unused pages so GC can reclaim a partially written line. */
        ppa.g.blk = line->id;
        for (ch = 0; ch < sp->nchs; ch++) {
            ppa.g.ch = ch;
            for (lun = 0; lun < sp->luns_per_ch; lun++) {
                ppa.g.lun = lun;
                for (pl = 0; pl < sp->pls_per_lun; pl++) {
                    ppa.g.pl = pl;
                    for (pg = 0; pg < sp->pgs_per_blk; pg++) {
                        ppa.g.pg = pg;
                        if (get_pg(ssd, &ppa)->status == PG_FREE) {
                            get_pg(ssd, &ppa)->status = PG_INVALID;
                            get_blk(ssd, &ppa)->ipc++;
                            line->ipc++;
                        }
                    }
                }
            }
        }
        line->close_time = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        line->close_seq = ssd->lm.next_close_seq++;
        pqueue_insert(ssd->lm.victim_line_pq, line);
    }
    memset(wp, 0, sizeof(*wp));
}

void ssd_release_stream(struct ssd *ssd, unsigned slot)
{
    ssd_stream_close_pointer(ssd, &ssd->stream_wp[slot]);
    ssd->stream_tags[slot] = 0;
}

struct ppa ssd_stream_page(struct ssd *ssd, unsigned slot, uint64_t tag)
{
    ssd->stream_tags[slot] = tag;
    return ssd_stream_pointer_page(ssd, &ssd->stream_wp[slot], tag);
}

void ssd_stream_advance(struct ssd *ssd, unsigned slot)
{
    ssd_advance_write_pointer_common(ssd, &ssd->stream_wp[slot]);
    if (ssd->stream_wp[slot].curline) {
        ssd->stream_wp[slot].curline->stream_tag = ssd->stream_tags[slot];
    }
}

static struct write_pointer *ssd_stream_gc_pointer(struct ssd *ssd,
                                                   uint64_t tag)
{
    unsigned i;

    for (i = 0; i < ssd->n->streams_max; i++) {
        if (ssd->stream_tags[i] == tag) {
            return &ssd->stream_wp[i];
        }
    }
    /* Released streams retain their identity while their data remains live. */
    if (ssd->stream_gc_tag != tag) {
        ssd_stream_close_pointer(ssd, &ssd->stream_gc_wp);
        ssd->stream_gc_tag = tag;
    }
    return &ssd->stream_gc_wp;
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

    ssd_wp_reset(wpp, curline);
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

    /* no line on this pointer, no page -- see get_new_page() */
    if (!wpp->curline) {
        ppa.ppa = INVALID_PPA;
        return ppa;
    }

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

    /*
     * The pointer is left without a line when nothing is free, and its block
     * field still names the line that has just closed -- so building an
     * address from it here hands back page zero of a line that is already
     * fully programmed. Say there is no page instead, and let the caller
     * decide; every allocation goes through here, so no path can miss it.
     */
    if (!wpp->curline) {
        ppa.ppa = INVALID_PPA;
        return ppa;
    }

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
    if (line->pos && !ssd->policy->by_close_order) {
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

/*
 * Free block @blk on every plane of LUN @ch/@lun and, with @charge, time them
 * as one multi-plane erase starting at @stime (0: now): a line holds the same
 * block index on every plane, so the die erases them together. The LUN's GC end
 * then follows its busy-until time. Returns the erase latency, 0 if untimed.
 */
uint64_t ssd_erase_lun_block(struct ssd *ssd, int ch, int lun, int blk,
                             bool charge, int64_t stime)
{
    struct ssdparams *spp = &ssd->sp;
    struct ppa ppas[1 << PL_BITS];
    struct ppa ppa = { .ppa = 0 };
    struct nand_lun *lunp;
    uint64_t lat = 0;

    ppa.g.ch = ch;
    ppa.g.lun = lun;
    ppa.g.blk = blk;
    lunp = get_lun(ssd, &ppa);
    for (int pl = 0; pl < spp->pls_per_lun; pl++) {
        ppa.g.pl = pl;
        mark_block_free(ssd, &ppa);
        ppas[pl] = ppa;
    }
    if (charge) {
        struct nand_cmd gce = {
            .type = GC_IO,
            .cmd = NAND_ERASE,
            .stime = stime,
        };

        lat = ssd_advance_status_multiplane(ssd, ppas, spp->pls_per_lun, &gce);
    }
    lunp->gc_endtime = lunp->next_lun_avail_time;
    return lat;
}

void mark_block_free(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_block *blk = get_blk(ssd, ppa);
    struct nand_page *pg = NULL;

    for (int i = 0; i < spp->pgs_per_blk; i++) {
        /* reset page status */
        pg = &blk->pg[i];
        pg->status = PG_FREE;
    }

    /* reset block status */
    ftl_assert(blk->npgs == spp->pgs_per_blk);
    blk->ipc = 0;
    blk->vpc = 0;
    if (blk->erase_cnt < UINT32_MAX) {
        blk->erase_cnt++;
    }
    ssd->total_erases++;
    blk->read_cnt = 0; /* the stress an erase clears */
    if (exp_watch_blk[ppa->g.blk])
        EXP_LOG("[ERASE] " PPA_FMT " erase_cnt=%u (vpc/ipc reset)\n",
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

/**
 * ssd_gc_move_page - record that collection copied one valid page
 * @ssd: the device
 * @lpn: the logical page the copy holds
 * @old_ppa: the copy being collected
 * @new_ppa: the destination, already chosen by the caller
 * @ops: how this mode marks a page valid or invalid
 * @dest: handed to @ops->mark_valid
 *
 * Call before advancing the write frontier, which reads the destination's
 * valid count to decide whether it is full. The old copy is retired now, not
 * at the erase: a victim that cannot be emptied goes back to the queue, and a
 * copy still counted valid would be moved again over newer data.
 */
void ssd_gc_move_page(struct ssd *ssd, uint64_t lpn, struct ppa *old_ppa,
                      struct ppa *new_ppa, const struct ssd_gc_move_ops *ops,
                      void *dest)
{
    ssd->mapping->gc_relocate_commit(ssd, lpn, old_ppa, new_ppa);
    ops->mark_invalid(ssd, old_ppa);
    set_rmap_ent(ssd, INVALID_LPN, old_ppa);
    ops->mark_valid(ssd, new_ppa, dest);
    ssd->gc_write_pages++; /* write amplification */
}

/**
 * ssd_gc_charge_move - time the program of a relocated page
 * @ssd: the device
 * @new_ppa: the page collection wrote
 *
 * Charges the program when collection is timed and moves the LUN's collection
 * end to its busy-until time.
 */
void ssd_gc_charge_move(struct ssd *ssd, struct ppa *new_ppa)
{
    struct nand_lun *lun = get_lun(ssd, new_ppa);

    if (ssd->sp.enable_gc_delay) {
        struct nand_cmd gcw;
        gcw.type = GC_IO;
        gcw.cmd = NAND_WRITE;
        gcw.stime = 0;
        ssd_advance_status(ssd, new_ppa, &gcw);
    }
    lun->gc_endtime = lun->next_lun_avail_time;
}

static void gc_mark_valid(struct ssd *ssd, struct ppa *ppa, void *dest)
{
    (void)dest;
    mark_page_valid(ssd, ppa);
}

static const struct ssd_gc_move_ops gc_line_move_ops = {
    .mark_valid   = gc_mark_valid,
    .mark_invalid = mark_page_invalid,
};

/* move valid page data (already in DRAM) from victim line to a new page */
/* true when the page was relocated; false when there is nowhere to put it */
static bool gc_write_page(struct ssd *ssd, struct ppa *old_ppa)
{
    struct ppa new_ppa;
    uint64_t lpn = get_rmap_ent(ssd, old_ppa);
    uint64_t tag = get_line(ssd, old_ppa)->stream_tag;
    struct write_pointer *stream_wp = NULL;

    ftl_assert(valid_lpn(ssd, lpn));
    if (tag) {
        stream_wp = ssd_stream_gc_pointer(ssd, tag);
        new_ppa = ssd_stream_pointer_page(ssd, stream_wp, tag);
    } else if (!ssd->wp.curline) {
        new_ppa = ssd_stream_pointer_page(ssd, &ssd->wp, 0);
    } else {
        new_ppa = get_new_page(ssd);
    }
    if (!mapped_ppa(&new_ppa)) {
        /*
         * Relocating with nowhere to relocate to used to mark a page valid a
         * second time, which carried the line's valid count past its capacity
         * -- and the test that returns a line to collection is an equality,
         * so that line was never collected again. Leave the page where it is.
         */
        return false;
    }
    ssd_gc_move_page(ssd, lpn, old_ppa, &new_ppa, &gc_line_move_ops, NULL);
    if (exp_lpn_watched(lpn)) {
        exp_watch_blk[new_ppa.g.blk] = 1; /* track the new block too */
        EXP_LOG("[GC_MOVE] lpn=%lu " PPA_FMT " -> " PPA_FMT "\n",
                lpn, PPA_ARG(old_ppa), PPA_ARG(&new_ppa));
    }

    /* need to advance the write pointer here */
    if (stream_wp) {
        ssd_advance_write_pointer_common(ssd, stream_wp);
        if (stream_wp->curline) {
            stream_wp->curline->stream_tag = tag;
        }
    } else {
        ssd_advance_write_pointer(ssd);
    }

    ssd_gc_charge_move(ssd, &new_ppa);
    return true;
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

    /* victim_line is a danggling node now */
    return victim_line;
}

/* Alternative victim policy: pick a random victim (selectable via
 * gc_policy=random). Demonstrates the policy vtable; greedy stays the default. */
static struct line *select_victim_line_random(struct ssd *ssd, bool force)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *victim_line = pqueue_randpop(lm->victim_line_pq,
                                              ftl_gc_rand(ssd));

    if (!victim_line) {
        return NULL;
    }
    if (!force && victim_line->ipc < ssd->sp.pgs_per_line / 8) {
        pqueue_insert(lm->victim_line_pq, victim_line);
        return NULL;
    }
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
    return best;
}

/*
 * FIFO victim selection: reclaim the line that was closed earliest, regardless
 * of validity -- the simplest age-based policy. Under this policy the victim
 * queue is ordered by close_seq, which never changes while a line is queued,
 * so the oldest line is at the top.
 */
static struct line *select_victim_line_fifo(struct ssd *ssd, bool force)
{
    struct line_mgmt *lm = &ssd->lm;
    struct line *best = pqueue_peek(lm->victim_line_pq);

    if (!best) {
        return NULL;
    }
    if (!force && best->ipc < ssd->sp.pgs_per_line / 8) {
        return NULL;
    }
    pqueue_pop(lm->victim_line_pq);
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
        size_t idx = 1 + ftl_gc_rand(ssd) % n;
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
    return best;
}

static const struct femu_ftl_policy_ops femu_ftl_policies[] = {
    { .name = "greedy", .select_victim_line = select_victim_line },
    { .name = "random", .select_victim_line = select_victim_line_random },
    { .name = "cost-benefit", .select_victim_line = select_victim_line_cb },
    { .name = "fifo", .select_victim_line = select_victim_line_fifo,
      .by_close_order = true },
    { .name = "d-choice", .select_victim_line = select_victim_line_dchoice },
};

/*
 * Next number for the policies that sample victims (splitmix64). It is seeded
 * from gc_seed, not the clock, so the same workload picks the same victims.
 */
uint64_t ftl_gc_rand(struct ssd *ssd)
{
    uint64_t z = (ssd->gc_rng += 0x9e3779b97f4a7c15ULL);

    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

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

/* Is this a collection policy the device has? See femu_mapping_scheme_known. */
bool femu_ftl_policy_known(const char *name)
{
    if (!name || !name[0]) {
        return true;
    }
    for (size_t i = 0; i < ARRAY_SIZE(femu_ftl_policies); i++) {
        if (!strcmp(name, femu_ftl_policies[i].name)) {
            return true;
        }
    }

    return false;
}

/* move a block's valid pages out; false when one had nowhere to go */
/*
 * After a line's erase, deal with each block of it that has reached its erase
 * limit. The erase that reaches the limit succeeds and the line holds no data
 * now, so taking it out of service loses nothing. Retire the line only while
 * that leaves the namespace its lines, collection its reserve, and space to
 * write into right now: an open data line and one free line. Counting usable
 * lines alone is not enough, since collection relocates into the open line
 * before it frees anything, and retiring victim after victim would use it up.
 * Otherwise the worn-out blocks stay in service, overworn, each counted once.
 *
 * Before any of that, a worn-out block is replaced by a spare block of its
 * plane when every plane with one has a spare left. The swap moves the whole
 * block, pages and counts, so addresses do not change: the line keeps its id
 * and the worn-out block sits in the spare line, which never holds data. When
 * one plane has no spare left, no spare is spent on the others.
 * Returns true when the line was retired.
 */
static bool ssd_wear_out_line(struct ssd *ssd, struct line *line)
{
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;
    int usable = lm->tt_lines - ssd->spare_lines - lm->retired_line_cnt;
    bool spares = ssd->spare_lines > 0;
    bool retire;
    int dead = 0;

    for (int ch = 0; ch < spp->nchs; ch++) {
        for (int lun = 0; lun < spp->luns_per_ch; lun++) {
            for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                struct nand_plane *plane = &ssd->ch[ch].lun[lun].pl[pl];
                struct nand_block *blk = &plane->blk[line->id];

                if (blk->pe_limit && blk->erase_cnt >= blk->pe_limit) {
                    dead++;
                    spares &= plane->spares_used < ssd->spare_lines;
                }
            }
        }
    }
    if (!dead) {
        return false;
    }
    if (spares) {
        for (int ch = 0; ch < spp->nchs; ch++) {
            for (int lun = 0; lun < spp->luns_per_ch; lun++) {
                for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                    struct nand_plane *plane = &ssd->ch[ch].lun[lun].pl[pl];
                    struct nand_block *blk = &plane->blk[line->id];
                    int slot;
                    struct nand_block worn;

                    if (!blk->pe_limit || blk->erase_cnt < blk->pe_limit) {
                        continue;
                    }
                    slot = lm->tt_lines - ssd->spare_lines +
                           plane->spares_used++;
                    worn = *blk;
                    *blk = plane->blk[slot];
                    if (worn.overworn) {
                        worn.overworn = false;
                        ssd->overworn_blocks--;
                    }
                    plane->blk[slot] = worn;
                    ssd->grown_bad_blocks++;
                }
            }
        }
        return false;
    }
    retire = usable - 1 >= ssd->wear_floor_lines && ssd->wp.curline &&
             lm->free_line_cnt >= 1;

    for (int ch = 0; ch < spp->nchs; ch++) {
        for (int lun = 0; lun < spp->luns_per_ch; lun++) {
            for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                struct nand_block *blk =
                    &ssd->ch[ch].lun[lun].pl[pl].blk[line->id];
                bool worn = blk->pe_limit && blk->erase_cnt >= blk->pe_limit;

                if (!retire) {
                    if (worn && !blk->overworn) {
                        blk->overworn = true;
                        ssd->overworn_blocks++;
                    }
                    continue;
                }
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
    if (!retire) {
        return false;
    }

    /* what mark_line_free() resets, without putting the line back */
    if (ssd->read_reclaim_line == line) {
        ssd->read_reclaim_line = NULL;
        ssd->reclaim_by_age = false;
    }
    line->ipc = 0;
    line->vpc = 0;
    line->close_time = 0;
    line->stream_tag = 0;
    line->retired = true;
    lm->retired_line_cnt++;
    return true;
}

/*
 * Tell the main loop when wear has just crossed into a SMART warning: the
 * spare below its threshold, or the first block kept in service past its
 * limit. Both only get worse, so each is raised once. The FTL thread may not
 * post a completion itself; the controller's event bottom half does.
 */
static void ssd_wear_events(struct ssd *ssd, uint8_t spare, uint64_t overworn)
{
    uint32_t bits = 0;

    if (spare >= NVME_SPARE_THRESHOLD &&
        ssd_available_spare(ssd) < NVME_SPARE_THRESHOLD) {
        bits |= NVME_SMART_SPARE;
    }
    if (!overworn && ssd->overworn_blocks) {
        bits |= NVME_SMART_RELIABILITY;
    }
    if (bits) {
        qatomic_or(&ssd->n->health_pending, bits);
        qemu_bh_schedule(ssd->n->aer_bh);
    }
}

static bool clean_one_block(struct ssd *ssd, struct ppa *ppa)
{
    struct ssdparams *spp = &ssd->sp;
    struct nand_page *pg_iter = NULL;

    for (int pg = 0; pg < spp->pgs_per_blk; pg++) {
        ppa->g.pg = pg;
        pg_iter = get_pg(ssd, ppa);
        /* there shouldn't be any free page in victim blocks */
        ftl_assert(pg_iter->status != PG_FREE);
        if (pg_iter->status == PG_VALID) {
            gc_read_page(ssd, ppa);
            if (!gc_write_page(ssd, ppa)) {
                return false;
            }
        }
    }

    ftl_assert(get_blk(ssd, ppa)->vpc == 0);
    return true;
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
        ssd->reclaim_by_age = false;
    }

    line->ipc = 0;
    line->vpc = 0;
    line->close_time = 0;
    line->stream_tag = 0;
    /* move this line to free line list */
    QTAILQ_INSERT_TAIL(&lm->free_line_list, line, entry);
    lm->free_line_cnt++;
}

/* return a line that could not be emptied to the list its counts call for */
static void requeue_line(struct ssd *ssd, struct line *line)
{
    struct line_mgmt *lm = &ssd->lm;

    if (line->vpc == ssd->sp.pgs_per_line) {
        QTAILQ_INSERT_TAIL(&lm->full_line_list, line, entry);
        lm->full_line_cnt++;
    } else {
        pqueue_insert(lm->victim_line_pq, line);
    }
}

/*
 * Relocate a line's valid pages, erase it, and return it to the free list.
 * Every page is moved before any block is erased: with nowhere left to put
 * one, the line is requeued as it stands and false returned. Erasing then
 * would destroy the pages still in it while their mappings point there.
 */
static bool reclaim_line(struct ssd *ssd, struct line *victim_line)
{
    struct ssdparams *spp = &ssd->sp;
    struct ppa ppa;
    int ch, lun, pl;

    /*
     * Only some fields are filled in below, so start from zero rather than
     * from the stack: the sector and reserved fields are copied into the
     * batch this builds and passed on to mark_line_free(). Nothing reads
     * them today, but valid_ppa() does check the sector, so the day anything
     * calls it on one of these the answer would come from whatever the stack
     * happened to hold.
     */
    ppa.ppa = 0;
    ppa.g.blk = victim_line->id;
    ftl_note_victim(ssd, victim_line->id);

    for (ch = 0; ch < spp->nchs && victim_line->vpc; ch++) {
        for (lun = 0; lun < spp->luns_per_ch; lun++) {
            ppa.g.ch = ch;
            ppa.g.lun = lun;
            for (pl = 0; pl < spp->pls_per_lun; pl++) {
                ppa.g.pl = pl;
                if (!clean_one_block(ssd, &ppa)) {
                    requeue_line(ssd, victim_line);
                    return false;
                }
            }
        }
    }

    for (ch = 0; ch < spp->nchs; ch++) {
        for (lun = 0; lun < spp->luns_per_ch; lun++) {
            ssd_erase_lun_block(ssd, ch, lun, ppa.g.blk, spp->enable_gc_delay,
                                0);
        }
    }
    if (ssd->wear_on) {
        uint8_t spare = ssd_available_spare(ssd);
        uint64_t overworn = ssd->overworn_blocks;
        bool retired;

        qemu_mutex_lock(&ssd->wear_lock);
        retired = ssd_wear_out_line(ssd, victim_line);
        qemu_mutex_unlock(&ssd->wear_lock);

        ssd_wear_events(ssd, spare, overworn);
        if (retired) {
            return true;
        }
    }

    /* update line status */
    mark_line_free(ssd, &ppa);
    return true;
}

int do_gc(struct ssd *ssd, bool force)
{
    int free_lines = ssd->lm.free_line_cnt;
    struct line *victim_line = ssd->policy->select_victim_line(ssd, force);

    if (!victim_line) {
        return -1;
    }

    if (ssd->n->streams && victim_line->vpc && !ssd->lm.free_line_cnt) {
        pqueue_insert(ssd->lm.victim_line_pq, victim_line);
        return -1;
    }

    ftl_debug("GC-ing line:%d,ipc=%d,victim=%zu,full=%d,free=%d\n",
              victim_line->id, victim_line->ipc,
              pqueue_size(ssd->lm.victim_line_pq),
              ssd->lm.full_line_cnt, ssd->lm.free_line_cnt);

    if (!reclaim_line(ssd, victim_line)) {
        return -1;
    }
    if (force && ssd->sp.enable_gc_delay) {
        int ch;
        int lun;

        ssd->forced_gc_timed++;
        /* The erase is the last command collection gives each LUN. */
        for (ch = 0; ch < ssd->sp.nchs; ch++) {
            for (lun = 0; lun < ssd->sp.luns_per_ch; lun++) {
                struct nand_lun *l = &ssd->ch[ch].lun[lun];

                ssd->forced_gc_end = MAX(ssd->forced_gc_end,
                                         l->next_lun_avail_time);
            }
        }
    }

    /* Distinct retired streams may occupy lines that cannot be combined. */
    if (ssd->n->streams && ssd->lm.free_line_cnt <= free_lines) {
        return -1;
    }
    return 0;
}

/*
 * Rewrite a line whose data has become worth refreshing, for either reason.
 *
 * Reading a page stresses the others in its block, so a block read many times
 * without being rewritten drifts towards errors. Charge also leaks out of a
 * cell on its own, so data that has simply sat programmed long enough drifts
 * the same way whether or not anything reads it. Real devices watch for both
 * and rewrite the data before it decays; the cost is relocation, which is why
 * this shows up as write amplification rather than as anything the host sees
 * directly. The two are counted apart -- read_reclaims and retention_refreshes
 * -- so a workload can tell which pressure it is paying for.
 *
 * A line nothing ever reads is never refreshed here: both triggers sit on the
 * read path. Modelling the background media scan a real device runs would need
 * a timer of its own, which this deliberately does not add.
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
    bool by_age;

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
    by_age = ssd->reclaim_by_age;
    ssd->reclaim_by_age = false;

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
    } else {
        /* being written to right now: leave it alone */
        return -1;
    }

    line->reclaiming = true;
    if (!reclaim_line(ssd, line)) {
        line->reclaiming = false;
        return -1;
    }
    line->reclaiming = false;
    if (by_age) {
        ssd->retention_refreshes++;
    } else {
        ssd->read_reclaims++;
    }

    return 0;
}

/* release what ssd_init_lines() took */
void ssd_free_lines(struct ssd *ssd)
{
    struct line_mgmt *lm = &ssd->lm;

    pqueue_free(lm->victim_line_pq);
    lm->victim_line_pq = NULL;
    g_free(lm->lines);
    lm->lines = NULL;
    lm->tt_lines = 0;
    lm->free_line_cnt = 0;
    lm->full_line_cnt = 0;
}
