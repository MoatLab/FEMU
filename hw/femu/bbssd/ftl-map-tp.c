/*
 * Translation pages (TPs) on flash for mapping=dftl without FDP.
 *
 * The flat maptbl still answers every lookup; this file gives the mapping a
 * home on NAND, as DFTL keeps it. Each TP holds the mappings of lpn_per_tp
 * logical pages and lives in a TP line, written only through tp_wp. The GTD
 * names the page holding the current copy of each TP. A copy is rewritten
 * out of place: on a dirty CMT eviction, when collection publishes the
 * changes it made to uncached TPs, and when a TP line is collected.
 *
 *   change of a mapping --> tp_note()
 *        |-- TP in the CMT --> slot dirty (written back on eviction)
 *        '-- otherwise     --> pending (published in one batch later)
 *
 * A TP program that would take one of the free lines forced collection
 * keeps is not made: the change stays dirty or pending. Only the relocation
 * of a TP line may use that reserve, so TP traffic never takes the room
 * collection needs to free a line.
 */
#include "qemu/osdep.h"
#include "qemu/bitmap.h"
#include "ftl.h"
#include "ftl-internal.h"

static inline uint64_t tp_now(uint64_t stime)
{
    return stime ? stime : qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
}

void tp_init(struct ssd *ssd)
{
    uint64_t n = DIV_ROUND_UP((uint64_t)ssd->sp.tt_pgs, ssd->cmt.lpn_per_tp);

    /* indexed by the global TP id: a namespace at an offset needs no base */
    ssd->n_tps = n;
    ssd->tp_live_max = MIN(n, DIV_ROUND_UP(DIV_ROUND_UP(ssd->ns->size,
                                                        ssd_page_size(ssd)),
                                           ssd->cmt.lpn_per_tp) + 1);
    ssd->gtd = g_new(struct ppa, n);
    for (uint64_t i = 0; i < n; i++) {
        ssd->gtd[i].ppa = UNMAPPED_PPA;
    }
    ssd->tp_ver = g_new0(uint32_t, n);
    ssd->gtd_ver = g_new0(uint32_t, n);
    ssd->tp_done = g_new0(uint64_t, n);
    ssd->tp_pending = bitmap_new(n);
    ssd->tp_queued = bitmap_new(n);
    ssd->tp_fifo = g_new(uint64_t, n);
    ssd->tp_fifo_head = 0;
    ssd->tp_fifo_cnt = 0;
    memset(&ssd->tp_wp, 0, sizeof(ssd->tp_wp));
    ssd->map_write_pages = 0;
    ssd->map_read_pages = 0;
    ssd->tp_moves = 0;
    ssd->tp_stale_loads = 0;
    ssd->tp_on = true;
}

void tp_free(struct ssd *ssd)
{
    g_free(ssd->gtd);
    g_free(ssd->tp_ver);
    g_free(ssd->gtd_ver);
    g_free(ssd->tp_done);
    g_free(ssd->tp_pending);
    g_free(ssd->tp_queued);
    g_free(ssd->tp_fifo);
    ssd->gtd = NULL;
    ssd->tp_ver = ssd->gtd_ver = NULL;
    ssd->tp_done = NULL;
    ssd->tp_pending = ssd->tp_queued = NULL;
    ssd->tp_fifo = NULL;
    ssd->tp_on = false;
}

/*
 * Give the TP pointer a line if it has none. The pointer takes one only
 * when it writes, so a full TP line never holds a free line nobody may use.
 * @reserve lets it take the free lines forced collection keeps.
 */
static bool tp_wp_ready(struct ssd *ssd, bool reserve)
{
    struct write_pointer *wp = &ssd->tp_wp;
    int keep = reserve ? 0 : ssd->sp.gc_thres_lines_high;
    struct line *line;

    if (wp->curline) {
        return true;
    }
    if (ssd->lm.free_line_cnt <= keep) {
        return false;
    }
    line = get_next_free_line(ssd);
    if (!line) {
        return false;
    }
    line->kind = LINE_TP;
    ssd_wp_reset(wp, line);
    return true;
}

/**
 * tp_program - write the current copy of a translation page
 * @ssd: the device
 * @tp: the TP
 * @reserve: may take the free lines forced collection keeps
 * @stime: when the program may start (0: now)
 * @timed: charge the program to the media
 * @done: set to the time the program ends (or the start, untimed)
 *
 * The old copy goes invalid and the GTD names the new one, which holds
 * every change so far. Returns false, changing nothing, with no page.
 */
bool tp_program(struct ssd *ssd, uint64_t tp, bool reserve, uint64_t stime,
                bool timed, uint64_t *done)
{
    struct write_pointer *wp = &ssd->tp_wp;
    struct ppa old = ssd->gtd[tp];
    struct ppa ppa;
    uint64_t t = tp_now(stime);

    if (!tp_wp_ready(ssd, reserve)) {
        return false;
    }
    ppa.ppa = 0;
    ppa.g.ch = wp->ch;
    ppa.g.lun = wp->lun;
    ppa.g.pl = wp->pl;
    ppa.g.pg = wp->pg;
    ppa.g.blk = wp->blk;

    if (mapped_ppa(&old)) {
        mark_page_invalid(ssd, &old);
        set_rmap_ent(ssd, INVALID_LPN, &old);
    }
    ssd->gtd[tp] = ppa;
    set_rmap_ent(ssd, TP_RMAP_TAG | tp, &ppa);
    mark_page_valid(ssd, &ppa);
    ssd->gtd_ver[tp] = ssd->tp_ver[tp];
    ssd->map_write_pages++;
    ssd_advance_tp_pointer(ssd);

    if (timed) {
        struct nand_cmd w = {
            .type = TP_IO,
            .cmd = NAND_WRITE,
            .stime = t,
        };

        t += ssd_advance_status(ssd, &ppa, &w);
        ssd->tp_done[tp] = t;
    }
    if (done) {
        *done = t;
    }
    return true;
}

/**
 * tp_read - read the flash copy of a translation page
 * @ssd: the device
 * @tp: the TP
 * @stime: when the read may start (0: now)
 * @timed: charge the read to the media
 *
 * A TP with no copy reads nothing: its mappings are all unmapped. A read
 * waits for a program of the same TP still under way. Returns the time the
 * TP is in DRAM.
 */
uint64_t tp_read(struct ssd *ssd, uint64_t tp, uint64_t stime, bool timed)
{
    struct ppa ppa = ssd->gtd[tp];
    uint64_t t = tp_now(stime);
    struct nand_cmd r = {
        .type = TP_IO,
        .cmd = NAND_READ,
    };
    int32_t slot = cmt_slot_of(ssd, tp);

    /* the copy is behind, and nothing holds the changes it lacks */
    if (ssd->tp_ver[tp] != ssd->gtd_ver[tp] &&
        !test_bit(tp, ssd->tp_pending) &&
        !(slot >= 0 && ssd->cmt.slots[slot].dirty)) {
        ssd->tp_stale_loads++;
    }

    if (!mapped_ppa(&ppa)) {
        return t;
    }
    ssd->map_read_pages++;
    if (!timed) {
        return t;
    }
    t = MAX(t, ssd->tp_done[tp]);
    r.stime = t;
    return t + ssd_advance_status(ssd, &ppa, &r);
}

/* the pending set: a bit per TP, and a ring of the TPs in arrival order */
static void tp_queue_push(struct ssd *ssd, uint64_t tp, bool front)
{
    uint64_t at;

    if (test_bit(tp, ssd->tp_queued)) {
        return;
    }
    set_bit(tp, ssd->tp_queued);
    if (front) {
        ssd->tp_fifo_head = (ssd->tp_fifo_head + ssd->n_tps - 1) % ssd->n_tps;
        at = ssd->tp_fifo_head;
    } else {
        at = (ssd->tp_fifo_head + ssd->tp_fifo_cnt) % ssd->n_tps;
    }
    ssd->tp_fifo[at] = tp;
    ssd->tp_fifo_cnt++;
}

static uint64_t tp_queue_pop(struct ssd *ssd)
{
    uint64_t tp = ssd->tp_fifo[ssd->tp_fifo_head];

    ssd->tp_fifo_head = (ssd->tp_fifo_head + 1) % ssd->n_tps;
    ssd->tp_fifo_cnt--;
    clear_bit(tp, ssd->tp_queued);
    return tp;
}

/**
 * tp_note - a mapping of @lpn has changed
 *
 * A TP in the CMT gets dirty, the lazy update of DFTL. Any other TP goes
 * pending, to be read, merged and written once for every change a victim
 * or a command makes to it.
 */
void tp_note(struct ssd *ssd, uint64_t lpn)
{
    uint64_t tp;
    int32_t slot;

    if (!ssd->tp_on) {
        return;
    }
    tp = lpn / ssd->cmt.lpn_per_tp;
    slot = cmt_slot_of(ssd, tp);
    if (slot >= 0) {
        ssd->cmt.slots[slot].dirty = true;
        return;
    }
    set_bit(tp, ssd->tp_pending);
    tp_queue_push(ssd, tp, false);
}

/* the pending changes of @tp now live elsewhere: a CMT slot or a new copy */
void tp_pending_drop(struct ssd *ssd, uint64_t tp)
{
    clear_bit(tp, ssd->tp_pending);
}

bool tp_pending(struct ssd *ssd, uint64_t tp)
{
    return test_bit(tp, ssd->tp_pending);
}

/**
 * tp_publish - write the pending TPs, one read-modify-write each
 * @ssd: the device
 * @stime: when the batch starts (0: now)
 * @timed: charge the reads and programs
 *
 * Stops at the first TP with no page to go to, which stays pending at the
 * head for the next call. The TPs run in parallel: each program waits only
 * for its own read. Returns the time the last one ends.
 */
uint64_t tp_publish(struct ssd *ssd, uint64_t stime, bool timed)
{
    uint64_t end = tp_now(stime);

    for (uint64_t n = ssd->tp_fifo_cnt; n; n--) {
        uint64_t tp = tp_queue_pop(ssd);
        uint64_t rd;
        uint64_t done;

        if (!test_bit(tp, ssd->tp_pending)) {
            continue;
        }
        /* no page to write to: stop before the read, which a retry repeats */
        if (!tp_wp_ready(ssd, false)) {
            tp_queue_push(ssd, tp, true);
            break;
        }
        rd = tp_read(ssd, tp, stime, timed);
        if (!tp_program(ssd, tp, false, rd, timed, &done)) {
            tp_queue_push(ssd, tp, true);
            break;
        }
        clear_bit(tp, ssd->tp_pending);
        end = MAX(end, done);
    }
    return end;
}

/**
 * tp_move - relocate the TP at @old_ppa for collection
 *
 * Reads the copy and writes the current mapping of the TP, so a change
 * pending or dirty in the CMT goes out with it. May use the reserve: it is
 * what frees a TP line. Returns false, with nothing changed, when there is
 * no page or the GTD does not name @old_ppa.
 */
bool tp_move(struct ssd *ssd, struct ppa *old_ppa)
{
    uint64_t owner = get_rmap_ent(ssd, old_ppa);
    uint64_t tp = owner & ~TP_RMAP_TAG;
    bool timed = ssd->sp.enable_gc_delay;
    struct ppa ppa;
    int32_t slot;
    uint64_t rd;

    if (!rmap_is_tp(owner) || tp >= ssd->n_tps ||
        ssd->gtd[tp].ppa != old_ppa->ppa) {
        ftl_err("TP page " PPA_FMT " has owner 0x%" PRIx64
                " that the GTD does not confirm\n", PPA_ARG(old_ppa), owner);
        return false;
    }
    /* the copy reaches DRAM before the program can start */
    rd = tp_read(ssd, tp, 0, timed);
    if (!tp_program(ssd, tp, true, rd, timed, NULL)) {
        return false;
    }
    clear_bit(tp, ssd->tp_pending);
    slot = cmt_slot_of(ssd, tp);
    if (slot >= 0) {
        ssd->cmt.slots[slot].dirty = false;
    }
    ppa = ssd->gtd[tp];
    get_lun(ssd, &ppa)->gc_endtime = get_lun(ssd, &ppa)->next_lun_avail_time;
    ssd->tp_moves++;
    return true;
}

/**
 * tp_discard_all - drop every translation page, as a Format or a Sanitize
 *
 * The caller has unmapped every logical page, so the mappings the TPs held
 * are gone: their pages go invalid with no write-back, the GTD, the CMT and
 * the pending set empty, and the TP pointer's line closes so collection can
 * take it.
 */
void tp_discard_all(struct ssd *ssd)
{
    if (!ssd->tp_on) {
        return;
    }
    for (uint64_t tp = 0; tp < ssd->n_tps; tp++) {
        struct ppa ppa = ssd->gtd[tp];

        if (mapped_ppa(&ppa)) {
            mark_page_invalid(ssd, &ppa);
            set_rmap_ent(ssd, INVALID_LPN, &ppa);
            ssd->gtd[tp].ppa = UNMAPPED_PPA;
        }
    }
    memset(ssd->tp_ver, 0, sizeof(*ssd->tp_ver) * ssd->n_tps);
    memset(ssd->gtd_ver, 0, sizeof(*ssd->gtd_ver) * ssd->n_tps);
    memset(ssd->tp_done, 0, sizeof(*ssd->tp_done) * ssd->n_tps);
    bitmap_zero(ssd->tp_pending, ssd->n_tps);
    bitmap_zero(ssd->tp_queued, ssd->n_tps);
    ssd->tp_fifo_head = 0;
    ssd->tp_fifo_cnt = 0;
    cmt_drop_all(ssd);
    ssd_close_pointer(ssd, &ssd->tp_wp);
}

/**
 * tp_check - check the TPs against the GTD, the media and the versions
 * @ssd: the device
 * @tp_pages: set to the valid TP pages on the media
 *
 * Returns the count of broken rules: a GTD entry whose page is not a valid
 * page tagged with its own TP in a TP line; a valid page whose owner kind is
 * not the kind of its line; a tagged page the GTD does not name; a TP whose
 * flash copy is behind its mappings while it is neither dirty in the CMT
 * nor pending, or that is both cached and pending; and every load of a
 * copy that was behind in that way (tp_stale_loads).
 */
uint64_t tp_check(struct ssd *ssd, uint64_t *tp_pages)
{
    struct ssdparams *spp = &ssd->sp;
    uint64_t bad = ssd->tp_stale_loads;
    struct ppa ppa;

    *tp_pages = 0;
    for (uint64_t tp = 0; ssd->tp_on && tp < ssd->n_tps; tp++) {
        int32_t slot = cmt_slot_of(ssd, tp);
        bool pend = test_bit(tp, ssd->tp_pending);
        bool dirty = slot >= 0 && ssd->cmt.slots[slot].dirty;

        ppa = ssd->gtd[tp];
        if (mapped_ppa(&ppa) &&
            (!valid_ppa(ssd, &ppa) || get_pg(ssd, &ppa)->status != PG_VALID ||
             get_rmap_ent(ssd, &ppa) != (TP_RMAP_TAG | tp) ||
             get_line(ssd, &ppa)->kind != LINE_TP)) {
            bad++;
        }
        if (slot >= 0 && pend) {
            bad++;
        } else if (ssd->tp_ver[tp] != ssd->gtd_ver[tp] && !dirty && !pend) {
            bad++;
        }
    }

    ppa.ppa = 0;
    for (int ch = 0; ch < spp->nchs; ch++) {
        ppa.g.ch = ch;
        for (int lun = 0; lun < spp->luns_per_ch; lun++) {
            ppa.g.lun = lun;
            for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                ppa.g.pl = pl;
                for (int blk = 0; blk < spp->blks_per_pl; blk++) {
                    ppa.g.blk = blk;
                    for (int pg = 0; pg < spp->pgs_per_blk; pg++) {
                        uint64_t owner;
                        bool tp_line;

                        ppa.g.pg = pg;
                        if (get_pg(ssd, &ppa)->status != PG_VALID) {
                            continue;
                        }
                        owner = get_rmap_ent(ssd, &ppa);
                        tp_line = get_line(ssd, &ppa)->kind == LINE_TP;
                        if (!rmap_is_tp(owner)) {
                            bad += tp_line;
                            continue;
                        }
                        (*tp_pages)++;
                        owner &= ~TP_RMAP_TAG;
                        if (!tp_line || !ssd->tp_on || owner >= ssd->n_tps ||
                            ssd->gtd[owner].ppa != ppa.ppa) {
                            bad++;
                        }
                    }
                }
            }
        }
    }
    return bad;
}
