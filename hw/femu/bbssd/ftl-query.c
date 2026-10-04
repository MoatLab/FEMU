/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * bbssd state for query-femu. Runs on the controller's FTL thread between
 * two requests, so the lists, counters and pages it reads all describe the
 * same point in time.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "../femu-query.h"

static void ssd_query_mark_wp(uint8_t *state, struct write_pointer *wp)
{
    if (wp->curline) {
        state[wp->curline->id] = FEMU_LINE_STATE_OPEN;
    }
}

/*
 * The FTL keeps no state field per line: a line's state is the list that
 * holds it. Mark every line from the lists and the write pointers.
 */
static void ssd_query_line_states(struct ssd *ssd, uint8_t *state)
{
    struct line_mgmt *lm = &ssd->lm;
    pqueue_t *pq = lm->victim_line_pq;
    struct line *line;
    size_t i;

    memset(state, FEMU_LINE_STATE_UNLISTED, lm->tt_lines);
    QTAILQ_FOREACH(line, &lm->free_line_list, entry) {
        state[line->id] = FEMU_LINE_STATE_FREE;
    }
    QTAILQ_FOREACH(line, &lm->full_line_list, entry) {
        state[line->id] = FEMU_LINE_STATE_FULL;
    }
    for (i = 1; i < pq->size; i++) {
        state[((struct line *)pq->d[i])->id] = FEMU_LINE_STATE_VICTIM;
    }
    ssd_query_mark_wp(state, &ssd->wp);
    ssd_query_mark_wp(state, &ssd->hot_wp);
    ssd_query_mark_wp(state, &ssd->log_wp);
    ssd_query_mark_wp(state, &ssd->stream_gc_wp);
    for (i = 0; i < ARRAY_SIZE(ssd->stream_wp); i++) {
        ssd_query_mark_wp(state, &ssd->stream_wp[i]);
    }
    for (i = 0; i < (size_t)lm->tt_lines; i++) {
        if (lm->lines[i].reclaiming) {
            state[i] = FEMU_LINE_STATE_RECLAIMING;
        }
    }
}

/* A line takes block index @id in every plane of every LUN. */
static void ssd_query_line_wear(struct ssd *ssd, int id, FemuQueryLine *out)
{
    struct ssdparams *spp = &ssd->sp;
    uint32_t lo = UINT32_MAX;
    uint32_t hi = 0;

    for (int ch = 0; ch < spp->nchs; ch++) {
        for (int lun = 0; lun < spp->luns_per_ch; lun++) {
            for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                uint32_t e = ssd->ch[ch].lun[lun].pl[pl].blk[id].erase_cnt;

                lo = MIN(lo, e);
                hi = MAX(hi, e);
            }
        }
    }
    out->erase_min = lo;
    out->erase_max = hi;
}

void ssd_query_collect(struct ssd *ssd, FemuQueryNs *q)
{
    struct ssdparams *spp = &ssd->sp;
    struct line_mgmt *lm = &ssd->lm;
    uint32_t end;

    q->nchs = spp->nchs;
    q->luns_per_ch = spp->luns_per_ch;
    q->pls_per_lun = spp->pls_per_lun;
    q->blks_per_pl = spp->blks_per_pl;
    q->pgs_per_blk = spp->pgs_per_blk;
    q->page_size = ssd_page_size(ssd);
    q->pgs_per_line = spp->pgs_per_line;
    q->tt_lines = lm->tt_lines;

    q->host_pages = ssd->host_write_pages;
    q->nand_pages = ssd->nand_write_pages;
    q->gc_pages = ssd->gc_write_pages;
    q->erases = ssd->total_erases;

    q->free_lines = lm->free_line_cnt;
    q->victim_lines = lm->victim_line_cnt;
    q->full_lines = lm->full_line_cnt;

    q->nr_lines = 0;
    if (!q->lines || q->offset >= q->tt_lines) {
        return;
    }
    if (q->tt_lines > q->state_cap) {
        q->status = -ENOENT;    /* rebuilt since the caller sized the buffer */
        return;
    }
    ssd_query_line_states(ssd, q->state);
    end = MIN(q->tt_lines, q->offset + q->max_lines);
    for (uint32_t i = q->offset; i < end; i++) {
        struct line *line = &lm->lines[i];
        FemuQueryLine *out = &q->lines[q->nr_lines++];

        out->id = line->id;
        out->vpc = line->vpc;
        out->ipc = line->ipc;
        out->state = q->state[i];
        ssd_query_line_wear(ssd, i, out);
    }
}
