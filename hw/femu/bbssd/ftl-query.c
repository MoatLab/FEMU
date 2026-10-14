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
    for (i = 0; i < (size_t)lm->tt_lines; i++) {
        if (lm->lines[i].retired) {
            state[i] = FEMU_LINE_STATE_RETIRED;
        } else if (lm->lines[i].spare) {
            state[i] = FEMU_LINE_STATE_SPARE;
        }
    }
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
static void ssd_query_block_wear(struct ssd *ssd, int id, uint32_t *lo,
                                 uint32_t *hi)
{
    struct ssdparams *spp = &ssd->sp;

    for (int ch = 0; ch < spp->nchs; ch++) {
        for (int lun = 0; lun < spp->luns_per_ch; lun++) {
            for (int pl = 0; pl < spp->pls_per_lun; pl++) {
                uint32_t e = ssd->ch[ch].lun[lun].pl[pl].blk[id].erase_cnt;

                *lo = MIN(*lo, e);
                *hi = MAX(*hi, e);
            }
        }
    }
}

static void ssd_query_line_wear(struct ssd *ssd, int id, FemuQueryLine *out)
{
    uint32_t lo = UINT32_MAX;
    uint32_t hi = 0;

    ssd_query_block_wear(ssd, id, &lo, &hi);
    out->erase_min = lo;
    out->erase_max = hi;
}

/* Unit @u of group @g, at index g * units-per-group + u in @state. */
static uint32_t ssd_query_ru_index(struct ssd *ssd, FemuReclaimUnit *ru)
{
    return ru->rgidx * ssd->rg[0].tt_nru + ru->ruidx;
}

/*
 * Like lines, a reclaim unit's state is the list or heap that holds it, or
 * the handle that writes to it. Free comes first: a free unit keeps the
 * handle that last wrote it.
 */
static void ssd_query_ru_states(struct ssd *ssd, uint8_t *state)
{
    FemuReclaimUnit *ru;

    memset(state, FEMU_RECLAIM_UNIT_STATE_UNLISTED,
           ssd->nrg * ssd->rg[0].tt_nru);
    for (uint64_t g = 0; g < ssd->nrg; g++) {
        struct ru_mgmt *rm = ssd->rg[g].ru_mgmt;

        QTAILQ_FOREACH(ru, &rm->full_ru_list, entry) {
            state[ssd_query_ru_index(ssd, ru)] = FEMU_RECLAIM_UNIT_STATE_FULL;
        }
        for (int i = 0; i < ssd->rg[g].tt_nru; i++) {
            if (ssd->rg[g].rus[i].pos) {
                state[ssd_query_ru_index(ssd, &ssd->rg[g].rus[i])] =
                    FEMU_RECLAIM_UNIT_STATE_VICTIM;
            }
        }
    }
    for (uint64_t h = 0; h < ssd->nruhs; h++) {
        FemuRuHandle *ruh = &ssd->ruhs[h];

        if (ruh->curr_ru) {
            state[ssd_query_ru_index(ssd, ruh->curr_ru)] =
                FEMU_RECLAIM_UNIT_STATE_OPEN;
        }
        if (ruh->gc_ru) {
            state[ssd_query_ru_index(ssd, ruh->gc_ru)] =
                FEMU_RECLAIM_UNIT_STATE_OPEN;
        }
    }
    for (uint64_t g = 0; g < ssd->nrg; g++) {
        QTAILQ_FOREACH(ru, &ssd->rg[g].ru_mgmt->free_ru_list, entry) {
            state[ssd_query_ru_index(ssd, ru)] = FEMU_RECLAIM_UNIT_STATE_FREE;
        }
    }
}

static void ssd_query_fdp(struct ssd *ssd, FemuQueryNs *q)
{
    uint32_t total = ssd->nrg * ssd->rg[0].tt_nru;
    uint32_t end;

    q->nrg = ssd->nrg;
    q->rus_per_rg = ssd->rg[0].tt_nru;
    q->pgs_per_ru = ssd->rg[0].rus[0].npages;
    if (ssd->nruhs != q->nr_ruhs || total > q->ru_state_cap) {
        q->status = -ENOENT;    /* rebuilt since the caller sized the buffers */
        return;
    }
    for (uint32_t h = 0; h < q->nr_ruhs; h++) {
        FemuRuHandle *ruh = &ssd->ruhs[h];

        q->ruhs[h].id = ruh->ruhid;
        q->ruhs[h].type = ruh->ruh_type == NVME_RUHT_PERSISTENTLY_ISOLATED ?
                          FEMU_RU_HANDLE_TYPE_PERSISTENTLY_ISOLATED :
                          FEMU_RU_HANDLE_TYPE_INITIALLY_ISOLATED;
        /*
         * The subsystem's handle lives as long as the FDP Statistics log; the
         * controller's copy starts again at zero when a controller replaces
         * another on the same subsystem.
         */
        q->ruhs[h].host_bytes = ruh->ruh ? ruh->ruh->hbmw : ruh->hbmw;
        q->ruhs[h].media_bytes = ruh->ruh ? ruh->ruh->mbmw : ruh->mbmw;
    }

    ssd_query_ru_states(ssd, q->ru_state);
    memset(q->ru_counts, 0, sizeof(q->ru_counts));
    for (uint32_t i = 0; i < total; i++) {
        q->ru_counts[q->ru_state[i]]++;
    }

    q->nr_rus = 0;
    if (!q->rus || q->offset >= total) {
        return;
    }
    end = MIN(total, q->offset + q->max_rus);
    for (uint32_t i = q->offset; i < end; i++) {
        FemuReclaimUnit *ru = &ssd->rg[i / q->rus_per_rg].rus[i % q->rus_per_rg];
        FemuQueryRu *out = &q->rus[q->nr_rus++];
        uint32_t lo = UINT32_MAX;
        uint32_t hi = 0;

        out->group = ru->rgidx;
        out->unit = ru->ruidx;
        out->state = q->ru_state[i];
        out->has_handle = out->state != FEMU_RECLAIM_UNIT_STATE_FREE &&
                          ru->ruh;
        out->handle = out->has_handle ? ru->ruh->ruhid : 0;
        out->vpc = ru->vpc;
        out->ipc = ru->ipc;
        for (int l = 0; l < ru->n_lines; l++) {
            ssd_query_block_wear(ssd, ru->lines[l]->id, &lo, &hi);
        }
        out->erase_min = lo;
        out->erase_max = hi;
    }
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
    q->pad_pages = ssd->pd_pad_pages;
    q->erases = ssd->total_erases;

    q->fdp = ssd->fdp_enabled;
    if (q->fdp) {
        ssd_query_fdp(ssd, q);
        return;
    }

    q->free_lines = lm->free_line_cnt;
    q->victim_lines = pqueue_size(lm->victim_line_pq);
    q->full_lines = lm->full_line_cnt;
    q->retired_lines = lm->retired_line_cnt;
    q->spare_lines = ssd->spare_lines;

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
