/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * bbssd pSLC tier: the seam between the FTL and an optional pool of lines
 * that the FTL programs one bit per NAND unit. Nothing builds the pool yet,
 * so ssd->tier stays NULL and every hook in the FTL returns at once.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"

/* lines the pSLC pool takes out of the dense lines; no pool yet */
uint64_t bb_tier_pool_lines(FemuCtrl *n)
{
    (void)n;
    return 0;
}

void ftl_tier_init(struct ssd *ssd, FemuCtrl *n)
{
    (void)n;
    ssd->tier = NULL;
}

/* move the pool lines out of the dense free list, highest ids first */
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

/* the pool has no page to give yet: every host page goes dense */
bool ftl_tier_host_page(struct ssd *ssd, struct ppa *ppa, uint64_t *stime,
                        uint64_t *base)
{
    (void)ppa;
    (void)stime;
    (void)base;
    ssd->tier->host_dense++;
    return false;
}

/* step the pSLC frontier, and close a full line into the FIFO */
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

/* the work the tier does after each request; none yet */
void ftl_tier_tick(struct ssd *ssd)
{
    (void)ssd;
}
