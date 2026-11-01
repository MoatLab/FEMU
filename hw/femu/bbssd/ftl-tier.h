/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * bbssd pSLC tier: a pool of lines that the FTL programs one bit per NAND
 * unit, in front of the dense (MLC, TLC or QLC) lines. See ftl-tier.c.
 *
 * The tier owns its lines. A pool line is never on the dense free list, the
 * full list or the victim queue, and its state lives here, not in the line.
 */
#ifndef __FEMU_BBSSD_FTL_TIER_H
#define __FEMU_BBSSD_FTL_TIER_H

#include "ftl.h"

enum ftl_tier_mode {
    FTL_TIER_OFF = 0,
    FTL_TIER_STATIC = 1,    /* a fixed pool, taken out of OP at realize */
};

/* what a host page does when the pool has no page for it */
enum ftl_tier_policy {
    FTL_TIER_DIRECT = 0,    /* program it on the dense frontier */
    FTL_TIER_THROUGH = 1,   /* fold a pool line first, then use the pool */
};

/* the state of a line, by line id; a line the tier does not own is dense */
enum ftl_tier_line_state {
    FTL_TIER_LINE_DENSE = 0,
    FTL_TIER_LINE_FREE,     /* erased, in the tier free list */
    FTL_TIER_LINE_OPEN,     /* the pSLC frontier writes it */
    FTL_TIER_LINE_CLOSED,   /* full, in the fold FIFO */
};

struct ftl_tier {
    int mode;
    int policy;
    int density;            /* bits per NAND unit of the dense lines */
    int blk_pgs;            /* usable pages of one pSLC block */
    int line_pgs;           /* usable pages of one pSLC line */
    int nlines;             /* lines in the pool */
    uint8_t *state;         /* enum ftl_tier_line_state, by line id */

    /* a pool line is on one of these, or the frontier holds it */
    QTAILQ_HEAD(, line) free_lines;
    QTAILQ_HEAD(, line) closed;     /* oldest first: the fold order */
    int free_cnt;
    int closed_cnt;
    struct write_pointer wp;        /* takes a line at its first write */

    uint64_t read_ns;       /* pSLC page read */
    uint64_t prog_ns;       /* pSLC page program */
    uint64_t erase_ns;      /* pSLC block erase */

    /* wear: pSLC erases by block; erase_cnt minus these is dense wear */
    uint32_t *slc_erases;
    uint64_t dense_limit;
    uint64_t slc_limit;

    uint64_t valid;         /* valid pages in pool lines */
    uint64_t host_pslc;     /* host pages programmed in the pool */
    uint64_t host_dense;    /* host pages the full policy sent to dense */
    uint64_t fold_pages;    /* pages folds moved, also in gc_write_pages */
    uint64_t folds;         /* pool lines folded and erased */
    uint64_t slc_erase_total;
    uint64_t fold_stale;    /* valid pool pages no mapping named */
    uint64_t last_fold_ns;  /* first read to last erase of the last fold */
};

/* true when the tier owns @line: a pool line in any state */
static inline bool ftl_tier_owns(struct ssd *ssd, struct line *line)
{
    return unlikely(ssd->tier) &&
           ssd->tier->state[line->id] != FTL_TIER_LINE_DENSE;
}

/*
 * The pages a block of @line takes. Physical indexing keeps the dense
 * size, so a pSLC block uses only its first pages and the rest stay free.
 */
static inline int ssd_blk_usable_pgs(struct ssd *ssd, struct line *line)
{
    return ftl_tier_owns(ssd, line) ? ssd->tier->blk_pgs :
                                      ssd->sp.pgs_per_blk;
}

/* the pages @line takes; pgs_per_line for a dense line */
static inline int ssd_line_usable_pgs(struct ssd *ssd, struct line *line)
{
    return ftl_tier_owns(ssd, line) ? ssd->tier->line_pgs :
                                      ssd->sp.pgs_per_line;
}

void ftl_tier_init(struct ssd *ssd, FemuCtrl *n);
void ftl_tier_take_lines(struct ssd *ssd);
void ftl_tier_free(struct ssd *ssd);
void ftl_tier_media_cfg(struct ssd *ssd, NandMediaConfig *cfg);
void ftl_tier_decode(struct ssd *ssd, struct ppa *ppa, NandLoc *loc);
bool ftl_tier_invalidate(struct ssd *ssd, struct line *line);
bool ftl_tier_host_page(struct ssd *ssd, struct ppa *ppa, uint64_t *stime,
                        uint64_t *base);
void ftl_tier_advance(struct ssd *ssd);
void ftl_tier_tick(struct ssd *ssd);

#endif /* __FEMU_BBSSD_FTL_TIER_H */
