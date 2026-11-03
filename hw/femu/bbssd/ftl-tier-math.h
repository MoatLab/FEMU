/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Pool arithmetic of the bbssd pSLC tier. Pure functions with no FTL state,
 * so the unit test (tests/unit/test-tier-math.c) builds them alone.
 */
#ifndef __FEMU_BBSSD_FTL_TIER_MATH_H
#define __FEMU_BBSSD_FTL_TIER_MATH_H

#include <stdint.h>

/*
 * Usable pSLC pages of a block of @pgs_per_blk dense pages at @density bits
 * per NAND unit. Each block rounds down by itself, so a line of N blocks
 * holds N times this, not the line total divided by @density.
 */
static inline uint32_t tier_blk_pgs(uint32_t pgs_per_blk, uint32_t density)
{
    return density ? pgs_per_blk / density : 0;
}

/* lines that hold @mb MiB of host data, @line_pgs pages of @page_bytes each */
static inline uint64_t tier_pool_lines(uint64_t mb, uint64_t page_bytes,
                                       uint64_t line_pgs)
{
    uint64_t line_bytes = page_bytes * line_pgs;

    if (!line_bytes) {
        return 0;
    }
    return (mb * 1048576ULL + line_bytes - 1) / line_bytes;
}

/* the pSLC erase rating: @pslc_pe, or 30 times the dense rating @dense_pe */
static inline uint64_t tier_slc_limit(uint32_t pslc_pe, uint32_t dense_pe)
{
    return pslc_pe ? pslc_pe : 30ULL * dense_pe;
}

/*
 * The wear of a block in millionths of its life: dense erases against the
 * dense rating plus pSLC erases against the pSLC rating. A rating of 0
 * adds nothing.
 */
static inline uint64_t tier_damage_ppm(uint64_t dense_erases,
                                       uint64_t dense_limit,
                                       uint64_t slc_erases,
                                       uint64_t slc_limit)
{
    uint64_t ppm = 0;

    if (dense_limit) {
        ppm += dense_erases * 1000000ULL / dense_limit;
    }
    if (slc_limit) {
        ppm += slc_erases * 1000000ULL / slc_limit;
    }
    return ppm;
}

/* whole lines of @line_pgs pages of @page_bytes each in @mb MiB: a cap */
static inline uint64_t tier_cap_lines(uint64_t mb, uint64_t page_bytes,
                                      uint64_t line_pgs)
{
    uint64_t line_bytes = page_bytes * line_pgs;

    return line_bytes ? mb * 1048576ULL / line_bytes : 0;
}

/*
 * The borrowed lines a dynamic pool may hold at a fill of @live of @total
 * host pages: @dmax up to @shrink_pct percent fill, then a straight line
 * down to 0 at a full device.
 */
static inline uint64_t tier_allowed(uint64_t dmax, uint64_t live,
                                    uint64_t total, uint32_t shrink_pct)
{
    uint64_t start;

    if (!total || live >= total) {
        return 0;
    }
    start = total * shrink_pct / 100;
    if (live <= start) {
        return dmax;
    }
    return dmax * (total - live) / (total - start);
}

#endif /* __FEMU_BBSSD_FTL_TIER_MATH_H */
