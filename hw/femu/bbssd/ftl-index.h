/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_FEMU_BBSSD_FTL_INDEX_H
#define HW_FEMU_BBSSD_FTL_INDEX_H

#include <stdint.h>

/*
 * The flat index of a physical page, as the rmap and the page state arrays
 * use it. The PPA bit fields promote to int, so each term is widened to 64
 * bits before its product: a device can have more than 2^31 pages.
 */
static inline uint64_t ftl_page_index(uint64_t ch, uint64_t lun, uint64_t pl,
                                      uint64_t blk, uint64_t pg,
                                      uint64_t pgs_per_ch,
                                      uint64_t pgs_per_lun,
                                      uint64_t pgs_per_pl,
                                      uint64_t pgs_per_blk)
{
    return ch * pgs_per_ch + lun * pgs_per_lun + pl * pgs_per_pl +
           blk * pgs_per_blk + pg;
}

#endif
