/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU bbssd page index tests: the flat page index past 2^31 and 2^32
 */

#include "qemu/osdep.h"
#include "hw/femu/bbssd/ftl-index.h"

/* the geometry of one line per plane block: g.pg + blk * pgs_per_blk + ... */
typedef struct Geo {
    uint64_t chs, luns, pls, blks, pgs;
} Geo;

static uint64_t idx(const Geo *g, uint64_t ch, uint64_t lun, uint64_t pl,
                    uint64_t blk, uint64_t pg)
{
    uint64_t per_pl = g->blks * g->pgs;
    uint64_t per_lun = per_pl * g->pls;
    uint64_t per_ch = per_lun * g->luns;

    return ftl_page_index(ch, lun, pl, blk, pg, per_ch, per_lun, per_pl,
                          g->pgs);
}

/*
 * The old index: each term an int product, the sum an int. Here in uint32_t,
 * which wraps the same way with no undefined behaviour, then sign-extended
 * as the int sum was on assignment to uint64_t.
 */
static uint64_t idx_old(const Geo *g, uint32_t ch, uint32_t lun, uint32_t pl,
                        uint32_t blk, uint32_t pg)
{
    uint32_t per_pl = g->blks * g->pgs;
    uint32_t per_lun = per_pl * g->pls;
    uint32_t per_ch = per_lun * g->luns;
    uint32_t sum = ch * per_ch + lun * per_lun + pl * per_pl +
                   blk * (uint32_t)g->pgs + pg;

    return (uint64_t)(int64_t)(int32_t)sum;
}

/* 129 channels of 2^24 pages: channel 128 starts at page 2^31 */
static void test_channel_term(void)
{
    Geo g = { 129, 1, 1, 256, 65536 };

    g_assert_cmpuint(idx(&g, 127, 0, 0, 255, 65535), ==, (1ULL << 31) - 1);
    g_assert_cmpuint(idx(&g, 128, 0, 0, 0, 0), ==, 1ULL << 31);
    g_assert_cmpuint(idx(&g, 128, 0, 0, 255, 65535), ==,
                     (1ULL << 31) + (1ULL << 24) - 1);
    /* the control: the old index agreed below 2^31 and was wrong at it */
    g_assert_cmpuint(idx_old(&g, 127, 0, 0, 255, 65535), ==, (1ULL << 31) - 1);
    g_assert_cmpuint(idx_old(&g, 128, 0, 0, 0, 0), !=, 1ULL << 31);
}

/* 4096 channels of 2^21 pages: channel 2048 starts at page 2^32 */
static void test_at_2_32(void)
{
    Geo g = { 4096, 1, 1, 32, 65536 };

    g_assert_cmpuint(idx(&g, 2048, 0, 0, 0, 0), ==, 1ULL << 32);
    g_assert_cmpuint(idx(&g, 2048, 0, 0, 0, 1), ==, (1ULL << 32) + 1);
    g_assert_cmpuint(idx(&g, 4095, 0, 0, 31, 65535), ==, (1ULL << 33) - 1);
    /* the old index wrapped to 0 here */
    g_assert_cmpuint(idx_old(&g, 2048, 0, 0, 0, 0), ==, 0);
}

/* 4096 channels of 2^20 pages: the last channel ends at 2^32 */
static void test_below_2_32(void)
{
    Geo g = { 4096, 1, 1, 16, 65536 };

    g_assert_cmpuint(idx(&g, 4095, 0, 0, 15, 65535), ==, (1ULL << 32) - 1);
    g_assert_cmpuint(idx(&g, 2048, 0, 0, 0, 0), ==, 1ULL << 31);
}

/* one plane of 65536 blocks of 65536 pages: blk * pgs_per_blk passes 2^31 */
static void test_block_term(void)
{
    Geo g = { 1, 1, 1, 65536, 65536 };

    g_assert_cmpuint(idx(&g, 0, 0, 0, 32768, 0), ==, 1ULL << 31);
    g_assert_cmpuint(idx(&g, 0, 0, 0, 65535, 65535), ==, (1ULL << 32) - 1);
    g_assert_cmpuint(idx_old(&g, 0, 0, 0, 32768, 0), !=, 1ULL << 31);
}

/* the LUN and plane terms with the largest field values */
static void test_lun_plane_terms(void)
{
    Geo g = { 2, 128, 16, 256, 4096 };
    uint64_t per_pl = 256ULL * 4096;

    g_assert_cmpuint(idx(&g, 1, 127, 15, 0, 0), ==,
                     per_pl * 16 * 128 + 127 * per_pl * 16 + 15 * per_pl);
    g_assert_cmpuint(idx(&g, 1, 127, 15, 255, 4095), ==,
                     2 * 128 * 16 * per_pl - 1);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/femu/ftl-index/channel-term", test_channel_term);
    g_test_add_func("/femu/ftl-index/below-2-32", test_below_2_32);
    g_test_add_func("/femu/ftl-index/at-2-32", test_at_2_32);
    g_test_add_func("/femu/ftl-index/block-term", test_block_term);
    g_test_add_func("/femu/ftl-index/lun-plane-terms", test_lun_plane_terms);
    return g_test_run();
}
