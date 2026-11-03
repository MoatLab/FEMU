/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Pool arithmetic of the bbssd pSLC tier (bbssd/ftl-tier-math.h)
 */

#include "qemu/osdep.h"
#include "hw/femu/bbssd/ftl-tier-math.h"

/* each block rounds down by itself: 256 TLC pages give 85, not 85.33 */
static void test_blk_pgs(void)
{
    g_assert_cmpuint(tier_blk_pgs(256, 2), ==, 128);
    g_assert_cmpuint(tier_blk_pgs(256, 3), ==, 85);
    g_assert_cmpuint(tier_blk_pgs(256, 4), ==, 64);
    g_assert_cmpuint(tier_blk_pgs(48, 3), ==, 16);
    g_assert_cmpuint(tier_blk_pgs(2, 3), ==, 0);
    g_assert_cmpuint(tier_blk_pgs(256, 0), ==, 0);
    /* 64 blocks of 85 pages, not floor(64 * 256 / 3) = 5461 */
    g_assert_cmpuint(64 * tier_blk_pgs(256, 3), ==, 5440);
}

/* whole lines, rounded up, to hold the host data */
static void test_pool_lines(void)
{
    /* 4 dies of 16 pSLC pages of 4 KiB: 256 KiB per line */
    g_assert_cmpuint(tier_pool_lines(1, 4096, 64), ==, 4);
    g_assert_cmpuint(tier_pool_lines(3, 4096, 64), ==, 12);
    /* 5440 pages of 4 KiB per line: 64 MiB needs 4 lines, not 3 */
    g_assert_cmpuint(tier_pool_lines(64, 4096, 5440), ==, 4);
    g_assert_cmpuint(tier_pool_lines(0, 4096, 64), ==, 0);
    g_assert_cmpuint(tier_pool_lines(1, 4096, 0), ==, 0);
    g_assert_cmpuint(tier_pool_lines(1, 0, 64), ==, 0);
}

static void test_slc_limit(void)
{
    g_assert_cmpuint(tier_slc_limit(0, 1000), ==, 30000);
    g_assert_cmpuint(tier_slc_limit(50000, 1000), ==, 50000);
    g_assert_cmpuint(tier_slc_limit(0, UINT32_MAX), ==, 30ULL * UINT32_MAX);
    g_assert_cmpuint(tier_slc_limit(0, 0), ==, 0);
}

/* one unit for both kinds of erase: the share of each rating used */
static void test_damage(void)
{
    g_assert_cmpuint(tier_damage_ppm(300, 1000, 15000, 30000), ==, 800000);
    g_assert_cmpuint(tier_damage_ppm(0, 1000, 30000, 30000), ==, 1000000);
    g_assert_cmpuint(tier_damage_ppm(1000, 1000, 0, 30000), ==, 1000000);
    /* a pSLC erase costs a thirtieth of a dense one, not the same */
    g_assert_cmpuint(tier_damage_ppm(0, 1000, 1, 30000), ==, 33);
    g_assert_cmpuint(tier_damage_ppm(5, 0, 7, 0), ==, 0);
}

/* a cap counts whole lines only, so it rounds down */
static void test_cap_lines(void)
{
    /* 64 pages of 4 KiB: 256 KiB a line */
    g_assert_cmpuint(tier_cap_lines(1, 4096, 64), ==, 4);
    /* 5440 pages of 4 KiB: 64 MiB is 3 lines, not 4 as for a pool */
    g_assert_cmpuint(tier_cap_lines(64, 4096, 5440), ==, 3);
    g_assert_cmpuint(tier_pool_lines(64, 4096, 5440), ==, 4);
    g_assert_cmpuint(tier_cap_lines(1, 4096, 5440), ==, 0);
    g_assert_cmpuint(tier_cap_lines(1, 4096, 0), ==, 0);
}

/* the borrowed-line allowance: flat to the shrink point, then down to 0 */
static void test_allowed(void)
{
    g_assert_cmpuint(tier_allowed(32, 0, 4096, 50), ==, 32);
    g_assert_cmpuint(tier_allowed(32, 2048, 4096, 50), ==, 32);
    g_assert_cmpuint(tier_allowed(32, 3072, 4096, 50), ==, 16);
    g_assert_cmpuint(tier_allowed(32, 4095, 4096, 50), ==, 0);
    g_assert_cmpuint(tier_allowed(32, 4096, 4096, 50), ==, 0);
    g_assert_cmpuint(tier_allowed(32, 5000, 4096, 50), ==, 0);
    /* 32 x 1024 / 3687 at a shrink point of 10% */
    g_assert_cmpuint(tier_allowed(32, 3072, 4096, 10), ==, 8);
    /* shrink at 0%: a straight line from empty */
    g_assert_cmpuint(tier_allowed(32, 1024, 4096, 0), ==, 24);
    g_assert_cmpuint(tier_allowed(32, 0, 0, 50), ==, 0);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/femu/tier/blk-pgs", test_blk_pgs);
    g_test_add_func("/femu/tier/pool-lines", test_pool_lines);
    g_test_add_func("/femu/tier/slc-limit", test_slc_limit);
    g_test_add_func("/femu/tier/damage", test_damage);
    g_test_add_func("/femu/tier/allowed", test_allowed);
    g_test_add_func("/femu/tier/cap-lines", test_cap_lines);
    return g_test_run();
}
