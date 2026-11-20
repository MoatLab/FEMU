/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The write plan of bbssd preconditioning (bbssd/ftl-precon-math.h)
 */

#include "qemu/osdep.h"
#include "hw/femu/bbssd/ftl-precon-math.h"

/* phase sizes round down, and the overwrite share counts filled pages */
static void test_sizes(void)
{
    g_assert_cmpuint(precon_fill_pages(1024, 100), ==, 1024);
    g_assert_cmpuint(precon_fill_pages(1024, 90), ==, 921);
    g_assert_cmpuint(precon_fill_pages(99, 1), ==, 0);
    g_assert_cmpuint(precon_fill_pages(0, 100), ==, 0);
    /* no overflow at the largest page count */
    g_assert_cmpuint(precon_fill_pages(UINT64_MAX, 100), ==, UINT64_MAX);
    g_assert_cmpuint(precon_overwrite_pages(921, 300), ==, 2763);
    g_assert_cmpuint(precon_overwrite_pages(921, 0), ==, 0);
    g_assert_cmpuint(precon_overwrite_pages(3, 50), ==, 1);
    g_assert_cmpuint(precon_overwrite_pages(1ULL << 60,
                                            PRECON_OVERWRITE_MAX_PCT), ==,
                     10ULL << 60);
}

/* phase 1 in order, then seq goes round the filled pages again */
static void test_seq(void)
{
    PreconPlan p;
    uint64_t lpn;
    uint64_t i = 0;

    precon_plan_init(&p, 10, 50, 250, true, 7);
    g_assert_cmpuint(p.fill, ==, 5);
    g_assert_cmpuint(p.overwrite, ==, 12);
    while (precon_plan_next(&p, &lpn)) {
        g_assert_cmpuint(lpn, ==, i < 5 ? i : (i - 5) % 5);
        i++;
    }
    g_assert_cmpuint(i, ==, 17);
    g_assert_false(precon_plan_next(&p, &lpn));
}

/* splitmix64: the published first output for seed 0, and fixed values */
static void test_rand_values(void)
{
    uint64_t s = 0;
    PreconPlan p;
    uint64_t lpn;
    const uint64_t want[] = { 316, 262, 638 };

    g_assert_cmphex(precon_rand_next(&s), ==, 0xe220a8397b1dcdafULL);
    g_assert_cmphex(precon_rand_next(&s), ==, 0x6e789e6aa1b965f4ULL);
    g_assert_cmphex(precon_rand_next(&s), ==, 0x06c45d188009454fULL);

    /* seed 11, 1000 filled pages: phase 2 starts with these pages */
    precon_plan_init(&p, 1000, 100, 1, false, 11);
    g_assert_cmpuint(p.overwrite, ==, 10);
    for (int i = 0; i < 1000; i++) {
        g_assert_true(precon_plan_next(&p, &lpn));
        g_assert_cmpuint(lpn, ==, i);
    }
    for (int i = 0; i < 3; i++) {
        g_assert_true(precon_plan_next(&p, &lpn));
        g_assert_cmpuint(lpn, ==, want[i]);
    }
}

/* every rand page is a filled one, and the draws are close to uniform */
static void test_rand_uniform(void)
{
    enum { BUCKETS = 64, DRAWS = 64 * 4096 };
    static uint32_t hist[BUCKETS];
    PreconPlan p;
    uint64_t lpn;
    double chi = 0;

    precon_plan_init(&p, BUCKETS, 100, DRAWS * 100ULL / BUCKETS, false, 3);
    g_assert_cmpuint(p.overwrite, ==, DRAWS);
    while (precon_plan_next(&p, &lpn)) {
        g_assert_cmpuint(lpn, <, BUCKETS);
        if (p.done > BUCKETS) {
            hist[lpn]++;
        }
    }
    for (int b = 0; b < BUCKETS; b++) {
        double d = hist[b] - (double)DRAWS / BUCKETS;

        chi += d * d / ((double)DRAWS / BUCKETS);
    }
    /* 63 degrees of freedom: the 99.9th percentile is about 104 */
    g_assert_cmpfloat(chi, <, 104.0);
}

/* a plan with nothing to fill writes nothing */
static void test_empty(void)
{
    PreconPlan p;
    uint64_t lpn;

    precon_plan_init(&p, 50, 1, 1000, false, 1);
    g_assert_cmpuint(precon_plan_total(&p), ==, 0);
    g_assert_false(precon_plan_next(&p, &lpn));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/femu/precon/sizes", test_sizes);
    g_test_add_func("/femu/precon/seq", test_seq);
    g_test_add_func("/femu/precon/rand-values", test_rand_values);
    g_test_add_func("/femu/precon/rand-uniform", test_rand_uniform);
    g_test_add_func("/femu/precon/empty", test_empty);
    return g_test_run();
}
