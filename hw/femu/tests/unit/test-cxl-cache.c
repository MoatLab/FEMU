/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "qemu/osdep.h"
#include "../cxlssd/cache.h"
#include "../cxlssd/der.h"

static unsigned dirty_count;

static bool record_dirty(void *opaque, FemuCxlEntry *entry)
{
    (void)opaque;
    dirty_count += entry->dirty;
    return true;
}

static void exercise(FemuCxlPolicy policy, unsigned ways)
{
    FemuCxlCache c;
    unsigned i;
    unsigned round;

    dirty_count = 0;
    femu_cxl_cache_init(&c, 32, ways, policy);
    for (round = 0; round < 4; round++) {
        for (i = 0; i < 10000; i++) {
            uint64_t lpn = ((uint64_t)(i % 3) << 32) + i % 61;
            FemuCxlEntry *e = femu_cxl_cache_find(&c, lpn);

            if (!e) {
                e = femu_cxl_cache_insert(&c, lpn, record_dirty, NULL);
            }
            g_assert_nonnull(e);
            g_assert_cmpuint(e->lpn, ==, lpn);
            e->dirty = true;
            g_assert_cmpuint(g_hash_table_size(c.entries), <=, 32);
        }
        g_assert_true(femu_cxl_cache_clear(&c, record_dirty, NULL));
        g_assert_cmpuint(g_hash_table_size(c.entries), ==, 0);
        g_assert_cmpuint(c.inserts, ==, c.evictions);
        g_assert_cmpuint(dirty_count, ==, c.evictions);
    }
    femu_cxl_cache_destroy(&c);
}

static void ordering(void)
{
    FemuCxlCache c;
    FemuCxlPolicy p;

    for (p = FEMU_CXL_FIFO; p <= FEMU_CXL_CLOCK; p++) {
        femu_cxl_cache_init(&c, 3, 3, p);
        femu_cxl_cache_insert(&c, 0, NULL, NULL);
        femu_cxl_cache_insert(&c, 1ULL << 32, NULL, NULL);
        femu_cxl_cache_insert(&c, UINT64_MAX, NULL, NULL);
        femu_cxl_cache_insert(&c, 7, NULL, NULL);
        g_assert_null(femu_cxl_cache_find(&c,
                      p == FEMU_CXL_LIFO ? UINT64_MAX : 0));
        g_assert_nonnull(femu_cxl_cache_find(&c, 1ULL << 32));
        femu_cxl_cache_destroy(&c);
    }
}

static void s3_promote(void)
{
    FemuCxlCache c;
    FemuCxlEntry *e;
    unsigned i;

    femu_cxl_cache_init(&c, 10, 10, FEMU_CXL_S3FIFO);
    for (i = 0; i < 10; i++) {
        femu_cxl_cache_insert(&c, i, NULL, NULL);
    }
    femu_cxl_cache_find(&c, 0);
    femu_cxl_cache_find(&c, 0);
    femu_cxl_cache_insert(&c, 10, NULL, NULL);
    g_assert_nonnull(femu_cxl_cache_find(&c, 0));
    g_assert_null(femu_cxl_cache_find(&c, 1));
    e = femu_cxl_cache_insert(&c, 1, NULL, NULL);
    g_assert_nonnull(g_queue_find(&c.sets[0].main, e));
    g_assert_cmpuint(c.sets[0].ghost.length, <=, 10);
    femu_cxl_cache_destroy(&c);
}

static void fully_associative(void)
{
    FemuCxlCache c;
    FemuCxlPolicy policy;
    const unsigned pages = 1258291;
    unsigned i;

    for (policy = FEMU_CXL_FIFO; policy <= FEMU_CXL_S3FIFO; policy++) {
        femu_cxl_cache_init(&c, pages, pages, policy);
        for (i = 0; i < 2 * pages; i++) {
            g_assert_nonnull(femu_cxl_cache_insert(&c, i, NULL, NULL));
        }
        g_assert_cmpuint(g_hash_table_size(c.entries), ==, pages);
        g_assert_cmpuint(c.evictions, ==, pages);
        for (i = 0; i < pages; i++) {
            g_assert_nonnull(femu_cxl_cache_insert(&c, i, NULL, NULL));
        }
        femu_cxl_cache_destroy(&c);
    }
}

static void direct_ratios(void)
{
    static const unsigned ratios[] = { 50, 75, 90, 95, 97, 98, 99, 995, 999 };
    static const unsigned periods[] = { 2, 4, 10, 20, 33, 50, 100, 200, 1000 };
    unsigned i;
    unsigned lpn;

    for (i = 0; i < G_N_ELEMENTS(ratios); i++) {
        unsigned selected = 0;

        for (lpn = 0; lpn < 1000; lpn++) {
            selected += femu_cxl_ratio_selected(ratios[i], lpn);
        }
        g_assert_cmpuint(selected, ==, 1000 - (999 / periods[i] + 1));
        g_assert_false(femu_cxl_ratio_selected(ratios[i], 0));
    }
    g_assert_false(femu_cxl_ratio_selected(0, 1));
    g_assert_true(femu_cxl_ratio_selected(100, 0));
}

int main(void)
{
    FemuCxlPolicy policy;
    unsigned ways;

    direct_ratios();
    fully_associative();
    ordering();
    s3_promote();
    for (policy = FEMU_CXL_FIFO; policy <= FEMU_CXL_S3FIFO; policy++) {
        for (ways = 1; ways <= 32; ways *= 2) {
            exercise(policy, ways);
        }
    }
    puts("CXL cache: ordering, large keys, dirty eviction, reset, "
         "all policies PASS");
    return 0;
}
