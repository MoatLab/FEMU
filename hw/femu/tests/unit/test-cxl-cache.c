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

/* Every node must point back at its entry, and the counts must agree. */
static void check_links(FemuCxlCache *c)
{
    static const FemuCxlQueue kinds[] = {
        FEMU_CXL_SMALL, FEMU_CXL_MAIN, FEMU_CXL_PINNED
    };
    uint64_t total = 0;
    uint64_t pinned = 0;
    uint32_t i;
    unsigned k;

    for (i = 0; i < c->nsets; i++) {
        FemuCxlSet *set = &c->sets[i];
        GQueue *queues[] = { &set->small, &set->main, &set->pinned };

        g_assert_cmpuint(set->small.length + set->main.length +
                         set->pinned.length, <=, c->ways);
        for (k = 0; k < G_N_ELEMENTS(queues); k++) {
            GList *l;

            for (l = queues[k]->head; l; l = l->next) {
                FemuCxlEntry *e = l->data;

                g_assert_true(e->link == l);
                g_assert_cmpint(e->queue, ==, kinds[k]);
                g_assert_true(g_hash_table_lookup(c->entries, &e->lpn) == e);
                g_assert_cmpuint(e->lpn % c->nsets, ==, i);
                total++;
            }
        }
        pinned += set->pinned.length;
    }
    g_assert_cmpuint(total, ==, g_hash_table_size(c->entries));
    g_assert_cmpuint(pinned, ==, c->pinned);
}

static FemuCxlEntry *touch(FemuCxlCache *c, uint64_t lpn)
{
    FemuCxlEntry *e = femu_cxl_cache_find(c, lpn);

    return e ? e : femu_cxl_cache_insert(c, lpn, NULL, NULL);
}

/* Pins survive any amount of traffic and use up to every way of a set. */
static void pin_policy(FemuCxlPolicy policy, uint32_t ways)
{
    const uint32_t nsets = 2;
    FemuCxlCache c;
    FemuCxlEntry *e;
    uint32_t i;

    femu_cxl_cache_init(&c, nsets * ways, ways, policy);
    e = femu_cxl_cache_insert(&c, 0, NULL, NULL);
    g_assert_cmpuint(femu_cxl_cache_pin_room(&c, 0), ==, ways);
    femu_cxl_cache_pin(&c, e);
    femu_cxl_cache_pin(&c, e);
    g_assert_cmpuint(c.pinned, ==, 1);
    g_assert_cmpuint(femu_cxl_cache_pin_room(&c, 0), ==, ways - 1);
    g_assert_cmpuint(femu_cxl_cache_pin_room(&c, 1), ==, ways);
    for (i = 1; i < 20 * ways; i++) {
        /* One way pinned is the whole set: its misses stay uncached. */
        if (ways == 1) {
            g_assert_null(touch(&c, (uint64_t)i * nsets));
        } else {
            g_assert_nonnull(touch(&c, (uint64_t)i * nsets));
        }
        check_links(&c);
    }
    g_assert_true(femu_cxl_cache_find(&c, 0) == e);

    /* Pin the rest of set 0; its misses then have nowhere to go. */
    for (i = 1; i < ways; i++) {
        FemuCxlEntry *p = femu_cxl_cache_insert(&c, (uint64_t)i * nsets,
                                                NULL, NULL);

        g_assert_nonnull(p);
        femu_cxl_cache_pin(&c, p);
    }
    g_assert_cmpuint(femu_cxl_cache_pin_room(&c, 0), ==, 0);
    g_assert_true(femu_cxl_cache_all_pinned(&c, 0));
    g_assert_false(femu_cxl_cache_all_pinned(&c, 1));
    g_assert_null(femu_cxl_cache_insert(&c, 1000 * nsets, NULL, NULL));
    g_assert_nonnull(femu_cxl_cache_insert(&c, 1000 * nsets + 1, NULL, NULL));
    check_links(&c);

    /* Unpinned, the page rejoins the documented queue. */
    femu_cxl_cache_unpin(&c, e);
    g_assert_cmpint(e->queue, ==, policy == FEMU_CXL_S3FIFO && ways > 1 ?
                    FEMU_CXL_MAIN : FEMU_CXL_SMALL);
    g_assert_cmpuint(c.pinned, ==, ways - 1);
    g_assert_false(femu_cxl_cache_all_pinned(&c, 0));
    if (policy == FEMU_CXL_LIFO || ways == 1) {
        g_assert_nonnull(femu_cxl_cache_insert(&c, 2000 * nsets, NULL, NULL));
        g_assert_null(g_hash_table_lookup(c.entries, &(uint64_t){ 0 }));
    }
    check_links(&c);

    /* Clearing keeps pins; destroy frees them (checked under ASan). */
    g_assert_true(femu_cxl_cache_clear(&c, NULL, NULL));
    g_assert_cmpuint(g_hash_table_size(c.entries), ==, c.pinned);
    check_links(&c);
    femu_cxl_cache_unpin_all(&c);
    g_assert_cmpuint(c.pinned, ==, 0);
    check_links(&c);
    femu_cxl_cache_destroy(&c);
}

static bool refuse(void *opaque, FemuCxlEntry *e)
{
    (void)opaque;
    (void)e;
    return false;
}

/* Remove from the ends and the middle of every queue. */
static void remove_policy(FemuCxlPolicy policy, uint32_t ways)
{
    FemuCxlCache c;
    uint32_t i;

    if (ways < 3) {
        return;
    }
    femu_cxl_cache_init(&c, ways, ways, policy);
    for (i = 0; i < ways; i++) {
        FemuCxlEntry *e = femu_cxl_cache_insert(&c, i, NULL, NULL);

        e->freq = 3;
        if (i % 3 == 0) {
            femu_cxl_cache_pin(&c, e);
        }
    }
    /* Rotations move some entries into main before removals begin. */
    femu_cxl_cache_unpin(&c, g_hash_table_lookup(c.entries, &(uint64_t){ 0 }));
    g_assert_nonnull(femu_cxl_cache_insert(&c, ways, NULL, NULL));
    check_links(&c);
    for (i = 0; i < 3; i++) {
        GQueue *queues[] = { &c.sets[0].small, &c.sets[0].main,
                             &c.sets[0].pinned };
        unsigned k;

        for (k = 0; k < G_N_ELEMENTS(queues); k++) {
            GList *l = i == 0 ? queues[k]->head : i == 1 ? queues[k]->tail :
                       g_queue_peek_nth_link(queues[k], queues[k]->length / 2);
            FemuCxlEntry *e;
            uint64_t lpn;
            uint64_t pinned = c.pinned;
            bool was_pinned;

            if (!l) {
                continue;
            }
            e = l->data;
            lpn = e->lpn;
            was_pinned = e->queue == FEMU_CXL_PINNED;
            g_assert_false(femu_cxl_cache_remove(&c, e, refuse, NULL));
            g_assert_true(g_hash_table_lookup(c.entries, &lpn) == e);
            g_assert_true(femu_cxl_cache_remove(&c, e, NULL, NULL));
            g_assert_null(g_hash_table_lookup(c.entries, &lpn));
            g_assert_null(g_hash_table_lookup(c.ghosts, &lpn));
            g_assert_cmpuint(c.pinned, ==, pinned - was_pinned);
            check_links(&c);
        }
    }
    femu_cxl_cache_destroy(&c);
}

/* Long rotation runs must keep every stored link valid. */
static void rotations(void)
{
    static const FemuCxlPolicy policies[] = { FEMU_CXL_CLOCK,
                                              FEMU_CXL_S3FIFO };
    unsigned p;

    for (p = 0; p < G_N_ELEMENTS(policies); p++) {
        FemuCxlCache c;
        uint32_t i;

        femu_cxl_cache_init(&c, 64, 16, policies[p]);
        for (i = 0; i < 1000000; i++) {
            uint64_t lpn = (i * 2654435761u) % 211;
            FemuCxlEntry *e = touch(&c, lpn);

            g_assert_nonnull(e);
            if (i % 997 == 0) {
                if (e->queue == FEMU_CXL_PINNED) {
                    femu_cxl_cache_unpin(&c, e);
                } else if (femu_cxl_cache_pin_room(&c, lpn) > 1) {
                    femu_cxl_cache_pin(&c, e);
                }
            }
            if (i % 100003 == 0) {
                check_links(&c);
            }
        }
        check_links(&c);
        femu_cxl_cache_destroy(&c);
    }
}

static unsigned written;

static bool count_write(void *opaque, FemuCxlEntry *e)
{
    (void)opaque;
    written += e->dirty;
    return true;
}

/* A way change keeps pins when they fit and refuses before touching them. */
static void rebuild(void)
{
    FemuCxlCache c;
    FemuCxlEntry *e;
    uint64_t hits;

    femu_cxl_cache_init(&c, 8, 2, FEMU_CXL_FIFO);
    e = femu_cxl_cache_insert(&c, 0, NULL, NULL);
    e->dirty = true;
    femu_cxl_cache_pin(&c, e);
    e = femu_cxl_cache_insert(&c, 4, NULL, NULL);
    femu_cxl_cache_pin(&c, e);
    femu_cxl_cache_insert(&c, 1, NULL, NULL);
    femu_cxl_cache_find(&c, 1);
    hits = c.hits;
    g_assert_true(femu_cxl_cache_pins_fit(&c, 8, 4));
    g_assert_true(femu_cxl_cache_pins_fit(&c, 8, 8));
    /* Eight sets of one way: pages 0 and 4 share none. */
    g_assert_true(femu_cxl_cache_pins_fit(&c, 8, 1));
    /* Two sets of one way hold both pages in set 0. */
    g_assert_false(femu_cxl_cache_pins_fit(&c, 2, 1));

    written = 0;
    g_assert_true(femu_cxl_cache_clear(&c, count_write, NULL));
    g_assert_true(femu_cxl_cache_clean_pinned(&c, count_write, NULL));
    g_assert_cmpuint(written, ==, 1);
    g_assert_cmpuint(g_hash_table_size(c.entries), ==, 2);
    femu_cxl_cache_rebuild(&c, 8, 8);
    g_assert_cmpuint(c.ways, ==, 8);
    g_assert_cmpuint(c.pinned, ==, 2);
    g_assert_cmpuint(c.generation, ==, 1);
    g_assert_cmpuint(c.hits, ==, hits);
    e = g_hash_table_lookup(c.entries, &(uint64_t){ 0 });
    g_assert_nonnull(e);
    g_assert_false(e->dirty);
    g_assert_cmpint(e->queue, ==, FEMU_CXL_PINNED);
    check_links(&c);
    femu_cxl_cache_destroy(&c);
}

/* The full-scale cache with a tenth of it pinned. */
static void fully_associative_pinned(void)
{
    FemuCxlCache c;
    FemuCxlPolicy policy;
    const unsigned pages = 1258291;
    unsigned i;

    for (policy = FEMU_CXL_FIFO; policy <= FEMU_CXL_S3FIFO; policy++) {
        femu_cxl_cache_init(&c, pages, pages, policy);
        for (i = 0; i < pages / 10; i++) {
            femu_cxl_cache_pin(&c, femu_cxl_cache_insert(&c, i, NULL, NULL));
        }
        for (i = 0; i < 2 * pages; i++) {
            g_assert_nonnull(femu_cxl_cache_insert(&c, pages + i, NULL, NULL));
        }
        g_assert_cmpuint(g_hash_table_size(c.entries), ==, pages);
        for (i = 0; i < pages / 10; i++) {
            g_assert_nonnull(g_hash_table_lookup(c.entries,
                                                 &(uint64_t){ i }));
        }
        check_links(&c);
        femu_cxl_cache_destroy(&c);
    }
}

/* Eviction passes over kept entries and takes the next in policy order. */
static bool keep_lpn(void *opaque, uint64_t lpn)
{
    return lpn == *(uint64_t *)opaque;
}

static bool keep_all(void *opaque, uint64_t lpn)
{
    (void)opaque;
    (void)lpn;
    return true;
}

static void keep_policy(FemuCxlPolicy policy)
{
    FemuCxlCache c;
    uint64_t kept;
    uint64_t lpn;

    /* One set of four ways: lpns 0, 1, 2, 3 fill it in that order. */
    femu_cxl_cache_init(&c, 4, 4, policy);
    for (lpn = 0; lpn < 4; lpn++) {
        g_assert_nonnull(femu_cxl_cache_insert(&c, lpn, NULL, NULL));
    }
    /* The plain policy evicts 0 (FIFO, clock, S3-FIFO) or 3 (LIFO); keep it. */
    kept = policy == FEMU_CXL_LIFO ? 3 : 0;
    g_assert_nonnull(femu_cxl_cache_insert_keep(&c, 4, NULL, keep_lpn,
                                                &kept));
    g_assert_true(g_hash_table_contains(c.entries, &kept));
    g_assert_cmpuint(g_hash_table_size(c.entries), ==, 4);
    /* Nothing to give: the insert fails and the set is unchanged. */
    lpn = 5;
    g_assert_null(femu_cxl_cache_insert_keep(&c, lpn, NULL, keep_all, NULL));
    g_assert_false(g_hash_table_contains(c.entries, &lpn));
    g_assert_cmpuint(g_hash_table_size(c.entries), ==, 4);
    check_links(&c);
    femu_cxl_cache_destroy(&c);
}

/*
 * CLOCK keeps its second chance when it passes over a kept entry: with
 * [A kept, B referenced, C not], it must evict C, not B.
 */
static void keep_clock(void)
{
    FemuCxlCache c;
    uint64_t lpn;
    uint64_t a = 0;
    uint64_t b = 1;
    uint64_t cold = 2;

    femu_cxl_cache_init(&c, 3, 3, FEMU_CXL_CLOCK);
    for (lpn = 0; lpn < 3; lpn++) {
        g_assert_nonnull(femu_cxl_cache_insert(&c, lpn, NULL, NULL));
    }
    ((FemuCxlEntry *)g_hash_table_lookup(c.entries, &a))->freq = 0;
    ((FemuCxlEntry *)g_hash_table_lookup(c.entries, &b))->freq = 1;
    ((FemuCxlEntry *)g_hash_table_lookup(c.entries, &cold))->freq = 0;
    lpn = 3;
    g_assert_nonnull(femu_cxl_cache_insert_keep(&c, lpn, NULL, keep_lpn, &a));
    g_assert_true(g_hash_table_contains(c.entries, &a));
    g_assert_true(g_hash_table_contains(c.entries, &b));
    g_assert_false(g_hash_table_contains(c.entries, &cold));
    check_links(&c);
    femu_cxl_cache_destroy(&c);
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
        for (ways = 1; ways <= 32; ways *= 2) {
            pin_policy(policy, ways);
            remove_policy(policy, ways);
        }
    }
    for (policy = FEMU_CXL_FIFO; policy <= FEMU_CXL_S3FIFO; policy++) {
        keep_policy(policy);
    }
    keep_clock();
    rotations();
    rebuild();
    fully_associative_pinned();
    puts("CXL cache: ordering, large keys, dirty eviction, reset, pinning, "
         "removal, rebuild, keep, all policies PASS");
    return 0;
}
