/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FEMU priority queue tests
 *
 * Copyright 2026 Changhyeon Park <changhyeonb533@gmail.com>
 */

#include "qemu/osdep.h"
#include "hw/femu/inc/pqueue.h"

typedef struct TestNode {
    pqueue_pri_t priority;
    size_t position;
} TestNode;

static int compare_priority(pqueue_pri_t next, pqueue_pri_t current)
{
    return next > current;
}

static pqueue_pri_t get_priority(void *data)
{
    return ((TestNode *)data)->priority;
}

static void set_priority(void *data, pqueue_pri_t priority)
{
    ((TestNode *)data)->priority = priority;
}

static size_t get_position(void *data)
{
    return ((TestNode *)data)->position;
}

static void set_position(void *data, size_t position)
{
    ((TestNode *)data)->position = position;
}

static pqueue_t *queue_new(TestNode *nodes, const pqueue_pri_t *priorities,
                           size_t count)
{
    pqueue_t *queue;
    size_t i;

    queue = pqueue_init(count, compare_priority, get_priority, set_priority,
                        get_position, set_position);
    g_assert_nonnull(queue);

    for (i = 0; i < count; i++) {
        nodes[i].priority = priorities[i];
        nodes[i].position = 0;
        g_assert_cmpint(pqueue_insert(queue, &nodes[i]), ==, 0);
    }

    g_assert_true(pqueue_is_valid(queue));
    return queue;
}

static void test_pop_order(void)
{
    const pqueue_pri_t priorities[] = { 40, 10, 50, 20, 30 };
    const pqueue_pri_t expected[] = { 10, 20, 30, 40, 50 };
    TestNode nodes[G_N_ELEMENTS(priorities)];
    pqueue_t *queue;
    TestNode *node;
    size_t i;

    queue = queue_new(nodes, priorities, G_N_ELEMENTS(priorities));

    for (i = 0; i < G_N_ELEMENTS(expected); i++) {
        node = pqueue_pop(queue);
        g_assert_nonnull(node);
        g_assert_cmpuint(node->priority, ==, expected[i]);
        g_assert_true(pqueue_is_valid(queue));
    }

    g_assert_null(pqueue_pop(queue));
    pqueue_free(queue);
}

static void test_change_preupdated_priority(void)
{
    const pqueue_pri_t priorities[] = { 10, 20, 30, 40, 50 };
    TestNode nodes[G_N_ELEMENTS(priorities)];
    pqueue_t *queue;

    queue = queue_new(nodes, priorities, G_N_ELEMENTS(priorities));

    /*
     * FEMU's FTL updates an element before notifying the queue. The repair
     * direction must therefore be chosen from the element's current parent,
     * not by comparing the already-updated priority with new_priority.
     */
    nodes[4].priority = 5;
    pqueue_change_priority(queue, nodes[4].priority, &nodes[4]);

    g_assert_true(pqueue_is_valid(queue));
    g_assert_true(pqueue_peek(queue) == &nodes[4]);

    pqueue_free(queue);
}

static void test_randpop_bubbles_replacement(void)
{
    const pqueue_pri_t priorities[] = { 1, 4, 2, 5, 6, 3 };
    TestNode nodes[G_N_ELEMENTS(priorities)];
    pqueue_t *queue;
    TestNode *node;

    queue = queue_new(nodes, priorities, G_N_ELEMENTS(priorities));
    g_assert_cmpuint(nodes[3].position, ==, 4);

    node = pqueue_randpop(queue, nodes[3].position - 1);

    g_assert_true(node == &nodes[3]);
    g_assert_true(pqueue_is_valid(queue));
    pqueue_free(queue);
}

/*
 * The caller's number picks the entry, so the same numbers pick the same
 * entries: a seeded caller repeats its choices run to run.
 */
static void test_randpop_follows_caller(void)
{
    const pqueue_pri_t priorities[] = { 7, 3, 9, 1, 5, 8, 2 };
    const uint64_t draws[] = { 0x9e3779b97f4a7c15ULL, 5, 12, 0, 3 };
    TestNode a[G_N_ELEMENTS(priorities)];
    TestNode b[G_N_ELEMENTS(priorities)];
    pqueue_t *qa = queue_new(a, priorities, G_N_ELEMENTS(priorities));
    pqueue_t *qb = queue_new(b, priorities, G_N_ELEMENTS(priorities));
    unsigned int i;

    for (i = 0; i < G_N_ELEMENTS(draws); i++) {
        TestNode *na;
        TestNode *nb;
        size_t want = draws[i] % (qa->size - 1) + 1;
        TestNode *at = qa->d[want];

        na = pqueue_randpop(qa, draws[i]);
        nb = pqueue_randpop(qb, draws[i]);
        g_assert_true(na == at);
        g_assert_cmpuint(na - a, ==, nb - b);
        g_assert_true(pqueue_is_valid(qa));
    }
    pqueue_free(qa);
    pqueue_free(qb);
}

/* every entry's stored index names its slot, and the heap order holds */
static void assert_indexed(pqueue_t *q)
{
    size_t i;

    g_assert_true(pqueue_is_valid(q));
    for (i = 1; i < q->size; i++) {
        g_assert_cmpuint(((TestNode *)q->d[i])->position, ==, i);
    }
}

/* @qa over @a and @qb over @b hold the same entries in the same slots */
static void assert_same_layout(pqueue_t *qa, TestNode *a, pqueue_t *qb,
                               TestNode *b)
{
    size_t i;

    g_assert_cmpuint(qa->size, ==, qb->size);
    for (i = 1; i < qa->size; i++) {
        g_assert_cmpint((TestNode *)qa->d[i] - a, ==,
                        (TestNode *)qb->d[i] - b);
    }
}

/*
 * The FTL tests an entry's index to know whether it is still queued, so
 * every way out of the queue leaves the index at 0. That includes the entry
 * in the last slot, whose index the repair step writes back.
 */
static void test_detach_clears_index(void)
{
    const pqueue_pri_t priorities[] = { 4, 1, 7, 3, 3, 9, 2, 6, 5, 8 };
    TestNode nodes[G_N_ELEMENTS(priorities)];
    pqueue_t *queue;
    TestNode *node;

    queue = queue_new(nodes, priorities, G_N_ELEMENTS(priorities));

    node = pqueue_pop(queue);
    g_assert_cmpuint(node->position, ==, 0);
    assert_indexed(queue);

    node = queue->d[3];
    pqueue_remove(queue, node);
    g_assert_cmpuint(node->position, ==, 0);
    assert_indexed(queue);

    node = queue->d[queue->size - 1];
    pqueue_remove(queue, node);
    g_assert_cmpuint(node->position, ==, 0);
    assert_indexed(queue);

    node = pqueue_randpop(queue, 1);
    g_assert_cmpuint(node->position, ==, 0);
    assert_indexed(queue);

    /* a draw of one less than the size picks the last slot */
    node = pqueue_randpop(queue, pqueue_size(queue) - 1);
    g_assert_cmpuint(node->position, ==, 0);
    assert_indexed(queue);

    while (pqueue_size(queue) > 1) {
        node = pqueue_pop(queue);
        g_assert_cmpuint(node->position, ==, 0);
        assert_indexed(queue);
    }
    /* the only entry is the top and the last slot at once */
    node = pqueue_pop(queue);
    g_assert_cmpuint(node->position, ==, 0);
    g_assert_cmpuint(pqueue_size(queue), ==, 0);
    pqueue_free(queue);
}

/*
 * Popping the top leaves the same slots as removing the entry peek returns.
 * The priorities repeat, so a different repair would show as a different
 * order of equal entries.
 */
static void test_pop_is_remove_top(void)
{
    const pqueue_pri_t priorities[] = { 5, 2, 2, 8, 5, 1, 2, 5, 8, 1, 3, 3 };
    TestNode a[G_N_ELEMENTS(priorities)];
    TestNode b[G_N_ELEMENTS(priorities)];
    pqueue_t *qa = queue_new(a, priorities, G_N_ELEMENTS(priorities));
    pqueue_t *qb = queue_new(b, priorities, G_N_ELEMENTS(priorities));

    while (pqueue_size(qa)) {
        TestNode *na = pqueue_pop(qa);
        TestNode *nb = pqueue_peek(qb);

        pqueue_remove(qb, nb);
        g_assert_cmpint(na - a, ==, nb - b);
        assert_same_layout(qa, a, qb, b);
        assert_indexed(qa);
        assert_indexed(qb);
    }
    pqueue_free(qa);
    pqueue_free(qb);
}

/* random pops on one copy against removals at the drawn index on another */
static void randpop_vs_remove(const pqueue_pri_t *priorities, size_t n,
                              const uint64_t *draws)
{
    g_autofree TestNode *a = g_new0(TestNode, n);
    g_autofree TestNode *b = g_new0(TestNode, n);
    pqueue_t *qa = queue_new(a, priorities, n);
    pqueue_t *qb = queue_new(b, priorities, n);
    size_t i;

    for (i = 0; i < n; i++) {
        TestNode *nb = qb->d[draws[i] % pqueue_size(qb) + 1];
        TestNode *na = pqueue_randpop(qa, draws[i]);

        pqueue_remove(qb, nb);
        g_assert_cmpint(na - a, ==, nb - b);
        assert_same_layout(qa, a, qb, b);
        assert_indexed(qa);
        assert_indexed(qb);
    }
    g_assert_cmpuint(pqueue_size(qa), ==, 0);
    pqueue_free(qa);
    pqueue_free(qb);
}

/*
 * A random pop leaves the same slots as removing the entry at the index the
 * same number picks: with the draws of the seeded caller test above, with a
 * replacement that must move up, and over seeded random heaps.
 */
static void test_randpop_is_remove_at(void)
{
    const pqueue_pri_t prio_caller[] = { 5, 2, 2, 8, 5, 1, 2, 5, 8, 1, 3, 3 };
    const uint64_t draws_caller[] = { 0x9e3779b97f4a7c15ULL, 5, 12, 0, 3, 7,
                                      1, 0xbf58476d1ce4e5b9ULL, 2, 6, 4, 9 };
    /* slot 4 holds 5; the last entry, 3, must rise above its new parent 4 */
    const pqueue_pri_t prio_up[] = { 1, 4, 2, 5, 6, 3 };
    const uint64_t draws_up[] = { 3, 0, 0, 0, 0, 0 };
    uint64_t rng = 1;
    int round;

    randpop_vs_remove(prio_caller, G_N_ELEMENTS(prio_caller), draws_caller);
    randpop_vs_remove(prio_up, G_N_ELEMENTS(prio_up), draws_up);
    for (round = 0; round < 200; round++) {
        pqueue_pri_t prio[16];
        uint64_t draws[16];
        size_t n;
        size_t i;

        rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
        n = (rng >> 33) % 16 + 1;
        for (i = 0; i < n; i++) {
            rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
            prio[i] = (rng >> 33) % 6;
            rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
            draws[i] = rng;
        }
        randpop_vs_remove(prio, n, draws);
    }
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/femu/pqueue/pop-order", test_pop_order);
    g_test_add_func("/femu/pqueue/change-preupdated-priority",
                    test_change_preupdated_priority);
    g_test_add_func("/femu/pqueue/randpop-bubbles-replacement",
                    test_randpop_bubbles_replacement);
    g_test_add_func("/femu/pqueue/randpop-follows-caller",
                    test_randpop_follows_caller);
    g_test_add_func("/femu/pqueue/detach-clears-index",
                    test_detach_clears_index);
    g_test_add_func("/femu/pqueue/pop-is-remove-top", test_pop_is_remove_top);
    g_test_add_func("/femu/pqueue/randpop-is-remove-at",
                    test_randpop_is_remove_at);

    return g_test_run();
}
