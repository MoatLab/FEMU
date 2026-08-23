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
    unsigned int seed;

    queue = queue_new(nodes, priorities, G_N_ELEMENTS(priorities));
    g_assert_cmpuint(nodes[3].position, ==, 4);

    /* Pick position 4 without relying on a platform-specific rand() stream. */
    for (seed = 0; seed < 10000; seed++) {
        srand(seed);
        if (rand() % G_N_ELEMENTS(priorities) + 1 == nodes[3].position) {
            break;
        }
    }
    g_assert_cmpuint(seed, <, 10000);

    srand(seed);
    node = pqueue_randpop(queue);

    g_assert_true(node == &nodes[3]);
    g_assert_true(pqueue_is_valid(queue));
    pqueue_free(queue);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/femu/pqueue/pop-order", test_pop_order);
    g_test_add_func("/femu/pqueue/change-preupdated-priority",
                    test_change_preupdated_priority);
    g_test_add_func("/femu/pqueue/randpop-bubbles-replacement",
                    test_randpop_bubbles_replacement);

    return g_test_run();
}
