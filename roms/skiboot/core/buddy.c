// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2016-2017 IBM Corp. */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "buddy.h"

#define BUDDY_DEBUG
#undef  BUDDY_VERBOSE

#ifdef BUDDY_VERBOSE
#define BUDDY_NOISE(fmt...)	printf(fmt)
#else
#define BUDDY_NOISE(fmt...)	do { } while(0)
#endif

static inline unsigned int buddy_map_size(struct buddy *b)
{
	return 1u << (b->max_order + 1);
}

static inline unsigned int buddy_order_start(struct buddy *b,
					     unsigned int order)
{
	unsigned int level = b->max_order - order;

	/* Starting bit of index for order */
	return 1u << level;
}

static inline unsigned int buddy_index_to_node(struct buddy *b,
					       unsigned int index,
					       unsigned int order)
{
	/* Ensure the index is a multiple of the order */
	assert((index & ((1u << order) - 1)) == 0);

	return buddy_order_start(b, order) + (index >> order);
}

static inline unsigned int buddy_node_to_index(struct buddy *b,
					       unsigned int node,
					       unsigned int order)
{
	unsigned int start = buddy_order_start(b, order);

	return (node - start) << order;
}

#ifdef BUDDY_DEBUG
static void buddy_check_alloc(struct buddy *b, unsigned int node)
{
	assert(bitmap_tst_bit(b->map, node));
}

static void buddy_check_alloc_down(struct buddy *b, unsigned int node)
{
	unsigned int i, count = 1;

	while (node < buddy_map_size(b)) {
		for (i = 0; i < count; i++)
			buddy_check_alloc(b, node + i);

		/* Down one level */
		node <<= 1;
		count <<= 1;
	}
}
#else
static inline void buddy_check_alloc(struct buddy *b __unused, unsigned int node __unused) {}
static inline void buddy_check_alloc_down(struct buddy *b __unused, unsigned int node __unused) {}
#endif

int buddy_alloc(struct buddy *b, unsigned int order)
{
	unsigned int o;
	int node, index;

	BUDDY_NOISE("buddy_alloc(%d)\n", order);
	/*
	 * Find the first order up the tree from our requested order that
	 * has at least one free node.
	 */
	for (o = order; o <= b->max_order; o++) {
		if (b->freecounts[o] > 0)
			break;
	}

	/* Nothing found ? fail */
	if (o > b->max_order) {
		BUDDY_NOISE("  no free nodes !\n");
		return -1;
	}

	BUDDY_NOISE("  %d free node(s) at order %d, bits %d(%d)\n",
		    b->freecounts[o], o,
		    buddy_order_start(b, o),
		    1u << (b->max_order - o));

	/* Now find a free node */
	node = bitmap_find_zero_bit(b->map, buddy_order_start(b, o),
				    1u << (b->max_order - o));

	/* There should always be one */
	assert(node >= 0);

	/* Mark it allocated and decrease free count */
	bitmap_set_bit(b->map, node);
	b->freecounts[o]--;

	/* We know that node was free which means all its children must have
	 * been marked "allocated". Double check.
	 */
	buddy_check_alloc_down(b, node);

	/* We have a node, we've marked it allocated, now we need to go down
	 * the tree until we reach "order" which is the order we need. For
	 * each level along the way, we mark the buddy free and leave the
	 * first child allocated.
	 */
	while (o > order) {
		/* Next level down */
		o--;
		node <<= 1;

		BUDDY_NOISE("  order %d, using %d marking %d free\n",
			    o, node, node ^ 1);
		bitmap_clr_bit(b->map, node ^ 1);
		b->freecounts[o]++;
		assert(bitmap_tst_bit(b->map, node));
	}

	index = buddy_node_to_index(b, node, order);

	BUDDY_NOISE("  result is index %d (node %d)\n", index, node);

	/* We have a node, convert it to an element number */
	return index;
}

bool buddy_reserve(struct buddy *b, unsigned int index, unsigned int order)
{
	unsigned int node, freenode, o;

	assert(index < (1u << b->max_order));

	BUDDY_NOISE("buddy_reserve(%d,%d)\n", index, order);

	/* Get bit number for node */
	node = buddy_index_to_node(b, index, order);

	BUDDY_NOISE("  node=%d\n", node);

	/* Find something free */
	for (freenode = node, o = order; freenode > 0; freenode >>= 1, o++)
		if (!bitmap_tst_bit(b->map, freenode))
			break;

	BUDDY_NOISE("  freenode=%d order %d\n", freenode, o);

	/* Nothing free, error out */
	if (!freenode)
		return false;

	/* We sit on a free node, mark it busy */
	bitmap_set_bit(b->map, freenode);
	assert(b->freecounts[o]);
	b->freecounts[o]--;

	/* We know that node was free which means all its children must have
	 * been marked "allocated". Double check.
	 */
	buddy_check_alloc_down(b, freenode);

	/* Reverse-walk the path and break down nodes */
	while (o > order) {
		/* Next level down */
		o--;
		freenode <<= 1;

		/* Find the right one on the path to node */
		if (node & (1u << (o - order)))
		    freenode++;

		BUDDY_NOISE("  order %d, using %d marking %d free\n",
			    o, freenode, freenode ^ 1);
		bitmap_clr_bit(b->map, freenode ^ 1);
		b->freecounts[o]++;
		assert(bitmap_tst_bit(b->map, node));
	}
	assert(node == freenode);

	return true;
}

void buddy_free(struct buddy *b, unsigned int index, unsigned int order)
{
	unsigned int node;

	assert(index < (1u << b->max_order));

	BUDDY_NOISE("buddy_free(%d,%d)\n", index, order);

	/* Get bit number for node */
	node = buddy_index_to_node(b, index, order);

	BUDDY_NOISE("  node=%d\n", node);

	/* We assume that anything freed was fully allocated, ie,
	 * there is no child node of that allocation index/order
	 * that is already free.
	 *
	 * BUDDY_DEBUG will verify it at the cost of performances
	 */
	buddy_check_alloc_down(b, node);

	/* Propagate if buddy is free */
	while (order < b->max_order && !bitmap_tst_bit(b->map, node ^ 1)) {
		BUDDY_NOISE("  order %d node %d buddy %d free, propagating\n",
			    order, node, node ^ 1);

		/* Mark buddy busy (we are already marked busy) */
		bitmap_set_bit(b->map, node ^ 1);

		/* Reduce free count */
		assert(b->freecounts[order] > 0);
		b->freecounts[order]--;

		/* Get parent */
		node >>= 1;
		order++;

		/* It must be busy already ! */
		buddy_check_alloc(b, node);

		BUDDY_NOISE("  testing order %d node %d\n", order, node ^ 1);
	}

	/* No more coalescing, mark it free */
	bitmap_clr_bit(b->map, node);

	/* Increase the freelist count for that level */
	b->freecounts[order]++;

	BUDDY_NOISE("  free count at order %d is %d\n",
		    order, b->freecounts[order]);
}

void buddy_reset(struct buddy *b)
{
	unsigned int bsize = BITMAP_BYTES(1u << (b->max_order + 1));

	BUDDY_NOISE("buddy_reset()\n");
	/* We fill the bitmap with 1's to make it completely "busy" */
	memset(b->map, 0xff, bsize);
	memset(b->freecounts, 0, sizeof(b->freecounts));

	/* We mark the root of the tree free, this is entry 1 as entry 0
	 * is unused.
	 */
	buddy_free(b, 0, b->max_order);
}

struct buddy *buddy_create(unsigned int max_order)
{
	struct buddy *b;
	unsigned int bsize;

	assert(max_order <= BUDDY_MAX_ORDER);

	bsize = BITMAP_BYTES(1u << (max_order + 1));

	b = zalloc(sizeof(struct buddy) + bsize);
	if (!b)
		return NULL;
	b->max_order = max_order;

	BUDDY_NOISE("Map @%p, size: %d bytes\n", b->map, bsize);

	buddy_reset(b);

	return b;
}

void buddy_destroy(struct buddy *b)
{
	free(b);
}

