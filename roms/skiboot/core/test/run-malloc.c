// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2018 IBM Corp.
 */

#include <config.h>

#define BITS_PER_LONG (sizeof(long) * 8)

#include "dummy-cpu.h"

#include <stdlib.h>

/* Use these before we undefine them below. */
static inline void *real_malloc(size_t size)
{
	return malloc(size);
}

static inline void real_free(void *p)
{
	return free(p);
}

#undef malloc
#undef free
#undef realloc

#include <skiboot.h>

#define is_rodata(p) true

#include "../mem_region.c"
#include "../malloc.c"
#include "../device.c"

#include "mem_region-malloc.h"

#define TEST_HEAP_ORDER 16
#define TEST_HEAP_SIZE (1ULL << TEST_HEAP_ORDER)

struct dt_node *dt_root;
enum proc_chip_quirks proc_chip_quirks;

void lock_caller(struct lock *l, const char *caller)
{
	(void)caller;
	assert(!l->lock_val);
	l->lock_val = 1;
}

void unlock(struct lock *l)
{
	assert(l->lock_val);
	l->lock_val = 0;
}

bool lock_held_by_me(struct lock *l)
{
	return l->lock_val;
}

static bool heap_empty(void)
{
	const struct alloc_hdr *h = region_start(&skiboot_heap);
	return h->num_longs == skiboot_heap.len / sizeof(long);
}

int main(void)
{
	char *test_heap = real_malloc(TEST_HEAP_SIZE);
	char *p, *p2, *p3, *p4;
	char *pr;
	size_t i;

	/* Use malloc for the heap, so valgrind can find issues. */
	skiboot_heap.start = (unsigned long)test_heap;
	skiboot_heap.len = TEST_HEAP_SIZE;

	/* Allocations of various sizes. */
	for (i = 0; i < TEST_HEAP_ORDER; i++) {
		p = malloc(1ULL << i);
		assert(p);
		assert(p > (char *)test_heap);
		assert(p + (1ULL << i) <= (char *)test_heap + TEST_HEAP_SIZE);
		assert(!skiboot_heap.free_list_lock.lock_val);
		free(p);
		assert(!skiboot_heap.free_list_lock.lock_val);
		assert(heap_empty());
	}

	/* Realloc as malloc. */
	skiboot_heap.free_list_lock.lock_val = 0;
	p = realloc(NULL, 100);
	assert(p);
	assert(!skiboot_heap.free_list_lock.lock_val);

	/* Realloc as free. */
	p = realloc(p, 0);
	assert(!p);
	assert(!skiboot_heap.free_list_lock.lock_val);
	assert(heap_empty());

	/* Realloc longer. */
	p = realloc(NULL, 100);
	assert(p);
	assert(!skiboot_heap.free_list_lock.lock_val);
	p2 = realloc(p, 200);
	assert(p2 == p);
	assert(!skiboot_heap.free_list_lock.lock_val);
	free(p2);
	assert(!skiboot_heap.free_list_lock.lock_val);
	assert(heap_empty());

	/* Realloc shorter. */
	skiboot_heap.free_list_lock.lock_val = 0;
	p = realloc(NULL, 100);
	assert(!skiboot_heap.free_list_lock.lock_val);
	assert(p);
	p2 = realloc(p, 1);
	assert(!skiboot_heap.free_list_lock.lock_val);
	assert(p2 == p);
	free(p2);
	assert(!skiboot_heap.free_list_lock.lock_val);
	assert(heap_empty());

	/* zalloc failure */
	p2 = zalloc(TEST_HEAP_SIZE * 2);
	assert(p2 == NULL);

	/* Realloc with move. */
	p2 = malloc(TEST_HEAP_SIZE - 64 - sizeof(struct alloc_hdr)*2);
	memset(p2, 'a', TEST_HEAP_SIZE - 64 - sizeof(struct alloc_hdr)*2);
	assert(p2);
	p = malloc(64);
	memset(p, 'b', 64);
	p[63] = 'c';
	assert(p);
	free(p2);

	p2 = realloc(p, 128);
	assert(p2 != p);
	assert(p2[63] == 'c');
	free(p2);
	assert(heap_empty());
	assert(!skiboot_heap.free_list_lock.lock_val);

	/* Realloc with failure to allocate new size */
	p2 = malloc(TEST_HEAP_SIZE - sizeof(struct alloc_hdr)*2);
	assert(p2);
	memset(p2, 'a', TEST_HEAP_SIZE - sizeof(struct alloc_hdr)*2);
	p = p2;
	p2 = realloc(p, TEST_HEAP_SIZE*2);
	assert(p2==NULL);
	memset(p, 'b', TEST_HEAP_SIZE - sizeof(struct alloc_hdr)*2);
	free(p);

	/* Reproduce bug BZ109128/SW257364 */
	p = malloc(100);
	p2 = malloc(100);
	p3 = malloc(100);
	p4 = malloc(100);
	free(p2);
	pr = realloc(p,216);
	assert(pr);
	free(p3);
	free(pr);
	free(p4);
	assert(heap_empty());
	assert(!skiboot_heap.free_list_lock.lock_val);

	real_free(test_heap);
	return 0;
}
