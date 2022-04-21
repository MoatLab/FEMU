// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2019 IBM Corp.
 */

#include <config.h>
#include <stdbool.h>
#include <stdint.h>

/* The lock backtrace structures consume too much room on the skiboot heap */
#undef DEBUG_LOCKS_BACKTRACE

#define BITS_PER_LONG (sizeof(long) * 8)

#include "dummy-cpu.h"

#include <stdlib.h>
#include <string.h>

/* Use these before we override definitions below. */
static void *real_malloc(size_t size)
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

#include <assert.h>
#include <stdio.h>

struct dt_node *dt_root;
enum proc_chip_quirks proc_chip_quirks;

void lock_caller(struct lock *l, const char *caller)
{
	(void)caller;
	assert(!l->lock_val);
	l->lock_val++;
}

void unlock(struct lock *l)
{
	assert(l->lock_val);
	l->lock_val--;
}

bool lock_held_by_me(struct lock *l)
{
	return l->lock_val;
}

#define TEST_HEAP_ORDER 16
#define TEST_HEAP_SIZE (1ULL << TEST_HEAP_ORDER)

static bool heap_empty(void)
{
	const struct alloc_hdr *h = region_start(&skiboot_heap);
	return h->num_longs == skiboot_heap.len / sizeof(long);
}

int main(void)
{
	char *test_heap;
	void *p, *ptrs[100];
	size_t i;
	struct mem_region *r;

	/* Use malloc for the heap, so valgrind can find issues. */
	test_heap = real_malloc(TEST_HEAP_SIZE);
	skiboot_heap.start = (unsigned long)test_heap;
	skiboot_heap.len = TEST_HEAP_SIZE;

	lock(&skiboot_heap.free_list_lock);

	/* Allocations of various sizes. */
	for (i = 0; i < TEST_HEAP_ORDER; i++) {
		p = mem_alloc(&skiboot_heap, 1ULL << i, 1, "here");
		assert(p);
		assert(mem_check(&skiboot_heap));
		assert(!strcmp(((struct alloc_hdr *)p)[-1].location, "here"));
		assert(p > (void *)test_heap);
		assert(p + (1ULL << i) <= (void *)test_heap + TEST_HEAP_SIZE);
		assert(mem_allocated_size(p) >= 1ULL << i);
		mem_free(&skiboot_heap, p, "freed");
		assert(heap_empty());
		assert(mem_check(&skiboot_heap));
		assert(!strcmp(((struct alloc_hdr *)p)[-1].location, "freed"));
	}
	p = mem_alloc(&skiboot_heap, 1ULL << i, 1, "here");
	assert(!p);
	mem_free(&skiboot_heap, p, "freed");
	assert(heap_empty());
	assert(mem_check(&skiboot_heap));

	/* Allocations of various alignments: use small alloc first. */
	ptrs[0] = mem_alloc(&skiboot_heap, 1, 1, "small");
	for (i = 0; ; i++) {
		p = mem_alloc(&skiboot_heap, 1, 1ULL << i, "here");
		assert(mem_check(&skiboot_heap));
		/* We will eventually fail... */
		if (!p) {
			assert(i >= TEST_HEAP_ORDER);
			break;
		}
		assert(p);
		assert((long)p % (1ULL << i) == 0);
		assert(p > (void *)test_heap);
		assert(p + 1 <= (void *)test_heap + TEST_HEAP_SIZE);
		mem_free(&skiboot_heap, p, "freed");
		assert(mem_check(&skiboot_heap));
	}
	mem_free(&skiboot_heap, ptrs[0], "small freed");
	assert(heap_empty());
	assert(mem_check(&skiboot_heap));

	/* Many little allocations, freed in reverse order. */
	for (i = 0; i < 100; i++) {
		ptrs[i] = mem_alloc(&skiboot_heap, sizeof(long), 1, "here");
		assert(ptrs[i]);
		assert(ptrs[i] > (void *)test_heap);
		assert(ptrs[i] + sizeof(long)
		       <= (void *)test_heap + TEST_HEAP_SIZE);
		assert(mem_check(&skiboot_heap));
	}
	mem_dump_free();
	for (i = 0; i < 100; i++)
		mem_free(&skiboot_heap, ptrs[100 - 1 - i], "freed");

	assert(heap_empty());
	assert(mem_check(&skiboot_heap));

	/* Check the prev_free gets updated properly. */
	ptrs[0] = mem_alloc(&skiboot_heap, sizeof(long), 1, "ptrs[0]");
	ptrs[1] = mem_alloc(&skiboot_heap, sizeof(long), 1, "ptrs[1]");
	assert(ptrs[1] > ptrs[0]);
	mem_free(&skiboot_heap, ptrs[0], "ptrs[0] free");
	assert(mem_check(&skiboot_heap));
	ptrs[0] = mem_alloc(&skiboot_heap, sizeof(long), 1, "ptrs[0] again");
	assert(mem_check(&skiboot_heap));
	mem_free(&skiboot_heap, ptrs[1], "ptrs[1] free");
	mem_free(&skiboot_heap, ptrs[0], "ptrs[0] free");
	assert(mem_check(&skiboot_heap));
	assert(heap_empty());

#if 0
	printf("Heap map:\n");
	for (i = 0; i < TEST_HEAP_SIZE / sizeof(long); i++) {
		printf("%u", test_bit(skiboot_heap.bitmap, i));
		if (i % 64 == 63)
			printf("\n");
		else if (i % 8 == 7)
			printf(" ");
	}
#endif

	/* Simple enlargement, then free */
	p = mem_alloc(&skiboot_heap, 1, 1, "one byte");
	assert(p);
	assert(mem_resize(&skiboot_heap, p, 100, "hundred bytes"));
	assert(mem_allocated_size(p) >= 100);
	assert(mem_check(&skiboot_heap));
	assert(!strcmp(((struct alloc_hdr *)p)[-1].location, "hundred bytes"));
	mem_free(&skiboot_heap, p, "freed");

	/* Simple shrink, then free */
	p = mem_alloc(&skiboot_heap, 100, 1, "100 bytes");
	assert(p);
	assert(mem_resize(&skiboot_heap, p, 1, "1 byte"));
	assert(mem_allocated_size(p) < 100);
	assert(mem_check(&skiboot_heap));
	assert(!strcmp(((struct alloc_hdr *)p)[-1].location, "1 byte"));
	mem_free(&skiboot_heap, p, "freed");

	/* Lots of resizing (enlarge). */
	p = mem_alloc(&skiboot_heap, 1, 1, "one byte");
	assert(p);
	for (i = 1; i <= TEST_HEAP_SIZE - sizeof(struct alloc_hdr); i++) {
		assert(mem_resize(&skiboot_heap, p, i, "enlarge"));
		assert(mem_allocated_size(p) >= i);
		assert(mem_check(&skiboot_heap));
	}

	/* Can't make it larger though. */
	assert(!mem_resize(&skiboot_heap, p, i, "enlarge"));

	for (i = TEST_HEAP_SIZE - sizeof(struct alloc_hdr); i > 0; i--) {
		assert(mem_resize(&skiboot_heap, p, i, "shrink"));
		assert(mem_check(&skiboot_heap));
	}

	mem_free(&skiboot_heap, p, "freed");
	assert(mem_check(&skiboot_heap));

	unlock(&skiboot_heap.free_list_lock);

	/* lock the regions list */
	lock(&mem_region_lock);
	/* Test splitting of a region. */
	r = new_region("base", (unsigned long)test_heap,
		       TEST_HEAP_SIZE, NULL, REGION_SKIBOOT_HEAP);
	assert(add_region(r));
	r = new_region("splitter", (unsigned long)test_heap + TEST_HEAP_SIZE/4,
		       TEST_HEAP_SIZE/2, NULL, REGION_RESERVED);
	assert(add_region(r));
	/* Now we should have *three* regions. */
	i = 0;
	list_for_each(&regions, r, list) {
		if (region_start(r) == test_heap) {
			assert(r->len == TEST_HEAP_SIZE/4);
			assert(strcmp(r->name, "base") == 0);
			assert(r->type == REGION_SKIBOOT_HEAP);
		} else if (region_start(r) == test_heap + TEST_HEAP_SIZE / 4) {
			assert(r->len == TEST_HEAP_SIZE/2);
			assert(strcmp(r->name, "splitter") == 0);
			assert(r->type == REGION_RESERVED);
			assert(!r->free_list.n.next);
		} else if (region_start(r) == test_heap + TEST_HEAP_SIZE/4*3) {
			assert(r->len == TEST_HEAP_SIZE/4);
			assert(strcmp(r->name, "base") == 0);
			assert(r->type == REGION_SKIBOOT_HEAP);
		} else
			abort();
		assert(mem_check(r));
		i++;
	}
	mem_dump_free();
	assert(i == 3);
	while ((r = list_pop(&regions, struct mem_region, list)) != NULL) {
		lock(&skiboot_heap.free_list_lock);
		mem_free(&skiboot_heap, r, __location__);
		unlock(&skiboot_heap.free_list_lock);
	}
	unlock(&mem_region_lock);
	assert(skiboot_heap.free_list_lock.lock_val == 0);
	real_free(test_heap);
	return 0;
}
