// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2015-2018 IBM Corp.
 */

#include <config.h>

#define BITS_PER_LONG (sizeof(long) * 8)

#include "dummy-cpu.h"

#include <stdlib.h>
#include <string.h>

/* Use these before we override definitions below. */
static void *real_malloc(size_t size)
{
	return malloc(size);
}

static void real_free(void *p)
{
	return free(p);
}

#undef malloc
#undef free

#include <skiboot.h>

#define is_rodata(p) true

#include "../mem_region.c"
#include "../malloc.c"
#include "../device.c"

#include <assert.h>
#include <stdio.h>

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

int main(void)
{
	struct mem_region *r;
	char *test_heap;

	/* Use malloc for the heap, so valgrind can find issues. */
	test_heap = real_malloc(TEST_HEAP_SIZE);
	skiboot_heap.start = (unsigned long)test_heap;
	skiboot_heap.len = TEST_HEAP_SIZE;

	lock(&mem_region_lock);

	/* empty regions */
	r = mem_region_next(NULL);
	assert(!r);

	r = new_region("test.1", 0x1000, 0x1000, NULL, REGION_RESERVED);
	assert(add_region(r));
	r = new_region("test.2", 0x2000, 0x1000, NULL, REGION_RESERVED);
	assert(add_region(r));
	mem_regions_finalised = true;

	r = mem_region_next(NULL);
	assert(r);
	assert(r->start == 0x1000);
	assert(r->len == 0x1000);
	assert(r->type == REGION_RESERVED);

	r = mem_region_next(r);
	assert(r);
	assert(r->start == 0x2000);
	assert(r->len == 0x1000);
	assert(r->type == REGION_RESERVED);

	r = mem_region_next(r);
	assert(!r);

	unlock(&mem_region_lock);
	real_free(test_heap);

	return 0;
}
