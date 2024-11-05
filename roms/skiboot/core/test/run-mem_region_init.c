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

#include "../malloc.c"

#include <skiboot.h>
/* We need mem_region to accept __location__ */
#define is_rodata(p) true
#include "../mem_region.c"

/* But we need device tree to make copies of names. */
#undef is_rodata
#define is_rodata(p) false

static inline char *skiboot_strdup(const char *str)
{
	char *ret = __malloc(strlen(str) + 1, "");
	return memcpy(ret, str, strlen(str) + 1);
}
#undef strdup
#define strdup skiboot_strdup

#include "../device.c"

#include <skiboot.h>

#include <assert.h>
#include <stdio.h>

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

/* We actually need a lot of room for the bitmaps! */
#define TEST_HEAP_ORDER 27
#define TEST_HEAP_SIZE (1ULL << TEST_HEAP_ORDER)

static void add_mem_node(uint64_t start, uint64_t len)
{
	struct dt_node *mem;
	u64 reg[2];
	char *name= (char*)malloc(sizeof("memory@") + STR_MAX_CHARS(reg[0]));

	assert(name);

	/* reg contains start and length */
	reg[0] = cpu_to_be64(start);
	reg[1] = cpu_to_be64(len);

	sprintf(name, "memory@%llx", (unsigned long long)start);

	mem = dt_new(dt_root, name);
	assert(mem);
	dt_add_property_string(mem, "device_type", "memory");
	dt_add_property(mem, "reg", reg, sizeof(reg));
	free(name);
}

void add_chip_dev_associativity(struct dt_node *dev __attribute__((unused)))
{
}

int main(void)
{
	uint64_t end;
	int builtins;
	struct mem_region *r;
	char *heap = real_malloc(TEST_HEAP_SIZE);

	/* Use malloc for the heap, so valgrind can find issues. */
	skiboot_heap.start = (unsigned long)heap;
	skiboot_heap.len = TEST_HEAP_SIZE;
	skiboot_os_reserve.len = 16384;

	dt_root = dt_new_root("");
	dt_add_property_cells(dt_root, "#address-cells", 2);
	dt_add_property_cells(dt_root, "#size-cells", 2);

	/* Make sure we overlap the heap, at least. */
	add_mem_node(0, (uint64_t)(heap + 0x100000000ULL));
	add_mem_node((uint64_t)heap+0x100000000ULL , 0x100000000ULL);
	end = (uint64_t)(heap+ 0x100000000ULL + 0x100000000ULL);

	/* Now convert. */
	mem_region_init();
	mem_dump_allocs();
	assert(mem_check(&skiboot_heap));

	builtins = 0;
	list_for_each(&regions, r, list) {
		/* Regions must not overlap. */
		struct mem_region *r2, *pre = NULL, *post = NULL;
		list_for_each(&regions, r2, list) {
			if (r == r2)
				continue;
			assert(!overlaps(r, r2));
		}

		/* But should have exact neighbours. */
		list_for_each(&regions, r2, list) {
			if (r == r2)
				continue;
			if (r2->start == r->start + r->len)
				post = r2;
			if (r2->start + r2->len == r->start)
				pre = r2;
		}
		assert(r->start == 0 || pre);
		assert(r->start + r->len == end || post);

		if (r == &skiboot_code_and_text ||
		    r == &skiboot_heap ||
		    r == &skiboot_after_heap ||
		    r == &skiboot_cpu_stacks ||
		    r == &skiboot_os_reserve)
			builtins++;
		else
			assert(r->type == REGION_MEMORY);
		assert(mem_check(r));
	}
	assert(builtins == 5);

	dt_free(dt_root);

	while ((r = list_pop(&regions, struct mem_region, list)) != NULL) {
		if (r != &skiboot_code_and_text &&
		    r != &skiboot_heap &&
		    r != &skiboot_after_heap &&
		    r != &skiboot_os_reserve &&
		    r != &skiboot_cpu_stacks) {
			free(r);
		}
		assert(mem_check(&skiboot_heap));
	}
	assert(skiboot_heap.free_list_lock.lock_val == 0);
	real_free(heap);
	return 0;
}
