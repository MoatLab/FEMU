// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2015-2019 IBM Corp.
 */

#include <config.h>

/* The lock backtrace structures consume too much room on the skiboot heap */
#undef DEBUG_LOCKS_BACKTRACE

#define BITS_PER_LONG (sizeof(long) * 8)

#include "dummy-cpu.h"

#include <stdlib.h>

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
#undef realloc

#include <skiboot.h>
#include <mem_region-malloc.h>

/* We need mem_region to accept __location__ */
#define is_rodata(p) true
#include "../mem_region.c"
#include "../malloc.c"

/* But we need device tree to make copies of names. */
#undef is_rodata
#define is_rodata(p) false
#include "../../libc/string/strdup.c"

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

static void add_mem_node(uint64_t start, uint64_t len)
{
	struct dt_node *mem;
	u64 reg[2];
	char *name;

	name = (char*)malloc(sizeof("memory@") + STR_MAX_CHARS(reg[0]));
	assert(name);

	/* reg contains start and length */
	reg[0] = cpu_to_be64(start);
	reg[1] = cpu_to_be64(len);

	sprintf(name, "memory@%llx", (long long)start);

	mem = dt_new(dt_root, name);
	dt_add_property_string(mem, "device_type", "memory");
	dt_add_property(mem, "reg", reg, sizeof(reg));
	free(name);
}

void add_chip_dev_associativity(struct dt_node *dev __attribute__((unused)))
{
}

struct test_region {
	uint64_t	start;
	uint64_t	end;
};

static struct test {
	struct test_region	regions[3];
	bool			reserved;
} tests[] = {
	/* empty region set */
	{ { { 0 } }, false },

	/* single exact match */
	{ { { 0x1000, 0x2000 }, }, true },

	/* overlap downwards */
	{ { { 0x0fff, 0x2000 }, }, true },

	/* overlap upwards */
	{ { { 0x1000, 0x2001 }, }, true },

	/* missing first byte */
	{ { { 0x1001, 0x2000 }, }, false },

	/* missing last byte */
	{ { { 0x1000, 0x1fff }, }, false },

	/* two regions, full coverage, split before start of range */
	{ { { 0x0500, 0x1000 }, { 0x1000, 0x2500 } }, true },

	/* two regions, full coverage, split after start of range */
	{ { { 0x0500, 0x1001 }, { 0x1001, 0x2500 } }, true },

	/* two regions, full coverage, split at middle of range */
	{ { { 0x0500, 0x1500 }, { 0x1500, 0x2500 } }, true },

	/* two regions, full coverage, split before end of range */
	{ { { 0x0500, 0x1fff }, { 0x1fff, 0x2500 } }, true },

	/* two regions, full coverage, split after end of range */
	{ { { 0x0500, 0x2000 }, { 0x2000, 0x2500 } }, true },

	/* two regions, missing byte in middle of range */
	{ { { 0x0500, 0x14ff }, { 0x1500, 0x2500 } }, false },

	/* two regions, missing byte after start of range */
	{ { { 0x0500, 0x1000 }, { 0x1001, 0x2500 } }, false },

	/* two regions, missing byte before end of range */
	{ { { 0x0500, 0x1fff }, { 0x2000, 0x2500 } }, false },
};

static void run_test(struct test *test)
{
	struct test_region *r;
	bool reserved;

	list_head_init(&regions);

	mem_region_init();

	/* create our reservations */
	for (r = test->regions; r->start; r++)
		mem_reserve_fw("r", r->start, r->end - r->start);

	reserved = mem_range_is_reserved(0x1000, 0x1000);

	if (reserved != test->reserved)	{
		struct mem_region *r;
		fprintf(stderr, "test failed; got %s, expected %s\n",
				reserved ? "reserved" : "unreserved",
				test->reserved ? "reserved" : "unreserved");

		fprintf(stderr, "reserved regions:\n");

		list_for_each(&regions, r, list) {
			fprintf(stderr, "\t: %08"PRIx64"[%08"PRIx64"] %s\n",
					r->start, r->len, r->name);
		}
		exit(EXIT_FAILURE);
	}
}


int main(void)
{
	unsigned int i;
	void *buf;

	/* Use malloc for the heap, so valgrind can find issues. */
	skiboot_heap.start = (long)real_malloc(TEST_HEAP_SIZE);
	skiboot_heap.len = TEST_HEAP_SIZE;

	/* shift the OS reserve area out of the way of our playground */
	skiboot_os_reserve.start = 0x100000;
	skiboot_os_reserve.len = 0x1000;

	dt_root = dt_new_root("");
	dt_add_property_cells(dt_root, "#address-cells", 2);
	dt_add_property_cells(dt_root, "#size-cells", 2);

	buf = real_malloc(1024*1024);
	add_mem_node((unsigned long)buf, 1024*1024);

	for (i = 0; i < ARRAY_SIZE(tests); i++)
		run_test(&tests[i]);

	dt_free(dt_root);
	real_free(buf);
	real_free((void *)(long)skiboot_heap.start);
	return 0;
}
