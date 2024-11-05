// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2018 IBM Corp.
 */

#include <config.h>

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

static struct {
	const char	*name;
	uint64_t	addr;
	bool		found;
} test_regions[] = {
	{ "test.1", 0x1000, false },
	{ "test.2", 0x2000, false },
	{ "test.3", 0x4000, false },
};

static void check_property_reservations(void)
{
	const struct dt_property *names, *ranges;
	unsigned int i, l;
	const char *name;
	uint64_t *rangep;
	const char *at;

	/* check dt properties */
	names = dt_find_property(dt_root, "reserved-names");
	ranges = dt_find_property(dt_root, "reserved-ranges");

	assert(names && ranges);

	/* walk through names & ranges properies, ensuring that the test
	 * regions are all present */
	for (name = names->prop, rangep = (uint64_t *)ranges->prop;
			name < names->prop + names->len;
			name += l, rangep += 2) {
		uint64_t addr;

		addr = dt_get_number(rangep, 2);
		l = strlen(name) + 1;

		for (i = 0; i < ARRAY_SIZE(test_regions); i++) {
			at = strchr(name, '@');
			if (strncmp(test_regions[i].name, name,
				    at ? at-name: strlen(name)))
				continue;
			assert(test_regions[i].addr == addr);
			assert(!test_regions[i].found);
			test_regions[i].found = true;
		}
	}

	for (i = 0; i < ARRAY_SIZE(test_regions); i++) {
		assert(test_regions[i].found);
		test_regions[i].found = false;
	}
}

static void check_node_reservations(void)
{
	struct dt_node *parent, *node;
	unsigned int i;

	parent = dt_find_by_name(dt_root, "reserved-memory");
	assert(parent);

	assert(dt_prop_get_cell(parent, "#address-cells", 0) == 2);
	assert(dt_prop_get_cell(parent, "#size-cells", 0) == 2);
	dt_require_property(parent, "ranges", 0);

	dt_for_each_child(parent, node) {
		uint64_t addr, size;

		addr = dt_get_address(node, 0, &size);

		for (i = 0; i < ARRAY_SIZE(test_regions); i++) {
			if (strncmp(test_regions[i].name, node->name,
						strlen(test_regions[i].name)))
				continue;

			assert(!test_regions[i].found);
			assert(test_regions[i].addr == addr);
			assert(size == 0x1000);
			test_regions[i].found = true;
		}
	}

	for (i = 0; i < ARRAY_SIZE(test_regions); i++) {
		assert(test_regions[i].found);
		test_regions[i].found = false;
	}
}

int main(void)
{
	struct mem_region *r;
	unsigned int i;
	void *buf;

	/* Use malloc for the heap, so valgrind can find issues. */
	skiboot_heap.start = (long)real_malloc(TEST_HEAP_SIZE);
	skiboot_heap.len = TEST_HEAP_SIZE;
	skiboot_os_reserve.len = skiboot_heap.start;

	dt_root = dt_new_root("");
	dt_add_property_cells(dt_root, "#address-cells", 2);
	dt_add_property_cells(dt_root, "#size-cells", 2);

	buf = real_malloc(1024*1024);
	add_mem_node((unsigned long)buf, 1024*1024);

	/* add pre-init reservations */
	for (i = 0; i < ARRAY_SIZE(test_regions); i++)
		mem_reserve_fw(test_regions[i].name,
				test_regions[i].addr, 0x1000);

	/* Now convert. */
	mem_region_init();

	/* add a post-init reservation */
	mem_reserve_fw("test.4", 0x5000, 0x1000);

	/* release unused */
	mem_region_release_unused();

	/* and create reservations */
	mem_region_add_dt_reserved();

	/* ensure we can't create further reservations */
	r = new_region("test.5", 0x5000, 0x1000, NULL, REGION_RESERVED);
	assert(!add_region(r));

	/* check old property-style reservations */
	check_property_reservations();

	/* and new node-style reservations */
	check_node_reservations();

	dt_free(dt_root);
	real_free(buf);
	real_free((void *)(long)skiboot_heap.start);
	return 0;
}
