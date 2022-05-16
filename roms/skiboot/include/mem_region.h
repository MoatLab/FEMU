// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#ifndef __MEMORY_REGION
#define __MEMORY_REGION
#include <ccan/list/list.h>
#include <stdint.h>

#include <lock.h>

enum mem_region_type {
	/* ranges allocatable by mem_alloc: this will be most of memory */
	REGION_SKIBOOT_HEAP,

	/* ranges allocatable by mem_alloc but shrunk (e.g. whole memory) */
	REGION_MEMORY,

	/* ranges used explicitly for skiboot, but not allocatable. eg .text */
	REGION_SKIBOOT_FIRMWARE,

	/* ranges reserved before skiboot init, eg HBRT memory */
	REGION_FW_RESERVED,

	/* ranges reserved, eg HW framebuffer */
	REGION_RESERVED,

	/* ranges available for the OS, created by mem_region_release_unused */
	REGION_OS,
};

/* An area of physical memory. */
struct mem_region {
	struct list_node list;
	const char *name;
	uint64_t start, len;
	struct dt_node *node;
	enum mem_region_type type;
	struct list_head free_list;
	struct lock free_list_lock;
};

extern struct lock mem_region_lock;
extern unsigned long top_of_ram;

void *mem_alloc(struct mem_region *region, size_t size, size_t align,
		const char *location);
void mem_free(struct mem_region *region, void *mem,
	      const char *location);
bool mem_resize(struct mem_region *region, void *mem, size_t len,
		const char *location);
size_t mem_allocated_size(const void *ptr);
bool mem_check(const struct mem_region *region);
bool mem_check_all(void);
void mem_region_release_unused(void);
void start_mem_region_clear_unused(void);
void wait_mem_region_clear_unused(void);
int64_t mem_dump_free(void);
void mem_dump_allocs(void);

/* Specifically for working on the heap. */
extern struct mem_region skiboot_heap;

void mem_region_init(void);
void mem_region_add_dt_reserved(void);

/* Mark memory as reserved */
void mem_reserve_fw(const char *name, uint64_t start, uint64_t len);
void mem_reserve_hwbuf(const char *name, uint64_t start, uint64_t len);

struct mem_region *find_mem_region(const char *name);

bool mem_range_is_reserved(uint64_t start, uint64_t size);

/* Read-only memory checksum */
bool verify_romem(void);

#endif /* __MEMORY_REGION */
