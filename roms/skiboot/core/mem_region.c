// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Simple memory allocator
 *
 * Copyright 2013-2018 IBM Corp.
 */

#include <inttypes.h>
#include <skiboot.h>
#include <mem-map.h>
#include <libfdt_env.h>
#include <lock.h>
#include <device.h>
#include <cpu.h>
#include <chip.h>
#include <affinity.h>
#include <types.h>
#include <mem_region.h>
#include <mem_region-malloc.h>

/* Memory poisoning on free (if POISON_MEM_REGION set to 1) */
#ifdef DEBUG
#define POISON_MEM_REGION	1
#else
#define POISON_MEM_REGION	0
#endif
#define POISON_MEM_REGION_WITH	0x99
#define POISON_MEM_REGION_LIMIT 1*1024*1024*1024

/* Locking: The mem_region_lock protects the regions list from concurrent
 * updates. Additions to, or removals from, the region list must be done
 * with this lock held. This is typically done when we're establishing
 * the memory & reserved regions.
 *
 * Each region has a lock (region->free_list_lock) to protect the free list
 * from concurrent modification. This lock is used when we're allocating
 * memory out of a specific region.
 *
 * If both locks are needed (eg, __local_alloc, where we need to find a region,
 * then allocate from it), the mem_region_lock must be acquired before (and
 * released after) the per-region lock.
 */
struct lock mem_region_lock = LOCK_UNLOCKED;

static struct list_head regions = LIST_HEAD_INIT(regions);
static struct list_head early_reserves = LIST_HEAD_INIT(early_reserves);

static bool mem_region_init_done = false;
static bool mem_regions_finalised = false;

unsigned long top_of_ram = SKIBOOT_BASE + SKIBOOT_SIZE;

static struct mem_region skiboot_os_reserve = {
	.name		= "ibm,os-reserve",
	.start		= 0,
	.len		= SKIBOOT_BASE,
	.type		= REGION_OS,
};

struct mem_region skiboot_heap = {
	.name		= "ibm,firmware-heap",
	.start		= HEAP_BASE,
	.len		= HEAP_SIZE,
	.type		= REGION_SKIBOOT_HEAP,
};

static struct mem_region skiboot_code_and_text = {
	.name		= "ibm,firmware-code",
	.start		= SKIBOOT_BASE,
	.len		= HEAP_BASE - SKIBOOT_BASE,
	.type		= REGION_SKIBOOT_FIRMWARE,
};

static struct mem_region skiboot_after_heap = {
	.name		= "ibm,firmware-data",
	.start		= HEAP_BASE + HEAP_SIZE,
	.len		= SKIBOOT_BASE + SKIBOOT_SIZE - (HEAP_BASE + HEAP_SIZE),
	.type		= REGION_SKIBOOT_FIRMWARE,
};

static struct mem_region skiboot_cpu_stacks = {
	.name		= "ibm,firmware-stacks",
	.start		= CPU_STACKS_BASE,
	.len		= 0, /* TBA */
	.type		= REGION_SKIBOOT_FIRMWARE,
};

static struct mem_region skiboot_mambo_kernel = {
	.name		= "ibm,firmware-mambo-kernel",
	.start		= (unsigned long)KERNEL_LOAD_BASE,
	.len		= KERNEL_LOAD_SIZE,
	.type		= REGION_SKIBOOT_FIRMWARE,
};

static struct mem_region skiboot_mambo_initramfs = {
	.name		= "ibm,firmware-mambo-initramfs",
	.start		= (unsigned long)INITRAMFS_LOAD_BASE,
	.len		= INITRAMFS_LOAD_SIZE,
	.type		= REGION_SKIBOOT_FIRMWARE,
};


struct alloc_hdr {
	bool free : 1;
	bool prev_free : 1;
	bool printed : 1;
	unsigned long num_longs : BITS_PER_LONG-3; /* Including header. */
	const char *location;
};

struct free_hdr {
	struct alloc_hdr hdr;
	struct list_node list;
	/* ... unsigned long tailer; */
};

#define ALLOC_HDR_LONGS (sizeof(struct alloc_hdr) / sizeof(long))
#define ALLOC_MIN_LONGS (sizeof(struct free_hdr) / sizeof(long) + 1)

/* Avoid ugly casts. */
static void *region_start(const struct mem_region *region)
{
	return (void *)(unsigned long)region->start;
}

/* Each free block has a tailer, so we can walk backwards. */
static unsigned long *tailer(struct free_hdr *f)
{
	return (unsigned long *)f + f->hdr.num_longs - 1;
}

/* This walks forward to the next hdr (or NULL if at the end). */
static struct alloc_hdr *next_hdr(const struct mem_region *region,
				  const struct alloc_hdr *hdr)
{
	void *next;

	next = ((unsigned long *)hdr + hdr->num_longs);
	if (next >= region_start(region) + region->len)
		next = NULL;
	return next;
}

#if POISON_MEM_REGION == 1
static void mem_poison(struct free_hdr *f)
{
	size_t poison_size = (void*)tailer(f) - (void*)(f+1);

	/* We only poison up to a limit, as otherwise boot is
	 * kinda slow */
	if (poison_size > POISON_MEM_REGION_LIMIT)
		poison_size = POISON_MEM_REGION_LIMIT;

	memset(f+1, POISON_MEM_REGION_WITH, poison_size);
}
#endif

/* Creates free block covering entire region. */
static void init_allocatable_region(struct mem_region *region)
{
	struct free_hdr *f = region_start(region);
	assert(region->type == REGION_SKIBOOT_HEAP ||
	       region->type == REGION_MEMORY);
	f->hdr.num_longs = region->len / sizeof(long);
	f->hdr.free = true;
	f->hdr.prev_free = false;
	*tailer(f) = f->hdr.num_longs;
	list_head_init(&region->free_list);
	list_add(&region->free_list, &f->list);
#if POISON_MEM_REGION == 1
	mem_poison(f);
#endif
}

static void make_free(struct mem_region *region, struct free_hdr *f,
		      const char *location, bool skip_poison)
{
	struct alloc_hdr *next;

#if POISON_MEM_REGION == 1
	if (!skip_poison)
		mem_poison(f);
#else
	(void)skip_poison;
#endif

	if (f->hdr.prev_free) {
		struct free_hdr *prev;
		unsigned long *prev_tailer = (unsigned long *)f - 1;

		assert(*prev_tailer);
		prev = (void *)((unsigned long *)f - *prev_tailer);
		assert(prev->hdr.free);
		assert(!prev->hdr.prev_free);

		/* Expand to cover the one we just freed. */
		prev->hdr.num_longs += f->hdr.num_longs;
		f = prev;
	} else {
		f->hdr.free = true;
		f->hdr.location = location;
		list_add(&region->free_list, &f->list);
	}

	/* Fix up tailer. */
	*tailer(f) = f->hdr.num_longs;

	/* If next is free, coalesce it */
	next = next_hdr(region, &f->hdr);
	if (next) {
		next->prev_free = true;
		if (next->free) {
			struct free_hdr *next_free = (void *)next;
			list_del_from(&region->free_list, &next_free->list);
			/* Maximum of one level of recursion */
			make_free(region, next_free, location, true);
		}
	}
}

/* Can we fit this many longs with this alignment in this free block? */
static bool fits(struct free_hdr *f, size_t longs, size_t align, size_t *offset)
{
	*offset = 0;

	while (f->hdr.num_longs >= *offset + longs) {
		size_t addr;

		addr = (unsigned long)f
			+ (*offset + ALLOC_HDR_LONGS) * sizeof(long);
		if ((addr & (align - 1)) == 0)
			return true;

		/* Don't make tiny chunks! */
		if (*offset == 0)
			*offset = ALLOC_MIN_LONGS;
		else
			(*offset)++;
	}
	return false;
}

static void discard_excess(struct mem_region *region,
			   struct alloc_hdr *hdr, size_t alloc_longs,
			   const char *location, bool skip_poison)
{
	/* Do we have excess? */
	if (hdr->num_longs > alloc_longs + ALLOC_MIN_LONGS) {
		struct free_hdr *post;

		/* Set up post block. */
		post = (void *)hdr + alloc_longs * sizeof(long);
		post->hdr.num_longs = hdr->num_longs - alloc_longs;
		post->hdr.prev_free = false;

		/* Trim our block. */
		hdr->num_longs = alloc_longs;

		/* This coalesces as required. */
		make_free(region, post, location, skip_poison);
	}
}

static const char *hdr_location(const struct alloc_hdr *hdr)
{
	/* Corrupt: step carefully! */
	if (is_rodata(hdr->location))
		return hdr->location;
	return "*CORRUPT*";
}

static void bad_header(const struct mem_region *region,
		       const struct alloc_hdr *hdr,
		       const char *during,
		       const char *location)
{
	/* Corrupt: step carefully! */
	if (is_rodata(hdr->location))
		prerror("%p (in %s) %s at %s, previously %s\n",
			hdr-1, region->name, during, location, hdr->location);
	else
		prerror("%p (in %s) %s at %s, previously %p\n",
			hdr-1, region->name, during, location, hdr->location);
	abort();
}

static bool region_is_reservable(struct mem_region *region)
{
	return region->type != REGION_OS;
}

static bool region_is_reserved(struct mem_region *region)
{
	return region->type != REGION_OS && region->type != REGION_MEMORY;
}

void mem_dump_allocs(void)
{
	struct mem_region *region;
	struct alloc_hdr *h, *i;

	/* Second pass: populate property data */
	prlog(PR_INFO, "Memory regions:\n");
	list_for_each(&regions, region, list) {
		if (!(region->type == REGION_SKIBOOT_HEAP ||
		      region->type == REGION_MEMORY))
			continue;
		prlog(PR_INFO, "  0x%012llx..%012llx : %s\n",
		       (long long)region->start,
		       (long long)(region->start + region->len - 1),
		       region->name);
		if (region->free_list.n.next == NULL) {
			prlog(PR_INFO, "    no allocs\n");
			continue;
		}

		/*
		 * XXX: When dumping the allocation list we coalase allocations
		 * with the same location and size into a single line. This is
		 * quadratic, but it makes the dump human-readable and the raw
		 * dump sometimes causes the log buffer to wrap.
		 */
		for (h = region_start(region); h; h = next_hdr(region, h))
			h->printed = false;

		for (h = region_start(region); h; h = next_hdr(region, h)) {
			unsigned long bytes;
			int count = 0;

			if (h->free)
				continue;
			if (h->printed)
				continue;

			for (i = h; i; i = next_hdr(region, i)) {
				if (i->free)
					continue;
				if (i->num_longs != h->num_longs)
					continue;
				if (strcmp(i->location, h->location))
					continue;

				i->printed = true;
				count++;
			}

			bytes = h->num_longs * sizeof(long);
			prlog(PR_NOTICE, " % 8d allocs of 0x%.8lx bytes at %s (total 0x%lx)\n",
				count, bytes, hdr_location(h), bytes * count);
		}
	}
}

int64_t mem_dump_free(void)
{
	struct mem_region *region;
	struct alloc_hdr *hdr;
	int64_t total_free;
	int64_t region_free;

	total_free = 0;

	prlog(PR_INFO, "Free space in HEAP memory regions:\n");
	list_for_each(&regions, region, list) {
		if (!(region->type == REGION_SKIBOOT_HEAP ||
		      region->type == REGION_MEMORY))
			continue;
		region_free = 0;

		if (region->free_list.n.next == NULL) {
			continue;
		}
		for (hdr = region_start(region); hdr; hdr = next_hdr(region, hdr)) {
			if (!hdr->free)
				continue;

			region_free+= hdr->num_longs * sizeof(long);
		}
		prlog(PR_INFO, "Region %s free: %"PRIx64"\n",
		       region->name, region_free);
		total_free += region_free;
	}

	prlog(PR_INFO, "Total free: %"PRIu64"\n", total_free);

	return total_free;
}

static void *__mem_alloc(struct mem_region *region, size_t size, size_t align,
			 const char *location)
{
	size_t alloc_longs, offset;
	struct free_hdr *f;
	struct alloc_hdr *next;

	/* Align must be power of 2. */
	assert(!((align - 1) & align));

	/* This should be a constant. */
	assert(is_rodata(location));

	/* Unallocatable region? */
	if (!(region->type == REGION_SKIBOOT_HEAP ||
	      region->type == REGION_MEMORY))
		return NULL;

	/* First allocation? */
	if (region->free_list.n.next == NULL)
		init_allocatable_region(region);

	/* Don't do screwy sizes. */
	if (size > region->len)
		return NULL;

	/* Don't do tiny alignments, we deal in long increments. */
	if (align < sizeof(long))
		align = sizeof(long);

	/* Convert size to number of longs, too. */
	alloc_longs = (size + sizeof(long)-1) / sizeof(long) + ALLOC_HDR_LONGS;

	/* Can't be too small for when we free it, either. */
	if (alloc_longs < ALLOC_MIN_LONGS)
		alloc_longs = ALLOC_MIN_LONGS;

	/* Walk free list. */
	list_for_each(&region->free_list, f, list) {
		/* We may have to skip some to meet alignment. */
		if (fits(f, alloc_longs, align, &offset))
			goto found;
	}

	return NULL;

found:
	assert(f->hdr.free);
	assert(!f->hdr.prev_free);

	/* This block is no longer free. */
	list_del_from(&region->free_list, &f->list);
	f->hdr.free = false;
	f->hdr.location = location;

	next = next_hdr(region, &f->hdr);
	if (next) {
		assert(next->prev_free);
		next->prev_free = false;
	}

	if (offset != 0) {
		struct free_hdr *pre = f;

		f = (void *)f + offset * sizeof(long);
		assert(f >= pre + 1);

		/* Set up new header. */
		f->hdr.num_longs = pre->hdr.num_longs - offset;
		/* f->hdr.prev_free will be set by make_free below. */
		f->hdr.free = false;
		f->hdr.location = location;

		/* Fix up old header. */
		pre->hdr.num_longs = offset;
		pre->hdr.prev_free = false;

		/* This coalesces as required. */
		make_free(region, pre, location, true);
	}

	/* We might be too long; put the rest back. */
	discard_excess(region, &f->hdr, alloc_longs, location, true);

	/* Clear tailer for debugging */
	*tailer(f) = 0;

	/* Their pointer is immediately after header. */
	return &f->hdr + 1;
}

void *mem_alloc(struct mem_region *region, size_t size, size_t align,
		const char *location)
{
	static bool dumped = false;
	void *r;

	assert(lock_held_by_me(&region->free_list_lock));

	r = __mem_alloc(region, size, align, location);
	if (r)
		return r;

	prerror("mem_alloc(0x%lx, 0x%lx, \"%s\", %s) failed !\n",
		size, align, location, region->name);
	if (!dumped) {
		mem_dump_allocs();
		dumped = true;
	}

	return NULL;
}

void mem_free(struct mem_region *region, void *mem, const char *location)
{
	struct alloc_hdr *hdr;

	/* This should be a constant. */
	assert(is_rodata(location));

	assert(lock_held_by_me(&region->free_list_lock));

	/* Freeing NULL is always a noop. */
	if (!mem)
		return;

	/* Your memory is in the region, right? */
	assert(mem >= region_start(region) + sizeof(*hdr));
	assert(mem < region_start(region) + region->len);

	/* Grab header. */
	hdr = mem - sizeof(*hdr);

	if (hdr->free)
		bad_header(region, hdr, "re-freed", location);

	make_free(region, (struct free_hdr *)hdr, location, false);
}

size_t mem_allocated_size(const void *ptr)
{
	const struct alloc_hdr *hdr = ptr - sizeof(*hdr);
	return hdr->num_longs * sizeof(long) - sizeof(struct alloc_hdr);
}

bool mem_resize(struct mem_region *region, void *mem, size_t len,
		const char *location)
{
	struct alloc_hdr *hdr, *next;
	struct free_hdr *f;

	/* This should be a constant. */
	assert(is_rodata(location));

	assert(lock_held_by_me(&region->free_list_lock));

	/* Get header. */
	hdr = mem - sizeof(*hdr);
	if (hdr->free)
		bad_header(region, hdr, "resize", location);

	/* Round up size to multiple of longs. */
	len = (sizeof(*hdr) + len + sizeof(long) - 1) / sizeof(long);

	/* Can't be too small for when we free it, either. */
	if (len < ALLOC_MIN_LONGS)
		len = ALLOC_MIN_LONGS;

	/* Shrinking is simple. */
	if (len <= hdr->num_longs) {
		hdr->location = location;
		discard_excess(region, hdr, len, location, false);
		return true;
	}

	/* Check if we can expand. */
	next = next_hdr(region, hdr);
	if (!next || !next->free || hdr->num_longs + next->num_longs < len)
		return false;

	/* OK, it's free and big enough, absorb it. */
	f = (struct free_hdr *)next;
	list_del_from(&region->free_list, &f->list);
	hdr->num_longs += next->num_longs;
	hdr->location = location;

	/* Update next prev_free */
	next = next_hdr(region, &f->hdr);
	if (next) {
		assert(next->prev_free);
		next->prev_free = false;
	}

	/* Clear tailer for debugging */
	*tailer(f) = 0;

	/* Now we might have *too* much. */
	discard_excess(region, hdr, len, location, true);
	return true;
}

bool mem_check(const struct mem_region *region)
{
	size_t frees = 0;
	struct alloc_hdr *hdr, *prev_free = NULL;
	struct free_hdr *f;

	/* Check it's sanely aligned. */
	if (region->start % sizeof(long)) {
		prerror("Region '%s' not sanely aligned (%llx)\n",
			region->name, (unsigned long long)region->start);
		return false;
	}
	if ((long)region->len % sizeof(long)) {
		prerror("Region '%s' not sane length (%llu)\n",
			region->name, (unsigned long long)region->len);
		return false;
	}

	/* Not ours to play with, or empty?  Don't do anything. */
	if (!(region->type == REGION_MEMORY ||
	      region->type == REGION_SKIBOOT_HEAP) ||
	    region->free_list.n.next == NULL)
		return true;

	/* Walk linearly. */
	for (hdr = region_start(region); hdr; hdr = next_hdr(region, hdr)) {
		if (hdr->num_longs < ALLOC_MIN_LONGS) {
			prerror("Region '%s' %s %p (%s) size %zu\n",
				region->name, hdr->free ? "free" : "alloc",
				hdr, hdr_location(hdr),
				hdr->num_longs * sizeof(long));
			return false;
		}
		if ((unsigned long)hdr + hdr->num_longs * sizeof(long) >
		    region->start + region->len) {
			prerror("Region '%s' %s %p (%s) oversize %zu\n",
				region->name, hdr->free ? "free" : "alloc",
				hdr, hdr_location(hdr),
				hdr->num_longs * sizeof(long));
			return false;
		}
		if (hdr->free) {
			if (hdr->prev_free || prev_free) {
				prerror("Region '%s' free %p (%s) has prev_free"
					" %p (%s) %sset?\n",
					region->name, hdr, hdr_location(hdr),
					prev_free,
					prev_free ? hdr_location(prev_free)
					: "NULL",
					hdr->prev_free ? "" : "un");
				return false;
			}
			prev_free = hdr;
			frees ^= (unsigned long)hdr - region->start;
		} else {
			if (hdr->prev_free != (bool)prev_free) {
				prerror("Region '%s' alloc %p (%s) has"
					" prev_free %p %sset?\n",
					region->name, hdr, hdr_location(hdr),
					prev_free, hdr->prev_free ? "" : "un");
				return false;
			}
			prev_free = NULL;
		}
	}

	/* Now walk free list. */
	list_for_each(&region->free_list, f, list)
		frees ^= (unsigned long)f - region->start;

	if (frees) {
		prerror("Region '%s' free list and walk do not match!\n",
			region->name);
		return false;
	}
	return true;
}

bool mem_check_all(void)
{
	struct mem_region *r;

	list_for_each(&regions, r, list) {
		if (!mem_check(r))
			return false;
	}

	return true;
}

static struct mem_region *new_region(const char *name,
				     uint64_t start, uint64_t len,
				     struct dt_node *node,
				     enum mem_region_type type)
{
	struct mem_region *region;

	region = malloc(sizeof(*region));
	if (!region)
		return NULL;

	region->name = name;
	region->start = start;
	region->len = len;
	region->node = node;
	region->type = type;
	region->free_list.n.next = NULL;
	init_lock(&region->free_list_lock);

	return region;
}

/* We always split regions, so we only have to replace one. */
static struct mem_region *split_region(struct mem_region *head,
				       uint64_t split_at,
				       enum mem_region_type type)
{
	struct mem_region *tail;
	uint64_t end = head->start + head->len;

	tail = new_region(head->name, split_at, end - split_at,
			  head->node, type);
	/* Original region becomes head. */
	if (tail)
		head->len -= tail->len;

	return tail;
}

static bool intersects(const struct mem_region *region, uint64_t addr)
{
	return addr > region->start &&
		addr < region->start + region->len;
}

static bool maybe_split(struct mem_region *r, uint64_t split_at)
{
	struct mem_region *tail;

	if (!intersects(r, split_at))
		return true;

	tail = split_region(r, split_at, r->type);
	if (!tail)
		return false;

	/* Tail add is important: we may need to split again! */
	list_add_after(&regions, &tail->list, &r->list);
	return true;
}

static bool overlaps(const struct mem_region *r1, const struct mem_region *r2)
{
	return (r1->start + r1->len > r2->start
		&& r1->start < r2->start + r2->len);
}

static bool contains(const struct mem_region *r1, const struct mem_region *r2)
{
	u64 r1_end = r1->start + r1->len;
	u64 r2_end = r2->start + r2->len;

	return (r1->start <= r2->start && r2_end <= r1_end);
}

static struct mem_region *get_overlap(const struct mem_region *region)
{
	struct mem_region *i;

	list_for_each(&regions, i, list) {
		if (overlaps(region, i))
			return i;
	}
	return NULL;
}

static void add_region_to_regions(struct mem_region *region)
{
	struct mem_region *r;

	list_for_each(&regions, r, list) {
		if (r->start < region->start)
			continue;

		list_add_before(&regions, &region->list, &r->list);
		return;
	}
	list_add_tail(&regions, &region->list);
}

static bool add_region(struct mem_region *region)
{
	struct mem_region *r;

	if (mem_regions_finalised) {
		prerror("MEM: add_region(%s@0x%"PRIx64") called after finalise!\n",
				region->name, region->start);
		return false;
	}

	/* First split any regions which intersect. */
	list_for_each(&regions, r, list) {
		/*
		 * The new region should be fully contained by an existing one.
		 * If it's not then we have a problem where reservations
		 * partially overlap which is probably broken.
		 *
		 * NB: There *might* be situations where this is legitimate,
		 * but the region handling does not currently support this.
		 */
		if (overlaps(r, region) && !contains(r, region)) {
			prerror("MEM: Partial overlap detected between regions:\n");
			prerror("MEM: %s [0x%"PRIx64"-0x%"PRIx64"] (new)\n",
				region->name, region->start,
				region->start + region->len);
			prerror("MEM: %s [0x%"PRIx64"-0x%"PRIx64"]\n",
				r->name, r->start, r->start + r->len);
			return false;
		}

		if (!maybe_split(r, region->start) ||
		    !maybe_split(r, region->start + region->len))
			return false;
	}

	/* Now we have only whole overlaps, if any. */
	while ((r = get_overlap(region)) != NULL) {
		assert(r->start == region->start);
		assert(r->len == region->len);
		list_del_from(&regions, &r->list);
		free(r);
	}

	/* Finally, add in our own region. */
	add_region_to_regions(region);
	return true;
}

static void mem_reserve(enum mem_region_type type, const char *name,
		uint64_t start, uint64_t len)
{
	struct mem_region *region;
	bool added = true;

	lock(&mem_region_lock);
	region = new_region(name, start, len, NULL, type);
	assert(region);

	if (!mem_region_init_done)
		list_add(&early_reserves, &region->list);
	else
		added = add_region(region);

	assert(added);
	unlock(&mem_region_lock);
}

void mem_reserve_fw(const char *name, uint64_t start, uint64_t len)
{
	mem_reserve(REGION_FW_RESERVED, name, start, len);
}

void mem_reserve_hwbuf(const char *name, uint64_t start, uint64_t len)
{
	mem_reserve(REGION_RESERVED, name, start, len);
}

static bool matches_chip_id(const __be32 ids[], size_t num, u32 chip_id)
{
	size_t i;

	for (i = 0; i < num; i++)
		if (be32_to_cpu(ids[i]) == chip_id)
			return true;

	return false;
}

void *__local_alloc(unsigned int chip_id, size_t size, size_t align,
		    const char *location)
{
	struct mem_region *region;
	void *p = NULL;
	bool use_local = true;

	lock(&mem_region_lock);

restart:
	list_for_each(&regions, region, list) {
		const struct dt_property *prop;
		const __be32 *ids;

		if (!(region->type == REGION_SKIBOOT_HEAP ||
		      region->type == REGION_MEMORY))
			continue;

		/* Don't allocate from normal heap. */
		if (region == &skiboot_heap)
			continue;

		/* First pass, only match node local regions */
		if (use_local) {
			if (!region->node)
				continue;
			prop = dt_find_property(region->node, "ibm,chip-id");
			ids = (const __be32 *)prop->prop;
			if (!matches_chip_id(ids, prop->len/sizeof(u32),
					     chip_id))
				continue;
		}

		/* Second pass, match anything */
		lock(&region->free_list_lock);
		p = mem_alloc(region, size, align, location);
		unlock(&region->free_list_lock);
		if (p)
			break;
	}

	/*
	 * If we can't allocate the memory block from the expected
	 * node, we bail to any one that can accommodate our request.
	 */
	if (!p && use_local) {
		use_local = false;
		goto restart;
	}

	unlock(&mem_region_lock);

	return p;
}

struct mem_region *find_mem_region(const char *name)
{
	struct mem_region *region;

	list_for_each(&regions, region, list) {
		if (streq(region->name, name))
			return region;
	}
	return NULL;
}

bool mem_range_is_reserved(uint64_t start, uint64_t size)
{
	uint64_t end = start + size;
	struct mem_region *region;
	struct list_head *search;

	/* We may have the range covered by a number of regions, which could
	 * appear in any order. So, we look for a region that covers the
	 * start address, and bump start up to the end of that region.
	 *
	 * We repeat until we've either bumped past the end of the range,
	 * or we didn't find a matching region.
	 *
	 * This has a worst-case of O(n^2), but n is well bounded by the
	 * small number of reservations.
	 */

	if (!mem_region_init_done)
		search = &early_reserves;
	else
		search = &regions;

	for (;;) {
		bool found = false;

		list_for_each(search, region, list) {
			if (!region_is_reserved(region))
				continue;

			/* does this region overlap the start address, and
			 * have a non-zero size? */
			if (region->start <= start &&
					region->start + region->len > start &&
					region->len) {
				start = region->start + region->len;
				found = true;
			}
		}

		/* 'end' is the first byte outside of the range */
		if (start >= end)
			return true;

		if (!found)
			break;
	}

	return false;
}

static void mem_region_parse_reserved_properties(void)
{
	const struct dt_property *names, *ranges;
	struct mem_region *region;

	prlog(PR_DEBUG, "MEM: parsing reserved memory from "
			"reserved-names/-ranges properties\n");

	names = dt_find_property(dt_root, "reserved-names");
	ranges = dt_find_property(dt_root, "reserved-ranges");
	if (names && ranges) {
		const uint64_t *range;
		int n, len;

		range = (const void *)ranges->prop;

		for (n = 0; n < names->len; n += len, range += 2) {
			char *name;

			len = strlen(names->prop + n) + 1;
			name = strdup(names->prop + n);

			region = new_region(name,
					dt_get_number(range, 2),
					dt_get_number(range + 1, 2),
					NULL, REGION_FW_RESERVED);
			if (!add_region(region)) {
				prerror("Couldn't add mem_region %s\n", name);
				abort();
			}
		}
	} else if (names || ranges) {
		prerror("Invalid properties: reserved-names=%p "
				"with reserved-ranges=%p\n",
				names, ranges);
		abort();
	} else {
		return;
	}
}

static bool mem_region_parse_reserved_nodes(const char *path)
{
	struct dt_node *parent, *node;

	parent = dt_find_by_path(dt_root, path);
	if (!parent)
		return false;

	prlog(PR_INFO, "MEM: parsing reserved memory from node %s\n", path);

	dt_for_each_child(parent, node) {
		const struct dt_property *reg;
		struct mem_region *region;
		int type;

		reg = dt_find_property(node, "reg");
		if (!reg) {
			char *nodepath = dt_get_path(node);
			prerror("node %s has no reg property, ignoring\n",
					nodepath);
			free(nodepath);
			continue;
		}

		if (dt_has_node_property(node, "no-map", NULL))
			type = REGION_RESERVED;
		else
			type = REGION_FW_RESERVED;

		region = new_region(strdup(node->name),
				dt_get_number(reg->prop, 2),
				dt_get_number(reg->prop + sizeof(u64), 2),
				node, type);
		if (!add_region(region)) {
			char *nodepath = dt_get_path(node);
			prerror("node %s failed to add_region()\n", nodepath);
			free(nodepath);
		}
	}

	return true;
}

/* Trawl through device tree, create memory regions from nodes. */
void mem_region_init(void)
{
	struct mem_region *region, *next;
	struct dt_node *i;
	bool rc;

	/*
	 * Add associativity properties outside of the lock
	 * to avoid recursive locking caused by allocations
	 * done by add_chip_dev_associativity()
	 */
	dt_for_each_node(dt_root, i) {
		if (!dt_has_node_property(i, "device_type", "memory") &&
		    !dt_has_node_property(i, "compatible", "pmem-region"))
			continue;

		/* Add associativity properties */
		add_chip_dev_associativity(i);
	}

	/* Add each memory node. */
	dt_for_each_node(dt_root, i) {
		uint64_t start, len;
		char *rname;
#define NODE_REGION_PREFIX 	"ibm,firmware-allocs-"

		if (!dt_has_node_property(i, "device_type", "memory"))
			continue;
		rname = zalloc(strlen(i->name) + strlen(NODE_REGION_PREFIX) + 1);
		assert(rname);
		strcat(rname, NODE_REGION_PREFIX);
		strcat(rname, i->name);
		start = dt_get_address(i, 0, &len);
		lock(&mem_region_lock);
		region = new_region(rname, start, len, i, REGION_MEMORY);
		if (!region) {
			prerror("MEM: Could not add mem region %s!\n", i->name);
			abort();
		}
		add_region_to_regions(region);
		if ((start + len) > top_of_ram)
			top_of_ram = start + len;
		unlock(&mem_region_lock);
	}

	/*
	 * This is called after we know the maximum PIR of all CPUs,
	 * so we can dynamically set the stack length.
	 */
	skiboot_cpu_stacks.len = (cpu_max_pir + 1) * STACK_SIZE;

	lock(&mem_region_lock);

	/* Now carve out our own reserved areas. */
	if (!add_region(&skiboot_os_reserve) ||
	    !add_region(&skiboot_code_and_text) ||
	    !add_region(&skiboot_heap) ||
	    !add_region(&skiboot_after_heap) ||
	    !add_region(&skiboot_cpu_stacks)) {
		prerror("Out of memory adding skiboot reserved areas\n");
		abort();
	}

	if (chip_quirk(QUIRK_MAMBO_CALLOUTS)) {
		if (!add_region(&skiboot_mambo_kernel) ||
		    !add_region(&skiboot_mambo_initramfs)) {
			prerror("Out of memory adding mambo payload\n");
			abort();
		}
	}

	/* Add reserved reanges from HDAT */
	list_for_each_safe(&early_reserves, region, next, list) {
		bool added;

		list_del(&region->list);
		added = add_region(region);
		assert(added);
	}

	/* Add reserved ranges from the DT */
	rc = mem_region_parse_reserved_nodes("/reserved-memory");
	if (!rc)
		rc = mem_region_parse_reserved_nodes(
				"/ibm,hostboot/reserved-memory");
	if (!rc)
		mem_region_parse_reserved_properties();

	mem_region_init_done = true;
	unlock(&mem_region_lock);
}

static uint64_t allocated_length(const struct mem_region *r)
{
	struct free_hdr *f, *last = NULL;

	/* No allocations at all? */
	if (r->free_list.n.next == NULL)
		return 0;

	/* Find last free block. */
	list_for_each(&r->free_list, f, list)
		if (f > last)
			last = f;

	/* No free blocks? */
	if (!last)
		return r->len;

	/* Last free block isn't at end? */
	if (next_hdr(r, &last->hdr))
		return r->len;
	return (unsigned long)last - r->start;
}

/* Separate out allocated sections into their own region. */
void mem_region_release_unused(void)
{
	struct mem_region *r;

	lock(&mem_region_lock);
	assert(!mem_regions_finalised);

	prlog(PR_INFO, "Releasing unused memory:\n");
	list_for_each(&regions, r, list) {
		uint64_t used_len;

		/* If it's not allocatable, ignore it. */
		if (!(r->type == REGION_SKIBOOT_HEAP ||
		      r->type == REGION_MEMORY))
			continue;

		used_len = allocated_length(r);

		prlog(PR_INFO, "    %s: %llu/%llu used\n",
		       r->name, (long long)used_len, (long long)r->len);

		/* We keep the skiboot heap. */
		if (r == &skiboot_heap)
			continue;

		/* Nothing used?  Whole thing is for Linux. */
		if (used_len == 0)
			r->type = REGION_OS;
		/* Partially used?  Split region. */
		else if (used_len != r->len) {
			struct mem_region *for_linux;
			struct free_hdr *last = region_start(r) + used_len;

			/* Remove the final free block. */
			list_del_from(&r->free_list, &last->list);

			for_linux = split_region(r, r->start + used_len,
						 REGION_OS);
			if (!for_linux) {
				prerror("OOM splitting mem node %s for linux\n",
					r->name);
				abort();
			}
			list_add(&regions, &for_linux->list);
		}
	}
	unlock(&mem_region_lock);
}

static void mem_clear_range(uint64_t s, uint64_t e)
{
	uint64_t res_start, res_end;

	/* Skip exception vectors */
	if (s < EXCEPTION_VECTORS_END)
		s = EXCEPTION_VECTORS_END;

	/* Skip kernel preload area */
	res_start = (uint64_t)KERNEL_LOAD_BASE;
	res_end = res_start + KERNEL_LOAD_SIZE;

	if (s >= res_start && s < res_end)
	       s = res_end;
	if (e > res_start && e <= res_end)
	       e = res_start;
	if (e <= s)
		return;
	if (s < res_start && e > res_end) {
		mem_clear_range(s, res_start);
		mem_clear_range(res_end, e);
		return;
	}

	/* Skip initramfs preload area */
	res_start = (uint64_t)INITRAMFS_LOAD_BASE;
	res_end = res_start + INITRAMFS_LOAD_SIZE;

	if (s >= res_start && s < res_end)
	       s = res_end;
	if (e > res_start && e <= res_end)
	       e = res_start;
	if (e <= s)
		return;
	if (s < res_start && e > res_end) {
		mem_clear_range(s, res_start);
		mem_clear_range(res_end, e);
		return;
	}

	prlog(PR_DEBUG, "Clearing region %llx-%llx\n",
	      (long long)s, (long long)e);
	memset((void *)s, 0, e - s);
}

struct mem_region_clear_job_args {
	char *job_name;
	uint64_t s,e;
};

static void mem_region_clear_job(void *data)
{
	struct mem_region_clear_job_args *arg = (struct mem_region_clear_job_args*)data;
	mem_clear_range(arg->s, arg->e);
}

#define MEM_REGION_CLEAR_JOB_SIZE (16ULL*(1<<30))

static struct cpu_job **mem_clear_jobs;
static struct mem_region_clear_job_args *mem_clear_job_args;
static int mem_clear_njobs = 0;

void start_mem_region_clear_unused(void)
{
	struct mem_region *r;
	uint64_t s,l;
	uint64_t total = 0;
	uint32_t chip_id;
	char *path;
	int i;
	struct cpu_job **jobs;
	struct mem_region_clear_job_args *job_args;

	lock(&mem_region_lock);
	assert(mem_regions_finalised);

	mem_clear_njobs = 0;

	list_for_each(&regions, r, list) {
		if (!(r->type == REGION_OS))
			continue;
		mem_clear_njobs++;
		/* One job per 16GB */
		mem_clear_njobs += r->len / MEM_REGION_CLEAR_JOB_SIZE;
	}

	jobs = malloc(mem_clear_njobs * sizeof(struct cpu_job*));
	job_args = malloc(mem_clear_njobs * sizeof(struct mem_region_clear_job_args));
	mem_clear_jobs = jobs;
	mem_clear_job_args = job_args;

	prlog(PR_NOTICE, "Clearing unused memory:\n");
	i = 0;
	list_for_each(&regions, r, list) {
		/* If it's not unused, ignore it. */
		if (!(r->type == REGION_OS))
			continue;

		assert(r != &skiboot_heap);

		s = r->start;
		l = r->len;
		while(l > MEM_REGION_CLEAR_JOB_SIZE) {
			job_args[i].s = s+l - MEM_REGION_CLEAR_JOB_SIZE;
			job_args[i].e = s+l;
			l-=MEM_REGION_CLEAR_JOB_SIZE;
			job_args[i].job_name = malloc(sizeof(char)*100);
			total+=MEM_REGION_CLEAR_JOB_SIZE;
			chip_id = __dt_get_chip_id(r->node);
			if (chip_id == -1)
				chip_id = 0;
			path = dt_get_path(r->node);
			snprintf(job_args[i].job_name, 100,
				 "clear %s, %s 0x%"PRIx64" len: %"PRIx64" on %d",
				 r->name, path,
				 job_args[i].s,
				 (job_args[i].e - job_args[i].s),
				 chip_id);
			free(path);
			jobs[i] = cpu_queue_job_on_node(chip_id,
							job_args[i].job_name,
							mem_region_clear_job,
							&job_args[i]);
			if (!jobs[i])
				jobs[i] = cpu_queue_job(NULL,
							job_args[i].job_name,
							mem_region_clear_job,
							&job_args[i]);
			assert(jobs[i]);
			i++;
		}
		job_args[i].s = s;
		job_args[i].e = s+l;
		job_args[i].job_name = malloc(sizeof(char)*100);
		total+=l;
		chip_id = __dt_get_chip_id(r->node);
		if (chip_id == -1)
			chip_id = 0;
		path = dt_get_path(r->node);
		snprintf(job_args[i].job_name,100,
			 "clear %s, %s 0x%"PRIx64" len: 0x%"PRIx64" on %d",
			 r->name, path,
			 job_args[i].s,
			 (job_args[i].e - job_args[i].s),
			 chip_id);
		free(path);
		jobs[i] = cpu_queue_job_on_node(chip_id,
						job_args[i].job_name,
						mem_region_clear_job,
						&job_args[i]);
		if (!jobs[i])
			jobs[i] = cpu_queue_job(NULL,
						job_args[i].job_name,
						mem_region_clear_job,
						&job_args[i]);
		assert(jobs[i]);
		i++;
	}
	unlock(&mem_region_lock);
	cpu_process_local_jobs();
}

void wait_mem_region_clear_unused(void)
{
	uint64_t l;
	uint64_t total = 0;
	int i;

	for(i=0; i < mem_clear_njobs; i++) {
		total += (mem_clear_job_args[i].e - mem_clear_job_args[i].s);
	}

	l = 0;
	for(i=0; i < mem_clear_njobs; i++) {
		cpu_wait_job(mem_clear_jobs[i], true);
		l += (mem_clear_job_args[i].e - mem_clear_job_args[i].s);
		printf("Clearing memory... %"PRIu64"/%"PRIu64"GB done\n",
		       l>>30, total>>30);
		free(mem_clear_job_args[i].job_name);
	}
	free(mem_clear_jobs);
	free(mem_clear_job_args);
}

static void mem_region_add_dt_reserved_node(struct dt_node *parent,
		struct mem_region *region)
{
	char *name, *p;

	/* If a reserved region was established before skiboot, it may be
	 * referenced by a device-tree node with extra data. In that case,
	 * copy the node to /reserved-memory/, unless it's already there.
	 *
	 * We update region->node to the new copy here, as the prd code may
	 * update regions' device-tree nodes, and we want those updates to
	 * apply to the nodes in /reserved-memory/.
	 */
	if (region->type == REGION_FW_RESERVED && region->node) {
		if (region->node->parent != parent)
			region->node = dt_copy(region->node, parent);
		return;
	}

	name = strdup(region->name);
	assert(name);

	/* remove any cell addresses in the region name; we have our own cell
	 * addresses here */
	p = strchr(name, '@');
	if (p)
		*p = '\0';

	region->node = dt_new_addr(parent, name, region->start);
	assert(region->node);
	dt_add_property_u64s(region->node, "reg", region->start, region->len);

	/*
	 * This memory is used by hardware and may need special handling. Ask
	 * the host kernel not to map it by default.
	 */
	if (region->type == REGION_RESERVED)
		dt_add_property(region->node, "no-map", NULL, 0);

	free(name);
}

void mem_region_add_dt_reserved(void)
{
	int names_len, ranges_len, len;
	const struct dt_property *prop;
	struct mem_region *region;
	void *names, *ranges;
	struct dt_node *node;
	fdt64_t *range;
	char *name;

	names_len = 0;
	ranges_len = 0;

	/* Finalise the region list, so we know that the regions list won't be
	 * altered after this point. The regions' free lists may change after
	 * we drop the lock, but we don't access those. */
	lock(&mem_region_lock);
	mem_regions_finalised = true;

	/* establish top-level reservation node */
	node = dt_find_by_path(dt_root, "reserved-memory");
	if (!node) {
		node = dt_new(dt_root, "reserved-memory");
		dt_add_property_cells(node, "#address-cells", 2);
		dt_add_property_cells(node, "#size-cells", 2);
		dt_add_property(node, "ranges", NULL, 0);
	}

	prlog(PR_INFO, "Reserved regions:\n");

	/* First pass, create /reserved-memory/ nodes for each reservation,
	 * and calculate the length for the /reserved-names and
	 * /reserved-ranges properties */
	list_for_each(&regions, region, list) {
		if (!region_is_reservable(region))
			continue;

		prlog(PR_INFO, "  0x%012llx..%012llx : %s\n",
		       (long long)region->start,
		       (long long)(region->start + region->len - 1),
		       region->name);

		mem_region_add_dt_reserved_node(node, region);

		/* calculate the size of the properties populated later */
		names_len += strlen(region->node->name) + 1;
		ranges_len += 2 * sizeof(uint64_t);
	}

	name = names = malloc(names_len);
	range = ranges = malloc(ranges_len);

	/* Second pass: populate the old-style reserved-names and
	 * reserved-regions arrays based on the node data */
	list_for_each(&regions, region, list) {
		if (!region_is_reservable(region))
			continue;

		len = strlen(region->node->name) + 1;
		memcpy(name, region->node->name, len);
		name += len;

		range[0] = cpu_to_fdt64(region->start);
		range[1] = cpu_to_fdt64(region->len);
		range += 2;
	}
	unlock(&mem_region_lock);

	prop = dt_find_property(dt_root, "reserved-names");
	if (prop)
		dt_del_property(dt_root, (struct dt_property *)prop);

	prop = dt_find_property(dt_root, "reserved-ranges");
	if (prop)
		dt_del_property(dt_root, (struct dt_property *)prop);

	dt_add_property(dt_root, "reserved-names", names, names_len);
	dt_add_property(dt_root, "reserved-ranges", ranges, ranges_len);

	free(names);
	free(ranges);
}

struct mem_region *mem_region_next(struct mem_region *region)
{
	struct list_node *node;

	assert(lock_held_by_me(&mem_region_lock));

	node = region ? &region->list : &regions.n;

	if (node->next == &regions.n)
		return NULL;

	return list_entry(node->next, struct mem_region, list);
}
