// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2019 IBM Corp.
 */

#include <config.h>
#include <stdlib.h>
#include <assert.h>
#include <sched.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <skiboot-valgrind.h>

/* Don't include these: PPC-specific */
#define __CPU_H
#define __TIME_H
#define __PROCESSOR_H

#if defined(__i386__) || defined(__x86_64__)
/* This is more than a lwsync, but it'll work */
static void full_barrier(void)
{
	asm volatile("mfence" : : : "memory");
}
#define lwsync full_barrier
#elif defined(__powerpc__) || defined(__powerpc64__)
static inline void lwsync(void)
{
	asm volatile("lwsync" : : : "memory");
}
#else
#error "Define lwsync for this arch"
#endif

#define zalloc(size) calloc((size), 1)

struct cpu_thread {
	uint32_t pir;
	uint32_t chip_id;
	struct trace_info *trace;
	uint32_t server_no;
	bool is_secondary;
	struct cpu_thread *primary;
};
static struct cpu_thread *this_cpu(void);

#define CPUS 4

static struct cpu_thread fake_cpus[CPUS];

static inline struct cpu_thread *next_cpu(struct cpu_thread *cpu)
{
	if (cpu == NULL)
		return &fake_cpus[0];
	cpu++;
	if (cpu == &fake_cpus[CPUS])
		return NULL;
	return cpu;
}

#define first_cpu() next_cpu(NULL)

#define for_each_cpu(cpu)	\
	for (cpu = first_cpu(); cpu; cpu = next_cpu(cpu))

static unsigned long timestamp;
static unsigned long mftb(void)
{
	return timestamp;
}

static void *local_alloc(unsigned int chip_id,
			 size_t size, size_t align)
{
	void *p;

	(void)chip_id;
	if (posix_memalign(&p, align, size))
		p = NULL;
	return p;
}

struct dt_node;
extern struct dt_node *opal_node;

#include "../trace.c"

#include "../external/trace/trace.c"
static struct trace_reader trace_readers[CPUS];
struct trace_reader *my_trace_reader;
#include "../device.c"

char __rodata_start[1], __rodata_end[1];
struct dt_node *opal_node;
struct debug_descriptor debug_descriptor = {
	.trace_mask = -1
};

const char *nvram_query_safe(const char *key __unused)
{
	return NULL;
}

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

struct cpu_thread *my_fake_cpu;
static struct cpu_thread *this_cpu(void)
{
	return my_fake_cpu;
}

#include <sys/mman.h>
#define PER_CHILD_TRACES ((RUNNING_ON_VALGRIND) ? (1024*16) : (1024*1024))

static void write_trace_entries(int id)
{
	void exit(int);
	unsigned int i;
	union trace trace;

	timestamp = id;
	for (i = 0; i < PER_CHILD_TRACES; i++) {
		timestamp = i * CPUS + id;
		assert(sizeof(trace.hdr) % 8 == 0);
		/* First child never repeats, second repeats once, etc. */
		trace_add(&trace, 3 + ((i / (id + 1)) % 0x40),
			  sizeof(trace.hdr));
	}

	/* Final entry has special type, so parent knows it's over. */
	trace_add(&trace, 0x70, sizeof(trace.hdr));
	exit(0);
}

static bool all_done(const bool done[])
{
	unsigned int i;

	for (i = 0; i < CPUS; i++)
		if (!done[i])
			return false;
	return true;
}

static void test_parallel(void)
{
	void *p;
	unsigned int cpu;
	unsigned int i, counts[CPUS] = { 0 }, overflows[CPUS] = { 0 };
	unsigned int repeats[CPUS] = { 0 }, num_overflows[CPUS] = { 0 };
	bool done[CPUS] = { false };
	size_t len = sizeof(struct trace_info) + TBUF_SZ + sizeof(union trace);
	int last = 0;

	/* Use a shared mmap to test actual parallel buffers. */
	i = (CPUS*len + getpagesize()-1)&~(getpagesize()-1);
	p = mmap(NULL, i, PROT_READ|PROT_WRITE,
		 MAP_ANONYMOUS|MAP_SHARED, -1, 0);

	for (i = 0; i < CPUS; i++) {
		fake_cpus[i].trace = p + i * len;
		fake_cpus[i].trace->tb.buf_size = cpu_to_be64(TBUF_SZ);
		fake_cpus[i].trace->tb.max_size = cpu_to_be32(sizeof(union trace));
		fake_cpus[i].is_secondary = false;
		memset(&trace_readers[i], 0, sizeof(struct trace_reader));
		trace_readers[i].tb = &fake_cpus[i].trace->tb;
	}

	for (i = 0; i < CPUS; i++) {
		if (!fork()) {
			/* Child. */
			my_fake_cpu = &fake_cpus[i];
			write_trace_entries(i);
		}
	}

	while (!all_done(done)) {
		union trace t;

		for (i = 0; i < CPUS; i++) {
			if (trace_get(&t, &trace_readers[(i+last) % CPUS]))
				break;
		}

		if (i == CPUS) {
			sched_yield();
			continue;
		}
		i = (i + last) % CPUS;
		last = i;

		if (t.hdr.type == TRACE_OVERFLOW) {
			/* Conveniently, each record is 16 bytes here. */
			assert(be64_to_cpu(t.overflow.bytes_missed) % 16 == 0);
			overflows[i] += be64_to_cpu(t.overflow.bytes_missed) / 16;
			num_overflows[i]++;
			continue;
		}

		assert(be16_to_cpu(t.hdr.cpu) < CPUS);
		assert(!done[be16_to_cpu(t.hdr.cpu)]);
		assert(be64_to_cpu(t.hdr.timestamp) % CPUS == be16_to_cpu(t.hdr.cpu));
		if (t.hdr.type == TRACE_REPEAT) {
			assert(t.hdr.len_div_8 * 8 == sizeof(t.repeat));
			assert(be16_to_cpu(t.repeat.num) != 0);
			assert(be16_to_cpu(t.repeat.num) <= be16_to_cpu(t.hdr.cpu));
			repeats[be16_to_cpu(t.hdr.cpu)] += be16_to_cpu(t.repeat.num);
		} else if (t.hdr.type == 0x70) {
			cpu = be16_to_cpu(t.hdr.cpu);
			assert(cpu < CPUS);
			done[cpu] = true;
		} else {
			cpu = be16_to_cpu(t.hdr.cpu);
			assert(cpu < CPUS);
			counts[cpu]++;
		}
	}

	/* Gather children. */
	for (i = 0; i < CPUS; i++) {
		int status;
		wait(&status);
	}

	for (i = 0; i < CPUS; i++) {
		printf("Child %i: %u produced, %u overflows, %llu total\n", i,
		       counts[i], overflows[i],
		       (long long)be64_to_cpu(fake_cpus[i].trace->tb.end));
		assert(counts[i] + repeats[i] <= PER_CHILD_TRACES);
	}
	/* Child 0 never repeats. */
	assert(repeats[0] == 0);
	assert(counts[0] + overflows[0] == PER_CHILD_TRACES);

	/*
	 * FIXME: Other children have some fuzz, since overflows may
	 * include repeat record we already read.  And odd-numbered
	 * overflows may include more repeat records than normal
	 * records (they alternate).
	 */
}

int main(void)
{
	union trace minimal;
	union trace large;
	union trace trace;
	unsigned int i, j;

	opal_node = dt_new_root("opal");
	dt_new(dt_new(opal_node, "firmware"), "exports");
	for (i = 0; i < CPUS; i++) {
		fake_cpus[i].server_no = i;
		fake_cpus[i].pir = i;
		fake_cpus[i].is_secondary = (i & 0x1);
		fake_cpus[i].primary = &fake_cpus[i & ~0x1];
	}
	my_fake_cpu = &fake_cpus[0];
	my_trace_reader = &trace_readers[0];
	init_trace_buffers();

	for (i = 0; i < CPUS; i++) {
		trace_readers[i].tb = &fake_cpus[i].trace->tb;
		assert(trace_empty(&trace_readers[i]));
		assert(!trace_get(&trace, &trace_readers[i]));
	}

	assert(sizeof(trace.hdr) % 8 == 0);
	timestamp = 1;
	trace_add(&minimal, 100, sizeof(trace.hdr));
	assert(trace_get(&trace, my_trace_reader));
	assert(trace.hdr.len_div_8 == minimal.hdr.len_div_8);
	assert(be64_to_cpu(trace.hdr.timestamp) == timestamp);

	/* Make it wrap once. */
	for (i = 0; i < TBUF_SZ / (minimal.hdr.len_div_8 * 8) + 1; i++) {
		timestamp = i;
		trace_add(&minimal, 99 + (i%2), sizeof(trace.hdr));
	}

	assert(trace_get(&trace, my_trace_reader));
	/* First one must be overflow marker. */
	assert(trace.hdr.type == TRACE_OVERFLOW);
	assert(trace.hdr.len_div_8 * 8 == sizeof(trace.overflow));
	assert(be64_to_cpu(trace.overflow.bytes_missed) == minimal.hdr.len_div_8 * 8);

	for (i = 0; i < TBUF_SZ / (minimal.hdr.len_div_8 * 8); i++) {
		assert(trace_get(&trace, my_trace_reader));
		assert(trace.hdr.len_div_8 == minimal.hdr.len_div_8);
		assert(be64_to_cpu(trace.hdr.timestamp) == i+1);
		assert(trace.hdr.type == 99 + ((i+1)%2));
	}
	assert(!trace_get(&trace, my_trace_reader));

	/* Now put in some weird-length ones, to test overlap.
	 * Last power of 2, minus 8. */
	for (j = 0; (1 << j) < sizeof(large); j++);
	for (i = 0; i < TBUF_SZ; i++) {
		timestamp = i;
		trace_add(&large, 100 + (i%2), (1 << (j-1)));
	}
	assert(trace_get(&trace, my_trace_reader));
	assert(trace.hdr.type == TRACE_OVERFLOW);
	assert(trace_get(&trace, my_trace_reader));
	assert(trace.hdr.len_div_8 == large.hdr.len_div_8);
	i = be64_to_cpu(trace.hdr.timestamp);
	while (trace_get(&trace, my_trace_reader))
		assert(be64_to_cpu(trace.hdr.timestamp) == ++i);

	/* Test repeats. */
	for (i = 0; i < 65538; i++) {
		timestamp = i;
		trace_add(&minimal, 100, sizeof(trace.hdr));
	}
	timestamp = i;
	trace_add(&minimal, 101, sizeof(trace.hdr));
	timestamp = i+1;
	trace_add(&minimal, 101, sizeof(trace.hdr));

	assert(trace_get(&trace, my_trace_reader));
	assert(trace.hdr.timestamp == 0);
	assert(trace.hdr.len_div_8 == minimal.hdr.len_div_8);
	assert(trace.hdr.type == 100);
	assert(trace_get(&trace, my_trace_reader));
	assert(trace.hdr.type == TRACE_REPEAT);
	assert(trace.hdr.len_div_8 * 8 == sizeof(trace.repeat));
	assert(be16_to_cpu(trace.repeat.num) == 65535);
	assert(be64_to_cpu(trace.repeat.timestamp) == 65535);
	assert(trace_get(&trace, my_trace_reader));
	assert(be64_to_cpu(trace.hdr.timestamp) == 65536);
	assert(trace.hdr.len_div_8 == minimal.hdr.len_div_8);
	assert(trace.hdr.type == 100);
	assert(trace_get(&trace, my_trace_reader));
	assert(trace.hdr.type == TRACE_REPEAT);
	assert(trace.hdr.len_div_8 * 8 == sizeof(trace.repeat));
	assert(be16_to_cpu(trace.repeat.num) == 1);
	assert(be64_to_cpu(trace.repeat.timestamp) == 65537);

	assert(trace_get(&trace, my_trace_reader));
	assert(be64_to_cpu(trace.hdr.timestamp) == 65538);
	assert(trace.hdr.len_div_8 == minimal.hdr.len_div_8);
	assert(trace.hdr.type == 101);
	assert(trace_get(&trace, my_trace_reader));
	assert(trace.hdr.type == TRACE_REPEAT);
	assert(trace.hdr.len_div_8 * 8 == sizeof(trace.repeat));
	assert(be16_to_cpu(trace.repeat.num) == 1);
	assert(be64_to_cpu(trace.repeat.timestamp) == 65539);

	/* Now, test adding repeat while we're reading... */
	timestamp = 0;
	trace_add(&minimal, 100, sizeof(trace.hdr));
	assert(trace_get(&trace, my_trace_reader));
	assert(be64_to_cpu(trace.hdr.timestamp) == 0);
	assert(trace.hdr.len_div_8 == minimal.hdr.len_div_8);
	assert(trace.hdr.type == 100);

	for (i = 1; i < TBUF_SZ; i++) {
		timestamp = i;
		trace_add(&minimal, 100, sizeof(trace.hdr));
		assert(trace_get(&trace, my_trace_reader));
		if (i % 65536 == 0) {
			assert(trace.hdr.type == 100);
			assert(trace.hdr.len_div_8 == minimal.hdr.len_div_8);
		} else {
			assert(trace.hdr.type == TRACE_REPEAT);
			assert(trace.hdr.len_div_8 * 8 == sizeof(trace.repeat));
			assert(be16_to_cpu(trace.repeat.num) == 1);
		}
		assert(be64_to_cpu(trace.repeat.timestamp) == i);
		assert(!trace_get(&trace, my_trace_reader));
	}

	for (i = 0; i < CPUS; i++)
		if (!fake_cpus[i].is_secondary)
			free(fake_cpus[i].trace);

	test_parallel();

	return 0;
}
