// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <malloc.h>
#include <stdint.h>

#include <compiler.h>

#include "../../ccan/list/list.c"

void _prlog(int log_level __attribute__((unused)), const char* fmt, ...) __attribute__((format (printf, 2, 3)));

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif
#define prlog(l, f, ...) do { _prlog(l, pr_fmt(f), ##__VA_ARGS__); } while(0)

void _prlog(int log_level __attribute__((unused)), const char* fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (log_level <= 7)
		vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/*
 * Skiboot malloc stubs
 *
 * The actual prototypes for these are defined in mem_region-malloc.h,
 * but that file also #defines malloc, and friends so we don't pull that in
 * directly.
 */

#define DEFAULT_ALIGN __alignof__(long)

void *__memalign(size_t blocksize, size_t bytes, const char *location __unused);
void *__memalign(size_t blocksize, size_t bytes, const char *location __unused)
{
	return memalign(blocksize, bytes);
}

void *__malloc(size_t bytes, const char *location);
void *__malloc(size_t bytes, const char *location)
{
	return __memalign(DEFAULT_ALIGN, bytes, location);
}

void __free(void *p, const char *location __unused);
void __free(void *p, const char *location __unused)
{
	free(p);
}

void *__realloc(void *ptr, size_t size, const char *location __unused);
void *__realloc(void *ptr, size_t size, const char *location __unused)
{
	return realloc(ptr, size);
}

void *__zalloc(size_t bytes, const char *location);
void *__zalloc(size_t bytes, const char *location)
{
	void *p = __malloc(bytes, location);

	if (p)
		memset(p, 0, bytes);
	return p;
}

struct cpu_thread;

struct cpu_job *__cpu_queue_job(struct cpu_thread *cpu,
				const char *name,
				void (*func)(void *data), void *data,
				bool no_return);

struct cpu_job *cpu_queue_job_on_node(uint32_t chip_id,
				      const char *name,
				      void (*func)(void *data), void *data);

struct cpu_job *cpu_queue_job_on_node(uint32_t chip_id,
				       const char *name,
				       void (*func)(void *data), void *data)
{
	(void)chip_id;
	return __cpu_queue_job(NULL, name, func, data, false);
}

struct cpu_job *__cpu_queue_job(struct cpu_thread *cpu,
				const char *name,
				void (*func)(void *data), void *data,
				bool no_return)
{
	(void)cpu;
	(void)name;
	(func)(data);
	(void)no_return;
	return NULL;
}

void cpu_wait_job(struct cpu_job *job, bool free_it);
void cpu_wait_job(struct cpu_job *job, bool free_it)
{
	(void)job;
	(void)free_it;
	return;
}

void cpu_process_local_jobs(void);
void cpu_process_local_jobs(void)
{
}

/* Add any stub functions required for linking here. */
static void stub_function(void)
{
	abort();
}

#define STUB(fnname) \
	void fnname(void) __attribute__((weak, alias ("stub_function")))

STUB(fsp_preload_lid);
STUB(fsp_wait_lid_loaded);
STUB(fsp_adjust_lid_side);

/* Add HW specific stubs here */
static bool true_stub(void) { return true; }
static bool false_stub(void) { return false; }

#define TRUE_STUB(fnname) \
	bool fnname(void) __attribute__((weak, alias ("true_stub")))
#define FALSE_STUB(fnname) \
	bool fnname(void) __attribute__((weak, alias ("false_stub")))
#define NOOP_STUB FALSE_STUB

TRUE_STUB(lock_held_by_me);
NOOP_STUB(lock_caller);
NOOP_STUB(unlock);
NOOP_STUB(early_uart_init);
NOOP_STUB(mem_reserve_fw);
NOOP_STUB(mem_reserve_hwbuf);
NOOP_STUB(add_chip_dev_associativity);
NOOP_STUB(enable_mambo_console);
NOOP_STUB(backtrace);

