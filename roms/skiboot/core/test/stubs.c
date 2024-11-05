// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2019 IBM Corp
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
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
        vprintf(fmt, ap);
        va_end(ap);
}

/* Add any stub functions required for linking here. */
static void stub_function(void)
{
	abort();
}

struct cpu_thread;

struct cpu_job *__cpu_queue_job(struct cpu_thread *cpu,
				const char *name,
				void (*func)(void *data), void *data,
				bool no_return);

void cpu_wait_job(struct cpu_job *job, bool free_it);
void cpu_process_local_jobs(void);
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

void cpu_wait_job(struct cpu_job *job, bool free_it)
{
	(void)job;
	(void)free_it;
	return;
}

void cpu_process_local_jobs(void)
{
}

#define STUB(fnname) \
	void fnname(void) __attribute__((weak, alias ("stub_function")))

STUB(fdt_begin_node);
STUB(fdt_property);
STUB(fdt_end_node);
STUB(fdt_create_with_flags);
STUB(fdt_add_reservemap_entry);
STUB(fdt_finish_reservemap);
STUB(fdt_strerror);
STUB(fdt_check_header);
STUB(fdt_check_node_offset_);
STUB(fdt_next_tag);
STUB(fdt_string);
STUB(fdt_get_name);
STUB(dt_first);
STUB(dt_next);
STUB(dt_has_node_property);
STUB(dt_get_address);
STUB(add_chip_dev_associativity);
STUB(pci_check_clear_freeze);
