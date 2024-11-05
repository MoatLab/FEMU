// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __TRACE_H
#define __TRACE_H
#include <ccan/short_types/short_types.h>
#include <stddef.h>
#include <lock.h>
#include <trace_types.h>


struct cpu_thread;

/* Here's one we prepared earlier. */
void init_boot_tracebuf(struct cpu_thread *boot_cpu);

struct trace_info {
	/* Lock for writers. Exposed to kernel. */
	struct lock lock;
	/* Exposed to kernel. */
	struct tracebuf tb;
};

#define TBUF_SZ ((1024 * 1024) - sizeof(struct trace_info) - sizeof(union trace))

/* Allocate trace buffers once we know memory topology */
void init_trace_buffers(void);
void trace_add_dt_props(void);

/* This will fill in timestamp and cpu; you must do type and len. */
void trace_add(union trace *trace, u8 type, u16 len);

/* Put trace node into dt. */
void trace_add_node(void);
#endif /* __TRACE_H */
