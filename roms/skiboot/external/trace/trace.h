// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2019 IBM Corp.
 */
#ifndef E_TRACE_H
#define E_TRACE_H

#include <stdbool.h>
#include <types.h>
#include <trace.h>
#include <trace_types.h>

struct trace_reader {
	/* This is where the reader is up to. */
	u64 rpos;
	/* If the last one we read was a repeat, this shows how many. */
	u32 last_repeat;
	struct list_head traces;
	struct tracebuf *tb;
};

/* Is this tracebuf empty? */
bool trace_empty(const struct trace_reader *tr);

/* Get the next trace from this buffer (false if empty). */
bool trace_get(union trace *t, struct trace_reader *tr);

#endif
