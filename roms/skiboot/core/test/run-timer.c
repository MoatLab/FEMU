// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2014-2018 IBM Corp
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define __TEST__
#include <timer.h>
#include <skiboot.h>

#define mftb()	(stamp)
#define sync()
#define smt_lowest()
#define smt_medium()

enum proc_gen proc_gen = proc_gen_unknown;

static uint64_t stamp, last;
struct lock;
static inline void lock_caller(struct lock *l, const char *caller)
{
	(void)caller;
	(void)l;
}
static inline void unlock(struct lock *l) { (void)l; }

unsigned long tb_hz = 512000000;

#include "../timer.c"

#define NUM_TIMERS	100

static struct timer timers[NUM_TIMERS];
static unsigned int rand_shift, count;

static void init_rand(void)
{
	unsigned long max = RAND_MAX;

	/* Get something reasonably small */
	while(max > 0x10000) {
		rand_shift++;
		max >>= 1;
	}
}

static void expiry(struct timer *t, void *data, uint64_t now)
{
	(void)data;
	(void)now;
	assert(t->target >= last);
	count--;
}

void p8_sbe_update_timer_expiry(uint64_t new_target)
{
	(void)new_target;
	/* FIXME: do intersting SLW timer sim */
}

void p9_sbe_update_timer_expiry(uint64_t new_target)
{
	(void)new_target;
}

int main(void)
{
	unsigned int i;

	init_rand();
	for (i = 0; i < NUM_TIMERS; i++) {
		init_timer(&timers[i], expiry, NULL);
		schedule_timer(&timers[i], random() >> rand_shift);
	}
	count = NUM_TIMERS;
	while(count) {
		check_timers(false);
		stamp++;
	}
	return 0;
}
