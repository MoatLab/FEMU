// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Timebase helpers.
 *
 * Note: Only use after the TODs are in sync !
 *
 * Copyright 2013-2016 IBM Corp.
 */

#ifndef __TIME_H
#define __TIME_H

#include <time.h>

#ifndef __TEST__
static inline unsigned long mftb(void)
{
	unsigned long tb;

	/* We use a memory clobber to avoid this being
	 * moved in the instruction stream
	 */
	asm volatile("mftb %0" : "=r"(tb) : : "memory");
	return tb;
}
#endif

enum tb_cmpval {
	TB_ABEFOREB = -1,
	TB_AEQUALB  = 0,
	TB_AAFTERB  = 1
};

static inline enum tb_cmpval tb_compare(unsigned long a,
					unsigned long b)
{
	if (a == b)
		return TB_AEQUALB;
	return ((long)(b - a)) > 0 ? TB_ABEFOREB : TB_AAFTERB;
}

/* Architected timebase */
extern unsigned long tb_hz;

static inline unsigned long secs_to_tb(unsigned long secs)
{
	return secs * tb_hz;
}

static inline unsigned long tb_to_secs(unsigned long tb)
{
	return tb / tb_hz;
}

static inline unsigned long tb_remaining_nsecs(unsigned long tb)
{
	return tb % tb_hz;
}

static inline unsigned long msecs_to_tb(unsigned long msecs)
{
	return msecs * (tb_hz / 1000);
}

static inline unsigned long tb_to_msecs(unsigned long tb)
{
	return (tb * 1000) / tb_hz;
}

static inline unsigned long usecs_to_tb(unsigned long usecs)
{
	return usecs * (tb_hz / 1000000);
}

static inline unsigned long tb_to_usecs(unsigned long tb)
{
	return (tb * 1000000) / tb_hz;
}

extern unsigned long timespec_to_tb(const struct timespec *ts);

/* time_wait - Wait a certain number of TB ticks while polling FSP */
extern void time_wait(unsigned long duration);
extern void time_wait_nopoll(unsigned long duration);

/* time_wait_ms - Wait a certain number of milliseconds while polling FSP */
extern void time_wait_ms(unsigned long ms);
extern void time_wait_ms_nopoll(unsigned long ms);

/* time_wait_us - Wait a certain number of microseconds while polling FSP */
extern void time_wait_us(unsigned long us);
extern void time_wait_us_nopoll(unsigned long us);

/* nanosleep_nopoll - variant for use from hostservices */
extern int nanosleep_nopoll(const struct timespec *req, struct timespec *rem);
#endif /* __TIME_H */
