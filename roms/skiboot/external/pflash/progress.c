// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * The most important part of pflash, the progress bars
 *
 * Copyright 2014-2017 IBM Corp.
 */

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "progress.h"

static uint64_t progress_max;
static uint64_t progress_pcent;
static uint64_t progress_n_upd;
static time_t progress_prevsec;
static struct timespec progress_start;

#define PROGRESS_CHARS	50

void progress_init(uint64_t count)
{
	unsigned int i;

	progress_max = count;
	progress_pcent = 0;
	progress_n_upd = ULONG_MAX;
	progress_prevsec = ULONG_MAX;

	printf("\r[");
	for (i = 0; i < PROGRESS_CHARS; i++)
		printf(" ");
	printf("] 0%%");
	fflush(stdout);
	clock_gettime(CLOCK_MONOTONIC, &progress_start);}

void progress_tick(uint64_t cur)
{
	unsigned int i, pos;
	struct timespec now;
	uint64_t pcent;
	double sec;

	pcent = (cur * 100) / progress_max;
	if (progress_pcent == pcent && cur < progress_n_upd &&
	    cur < progress_max)
		return;
	progress_pcent = pcent;
	pos = (pcent * PROGRESS_CHARS) / 101;
	clock_gettime(CLOCK_MONOTONIC, &now);

	printf("\r[");
	for (i = 0; i <= pos; i++)
		printf("=");
	for (; i < PROGRESS_CHARS; i++)
		printf(" ");
	printf("] %" PRIu64 "%%", pcent);

	sec = difftime(now.tv_sec, progress_start.tv_sec);
	if (sec >= 5 && pcent > 0) {
		uint64_t persec = cur / sec;
		uint64_t rem_sec;

		if (!persec)
			persec = 1;
		progress_n_upd = cur + persec;
		rem_sec = ((sec * 100) + (pcent / 2)) / pcent - sec;
		if (rem_sec > progress_prevsec)
			rem_sec = progress_prevsec;
		progress_prevsec = rem_sec;
		if (rem_sec < 60)
			printf(" ETA:%" PRIu64 "s     ", rem_sec);
		else {
			printf(" ETA:%" PRIu64 ":%02" PRIu64 ":%02" PRIu64 " ",
				rem_sec / 3600,
				(rem_sec / 60) % 60,
				rem_sec % 60);
		}
	}

	fflush(stdout);
}

void progress_end(void)
{
	printf("\n");
}
