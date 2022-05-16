// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2015-2017 IBM Corp.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

#define __TEST__

#include "../time-utils.c"

int main(void)
{
	struct tm *t = malloc(sizeof(struct tm));
	uint32_t *ymd = malloc(sizeof(uint32_t));
	uint64_t *hms = malloc(sizeof(uint64_t));

	t->tm_year = 1982;
	t->tm_mon = 0;
	t->tm_mday = 29;
	t->tm_hour = 7;
	t->tm_min = 42;
	t->tm_sec = 24;

	tm_to_datetime(t, ymd, hms);

	assert(*ymd == 0x19820129);
	assert(*hms == 0x742240000000000ULL);

	memset(t, 0, sizeof(struct tm));

	*ymd = 0x19760412;

	datetime_to_tm(*ymd, *hms, t);
	assert(t->tm_year == 1976);
	assert(t->tm_mon == 03);
	assert(t->tm_mday == 12);
	assert(t->tm_hour == 7);
	assert(t->tm_min == 42);
	assert(t->tm_sec == 24);

	free(t);
	free(ymd);
	free(hms);
	return 0;
}

