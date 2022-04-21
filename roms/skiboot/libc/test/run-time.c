// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2014-2015 IBM Corp.
 */
#include "/usr/include/assert.h"
#include <stdio.h>
#include <libc/include/time.h>
#include <stdint.h>

#include "../time.c"

#define MKTIME_TEST(Y,M,D,h,m,s,t) \
	tm.tm_year = Y; \
	tm.tm_mon = M; \
	tm.tm_mday = D; \
	tm.tm_hour = h; \
	tm.tm_min = m; \
	tm.tm_sec = s; \
	assert(mktime(&tm) == t); \
	assert(tm.tm_year == Y); \
	assert(tm.tm_mon == M); \
	assert(tm.tm_mday == D); \
	assert(tm.tm_hour == h); \
	assert(tm.tm_min == m); \
	assert(tm.tm_sec == s)

#define GMTIME_TEST(Y,M,D,h,m,s,tv) \
	t = tv; \
	gmtime_r(&t, &tm); \
	assert(tm.tm_year == Y); \
	assert(tm.tm_mon == M); \
	assert(tm.tm_mday == D); \
	assert(tm.tm_hour == h); \
	assert(tm.tm_min == m); \
	assert(tm.tm_sec == s)

#define TIME_TEST(Y,M,D,h,m,s,tv) \
	MKTIME_TEST(Y,M,D,h,m,s,tv);		\
	GMTIME_TEST(Y,M,D,h,m,s,tv)

int main(void)
{
	struct tm tm;
	time_t t = 0;

	TIME_TEST(1970, 0, 1, 0, 0, 0, 0);
	TIME_TEST(1971, 0, 1, 0, 0, 0, 365*SECS_PER_DAY);
	TIME_TEST(1972, 0, 1, 0, 0, 0, 2*365*SECS_PER_DAY);
	TIME_TEST(1972, 11, 31, 0, 0, 0, 3*365*SECS_PER_DAY);
	TIME_TEST(1973, 0, 1, 0, 0, 0, (3*365+1)*SECS_PER_DAY);
	TIME_TEST(2000, 11, 31, 0, 0, 0, 978220800);
	TIME_TEST(2001, 0, 1, 0, 0, 0, 978307200);
	TIME_TEST(2003, 11, 31, 0, 0, 0, 1072828800);
	TIME_TEST(2004, 0, 1, 0, 0, 0, 1072828800+SECS_PER_DAY);
	TIME_TEST(2004, 11, 29, 0, 0, 0, 1072828800+364*SECS_PER_DAY);
	TIME_TEST(2004, 11, 30, 0, 0, 0, 1072828800+365*SECS_PER_DAY);
	TIME_TEST(2004, 11, 31, 0, 0, 0, 1072828800+366*SECS_PER_DAY);
	TIME_TEST(2004, 11, 31, 23, 59, 59, 1072828800+367*SECS_PER_DAY-1);
	TIME_TEST(2100, 11, 31, 0, 0, 0, 4133894400);
	TIME_TEST(2101, 0, 1, 0, 0, 0, 4133980800);

	/* Test the normalisation functionality of mktime */
	tm.tm_year = 2000;
	tm.tm_mon = 1;
	tm.tm_mday = 10;
	tm.tm_hour = 5;
	tm.tm_min = 32;
	tm.tm_sec = 105;
	mktime(&tm);
	assert(tm.tm_year == 2000);
	assert(tm.tm_mon == 1);
	assert(tm.tm_mday == 10);
	assert(tm.tm_hour == 5);
	assert(tm.tm_min == 33);
	assert(tm.tm_sec == 45);
	tm.tm_sec += 366*24*60*60;
	mktime(&tm);
	assert(tm.tm_year == 2001);
	assert(tm.tm_mon == 1);
	assert(tm.tm_mday == 10);
	assert(tm.tm_hour == 5);
	assert(tm.tm_min == 33);
	assert(tm.tm_sec == 45);

	return 0;
}
