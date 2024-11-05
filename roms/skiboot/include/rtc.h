// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2014 IBM Corp. */

#ifndef __RTC_H
#define __RTC_H

#include <time-utils.h>

/*
 * Update the cache to the current time as specified by tm.
 */
void rtc_cache_update(struct tm *tm);

/*
 * Get the current time based on the cache. If the cache is valid the result
 * is returned in tm and the function returns 0. Otherwise returns -1.
 */
int rtc_cache_get(struct tm *tm);

/*
 * Same as the previous function except the result is returned as an OPAL
 * datetime.
 */
int rtc_cache_get_datetime(uint32_t *year_month_day,
			   uint64_t *hour_minute_second_millisecond);

#endif
