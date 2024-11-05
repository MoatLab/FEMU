// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Converts an OPAL formatted datetime into a struct tm. We ignore microseconds
 * as Linux doesn't use them anyway.
 *
 *  |      year       | month |   mday   |
 *  +------------------------------------+
 *  |  hour  | minute | secs  | reserved |
 *  +------------------------------------+
 *  |             microseconds           |
 *
 * Copyright 2013-2014 IBM Corp.
 */

#include <time-utils.h>

void datetime_to_tm(uint32_t y_m_d, uint64_t h_m_s_m, struct tm *tm)
{
	uint32_t x;

	tm->tm_year = bcd_byte(y_m_d, 3) * 100 + bcd_byte(y_m_d, 2);
	tm->tm_mon = bcd_byte(y_m_d, 1) - 1;
	tm->tm_mday = bcd_byte(y_m_d, 0);

	x = h_m_s_m >> 32;
	tm->tm_hour = bcd_byte(x, 3);
	tm->tm_min = bcd_byte(x, 2);
	tm->tm_sec = bcd_byte(x, 1);
}

/*
 * The OPAL API is defined as returned a u64 of a similar
 * format to the FSP message; the 32-bit date field is
 * in the format:
 *
 * |      year        | month |   mday   |
 *
 * ... and the 64-bit time field is in the format
 *
 * |  hour  | minutes | secs  | millisec |
 * | -------------------------------------
 * |        millisec          | reserved |
 *
 * We simply ignore the microseconds/milliseconds for now
 * as I don't quite understand why the OPAL API defines that
 * it needs 6 digits for the milliseconds :-) I suspect the
 * doc got that wrong and it's supposed to be micro but
 * let's ignore it.
 *
 * Note that Linux doesn't use nor set the ms field anyway.
 */
void tm_to_datetime(struct tm *tm, uint32_t *y_m_d, uint64_t *h_m_s_m)
{
	uint64_t h_m_s;
	*y_m_d = int_to_bcd4(tm->tm_year) << 16 |
		 int_to_bcd2(tm->tm_mon + 1) << 8 |
		 int_to_bcd2(tm->tm_mday);

	h_m_s = int_to_bcd2(tm->tm_hour) << 24 |
	        int_to_bcd2(tm->tm_min) << 16 |
	        int_to_bcd2(tm->tm_sec) << 8;

	*h_m_s_m = h_m_s << 32;
}
