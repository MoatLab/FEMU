// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Console Log routines
 * Wraps libc and console lower level functions
 * does fancy-schmancy things like timestamps and priorities
 * Doesn't make waffles.
 *
 * Copyright 2013-2018 IBM Corp.
 */

#include "skiboot.h"
#include "unistd.h"
#include "stdio.h"
#include "console.h"
#include "timebase.h"
#include <debug_descriptor.h>

static int vprlog(int log_level, const char *fmt, va_list ap)
{
	int count;
	char buffer[320];
	bool flush_to_drivers = true;
	unsigned long tb = mftb();

	/* It's safe to return 0 when we "did" something here
	 * as only printf cares about how much we wrote, and
	 * if you change log_level to below PR_PRINTF then you
	 * get everything you deserve.
	 * By default, only PR_DEBUG and higher are stored in memory.
	 * PR_TRACE and PR_INSANE are for those having a bad day.
	 */
	if (log_level > (debug_descriptor.console_log_levels >> 4))
		return 0;

	count = snprintf(buffer, sizeof(buffer), "[%5lu.%09lu,%d] ",
			 tb_to_secs(tb), tb_remaining_nsecs(tb), log_level);
	count+= vsnprintf(buffer+count, sizeof(buffer)-count, fmt, ap);

	if (log_level > (debug_descriptor.console_log_levels & 0x0f))
		flush_to_drivers = false;

	console_write(flush_to_drivers, buffer, count);

	return count;
}

/* we don't return anything as what on earth are we going to do
 * if we actually fail to print a log message? Print a log message about it?
 * Callers shouldn't care, prlog and friends should do something generically
 * sane in such crazy situations.
 */
void _prlog(int log_level, const char* fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprlog(log_level, fmt, ap);
	va_end(ap);
}

int _printf(const char* fmt, ...)
{
	int count;
	va_list ap;

	va_start(ap, fmt);
	count = vprlog(PR_PRINTF, fmt, ap);
	va_end(ap);

	return count;
}
