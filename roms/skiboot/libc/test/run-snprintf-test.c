// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2015 IBM Corp.
 *
 * This file is run with the skiboot libc files rather than system libc.
 * This means we have a bit of "fun" with actually executing the tests on
 * the host.
 * Patches to make this less ugly are very welcome.
 */

#include <config.h>
#include <stdarg.h>

#include "../stdio/snprintf.c"
#include "../stdio/vsnprintf.c"

int test1(void);

int test1(void)
{
	return snprintf(NULL, 1, "Hello");
}

int skiboot_snprintf(char *buf, size_t bufsz, size_t l, const char* format, ...);

int skiboot_snprintf(char *buf, size_t bufsz, size_t l, const char* format, ...)
{
	va_list ar;
	int count;

	if (buf)
		memset(buf, 0, bufsz);

	if ((buf==NULL) || (format==NULL))
		return(-1);

	va_start(ar, format);
	count = vsnprintf(buf, l, format, ar);
	va_end(ar);

	return(count);
}
