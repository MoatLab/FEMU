// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2014-2016 IBM Corp.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#define __TEST__

#define _printf printf

unsigned long tb_hz = 512000000;

static inline unsigned long mftb(void)
{
	return 42;
}

int _printf(const char* fmt, ...);

#include "../console-log.c"

struct debug_descriptor debug_descriptor;

bool flushed_to_drivers;
char console_buffer[4096];

ssize_t console_write(bool flush_to_drivers, const void *buf, size_t count)
{
	flushed_to_drivers = flush_to_drivers;
	memcpy(console_buffer, buf, count);
	return count;
}

int main(void)
{
	debug_descriptor.console_log_levels = 0x75;

	prlog(PR_EMERG, "Hello World");
	assert(strcmp(console_buffer, "[    0.000000042,0] Hello World") == 0);
	assert(flushed_to_drivers==true);

	memset(console_buffer, 0, sizeof(console_buffer));

	// Below log level
	prlog(PR_TRACE, "Hello World");
	assert(console_buffer[0] == 0);

	// Should not be flushed to console
	prlog(PR_DEBUG, "Hello World");
	assert(strcmp(console_buffer, "[    0.000000042,7] Hello World") == 0);
	assert(flushed_to_drivers==false);

	printf("Hello World");
	assert(strcmp(console_buffer, "[    0.000000042,5] Hello World") == 0);
	assert(flushed_to_drivers==true);

	return 0;
}
