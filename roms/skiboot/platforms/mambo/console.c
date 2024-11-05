// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2016-2017 IBM Corp. */

#include <skiboot.h>
#include <console.h>

#include "mambo.h"

/*
 * The SIM_READ_CONSOLE callout will return -1 if there is no character to read.
 * There's no explicit poll callout so we "poll" by doing a read and stashing
 * the result until we do an actual read.
 */
static int mambo_char = -1;

static bool mambo_console_poll(void)
{
	if (mambo_char < 0)
		mambo_char = callthru0(SIM_READ_CONSOLE_CODE);

	return mambo_char >= 0;
}

static size_t mambo_console_read(char *buf, size_t len)
{
	size_t count = 0;

	while (count < len) {
		if (!mambo_console_poll())
			break;

		buf[count++] = mambo_char;
		mambo_char = -1;
	}

	return count;
}

size_t mambo_console_write(const char *buf, size_t len)
{
	callthru2(SIM_WRITE_CONSOLE_CODE, (unsigned long)buf, len);
	return len;
}

static struct con_ops mambo_con_driver = {
	.poll_read = mambo_console_poll,
	.read = mambo_console_read,
	.write = mambo_console_write,
};

void enable_mambo_console(void)
{
	prlog(PR_NOTICE, "Enabling Mambo console\n");
	set_console(&mambo_con_driver);
}

/*
 * mambo console based printf(), this is useful for debugging the console
 * since mambo_console_write() can be safely called from anywhere.
 *
 * This is a debug hack and you shouldn't use it in real code.
 */
void mprintf(const char *fmt, ...)
{
	char buf[320];
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	mambo_console_write(buf, i);
}
