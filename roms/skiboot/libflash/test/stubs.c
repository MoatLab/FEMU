// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Stubs for libflash test
 *
 * Copyright 2013-2018 IBM Corp.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <sys/unistd.h> /* for usleep */

#include "../../include/lpc-mbox.h"
#include "stubs.h"

#define __unused          __attribute__((unused))

__attribute__((weak)) void check_timers(bool __unused unused)
{
	return;
}

void time_wait_ms(unsigned long ms)
{
	usleep(ms * 1000);
}

/* skiboot stubs */
unsigned long mftb(void)
{
	return 42;
}
unsigned long tb_hz = 512000000ul;

void _prlog(int __unused log_level, const char* fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

/* accessor junk */

void bmc_put_u16(struct bmc_mbox_msg *msg, int offset, uint16_t data)
{
	msg->args[offset + 0] = data & 0xff;
	msg->args[offset + 1] = data >> 8;
}

void bmc_put_u32(struct bmc_mbox_msg *msg, int offset, uint32_t data)
{
	msg->args[offset + 0] = (data)       & 0xff;
	msg->args[offset + 1] = (data >>  8) & 0xff;
	msg->args[offset + 2] = (data >> 16) & 0xff;
	msg->args[offset + 3] = (data >> 24) & 0xff;
}

u32 bmc_get_u32(struct bmc_mbox_msg *msg, int offset)
{
	u32 data = 0;

	data |= msg->args[offset + 0];
	data |= msg->args[offset + 1] << 8;
	data |= msg->args[offset + 2] << 16;
	data |= msg->args[offset + 3] << 24;

	return data;
}

u16 bmc_get_u16(struct bmc_mbox_msg *msg, int offset)
{
	u16 data = 0;

	data |= msg->args[offset + 0];
	data |= msg->args[offset + 1] << 8;

	return data;
}

void *__zalloc(size_t sz)
{
	return calloc(1, sz);
}

void __free(const void *p)
{
	free((void *)p);
}

void lock_caller(struct lock *l __attribute__((unused)),
		 const char *caller __attribute__((unused)))
{
}

void unlock(struct lock *l __attribute__((unused)))
{
}
