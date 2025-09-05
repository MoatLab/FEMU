/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <stdarg.h>

#include "libmctp.h"
#include "libmctp-log.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef MCTP_HAVE_STDIO
#include <stdio.h>
#endif

#ifdef MCTP_HAVE_SYSLOG
#include <syslog.h>
#endif

enum {
	MCTP_LOG_NONE,
	MCTP_LOG_STDIO,
	MCTP_LOG_SYSLOG,
	MCTP_LOG_CUSTOM,
} log_type = MCTP_LOG_NONE;

static int log_stdio_level;
static void (*log_custom_fn)(int, const char *, va_list);

void mctp_prlog(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	switch (log_type) {
	case MCTP_LOG_NONE:
		break;
	case MCTP_LOG_STDIO:
#ifdef MCTP_HAVE_STDIO
		if (level <= log_stdio_level) {
			vfprintf(stderr, fmt, ap);
			fputs("\n", stderr);
		}
#endif
		break;
	case MCTP_LOG_SYSLOG:
#ifdef MCTP_HAVE_SYSLOG
		vsyslog(level, fmt, ap);
#endif
		break;
	case MCTP_LOG_CUSTOM:
		log_custom_fn(level, fmt, ap);
		break;
	}

	va_end(ap);
}

void mctp_set_log_stdio(int level)
{
	log_type = MCTP_LOG_STDIO;
	log_stdio_level = level;
}

void mctp_set_log_syslog(void)
{
	log_type = MCTP_LOG_SYSLOG;
}

void mctp_set_log_custom(void (*fn)(int, const char *, va_list))
{
	log_type = MCTP_LOG_CUSTOM;
	log_custom_fn = fn;
}
