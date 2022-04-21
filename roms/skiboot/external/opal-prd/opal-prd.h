// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2015 IBM Corp. */

#ifndef OPAL_PRD_H
#define OPAL_PRD_H

#include <syslog.h>

#define pr_debug(fmt, ...) pr_log(LOG_DEBUG, fmt, ## __VA_ARGS__)

void pr_log(int priority, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

#endif /* OPAL_PRD_H */

