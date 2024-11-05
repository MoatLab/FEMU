// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2015 IBM Corp. */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <linux/limits.h>

#include <libflash/libffs.h>
#include <pnor.h>

extern void dump_parts(struct ffs_handle *ffs);

void pr_log(int priority, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

int main(int argc, char **argv)
{
	struct pnor pnor;
	int rc;

	if (argc != 2) {
		printf("usage: %s [pnor file]\n", argv[0]);
		exit(EXIT_FAILURE);
	}


	pnor.path = strndup(argv[1], PATH_MAX);

	rc = pnor_init(&pnor);
	assert(rc);

	dump_parts(pnor.ffsh);

	pnor_close(&pnor);

	return 0;
}
