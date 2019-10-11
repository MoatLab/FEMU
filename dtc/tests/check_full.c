/*
 * libfdt - Flat Device Tree manipulation
 *	Tests if two given dtbs are structurally equal (including order)
 * Copyright (C) 2007 David Gibson, IBM Corporation.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <libfdt.h>

#include "tests.h"
#include "testdata.h"

static int expect_bad; /* = 0 */

int main(int argc, char *argv[])
{
	const char *filename;
	char *fdt;
	size_t len;
	int err;

	test_init(argc, argv);
	if ((argc != 2)
	    && ((argc != 3) || !streq(argv[1], "-n")))
		CONFIG("Usage: %s [-n] <dtb file>", argv[0]);
	if (argc == 3)
		expect_bad = 1;

	filename = argv[argc-1];
	err = utilfdt_read_err(filename, &fdt, &len);
	if (err)
		CONFIG("Couldn't open blob from \"%s\": %s",
		       filename, strerror(err));

	vg_prepare_blob(fdt, len);

	err = fdt_check_full(fdt, len);

	if (expect_bad && (err == 0))
		FAIL("fdt_check_full() succeeded unexpectedly");
	else if (!expect_bad && (err != 0))
		FAIL("fdt_check_full() failed: %s", fdt_strerror(err));

	PASS();
}
