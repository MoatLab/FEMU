// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2015 IBM Corp.
 */

#define BUFSZ 50

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void)
{
	char buf[] = "42, and stuff.";
	char *ptr;

	/* atoi/strtol - general correct behavior */
	assert(atoi("0") == 0);
	assert(atoi("1") == 1);
	assert(atoi(" 123456") == 123456);
	assert(atoi("-72") == -72);
	assert(atoi("  -84") == -84);
	assert(atoi("2147483647") == 2147483647);

	/* atoi/strtol - numbers before and after strings */
	assert(atoi("hello!123") == 0);
	assert(atoi(buf) == 42);
	assert(atoi("42isthemagicnumber") == 42);

	/* atoi is base 10 only */
	assert(atoi("0x800") == 0);

	/* atol - ensure it recognises longs */
	assert(atol("2147483648") == 2147483648);
	assert(atol("-2147483649") == -2147483649);

	/* strtol detects hex */
	assert(strtol("0x800", NULL, 0) == 0x800);
	/* But not with a duplicate prefix */
	assert(strtol("0x0x800", NULL, 0) == 0);

	/* strtol - invalid/weird bases */
	assert(strtol("z", NULL, -1) == 0);
	assert(strtol("11111", NULL, 1) == 0);
	assert(strtol("z", NULL, 37) == 0);
	assert(strtol("z", NULL, 36) == 35);
	assert(strtol("-Y", NULL, 36) == -34);

	/* strtol - ptr advanced correctly */
	ptr = buf;
	assert(strtol(buf, &ptr, 10) == 42);
	assert(ptr == buf + 2);

	/* strtoul - base 10 */
	assert(strtoul("0", NULL, 10) == 0);
	assert(strtoul("1", NULL, 10) == 1);
	assert(strtoul(" 123456", NULL, 10) == 123456);
	assert(strtoul("-72", NULL, 10) == 0);
	assert(strtoul("9999999999", NULL, 10) == 9999999999);
	assert(strtoul("hello!123", NULL, 10) == 0);
	assert(strtoul(buf, NULL, 10) == 42);
	assert(strtoul("42isthemagicnumber", NULL, 10) == 42);

	/* strtoul - autodetection of base */
	assert(strtoul(" 123456", NULL, 0) == 123456);
	assert(strtoul("0x800", NULL, 0) == 0x800);
	assert(strtoul("0x0x800", NULL, 0) == 0);

	/* strtoul - weird/invalid bases */
	assert(strtoul("z", NULL, -1) == 0);
	assert(strtoul("11111", NULL, 1) == 0);
	assert(strtoul("z", NULL, 37) == 0);
	assert(strtoul("z", NULL, 36) == 35);
	assert(strtoul("Y", NULL, 36) == 34);

	/* labs - ensure it returns absolute value */
	assert(labs(0) == 0);
	assert(labs(2147483647) == 2147483647);
	assert(labs(-2147483647) == 2147483647);
	assert(labs(9223372036854775807) == 9223372036854775807);
	assert(labs(-9223372036854775807) == 9223372036854775807);

	return 0;
}
