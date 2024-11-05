// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2015 IBM Corp.
 */

#define BUFSZ 50

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>

int skiboot_isdigit(int ch);
int skiboot_isprint(int ch);
int skiboot_isspace(int ch);
int skiboot_isxdigit(int ch);
int skiboot_tolower(int ch);
int skiboot_toupper(int ch);

int main(void)
{
	int i;
	int r1, r2;

	for(i = '0'; i <= '9'; i++)
		assert(skiboot_isdigit(i));
	assert(skiboot_isdigit('a') == 0);
	assert(skiboot_isdigit('Z') == 0);

	for (i = 0; i < 257; i++) {
		r1 = skiboot_isdigit(i);
		r2 = isdigit(i);
		if (r1)
			assert(r2);
		if (!r1)
			assert(!r2);
	}

	for(i = '0'; i <= '9'; i++)
		assert(skiboot_isprint(i));
	assert(skiboot_isprint('\0') == 0);
	assert(skiboot_isprint(4) == 0);

	for (i = 0; i < 257; i++) {
		r1 = skiboot_isprint(i);
		r2 = isprint(i);
		if (r1)
			assert(r2);
		if (!r1)
			assert(!r2);
	}

	for(i = '0'; i <= '9'; i++)
		assert(skiboot_isspace(i) == 0);
	assert(skiboot_isspace('\f'));
	assert(skiboot_isspace('\n'));
	assert(skiboot_isspace(' '));

	for (i = 0; i < 257; i++) {
		r1 = skiboot_isspace(i);
		r2 = isspace(i);
		if (r1)
			assert(r2);
		if (!r1)
			assert(!r2);
	}

	for(i = '0'; i <= '9'; i++)
		assert(skiboot_isxdigit(i));
	assert(skiboot_isxdigit('a'));
	assert(skiboot_isxdigit('A'));
	assert(skiboot_isxdigit('F'));
	assert(skiboot_isxdigit('Z') == 0);

	for (i = 0; i < 257; i++) {
		r1 = skiboot_isxdigit(i);
		r2 = isxdigit(i);
		if (r1)
			assert(r2);
		if (!r1)
			assert(!r2);
	}

	for (i = 0; i < 257; i++) {
		assert(skiboot_tolower(i) == tolower(i));
	}

	for (i = 0; i < 257; i++) {
		assert(skiboot_toupper(i) == toupper(i));
	}

	return 0;
}
