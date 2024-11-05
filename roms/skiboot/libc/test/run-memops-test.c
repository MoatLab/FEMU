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

#include "../string/memchr.c"
#include "../string/memcmp.c"
#include "../string/memcpy.c"
#include "../string/memmove.c"
#include "../string/memset.c"
#include "../string/strcasecmp.c"
#include "../string/strcat.c"
#include "../string/strchr.c"
#include "../string/strrchr.c"
#include "../string/strcmp.c"
#include "../string/strcpy.c"
/* #include "../string/strdup.c" */
#include "../string/strlen.c"
#include "../string/strncasecmp.c"
#include "../string/strncmp.c"
#include "../string/strncpy.c"
#include "../string/strstr.c"
#include "../string/strtok.c"
#include <stdlib.h>

int test_memset(char* buf, int c, size_t s);
int test_memchr(const void *ptr, int c, size_t n, void* expected);
int test_memcmp(const void *ptr1, const void *ptr2, size_t n, int expected);
int test_strcmp(const void *ptr1, const void *ptr2, int expected);
int test_strchr(const char *s, int c, char *expected);
int test_strrchr(const char *s, int c, char *expected);
int test_strcasecmp(const char *s1, const char *s2, int expected);
int test_strncasecmp(const char *s1, const char *s2, size_t n, int expected);
int test_memmove(void *dest, const void *src, size_t n, const void *r, const void *expected, size_t expected_n);

int test_memset(char* buf, int c, size_t s)
{
	int i;
	int r= 0;

	memset(buf, c, s);
	for(i=0; i<s; i++)
		if (buf[i] != c)
			r = -1;

	return r;
}

int test_memchr(const void *ptr, int c, size_t n, void* expected)
{
	return(expected == memchr(ptr, c, n));
}

int test_memcmp(const void *ptr1, const void *ptr2, size_t n, int expected)
{
	return(expected == memcmp(ptr1, ptr2, n));
}

int test_strcmp(const void *ptr1, const void *ptr2, int expected)
{
	return(expected == strcmp(ptr1, ptr2));
}

int test_strchr(const char *s, int c, char *expected)
{
	return(expected == strchr(s, c));
}

int test_strrchr(const char *s, int c, char *expected)
{
	return(expected == strrchr(s, c));
}

int test_strcasecmp(const char *s1, const char *s2, int expected)
{
	return(expected == strcasecmp(s1, s2));
}

int test_strncasecmp(const char *s1, const char *s2, size_t n, int expected)
{
	return(expected == strncasecmp(s1, s2, n));
}

int test_memmove(void *dest, const void *src, size_t n, const void *r, const void *expected, size_t expected_n)
{
	if (memmove(dest, src, n) != dest)
		return -1;
	return(memcmp(r, expected, expected_n) == 0);
}
