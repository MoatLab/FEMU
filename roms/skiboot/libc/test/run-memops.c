// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2015 IBM Corp.
 */

#define BUFSZ 50

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

int test_memset(char* buf, int c, size_t s);
int test_memchr(const void *ptr, int c, size_t n, void* expected);
int test_memcmp(const void *ptr1, const void *ptr2, size_t n, int expected);
int test_strcmp(const void *ptr1, const void *ptr2, int expected);
int test_strchr(const char *s, int c, char *expected);
int test_strrchr(const char *s, int c, char *expected);
int test_strcasecmp(const char *s1, const char *s2, int expected);
int test_strncasecmp(const char *s1, const char *s2, size_t n, int expected);
int test_memmove(void *dest, const void *src, size_t n, const void *r, const void *expected, size_t expected_n);

int main(void)
{
	char *buf;
	char *buf2;

	buf = malloc(100);
	assert(test_memset(buf, 0x42, 100) == 0);
	free(buf);

	buf = malloc(128);
	assert(test_memset(buf, 0, 128) == 0);
	assert(test_memset(buf+1, 0, 127) == 0);
	free(buf);

	buf = malloc(1024);
	assert(test_memset(buf, 0, 1024) == 0);
	free(buf);

	buf = malloc(20);
	strncpy(buf, "Hello World!", 20);
	assert(test_memchr(buf, 'o', strlen(buf), buf+4));
	assert(test_memchr(buf, 'a', strlen(buf), NULL));

	assert(test_memcmp(buf, "Hello World!", strlen(buf), 0));
	assert(test_memcmp(buf, "Hfllow World", strlen(buf), -1));

	assert(test_strcmp(buf, "Hello World!",  0));
	assert(test_strcmp(buf, "Hfllow World", -1));

	assert(test_strchr(buf, 'H', buf));
	assert(test_strchr(buf, 'e', buf+1));
	assert(test_strchr(buf, 'a', NULL));
	assert(test_strchr(buf, '!', buf+11));

	assert(test_strrchr(buf, 'H', buf));
	assert(test_strrchr(buf, 'o', buf+7));
	assert(test_strrchr(buf, 'a', NULL));
	assert(test_strrchr(buf, 'l', buf+9));
	assert(test_strrchr(buf, '!', buf+11));

	assert(test_strcasecmp(buf, "Hello World!", 0));
	assert(test_strcasecmp(buf, "HELLO WORLD!", 0));
	assert(test_strcasecmp(buf, "IELLO world!", -1));
	assert(test_strcasecmp(buf, "HeLLo WOrlc!", 1));

	assert(test_strncasecmp(buf, "Hello World!", strlen(buf), 0));
	assert(test_strncasecmp(buf, "HELLO WORLD!", strlen(buf), 0));
	assert(test_strncasecmp(buf, "IELLO world!", strlen(buf), -1));
	assert(test_strncasecmp(buf, "HeLLo WOrlc!", strlen(buf), 1));

	assert(test_strncasecmp(buf, "HeLLo WOrlc!", 0, 0));
	assert(test_strncasecmp(buf, "HeLLo WOrlc!", 1, 0));
	assert(test_strncasecmp(buf, "HeLLo WOrlc!", 2, 0));
	assert(test_strncasecmp(buf, "HeLLp WOrlc!", 5, -1));

	free(buf);

	buf  = malloc(20);
	buf2 = malloc(20);
	strncpy(buf, "Hello", 20);
	strncpy(buf2, " World!", 20);

	assert(test_memmove(buf + 5, buf2, strlen(buf2), buf,
			    "Hello World!", strlen("Hello World!")));

	strncpy(buf, "HHello World!", 20);
	assert(test_memmove(buf, buf+1, strlen("Hello World!"), buf, "Hello World!", strlen("Hello World!")));

	strncpy(buf, "0123456789", 20);
	assert(test_memmove(buf+1, buf , strlen("0123456789"), buf, "00123456789", strlen("00123456789")));

	free(buf);
	free(buf2);

	return 0;
}
