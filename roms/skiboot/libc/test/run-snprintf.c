// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2013-2015 IBM Corp.
 */

#define BUFSZ 50

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

int test1(void);
int skiboot_snprintf(char *buf, size_t bufsz, size_t l, const char* format, ...);

static void test_printf_0u(int n)
{
	char *buf, *buf2;
	int blen;
	unsigned int i;

	for(i=1; i<10; i++)
	{
		blen = i+1;
		if (n<0)
			blen++;

		buf = (char*)malloc(blen);
		buf2 = (char*)malloc(blen);
		skiboot_snprintf(buf, blen, blen, "%08u", n);
		snprintf(buf2, blen, "%08u", n);
		n = n * 10;
		assert(0 == strncmp(buf, buf2, blen));
		free(buf);
		free(buf2);
	}
}

static void test_printf_u(int n)
{
	char *buf, *buf2;
	int blen;
	unsigned int r;
	unsigned int i;

	for(i=1; i<10; i++)
	{
		blen = i+1;
		if (n<0)
			blen++;

		buf = (char*)malloc(blen);
		buf2 = (char*)malloc(blen);
		r = skiboot_snprintf(buf, blen, blen, "%u", n);
		snprintf(buf2, blen, "%u", n);
		n = n * 10;
		if (n<0)
			assert(i+1 == r);
		else
			assert(i == r);
		assert(0 == strncmp(buf, buf2, blen));
		free(buf);
		free(buf2);
	}
}

static void test_printf_d(int n)
{
	char *buf, *buf2;
	int blen;
	int r;
	int i;

	for(i=1; i<10; i++)
	{
		blen = i+1;
		if (n<0)
			blen++;

		buf = (char*)malloc(blen);
		buf2 = (char*)malloc(blen);
		r = skiboot_snprintf(buf, blen, blen, "%d", n);
		snprintf(buf2, blen, "%d", n);
		n = n * 10;
		if (n<0)
			assert(i+1 == r);
		else
			assert(i == r);
		assert(0 == strncmp(buf, buf2, blen));
		free(buf);
		free(buf2);
	}
}

static void test_printf_x(const char* f)
{
	char *buf, *buf2;
	int blen;
	int i, r;
	unsigned int n=0x1;

	for (i=0; i<8; i++)
	{
		blen = i+2;
		buf = (char*)malloc(blen);
		buf2 = (char*)malloc(blen);
		r = skiboot_snprintf(buf, blen, blen, f, n);
		snprintf(buf2, blen, f, n);
		assert(i+1 == r);
		assert(0 == strncmp(buf, buf2, blen));
		free(buf);
		free(buf2);
		n = n << 4;
	}
}

static void test_printf_c(void)
{
	char *buf= (char*)malloc(2);
	char buf2[2];
	unsigned char i= 0xff;
	int r;
	while(i)
	{
		r = skiboot_snprintf(buf, 2, 2, "%c", i);
		snprintf(buf2, 2, "%c", i);
		assert(r==1);
		assert(0 == strncmp(buf, buf2, 2));
		i--;
	}
	free(buf);
}

static void test_printf_p(void)
{
	char *buf= (char*)malloc(32);
	char buf2[32];
	skiboot_snprintf(buf, 32, 32, "%p", buf);
	snprintf(buf2, 32, "%p", buf);
	assert(0 == strncmp(buf, buf2, 32));
	free(buf);
}

static void test_printf_o(void)
{
	char *buf= (char*)malloc(32);
	char buf2[32];
	skiboot_snprintf(buf, 32, 32, "%o", 0x12345678);
	snprintf(buf2, 32, "%o", 0x12345678);
	assert(0 == strncmp(buf, buf2, 32));
	free(buf);
}

static void test_printf_h(short i)
{
	char *buf= (char*)malloc(32);
	char buf2[32];
	skiboot_snprintf(buf, 32, 32, "%hd", i);
	snprintf(buf2, 32, "%hd", i);
	assert(0 == strncmp(buf, buf2, 32));
	free(buf);
}

static void test_printf_z(size_t i)
{
	char *buf= (char*)malloc(32);
	char buf2[32];
	skiboot_snprintf(buf, 32, 32, "%zu", i);
	snprintf(buf2, 32, "%zu", i);
	assert(0 == strncmp(buf, buf2, 32));
	free(buf);
}

int main(void)
{
	char *buf;
	int r;

	buf = (char*)malloc(BUFSZ);
	memset(buf, 0, BUFSZ);

	assert(-1 == test1());

	r = skiboot_snprintf(buf, BUFSZ, 2, "%%");
	assert(r==1);
	assert(buf[0] == '%' && buf[1] == 0);

	r = skiboot_snprintf(buf, BUFSZ, 2, "%d", 137);
	/* BUG/FIXME:
	 * skiboot libc does NOT return the length of the buffer you'd need
	 * Instead, it'll return something random, possibly zero (as here)
	 * but as you'll see in test_in_buf_len2, sometimes not.
	 *
	 * Basically, we're not POSIX printf and this is some day going to
	 * cause things to be awful.
	 */
	assert(0 == r); // BUG, should be 3
	assert(0 == strncmp(buf, "", 3));

	r = skiboot_snprintf(buf, BUFSZ, 4, "%d", 137);
	assert(3 == r);
	assert(0 == strncmp(buf, "137", 3));
	assert(buf[3] == 0);

	/* Now we test the strange behaviour of our printf.
	 * For strings, we get partial prints going, but if we whack an
	 * integer on the end, we may or may not get that integer, depending
	 * on if we have enough size. We should test that though */

	r = skiboot_snprintf(buf, BUFSZ, 4, "Hello %d", 137);
	assert(3 == r);
	assert(0 == strncmp(buf, "Hel", 3));
	assert(buf[3] == 0);
	r = skiboot_snprintf(buf, BUFSZ, 7, "Hello %d", 137);
	assert(6 == r);
	assert(0 == strncmp(buf, "Hello ", 6));
	assert(buf[6] == 0);
	r = skiboot_snprintf(buf, BUFSZ, 10, "Hello %d", 137);
	assert(9 == r);
	assert(0 == strncmp(buf, "Hello 137", 10));
	assert(buf[9] == 0);
	free(buf);

	test_printf_u(1);
	test_printf_0u(1);
	test_printf_d(1);
	test_printf_d(-1);
	test_printf_x("%x");
	test_printf_x("%X");
	test_printf_c();
	test_printf_p();
	test_printf_o();
	test_printf_h(0);
	test_printf_h(128);
	test_printf_h(256);
	test_printf_h(-1);
	test_printf_h(32767);
	test_printf_h(32768);
	test_printf_h(65535);
	test_printf_z(0);
	test_printf_z(-1);
	test_printf_z(12345);
	test_printf_z(128000000);

	return 0;
}
