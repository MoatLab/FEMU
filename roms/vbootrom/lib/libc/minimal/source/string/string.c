/* string.c - common string routines */

/*
 * Copyright (c) 2014 Wind River Systems, Inc.
 * Copyright (C) ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdint.h>
#include <sys/types.h>

/**
 *
 * @brief Copy a string
 *
 * @return pointer to destination buffer <d>
 */

char *strcpy(char *ZRESTRICT d, const char *ZRESTRICT s)
{
	char *dest = d;

	while (*s != '\0') {
		*d = *s;
		d++;
		s++;
	}

	*d = '\0';

	return dest;
}

/**
 *
 * @brief Copy part of a string
 *
 * @return pointer to destination buffer <d>
 */

char *strncpy(char *ZRESTRICT d, const char *ZRESTRICT s, size_t n)
{
	char *dest = d;

	while ((n > 0) && (*s != '\0')) {
		*d = *s;
		s++;
		d++;
		n--;
	}

	while (n > 0) {
		*d = '\0';
		d++;
		n--;
	}

	return dest;
}

/**
 *
 * @brief String scanning operation
 *
 * @return pointer to 1st instance of found byte, or NULL if not found
 */

char *strchr(const char *s, int c)
{
	char tmp = (char) c;

	while ((*s != tmp) && (*s != '\0')) {
		s++;
	}

	return (*s == tmp) ? (char *) s : NULL;
}

/**
 *
 * @brief String scanning operation
 *
 * @return pointer to last instance of found byte, or NULL if not found
 */

char *strrchr(const char *s, int c)
{
	char *match = NULL;

	do {
		if (*s == (char)c) {
			match = (char *)s;
		}
	} while (*s++ != '\0');

	return match;
}

/**
 * strlen - Find the length of a string
 * @s: The string to be sized
 */
size_t strlen(const char *s)
{
	const char *sc;

	for (sc = s; *sc != '\0'; ++sc)
		/* nothing */;
	return sc - s;
}

/**
 *
 * @brief Compare two strings
 *
 * @return negative # if <s1> < <s2>, 0 if <s1> == <s2>, else positive #
 */

int strcmp(const char *s1, const char *s2)
{
	while ((*s1 == *s2) && (*s1 != '\0')) {
		s1++;
		s2++;
	}

	return *s1 - *s2;
}

/**
 *
 * @brief Compare part of two strings
 *
 * @return negative # if <s1> < <s2>, 0 if <s1> == <s2>, else positive #
 */

int strncmp(const char *s1, const char *s2, size_t n)
{
	while ((n > 0) && (*s1 == *s2) && (*s1 != '\0')) {
		s1++;
		s2++;
		n--;
	}

	return (n == 0) ? 0 : (*s1 - *s2);
}

/**
 * @brief Separate `str` by any char in `sep` and return NULL terminated
 * sections. Consecutive `sep` chars in `str` are treated as a single
 * separator.
 *
 * @return pointer to NULL terminated string or NULL on errors.
 */
char *strtok_r(char *str, const char *sep, char **state)
{
	char *start, *end;

	start = str ? str : *state;

	/* skip leading delimiters */
	while (*start && strchr(sep, *start)) {
		start++;
	}

	if (*start == '\0') {
		*state = start;
		return NULL;
	}

	/* look for token chars */
	end = start;
	while (*end && !strchr(sep, *end)) {
		end++;
	}

	if (*end != '\0') {
		*end = '\0';
		*state = end + 1;
	} else {
		*state = end;
	}

	return start;
}

char *strcat(char *ZRESTRICT dest, const char *ZRESTRICT src)
{
	strcpy(dest + strlen(dest), src);
	return dest;
}

char *strncat(char *ZRESTRICT dest, const char *ZRESTRICT src,
	      size_t n)
{
	char *orig_dest = dest;
	size_t len = strlen(dest);

	dest += len;
	while ((n-- > 0) && (*src != '\0')) {
		*dest++ = *src++;
	}
	*dest = '\0';

	return orig_dest;
}

/**
 *
 * @brief Compare two memory areas
 *
 * @return negative # if <m1> < <m2>, 0 if <m1> == <m2>, else positive #
 */
int memcmp(const void *m1, const void *m2, size_t n)
{
	const char *c1 = m1;
	const char *c2 = m2;

	if (!n) {
		return 0;
	}

	while ((--n > 0) && (*c1 == *c2)) {
		c1++;
		c2++;
	}

	return *c1 - *c2;
}

/**
 *
 * @brief Copy bytes in memory with overlapping areas
 *
 * @return pointer to destination buffer <d>
 */

void *memmove(void *d, const void *s, size_t n)
{
	char *dest = d;
	const char *src  = s;

	if ((size_t) (dest - src) < n) {
		/*
		 * The <src> buffer overlaps with the start of the <dest> buffer.
		 * Copy backwards to prevent the premature corruption of <src>.
		 */

		while (n > 0) {
			n--;
			dest[n] = src[n];
		}
	} else {
		/* It is safe to perform a forward-copy */
		while (n > 0) {
			*dest = *src;
			dest++;
			src++;
			n--;
		}
	}

	return d;
}

/**
 *
 * @brief Copy bytes in memory
 *
 * @return pointer to start of destination buffer
 */

void *memcpy(void *ZRESTRICT d, const void *ZRESTRICT s, size_t n)
{
	/* attempt word-sized copying only if buffers have identical alignment */
        uintptr_t d_addr = (uintptr_t)d;
        uintptr_t s_addr = (uintptr_t)s;

	unsigned char *d_byte = (unsigned char *)(uintptr_t)d_addr;
	const unsigned char *s_byte = (const unsigned char *)(uintptr_t)s_addr;

	/* do byte-sized copying until finished */

	while (n > 0) {
		*(d_byte++) = *(s_byte++);
		n--;
	}

	return d;
}

/**
 *
 * @brief Set bytes in memory
 *
 * @return pointer to start of buffer
 */

void *memset(void *buf, int c, size_t n)
{
	/* do byte-sized initialization until word-aligned or finished */

	unsigned char *d_byte = (unsigned char *)buf;
	unsigned char c_byte = (unsigned char)c;

	while (n > 0) {
		*(d_byte++) = c_byte;
		n--;
	}

	return buf;
}

/**
 *
 * @brief Scan byte in memory
 *
 * @return pointer to start of found byte
 */

void *memchr(const void *s, int c, size_t n)
{
	if (n != 0) {
		const unsigned char *p = s;

		do {
			if (*p++ == (unsigned char)c) {
				return ((void *)(p - 1));
			}

		} while (--n != 0);
	}

	return NULL;
}

/**
 *
 * @brief Get fixed-size string length
 *
 *        This function is not available in ARM C Standard library.
 *
 * @return number of bytes in fixed-size string <s>
 */

size_t strnlen(const char *s, size_t maxlen)
{
	size_t n = 0;

	while (*s != '\0' && n < maxlen) {
		s++;
		n++;
	}

	return n;
}
