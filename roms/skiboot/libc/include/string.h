/******************************************************************************
 * Copyright (c) 2004, 2016 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#ifndef _STRING_H
#define _STRING_H

#include "stddef.h"

#define strcpy __builtin_strcpy
#define strncpy __builtin_strncpy
#define strcat __builtin_strcat
#define strcmp __builtin_strcmp
#define strncmp __builtin_strncmp
#define strcasecmp __builtin_strcasecmp
#define strncasecmp __builtin_strncasecmp
#define strchr __builtin_strchr
#define strrchr __builtin_strrchr
#define strlen __builtin_strlen
#define strlen __builtin_strlen
size_t strnlen(const char *s, size_t maxlen);
#define strstr __builtin_strstr
#define strdup __builtin_strdup
char *strtok(char *src, const char *pattern);

#define memset __builtin_memset
#define memchr __builtin_memchr
#define memcpy __builtin_memcpy
#define memmove __builtin_memmove
#define memcmp __builtin_memcmp
static inline void *memcpy_null(void *dest, const void *src, size_t n)
{
	asm("" : "+r"(dest));
	asm("" : "+r"(src));
	return memcpy(dest, src, n);
}
void *memcpy_from_ci(void *destpp, const void *srcpp, size_t len);

static inline int ffs(unsigned long val)
{
	return __builtin_ffs(val);
}

#endif
