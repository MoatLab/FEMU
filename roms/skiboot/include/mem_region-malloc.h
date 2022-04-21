// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __MEM_REGION_MALLOC_H
#define __MEM_REGION_MALLOC_H

#include <compiler.h>

#define __loc2(line)    #line
#define __loc(line)	__loc2(line)
#define __location__	__FILE__ ":" __loc(__LINE__)

void *__malloc(size_t size, const char *location) __warn_unused_result;
void *__zalloc(size_t size, const char *location) __warn_unused_result;
void *__realloc(void *ptr, size_t size, const char *location) __warn_unused_result;
void __free(void *ptr, const char *location);
void *__memalign(size_t boundary, size_t size, const char *location) __warn_unused_result;

#define malloc(size) __malloc(size, __location__)
#define zalloc(size) __zalloc(size, __location__)
#define calloc(nmemb, size) __zalloc(((nmemb) * (size)), __location__)
#define realloc(ptr, size) __realloc(ptr, size, __location__)
#define free(ptr) __free(ptr, __location__)
#define memalign(boundary, size) __memalign(boundary, size, __location__)

void *__local_alloc(unsigned int chip, size_t size, size_t align,
		    const char *location) __warn_unused_result;
#define local_alloc(chip_id, size, align)	\
	__local_alloc((chip_id), (size), (align), __location__)

#endif /* __MEM_REGION_MALLOC_H */
