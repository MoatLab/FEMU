/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Intrinsic Memory Routines Wrapper Implementation.
 **/

#include "hal/base.h"
#include "hal/library/memlib.h"

#if defined(__GNUC__) || defined(__clang__)
#define GLOBAL_USED __attribute__((used))
#else
#define GLOBAL_USED
#endif

/* OpenSSL will use floating point support, and C compiler produces the _fltused
 * symbol by default. Simply define this symbol here to satisfy the linker. */
int GLOBAL_USED _fltused = 1;

/* Sets buffers to a specified character */
void *memset(void *dest, int ch, size_t count)
{

    /* NOTE: Here we use one base implementation for memset, instead of the direct
     *       optimized libspdm_set_mem() wrapper. Because the intrinsiclib has to be built
     *       without whole program optimization option, and there will be some
     *       potential register usage errors when calling other optimized codes.*/



    /* Declare the local variables that actually move the data elements as
     * volatile to prevent the optimizer from replacing this function with
     * the intrinsic memset()*/

    volatile uint8_t *pointer;

    pointer = (uint8_t *)dest;
    while (count-- != 0) {
        *(pointer++) = (uint8_t)ch;
    }

    return dest;
}

void *memmove(void *dest, const void *src, size_t count)
{
    unsigned char        *d;
    unsigned char const  *s;

    d = dest;
    s = src;

    if (d < s) {
        while (count-- != 0) {
            *d++ = *s++;
        }
    } else {
        d += count;
        s += count;
        while (count-- != 0) {
            *--d = *--s;
        }
    }
    return dest;
}

/* Compare bytes in two buffers. */
int memcmp(const void *buf1, const void *buf2, size_t count)
{
    return (int)libspdm_consttime_is_mem_equal(buf1, buf2, count);
}

#if defined(__clang__) && !defined(__APPLE__)

/* Copies bytes between buffers */
static __attribute__((__used__)) void *__memcpy(void *dest, const void *src,
                                                unsigned int count)
{
    libspdm_copy_mem(dest, (size_t)count, src, (size_t)count);
    return dest;
}
__attribute__((__alias__("__memcpy"))) void *memcpy(void *dest, const void *src,
                                                    unsigned int count);

#else
/* Copies bytes between buffers */
void *memcpy(void *dest, const void *src, unsigned int count)
{
    libspdm_copy_mem(dest, (size_t) count, src, (size_t)count);
    return dest;
}
#endif

int ascii_strcmp(const char *first_string, const char *second_string)
{
    while ((*first_string != '\0') && (*first_string == *second_string)) {
        first_string++;
        second_string++;
    }

    return *first_string - *second_string;
}

int ascii_strncmp(const char *first_string, const char *second_string, size_t length)
{
    if (length == 0) {
        return 0;
    }
    while ((*first_string != '\0') && (*first_string != '\0')  &&
           (*first_string == *second_string) && (length > 1)) {
        first_string++;
        second_string++;
        length--;
    }

    return *first_string - *second_string;
}

int strcmp(const char *s1, const char *s2)
{
    return (int)ascii_strcmp(s1, s2);
}

size_t ascii_strlen(const char *string)
{
    size_t length;

    if (string == NULL) {
        return 0;
    }
    for (length = 0; *string != '\0'; string++, length++) {
    }
    return length;
}

unsigned int strlen(char *s)
{
    return (unsigned int)ascii_strlen(s);
}

char *ascii_strstr(char *string, const char *search_string)
{
    char *first_match;
    const char *search_string_tmp;

    if (*search_string == '\0') {
        return string;
    }

    while (*string != '\0') {
        search_string_tmp = search_string;
        first_match = string;

        while ((*string == *search_string_tmp) && (*string != '\0')) {
            string++;
            search_string_tmp++;
        }

        if (*search_string_tmp == '\0') {
            return first_match;
        }

        if (*string == '\0') {
            return NULL;
        }

        string = first_match + 1;
    }

    return NULL;
}

char *strstr(char *str1, const char *str2)
{
    return ascii_strstr(str1, str2);
}

const void * memscan ( const void * ptr, int value, size_t num )
{
    const char  *p;

    p = (const void *)ptr;
    do {
        if (*p == value) {
            return (const void *)p;
        }
        ++p;
    } while (--num != 0);

    return NULL;
}

const void * memchr ( const void * ptr, int value, size_t num )
{
    return memscan (ptr, value, num);
}

const char * strchr ( const char * str, int ch )
{
    return memscan (str, (int)ascii_strlen(str) + 1, ch);
}

int strncmp ( const char * str1, const char * str2, size_t num )
{
    return (int)ascii_strncmp(str1, str2, num);
}
