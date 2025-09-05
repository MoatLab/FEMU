/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * C Run-Time Libraries (CRT) Wrapper Implementation.
 **/

#include <stdio.h>

#include <base.h>
#include "library/debuglib.h"
#include <openssl/bio.h>

/* Convert character to lowercase */
int tolower(int c)
{
    if (('A' <= (c)) && ((c) <= 'Z')) {
        return (c - ('A' - 'a'));
    }
    return (c);
}

/* Compare first n bytes of string s1 with string s2, ignoring case */
int strncasecmp(const char *s1, const char *s2, size_t n)
{
    int val;

    LIBSPDM_ASSERT(s1 != NULL);
    LIBSPDM_ASSERT(s2 != NULL);
    if (s1 == NULL || s2 == NULL) {
        return -1;
    }

    if (n != 0) {
        do {
            val = tolower(*s1) - tolower(*s2);
            if (val != 0) {
                return val;
            }
            ++s1;
            ++s2;
            if (*s1 == '\0') {
                break;
            }
        } while (--n != 0);
    }
    return 0;
}

int strcasecmp(const char *s1, const char *s2)
{
    int val;

    LIBSPDM_ASSERT(s1 != NULL);
    LIBSPDM_ASSERT(s2 != NULL);
    if (s1 == NULL || s2 == NULL) {
        return -1;
    }

    while ((*s1 != '\0') && (*s2 != '\0')) {
        val = tolower(*s1) - tolower(*s2);
        if (val != 0) {
            return val;
        }
        ++s1;
        ++s2;
    }

    val = tolower(*s1) - tolower(*s2);
    return val;
}

/* Read formatted data from a string */
int sscanf(const char *buffer, const char *format, ...)
{

    /* Null sscanf() function implementation to satisfy the linker, since
     * no direct functionality logic dependency in present cases.*/

    return 0;
}


/*  -- Dummy OpenSSL Support Routines --*/


uid_t getuid(void)
{
    return 0;
}

uid_t geteuid(void)
{
    return 0;
}

gid_t getgid(void)
{
    return 0;
}

gid_t getegid(void)
{
    return 0;
}

#if !defined(__GNUC__) && !defined(_WIN32)
int GetLastError ()
{
    return 0;
}
#endif

void SetLastError(int e)
{
}
