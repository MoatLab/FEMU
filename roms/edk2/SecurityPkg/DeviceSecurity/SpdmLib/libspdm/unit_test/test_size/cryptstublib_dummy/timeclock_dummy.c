/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"
#include "hal/library/debuglib.h"

#if defined(__GNUC__) && !defined(_WIN32)
typedef size_t time_t;
#elif defined(__clang__)
typedef size_t time_t;
#endif

/* Structures Definitions*/

struct tm {
    int tm_sec; /* seconds after the minute [0-60] */
    int tm_min; /* minutes after the hour [0-59] */
    int tm_hour; /* hours since midnight [0-23] */
    int tm_mday; /* day of the month [1-31] */
    int tm_mon; /* months since January [0-11] */
    int tm_year; /* years since 1900 */
    int tm_wday; /* days since Sunday [0-6] */
    int tm_yday; /* days since January 1 [0-365] */
    int tm_isdst; /* Daylight Savings Time flag */
    long tm_gmtoff; /* offset from CUT in seconds */
    char *tm_zone; /* timezone abbreviation */
};


/* -- Time Management Routines --*/


time_t time(time_t *timer)
{
    LIBSPDM_ASSERT(false);
    return 0;
}

struct tm *gmtime(const time_t *timer)
{
    LIBSPDM_ASSERT(false);
    return NULL;
}

time_t _time64(time_t *t)
{
    LIBSPDM_ASSERT(false);
    return 0;
}

struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
    LIBSPDM_ASSERT(false);
    return NULL;
}
