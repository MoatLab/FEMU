/**
 * Copyright Notice:
 * Copyright 2022 DMTF. All rights reserved.
 * License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <base.h>
#include <stdlib.h>
#include <sys/time.h>
#include <errno.h>

/**
 * Suspends the execution of the current thread until the time-out interval elapses.
 *
 * @param microseconds     The time interval for which execution is to be suspended, in microseconds.
 *
 **/
void libspdm_sleep(uint64_t microseconds)
{
    struct timeval tv;
    int err;

    tv.tv_sec = microseconds / 1000000;
    tv.tv_usec = (microseconds % 1000000);

    do {
        err=select(0, NULL, NULL, NULL, &tv);
    } while(err<0 && errno==EINTR);
}
