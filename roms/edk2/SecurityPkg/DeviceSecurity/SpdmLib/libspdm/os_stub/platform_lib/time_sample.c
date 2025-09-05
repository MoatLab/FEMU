/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*
 * this is armv8 reference code to implement time_sleep
 * the armv8 special code form https://github.com/altera-opensource/intel-socfpga-hwlib
 **/

#include <base.h>
#include <stdlib.h>
#include <errno.h>
#include "hal/library/debuglib.h"

/**
 * Suspends the execution of the current thread until the time-out interval elapses.
 *
 * @param microseconds     The time interval for which execution is to be suspended, in microseconds.
 *
 **/

void libspdm_sleep(uint64_t microseconds)
{
    /*the feature for armclang build is TBD*/
    LIBSPDM_ASSERT(false);
}
