/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/library/memlib.h"

#ifdef _WIN32
#include <windows.h>
#elif defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#include <strings.h>
#include <string.h>
#endif

void libspdm_zero_mem(void *buffer, size_t length)
{

#if defined(__STDC_LIB_EXT1__)
    memset_s(buffer, length, 0, length);
#elif defined(_WIN32)
    SecureZeroMemory(buffer, length);
#elif defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
    explicit_bzero(buffer, length);
#else
    volatile uint8_t *pointer;

    pointer = (uint8_t *)buffer;
    while (length-- != 0) {
        *(pointer++) = 0;
    }

#if defined(_MSC_VER) && (_MSC_VER > 1200) && !defined(__clang__)
    _ReadWriteBarrier();
#elif defined(__GNUC__)
    __asm__ __volatile__ ("" : : : "memory");
#endif

#endif
}
