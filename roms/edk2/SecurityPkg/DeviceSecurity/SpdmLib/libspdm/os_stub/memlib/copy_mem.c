/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "library/debuglib.h"
#include "hal/library/memlib.h"

void libspdm_copy_mem(void *dst_buf, size_t dst_len,
                      const void *src_buf, size_t src_len)
{
    volatile uint8_t* dst;
    const volatile uint8_t* src;

    dst = (volatile uint8_t*) dst_buf;
    src = (const volatile uint8_t*) src_buf;

    if ((dst == NULL) || (src == NULL)) {
        LIBSPDM_ASSERT(0);
    }
    if (((src < dst) && ((src + src_len) > dst)) || ((dst < src) && ((dst + src_len) > src))) {
        LIBSPDM_ASSERT(0);
    }
    if (src_len > dst_len) {
        LIBSPDM_ASSERT(0);
    }

    while (src_len-- != 0) {
        *(dst++) = *(src++);
    }
}
