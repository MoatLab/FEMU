/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*Portions of this file have been modified from the original (https://github.com/intel/linux-sgx/blob/master/sdk/compiler-rt/ashldi3.c) under the following copyright and license.*/

/**
 * Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 * See https://llvm.org/LICENSE.txt for license information.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 **/

typedef int si_int;
typedef unsigned su_int;
typedef long long di_int;

typedef union {
    di_int all;
    struct {
#if _YUGA_LITTLE_ENDIAN
        su_int low;
        si_int high;
#else
        si_int high;
        su_int low;
#endif /* _YUGA_LITTLE_ENDIAN */
    } s;
} dwords;

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

di_int __ashldi3(di_int a, int b) {
    const int bits_in_word = (int)(sizeof(si_int) * CHAR_BIT);
    dwords input;
    dwords result;
    input.all = a;
    if (b & bits_in_word) { /* bits_in_word <= b < bits_in_dword */
        result.s.low = 0;
        result.s.high = input.s.low << (b - bits_in_word);
    } else { /* 0 <= b < bits_in_word */
        if (b == 0) {
            return a;
        }
        result.s.low = input.s.low << b;
        result.s.high = (input.s.high << b) | (input.s.low >> (bits_in_word - b));
    }
    return result.all;
}
