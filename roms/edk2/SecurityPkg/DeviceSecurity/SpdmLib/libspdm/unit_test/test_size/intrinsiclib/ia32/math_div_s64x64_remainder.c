/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"

uint64_t internal_math_div_rem_u64x64(uint64_t dividend, uint64_t divisor,
                                      uint64_t *remainder);

int64_t internal_math_div_rem_s64x64(const int64_t dividend, const int64_t divisor,
                                     int64_t *remainder)
{
    int64_t quot;

    quot = internal_math_div_rem_u64x64(
        (uint64_t)(dividend >= 0 ? dividend : -dividend),
        (uint64_t)(divisor >= 0 ? divisor : -divisor),
        (uint64_t *)remainder);
    if (remainder != NULL && dividend < 0) {
        *remainder = -*remainder;
    }
    return (dividend ^ divisor) >= 0 ? quot : -quot;
}

int64_t div_s64x64_remainder(const int64_t dividend, const int64_t divisor,
                             int64_t *remainder)
{
    return internal_math_div_rem_s64x64(dividend, divisor, remainder);
}

/*
 * Divides a 64-bit signed value with a 64-bit signed value and returns
 * a 64-bit signed result and 64-bit signed remainder.
 */
__declspec(naked) void __cdecl _alldvrm(void)
{

    /*    int64_t
     *            div_s64x64_remainder (
     *      const      int64_t     dividend,
     *      const      int64_t     divisor,
     *          int64_t     *remainder
     *      )*/

    _asm {

        ; Original local stack when calling _alldvrm
        ;               -----------------
        ;               |               |
        ;               |--------------- |
        ;               |               |
        ;               |--divisor--|
        ;               |               |
        ;               |--------------- |
        ;               |               |
        ;               |--dividend--|
        ;               |               |
        ;               |--------------- |
        ;               |  ReturnAddr** |
        ;       ESP---->|--------------- |
        ;

        ;
        ; Set up the local stack for Reminder pointer
        ;
        sub esp, 8
        push esp

        ;
        ; Set up the local stack for divisor parameter
        ;
        mov eax, [esp + 28]
        push eax
        mov eax, [esp + 28]
        push eax

        ;
        ; Set up the local stack for dividend parameter
        ;
        mov eax, [esp + 28]
        push eax
        mov eax, [esp + 28]
        push eax

        ;
        ; Call native div_s64x64_remainder of BaseLib
        ;
        call div_s64x64_remainder

        ;
        ; Put the Reminder in EBX:ECX as return value
        ;
        mov ecx, [esp + 20]
        mov ebx, [esp + 24]

        ;
        ; Adjust stack
        ;
        add esp, 28

        ret  16
    }
}
