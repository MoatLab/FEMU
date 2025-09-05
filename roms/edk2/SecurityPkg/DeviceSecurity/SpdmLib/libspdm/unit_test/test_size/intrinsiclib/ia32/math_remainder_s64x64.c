/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"

int64_t div_s64x64_remainder(const int64_t dividend, const int64_t divisor,
                             int64_t *remainder);

/*
 * Divides a 64-bit signed value by another 64-bit signed value and returns
 * the 64-bit signed remainder.
 */
__declspec(naked) void __cdecl _allrem(void)
{

    /*    int64_t
     *            div_s64x64_remainder (
     *      const      int64_t     dividend,
     *      const      int64_t     divisor,
     *          int64_t     *remainder
     *      )*/

    _asm {
        ; Original local stack when calling _allrem
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
        ; Put the Reminder in EDX:EAX as return value
        ;
        mov eax, [esp + 20]
        mov edx, [esp + 24]

        ;
        ; Adjust stack
        ;
        add esp, 28

        ret  16
    }
}
