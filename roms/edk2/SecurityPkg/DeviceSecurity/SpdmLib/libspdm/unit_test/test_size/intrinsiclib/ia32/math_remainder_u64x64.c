/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"

uint64_t div_u64x64_remainder(uint64_t dividend, uint64_t divisor,
                              uint64_t *remainder);

/*
 * Divides a 64-bit unsigned value by another 64-bit unsigned value and returns
 * the 64-bit unsigned remainder.
 */
__declspec(naked) void __cdecl _aullrem(void)
{

    /*    uint64_t
     *            div_u64x64_remainder (
     *      const      uint64_t     dividend,
     *      const      uint64_t     divisor,
     *          uint64_t     *remainder
     *      )*/

    _asm {
        ; Original local stack when calling _aullrem
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
        ; Call native div_u64x64_remainder of BaseLib
        ;
        call div_u64x64_remainder

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
