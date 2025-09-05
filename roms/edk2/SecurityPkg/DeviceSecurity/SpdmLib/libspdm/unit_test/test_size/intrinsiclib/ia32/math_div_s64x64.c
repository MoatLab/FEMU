/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"

int64_t div_s64x64_remainder(const int64_t dividend, const int64_t divisor,
                             int64_t *remainder);

/*
 * Divides a 64-bit signed value with a 64-bit signed value and returns
 * a 64-bit signed result.
 */
__declspec(naked) void __cdecl _alldiv(void)
{

    /*    int64_t
     *            div_s64x64_remainder (
     *      const      int64_t     dividend,
     *      const      int64_t     divisor,
     *          int64_t     *remainder
     *      )*/

    _asm {

        ; Original local stack when calling _alldiv
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
        ; Set up the local stack for NULL Reminder pointer
        ;
        xor eax, eax
        push eax

        ;
        ; Set up the local stack for divisor parameter
        ;
        mov eax, [esp + 20]
        push eax
        mov eax, [esp + 20]
        push eax

        ;
        ; Set up the local stack for dividend parameter
        ;
        mov eax, [esp + 20]
        push eax
        mov eax, [esp + 20]
        push eax

        ;
        ; Call native div_s64x64_remainder of BaseLib
        ;
        call div_s64x64_remainder

        ;
        ; Adjust stack
        ;
        add esp, 20

        ret  16
    }
}
