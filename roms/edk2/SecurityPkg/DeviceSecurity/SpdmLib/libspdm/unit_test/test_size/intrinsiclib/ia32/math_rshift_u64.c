/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*
 * Shifts a 64-bit unsigned value right by a certain number of bits.
 */
__declspec(naked) void __cdecl _aullshr(void)
{
    _asm {
        ;
        ; Checking: Only handle 64bit shifting or more
        ;
        cmp cl, 64
        jae _Exit

        ;
        ; Handle shifting between 0 and 31 bits
        ;
        cmp cl, 32
        jae More32
        shrd eax, edx, cl
        shr edx, cl
            ret

        ;
        ; Handle shifting of 32-63 bits
        ;
More32:
        mov eax, edx
        xor edx, edx
        and cl, 31
        shr eax, cl
        ret

        ;
        ; Invalid number (less then 32bits), return 0
        ;
_Exit:
        xor eax, eax
        xor edx, edx
        ret
    }
}
