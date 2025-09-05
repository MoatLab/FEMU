/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*
 * Shifts a 64-bit signed value right by a certain number of bits.
 */
__declspec(naked) void __cdecl _allshr(void)
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
        sar edx, cl
            ret

        ;
        ; Handle shifting of 32-63 bits
        ;
More32:
        mov eax, edx
        sar edx, 31
        and cl, 31
        sar eax, cl
        ret

        ;
        ; Return 0 or -1, depending on the sign of edx
        ;
_Exit:
        sar edx, 31
        mov eax, edx
        ret
    }
}
