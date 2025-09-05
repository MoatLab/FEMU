/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/*
 * Floating point to integer conversion.
 */
__declspec(naked) void _ftol2(void)
{
    _asm {
        fistp qword ptr [esp-8]
        mov edx, [esp-4]
        mov eax, [esp-8]
        ret
    }
}
