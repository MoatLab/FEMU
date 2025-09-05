/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"

uint64_t internal_math_mult_u64x64(uint64_t multiplicand, uint64_t multiplier)
{
    _asm {
        mov ebx, dword ptr [multiplicand + 0]
        mov edx, dword ptr [multiplier + 0]
        mov ecx, ebx
        mov eax, edx
        imul ebx, dword ptr [multiplier + 4]
        imul edx, dword ptr [multiplicand + 4]
        add ebx, edx
        mul ecx
        add edx, ebx
    }
}

uint64_t mult_u64x64(uint64_t multiplicand, uint64_t multiplier)
{
    uint64_t result;

    result = internal_math_mult_u64x64(multiplicand, multiplier);

    return result;
}

int64_t mult_s64x64(const int64_t multiplicand, const int64_t multiplier)
{
    return (int64_t)mult_u64x64((uint64_t)multiplicand, (uint64_t)multiplier);
}

/*
 * Multiplies a 64-bit signed or unsigned value by a 64-bit signed or unsigned value
 * and returns a 64-bit result.
 */
__declspec(naked) void __cdecl _allmul(void)
{

    /*    int64_t
     *            mult_s64x64 (
     *      const      int64_t      multiplicand,
     *      const      int64_t      multiplier
     *      )*/

    _asm {
        ; Original local stack when calling _allmul
        ;               -----------------
        ;               |               |
        ;               |--------------- |
        ;               |               |
        ;               |--multiplier--|
        ;               |               |
        ;               |--------------- |
        ;               |               |
        ;               |--multiplicand- |
        ;               |               |
        ;               |--------------- |
        ;               |  ReturnAddr** |
        ;       ESP---->|--------------- |
        ;

        ;
        ; Set up the local stack for multiplicand parameter
        ;
        mov eax, [esp + 16]
        push eax
        mov eax, [esp + 16]
        push eax

        ;
        ; Set up the local stack for multiplier parameter
        ;
        mov eax, [esp + 16]
        push eax
        mov eax, [esp + 16]
        push eax

        ;
        ; Call native MulS64x64 of BaseLib
        ;
        call mult_s64x64

        ;
        ; Adjust stack
        ;
        add esp, 16

        ret  16
    }
}
