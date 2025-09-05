/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "hal/base.h"

uint64_t internal_math_div_rem_u64x32(uint64_t dividend, uint32_t divisor,
                                      uint32_t *remainder)
{
    _asm {
        mov ecx, divisor
        mov eax, dword ptr [dividend + 4]
        xor edx, edx
        div ecx
        push eax
        mov eax, dword ptr [dividend + 0]
        div ecx
        mov ecx, remainder
        jecxz RemainderNull /* abandon remainder if remainder == NULL*/
            mov     [ecx], edx
RemainderNull:
        pop edx
    }
}

__declspec(naked) uint64_t
internal_math_div_rem_u64x64(uint64_t dividend, uint64_t divisor,
                             uint64_t *remainder)
{
    _asm {
        mov ecx, [esp + 16]; ecx <-divisor[32..63]
        test ecx, ecx
        jnz ___DivRemU64x64; call _@DivRemU64x64 if divisor > 2^32
        mov ecx, [esp + 20]
        jecxz __0
        and     [ecx + 4], 0; zero high dword of remainder
            mov     [esp + 16], ecx; set up stack frame to match DivRemU64x32
__0:
        jmp internal_math_div_rem_u64x32

___DivRemU64x64:
        push ebx
        push esi
        push edi
        mov edx, [esp + 20]
        mov eax, [esp + 16]; edx:eax <-dividend
        mov edi, edx
        mov esi, eax; edi:esi <-dividend
        mov ebx, [esp + 24]; ecx:ebx <-divisor
__1:
        shr edx, 1
        rcr eax, 1
        shrd ebx, ecx, 1
        shr ecx, 1
        jnz __1
        div ebx
        mov ebx, eax; ebx <-quotient
        mov ecx, [esp + 28]; ecx <-high dword of divisor
        mul     [esp + 24]; edx:eax <-quotient * divisor[0..31]
        imul ecx, ebx; ecx <-quotient * divisor[32..63]
        add edx, ecx; edx <-(quotient * divisor)[32..63]
        mov ecx, [esp + 32]; ecx <-addr for remainder
        jc __TooLarge; product > 2^64
        cmp edi, edx; compare high 32 bits
        ja __Correct
        jb __TooLarge; product > dividend
        cmp esi, eax
        jae __Correct; product <= dividend
__TooLarge:
        dec ebx; adjust quotient by -1
        jecxz __Return; return if remainder == NULL
               sub eax, [esp + 24]
               sbb edx, [esp + 28]; edx:eax <-(quotient - 1) * divisor
__Correct:
        jecxz __Return
        sub esi, eax
        sbb edi, edx; edi:esi <-remainder
        mov     [ecx], esi
        mov     [ecx + 4], edi
__Return:
        mov eax, ebx; eax <-quotient
        xor edx, edx; quotient is 32 bits long
        pop edi
        pop esi
        pop ebx
                               ret
    }
}

uint64_t div_u64x64_remainder(uint64_t dividend, uint64_t divisor,
                              uint64_t *remainder)
{
    return internal_math_div_rem_u64x64(dividend, divisor, remainder);
}

/*
 * Divides a 64-bit unsigned value with a 64-bit unsigned value and returns
 * a 64-bit unsigned result and 64-bit unsigned remainder.
 */
__declspec(naked) void __cdecl _aulldvrm(void)
{

    /*    uint64_t
     *            div_u64x64_remainder (
     *      const      uint64_t     dividend,
     *      const      uint64_t     divisor,
     *          uint64_t     *remainder
     *      )*/

    _asm {

        ; Original local stack when calling _aulldvrm
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
