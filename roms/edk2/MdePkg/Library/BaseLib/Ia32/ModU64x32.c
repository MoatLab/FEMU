/** @file
  Calculate the remainder of a 64-bit integer by a 32-bit integer

  Copyright (c) 2006 - 2008, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

/**
  Divides a 64-bit unsigned integer by a 32-bit unsigned integer and
  generates a 32-bit unsigned remainder.

  This function divides the 64-bit unsigned value Dividend by the 32-bit
  unsigned value Divisor and generates a 32-bit remainder. This function
  returns the 32-bit unsigned remainder.

  @param  Dividend  A 64-bit unsigned value.
  @param  Divisor   A 32-bit unsigned value.

  @return Dividend % Divisor

**/
UINT32
EFIAPI
InternalMathModU64x32 (
  IN      UINT64  Dividend,
  IN      UINT32  Divisor
  )
{
  _asm {
    mov     eax, dword ptr [Dividend + 4]
    mov     ecx, Divisor
    xor     edx, edx
    div     ecx
    mov     eax, dword ptr [Dividend + 0]
    div     ecx
    mov     eax, edx
  }
}
