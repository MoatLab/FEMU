/** @file
  AsmReadDr1 function

  Copyright (c) 2006 - 2008, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

/**
  Reads the current value of Debug Register 1 (DR1).

  Reads and returns the current value of DR1. This function is only available
  on IA-32 and x64. This returns a 32-bit value on IA-32 and a 64-bit value on
  x64.

  @return The value of Debug Register 1 (DR1).

**/
UINTN
EFIAPI
AsmReadDr1 (
  VOID
  )
{
  __asm {
    mov     eax, dr1
  }
}
