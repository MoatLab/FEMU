;------------------------------------------------------------------------------
;
; Copyright (c) 2006, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
; Module Name:
;
;   ReadTsc.Asm
;
; Abstract:
;
;   AsmReadTsc function
;
; Notes:
;
;------------------------------------------------------------------------------

    DEFAULT REL
    SECTION .text

;------------------------------------------------------------------------------
; UINT64
; EFIAPI
; AsmReadTsc (
;   VOID
;   );
;------------------------------------------------------------------------------
global ASM_PFX(AsmReadTsc)
ASM_PFX(AsmReadTsc):
    rdtsc
    shl     rdx, 0x20
    or      rax, rdx
    ret

