;------------------------------------------------------------------------------
;
; Copyright (c) 2006, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
; Module Name:
;
;   ReadDr2.Asm
;
; Abstract:
;
;   AsmReadDr2 function
;
; Notes:
;
;------------------------------------------------------------------------------

    DEFAULT REL
    SECTION .text

;------------------------------------------------------------------------------
; UINTN
; EFIAPI
; AsmReadDr2 (
;   VOID
;   );
;------------------------------------------------------------------------------
global ASM_PFX(AsmReadDr2)
ASM_PFX(AsmReadDr2):
    mov     rax, dr2
    ret

