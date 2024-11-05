;------------------------------------------------------------------------------
;
; Copyright (c) 2006 - 2010, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
; Module Name:
;
;   WriteIdtr.Asm
;
; Abstract:
;
;   AsmWriteIdtr function
;
; Notes:
;
;------------------------------------------------------------------------------

    DEFAULT REL
    SECTION .text

;------------------------------------------------------------------------------
; VOID
; EFIAPI
; InternalX86WriteIdtr (
;   IN      CONST IA32_DESCRIPTOR     *Idtr
;   );
;------------------------------------------------------------------------------
global ASM_PFX(InternalX86WriteIdtr)
ASM_PFX(InternalX86WriteIdtr):
    pushfq
    cli
    lidt    [rcx]
    popfq
    ret

