;------------------------------------------------------------------------------ ;
; Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
;-------------------------------------------------------------------------------

%include "Nasm.inc"

DEFAULT REL
SECTION .text

global ASM_PFX(DisableCet)
ASM_PFX(DisableCet):

    ; Skip the pushed data for call
    mov     rax, 1
    INCSSP_RAX

    mov     rax, cr4
    btr     eax, 23                      ; clear CET
    mov     cr4, rax
    ret

global ASM_PFX(EnableCet)
ASM_PFX(EnableCet):

    mov     rax, cr4
    bts     eax, 23                      ; set CET
    mov     cr4, rax

    ; use jmp to skip the check for ret
    pop     rax
    jmp     rax

