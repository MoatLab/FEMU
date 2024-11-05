;------------------------------------------------------------------------------
;
; Copyright (c) 2006, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
; Module Name:
;
;   SetMem64.nasm
;
; Abstract:
;
;   SetMem64 function
;
; Notes:
;
;------------------------------------------------------------------------------

    DEFAULT REL
    SECTION .text

;------------------------------------------------------------------------------
;  VOID *
;  InternalMemSetMem64 (
;    IN VOID   *Buffer,
;    IN UINTN  Count,
;    IN UINT64 Value
;    )
;------------------------------------------------------------------------------
global ASM_PFX(InternalMemSetMem64)
ASM_PFX(InternalMemSetMem64):
    mov     rax, rcx                    ; rax <- Buffer
    xchg    rcx, rdx                    ; rcx <- Count & rdx <- Buffer
    test    dl, 8
    movq    xmm0, r8
    jz      .0
    mov     [rdx], r8
    add     rdx, 8
    dec     rcx
.0:
    push    rbx
    mov     rbx, rcx
    and     rbx, 7
    shr     rcx, 3
    jz      @SetQwords
    movlhps xmm0, xmm0
.1:
    movntdq [rdx], xmm0
    movntdq [rdx + 16], xmm0
    movntdq [rdx + 32], xmm0
    movntdq [rdx + 48], xmm0
    lea     rdx, [rdx + 64]
    loop    .1
    mfence
@SetQwords:
    push    rdi
    mov     rcx, rbx
    mov     rax, r8
    mov     rdi, rdx
    rep     stosq
    pop     rdi
.2:
    pop rbx
    ret

