;------------------------------------------------------------------------------ ;
; Copyright (c) 2012 - 2018, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
; Module Name:
;
;   ExceptionHandlerAsm.Asm
;
; Abstract:
;
;   x64 CPU Exception Handler
;
; Notes:
;
;------------------------------------------------------------------------------
%include "Nasm.inc"

;
; Equivalent NASM structure of IA32_DESCRIPTOR
;
struc IA32_DESCRIPTOR
  .Limit                         CTYPE_UINT16 1
  .Base                          CTYPE_UINTN  1
endstruc

;
; Equivalent NASM structure of IA32_IDT_GATE_DESCRIPTOR
;
struc IA32_IDT_GATE_DESCRIPTOR
  .OffsetLow                     CTYPE_UINT16 1
  .Selector                      CTYPE_UINT16 1
  .Reserved_0                    CTYPE_UINT8 1
  .GateType                      CTYPE_UINT8 1
  .OffsetHigh                    CTYPE_UINT16 1
  .OffsetUpper                   CTYPE_UINT32 1
  .Reserved_1                    CTYPE_UINT32 1
endstruc

;
; CommonExceptionHandler()
;

%define VC_EXCEPTION 29

extern ASM_PFX(mErrorCodeFlag)    ; Error code flags for exceptions
extern ASM_PFX(mDoFarReturnFlag)  ; Do far return flag
extern ASM_PFX(CommonExceptionHandler)

SECTION .data

DEFAULT REL
SECTION .text

ALIGN   8

AsmIdtVectorBegin:
%rep  32
    db      0x6a        ; push  #VectorNum
    db      ($ - AsmIdtVectorBegin) / ((AsmIdtVectorEnd - AsmIdtVectorBegin) / 32) ; VectorNum
    push    rax
    mov     rax, strict qword 0 ;    mov     rax, ASM_PFX(CommonInterruptEntry)
    jmp     rax
%endrep
AsmIdtVectorEnd:

HookAfterStubHeaderBegin:
    db      0x6a        ; push
@VectorNum:
    db      0          ; 0 will be fixed
    push    rax
    mov     rax, strict qword 0 ;     mov     rax, HookAfterStubHeaderEnd
JmpAbsoluteAddress:
    jmp     rax
HookAfterStubHeaderEnd:
    mov     rax, rsp
    and     sp,  0xfff0        ; make sure 16-byte aligned for exception context
    sub     rsp, 0x18           ; reserve room for filling exception data later
    push    rcx
    mov     rcx, [rax + 8]
    bt      [ASM_PFX(mErrorCodeFlag)], ecx
    jnc     .0
    push    qword [rsp]             ; push additional rcx to make stack alignment
.0:
    xchg    rcx, [rsp]        ; restore rcx, save Exception Number in stack
    push    qword [rax]             ; push rax into stack to keep code consistence

;---------------------------------------;
; CommonInterruptEntry                  ;
;---------------------------------------;
; The follow algorithm is used for the common interrupt routine.
; Entry from each interrupt with a push eax and eax=interrupt number
; Stack frame would be as follows as specified in IA32 manuals:
;
; +---------------------+ <-- 16-byte aligned ensured by processor
; +    Old SS           +
; +---------------------+
; +    Old RSP          +
; +---------------------+
; +    RFlags           +
; +---------------------+
; +    CS               +
; +---------------------+
; +    RIP              +
; +---------------------+
; +    Error Code       +
; +---------------------+
; +   Vector Number     +
; +---------------------+
; +    RBP              +
; +---------------------+ <-- RBP, 16-byte aligned
; The follow algorithm is used for the common interrupt routine.
global ASM_PFX(CommonInterruptEntry)
ASM_PFX(CommonInterruptEntry):
    cli
    pop     rax
    ;
    ; All interrupt handlers are invoked through interrupt gates, so
    ; IF flag automatically cleared at the entry point
    ;
    xchg    rcx, [rsp]      ; Save rcx into stack and save vector number into rcx
    and     rcx, 0xFF
    cmp     ecx, 32         ; Intel reserved vector for exceptions?
    jae     NoErrorCode
    bt      [ASM_PFX(mErrorCodeFlag)], ecx
    jc      HasErrorCode

NoErrorCode:

    ;
    ; Push a dummy error code on the stack
    ; to maintain coherent stack map
    ;
    push    qword [rsp]
    mov     qword [rsp + 8], 0
HasErrorCode:
    push    rbp
    mov     rbp, rsp
    push    0             ; clear EXCEPTION_HANDLER_CONTEXT.OldIdtHandler
    push    0             ; clear EXCEPTION_HANDLER_CONTEXT.ExceptionDataFlag

    ;
    ; Stack:
    ; +---------------------+ <-- 16-byte aligned ensured by processor
    ; +    Old SS           +
    ; +---------------------+
    ; +    Old RSP          +
    ; +---------------------+
    ; +    RFlags           +
    ; +---------------------+
    ; +    CS               +
    ; +---------------------+
    ; +    RIP              +
    ; +---------------------+
    ; +    Error Code       +
    ; +---------------------+
    ; + RCX / Vector Number +
    ; +---------------------+
    ; +    RBP              +
    ; +---------------------+ <-- RBP, 16-byte aligned
    ;

    ;
    ; Since here the stack pointer is 16-byte aligned, so
    ; EFI_FX_SAVE_STATE_X64 of EFI_SYSTEM_CONTEXT_x64
    ; is 16-byte aligned
    ;

;; UINT64  Rdi, Rsi, Rbp, Rsp, Rbx, Rdx, Rcx, Rax;
;; UINT64  R8, R9, R10, R11, R12, R13, R14, R15;
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rax
    push qword [rbp + 8]   ; RCX
    push rdx
    push rbx
    push qword [rbp + 48]  ; RSP
    push qword [rbp]       ; RBP
    push rsi
    push rdi

;; UINT64  Gs, Fs, Es, Ds, Cs, Ss;  insure high 16 bits of each is zero
    movzx   rax, word [rbp + 56]
    push    rax                      ; for ss
    movzx   rax, word [rbp + 32]
    push    rax                      ; for cs
    mov     rax, ds
    push    rax
    mov     rax, es
    push    rax
    mov     rax, fs
    push    rax
    mov     rax, gs
    push    rax

    mov     [rbp + 8], rcx               ; save vector number

;; UINT64  Rip;
    push    qword [rbp + 24]

;; UINT64  Gdtr[2], Idtr[2];
    xor     rax, rax
    push    rax
    push    rax
    sidt    [rsp]
    mov     bx, word [rsp]
    mov     rax, qword [rsp + 2]
    mov     qword [rsp], rax
    mov     word [rsp + 8], bx

    xor     rax, rax
    push    rax
    push    rax
    sgdt    [rsp]
    mov     bx, word [rsp]
    mov     rax, qword [rsp + 2]
    mov     qword [rsp], rax
    mov     word [rsp + 8], bx

;; UINT64  Ldtr, Tr;
    xor     rax, rax
    str     ax
    push    rax
    sldt    ax
    push    rax

;; UINT64  RFlags;
    push    qword [rbp + 40]

;; UINT64  Cr0, Cr1, Cr2, Cr3, Cr4, Cr8;
    mov     rax, cr8
    push    rax
    mov     rax, cr4
    or      rax, 0x208
    mov     cr4, rax
    push    rax
    mov     rax, cr3
    push    rax
    mov     rax, cr2
    push    rax
    xor     rax, rax
    push    rax
    mov     rax, cr0
    push    rax

;; UINT64  Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    cmp     qword [rbp + 8], VC_EXCEPTION
    je      VcDebugRegs          ; For SEV-ES (#VC) Debug registers ignored

    mov     rax, dr7
    push    rax
    mov     rax, dr6
    push    rax
    mov     rax, dr3
    push    rax
    mov     rax, dr2
    push    rax
    mov     rax, dr1
    push    rax
    mov     rax, dr0
    push    rax
    jmp     DrFinish

VcDebugRegs:
;; UINT64  Dr0, Dr1, Dr2, Dr3, Dr6, Dr7 are skipped for #VC to avoid exception recursion
    xor     rax, rax
    push    rax
    push    rax
    push    rax
    push    rax
    push    rax
    push    rax

DrFinish:
;; FX_SAVE_STATE_X64 FxSaveState;
    sub rsp, 512
    mov rdi, rsp
    db 0xf, 0xae, 0x7 ;fxsave [rdi]

;; UEFI calling convention for x64 requires that Direction flag in EFLAGs is clear
    cld

;; UINT32  ExceptionData;
    push    qword [rbp + 16]

;; Prepare parameter and call
    mov     rcx, [rbp + 8]
    mov     rdx, rsp
    ;
    ; Per X64 calling convention, allocate maximum parameter stack space
    ; and make sure RSP is 16-byte aligned
    ;
    sub     rsp, 4 * 8 + 8
    call    ASM_PFX(CommonExceptionHandler)
    add     rsp, 4 * 8 + 8

    ; The follow algorithm is used for clear shadow stack token busy bit.
    ; The comment is based on the sample shadow stack.
    ; Shadow stack is 32 bytes aligned.
    ; The sample shadow stack layout :
    ; Address | Context
    ;         +-------------------------+
    ;  0xFB8  |   FREE                  | It is 0xFC0|0x02|(LMA & CS.L), after SAVEPREVSSP.
    ;         +-------------------------+
    ;  0xFC0  |  Prev SSP               |
    ;         +-------------------------+
    ;  0xFC8  |   RIP                   |
    ;         +-------------------------+
    ;  0xFD0  |   CS                    |
    ;         +-------------------------+
    ;  0xFD8  |  0xFD8 | BUSY           | BUSY flag cleared after CLRSSBSY
    ;         +-------------------------+
    ;  0xFE0  | 0xFC0|0x02|(LMA & CS.L) |
    ;         +-------------------------+
    ; Instructions for Intel Control Flow Enforcement Technology (CET) are supported since NASM version 2.15.01.
    cmp     qword [ASM_PFX(mDoFarReturnFlag)], 0
    jz      CetDone
    mov     rax, cr4
    and     rax, 0x800000       ; Check if CET is enabled
    jz      CetDone
    sub     rsp, 0x10
    sidt    [rsp]
    mov     rcx, qword [rsp + IA32_DESCRIPTOR.Base]; Get IDT base address
    add     rsp, 0x10
    mov     rax, qword [rbp + 8]; Get exception number
    sal     rax, 0x04           ; Get IDT offset
    add     rax, rcx            ; Get IDT gate descriptor address
    mov     al, byte [rax + IA32_IDT_GATE_DESCRIPTOR.Reserved_0]
    and     rax, 0x01           ; Check IST field
    jz      CetDone
                                ; SSP should be 0xFC0 at this point
    mov     rax, 0x04           ; advance past cs:lip:prevssp;supervisor shadow stack token
    INCSSP_RAX                  ; After this SSP should be 0xFE0
    SAVEPREVSSP                 ; now the shadow stack restore token will be created at 0xFB8
    READSSP_RAX                 ; Read new SSP, SSP should be 0xFE8
    sub     rax, 0x10
    CLRSSBSY_RAX                ; Clear token at 0xFD8, SSP should be 0 after this
    sub     rax, 0x20
    RSTORSSP_RAX                ; Restore to token at 0xFB8, new SSP will be 0xFB8
    mov     rax, 0x01           ; Pop off the new save token created
    INCSSP_RAX                  ; SSP should be 0xFC0 now
CetDone:

    cli
;; UINT64  ExceptionData;
    add     rsp, 8

;; FX_SAVE_STATE_X64 FxSaveState;

    mov rsi, rsp
    db 0xf, 0xae, 0xE ; fxrstor [rsi]
    add rsp, 512

;; UINT64  Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
;; Skip restoration of DRx registers to support in-circuit emualators
;; or debuggers set breakpoint in interrupt/exception context
    add     rsp, 8 * 6

;; UINT64  Cr0, Cr1, Cr2, Cr3, Cr4, Cr8;
    pop     rax
    mov     cr0, rax
    add     rsp, 8   ; not for Cr1
    pop     rax
    mov     cr2, rax
    pop     rax
    mov     cr3, rax
    pop     rax
    mov     cr4, rax
    pop     rax
    mov     cr8, rax

;; UINT64  RFlags;
    pop     qword [rbp + 40]

;; UINT64  Ldtr, Tr;
;; UINT64  Gdtr[2], Idtr[2];
;; Best not let anyone mess with these particular registers...
    add     rsp, 48

;; UINT64  Rip;
    pop     qword [rbp + 24]

;; UINT64  Gs, Fs, Es, Ds, Cs, Ss;
    pop     rax
    ; mov     gs, rax ; not for gs
    pop     rax
    ; mov     fs, rax ; not for fs
    ; (X64 will not use fs and gs, so we do not restore it)
    pop     rax
    mov     es, rax
    pop     rax
    mov     ds, rax
    pop     qword [rbp + 32]  ; for cs
    pop     qword [rbp + 56]  ; for ss

;; UINT64  Rdi, Rsi, Rbp, Rsp, Rbx, Rdx, Rcx, Rax;
;; UINT64  R8, R9, R10, R11, R12, R13, R14, R15;
    pop     rdi
    pop     rsi
    add     rsp, 8               ; not for rbp
    pop     qword [rbp + 48] ; for rsp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15

    mov     rsp, rbp
    pop     rbp
    add     rsp, 16
    cmp     qword [rsp - 32], 0  ; check EXCEPTION_HANDLER_CONTEXT.OldIdtHandler
    jz      DoReturn
    cmp     qword [rsp - 40], 1  ; check EXCEPTION_HANDLER_CONTEXT.ExceptionDataFlag
    jz      ErrorCode
    jmp     qword [rsp - 32]
ErrorCode:
    sub     rsp, 8
    jmp     qword [rsp - 24]

DoReturn:
    cmp     qword [ASM_PFX(mDoFarReturnFlag)], 0   ; Check if need to do far return instead of IRET
    jz      DoIret
    push    rax
    mov     rax, rsp          ; save old RSP to rax
    mov     rsp, [rsp + 0x20]
    push    qword [rax + 0x10]       ; save CS in new location
    push    qword [rax + 0x8]        ; save EIP in new location
    push    qword [rax + 0x18]       ; save EFLAGS in new location
    mov     rax, [rax]        ; restore rax
    popfq                     ; restore EFLAGS
    DB      0x48                ; prefix to composite "retq" with next "retf"
    retf                        ; far return
DoIret:
    iretq

;-------------------------------------------------------------------------------------
;  GetTemplateAddressMap (&AddressMap);
;-------------------------------------------------------------------------------------
; comments here for definition of address map
global ASM_PFX(AsmGetTemplateAddressMap)
ASM_PFX(AsmGetTemplateAddressMap):
    lea     rax, [AsmIdtVectorBegin]
    mov     qword [rcx], rax
    mov     qword [rcx + 0x8],  (AsmIdtVectorEnd - AsmIdtVectorBegin) / 32
    lea     rax, [HookAfterStubHeaderBegin]
    mov     qword [rcx + 0x10], rax

; Fix up CommonInterruptEntry address
    lea    rax, [ASM_PFX(CommonInterruptEntry)]
    lea    rcx, [AsmIdtVectorBegin]
%rep  32
    mov    qword [rcx + (JmpAbsoluteAddress - 8 - HookAfterStubHeaderBegin)], rax
    add    rcx, (AsmIdtVectorEnd - AsmIdtVectorBegin) / 32
%endrep
; Fix up HookAfterStubHeaderEnd
    lea    rax, [HookAfterStubHeaderEnd]
    lea    rcx, [JmpAbsoluteAddress]
    mov    qword [rcx - 8], rax

    ret

;-------------------------------------------------------------------------------------
;  AsmVectorNumFixup (*NewVectorAddr, VectorNum, *OldVectorAddr);
;-------------------------------------------------------------------------------------
global ASM_PFX(AsmVectorNumFixup)
ASM_PFX(AsmVectorNumFixup):
    mov     rax, rdx
    mov     [rcx + (@VectorNum - HookAfterStubHeaderBegin)], al
    ret

