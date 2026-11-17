/*
 * FreeBSD i386 register structures
 *
 * Copyright (c) 2015 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_REG_H
#define TARGET_ARCH_REG_H

/* See sys/i386/include/reg.h */
typedef struct target_reg {
    uint32_t        r_fs;
    uint32_t        r_es;
    uint32_t        r_ds;
    uint32_t        r_edi;
    uint32_t        r_esi;
    uint32_t        r_ebp;
    uint32_t        r_isp;
    uint32_t        r_ebx;
    uint32_t        r_edx;
    uint32_t        r_ecx;
    uint32_t        r_eax;
    uint32_t        r_trapno;
    uint32_t        r_err;
    uint32_t        r_eip;
    uint32_t        r_cs;
    uint32_t        r_eflags;
    uint32_t        r_esp;
    uint32_t        r_ss;
    uint32_t        r_gs;
} target_reg_t;

typedef struct target_fpreg {
    uint32_t        fpr_env[7];
    uint8_t         fpr_acc[8][10];
    uint32_t        fpr_ex_sw;
    uint8_t         fpr_pad[64];
} target_fpreg_t;

static inline void target_copy_regs(target_reg_t *regs, const CPUX86State *env)
{

    regs->r_fs = env->segs[R_FS].selector & 0xffff;
    regs->r_es = env->segs[R_ES].selector & 0xffff;
    regs->r_ds = env->segs[R_DS].selector & 0xffff;

    regs->r_edi = env->regs[R_EDI];
    regs->r_esi = env->regs[R_ESI];
    regs->r_ebp = env->regs[R_EBP];
    /* regs->r_isp = env->regs[R_ISP]; XXX */
    regs->r_ebx = env->regs[R_EBX];
    regs->r_edx = env->regs[R_EDX];
    regs->r_ecx = env->regs[R_ECX];
    regs->r_eax = env->regs[R_EAX];
    /* regs->r_trapno = env->regs[R_TRAPNO]; XXX */
    regs->r_err = env->error_code;  /* XXX ? */
    regs->r_eip = env->eip;

    regs->r_cs = env->segs[R_CS].selector & 0xffff;

    regs->r_eflags = env->eflags;
    regs->r_esp = env->regs[R_ESP];

    regs->r_ss = env->segs[R_SS].selector & 0xffff;
    regs->r_gs = env->segs[R_GS].selector & 0xffff;
}

#endif /* TARGET_ARCH_REG_H */
