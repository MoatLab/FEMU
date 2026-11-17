/*
 * FreeBSD arm64 register structures
 *
 * Copyright (c) 2015 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_REG_H
#define TARGET_ARCH_REG_H

/* See sys/arm64/include/reg.h */
typedef struct target_reg {
    uint64_t        x[30];
    uint64_t        lr;
    uint64_t        sp;
    uint64_t        elr;
    uint64_t        spsr;
} target_reg_t;

typedef struct target_fpreg {
    Int128          fp_q[32];
    uint32_t        fp_sr;
    uint32_t        fp_cr;
} target_fpreg_t;

#define tswapreg(ptr)   tswapal(ptr)

static inline void target_copy_regs(target_reg_t *regs, CPUARMState *env)
{
    int i;

    for (i = 0; i < 30; i++) {
        regs->x[i] = tswapreg(env->xregs[i]);
    }
    regs->lr = tswapreg(env->xregs[30]);
    regs->sp = tswapreg(env->xregs[31]);
    regs->elr = tswapreg(env->pc);
    regs->spsr = tswapreg(pstate_read(env));
}

#undef tswapreg

#endif /* TARGET_ARCH_REG_H */
