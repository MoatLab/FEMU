/*
 * FreeBSD arm register structures
 *
 * Copyright (c) 2015 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_REG_H
#define TARGET_ARCH_REG_H

/* See sys/arm/include/reg.h */
typedef struct target_reg {
    uint32_t        r[13];
    uint32_t        r_sp;
    uint32_t        r_lr;
    uint32_t        r_pc;
    uint32_t        r_cpsr;
} target_reg_t;

typedef struct target_fp_reg {
    uint32_t        fp_exponent;
    uint32_t        fp_mantissa_hi;
    u_int32_t       fp_mantissa_lo;
} target_fp_reg_t;

typedef struct target_fpreg {
    uint32_t        fpr_fpsr;
    target_fp_reg_t fpr[8];
} target_fpreg_t;

#define tswapreg(ptr)   tswapal(ptr)

static inline void target_copy_regs(target_reg_t *regs, const CPUARMState *env)
{
    int i;

    for (i = 0; i < 13; i++) {
        regs->r[i] = tswapreg(env->regs[i + 1]);
    }
    regs->r_sp = tswapreg(env->regs[13]);
    regs->r_lr = tswapreg(env->regs[14]);
    regs->r_pc = tswapreg(env->regs[15]);
    regs->r_cpsr = tswapreg(cpsr_read((CPUARMState *)env));
}

#undef tswapreg

#endif /* TARGET_ARCH_REG_H */
