/*
 * ARM AArch64 thread support for bsd-user.
 *
 * Copyright (c) 2015 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_THREAD_H
#define TARGET_ARCH_THREAD_H

/* Compare to arm64/arm64/vm_machdep.c cpu_set_upcall_kse() */
static inline void target_thread_set_upcall(CPUARMState *regs, abi_ulong entry,
    abi_ulong arg, abi_ulong stack_base, abi_ulong stack_size)
{
    abi_ulong sp;

    /*
     * Make sure the stack is properly aligned.
     * arm64/include/param.h (STACKLIGN() macro)
     */
    sp = ROUND_DOWN(stack_base + stack_size, 16);

    /* sp = stack base */
    regs->xregs[31] = sp;
    /* pc = start function entry */
    regs->pc = entry;
    /* r0 = arg */
    regs->xregs[0] = arg;

    
}

static inline void target_thread_init(struct target_pt_regs *regs,
        struct image_info *infop)
{
    abi_long stack = infop->start_stack;

    /*
     * Make sure the stack is properly aligned.
     * arm64/include/param.h (STACKLIGN() macro)
     */

    memset(regs, 0, sizeof(*regs));
    regs->regs[0] = infop->start_stack;
    regs->pc = infop->entry;
    regs->sp = ROUND_DOWN(stack, 16);
}

#endif /* TARGET_ARCH_THREAD_H */
