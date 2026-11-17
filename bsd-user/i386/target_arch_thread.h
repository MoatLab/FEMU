/*
 * i386 thread support
 *
 * Copyright (c) 2013 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_THREAD_H
#define TARGET_ARCH_THREAD_H

/* Compare to vm_machdep.c cpu_set_upcall_kse() */
static inline void target_thread_set_upcall(CPUX86State *regs, abi_ulong entry,
    abi_ulong arg, abi_ulong stack_base, abi_ulong stack_size)
{
    /* XXX */
}

static inline void target_thread_init(struct target_pt_regs *regs,
        struct image_info *infop)
{
    regs->esp = infop->start_stack;
    regs->eip = infop->entry;

    /*
     * SVR4/i386 ABI (pages 3-31, 3-32) says that when the program starts %edx
     * contains a pointer to a function which might be registered using
     * `atexit'.  This provides a mean for the dynamic linker to call DT_FINI
     * functions for shared libraries that have been loaded before the code
     * runs.
     *
     * A value of 0 tells we have no such handler.
     */
    regs->edx = 0;
}

#endif /* TARGET_ARCH_THREAD_H */
