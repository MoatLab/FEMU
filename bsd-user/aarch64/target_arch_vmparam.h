/*
 * ARM AArch64 VM parameters definitions for bsd-user.
 *
 * Copyright (c) 2015 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_VMPARAM_H
#define TARGET_ARCH_VMPARAM_H

#include "cpu.h"

/**
 * FreeBSD/arm64 Address space layout.
 *
 * ARMv8 implements up to a 48 bit virtual address space. The address space is
 * split into 2 regions at each end of the 64 bit address space, with an
 * out of range "hole" in the middle.
 *
 * We limit the size of the two spaces to 39 bits each.
 *
 * Upper region:        0xffffffffffffffff
 *                      0xffffff8000000000
 *
 * Hole:                0xffffff7fffffffff
 *                      0x0000008000000000
 *
 * Lower region:        0x0000007fffffffff
 *                      0x0000000000000000
 *
 * The upper region for the kernel, and the lower region for userland.
 */


/* compare to sys/arm64/include/vmparam.h */
#define TARGET_MAXTSIZ      (1 * GiB)           /* max text size */
#define TARGET_DFLDSIZ      (128 * MiB)         /* initial data size limit */
#define TARGET_MAXDSIZ      (1 * GiB)           /* max data size */
#define TARGET_DFLSSIZ      (128 * MiB)         /* initial stack size limit */
#define TARGET_MAXSSIZ      (1 * GiB)           /* max stack size */
#define TARGET_SGROWSIZ     (128 * KiB)         /* amount to grow stack */

                /* KERNBASE - 512 MB */
#define TARGET_VM_MAXUSER_ADDRESS   (0x00007fffff000000ULL - (512 * MiB))
#define TARGET_USRSTACK             TARGET_VM_MAXUSER_ADDRESS

static inline abi_ulong get_sp_from_cpustate(CPUARMState *state)
{
    return state->xregs[31]; /* sp */
}

static inline void set_second_rval(CPUARMState *state, abi_ulong retval2)
{
    state->xregs[1] = retval2; /* XXX not really used on 64-bit arch */
}

static inline abi_ulong get_second_rval(CPUARMState *state)
{
    return state->xregs[1];
}

#endif /* TARGET_ARCH_VMPARAM_H */
