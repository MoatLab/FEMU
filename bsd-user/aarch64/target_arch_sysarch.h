/*
 * ARM AArch64 sysarch() system call emulation for bsd-user.
 *
 * Copyright (c) 2015 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_SYSARCH_H
#define TARGET_ARCH_SYSARCH_H

#include "target_syscall.h"
#include "target_arch.h"

/* See sysarch() in sys/arm64/arm64/sys_machdep.c */
static inline abi_long do_freebsd_arch_sysarch(CPUARMState *env, int op,
        abi_ulong parms)
{
    int ret = -TARGET_EOPNOTSUPP;

    fprintf(stderr, "sysarch");
    return ret;
}

static inline void do_freebsd_arch_print_sysarch(
        const struct syscallname *name, abi_long arg1, abi_long arg2,
        abi_long arg3, abi_long arg4, abi_long arg5, abi_long arg6)
{
}

#endif /* TARGET_ARCH_SYSARCH_H */
