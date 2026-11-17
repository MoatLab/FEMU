/*
 * arm sysarch() system call emulation
 *
 * Copyright (c) 2013 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_SYSARCH_H
#define TARGET_ARCH_SYSARCH_H

#include "target_syscall.h"
#include "target_arch.h"

static inline abi_long do_freebsd_arch_sysarch(CPUARMState *env, int op,
        abi_ulong parms)
{
    int ret = 0;

    switch (op) {
    case TARGET_FREEBSD_ARM_SYNC_ICACHE:
    case TARGET_FREEBSD_ARM_DRAIN_WRITEBUF:
        break;

    case TARGET_FREEBSD_ARM_SET_TP:
        target_cpu_set_tls(env, parms);
        break;

    case TARGET_FREEBSD_ARM_GET_TP:
        ret = target_cpu_get_tls(env);
        break;

    default:
        ret = -TARGET_EINVAL;
        break;
    }
    return ret;
}

static inline void do_freebsd_arch_print_sysarch(
        const struct syscallname *name, abi_long arg1, abi_long arg2,
        abi_long arg3, abi_long arg4, abi_long arg5, abi_long arg6)
{

    switch (arg1) {
    case TARGET_FREEBSD_ARM_SYNC_ICACHE:
        gemu_log("%s(ARM_SYNC_ICACHE, ...)", name->name);
        break;

    case TARGET_FREEBSD_ARM_DRAIN_WRITEBUF:
        gemu_log("%s(ARM_DRAIN_WRITEBUF, ...)", name->name);
        break;

    case TARGET_FREEBSD_ARM_SET_TP:
        gemu_log("%s(ARM_SET_TP, 0x" TARGET_ABI_FMT_lx ")", name->name, arg2);
        break;

    case TARGET_FREEBSD_ARM_GET_TP:
        gemu_log("%s(ARM_GET_TP, 0x" TARGET_ABI_FMT_lx ")", name->name, arg2);
        break;

    default:
        gemu_log("UNKNOWN OP: %d, " TARGET_ABI_FMT_lx ")", (int)arg1, arg2);
    }
}

#endif /* TARGET_ARCH_SYSARCH_H */
