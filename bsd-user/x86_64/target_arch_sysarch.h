/*
 * x86_64 sysarch() syscall emulation
 *
 * Copyright (c) 2013 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_SYSARCH_H
#define TARGET_ARCH_SYSARCH_H

#include "target_syscall.h"

static inline abi_long do_freebsd_arch_sysarch(CPUX86State *env, int op,
        abi_ulong parms)
{
    abi_long ret = 0;
    abi_ulong val;
    int idx;

    switch (op) {
    case TARGET_FREEBSD_AMD64_SET_GSBASE:
    case TARGET_FREEBSD_AMD64_SET_FSBASE:
        if (op == TARGET_FREEBSD_AMD64_SET_GSBASE) {
            idx = R_GS;
        } else {
            idx = R_FS;
        }
        if (get_user(val, parms, abi_ulong)) {
            return -TARGET_EFAULT;
        }
        cpu_x86_load_seg(env, idx, 0);
        env->segs[idx].base = val;
        break;

    case TARGET_FREEBSD_AMD64_GET_GSBASE:
    case TARGET_FREEBSD_AMD64_GET_FSBASE:
        if (op == TARGET_FREEBSD_AMD64_GET_GSBASE) {
            idx = R_GS;
        } else {
            idx = R_FS;
        }
        val = env->segs[idx].base;
        if (put_user(val, parms, abi_ulong)) {
            return -TARGET_EFAULT;
        }
        break;

    /* XXX handle the others... */
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

    gemu_log("%s(%d, " TARGET_ABI_FMT_lx ", " TARGET_ABI_FMT_lx ", "
        TARGET_ABI_FMT_lx ")", name->name, (int)arg1, arg2, arg3, arg4);
}

#endif /* TARGET_ARCH_SYSARCH_H */
