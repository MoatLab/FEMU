/*
 * FreeBSD dependent strace print functions
 *
 * Copyright (c) 2013 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "target_arch_sysarch.h"    /* architecture dependent functions */

static inline void do_os_print_sysarch(const struct syscallname *name,
        abi_long arg1, abi_long arg2, abi_long arg3, abi_long arg4,
        abi_long arg5, abi_long arg6)
{
    /* This is arch dependent */
    do_freebsd_arch_print_sysarch(name, arg1, arg2, arg3, arg4, arg5, arg6);
}
