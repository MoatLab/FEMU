/*
 * ARM AArch64 specific CPU for bsd-user
 *
 * Copyright (c) 2015 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "target_arch.h"

/* See cpu_set_user_tls() in arm64/arm64/vm_machdep.c */
void target_cpu_set_tls(CPUARMState *env, target_ulong newtls)
{
    env->cp15.tpidr_el[0] = newtls;
}

target_ulong target_cpu_get_tls(CPUARMState *env)
{
    return env->cp15.tpidr_el[0];
}
