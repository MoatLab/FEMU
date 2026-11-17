/*
 * arm cpu related code
 *
 * Copyright (c) 2013 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "target_arch.h"

void target_cpu_set_tls(CPUARMState *env, target_ulong newtls)
{
    if (access_secure_reg(env)) {
        env->cp15.tpidrurw_s = newtls;
        env->cp15.tpidruro_s = newtls;
        return;
    }

    env->cp15.tpidr_el[0] = newtls;
    env->cp15.tpidrro_el[0] = newtls;
}

target_ulong target_cpu_get_tls(CPUARMState *env)
{
    if (access_secure_reg(env)) {
        return env->cp15.tpidruro_s;
    }
    return env->cp15.tpidrro_el[0];
}
