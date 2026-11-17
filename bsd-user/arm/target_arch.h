/*
 * ARM 32-bit specific prototypes for bsd-user
 *
 * Copyright (c) 2013 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_ARCH_H
#define TARGET_ARCH_H

#include "qemu.h"
#include "target/arm/cpu-features.h"

void target_cpu_set_tls(CPUARMState *env, target_ulong newtls);
target_ulong target_cpu_get_tls(CPUARMState *env);

#endif /* TARGET_ARCH_H */
