/*
 * FreeBSD VM parameters definitions
 *
 * Copyright (c) 2013 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TARGET_OS_VMPARAM_H
#define TARGET_OS_VMPARAM_H

#include "target_arch_vmparam.h"

/* Compare to sys/exec.h */
struct target_ps_strings {
    abi_ulong ps_argvstr;
    uint32_t ps_nargvstr;
    abi_ulong ps_envstr;
    uint32_t ps_nenvstr;
};

extern abi_ulong target_stkbas;
extern abi_ulong target_stksiz;

#define TARGET_PS_STRINGS  ((target_stkbas + target_stksiz) - \
                            sizeof(struct target_ps_strings))

#endif /* TARGET_OS_VMPARAM_H */
