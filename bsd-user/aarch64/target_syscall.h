/*
 * ARM AArch64 specific CPU for bsd-user
 *
 * Copyright (c) 2015 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef BSD_USER_AARCH64_TARGET_SYSCALL_H
#define BSD_USER_AARCH64_TARGET_SYSCALL_H

/*
 * The aarch64 registers are named:
 *
 * x0 through x30 - for 64-bit-wide access (same registers)
 * Register '31' is one of two registers depending on the instruction context:
 *  For instructions dealing with the stack, it is the stack pointer, named rsp
 *  For all other instructions, it is a "zero" register, which returns 0 when
 *  read and discards data when written - named rzr (xzr, wzr)
 *
 * Usage during syscall/function call:
 * r0-r7 are used for arguments and return values
 * For syscalls, the syscall number is in r8
 * r9-r15 are for temporary values (may get trampled)
 * r16-r18 are used for intra-procedure-call and platform values (avoid)
 * The called routine is expected to preserve r19-r28
 * r29 and r30 are used as the frame register and link register (avoid)
 * See the ARM Procedure Call Reference for details.
 */
struct target_pt_regs {
    uint64_t    regs[31];
    uint64_t    sp;
    uint64_t    pc;
    uint64_t    pstate;
};

#define TARGET_HW_MACHINE       "arm64"
#define TARGET_HW_MACHINE_ARCH  "aarch64"

#endif /* BSD_USER_AARCH64_TARGET_SYSCALL_H */
