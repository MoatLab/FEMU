# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# Derived from automatically generated HostBoot rom_entry.S

#include <asm-utils.h>
#include <processor.h>

# Updated hostboot location is src/securerom/rom_entry.S.
# This also has a fix for TOC save frame pointer.

#include <stack.h>

.section .text

.global __cvc_verify_v1
.global __cvc_sha512_v1

__cvc_verify_v1:
__cvc_sha512_v1:

call_rom_entry:
    mflr %r0
    std %r0, 16(%r1)
    stdu %r1, -128(%r1)
    std %r2, STACK_TOC_OFFSET(%r1)
    li %r2, 0
    mtctr %r3
    mr %r3, %r4
    mr %r4, %r5
    mr %r5, %r6
    mr %r6, %r7
    mr %r7, %r8
#if HAVE_BIG_ENDIAN
    bctrl
#else
    bl $+4
1:  mflr %r9
    addi %r9,%r9,2f - 1b
    mtspr SPR_HSRR0, %r9
    mfmsr %r9
    xori %r9,%r9,MSR_LE
    mtspr SPR_HSRR1, %r9
    hrfid
2:  .long 0x2104804e /* bctrl */
    FIXUP_ENDIAN
#endif
    ld %r2, STACK_TOC_OFFSET(%r1)
    addi %r1, %r1, 128
    ld %r0, 16(%r1)
    mtlr %r0
    blr

