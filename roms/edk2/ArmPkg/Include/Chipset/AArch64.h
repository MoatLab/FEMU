/** @file

  Copyright (c) 2008 - 2009, Apple Inc. All rights reserved.<BR>
  Copyright (c) 2011 - 2021, Arm Limited. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef AARCH64_H_
#define AARCH64_H_

#include <Chipset/AArch64Mmu.h>

// ARM Interrupt ID in Exception Table
#define ARM_ARCH_EXCEPTION_IRQ  EXCEPT_AARCH64_IRQ

// CPACR - Coprocessor Access Control Register definitions
#define CPACR_TTA_EN          (1UL << 28)
#define CPACR_FPEN_EL1        (1UL << 20)
#define CPACR_FPEN_FULL       (3UL << 20)
#define CPACR_CP_FULL_ACCESS  0x300000

// Coprocessor Trap Register (CPTR)
#define AARCH64_CPTR_TFP  (1 << 10)

// ID_AA64PFR0 - AArch64 Processor Feature Register 0 definitions
#define AARCH64_PFR0_FP   (0xF << 16)
#define AARCH64_PFR0_GIC  (0xF << 24)

// SCR - Secure Configuration Register definitions
#define SCR_NS   (1 << 0)
#define SCR_IRQ  (1 << 1)
#define SCR_FIQ  (1 << 2)
#define SCR_EA   (1 << 3)
#define SCR_FW   (1 << 4)
#define SCR_AW   (1 << 5)

// MIDR - Main ID Register definitions
#define ARM_CPU_TYPE_SHIFT  4
#define ARM_CPU_TYPE_MASK   0xFFF
#define ARM_CPU_TYPE_AEMV8  0xD0F
#define ARM_CPU_TYPE_A53    0xD03
#define ARM_CPU_TYPE_A57    0xD07
#define ARM_CPU_TYPE_A72    0xD08
#define ARM_CPU_TYPE_A15    0xC0F
#define ARM_CPU_TYPE_A9     0xC09
#define ARM_CPU_TYPE_A7     0xC07
#define ARM_CPU_TYPE_A5     0xC05

#define ARM_CPU_REV_MASK  ((0xF << 20) | (0xF) )
#define ARM_CPU_REV(rn, pn)  ((((rn) & 0xF) << 20) | ((pn) & 0xF))

// Hypervisor Configuration Register
#define ARM_HCR_FMO  BIT3
#define ARM_HCR_IMO  BIT4
#define ARM_HCR_AMO  BIT5
#define ARM_HCR_TSC  BIT19
#define ARM_HCR_TGE  BIT27

// Exception Syndrome Register
#define AARCH64_ESR_EC(Ecr)   ((0x3F << 26) & (Ecr))
#define AARCH64_ESR_ISS(Ecr)  ((0x1FFFFFF) & (Ecr))

#define AARCH64_ESR_EC_SMC32  (0x13 << 26)
#define AARCH64_ESR_EC_SMC64  (0x17 << 26)

// AArch64 Exception Level
#define AARCH64_EL3  0xC
#define AARCH64_EL2  0x8
#define AARCH64_EL1  0x4

// Saved Program Status Register definitions
#define SPSR_A  BIT8
#define SPSR_I  BIT7
#define SPSR_F  BIT6

#define SPSR_AARCH32  BIT4

#define SPSR_AARCH32_MODE_USER   0x0
#define SPSR_AARCH32_MODE_FIQ    0x1
#define SPSR_AARCH32_MODE_IRQ    0x2
#define SPSR_AARCH32_MODE_SVC    0x3
#define SPSR_AARCH32_MODE_ABORT  0x7
#define SPSR_AARCH32_MODE_UNDEF  0xB
#define SPSR_AARCH32_MODE_SYS    0xF

// Counter-timer Hypervisor Control register definitions
#define CNTHCTL_EL2_EL1PCTEN  BIT0
#define CNTHCTL_EL2_EL1PCEN   BIT1

#define ARM_VECTOR_TABLE_ALIGNMENT  ((1 << 11)-1)

// Vector table offset definitions
#define ARM_VECTOR_CUR_SP0_SYNC  0x000
#define ARM_VECTOR_CUR_SP0_IRQ   0x080
#define ARM_VECTOR_CUR_SP0_FIQ   0x100
#define ARM_VECTOR_CUR_SP0_SERR  0x180

#define ARM_VECTOR_CUR_SPX_SYNC  0x200
#define ARM_VECTOR_CUR_SPX_IRQ   0x280
#define ARM_VECTOR_CUR_SPX_FIQ   0x300
#define ARM_VECTOR_CUR_SPX_SERR  0x380

#define ARM_VECTOR_LOW_A64_SYNC  0x400
#define ARM_VECTOR_LOW_A64_IRQ   0x480
#define ARM_VECTOR_LOW_A64_FIQ   0x500
#define ARM_VECTOR_LOW_A64_SERR  0x580

#define ARM_VECTOR_LOW_A32_SYNC  0x600
#define ARM_VECTOR_LOW_A32_IRQ   0x680
#define ARM_VECTOR_LOW_A32_FIQ   0x700
#define ARM_VECTOR_LOW_A32_SERR  0x780

// The ID_AA64MMFR2_EL1 register was added in ARMv8.2. Since we
// build for ARMv8.0, we need to define the register here.
#define ID_AA64MMFR2_EL1  S3_0_C0_C7_2

#define VECTOR_BASE(tbl)          \
  .section .text.##tbl##,"ax";    \
  .align 11;                      \
  .org 0x0;                       \
  GCC_ASM_EXPORT(tbl);            \
  ASM_PFX(tbl):                   \

#define VECTOR_ENTRY(tbl, off)    \
  .org off

#define VECTOR_END(tbl)           \
  .org 0x800;                     \
  .previous

VOID
EFIAPI
ArmEnableSWPInstruction (
  VOID
  );

UINTN
EFIAPI
ArmReadCbar (
  VOID
  );

UINTN
EFIAPI
ArmReadTpidrurw (
  VOID
  );

VOID
EFIAPI
ArmWriteTpidrurw (
  UINTN  Value
  );

UINTN
EFIAPI
ArmGetTCR (
  VOID
  );

VOID
EFIAPI
ArmSetTCR (
  UINTN  Value
  );

UINTN
EFIAPI
ArmGetMAIR (
  VOID
  );

VOID
EFIAPI
ArmSetMAIR (
  UINTN  Value
  );

VOID
EFIAPI
ArmDisableAlignmentCheck (
  VOID
  );

VOID
EFIAPI
ArmEnableAlignmentCheck (
  VOID
  );

VOID
EFIAPI
ArmDisableStackAlignmentCheck (
  VOID
  );

VOID
EFIAPI
ArmEnableStackAlignmentCheck (
  VOID
  );

VOID
EFIAPI
ArmDisableAllExceptions (
  VOID
  );

VOID
ArmWriteHcr (
  IN UINTN  Hcr
  );

UINTN
ArmReadHcr (
  VOID
  );

UINTN
ArmReadCurrentEL (
  VOID
  );

UINTN
ArmWriteCptr (
  IN  UINT64  Cptr
  );

UINT32
ArmReadCntHctl (
  VOID
  );

VOID
ArmWriteCntHctl (
  IN UINT32  CntHctl
  );

#endif // AARCH64_H_
