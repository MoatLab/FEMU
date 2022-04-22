//
//  Copyright (c) 2011 - 2020, Arm Limited. All rights reserved.<BR>
//
//  SPDX-License-Identifier: BSD-2-Clause-Patent
//
//

#include <AutoGen.h>
#include <Chipset/ArmV7.h>

  INCLUDE AsmMacroIoLib.inc

  IMPORT  CEntryPoint
  IMPORT  ArmPlatformIsPrimaryCore
  IMPORT  ArmReadMpidr
  IMPORT  ArmPlatformPeiBootAction
  IMPORT  ArmPlatformStackSet
  IMPORT  mSystemMemoryEnd

  EXPORT  _ModuleEntryPoint

  PRESERVE8
  AREA    PrePiCoreEntryPoint, CODE, READONLY

StartupAddr        DCD      CEntryPoint

_ModuleEntryPoint
  // Do early platform specific actions
  bl    ArmPlatformPeiBootAction

  // Get ID of this CPU in multi-core system
  bl    ArmReadMpidr
  // Keep a copy of the MpId register value
  mov   r8, r0

_SetSVCMode
  // Enter SVC mode, Disable FIQ and IRQ
  mov     r1, #(CPSR_MODE_SVC :OR: CPSR_IRQ :OR: CPSR_FIQ)
  msr     CPSR_c, r1

// Check if we can install the stack at the top of the System Memory or if we need
// to install the stacks at the bottom of the Firmware Device (case the FD is located
// at the top of the DRAM)
_SystemMemoryEndInit
  adrll r1, mSystemMemoryEnd
  ldrd  r2, r3, [r1]
  teq   r3, #0
  moveq r1, r2
  mvnne r1, #0

_SetupStackPosition
  // r1 = SystemMemoryTop

  // Calculate Top of the Firmware Device
  mov32 r2, FixedPcdGet32(PcdFdBaseAddress)
  mov32 r3, FixedPcdGet32(PcdFdSize)
  sub   r3, r3, #1
  add   r3, r3, r2      // r3 = FdTop = PcdFdBaseAddress + PcdFdSize

  // UEFI Memory Size (stacks are allocated in this region)
  mov32 r4, FixedPcdGet32(PcdSystemMemoryUefiRegionSize)

  //
  // Reserve the memory for the UEFI region (contain stacks on its top)
  //

  // Calculate how much space there is between the top of the Firmware and the Top of the System Memory
  subs  r0, r1, r3      // r0 = SystemMemoryTop - FdTop
  bmi   _SetupStack     // Jump if negative (FdTop > SystemMemoryTop). Case when the PrePi is in XIP memory outside of the DRAM
  cmp   r0, r4
  bge   _SetupStack

  // Case the top of stacks is the FdBaseAddress
  mov   r1, r2

_SetupStack
  // r1 contains the top of the stack (and the UEFI Memory)

  // Because the 'push' instruction is equivalent to 'stmdb' (decrement before), we need to increment
  // one to the top of the stack. We check if incrementing one does not overflow (case of DRAM at the
  // top of the memory space)
  adds  r9, r1, #1
  bcs   _SetupOverflowStack

_SetupAlignedStack
  mov   r1, r9
  b     _GetBaseUefiMemory

_SetupOverflowStack
  // Case memory at the top of the address space. Ensure the top of the stack is EFI_PAGE_SIZE
  // aligned (4KB)
  mov32 r9, EFI_PAGE_MASK
  and   r9, r9, r1
  sub   r1, r1, r9

_GetBaseUefiMemory
  // Calculate the Base of the UEFI Memory
  sub   r9, r1, r4

_GetStackBase
  // r1 = The top of the Mpcore Stacks
  // Stack for the primary core = PrimaryCoreStack
  mov32 r2, FixedPcdGet32(PcdCPUCorePrimaryStackSize)
  sub   r10, r1, r2

  // Stack for the secondary core = Number of Cores - 1
  mov32 r1, (FixedPcdGet32(PcdCoreCount) - 1) * FixedPcdGet32(PcdCPUCoreSecondaryStackSize)
  sub   r10, r10, r1

  // r10 = The base of the MpCore Stacks (primary stack & secondary stacks)
  mov   r0, r10
  mov   r1, r8
  //ArmPlatformStackSet(StackBase, MpId, PrimaryStackSize, SecondaryStackSize)
  mov32 r2, FixedPcdGet32(PcdCPUCorePrimaryStackSize)
  mov32 r3, FixedPcdGet32(PcdCPUCoreSecondaryStackSize)
  bl    ArmPlatformStackSet

  // Is it the Primary Core ?
  mov   r0, r8
  bl    ArmPlatformIsPrimaryCore
  cmp   r0, #1
  bne   _PrepareArguments

_PrepareArguments
  mov   r0, r8
  mov   r1, r9
  mov   r2, r10

  // Move sec startup address into a data register
  // Ensure we're jumping to FV version of the code (not boot remapped alias)
  ldr   r4, StartupAddr

  // Jump to PrePiCore C code
  //    r0 = MpId
  //    r1 = UefiMemoryBase
  //    r2 = StacksBase
  blx   r4

_NeverReturn
  b _NeverReturn

  END
