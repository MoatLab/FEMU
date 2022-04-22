/** @file
  Main file supporting the transition to PEI Core in Normal World for Versatile Express

  Copyright (c) 2011, ARM Limited. All rights reserved.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __PREPEICORE_H_
#define __PREPEICORE_H_

#include <Library/ArmLib.h>
#include <Library/ArmPlatformLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/IoLib.h>
#include <Library/PcdLib.h>

#include <PiPei.h>
#include <Ppi/TemporaryRamSupport.h>

VOID
CreatePpiList (
  OUT UINTN                   *PpiListSize,
  OUT EFI_PEI_PPI_DESCRIPTOR  **PpiList
  );

EFI_STATUS
EFIAPI
PrePeiCoreTemporaryRamSupport (
  IN CONST EFI_PEI_SERVICES  **PeiServices,
  IN EFI_PHYSICAL_ADDRESS    TemporaryMemoryBase,
  IN EFI_PHYSICAL_ADDRESS    PermanentMemoryBase,
  IN UINTN                   CopySize
  );

VOID
SecSwitchStack (
  INTN  StackDelta
  );

// Vector Table for Pei Phase
VOID
PeiVectorTable (
  VOID
  );

VOID
EFIAPI
PrimaryMain (
  IN  EFI_PEI_CORE_ENTRY_POINT  PeiCoreEntryPoint
  );

/*
 * This is the main function for secondary cores. They loop around until a non Null value is written to
 * SYS_FLAGS register.The SYS_FLAGS register is platform specific.
 * Note:The secondary cores, while executing secondary_main, assumes that:
 *      : SGI 0 is configured as Non-secure interrupt
 *      : Priority Mask is configured to allow SGI 0
 *      : Interrupt Distributor and CPU interfaces are enabled
 *
 */
VOID
EFIAPI
SecondaryMain (
  IN UINTN  MpId
  );

VOID
PeiCommonExceptionEntry (
  IN UINT32  Entry,
  IN UINTN   LR
  );

#endif
