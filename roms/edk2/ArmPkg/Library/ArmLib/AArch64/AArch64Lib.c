/** @file

  Copyright (c) 2008 - 2009, Apple Inc. All rights reserved.<BR>
  Portions copyright (c) 2011 - 2014, ARM Ltd. All rights reserved.<BR>
  Copyright (c) 2021, NUVIA Inc. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Base.h>

#include <Library/ArmLib.h>
#include <Library/DebugLib.h>

#include <Chipset/AArch64.h>

#include "AArch64Lib.h"
#include "ArmLibPrivate.h"

VOID
AArch64DataCacheOperation (
  IN  AARCH64_CACHE_OPERATION  DataCacheOperation
  )
{
  UINTN  SavedInterruptState;

  SavedInterruptState = ArmGetInterruptState ();
  ArmDisableInterrupts ();

  AArch64AllDataCachesOperation (DataCacheOperation);

  ArmDataSynchronizationBarrier ();

  if (SavedInterruptState) {
    ArmEnableInterrupts ();
  }
}

VOID
EFIAPI
ArmInvalidateDataCache (
  VOID
  )
{
  ASSERT (!ArmMmuEnabled ());

  ArmDataSynchronizationBarrier ();
  AArch64DataCacheOperation (ArmInvalidateDataCacheEntryBySetWay);
}

VOID
EFIAPI
ArmCleanInvalidateDataCache (
  VOID
  )
{
  ASSERT (!ArmMmuEnabled ());

  ArmDataSynchronizationBarrier ();
  AArch64DataCacheOperation (ArmCleanInvalidateDataCacheEntryBySetWay);
}

VOID
EFIAPI
ArmCleanDataCache (
  VOID
  )
{
  ASSERT (!ArmMmuEnabled ());

  ArmDataSynchronizationBarrier ();
  AArch64DataCacheOperation (ArmCleanDataCacheEntryBySetWay);
}

/**
  Check whether the CPU supports the GIC system register interface (any version)

  @return   Whether GIC System Register Interface is supported

**/
BOOLEAN
EFIAPI
ArmHasGicSystemRegisters (
  VOID
  )
{
  return ((ArmReadIdAA64Pfr0 () & AARCH64_PFR0_GIC) != 0);
}

/** Checks if CCIDX is implemented.

   @retval TRUE  CCIDX is implemented.
   @retval FALSE CCIDX is not implemented.
**/
BOOLEAN
EFIAPI
ArmHasCcidx (
  VOID
  )
{
  UINTN  Mmfr2;

  Mmfr2 = ArmReadIdAA64Mmfr2 ();
  return (((Mmfr2 >> 20) & 0xF) == 1) ? TRUE : FALSE;
}

/**
  Checks whether the CPU implements the Virtualization Host Extensions.

  @retval TRUE  FEAT_VHE is implemented.
  @retval FALSE FEAT_VHE is not mplemented.
**/
BOOLEAN
EFIAPI
ArmHasVhe (
  VOID
  )
{
  return ((ArmReadIdAA64Mmfr1 () & AARCH64_MMFR1_VH) != 0);
}

/**
  Checks whether the CPU implements the Trace Buffer Extension.

  @retval TRUE  FEAT_TRBE is implemented.
  @retval FALSE FEAT_TRBE is not mplemented.
**/
BOOLEAN
EFIAPI
ArmHasTrbe (
  VOID
  )
{
  return ((ArmReadIdAA64Dfr0 () & AARCH64_DFR0_TRBE) != 0);
}

/**
  Checks whether the CPU implements the Embedded Trace Extension.

  @retval TRUE  FEAT_ETE is implemented.
  @retval FALSE FEAT_ETE is not mplemented.
**/
BOOLEAN
EFIAPI
ArmHasEte (
  VOID
  )
{
  // The ID_AA64DFR0_EL1.TraceVer field identifies the presence of FEAT_ETE.
  return ((ArmReadIdAA64Dfr0 () & AARCH64_DFR0_TRACEVER) != 0);
}
