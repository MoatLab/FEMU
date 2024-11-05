/** @file
  PEI Services Table Pointer Library.

  This library is used for PEIM which does executed from flash device directly but
  executed in memory.

  Copyright (c) 2006 - 2010, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2011 Hewlett-Packard Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <Library/PeiServicesTablePointerLib.h>
#include <Library/ArmLib.h>
#include <Library/DebugLib.h>

/**
  Caches a pointer PEI Services Table.

  Caches the pointer to the PEI Services Table specified by PeiServicesTablePointer
  in a platform specific manner.

  If PeiServicesTablePointer is NULL, then ASSERT().

  @param    PeiServicesTablePointer   The address of PeiServices pointer.
**/
VOID
EFIAPI
SetPeiServicesTablePointer (
  IN CONST EFI_PEI_SERVICES  **PeiServicesTablePointer
  )
{
  ArmWriteTpidrurw ((UINTN)PeiServicesTablePointer);
}

/**
  Retrieves the cached value of the PEI Services Table pointer.

  Returns the cached value of the PEI Services Table pointer in a CPU specific manner
  as specified in the CPU binding section of the Platform Initialization Pre-EFI
  Initialization Core Interface Specification.

  If the cached PEI Services Table pointer is NULL, then ASSERT().

  @return  The pointer to PeiServices.

**/
CONST EFI_PEI_SERVICES **
EFIAPI
GetPeiServicesTablePointer (
  VOID
  )
{
  return (CONST EFI_PEI_SERVICES **)ArmReadTpidrurw ();
}

/**
Perform CPU specific actions required to migrate the PEI Services Table
pointer from temporary RAM to permanent RAM.

For IA32 CPUs, the PEI Services Table pointer is stored in the 4 bytes
immediately preceding the Interrupt Descriptor Table (IDT) in memory.
For X64 CPUs, the PEI Services Table pointer is stored in the 8 bytes
immediately preceding the Interrupt Descriptor Table (IDT) in memory.
For Itanium and ARM CPUs, a the PEI Services Table Pointer is stored in
a dedicated CPU register.  This means that there is no memory storage
associated with storing the PEI Services Table pointer, so no additional
migration actions are required for Itanium or ARM CPUs.

**/
VOID
EFIAPI
MigratePeiServicesTablePointer (
  VOID
  )
{
  return;
}
