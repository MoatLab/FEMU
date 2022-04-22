/** @file
*
*  Copyright (c) 2011-2014, ARM Limited. All rights reserved.
*  Copyright (c) 2014, Linaro Limited. All rights reserved.
*
*  SPDX-License-Identifier: BSD-2-Clause-Patent
*
**/

#include <PiPei.h>

#include <Library/ArmMmuLib.h>
#include <Library/ArmVirtMemInfoLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/CacheMaintenanceLib.h>

VOID
BuildMemoryTypeInformationHob (
  VOID
  );

VOID
InitMmu (
  VOID
  )
{
  ARM_MEMORY_REGION_DESCRIPTOR  *MemoryTable;
  VOID                          *TranslationTableBase;
  UINTN                         TranslationTableSize;
  RETURN_STATUS                 Status;

  // Get Virtual Memory Map from the Platform Library
  ArmVirtGetMemoryMap (&MemoryTable);

  // Note: Because we called PeiServicesInstallPeiMemory() before to call InitMmu() the MMU Page Table resides in
  //      DRAM (even at the top of DRAM as it is the first permanent memory allocation)
  Status = ArmConfigureMmu (MemoryTable, &TranslationTableBase, &TranslationTableSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Error: Failed to enable MMU\n"));
  }
}

EFI_STATUS
EFIAPI
MemoryPeim (
  IN EFI_PHYSICAL_ADDRESS  UefiMemoryBase,
  IN UINT64                UefiMemorySize
  )
{
  EFI_RESOURCE_ATTRIBUTE_TYPE  ResourceAttributes;
  UINT64                       SystemMemoryTop;

  // Ensure PcdSystemMemorySize has been set
  ASSERT (PcdGet64 (PcdSystemMemorySize) != 0);

  //
  // Now, the permanent memory has been installed, we can call AllocatePages()
  //
  ResourceAttributes = (
                        EFI_RESOURCE_ATTRIBUTE_PRESENT |
                        EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
                        EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE |
                        EFI_RESOURCE_ATTRIBUTE_TESTED
                        );

  SystemMemoryTop = PcdGet64 (PcdSystemMemoryBase) +
                    PcdGet64 (PcdSystemMemorySize);

  if (SystemMemoryTop - 1 > MAX_ALLOC_ADDRESS) {
    BuildResourceDescriptorHob (
      EFI_RESOURCE_SYSTEM_MEMORY,
      ResourceAttributes,
      PcdGet64 (PcdSystemMemoryBase),
      (UINT64)MAX_ALLOC_ADDRESS - PcdGet64 (PcdSystemMemoryBase) + 1
      );
    BuildResourceDescriptorHob (
      EFI_RESOURCE_SYSTEM_MEMORY,
      ResourceAttributes,
      (UINT64)MAX_ALLOC_ADDRESS + 1,
      SystemMemoryTop - MAX_ALLOC_ADDRESS - 1
      );
  } else {
    BuildResourceDescriptorHob (
      EFI_RESOURCE_SYSTEM_MEMORY,
      ResourceAttributes,
      PcdGet64 (PcdSystemMemoryBase),
      PcdGet64 (PcdSystemMemorySize)
      );
  }

  //
  // When running under virtualization, the PI/UEFI memory region may be
  // clean but not invalidated in system caches or in lower level caches
  // on other CPUs. So invalidate the region by virtual address, to ensure
  // that the contents we put there with the caches and MMU off will still
  // be visible after turning them on.
  //
  InvalidateDataCacheRange ((VOID *)(UINTN)UefiMemoryBase, UefiMemorySize);

  // Build Memory Allocation Hob
  InitMmu ();

  if (FeaturePcdGet (PcdPrePiProduceMemoryTypeInformationHob)) {
    // Optional feature that helps prevent EFI memory map fragmentation.
    BuildMemoryTypeInformationHob ();
  }

  return EFI_SUCCESS;
}
