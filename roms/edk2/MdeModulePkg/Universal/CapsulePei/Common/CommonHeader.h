/** @file
  Common header file.

Copyright (c) 2011 - 2016, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _CAPSULE_COMMON_HEADER_
#define _CAPSULE_COMMON_HEADER_

//
// 8 extra pages for PF handler.
//
#define EXTRA_PAGE_TABLE_PAGES  8

#define PAGING_1G_ADDRESS_MASK_64  0x000FFFFFC0000000ull

//
// This capsule PEIM puts its private data at the start of the
// coalesced capsule. Here's the structure definition.
//
#define EFI_CAPSULE_PEIM_PRIVATE_DATA_SIGNATURE  SIGNATURE_32 ('C', 'a', 'p', 'P')

#pragma pack(1)
typedef struct {
  UINT64    Signature;
  UINT64    CapsuleAllImageSize;
  UINT64    CapsuleNumber;
  UINT64    CapsuleOffset[1];
} EFI_CAPSULE_PEIM_PRIVATE_DATA;
#pragma pack()

typedef struct {
  ///
  /// The physical start address of the resource region.
  ///
  EFI_PHYSICAL_ADDRESS    PhysicalStart;
  ///
  /// The number of bytes of the resource region.
  ///
  UINT64                  ResourceLength;
} MEMORY_RESOURCE_DESCRIPTOR;

#define CAPSULE_TEST_SIGNATURE  SIGNATURE_32('T', 'E', 'S', 'T')

#if defined (MDE_CPU_IA32) || defined (MDE_CPU_X64)
  #pragma pack(1)
typedef struct {
  EFI_PHYSICAL_ADDRESS    EntryPoint;
  EFI_PHYSICAL_ADDRESS    StackBufferBase;
  UINT64                  StackBufferLength;
  EFI_PHYSICAL_ADDRESS    JumpBuffer;
  EFI_PHYSICAL_ADDRESS    BlockListAddr;
  EFI_PHYSICAL_ADDRESS    MemoryResource;
  EFI_PHYSICAL_ADDRESS    MemoryBase64Ptr;
  EFI_PHYSICAL_ADDRESS    MemorySize64Ptr;
  BOOLEAN                 Page1GSupport;
  UINT64                  AddressEncMask;
} SWITCH_32_TO_64_CONTEXT;

typedef struct {
  UINT16                  ReturnCs;
  EFI_PHYSICAL_ADDRESS    ReturnEntryPoint;
  UINT64                  ReturnStatus;
  //
  // NOTICE:
  // Be careful about the Base field of IA32_DESCRIPTOR
  // that is UINTN type.
  // To extend new field for this structure, add it to
  // right before this Gdtr field.
  //
  IA32_DESCRIPTOR         Gdtr;
} SWITCH_64_TO_32_CONTEXT;
  #pragma pack()
#endif

/**
  The function to coalesce a fragmented capsule in memory.

  @param PeiServices        General purpose services available to every PEIM.
  @param BlockListBuffer    Point to the buffer of Capsule Descriptor Variables.
  @param MemoryResource     Pointer to the buffer of memory resource descriptor.
  @param MemoryBase         Pointer to the base of a block of memory that we can walk
                            all over while trying to coalesce our buffers.
                            On output, this variable will hold the base address of
                            a coalesced capsule.
  @param MemorySize         Size of the memory region pointed to by MemoryBase.
                            On output, this variable will contain the size of the
                            coalesced capsule.

  @retval EFI_NOT_FOUND     if we can't determine the boot mode
                            if the boot mode is not flash-update
                            if we could not find the capsule descriptors

  @retval EFI_BUFFER_TOO_SMALL
                            if we could not coalesce the capsule in the memory
                            region provided to us

  @retval EFI_SUCCESS       if there's no capsule, or if we processed the
                            capsule successfully.
**/
EFI_STATUS
EFIAPI
CapsuleDataCoalesce (
  IN EFI_PEI_SERVICES            **PeiServices,
  IN EFI_PHYSICAL_ADDRESS        *BlockListBuffer,
  IN MEMORY_RESOURCE_DESCRIPTOR  *MemoryResource,
  IN OUT VOID                    **MemoryBase,
  IN OUT UINTN                   *MemorySize
  );

#endif
