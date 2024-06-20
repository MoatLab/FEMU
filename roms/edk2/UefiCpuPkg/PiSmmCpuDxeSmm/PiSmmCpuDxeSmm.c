/** @file
Agent Module to load other modules to deploy SMM Entry Vector for X86 CPU.

Copyright (c) 2009 - 2023, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>
Copyright (C) 2023 Advanced Micro Devices, Inc. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PiSmmCpuDxeSmm.h"

//
// SMM CPU Private Data structure that contains SMM Configuration Protocol
// along its supporting fields.
//
SMM_CPU_PRIVATE_DATA  mSmmCpuPrivateData = {
  SMM_CPU_PRIVATE_DATA_SIGNATURE,               // Signature
  NULL,                                         // SmmCpuHandle
  NULL,                                         // Pointer to ProcessorInfo array
  NULL,                                         // Pointer to Operation array
  NULL,                                         // Pointer to CpuSaveStateSize array
  NULL,                                         // Pointer to CpuSaveState array
  {
    { 0    }
  },                                            // SmmReservedSmramRegion
  {
    SmmStartupThisAp,                           // SmmCoreEntryContext.SmmStartupThisAp
    0,                                          // SmmCoreEntryContext.CurrentlyExecutingCpu
    0,                                          // SmmCoreEntryContext.NumberOfCpus
    NULL,                                       // SmmCoreEntryContext.CpuSaveStateSize
    NULL                                        // SmmCoreEntryContext.CpuSaveState
  },
  NULL,                                         // SmmCoreEntry
  {
    mSmmCpuPrivateData.SmmReservedSmramRegion,  // SmmConfiguration.SmramReservedRegions
    RegisterSmmEntry                            // SmmConfiguration.RegisterSmmEntry
  },
  NULL,                                         // pointer to Ap Wrapper Func array
  { NULL, NULL },                               // List_Entry for Tokens.
};

CPU_HOT_PLUG_DATA  mCpuHotPlugData = {
  CPU_HOT_PLUG_DATA_REVISION_1,                 // Revision
  0,                                            // Array Length of SmBase and APIC ID
  NULL,                                         // Pointer to APIC ID array
  NULL,                                         // Pointer to SMBASE array
  0,                                            // Reserved
  0,                                            // SmrrBase
  0                                             // SmrrSize
};

//
// Global pointer used to access mSmmCpuPrivateData from outside and inside SMM
//
SMM_CPU_PRIVATE_DATA  *gSmmCpuPrivate = &mSmmCpuPrivateData;

//
// SMM Relocation variables
//
volatile BOOLEAN  *mRebased;

///
/// Handle for the SMM CPU Protocol
///
EFI_HANDLE  mSmmCpuHandle = NULL;

///
/// SMM CPU Protocol instance
///
EFI_SMM_CPU_PROTOCOL  mSmmCpu = {
  SmmReadSaveState,
  SmmWriteSaveState
};

///
/// SMM Memory Attribute Protocol instance
///
EDKII_SMM_MEMORY_ATTRIBUTE_PROTOCOL  mSmmMemoryAttribute = {
  EdkiiSmmGetMemoryAttributes,
  EdkiiSmmSetMemoryAttributes,
  EdkiiSmmClearMemoryAttributes
};

EFI_CPU_INTERRUPT_HANDLER  mExternalVectorTable[EXCEPTION_VECTOR_NUMBER];

BOOLEAN           mSmmRelocated    = FALSE;
volatile BOOLEAN  *mSmmInitialized = NULL;
UINT32            mBspApicId       = 0;

//
// SMM stack information
//
UINTN  mSmmStackArrayBase;
UINTN  mSmmStackArrayEnd;
UINTN  mSmmStackSize;

UINTN    mSmmShadowStackSize;
BOOLEAN  mCetSupported = TRUE;

UINTN  mMaxNumberOfCpus = 0;
UINTN  mNumberOfCpus    = 0;

//
// SMM ready to lock flag
//
BOOLEAN  mSmmReadyToLock = FALSE;

//
// Global used to cache PCD for SMM Code Access Check enable
//
BOOLEAN  mSmmCodeAccessCheckEnable = FALSE;

//
// Global used to cache SMM Debug Agent Supported ot not
//
BOOLEAN  mSmmDebugAgentSupport = FALSE;

//
// Global copy of the PcdPteMemoryEncryptionAddressOrMask
//
UINT64  mAddressEncMask = 0;

//
// Spin lock used to serialize setting of SMM Code Access Check feature
//
SPIN_LOCK  *mConfigSmmCodeAccessCheckLock = NULL;

//
// Saved SMM ranges information
//
EFI_SMRAM_DESCRIPTOR  *mSmmCpuSmramRanges;
UINTN                 mSmmCpuSmramRangeCount;

UINT8  mPhysicalAddressBits;

//
// Control register contents saved for SMM S3 resume state initialization.
//
UINT32  mSmmCr0;
UINT32  mSmmCr4;

/**
  Initialize IDT to setup exception handlers for SMM.

**/
VOID
InitializeSmmIdt (
  VOID
  )
{
  EFI_STATUS       Status;
  BOOLEAN          InterruptState;
  IA32_DESCRIPTOR  DxeIdtr;

  //
  // There are 32 (not 255) entries in it since only processor
  // generated exceptions will be handled.
  //
  gcSmiIdtr.Limit = (sizeof (IA32_IDT_GATE_DESCRIPTOR) * 32) - 1;
  //
  // Allocate page aligned IDT, because it might be set as read only.
  //
  gcSmiIdtr.Base = (UINTN)AllocateCodePages (EFI_SIZE_TO_PAGES (gcSmiIdtr.Limit + 1));
  ASSERT (gcSmiIdtr.Base != 0);
  ZeroMem ((VOID *)gcSmiIdtr.Base, gcSmiIdtr.Limit + 1);

  //
  // Disable Interrupt and save DXE IDT table
  //
  InterruptState = SaveAndDisableInterrupts ();
  AsmReadIdtr (&DxeIdtr);
  //
  // Load SMM temporary IDT table
  //
  AsmWriteIdtr (&gcSmiIdtr);
  //
  // Setup SMM default exception handlers, SMM IDT table
  // will be updated and saved in gcSmiIdtr
  //
  Status = InitializeCpuExceptionHandlers (NULL);
  ASSERT_EFI_ERROR (Status);
  //
  // Restore DXE IDT table and CPU interrupt
  //
  AsmWriteIdtr ((IA32_DESCRIPTOR *)&DxeIdtr);
  SetInterruptState (InterruptState);
}

/**
  Search module name by input IP address and output it.

  @param CallerIpAddress   Caller instruction pointer.

**/
VOID
DumpModuleInfoByIp (
  IN  UINTN  CallerIpAddress
  )
{
  UINTN  Pe32Data;
  VOID   *PdbPointer;

  //
  // Find Image Base
  //
  Pe32Data = PeCoffSearchImageBase (CallerIpAddress);
  if (Pe32Data != 0) {
    DEBUG ((DEBUG_ERROR, "It is invoked from the instruction before IP(0x%p)", (VOID *)CallerIpAddress));
    PdbPointer = PeCoffLoaderGetPdbPointer ((VOID *)Pe32Data);
    if (PdbPointer != NULL) {
      DEBUG ((DEBUG_ERROR, " in module (%a)\n", PdbPointer));
    }
  }
}

/**
  Read information from the CPU save state.

  @param  This      EFI_SMM_CPU_PROTOCOL instance
  @param  Width     The number of bytes to read from the CPU save state.
  @param  Register  Specifies the CPU register to read form the save state.
  @param  CpuIndex  Specifies the zero-based index of the CPU save state.
  @param  Buffer    Upon return, this holds the CPU register value read from the save state.

  @retval EFI_SUCCESS   The register was read from Save State
  @retval EFI_NOT_FOUND The register is not defined for the Save State of Processor
  @retval EFI_INVALID_PARAMETER   This or Buffer is NULL.

**/
EFI_STATUS
EFIAPI
SmmReadSaveState (
  IN CONST EFI_SMM_CPU_PROTOCOL   *This,
  IN UINTN                        Width,
  IN EFI_SMM_SAVE_STATE_REGISTER  Register,
  IN UINTN                        CpuIndex,
  OUT VOID                        *Buffer
  )
{
  EFI_STATUS  Status;

  //
  // Retrieve pointer to the specified CPU's SMM Save State buffer
  //
  if ((CpuIndex >= gSmst->NumberOfCpus) || (Buffer == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // The SpeculationBarrier() call here is to ensure the above check for the
  // CpuIndex has been completed before the execution of subsequent codes.
  //
  SpeculationBarrier ();

  //
  // Check for special EFI_SMM_SAVE_STATE_REGISTER_PROCESSOR_ID
  //
  if (Register == EFI_SMM_SAVE_STATE_REGISTER_PROCESSOR_ID) {
    //
    // The pseudo-register only supports the 64-bit size specified by Width.
    //
    if (Width != sizeof (UINT64)) {
      return EFI_INVALID_PARAMETER;
    }

    //
    // If the processor is in SMM at the time the SMI occurred,
    // the pseudo register value for EFI_SMM_SAVE_STATE_REGISTER_PROCESSOR_ID is returned in Buffer.
    // Otherwise, EFI_NOT_FOUND is returned.
    //
    if (*(mSmmMpSyncData->CpuData[CpuIndex].Present)) {
      *(UINT64 *)Buffer = gSmmCpuPrivate->ProcessorInfo[CpuIndex].ProcessorId;
      return EFI_SUCCESS;
    } else {
      return EFI_NOT_FOUND;
    }
  }

  if (!(*(mSmmMpSyncData->CpuData[CpuIndex].Present))) {
    return EFI_INVALID_PARAMETER;
  }

  Status = MmSaveStateReadRegister (CpuIndex, Register, Width, Buffer);

  return Status;
}

/**
  Write data to the CPU save state.

  @param  This      EFI_SMM_CPU_PROTOCOL instance
  @param  Width     The number of bytes to read from the CPU save state.
  @param  Register  Specifies the CPU register to write to the save state.
  @param  CpuIndex  Specifies the zero-based index of the CPU save state
  @param  Buffer    Upon entry, this holds the new CPU register value.

  @retval EFI_SUCCESS   The register was written from Save State
  @retval EFI_NOT_FOUND The register is not defined for the Save State of Processor
  @retval EFI_INVALID_PARAMETER   ProcessorIndex or Width is not correct

**/
EFI_STATUS
EFIAPI
SmmWriteSaveState (
  IN CONST EFI_SMM_CPU_PROTOCOL   *This,
  IN UINTN                        Width,
  IN EFI_SMM_SAVE_STATE_REGISTER  Register,
  IN UINTN                        CpuIndex,
  IN CONST VOID                   *Buffer
  )
{
  EFI_STATUS  Status;

  //
  // Retrieve pointer to the specified CPU's SMM Save State buffer
  //
  if ((CpuIndex >= gSmst->NumberOfCpus) || (Buffer == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Writes to EFI_SMM_SAVE_STATE_REGISTER_PROCESSOR_ID are ignored
  //
  if (Register == EFI_SMM_SAVE_STATE_REGISTER_PROCESSOR_ID) {
    return EFI_SUCCESS;
  }

  if (!mSmmMpSyncData->CpuData[CpuIndex].Present) {
    return EFI_INVALID_PARAMETER;
  }

  Status = MmSaveStateWriteRegister (CpuIndex, Register, Width, Buffer);

  return Status;
}

/**
  C function for SMI handler. To change all processor's SMMBase Register.

**/
VOID
EFIAPI
SmmInitHandler (
  VOID
  )
{
  UINT32   ApicId;
  UINTN    Index;
  BOOLEAN  IsBsp;

  //
  // Update SMM IDT entries' code segment and load IDT
  //
  AsmWriteIdtr (&gcSmiIdtr);
  ApicId = GetApicId ();

  IsBsp = (BOOLEAN)(mBspApicId == ApicId);

  ASSERT (mNumberOfCpus <= mMaxNumberOfCpus);

  for (Index = 0; Index < mNumberOfCpus; Index++) {
    if (ApicId == (UINT32)gSmmCpuPrivate->ProcessorInfo[Index].ProcessorId) {
      PERF_CODE (
        MpPerfBegin (Index, SMM_MP_PERF_PROCEDURE_ID (SmmInitHandler));
        );
      //
      // Initialize SMM specific features on the currently executing CPU
      //
      SmmCpuFeaturesInitializeProcessor (
        Index,
        IsBsp,
        gSmmCpuPrivate->ProcessorInfo,
        &mCpuHotPlugData
        );

      if (!mSmmS3Flag) {
        //
        // Check XD and BTS features on each processor on normal boot
        //
        CheckFeatureSupported ();
      } else if (IsBsp) {
        //
        // BSP rebase is already done above.
        // Initialize private data during S3 resume
        //
        InitializeMpSyncData ();
      }

      if (!mSmmRelocated) {
        //
        // Hook return after RSM to set SMM re-based flag
        //
        SemaphoreHook (Index, &mRebased[Index]);
      }

      PERF_CODE (
        MpPerfEnd (Index, SMM_MP_PERF_PROCEDURE_ID (SmmInitHandler));
        );

      return;
    }
  }

  ASSERT (FALSE);
}

/**
  Issue SMI IPI (All Excluding Self SMM IPI + BSP SMM IPI) to execute first SMI init.

**/
VOID
ExecuteFirstSmiInit (
  VOID
  )
{
  UINTN  Index;

  PERF_FUNCTION_BEGIN ();

  if (mSmmInitialized == NULL) {
    mSmmInitialized = (BOOLEAN *)AllocatePool (sizeof (BOOLEAN) * mMaxNumberOfCpus);
  }

  ASSERT (mSmmInitialized != NULL);
  if (mSmmInitialized == NULL) {
    PERF_FUNCTION_END ();
    return;
  }

  //
  // Reset the mSmmInitialized to false.
  //
  ZeroMem ((VOID *)mSmmInitialized, sizeof (BOOLEAN) * mMaxNumberOfCpus);

  //
  // Get the BSP ApicId.
  //
  mBspApicId = GetApicId ();

  //
  // Issue SMI IPI (All Excluding Self SMM IPI + BSP SMM IPI) for SMM init
  //
  SendSmiIpi (mBspApicId);
  SendSmiIpiAllExcludingSelf ();

  //
  // Wait for all processors to finish its 1st SMI
  //
  for (Index = 0; Index < mNumberOfCpus; Index++) {
    while (!(BOOLEAN)mSmmInitialized[Index]) {
    }
  }

  PERF_FUNCTION_END ();
}

/**
  Relocate SmmBases for each processor.

  Execute on first boot and all S3 resumes

**/
VOID
EFIAPI
SmmRelocateBases (
  VOID
  )
{
  UINT8                 BakBuf[BACK_BUF_SIZE];
  SMRAM_SAVE_STATE_MAP  BakBuf2;
  SMRAM_SAVE_STATE_MAP  *CpuStatePtr;
  UINT8                 *U8Ptr;
  UINTN                 Index;
  UINTN                 BspIndex;

  PERF_FUNCTION_BEGIN ();

  //
  // Make sure the reserved size is large enough for procedure SmmInitTemplate.
  //
  ASSERT (sizeof (BakBuf) >= gcSmmInitSize);

  //
  // Patch ASM code template with current CR0, CR3, and CR4 values
  //
  mSmmCr0 = (UINT32)AsmReadCr0 ();
  PatchInstructionX86 (gPatchSmmCr0, mSmmCr0, 4);
  PatchInstructionX86 (gPatchSmmCr3, AsmReadCr3 (), 4);
  mSmmCr4 = (UINT32)AsmReadCr4 ();
  PatchInstructionX86 (gPatchSmmCr4, mSmmCr4 & (~CR4_CET_ENABLE), 4);

  //
  // Patch GDTR for SMM base relocation
  //
  gcSmiInitGdtr.Base  = gcSmiGdtr.Base;
  gcSmiInitGdtr.Limit = gcSmiGdtr.Limit;

  U8Ptr       = (UINT8 *)(UINTN)(SMM_DEFAULT_SMBASE + SMM_HANDLER_OFFSET);
  CpuStatePtr = (SMRAM_SAVE_STATE_MAP *)(UINTN)(SMM_DEFAULT_SMBASE + SMRAM_SAVE_STATE_MAP_OFFSET);

  //
  // Backup original contents at address 0x38000
  //
  CopyMem (BakBuf, U8Ptr, sizeof (BakBuf));
  CopyMem (&BakBuf2, CpuStatePtr, sizeof (BakBuf2));

  //
  // Load image for relocation
  //
  CopyMem (U8Ptr, gcSmmInitTemplate, gcSmmInitSize);

  //
  // Retrieve the local APIC ID of current processor
  //
  mBspApicId = GetApicId ();

  //
  // Relocate SM bases for all APs
  // This is APs' 1st SMI - rebase will be done here, and APs' default SMI handler will be overridden by gcSmmInitTemplate
  //
  BspIndex = (UINTN)-1;
  for (Index = 0; Index < mNumberOfCpus; Index++) {
    mRebased[Index] = FALSE;
    if (mBspApicId != (UINT32)gSmmCpuPrivate->ProcessorInfo[Index].ProcessorId) {
      SendSmiIpi ((UINT32)gSmmCpuPrivate->ProcessorInfo[Index].ProcessorId);
      //
      // Wait for this AP to finish its 1st SMI
      //
      while (!mRebased[Index]) {
      }
    } else {
      //
      // BSP will be Relocated later
      //
      BspIndex = Index;
    }
  }

  //
  // Relocate BSP's SMM base
  //
  ASSERT (BspIndex != (UINTN)-1);
  SendSmiIpi (mBspApicId);
  //
  // Wait for the BSP to finish its 1st SMI
  //
  while (!mRebased[BspIndex]) {
  }

  //
  // Restore contents at address 0x38000
  //
  CopyMem (CpuStatePtr, &BakBuf2, sizeof (BakBuf2));
  CopyMem (U8Ptr, BakBuf, sizeof (BakBuf));
  PERF_FUNCTION_END ();
}

/**
  SMM Ready To Lock event notification handler.

  The CPU S3 data is copied to SMRAM for security and mSmmReadyToLock is set to
  perform additional lock actions that must be performed from SMM on the next SMI.

  @param[in] Protocol   Points to the protocol's unique identifier.
  @param[in] Interface  Points to the interface instance.
  @param[in] Handle     The handle on which the interface was installed.

  @retval EFI_SUCCESS   Notification handler runs successfully.
 **/
EFI_STATUS
EFIAPI
SmmReadyToLockEventNotify (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  )
{
  GetAcpiCpuData ();

  //
  // Cache a copy of UEFI memory map before we start profiling feature.
  //
  GetUefiMemoryMap ();

  //
  // Set SMM ready to lock flag and return
  //
  mSmmReadyToLock = TRUE;
  return EFI_SUCCESS;
}

/**
  Function to compare 2 SMM_BASE_HOB_DATA pointer based on ProcessorIndex.

  @param[in] Buffer1            pointer to SMM_BASE_HOB_DATA poiner to compare
  @param[in] Buffer2            pointer to second SMM_BASE_HOB_DATA pointer to compare

  @retval 0                     Buffer1 equal to Buffer2
  @retval <0                    Buffer1 is less than Buffer2
  @retval >0                    Buffer1 is greater than Buffer2
**/
INTN
EFIAPI
SmBaseHobCompare (
  IN  CONST VOID  *Buffer1,
  IN  CONST VOID  *Buffer2
  )
{
  if ((*(SMM_BASE_HOB_DATA **)Buffer1)->ProcessorIndex > (*(SMM_BASE_HOB_DATA **)Buffer2)->ProcessorIndex) {
    return 1;
  } else if ((*(SMM_BASE_HOB_DATA **)Buffer1)->ProcessorIndex < (*(SMM_BASE_HOB_DATA **)Buffer2)->ProcessorIndex) {
    return -1;
  }

  return 0;
}

/**
  Extract SmBase for all CPU from SmmBase HOB.

  @param[in]  MaxNumberOfCpus        Max NumberOfCpus.

  @param[out] AllocatedSmBaseBuffer  Pointer to SmBase Buffer allocated
                                     by this function. Only set if the
                                     function returns EFI_SUCCESS.

  @retval EFI_SUCCESS           SmBase Buffer output successfully.
  @retval EFI_OUT_OF_RESOURCES  Memory allocation failed.
  @retval EFI_NOT_FOUND         gSmmBaseHobGuid was never created.
**/
STATIC
EFI_STATUS
GetSmBase (
  IN  UINTN  MaxNumberOfCpus,
  OUT UINTN  **AllocatedSmBaseBuffer
  )
{
  UINTN              HobCount;
  EFI_HOB_GUID_TYPE  *GuidHob;
  SMM_BASE_HOB_DATA  *SmmBaseHobData;
  UINTN              NumberOfProcessors;
  SMM_BASE_HOB_DATA  **SmBaseHobs;
  UINTN              *SmBaseBuffer;
  UINTN              HobIndex;
  UINTN              SortBuffer;
  UINTN              ProcessorIndex;
  UINT64             PrevProcessorIndex;
  EFI_HOB_GUID_TYPE  *FirstSmmBaseGuidHob;

  SmmBaseHobData     = NULL;
  HobIndex           = 0;
  ProcessorIndex     = 0;
  HobCount           = 0;
  NumberOfProcessors = 0;

  FirstSmmBaseGuidHob = GetFirstGuidHob (&gSmmBaseHobGuid);
  if (FirstSmmBaseGuidHob == NULL) {
    return EFI_NOT_FOUND;
  }

  GuidHob = FirstSmmBaseGuidHob;
  while (GuidHob != NULL) {
    HobCount++;
    SmmBaseHobData      = GET_GUID_HOB_DATA (GuidHob);
    NumberOfProcessors += SmmBaseHobData->NumberOfProcessors;

    if (NumberOfProcessors >= MaxNumberOfCpus) {
      break;
    }

    GuidHob = GetNextGuidHob (&gSmmBaseHobGuid, GET_NEXT_HOB (GuidHob));
  }

  ASSERT (NumberOfProcessors == MaxNumberOfCpus);
  if (NumberOfProcessors != MaxNumberOfCpus) {
    CpuDeadLoop ();
  }

  SmBaseHobs = AllocatePool (sizeof (SMM_BASE_HOB_DATA *) * HobCount);
  if (SmBaseHobs == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Record each SmmBaseHob pointer in the SmBaseHobs.
  // The FirstSmmBaseGuidHob is to speed up this while-loop
  // without needing to look for SmBaseHob from beginning.
  //
  GuidHob = FirstSmmBaseGuidHob;
  while (HobIndex < HobCount) {
    SmBaseHobs[HobIndex++] = GET_GUID_HOB_DATA (GuidHob);
    GuidHob                = GetNextGuidHob (&gSmmBaseHobGuid, GET_NEXT_HOB (GuidHob));
  }

  SmBaseBuffer = (UINTN *)AllocatePool (sizeof (UINTN) * (MaxNumberOfCpus));
  ASSERT (SmBaseBuffer != NULL);
  if (SmBaseBuffer == NULL) {
    FreePool (SmBaseHobs);
    return EFI_OUT_OF_RESOURCES;
  }

  QuickSort (SmBaseHobs, HobCount, sizeof (SMM_BASE_HOB_DATA *), (BASE_SORT_COMPARE)SmBaseHobCompare, &SortBuffer);
  PrevProcessorIndex = 0;
  for (HobIndex = 0; HobIndex < HobCount; HobIndex++) {
    //
    // Make sure no overlap and no gap in the CPU range covered by each HOB
    //
    ASSERT (SmBaseHobs[HobIndex]->ProcessorIndex == PrevProcessorIndex);

    //
    // Cache each SmBase in order.
    //
    for (ProcessorIndex = 0; ProcessorIndex < SmBaseHobs[HobIndex]->NumberOfProcessors; ProcessorIndex++) {
      SmBaseBuffer[PrevProcessorIndex + ProcessorIndex] = (UINTN)SmBaseHobs[HobIndex]->SmBase[ProcessorIndex];
    }

    PrevProcessorIndex += SmBaseHobs[HobIndex]->NumberOfProcessors;
  }

  FreePool (SmBaseHobs);
  *AllocatedSmBaseBuffer = SmBaseBuffer;
  return EFI_SUCCESS;
}

/**
  Function to compare 2 MP_INFORMATION2_HOB_DATA pointer based on ProcessorIndex.

  @param[in] Buffer1            pointer to MP_INFORMATION2_HOB_DATA poiner to compare
  @param[in] Buffer2            pointer to second MP_INFORMATION2_HOB_DATA pointer to compare

  @retval 0                     Buffer1 equal to Buffer2
  @retval <0                    Buffer1 is less than Buffer2
  @retval >0                    Buffer1 is greater than Buffer2
**/
INTN
EFIAPI
MpInformation2HobCompare (
  IN  CONST VOID  *Buffer1,
  IN  CONST VOID  *Buffer2
  )
{
  if ((*(MP_INFORMATION2_HOB_DATA **)Buffer1)->ProcessorIndex > (*(MP_INFORMATION2_HOB_DATA **)Buffer2)->ProcessorIndex) {
    return 1;
  } else if ((*(MP_INFORMATION2_HOB_DATA **)Buffer1)->ProcessorIndex < (*(MP_INFORMATION2_HOB_DATA **)Buffer2)->ProcessorIndex) {
    return -1;
  }

  return 0;
}

/**
  Extract NumberOfCpus, MaxNumberOfCpus and EFI_PROCESSOR_INFORMATION for all CPU from MpInformation2 HOB.

  @param[out] NumberOfCpus           Pointer to NumberOfCpus.
  @param[out] MaxNumberOfCpus        Pointer to MaxNumberOfCpus.

  @retval ProcessorInfo              Pointer to EFI_PROCESSOR_INFORMATION buffer.
**/
EFI_PROCESSOR_INFORMATION *
GetMpInformation (
  OUT UINTN  *NumberOfCpus,
  OUT UINTN  *MaxNumberOfCpus
  )
{
  EFI_HOB_GUID_TYPE          *GuidHob;
  EFI_HOB_GUID_TYPE          *FirstMpInfo2Hob;
  MP_INFORMATION2_HOB_DATA   *MpInformation2HobData;
  UINTN                      HobCount;
  UINTN                      HobIndex;
  MP_INFORMATION2_HOB_DATA   **MpInfo2Hobs;
  UINTN                      SortBuffer;
  UINTN                      ProcessorIndex;
  UINT64                     PrevProcessorIndex;
  MP_INFORMATION2_ENTRY      *MpInformation2Entry;
  EFI_PROCESSOR_INFORMATION  *ProcessorInfo;

  GuidHob               = NULL;
  MpInformation2HobData = NULL;
  FirstMpInfo2Hob       = NULL;
  MpInfo2Hobs           = NULL;
  HobIndex              = 0;
  HobCount              = 0;

  FirstMpInfo2Hob = GetFirstGuidHob (&gMpInformation2HobGuid);
  ASSERT (FirstMpInfo2Hob != NULL);
  GuidHob = FirstMpInfo2Hob;
  while (GuidHob != NULL) {
    MpInformation2HobData = GET_GUID_HOB_DATA (GuidHob);

    //
    // This is the last MpInformationHob in the HOB list.
    //
    if (MpInformation2HobData->NumberOfProcessors == 0) {
      ASSERT (HobCount != 0);
      break;
    }

    HobCount++;
    *NumberOfCpus += MpInformation2HobData->NumberOfProcessors;
    GuidHob        = GetNextGuidHob (&gMpInformation2HobGuid, GET_NEXT_HOB (GuidHob));
  }

  ASSERT (*NumberOfCpus <= PcdGet32 (PcdCpuMaxLogicalProcessorNumber));

  //
  // If support CPU hot plug, we need to allocate resources for possibly hot-added processors
  //
  if (FeaturePcdGet (PcdCpuHotPlugSupport)) {
    *MaxNumberOfCpus = PcdGet32 (PcdCpuMaxLogicalProcessorNumber);
  } else {
    *MaxNumberOfCpus = *NumberOfCpus;
  }

  MpInfo2Hobs = AllocatePool (sizeof (MP_INFORMATION2_HOB_DATA *) * HobCount);
  ASSERT (MpInfo2Hobs != NULL);
  if (MpInfo2Hobs == NULL) {
    return NULL;
  }

  //
  // Record each MpInformation2Hob pointer in the MpInfo2Hobs.
  // The FirstMpInfo2Hob is to speed up this while-loop without
  // needing to look for MpInfo2Hob from beginning.
  //
  GuidHob = FirstMpInfo2Hob;
  while (HobIndex < HobCount) {
    MpInfo2Hobs[HobIndex++] = GET_GUID_HOB_DATA (GuidHob);
    GuidHob                 = GetNextGuidHob (&gMpInformation2HobGuid, GET_NEXT_HOB (GuidHob));
  }

  ProcessorInfo = (EFI_PROCESSOR_INFORMATION *)AllocatePool (sizeof (EFI_PROCESSOR_INFORMATION) * (*MaxNumberOfCpus));
  ASSERT (ProcessorInfo != NULL);
  if (ProcessorInfo == NULL) {
    FreePool (MpInfo2Hobs);
    return NULL;
  }

  QuickSort (MpInfo2Hobs, HobCount, sizeof (MP_INFORMATION2_HOB_DATA *), (BASE_SORT_COMPARE)MpInformation2HobCompare, &SortBuffer);
  PrevProcessorIndex = 0;
  for (HobIndex = 0; HobIndex < HobCount; HobIndex++) {
    //
    // Make sure no overlap and no gap in the CPU range covered by each HOB
    //
    ASSERT (MpInfo2Hobs[HobIndex]->ProcessorIndex == PrevProcessorIndex);

    //
    // Cache each EFI_PROCESSOR_INFORMATION in order.
    //
    for (ProcessorIndex = 0; ProcessorIndex < MpInfo2Hobs[HobIndex]->NumberOfProcessors; ProcessorIndex++) {
      MpInformation2Entry = GET_MP_INFORMATION_ENTRY (MpInfo2Hobs[HobIndex], ProcessorIndex);
      CopyMem (
        &ProcessorInfo[PrevProcessorIndex + ProcessorIndex],
        &MpInformation2Entry->ProcessorInfo,
        sizeof (EFI_PROCESSOR_INFORMATION)
        );
    }

    PrevProcessorIndex += MpInfo2Hobs[HobIndex]->NumberOfProcessors;
  }

  FreePool (MpInfo2Hobs);
  return ProcessorInfo;
}

/**
  The module Entry Point of the CPU SMM driver.

  @param  ImageHandle    The firmware allocated handle for the EFI image.
  @param  SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS    The entry point is executed successfully.
  @retval Other          Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
PiCpuSmmEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  UINTN       Index;
  VOID        *Buffer;
  UINTN       BufferPages;
  UINTN       TileCodeSize;
  UINTN       TileDataSize;
  UINTN       TileSize;
  UINT8       *Stacks;
  VOID        *Registration;
  UINT32      RegEax;
  UINT32      RegEbx;
  UINT32      RegEcx;
  UINT32      RegEdx;
  UINTN       FamilyId;
  UINTN       ModelId;
  UINT32      Cr3;

  PERF_FUNCTION_BEGIN ();

  //
  // Initialize address fixup
  //
  PiSmmCpuSmmInitFixupAddress ();
  PiSmmCpuSmiEntryFixupAddress ();

  //
  // Initialize Debug Agent to support source level debug in SMM code
  //
  InitializeDebugAgent (DEBUG_AGENT_INIT_SMM, &mSmmDebugAgentSupport, NULL);

  //
  // Report the start of CPU SMM initialization.
  //
  REPORT_STATUS_CODE (
    EFI_PROGRESS_CODE,
    EFI_COMPUTING_UNIT_HOST_PROCESSOR | EFI_CU_HP_PC_SMM_INIT
    );

  //
  // Find out SMRR Base and SMRR Size
  //
  FindSmramInfo (&mCpuHotPlugData.SmrrBase, &mCpuHotPlugData.SmrrSize);

  //
  // Retrive NumberOfProcessors, MaxNumberOfCpus and EFI_PROCESSOR_INFORMATION for all CPU from MpInformation2 HOB.
  //
  gSmmCpuPrivate->ProcessorInfo = GetMpInformation (&mNumberOfCpus, &mMaxNumberOfCpus);
  ASSERT (gSmmCpuPrivate->ProcessorInfo != NULL);

  //
  // If support CPU hot plug, PcdCpuSmmEnableBspElection should be set to TRUE.
  // A constant BSP index makes no sense because it may be hot removed.
  //
  DEBUG_CODE_BEGIN ();
  if (FeaturePcdGet (PcdCpuHotPlugSupport)) {
    ASSERT (FeaturePcdGet (PcdCpuSmmEnableBspElection));
  }

  DEBUG_CODE_END ();

  //
  // Save the PcdCpuSmmCodeAccessCheckEnable value into a global variable.
  //
  mSmmCodeAccessCheckEnable = PcdGetBool (PcdCpuSmmCodeAccessCheckEnable);
  DEBUG ((DEBUG_INFO, "PcdCpuSmmCodeAccessCheckEnable = %d\n", mSmmCodeAccessCheckEnable));

  //
  // Save the PcdPteMemoryEncryptionAddressOrMask value into a global variable.
  // Make sure AddressEncMask is contained to smallest supported address field.
  //
  mAddressEncMask = PcdGet64 (PcdPteMemoryEncryptionAddressOrMask) & PAGING_1G_ADDRESS_MASK_64;
  DEBUG ((DEBUG_INFO, "mAddressEncMask = 0x%lx\n", mAddressEncMask));

  gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus = mMaxNumberOfCpus;

  PERF_CODE (
    InitializeMpPerf (gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus);
    );

  //
  // The CPU save state and code for the SMI entry point are tiled within an SMRAM
  // allocated buffer.  The minimum size of this buffer for a uniprocessor system
  // is 32 KB, because the entry point is SMBASE + 32KB, and CPU save state area
  // just below SMBASE + 64KB.  If more than one CPU is present in the platform,
  // then the SMI entry point and the CPU save state areas can be tiles to minimize
  // the total amount SMRAM required for all the CPUs.  The tile size can be computed
  // by adding the   // CPU save state size, any extra CPU specific context, and
  // the size of code that must be placed at the SMI entry point to transfer
  // control to a C function in the native SMM execution mode.  This size is
  // rounded up to the nearest power of 2 to give the tile size for a each CPU.
  // The total amount of memory required is the maximum number of CPUs that
  // platform supports times the tile size.  The picture below shows the tiling,
  // where m is the number of tiles that fit in 32KB.
  //
  //  +-----------------------------+  <-- 2^n offset from Base of allocated buffer
  //  |   CPU m+1 Save State        |
  //  +-----------------------------+
  //  |   CPU m+1 Extra Data        |
  //  +-----------------------------+
  //  |   Padding                   |
  //  +-----------------------------+
  //  |   CPU 2m  SMI Entry         |
  //  +#############################+  <-- Base of allocated buffer + 64 KB
  //  |   CPU m-1 Save State        |
  //  +-----------------------------+
  //  |   CPU m-1 Extra Data        |
  //  +-----------------------------+
  //  |   Padding                   |
  //  +-----------------------------+
  //  |   CPU 2m-1 SMI Entry        |
  //  +=============================+  <-- 2^n offset from Base of allocated buffer
  //  |   . . . . . . . . . . . .   |
  //  +=============================+  <-- 2^n offset from Base of allocated buffer
  //  |   CPU 2 Save State          |
  //  +-----------------------------+
  //  |   CPU 2 Extra Data          |
  //  +-----------------------------+
  //  |   Padding                   |
  //  +-----------------------------+
  //  |   CPU m+1 SMI Entry         |
  //  +=============================+  <-- Base of allocated buffer + 32 KB
  //  |   CPU 1 Save State          |
  //  +-----------------------------+
  //  |   CPU 1 Extra Data          |
  //  +-----------------------------+
  //  |   Padding                   |
  //  +-----------------------------+
  //  |   CPU m SMI Entry           |
  //  +#############################+  <-- Base of allocated buffer + 32 KB == CPU 0 SMBASE + 64 KB
  //  |   CPU 0 Save State          |
  //  +-----------------------------+
  //  |   CPU 0 Extra Data          |
  //  +-----------------------------+
  //  |   Padding                   |
  //  +-----------------------------+
  //  |   CPU m-1 SMI Entry         |
  //  +=============================+  <-- 2^n offset from Base of allocated buffer
  //  |   . . . . . . . . . . . .   |
  //  +=============================+  <-- 2^n offset from Base of allocated buffer
  //  |   Padding                   |
  //  +-----------------------------+
  //  |   CPU 1 SMI Entry           |
  //  +=============================+  <-- 2^n offset from Base of allocated buffer
  //  |   Padding                   |
  //  +-----------------------------+
  //  |   CPU 0 SMI Entry           |
  //  +#############################+  <-- Base of allocated buffer == CPU 0 SMBASE + 32 KB
  //

  //
  // Retrieve CPU Family
  //
  AsmCpuid (CPUID_VERSION_INFO, &RegEax, NULL, NULL, NULL);
  FamilyId = (RegEax >> 8) & 0xf;
  ModelId  = (RegEax >> 4) & 0xf;
  if ((FamilyId == 0x06) || (FamilyId == 0x0f)) {
    ModelId = ModelId | ((RegEax >> 12) & 0xf0);
  }

  RegEdx = 0;
  AsmCpuid (CPUID_EXTENDED_FUNCTION, &RegEax, NULL, NULL, NULL);
  if (RegEax >= CPUID_EXTENDED_CPU_SIG) {
    AsmCpuid (CPUID_EXTENDED_CPU_SIG, NULL, NULL, NULL, &RegEdx);
  }

  //
  // Determine the mode of the CPU at the time an SMI occurs
  //   Intel(R) 64 and IA-32 Architectures Software Developer's Manual
  //   Volume 3C, Section 34.4.1.1
  //
  mSmmSaveStateRegisterLma = EFI_SMM_SAVE_STATE_REGISTER_LMA_32BIT;
  if ((RegEdx & BIT29) != 0) {
    mSmmSaveStateRegisterLma = EFI_SMM_SAVE_STATE_REGISTER_LMA_64BIT;
  }

  if (FamilyId == 0x06) {
    if ((ModelId == 0x17) || (ModelId == 0x0f) || (ModelId == 0x1c)) {
      mSmmSaveStateRegisterLma = EFI_SMM_SAVE_STATE_REGISTER_LMA_64BIT;
    }
  }

  DEBUG ((DEBUG_INFO, "PcdControlFlowEnforcementPropertyMask = %d\n", PcdGet32 (PcdControlFlowEnforcementPropertyMask)));
  if (PcdGet32 (PcdControlFlowEnforcementPropertyMask) != 0) {
    AsmCpuid (CPUID_SIGNATURE, &RegEax, NULL, NULL, NULL);
    if (RegEax >= CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS) {
      AsmCpuidEx (CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS, CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS_SUB_LEAF_INFO, NULL, NULL, &RegEcx, &RegEdx);
      DEBUG ((DEBUG_INFO, "CPUID[7/0] ECX - 0x%08x\n", RegEcx));
      DEBUG ((DEBUG_INFO, "  CET_SS  - 0x%08x\n", RegEcx & CPUID_CET_SS));
      DEBUG ((DEBUG_INFO, "  CET_IBT - 0x%08x\n", RegEdx & CPUID_CET_IBT));
      if ((RegEcx & CPUID_CET_SS) == 0) {
        mCetSupported = FALSE;
        PatchInstructionX86 (mPatchCetSupported, mCetSupported, 1);
      }

      if (mCetSupported) {
        AsmCpuidEx (CPUID_EXTENDED_STATE, CPUID_EXTENDED_STATE_SUB_LEAF, NULL, &RegEbx, &RegEcx, NULL);
        DEBUG ((DEBUG_INFO, "CPUID[D/1] EBX - 0x%08x, ECX - 0x%08x\n", RegEbx, RegEcx));
        AsmCpuidEx (CPUID_EXTENDED_STATE, 11, &RegEax, NULL, &RegEcx, NULL);
        DEBUG ((DEBUG_INFO, "CPUID[D/11] EAX - 0x%08x, ECX - 0x%08x\n", RegEax, RegEcx));
        AsmCpuidEx (CPUID_EXTENDED_STATE, 12, &RegEax, NULL, &RegEcx, NULL);
        DEBUG ((DEBUG_INFO, "CPUID[D/12] EAX - 0x%08x, ECX - 0x%08x\n", RegEax, RegEcx));
      }
    } else {
      mCetSupported = FALSE;
      PatchInstructionX86 (mPatchCetSupported, mCetSupported, 1);
    }
  } else {
    mCetSupported = FALSE;
    PatchInstructionX86 (mPatchCetSupported, mCetSupported, 1);
  }

  //
  // Compute tile size of buffer required to hold the CPU SMRAM Save State Map, extra CPU
  // specific context start starts at SMBASE + SMM_PSD_OFFSET, and the SMI entry point.
  // This size is rounded up to nearest power of 2.
  //
  TileCodeSize = GetSmiHandlerSize ();
  TileCodeSize = ALIGN_VALUE (TileCodeSize, SIZE_4KB);
  TileDataSize = (SMRAM_SAVE_STATE_MAP_OFFSET - SMM_PSD_OFFSET) + sizeof (SMRAM_SAVE_STATE_MAP);
  TileDataSize = ALIGN_VALUE (TileDataSize, SIZE_4KB);
  TileSize     = TileDataSize + TileCodeSize - 1;
  TileSize     = 2 * GetPowerOfTwo32 ((UINT32)TileSize);
  DEBUG ((DEBUG_INFO, "SMRAM TileSize = 0x%08x (0x%08x, 0x%08x)\n", TileSize, TileCodeSize, TileDataSize));

  //
  // If the TileSize is larger than space available for the SMI Handler of
  // CPU[i], the extra CPU specific context of CPU[i+1], and the SMRAM Save
  // State Map of CPU[i+1], then ASSERT().  If this ASSERT() is triggered, then
  // the SMI Handler size must be reduced or the size of the extra CPU specific
  // context must be reduced.
  //
  ASSERT (TileSize <= (SMRAM_SAVE_STATE_MAP_OFFSET + sizeof (SMRAM_SAVE_STATE_MAP) - SMM_HANDLER_OFFSET));

  //
  // Retrive the allocated SmmBase from gSmmBaseHobGuid. If found,
  // means the SmBase relocation has been done.
  //
  mCpuHotPlugData.SmBase = NULL;
  Status                 = GetSmBase (mMaxNumberOfCpus, &mCpuHotPlugData.SmBase);
  if (Status == EFI_OUT_OF_RESOURCES) {
    ASSERT (Status != EFI_OUT_OF_RESOURCES);
    CpuDeadLoop ();
  }

  if (!EFI_ERROR (Status)) {
    ASSERT (mCpuHotPlugData.SmBase != NULL);
    //
    // Check whether the Required TileSize is enough.
    //
    if (TileSize > SIZE_8KB) {
      DEBUG ((DEBUG_ERROR, "The Range of Smbase in SMRAM is not enough -- Required TileSize = 0x%08x, Actual TileSize = 0x%08x\n", TileSize, SIZE_8KB));
      FreePool (mCpuHotPlugData.SmBase);
      FreePool (gSmmCpuPrivate->ProcessorInfo);
      CpuDeadLoop ();
      return RETURN_BUFFER_TOO_SMALL;
    }

    mSmmRelocated = TRUE;
  } else {
    ASSERT (Status == EFI_NOT_FOUND);
    ASSERT (mCpuHotPlugData.SmBase == NULL);
    //
    // When the HOB doesn't exist, allocate new SMBASE itself.
    //
    DEBUG ((DEBUG_INFO, "PiCpuSmmEntry: gSmmBaseHobGuid not found!\n"));

    mCpuHotPlugData.SmBase = (UINTN *)AllocatePool (sizeof (UINTN) * mMaxNumberOfCpus);
    if (mCpuHotPlugData.SmBase == NULL) {
      ASSERT (mCpuHotPlugData.SmBase != NULL);
      CpuDeadLoop ();
    }

    //
    // very old processors (i486 + pentium) need 32k not 4k alignment, exclude them.
    //
    ASSERT (FamilyId >= 6);
    //
    // Allocate buffer for all of the tiles.
    //
    BufferPages = EFI_SIZE_TO_PAGES (SIZE_32KB + TileSize * (mMaxNumberOfCpus - 1));
    Buffer      = AllocateAlignedCodePages (BufferPages, SIZE_4KB);
    if (Buffer == NULL) {
      DEBUG ((DEBUG_ERROR, "Failed to allocate %Lu pages.\n", (UINT64)BufferPages));
      CpuDeadLoop ();
      return EFI_OUT_OF_RESOURCES;
    }

    ASSERT (Buffer != NULL);
    DEBUG ((DEBUG_INFO, "New Allcoated SMRAM SaveState Buffer (0x%08x, 0x%08x)\n", Buffer, EFI_PAGES_TO_SIZE (BufferPages)));
  }

  //
  // Allocate buffer for pointers to array in  SMM_CPU_PRIVATE_DATA.
  //
  gSmmCpuPrivate->Operation = (SMM_CPU_OPERATION *)AllocatePool (sizeof (SMM_CPU_OPERATION) * mMaxNumberOfCpus);
  ASSERT (gSmmCpuPrivate->Operation != NULL);

  gSmmCpuPrivate->CpuSaveStateSize = (UINTN *)AllocatePool (sizeof (UINTN) * mMaxNumberOfCpus);
  ASSERT (gSmmCpuPrivate->CpuSaveStateSize != NULL);

  gSmmCpuPrivate->CpuSaveState = (VOID **)AllocatePool (sizeof (VOID *) * mMaxNumberOfCpus);
  ASSERT (gSmmCpuPrivate->CpuSaveState != NULL);

  mSmmCpuPrivateData.SmmCoreEntryContext.CpuSaveStateSize = gSmmCpuPrivate->CpuSaveStateSize;
  mSmmCpuPrivateData.SmmCoreEntryContext.CpuSaveState     = gSmmCpuPrivate->CpuSaveState;

  //
  // Allocate buffer for pointers to array in CPU_HOT_PLUG_DATA.
  //
  mCpuHotPlugData.ApicId = (UINT64 *)AllocatePool (sizeof (UINT64) * mMaxNumberOfCpus);
  ASSERT (mCpuHotPlugData.ApicId != NULL);
  mCpuHotPlugData.ArrayLength = (UINT32)mMaxNumberOfCpus;

  //
  // Retrieve APIC ID of each enabled processor from the MP Services protocol.
  // Also compute the SMBASE address, CPU Save State address, and CPU Save state
  // size for each CPU in the platform
  //
  for (Index = 0; Index < mMaxNumberOfCpus; Index++) {
    if (!mSmmRelocated) {
      mCpuHotPlugData.SmBase[Index] = (UINTN)Buffer + Index * TileSize - SMM_HANDLER_OFFSET;
    }

    gSmmCpuPrivate->CpuSaveStateSize[Index] = sizeof (SMRAM_SAVE_STATE_MAP);
    gSmmCpuPrivate->CpuSaveState[Index]     = (VOID *)(mCpuHotPlugData.SmBase[Index] + SMRAM_SAVE_STATE_MAP_OFFSET);
    gSmmCpuPrivate->Operation[Index]        = SmmCpuNone;

    if (Index < mNumberOfCpus) {
      mCpuHotPlugData.ApicId[Index] = gSmmCpuPrivate->ProcessorInfo[Index].ProcessorId;

      DEBUG ((
        DEBUG_INFO,
        "CPU[%03x]  APIC ID=%04x  SMBASE=%08x  SaveState=%08x  Size=%08x\n",
        Index,
        (UINT32)gSmmCpuPrivate->ProcessorInfo[Index].ProcessorId,
        mCpuHotPlugData.SmBase[Index],
        gSmmCpuPrivate->CpuSaveState[Index],
        gSmmCpuPrivate->CpuSaveStateSize[Index]
        ));
    } else {
      gSmmCpuPrivate->ProcessorInfo[Index].ProcessorId = INVALID_APIC_ID;
      mCpuHotPlugData.ApicId[Index]                    = INVALID_APIC_ID;
    }
  }

  //
  // Allocate SMI stacks for all processors.
  //
  mSmmStackSize = EFI_PAGES_TO_SIZE (EFI_SIZE_TO_PAGES (PcdGet32 (PcdCpuSmmStackSize)));
  if (FeaturePcdGet (PcdCpuSmmStackGuard)) {
    //
    // SMM Stack Guard Enabled
    //   2 more pages is allocated for each processor, one is guard page and the other is known good stack.
    //
    // +--------------------------------------------------+-----+--------------------------------------------------+
    // | Known Good Stack | Guard Page |     SMM Stack    | ... | Known Good Stack | Guard Page |     SMM Stack    |
    // +--------------------------------------------------+-----+--------------------------------------------------+
    // |        4K        |    4K       PcdCpuSmmStackSize|     |        4K        |    4K       PcdCpuSmmStackSize|
    // |<---------------- mSmmStackSize ----------------->|     |<---------------- mSmmStackSize ----------------->|
    // |                                                  |     |                                                  |
    // |<------------------ Processor 0 ----------------->|     |<------------------ Processor n ----------------->|
    //
    mSmmStackSize += EFI_PAGES_TO_SIZE (2);
  }

  mSmmShadowStackSize = 0;
  if ((PcdGet32 (PcdControlFlowEnforcementPropertyMask) != 0) && mCetSupported) {
    mSmmShadowStackSize = EFI_PAGES_TO_SIZE (EFI_SIZE_TO_PAGES (PcdGet32 (PcdCpuSmmShadowStackSize)));

    if (FeaturePcdGet (PcdCpuSmmStackGuard)) {
      //
      // SMM Stack Guard Enabled
      // Append Shadow Stack after normal stack
      //   2 more pages is allocated for each processor, one is guard page and the other is known good shadow stack.
      //
      // |= Stacks
      // +--------------------------------------------------+---------------------------------------------------------------+
      // | Known Good Stack | Guard Page |    SMM Stack     | Known Good Shadow Stack | Guard Page |    SMM Shadow Stack    |
      // +--------------------------------------------------+---------------------------------------------------------------+
      // |         4K       |    4K      |PcdCpuSmmStackSize|            4K           |    4K      |PcdCpuSmmShadowStackSize|
      // |<---------------- mSmmStackSize ----------------->|<--------------------- mSmmShadowStackSize ------------------->|
      // |                                                                                                                  |
      // |<-------------------------------------------- Processor N ------------------------------------------------------->|
      //
      mSmmShadowStackSize += EFI_PAGES_TO_SIZE (2);
    } else {
      //
      // SMM Stack Guard Disabled (Known Good Stack is still required for potential stack switch.)
      //   Append Shadow Stack after normal stack with 1 more page as known good shadow stack.
      //   1 more pages is allocated for each processor, it is known good stack.
      //
      //
      // |= Stacks
      // +-------------------------------------+--------------------------------------------------+
      // | Known Good Stack |    SMM Stack     | Known Good Shadow Stack |    SMM Shadow Stack    |
      // +-------------------------------------+--------------------------------------------------+
      // |        4K        |PcdCpuSmmStackSize|          4K             |PcdCpuSmmShadowStackSize|
      // |<---------- mSmmStackSize ---------->|<--------------- mSmmShadowStackSize ------------>|
      // |                                                                                        |
      // |<-------------------------------- Processor N ----------------------------------------->|
      //
      mSmmShadowStackSize += EFI_PAGES_TO_SIZE (1);
      mSmmStackSize       += EFI_PAGES_TO_SIZE (1);
    }
  }

  Stacks = (UINT8 *)AllocatePages (gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus * (EFI_SIZE_TO_PAGES (mSmmStackSize + mSmmShadowStackSize)));
  ASSERT (Stacks != NULL);
  mSmmStackArrayBase = (UINTN)Stacks;
  mSmmStackArrayEnd  = mSmmStackArrayBase + gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus * (mSmmStackSize + mSmmShadowStackSize) - 1;

  DEBUG ((DEBUG_INFO, "Stacks                   - 0x%x\n", Stacks));
  DEBUG ((DEBUG_INFO, "mSmmStackSize            - 0x%x\n", mSmmStackSize));
  DEBUG ((DEBUG_INFO, "PcdCpuSmmStackGuard      - 0x%x\n", FeaturePcdGet (PcdCpuSmmStackGuard)));
  if ((PcdGet32 (PcdControlFlowEnforcementPropertyMask) != 0) && mCetSupported) {
    DEBUG ((DEBUG_INFO, "mSmmShadowStackSize      - 0x%x\n", mSmmShadowStackSize));
  }

  //
  // Set SMI stack for SMM base relocation
  //
  PatchInstructionX86 (
    gPatchSmmInitStack,
    (UINTN)(Stacks + mSmmStackSize - sizeof (UINTN)),
    sizeof (UINTN)
    );

  //
  // Initialize IDT
  //
  InitializeSmmIdt ();

  //
  // Check whether Smm Relocation is done or not.
  // If not, will do the SmmBases Relocation here!!!
  //
  if (!mSmmRelocated) {
    //
    // Relocate SMM Base addresses to the ones allocated from SMRAM
    //
    mRebased = (BOOLEAN *)AllocateZeroPool (sizeof (BOOLEAN) * mMaxNumberOfCpus);
    ASSERT (mRebased != NULL);
    SmmRelocateBases ();

    //
    // Call hook for BSP to perform extra actions in normal mode after all
    // SMM base addresses have been relocated on all CPUs
    //
    SmmCpuFeaturesSmmRelocationComplete ();
  }

  DEBUG ((DEBUG_INFO, "mXdSupported - 0x%x\n", mXdSupported));

  //
  // SMM Time initialization
  //
  InitializeSmmTimer ();

  //
  // Initialize MP globals
  //
  Cr3 = InitializeMpServiceData (Stacks, mSmmStackSize, mSmmShadowStackSize);

  if ((PcdGet32 (PcdControlFlowEnforcementPropertyMask) != 0) && mCetSupported) {
    for (Index = 0; Index < gSmmCpuPrivate->SmmCoreEntryContext.NumberOfCpus; Index++) {
      SetShadowStack (
        Cr3,
        (EFI_PHYSICAL_ADDRESS)(UINTN)Stacks + mSmmStackSize + (mSmmStackSize + mSmmShadowStackSize) * Index,
        mSmmShadowStackSize
        );
      if (FeaturePcdGet (PcdCpuSmmStackGuard)) {
        ConvertMemoryPageAttributes (
          Cr3,
          mPagingMode,
          (EFI_PHYSICAL_ADDRESS)(UINTN)Stacks + mSmmStackSize + EFI_PAGES_TO_SIZE (1) + (mSmmStackSize + mSmmShadowStackSize) * Index,
          EFI_PAGES_TO_SIZE (1),
          EFI_MEMORY_RP,
          TRUE,
          NULL
          );
      }
    }
  }

  //
  // For relocated SMBASE, some MSRs & CSRs are still required to be configured in SMM Mode for SMM Initialization.
  // Those MSRs & CSRs must be configured before normal SMI sources happen.
  // So, here is to issue SMI IPI (All Excluding  Self SMM IPI + BSP SMM IPI) to execute first SMI init.
  //
  if (mSmmRelocated) {
    ExecuteFirstSmiInit ();

    //
    // Call hook for BSP to perform extra actions in normal mode after all
    // SMM base addresses have been relocated on all CPUs
    //
    SmmCpuFeaturesSmmRelocationComplete ();
  }

  //
  // Fill in SMM Reserved Regions
  //
  gSmmCpuPrivate->SmmReservedSmramRegion[0].SmramReservedStart = 0;
  gSmmCpuPrivate->SmmReservedSmramRegion[0].SmramReservedSize  = 0;

  //
  // Install the SMM Configuration Protocol onto a new handle on the handle database.
  // The entire SMM Configuration Protocol is allocated from SMRAM, so only a pointer
  // to an SMRAM address will be present in the handle database
  //
  Status = SystemTable->BootServices->InstallMultipleProtocolInterfaces (
                                        &gSmmCpuPrivate->SmmCpuHandle,
                                        &gEfiSmmConfigurationProtocolGuid,
                                        &gSmmCpuPrivate->SmmConfiguration,
                                        NULL
                                        );
  ASSERT_EFI_ERROR (Status);

  //
  // Install the SMM CPU Protocol into SMM protocol database
  //
  Status = gSmst->SmmInstallProtocolInterface (
                    &mSmmCpuHandle,
                    &gEfiSmmCpuProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &mSmmCpu
                    );
  ASSERT_EFI_ERROR (Status);

  //
  // Install the SMM Memory Attribute Protocol into SMM protocol database
  //
  Status = gSmst->SmmInstallProtocolInterface (
                    &mSmmCpuHandle,
                    &gEdkiiSmmMemoryAttributeProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &mSmmMemoryAttribute
                    );
  ASSERT_EFI_ERROR (Status);

  //
  // Initialize global buffer for MM MP.
  //
  InitializeDataForMmMp ();

  //
  // Initialize Package First Thread Index Info.
  //
  InitPackageFirstThreadIndexInfo ();

  //
  // Install the SMM Mp Protocol into SMM protocol database
  //
  Status = gSmst->SmmInstallProtocolInterface (
                    &mSmmCpuHandle,
                    &gEfiMmMpProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &mSmmMp
                    );
  ASSERT_EFI_ERROR (Status);

  //
  // Expose address of CPU Hot Plug Data structure if CPU hot plug is supported.
  //
  if (FeaturePcdGet (PcdCpuHotPlugSupport)) {
    Status = PcdSet64S (PcdCpuHotPlugDataAddress, (UINT64)(UINTN)&mCpuHotPlugData);
    ASSERT_EFI_ERROR (Status);
  }

  //
  // Initialize SMM CPU Services Support
  //
  Status = InitializeSmmCpuServices (mSmmCpuHandle);
  ASSERT_EFI_ERROR (Status);

  //
  // register SMM Ready To Lock Protocol notification
  //
  Status = gSmst->SmmRegisterProtocolNotify (
                    &gEfiSmmReadyToLockProtocolGuid,
                    SmmReadyToLockEventNotify,
                    &Registration
                    );
  ASSERT_EFI_ERROR (Status);

  //
  // Initialize SMM Profile feature
  //
  InitSmmProfile (Cr3);

  GetAcpiS3EnableFlag ();
  InitSmmS3ResumeState (Cr3);

  DEBUG ((DEBUG_INFO, "SMM CPU Module exit from SMRAM with EFI_SUCCESS\n"));

  PERF_FUNCTION_END ();
  return EFI_SUCCESS;
}

/**
  Function to compare 2 EFI_SMRAM_DESCRIPTOR based on CpuStart.

  @param[in] Buffer1            pointer to Device Path poiner to compare
  @param[in] Buffer2            pointer to second DevicePath pointer to compare

  @retval 0                     Buffer1 equal to Buffer2
  @retval <0                    Buffer1 is less than Buffer2
  @retval >0                    Buffer1 is greater than Buffer2
**/
INTN
EFIAPI
CpuSmramRangeCompare (
  IN  CONST VOID  *Buffer1,
  IN  CONST VOID  *Buffer2
  )
{
  if (((EFI_SMRAM_DESCRIPTOR *)Buffer1)->CpuStart > ((EFI_SMRAM_DESCRIPTOR *)Buffer2)->CpuStart) {
    return 1;
  } else if (((EFI_SMRAM_DESCRIPTOR *)Buffer1)->CpuStart < ((EFI_SMRAM_DESCRIPTOR *)Buffer2)->CpuStart) {
    return -1;
  }

  return 0;
}

/**

  Find out SMRAM information including SMRR base and SMRR size.

  @param          SmrrBase          SMRR base
  @param          SmrrSize          SMRR size

**/
VOID
FindSmramInfo (
  OUT UINT32  *SmrrBase,
  OUT UINT32  *SmrrSize
  )
{
  EFI_STATUS                Status;
  UINTN                     Size;
  EFI_SMM_ACCESS2_PROTOCOL  *SmmAccess;
  EFI_SMRAM_DESCRIPTOR      *CurrentSmramRange;
  UINTN                     Index;
  UINT64                    MaxSize;
  BOOLEAN                   Found;
  EFI_SMRAM_DESCRIPTOR      SmramDescriptor;

  //
  // Get SMM Access Protocol
  //
  Status = gBS->LocateProtocol (&gEfiSmmAccess2ProtocolGuid, NULL, (VOID **)&SmmAccess);
  ASSERT_EFI_ERROR (Status);

  //
  // Get SMRAM information
  //
  Size   = 0;
  Status = SmmAccess->GetCapabilities (SmmAccess, &Size, NULL);
  ASSERT (Status == EFI_BUFFER_TOO_SMALL);

  mSmmCpuSmramRanges = (EFI_SMRAM_DESCRIPTOR *)AllocatePool (Size);
  ASSERT (mSmmCpuSmramRanges != NULL);

  Status = SmmAccess->GetCapabilities (SmmAccess, &Size, mSmmCpuSmramRanges);
  ASSERT_EFI_ERROR (Status);

  mSmmCpuSmramRangeCount = Size / sizeof (EFI_SMRAM_DESCRIPTOR);

  //
  // Sort the mSmmCpuSmramRanges
  //
  QuickSort (mSmmCpuSmramRanges, mSmmCpuSmramRangeCount, sizeof (EFI_SMRAM_DESCRIPTOR), (BASE_SORT_COMPARE)CpuSmramRangeCompare, &SmramDescriptor);

  //
  // Find the largest SMRAM range between 1MB and 4GB that is at least 256K - 4K in size
  //
  CurrentSmramRange = NULL;
  for (Index = 0, MaxSize = SIZE_256KB - EFI_PAGE_SIZE; Index < mSmmCpuSmramRangeCount; Index++) {
    //
    // Skip any SMRAM region that is already allocated, needs testing, or needs ECC initialization
    //
    if ((mSmmCpuSmramRanges[Index].RegionState & (EFI_ALLOCATED | EFI_NEEDS_TESTING | EFI_NEEDS_ECC_INITIALIZATION)) != 0) {
      continue;
    }

    if (mSmmCpuSmramRanges[Index].CpuStart >= BASE_1MB) {
      if ((mSmmCpuSmramRanges[Index].CpuStart + mSmmCpuSmramRanges[Index].PhysicalSize) <= SMRR_MAX_ADDRESS) {
        if (mSmmCpuSmramRanges[Index].PhysicalSize >= MaxSize) {
          MaxSize           = mSmmCpuSmramRanges[Index].PhysicalSize;
          CurrentSmramRange = &mSmmCpuSmramRanges[Index];
        }
      }
    }
  }

  ASSERT (CurrentSmramRange != NULL);

  *SmrrBase = (UINT32)CurrentSmramRange->CpuStart;
  *SmrrSize = (UINT32)CurrentSmramRange->PhysicalSize;

  do {
    Found = FALSE;
    for (Index = 0; Index < mSmmCpuSmramRangeCount; Index++) {
      if ((mSmmCpuSmramRanges[Index].CpuStart < *SmrrBase) &&
          (*SmrrBase == (mSmmCpuSmramRanges[Index].CpuStart + mSmmCpuSmramRanges[Index].PhysicalSize)))
      {
        *SmrrBase = (UINT32)mSmmCpuSmramRanges[Index].CpuStart;
        *SmrrSize = (UINT32)(*SmrrSize + mSmmCpuSmramRanges[Index].PhysicalSize);
        Found     = TRUE;
      } else if (((*SmrrBase + *SmrrSize) == mSmmCpuSmramRanges[Index].CpuStart) && (mSmmCpuSmramRanges[Index].PhysicalSize > 0)) {
        *SmrrSize = (UINT32)(*SmrrSize + mSmmCpuSmramRanges[Index].PhysicalSize);
        Found     = TRUE;
      }
    }
  } while (Found);

  DEBUG ((DEBUG_INFO, "SMRR Base: 0x%x, SMRR Size: 0x%x\n", *SmrrBase, *SmrrSize));
}

/**
Configure SMM Code Access Check feature on an AP.
SMM Feature Control MSR will be locked after configuration.

@param[in,out] Buffer  Pointer to private data buffer.
**/
VOID
EFIAPI
ConfigSmmCodeAccessCheckOnCurrentProcessor (
  IN OUT VOID  *Buffer
  )
{
  UINTN   CpuIndex;
  UINT64  SmmFeatureControlMsr;
  UINT64  NewSmmFeatureControlMsr;

  //
  // Retrieve the CPU Index from the context passed in
  //
  CpuIndex = *(UINTN *)Buffer;

  //
  // Get the current SMM Feature Control MSR value
  //
  SmmFeatureControlMsr = SmmCpuFeaturesGetSmmRegister (CpuIndex, SmmRegFeatureControl);

  //
  // Compute the new SMM Feature Control MSR value
  //
  NewSmmFeatureControlMsr = SmmFeatureControlMsr;
  if (mSmmCodeAccessCheckEnable) {
    NewSmmFeatureControlMsr |= SMM_CODE_CHK_EN_BIT;
    if (FeaturePcdGet (PcdCpuSmmFeatureControlMsrLock)) {
      NewSmmFeatureControlMsr |= SMM_FEATURE_CONTROL_LOCK_BIT;
    }
  }

  //
  // Only set the SMM Feature Control MSR value if the new value is different than the current value
  //
  if (NewSmmFeatureControlMsr != SmmFeatureControlMsr) {
    SmmCpuFeaturesSetSmmRegister (CpuIndex, SmmRegFeatureControl, NewSmmFeatureControlMsr);
  }

  //
  // Release the spin lock user to serialize the updates to the SMM Feature Control MSR
  //
  ReleaseSpinLock (mConfigSmmCodeAccessCheckLock);
}

/**
Configure SMM Code Access Check feature for all processors.
SMM Feature Control MSR will be locked after configuration.
**/
VOID
ConfigSmmCodeAccessCheck (
  VOID
  )
{
  UINTN       Index;
  EFI_STATUS  Status;

  PERF_FUNCTION_BEGIN ();

  //
  // Check to see if the Feature Control MSR is supported on this CPU
  //
  Index = gSmmCpuPrivate->SmmCoreEntryContext.CurrentlyExecutingCpu;
  if (!SmmCpuFeaturesIsSmmRegisterSupported (Index, SmmRegFeatureControl)) {
    mSmmCodeAccessCheckEnable = FALSE;
    PERF_FUNCTION_END ();
    return;
  }

  //
  // Check to see if the CPU supports the SMM Code Access Check feature
  // Do not access this MSR unless the CPU supports the SmmRegFeatureControl
  //
  if ((AsmReadMsr64 (EFI_MSR_SMM_MCA_CAP) & SMM_CODE_ACCESS_CHK_BIT) == 0) {
    mSmmCodeAccessCheckEnable = FALSE;
    PERF_FUNCTION_END ();
    return;
  }

  //
  // Initialize the lock used to serialize the MSR programming in BSP and all APs
  //
  InitializeSpinLock (mConfigSmmCodeAccessCheckLock);

  //
  // Acquire Config SMM Code Access Check spin lock.  The BSP will release the
  // spin lock when it is done executing ConfigSmmCodeAccessCheckOnCurrentProcessor().
  //
  AcquireSpinLock (mConfigSmmCodeAccessCheckLock);

  //
  // Enable SMM Code Access Check feature on the BSP.
  //
  ConfigSmmCodeAccessCheckOnCurrentProcessor (&Index);

  //
  // Enable SMM Code Access Check feature for the APs.
  //
  for (Index = 0; Index < gSmst->NumberOfCpus; Index++) {
    if (Index != gSmmCpuPrivate->SmmCoreEntryContext.CurrentlyExecutingCpu) {
      if (gSmmCpuPrivate->ProcessorInfo[Index].ProcessorId == INVALID_APIC_ID) {
        //
        // If this processor does not exist
        //
        continue;
      }

      //
      // Acquire Config SMM Code Access Check spin lock.  The AP will release the
      // spin lock when it is done executing ConfigSmmCodeAccessCheckOnCurrentProcessor().
      //
      AcquireSpinLock (mConfigSmmCodeAccessCheckLock);

      //
      // Call SmmStartupThisAp() to enable SMM Code Access Check on an AP.
      //
      Status = gSmst->SmmStartupThisAp (ConfigSmmCodeAccessCheckOnCurrentProcessor, Index, &Index);
      ASSERT_EFI_ERROR (Status);

      //
      // Wait for the AP to release the Config SMM Code Access Check spin lock.
      //
      while (!AcquireSpinLockOrFail (mConfigSmmCodeAccessCheckLock)) {
        CpuPause ();
      }

      //
      // Release the Config SMM Code Access Check spin lock.
      //
      ReleaseSpinLock (mConfigSmmCodeAccessCheckLock);
    }
  }

  PERF_FUNCTION_END ();
}

/**
  Allocate pages for code.

  @param[in]  Pages Number of pages to be allocated.

  @return Allocated memory.
**/
VOID *
AllocateCodePages (
  IN UINTN  Pages
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  Memory;

  if (Pages == 0) {
    return NULL;
  }

  Status = gSmst->SmmAllocatePages (AllocateAnyPages, EfiRuntimeServicesCode, Pages, &Memory);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  return (VOID *)(UINTN)Memory;
}

/**
  Allocate aligned pages for code.

  @param[in]  Pages                 Number of pages to be allocated.
  @param[in]  Alignment             The requested alignment of the allocation.
                                    Must be a power of two.
                                    If Alignment is zero, then byte alignment is used.

  @return Allocated memory.
**/
VOID *
AllocateAlignedCodePages (
  IN UINTN  Pages,
  IN UINTN  Alignment
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  Memory;
  UINTN                 AlignedMemory;
  UINTN                 AlignmentMask;
  UINTN                 UnalignedPages;
  UINTN                 RealPages;

  //
  // Alignment must be a power of two or zero.
  //
  ASSERT ((Alignment & (Alignment - 1)) == 0);

  if (Pages == 0) {
    return NULL;
  }

  if (Alignment > EFI_PAGE_SIZE) {
    //
    // Calculate the total number of pages since alignment is larger than page size.
    //
    AlignmentMask = Alignment - 1;
    RealPages     = Pages + EFI_SIZE_TO_PAGES (Alignment);
    //
    // Make sure that Pages plus EFI_SIZE_TO_PAGES (Alignment) does not overflow.
    //
    ASSERT (RealPages > Pages);

    Status = gSmst->SmmAllocatePages (AllocateAnyPages, EfiRuntimeServicesCode, RealPages, &Memory);
    if (EFI_ERROR (Status)) {
      return NULL;
    }

    AlignedMemory  = ((UINTN)Memory + AlignmentMask) & ~AlignmentMask;
    UnalignedPages = EFI_SIZE_TO_PAGES (AlignedMemory - (UINTN)Memory);
    if (UnalignedPages > 0) {
      //
      // Free first unaligned page(s).
      //
      Status = gSmst->SmmFreePages (Memory, UnalignedPages);
      ASSERT_EFI_ERROR (Status);
    }

    Memory         = AlignedMemory + EFI_PAGES_TO_SIZE (Pages);
    UnalignedPages = RealPages - Pages - UnalignedPages;
    if (UnalignedPages > 0) {
      //
      // Free last unaligned page(s).
      //
      Status = gSmst->SmmFreePages (Memory, UnalignedPages);
      ASSERT_EFI_ERROR (Status);
    }
  } else {
    //
    // Do not over-allocate pages in this case.
    //
    Status = gSmst->SmmAllocatePages (AllocateAnyPages, EfiRuntimeServicesCode, Pages, &Memory);
    if (EFI_ERROR (Status)) {
      return NULL;
    }

    AlignedMemory = (UINTN)Memory;
  }

  return (VOID *)AlignedMemory;
}

/**
  Perform the remaining tasks.

**/
VOID
PerformRemainingTasks (
  VOID
  )
{
  if (mSmmReadyToLock) {
    PERF_FUNCTION_BEGIN ();

    //
    // Check if all Aps enter SMM. In Relaxed-AP Sync Mode, BSP will not wait for
    // all Aps arrive. However,PerformRemainingTasks() needs to wait all Aps arrive before calling
    // SetMemMapAttributes() and ConfigSmmCodeAccessCheck() when mSmmReadyToLock
    // is true. In SetMemMapAttributes(), SmmSetMemoryAttributesEx() will call
    // FlushTlbForAll() that need to start up the aps. So it need to let all
    // aps arrive. Same as SetMemMapAttributes(), ConfigSmmCodeAccessCheck()
    // also will start up the aps.
    //
    if (EFI_ERROR (SmmCpuRendezvous (NULL, TRUE))) {
      DEBUG ((DEBUG_ERROR, "PerformRemainingTasks: fail to wait for all AP check in SMM!\n"));
    }

    //
    // Start SMM Profile feature
    //
    if (FeaturePcdGet (PcdCpuSmmProfileEnable)) {
      SmmProfileStart ();
    }

    //
    // Create a mix of 2MB and 4KB page table. Update some memory ranges absent and execute-disable.
    //
    InitPaging ();

    //
    // Mark critical region to be read-only in page table
    //
    SetMemMapAttributes ();

    if (IsRestrictedMemoryAccess ()) {
      //
      // For outside SMRAM, we only map SMM communication buffer or MMIO.
      //
      SetUefiMemMapAttributes ();

      //
      // Set page table itself to be read-only
      //
      SetPageTableAttributes ();
    }

    //
    // Configure SMM Code Access Check feature if available.
    //
    ConfigSmmCodeAccessCheck ();

    //
    // Measure performance of SmmCpuFeaturesCompleteSmmReadyToLock() from caller side
    // as the implementation is provided by platform.
    //
    PERF_START (NULL, "SmmCompleteReadyToLock", NULL, 0);
    SmmCpuFeaturesCompleteSmmReadyToLock ();
    PERF_END (NULL, "SmmCompleteReadyToLock", NULL, 0);

    //
    // Clean SMM ready to lock flag
    //
    mSmmReadyToLock = FALSE;

    PERF_FUNCTION_END ();
  }
}

/**
  Perform the pre tasks.

**/
VOID
PerformPreTasks (
  VOID
  )
{
  RestoreSmmConfigurationInS3 ();
}
