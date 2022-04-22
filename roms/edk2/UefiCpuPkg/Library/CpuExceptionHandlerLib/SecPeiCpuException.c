/** @file
  CPU exception handler library implemenation for SEC/PEIM modules.

Copyright (c) 2012 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <Library/VmgExitLib.h>
#include "CpuExceptionCommon.h"

CONST UINTN  mDoFarReturnFlag = 0;

/**
  Common exception handler.

  @param ExceptionType  Exception type.
  @param SystemContext  Pointer to EFI_SYSTEM_CONTEXT.
**/
VOID
EFIAPI
CommonExceptionHandler (
  IN EFI_EXCEPTION_TYPE  ExceptionType,
  IN EFI_SYSTEM_CONTEXT  SystemContext
  )
{
  if (ExceptionType == VC_EXCEPTION) {
    EFI_STATUS  Status;
    //
    // #VC needs to be handled immediately upon enabling exception handling
    // and therefore can't use the RegisterCpuInterruptHandler() interface
    // (which isn't supported under Sec and Pei anyway).
    //
    // Handle the #VC:
    //   On EFI_SUCCESS - Exception has been handled, return
    //   On other       - ExceptionType contains (possibly new) exception
    //                    value
    //
    Status = VmgExitHandleVc (&ExceptionType, SystemContext);
    if (!EFI_ERROR (Status)) {
      return;
    }
  }

  //
  // Initialize the serial port before dumping.
  //
  SerialPortInitialize ();
  //
  // Display ExceptionType, CPU information and Image information
  //
  DumpImageAndCpuContent (ExceptionType, SystemContext);

  //
  // Enter a dead loop.
  //
  CpuDeadLoop ();
}

/**
  Initializes all CPU exceptions entries and provides the default exception handlers.

  Caller should try to get an array of interrupt and/or exception vectors that are in use and need to
  persist by EFI_VECTOR_HANDOFF_INFO defined in PI 1.3 specification.
  If caller cannot get reserved vector list or it does not exists, set VectorInfo to NULL.
  If VectorInfo is not NULL, the exception vectors will be initialized per vector attribute accordingly.
  Note: Before invoking this API, caller must allocate memory for IDT table and load
        IDTR by AsmWriteIdtr().

  @param[in]  VectorInfo    Pointer to reserved vector list.

  @retval EFI_SUCCESS           CPU Exception Entries have been successfully initialized
                                with default exception handlers.
  @retval EFI_INVALID_PARAMETER VectorInfo includes the invalid content if VectorInfo is not NULL.
  @retval EFI_UNSUPPORTED       This function is not supported.

**/
EFI_STATUS
EFIAPI
InitializeCpuExceptionHandlers (
  IN EFI_VECTOR_HANDOFF_INFO  *VectorInfo OPTIONAL
  )
{
  EFI_STATUS                      Status;
  RESERVED_VECTORS_DATA           ReservedVectorData[CPU_EXCEPTION_NUM];
  IA32_DESCRIPTOR                 IdtDescriptor;
  UINTN                           IdtEntryCount;
  UINT16                          CodeSegment;
  EXCEPTION_HANDLER_TEMPLATE_MAP  TemplateMap;
  IA32_IDT_GATE_DESCRIPTOR        *IdtTable;
  UINTN                           Index;
  UINTN                           InterruptHandler;

  if (VectorInfo != NULL) {
    SetMem ((VOID *)ReservedVectorData, sizeof (RESERVED_VECTORS_DATA) * CPU_EXCEPTION_NUM, 0xff);
    Status = ReadAndVerifyVectorInfo (VectorInfo, ReservedVectorData, CPU_EXCEPTION_NUM);
    if (EFI_ERROR (Status)) {
      return EFI_INVALID_PARAMETER;
    }
  }

  //
  // Read IDT descriptor and calculate IDT size
  //
  AsmReadIdtr (&IdtDescriptor);
  IdtEntryCount = (IdtDescriptor.Limit + 1) / sizeof (IA32_IDT_GATE_DESCRIPTOR);
  if (IdtEntryCount > CPU_EXCEPTION_NUM) {
    //
    // CPU exception library only setup CPU_EXCEPTION_NUM exception handler at most
    //
    IdtEntryCount = CPU_EXCEPTION_NUM;
  }

  //
  // Use current CS as the segment selector of interrupt gate in IDT
  //
  CodeSegment = AsmReadCs ();

  AsmGetTemplateAddressMap (&TemplateMap);
  IdtTable = (IA32_IDT_GATE_DESCRIPTOR *)IdtDescriptor.Base;
  for (Index = 0; Index < IdtEntryCount; Index++) {
    IdtTable[Index].Bits.Selector = CodeSegment;
    //
    // Check reserved vectors attributes if has, only EFI_VECTOR_HANDOFF_DO_NOT_HOOK
    // supported in this instance
    //
    if (VectorInfo != NULL) {
      if (ReservedVectorData[Index].Attribute == EFI_VECTOR_HANDOFF_DO_NOT_HOOK) {
        continue;
      }
    }

    //
    // Update IDT entry
    //
    InterruptHandler = TemplateMap.ExceptionStart + Index * TemplateMap.ExceptionStubHeaderSize;
    ArchUpdateIdtEntry (&IdtTable[Index], InterruptHandler);
  }

  return EFI_SUCCESS;
}

/**
  Initializes all CPU interrupt/exceptions entries and provides the default interrupt/exception handlers.

  Caller should try to get an array of interrupt and/or exception vectors that are in use and need to
  persist by EFI_VECTOR_HANDOFF_INFO defined in PI 1.3 specification.
  If caller cannot get reserved vector list or it does not exists, set VectorInfo to NULL.
  If VectorInfo is not NULL, the exception vectors will be initialized per vector attribute accordingly.

  @param[in]  VectorInfo    Pointer to reserved vector list.

  @retval EFI_SUCCESS           All CPU interrupt/exception entries have been successfully initialized
                                with default interrupt/exception handlers.
  @retval EFI_INVALID_PARAMETER VectorInfo includes the invalid content if VectorInfo is not NULL.
  @retval EFI_UNSUPPORTED       This function is not supported.

**/
EFI_STATUS
EFIAPI
InitializeCpuInterruptHandlers (
  IN EFI_VECTOR_HANDOFF_INFO  *VectorInfo OPTIONAL
  )
{
  return EFI_UNSUPPORTED;
}

/**
  Registers a function to be called from the processor interrupt handler.

  This function registers and enables the handler specified by InterruptHandler for a processor
  interrupt or exception type specified by InterruptType. If InterruptHandler is NULL, then the
  handler for the processor interrupt or exception type specified by InterruptType is uninstalled.
  The installed handler is called once for each processor interrupt or exception.
  NOTE: This function should be invoked after InitializeCpuExceptionHandlers() or
  InitializeCpuInterruptHandlers() invoked, otherwise EFI_UNSUPPORTED returned.

  @param[in]  InterruptType     Defines which interrupt or exception to hook.
  @param[in]  InterruptHandler  A pointer to a function of type EFI_CPU_INTERRUPT_HANDLER that is called
                                when a processor interrupt occurs. If this parameter is NULL, then the handler
                                will be uninstalled.

  @retval EFI_SUCCESS           The handler for the processor interrupt was successfully installed or uninstalled.
  @retval EFI_ALREADY_STARTED   InterruptHandler is not NULL, and a handler for InterruptType was
                                previously installed.
  @retval EFI_INVALID_PARAMETER InterruptHandler is NULL, and a handler for InterruptType was not
                                previously installed.
  @retval EFI_UNSUPPORTED       The interrupt specified by InterruptType is not supported,
                                or this function is not supported.
**/
EFI_STATUS
EFIAPI
RegisterCpuInterruptHandler (
  IN EFI_EXCEPTION_TYPE         InterruptType,
  IN EFI_CPU_INTERRUPT_HANDLER  InterruptHandler
  )
{
  return EFI_UNSUPPORTED;
}

/**
  Initializes all CPU exceptions entries with optional extra initializations.

  By default, this method should include all functionalities implemented by
  InitializeCpuExceptionHandlers(), plus extra initialization works, if any.
  This could be done by calling InitializeCpuExceptionHandlers() directly
  in this method besides the extra works.

  InitData is optional and its use and content are processor arch dependent.
  The typical usage of it is to convey resources which have to be reserved
  elsewhere and are necessary for the extra initializations of exception.

  @param[in]  VectorInfo    Pointer to reserved vector list.
  @param[in]  InitData      Pointer to data optional for extra initializations
                            of exception.

  @retval EFI_SUCCESS             The exceptions have been successfully
                                  initialized.
  @retval EFI_INVALID_PARAMETER   VectorInfo or InitData contains invalid
                                  content.

**/
EFI_STATUS
EFIAPI
InitializeCpuExceptionHandlersEx (
  IN EFI_VECTOR_HANDOFF_INFO  *VectorInfo OPTIONAL,
  IN CPU_EXCEPTION_INIT_DATA  *InitData OPTIONAL
  )
{
  return InitializeCpuExceptionHandlers (VectorInfo);
}
