/** @file
  It updates TPM items in ACPI table and registers SMI callback
  functions for physical presence and ClearMemory.

  Caution: This module requires additional review when modified.
  This driver will have external input - variable and ACPINvs data in SMM mode.
  This external input must be validated carefully to avoid security issue.

  PhysicalPresenceCallback() and MemoryClearCallback() will receive untrusted input and do some check.

Copyright (c) 2011 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TcgSmm.h"

EFI_SMM_VARIABLE_PROTOCOL  *mSmmVariable;
TCG_NVS                    *mTcgNvs;

/**
  Software SMI callback for TPM physical presence which is called from ACPI method.

  Caution: This function may receive untrusted input.
  Variable and ACPINvs are external input, so this function will validate
  its data structure to be valid value.

  @param[in]      DispatchHandle  The unique handle assigned to this handler by SmiHandlerRegister().
  @param[in]      Context         Points to an optional handler context which was specified when the
                                  handler was registered.
  @param[in, out] CommBuffer      A pointer to a collection of data in memory that will
                                  be conveyed from a non-SMM environment into an SMM environment.
  @param[in, out] CommBufferSize  The size of the CommBuffer.

  @retval EFI_SUCCESS             The interrupt was handled successfully.

**/
EFI_STATUS
EFIAPI
PhysicalPresenceCallback (
  IN EFI_HANDLE  DispatchHandle,
  IN CONST VOID  *Context,
  IN OUT VOID    *CommBuffer,
  IN OUT UINTN   *CommBufferSize
  )
{
  EFI_STATUS                   Status;
  UINTN                        DataSize;
  EFI_PHYSICAL_PRESENCE        PpData;
  EFI_PHYSICAL_PRESENCE_FLAGS  Flags;
  BOOLEAN                      RequestConfirmed;

  //
  // Get the Physical Presence variable
  //
  DataSize = sizeof (EFI_PHYSICAL_PRESENCE);
  Status   = mSmmVariable->SmmGetVariable (
                             PHYSICAL_PRESENCE_VARIABLE,
                             &gEfiPhysicalPresenceGuid,
                             NULL,
                             &DataSize,
                             &PpData
                             );

  DEBUG ((DEBUG_INFO, "[TPM] PP callback, Parameter = %x\n", mTcgNvs->PhysicalPresence.Parameter));
  if (mTcgNvs->PhysicalPresence.Parameter == ACPI_FUNCTION_RETURN_REQUEST_RESPONSE_TO_OS) {
    if (EFI_ERROR (Status)) {
      mTcgNvs->PhysicalPresence.ReturnCode  = PP_RETURN_TPM_OPERATION_RESPONSE_FAILURE;
      mTcgNvs->PhysicalPresence.LastRequest = 0;
      mTcgNvs->PhysicalPresence.Response    = 0;
      DEBUG ((DEBUG_ERROR, "[TPM] Get PP variable failure! Status = %r\n", Status));
      return EFI_SUCCESS;
    }

    mTcgNvs->PhysicalPresence.ReturnCode  = PP_RETURN_TPM_OPERATION_RESPONSE_SUCCESS;
    mTcgNvs->PhysicalPresence.LastRequest = PpData.LastPPRequest;
    mTcgNvs->PhysicalPresence.Response    = PpData.PPResponse;
  } else if (  (mTcgNvs->PhysicalPresence.Parameter == ACPI_FUNCTION_SUBMIT_REQUEST_TO_BIOS)
            || (mTcgNvs->PhysicalPresence.Parameter == ACPI_FUNCTION_SUBMIT_REQUEST_TO_BIOS_2))
  {
    if (EFI_ERROR (Status)) {
      mTcgNvs->PhysicalPresence.ReturnCode = TCG_PP_SUBMIT_REQUEST_TO_PREOS_GENERAL_FAILURE;
      DEBUG ((DEBUG_ERROR, "[TPM] Get PP variable failure! Status = %r\n", Status));
      return EFI_SUCCESS;
    }

    if (mTcgNvs->PhysicalPresence.Request == PHYSICAL_PRESENCE_SET_OPERATOR_AUTH) {
      //
      // This command requires UI to prompt user for Auth data.
      //
      mTcgNvs->PhysicalPresence.ReturnCode = TCG_PP_SUBMIT_REQUEST_TO_PREOS_NOT_IMPLEMENTED;
      return EFI_SUCCESS;
    }

    if (PpData.PPRequest != mTcgNvs->PhysicalPresence.Request) {
      PpData.PPRequest = (UINT8)mTcgNvs->PhysicalPresence.Request;
      DataSize         = sizeof (EFI_PHYSICAL_PRESENCE);
      Status           = mSmmVariable->SmmSetVariable (
                                         PHYSICAL_PRESENCE_VARIABLE,
                                         &gEfiPhysicalPresenceGuid,
                                         EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
                                         DataSize,
                                         &PpData
                                         );
    }

    if (EFI_ERROR (Status)) {
      mTcgNvs->PhysicalPresence.ReturnCode = TCG_PP_SUBMIT_REQUEST_TO_PREOS_GENERAL_FAILURE;
      return EFI_SUCCESS;
    }

    mTcgNvs->PhysicalPresence.ReturnCode = TCG_PP_SUBMIT_REQUEST_TO_PREOS_SUCCESS;

    if (mTcgNvs->PhysicalPresence.Request >= TCG_PHYSICAL_PRESENCE_VENDOR_SPECIFIC_OPERATION) {
      DataSize = sizeof (EFI_PHYSICAL_PRESENCE_FLAGS);
      Status   = mSmmVariable->SmmGetVariable (
                                 PHYSICAL_PRESENCE_FLAGS_VARIABLE,
                                 &gEfiPhysicalPresenceGuid,
                                 NULL,
                                 &DataSize,
                                 &Flags
                                 );
      if (EFI_ERROR (Status)) {
        Flags.PPFlags = TCG_BIOS_TPM_MANAGEMENT_FLAG_NO_PPI_PROVISION;
      }

      mTcgNvs->PhysicalPresence.ReturnCode = TcgPpVendorLibSubmitRequestToPreOSFunction (mTcgNvs->PhysicalPresence.Request, Flags.PPFlags);
    }
  } else if (mTcgNvs->PhysicalPresence.Parameter == ACPI_FUNCTION_GET_USER_CONFIRMATION_STATUS_FOR_REQUEST) {
    if (EFI_ERROR (Status)) {
      mTcgNvs->PhysicalPresence.ReturnCode = TCG_PP_GET_USER_CONFIRMATION_BLOCKED_BY_BIOS_CONFIGURATION;
      DEBUG ((DEBUG_ERROR, "[TPM] Get PP variable failure! Status = %r\n", Status));
      return EFI_SUCCESS;
    }

    //
    // Get the Physical Presence flags
    //
    DataSize = sizeof (EFI_PHYSICAL_PRESENCE_FLAGS);
    Status   = mSmmVariable->SmmGetVariable (
                               PHYSICAL_PRESENCE_FLAGS_VARIABLE,
                               &gEfiPhysicalPresenceGuid,
                               NULL,
                               &DataSize,
                               &Flags
                               );
    if (EFI_ERROR (Status)) {
      mTcgNvs->PhysicalPresence.ReturnCode = TCG_PP_GET_USER_CONFIRMATION_BLOCKED_BY_BIOS_CONFIGURATION;
      DEBUG ((DEBUG_ERROR, "[TPM] Get PP flags failure! Status = %r\n", Status));
      return EFI_SUCCESS;
    }

    RequestConfirmed = FALSE;

    switch (mTcgNvs->PPRequestUserConfirm) {
      case PHYSICAL_PRESENCE_ENABLE:
      case PHYSICAL_PRESENCE_DISABLE:
      case PHYSICAL_PRESENCE_ACTIVATE:
      case PHYSICAL_PRESENCE_DEACTIVATE:
      case PHYSICAL_PRESENCE_ENABLE_ACTIVATE:
      case PHYSICAL_PRESENCE_DEACTIVATE_DISABLE:
      case PHYSICAL_PRESENCE_SET_OWNER_INSTALL_TRUE:
      case PHYSICAL_PRESENCE_SET_OWNER_INSTALL_FALSE:
      case PHYSICAL_PRESENCE_ENABLE_ACTIVATE_OWNER_TRUE:
      case PHYSICAL_PRESENCE_DEACTIVATE_DISABLE_OWNER_FALSE:
        if ((Flags.PPFlags & TCG_BIOS_TPM_MANAGEMENT_FLAG_NO_PPI_PROVISION) != 0) {
          RequestConfirmed = TRUE;
        }

        break;

      case PHYSICAL_PRESENCE_CLEAR:
      case PHYSICAL_PRESENCE_ENABLE_ACTIVATE_CLEAR:
        if ((Flags.PPFlags & TCG_BIOS_TPM_MANAGEMENT_FLAG_NO_PPI_CLEAR) != 0) {
          RequestConfirmed = TRUE;
        }

        break;

      case PHYSICAL_PRESENCE_DEFERRED_PP_UNOWNERED_FIELD_UPGRADE:
        if ((Flags.PPFlags & TCG_BIOS_TPM_MANAGEMENT_FLAG_NO_PPI_MAINTENANCE) != 0) {
          RequestConfirmed = TRUE;
        }

        break;

      case PHYSICAL_PRESENCE_ENABLE_ACTIVATE_CLEAR_ENABLE_ACTIVATE:
      case PHYSICAL_PRESENCE_CLEAR_ENABLE_ACTIVATE:
        if (((Flags.PPFlags & TCG_BIOS_TPM_MANAGEMENT_FLAG_NO_PPI_CLEAR) != 0) && ((Flags.PPFlags & TCG_BIOS_TPM_MANAGEMENT_FLAG_NO_PPI_PROVISION) != 0)) {
          RequestConfirmed = TRUE;
        }

        break;

      case PHYSICAL_PRESENCE_SET_NO_PPI_PROVISION_FALSE:
      case PHYSICAL_PRESENCE_SET_NO_PPI_CLEAR_FALSE:
      case PHYSICAL_PRESENCE_SET_NO_PPI_MAINTENANCE_FALSE:
      case PHYSICAL_PRESENCE_NO_ACTION:
        RequestConfirmed = TRUE;
        break;

      case PHYSICAL_PRESENCE_SET_OPERATOR_AUTH:
        //
        // This command requires UI to prompt user for Auth data
        //
        mTcgNvs->PhysicalPresence.ReturnCode = TCG_PP_GET_USER_CONFIRMATION_NOT_IMPLEMENTED;
        return EFI_SUCCESS;
      default:
        break;
    }

    if (RequestConfirmed) {
      mTcgNvs->PhysicalPresence.ReturnCode = TCG_PP_GET_USER_CONFIRMATION_ALLOWED_AND_PPUSER_NOT_REQUIRED;
    } else {
      mTcgNvs->PhysicalPresence.ReturnCode = TCG_PP_GET_USER_CONFIRMATION_ALLOWED_AND_PPUSER_REQUIRED;
    }

    if (mTcgNvs->PhysicalPresence.Request >= TCG_PHYSICAL_PRESENCE_VENDOR_SPECIFIC_OPERATION) {
      mTcgNvs->PhysicalPresence.ReturnCode = TcgPpVendorLibGetUserConfirmationStatusFunction (mTcgNvs->PhysicalPresence.Request, Flags.PPFlags);
    }
  }

  return EFI_SUCCESS;
}

/**
  Software SMI callback for MemoryClear which is called from ACPI method.

  Caution: This function may receive untrusted input.
  Variable and ACPINvs are external input, so this function will validate
  its data structure to be valid value.

  @param[in]      DispatchHandle  The unique handle assigned to this handler by SmiHandlerRegister().
  @param[in]      Context         Points to an optional handler context which was specified when the
                                  handler was registered.
  @param[in, out] CommBuffer      A pointer to a collection of data in memory that will
                                  be conveyed from a non-SMM environment into an SMM environment.
  @param[in, out] CommBufferSize  The size of the CommBuffer.

  @retval EFI_SUCCESS             The interrupt was handled successfully.

**/
EFI_STATUS
EFIAPI
MemoryClearCallback (
  IN EFI_HANDLE  DispatchHandle,
  IN CONST VOID  *Context,
  IN OUT VOID    *CommBuffer,
  IN OUT UINTN   *CommBufferSize
  )
{
  EFI_STATUS  Status;
  UINTN       DataSize;
  UINT8       MorControl;

  mTcgNvs->MemoryClear.ReturnCode = MOR_REQUEST_SUCCESS;
  if (mTcgNvs->MemoryClear.Parameter == ACPI_FUNCTION_DSM_MEMORY_CLEAR_INTERFACE) {
    MorControl = (UINT8)mTcgNvs->MemoryClear.Request;
  } else if (mTcgNvs->MemoryClear.Parameter == ACPI_FUNCTION_PTS_CLEAR_MOR_BIT) {
    DataSize = sizeof (UINT8);
    Status   = mSmmVariable->SmmGetVariable (
                               MEMORY_OVERWRITE_REQUEST_VARIABLE_NAME,
                               &gEfiMemoryOverwriteControlDataGuid,
                               NULL,
                               &DataSize,
                               &MorControl
                               );
    if (EFI_ERROR (Status)) {
      mTcgNvs->MemoryClear.ReturnCode = MOR_REQUEST_GENERAL_FAILURE;
      DEBUG ((DEBUG_ERROR, "[TPM] Get MOR variable failure! Status = %r\n", Status));
      return EFI_SUCCESS;
    }

    if (MOR_CLEAR_MEMORY_VALUE (MorControl) == 0x0) {
      return EFI_SUCCESS;
    }

    MorControl &= ~MOR_CLEAR_MEMORY_BIT_MASK;
  } else {
    mTcgNvs->MemoryClear.ReturnCode = MOR_REQUEST_GENERAL_FAILURE;
    DEBUG ((DEBUG_ERROR, "[TPM] MOR Parameter error! Parameter = %x\n", mTcgNvs->MemoryClear.Parameter));
    return EFI_SUCCESS;
  }

  DataSize = sizeof (UINT8);
  Status   = mSmmVariable->SmmSetVariable (
                             MEMORY_OVERWRITE_REQUEST_VARIABLE_NAME,
                             &gEfiMemoryOverwriteControlDataGuid,
                             EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
                             DataSize,
                             &MorControl
                             );
  if (EFI_ERROR (Status)) {
    mTcgNvs->MemoryClear.ReturnCode = MOR_REQUEST_GENERAL_FAILURE;
    DEBUG ((DEBUG_ERROR, "[TPM] Set MOR variable failure! Status = %r\n", Status));
  }

  return EFI_SUCCESS;
}

/**
  Find the operation region in TCG ACPI table by given Name and Size,
  and initialize it if the region is found.

  @param[in, out] Table          The TPM item in ACPI table.
  @param[in]      Name           The name string to find in TPM table.
  @param[in]      Size           The size of the region to find.

  @return                        The allocated address for the found region.

**/
VOID *
AssignOpRegion (
  EFI_ACPI_DESCRIPTION_HEADER  *Table,
  UINT32                       Name,
  UINT16                       Size
  )
{
  EFI_STATUS            Status;
  AML_OP_REGION_32_8    *OpRegion;
  EFI_PHYSICAL_ADDRESS  MemoryAddress;

  MemoryAddress = SIZE_4GB - 1;

  //
  // Patch some pointers for the ASL code before loading the SSDT.
  //
  for (OpRegion  = (AML_OP_REGION_32_8 *)(Table + 1);
       OpRegion <= (AML_OP_REGION_32_8 *)((UINT8 *)Table + Table->Length);
       OpRegion  = (AML_OP_REGION_32_8 *)((UINT8 *)OpRegion + 1))
  {
    if ((OpRegion->OpRegionOp  == AML_EXT_REGION_OP) &&
        (OpRegion->NameString  == Name) &&
        (OpRegion->DWordPrefix == AML_DWORD_PREFIX) &&
        (OpRegion->BytePrefix  == AML_BYTE_PREFIX))
    {
      Status = gBS->AllocatePages (AllocateMaxAddress, EfiACPIMemoryNVS, EFI_SIZE_TO_PAGES (Size), &MemoryAddress);
      ASSERT_EFI_ERROR (Status);
      ZeroMem ((VOID *)(UINTN)MemoryAddress, Size);
      OpRegion->RegionOffset = (UINT32)(UINTN)MemoryAddress;
      OpRegion->RegionLen    = (UINT8)Size;
      break;
    }
  }

  return (VOID *)(UINTN)MemoryAddress;
}

/**
  Initialize and publish TPM items in ACPI table.

  @retval   EFI_SUCCESS     The TCG ACPI table is published successfully.
  @retval   Others          The TCG ACPI table is not published.

**/
EFI_STATUS
PublishAcpiTable (
  VOID
  )
{
  EFI_STATUS                   Status;
  EFI_ACPI_TABLE_PROTOCOL      *AcpiTable;
  UINTN                        TableKey;
  EFI_ACPI_DESCRIPTION_HEADER  *Table;
  UINTN                        TableSize;

  Status = GetSectionFromFv (
             &gEfiCallerIdGuid,
             EFI_SECTION_RAW,
             0,
             (VOID **)&Table,
             &TableSize
             );
  ASSERT_EFI_ERROR (Status);

  //
  // Measure to PCR[0] with event EV_POST_CODE ACPI DATA
  //
  TpmMeasureAndLogData (
    0,
    EV_POST_CODE,
    EV_POSTCODE_INFO_ACPI_DATA,
    ACPI_DATA_LEN,
    Table,
    TableSize
    );

  ASSERT (Table->OemTableId == SIGNATURE_64 ('T', 'c', 'g', 'T', 'a', 'b', 'l', 'e'));
  CopyMem (Table->OemId, PcdGetPtr (PcdAcpiDefaultOemId), sizeof (Table->OemId));
  mTcgNvs = AssignOpRegion (Table, SIGNATURE_32 ('T', 'N', 'V', 'S'), (UINT16)sizeof (TCG_NVS));
  ASSERT (mTcgNvs != NULL);

  //
  // Publish the TPM ACPI table
  //
  Status = gBS->LocateProtocol (&gEfiAcpiTableProtocolGuid, NULL, (VOID **)&AcpiTable);
  ASSERT_EFI_ERROR (Status);

  TableKey = 0;
  Status   = AcpiTable->InstallAcpiTable (
                          AcpiTable,
                          Table,
                          TableSize,
                          &TableKey
                          );
  ASSERT_EFI_ERROR (Status);

  return Status;
}

/**
  The driver's entry point.

  It install callbacks for TPM physical presence and MemoryClear, and locate
  SMM variable to be used in the callback function.

  @param[in] ImageHandle  The firmware allocated handle for the EFI image.
  @param[in] SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS     The entry point is executed successfully.
  @retval Others          Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
InitializeTcgSmm (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                     Status;
  EFI_SMM_SW_DISPATCH2_PROTOCOL  *SwDispatch;
  EFI_SMM_SW_REGISTER_CONTEXT    SwContext;
  EFI_HANDLE                     SwHandle;

  if (!CompareGuid (PcdGetPtr (PcdTpmInstanceGuid), &gEfiTpmDeviceInstanceTpm12Guid)) {
    DEBUG ((DEBUG_ERROR, "No TPM12 instance required!\n"));
    return EFI_UNSUPPORTED;
  }

  Status = PublishAcpiTable ();
  ASSERT_EFI_ERROR (Status);

  //
  // Get the Sw dispatch protocol and register SMI callback functions.
  //
  Status = gSmst->SmmLocateProtocol (&gEfiSmmSwDispatch2ProtocolGuid, NULL, (VOID **)&SwDispatch);
  ASSERT_EFI_ERROR (Status);
  SwContext.SwSmiInputValue = (UINTN)-1;
  Status                    = SwDispatch->Register (SwDispatch, PhysicalPresenceCallback, &SwContext, &SwHandle);
  ASSERT_EFI_ERROR (Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  mTcgNvs->PhysicalPresence.SoftwareSmi = (UINT8)SwContext.SwSmiInputValue;

  SwContext.SwSmiInputValue = (UINTN)-1;
  Status                    = SwDispatch->Register (SwDispatch, MemoryClearCallback, &SwContext, &SwHandle);
  ASSERT_EFI_ERROR (Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  mTcgNvs->MemoryClear.SoftwareSmi = (UINT8)SwContext.SwSmiInputValue;

  //
  // Locate SmmVariableProtocol.
  //
  Status = gSmst->SmmLocateProtocol (&gEfiSmmVariableProtocolGuid, NULL, (VOID **)&mSmmVariable);
  ASSERT_EFI_ERROR (Status);

  return EFI_SUCCESS;
}
