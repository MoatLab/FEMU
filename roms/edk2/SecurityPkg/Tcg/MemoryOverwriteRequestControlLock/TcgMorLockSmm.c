/** @file
   TCG MOR (Memory Overwrite Request) Lock Control Driver SMM wrapper.

Copyright (c) 2015 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiSmm.h>
#include <Library/SmmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Protocol/SmmVarCheck.h>
#include <Protocol/SmmVariable.h>
#include "TcgMorLock.h"

EFI_SMM_VARIABLE_PROTOCOL  *mSmmVariable;

/**
  This service is a wrapper for the UEFI Runtime Service GetVariable().

  @param  VariableName the name of the vendor's variable, it's a Null-Terminated Unicode String
  @param  VendorGuid   Unify identifier for vendor.
  @param  Attributes   Point to memory location to return the attributes of variable. If the point
                       is NULL, the parameter would be ignored.
  @param  DataSize     As input, point to the maximum size of return Data-Buffer.
                       As output, point to the actual size of the returned Data-Buffer.
  @param  Data         Point to return Data-Buffer.

  @retval  EFI_SUCCESS            The function completed successfully.
  @retval  EFI_NOT_FOUND          The variable was not found.
  @retval  EFI_BUFFER_TOO_SMALL   The DataSize is too small for the result. DataSize has
                                  been updated with the size needed to complete the request.
  @retval  EFI_INVALID_PARAMETER  VariableName is NULL.
  @retval  EFI_INVALID_PARAMETER  VendorGuid is NULL.
  @retval  EFI_INVALID_PARAMETER  DataSize is NULL.
  @retval  EFI_INVALID_PARAMETER  The DataSize is not too small and Data is NULL.
  @retval  EFI_DEVICE_ERROR       The variable could not be retrieved due to a hardware error.
  @retval  EFI_SECURITY_VIOLATION The variable could not be retrieved due to an authentication failure.
**/
EFI_STATUS
EFIAPI
InternalGetVariable (
  IN      CHAR16    *VariableName,
  IN      EFI_GUID  *VendorGuid,
  OUT     UINT32    *Attributes OPTIONAL,
  IN OUT  UINTN     *DataSize,
  OUT     VOID      *Data
  )
{
  return mSmmVariable->SmmGetVariable (
                         VariableName,
                         VendorGuid,
                         Attributes,
                         DataSize,
                         Data
                         );
}

/**
  This service is a wrapper for the UEFI Runtime Service SetVariable()

  @param  VariableName the name of the vendor's variable, as a
                       Null-Terminated Unicode String
  @param  VendorGuid   Unify identifier for vendor.
  @param  Attributes   Point to memory location to return the attributes of variable. If the point
                       is NULL, the parameter would be ignored.
  @param  DataSize     The size in bytes of Data-Buffer.
  @param  Data         Point to the content of the variable.

  @retval  EFI_SUCCESS            The firmware has successfully stored the variable and its data as
                                  defined by the Attributes.
  @retval  EFI_INVALID_PARAMETER  An invalid combination of attribute bits was supplied, or the
                                  DataSize exceeds the maximum allowed.
  @retval  EFI_INVALID_PARAMETER  VariableName is an empty Unicode string.
  @retval  EFI_OUT_OF_RESOURCES   Not enough storage is available to hold the variable and its data.
  @retval  EFI_DEVICE_ERROR       The variable could not be saved due to a hardware failure.
  @retval  EFI_WRITE_PROTECTED    The variable in question is read-only.
  @retval  EFI_WRITE_PROTECTED    The variable in question cannot be deleted.
  @retval  EFI_SECURITY_VIOLATION The variable could not be written due to EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
                                  set but the AuthInfo does NOT pass the validation check carried
                                  out by the firmware.
  @retval  EFI_NOT_FOUND          The variable trying to be updated or deleted was not found.

**/
EFI_STATUS
EFIAPI
InternalSetVariable (
  IN CHAR16    *VariableName,
  IN EFI_GUID  *VendorGuid,
  IN UINT32    Attributes,
  IN UINTN     DataSize,
  IN VOID      *Data
  )
{
  return mSmmVariable->SmmSetVariable (
                         VariableName,
                         VendorGuid,
                         Attributes,
                         DataSize,
                         Data
                         );
}

/**
  Entry Point for MOR Lock Control driver.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       EntryPoint runs successfully.

**/
EFI_STATUS
EFIAPI
MorLockDriverEntryPointSmm (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                    Status;
  EDKII_SMM_VAR_CHECK_PROTOCOL  *SmmVarCheck;

  //
  // This driver link to Smm Variable driver
  //
  DEBUG ((DEBUG_INFO, "MorLockDriverEntryPointSmm\n"));

  Status = gSmst->SmmLocateProtocol (
                    &gEfiSmmVariableProtocolGuid,
                    NULL,
                    (VOID **)&mSmmVariable
                    );
  ASSERT_EFI_ERROR (Status);

  Status = gSmst->SmmLocateProtocol (
                    &gEdkiiSmmVarCheckProtocolGuid,
                    NULL,
                    (VOID **)&SmmVarCheck
                    );
  ASSERT_EFI_ERROR (Status);

  Status = MorLockDriverInit ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = SmmVarCheck->SmmRegisterSetVariableCheckHandler (SetVariableCheckHandlerMor);
  ASSERT_EFI_ERROR (Status);

  return Status;
}
