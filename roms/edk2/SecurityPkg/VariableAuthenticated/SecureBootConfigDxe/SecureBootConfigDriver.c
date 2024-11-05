/** @file
  The module entry point for SecureBoot configuration module.

Copyright (c) 2011 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SecureBootConfigImpl.h"

/**
  The entry point for SecureBoot configuration driver.

  @param[in]  ImageHandle        The image handle of the driver.
  @param[in]  SystemTable        The system table.

  @retval EFI_ALREADY_STARTED    The driver already exists in system.
  @retval EFI_OUT_OF_RESOURCES   Fail to execute entry point due to lack of resources.
  @retval EFI_SUCCESS            All the related protocols are installed on the driver.
  @retval Others                 Fail to get the SecureBootEnable variable.

**/
EFI_STATUS
EFIAPI
SecureBootConfigDriverEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                      Status;
  SECUREBOOT_CONFIG_PRIVATE_DATA  *PrivateData;

  //
  // If already started, return.
  //
  Status = gBS->OpenProtocol (
                  ImageHandle,
                  &gEfiCallerIdGuid,
                  NULL,
                  ImageHandle,
                  ImageHandle,
                  EFI_OPEN_PROTOCOL_TEST_PROTOCOL
                  );
  if (!EFI_ERROR (Status)) {
    return EFI_ALREADY_STARTED;
  }

  //
  // Create a private data structure.
  //
  PrivateData = AllocateCopyPool (sizeof (SECUREBOOT_CONFIG_PRIVATE_DATA), &mSecureBootConfigPrivateDateTemplate);
  if (PrivateData == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Install SecureBoot configuration form
  //
  Status = InstallSecureBootConfigForm (PrivateData);
  if (EFI_ERROR (Status)) {
    goto ErrorExit;
  }

  //
  // Install private GUID.
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &ImageHandle,
                  &gEfiCallerIdGuid,
                  PrivateData,
                  NULL
                  );

  if (EFI_ERROR (Status)) {
    goto ErrorExit;
  }

  return EFI_SUCCESS;

ErrorExit:
  if (PrivateData != NULL) {
    UninstallSecureBootConfigForm (PrivateData);
  }

  return Status;
}

/**
  Unload the SecureBoot configuration form.

  @param[in]  ImageHandle         The driver's image handle.

  @retval     EFI_SUCCESS         The SecureBoot configuration form is unloaded.
  @retval     Others              Failed to unload the form.

**/
EFI_STATUS
EFIAPI
SecureBootConfigDriverUnload (
  IN EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS                      Status;
  SECUREBOOT_CONFIG_PRIVATE_DATA  *PrivateData;

  Status = gBS->HandleProtocol (
                  ImageHandle,
                  &gEfiCallerIdGuid,
                  (VOID **)&PrivateData
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  ASSERT (PrivateData->Signature == SECUREBOOT_CONFIG_PRIVATE_DATA_SIGNATURE);

  gBS->UninstallMultipleProtocolInterfaces (
         ImageHandle,
         &gEfiCallerIdGuid,
         PrivateData,
         NULL
         );

  UninstallSecureBootConfigForm (PrivateData);

  return EFI_SUCCESS;
}
