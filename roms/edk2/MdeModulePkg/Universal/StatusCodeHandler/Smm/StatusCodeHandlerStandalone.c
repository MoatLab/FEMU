/** @file
  Abstraction layer that contains Standalone MM specific implementation for
  Status Code Handler Driver.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "StatusCodeHandlerMm.h"

/**
  Entry point of Standalone MM Status Code Driver.

  This function is the entry point of Standalone MM Status Code Driver.

  @param  ImageHandle       The firmware allocated handle for the EFI image.
  @param  SystemTable       A pointer to the EFI MM System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.

**/
EFI_STATUS
EFIAPI
StatusCodeHandlerStandaloneMmEntry (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  return StatusCodeHandlerCommonEntry ();
}
