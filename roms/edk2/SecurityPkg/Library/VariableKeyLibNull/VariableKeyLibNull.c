/** @file
  Null version of VariableKeyLib for build purpose. Don't use it in real product.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#include <Library/DebugLib.h>
#include <Library/VariableKeyLib.h>

/**
  Retrieves the key for integrity and/or confidentiality of variables.

  @param[out]     VariableKey         A pointer to pointer for the variable key buffer.
  @param[in,out]  VariableKeySize     The size in bytes of the variable key.

  @retval       EFI_SUCCESS             The variable key was returned.
  @retval       EFI_DEVICE_ERROR        An error occurred while attempting to get the variable key.
  @retval       EFI_ACCESS_DENIED       The function was invoked after locking the key interface.
  @retval       EFI_UNSUPPORTED         The variable key is not supported in the current boot configuration.
**/
EFI_STATUS
EFIAPI
GetVariableKey (
  OUT VOID       **VariableKey,
  IN  OUT UINTN  *VariableKeySize
  )
{
  ASSERT (FALSE);
  return EFI_UNSUPPORTED;
}

/**
  Regenerates the variable key.

  @retval       EFI_SUCCESS             The variable key was regenerated successfully.
  @retval       EFI_DEVICE_ERROR        An error occurred while attempting to regenerate the key.
  @retval       EFI_ACCESS_DENIED       The function was invoked after locking the key interface.
  @retval       EFI_UNSUPPORTED         Key regeneration is not supported in the current boot configuration.
**/
EFI_STATUS
EFIAPI
RegenerateVariableKey (
  VOID
  )
{
  ASSERT (FALSE);
  return EFI_UNSUPPORTED;
}

/**
  Locks the regenerate key interface.

  @retval       EFI_SUCCESS             The key interface was locked successfully.
  @retval       EFI_UNSUPPORTED         Locking the key interface is not supported in the current boot configuration.
  @retval       Others                  An error occurred while attempting to lock the key interface.
**/
EFI_STATUS
EFIAPI
LockVariableKeyInterface (
  VOID
  )
{
  ASSERT (FALSE);
  return EFI_UNSUPPORTED;
}
