/** @file
  Implementation for EFI_AUTHENTICATION_INFO_PROTOCOL. Currently it is a
  dummy support.

Copyright (c) 2009 - 2011, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "IScsiImpl.h"

EFI_AUTHENTICATION_INFO_PROTOCOL  gIScsiAuthenticationInfo = {
  IScsiGetAuthenticationInfo,
  IScsiSetAuthenticationInfo
};

/**
  Retrieves the authentication information associated with a particular controller handle.

  @param[in]  This              Pointer to the EFI_AUTHENTICATION_INFO_PROTOCOL.
  @param[in]  ControllerHandle  Handle to the Controller.
  @param[out] Buffer            Pointer to the authentication information. This function is
                                responsible for allocating the buffer and it is the caller's
                                responsibility to free buffer when the caller is finished with buffer.

  @retval EFI_DEVICE_ERROR      The authentication information could not be
                                retrieved due to a hardware error.

**/
EFI_STATUS
EFIAPI
IScsiGetAuthenticationInfo (
  IN  EFI_AUTHENTICATION_INFO_PROTOCOL  *This,
  IN  EFI_HANDLE                        ControllerHandle,
  OUT VOID                              **Buffer
  )
{
  return EFI_DEVICE_ERROR;
}

/**
  Set the authentication information for a given controller handle.

  @param[in]  This             Pointer to the EFI_AUTHENTICATION_INFO_PROTOCOL.
  @param[in]  ControllerHandle Handle to the Controller.
  @param[in]  Buffer           Pointer to the authentication information.

  @retval EFI_UNSUPPORTED      If the platform policies do not allow setting of
                               the authentication information.

**/
EFI_STATUS
EFIAPI
IScsiSetAuthenticationInfo (
  IN EFI_AUTHENTICATION_INFO_PROTOCOL  *This,
  IN EFI_HANDLE                        ControllerHandle,
  IN VOID                              *Buffer
  )
{
  return EFI_UNSUPPORTED;
}
