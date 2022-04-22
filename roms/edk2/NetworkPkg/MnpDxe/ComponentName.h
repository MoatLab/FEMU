/** @file
  The header file of UEFI Component Name(2) protocol.

Copyright (c) 2004 - 2012, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _COMPONENT_NAME_H_
#define _COMPONENT_NAME_H_

#include <Protocol/ComponentName.h>
#include <Protocol/ComponentName2.h>

extern EFI_COMPONENT_NAME2_PROTOCOL  gMnpComponentName2;
extern EFI_COMPONENT_NAME_PROTOCOL   gMnpComponentName;
extern EFI_UNICODE_STRING_TABLE      *gMnpControllerNameTable;

/**
  Retrieves a Unicode string that is the user readable name of the driver.

  This function retrieves the user readable name of a driver in the form of a
  Unicode string. If the driver specified by This has a user readable name in
  the language specified by Language, then a pointer to the driver name is
  returned in DriverName, and EFI_SUCCESS is returned. If the driver specified
  by This does not support the language specified by Language,
  then EFI_UNSUPPORTED is returned.

  @param[in]   This             A pointer to the EFI_COMPONENT_NAME2_PROTOCOL or
                                EFI_COMPONENT_NAME_PROTOCOL instance.

  @param[in]   Language         A pointer to a Null-terminated ASCII string
                                array indicating the language. This is the
                                language of the driver name that the caller is
                                requesting, and it must match one of the
                                languages specified in SupportedLanguages. The
                                number of languages supported by a driver is up
                                to the driver writer. Language is specified
                                in RFC 4646 or ISO 639-2 language code format.

  @param[out]  DriverName       A pointer to the Unicode string to return.
                                This Unicode string is the name of the
                                driver specified by This in the language
                                specified by Language.

  @retval EFI_SUCCESS           The Unicode string for the Driver specified by
                                This and the language specified by Language was
                                returned in DriverName.

  @retval EFI_INVALID_PARAMETER Language is NULL.

  @retval EFI_INVALID_PARAMETER DriverName is NULL.

  @retval EFI_UNSUPPORTED       The driver specified by This does not support
                                the language specified by Language.

**/
EFI_STATUS
EFIAPI
MnpComponentNameGetDriverName (
  IN     EFI_COMPONENT_NAME_PROTOCOL  *This,
  IN     CHAR8                        *Language,
  OUT CHAR16                          **DriverName
  );

/**
  Retrieves a Unicode string that is the user readable name of the controller
  that is being managed by a driver.

  This function retrieves the user readable name of the controller specified by
  ControllerHandle and ChildHandle in the form of a Unicode string. If the
  driver specified by This has a user readable name in the language specified by
  Language, then a pointer to the controller name is returned in ControllerName,
  and EFI_SUCCESS is returned.  If the driver specified by This is not currently
  managing the controller specified by ControllerHandle and ChildHandle,
  then EFI_UNSUPPORTED is returned.  If the driver specified by This does not
  support the language specified by Language, then EFI_UNSUPPORTED is returned.
  Currently not implemented.

  @param[in]   This             A pointer to the EFI_COMPONENT_NAME2_PROTOCOL or
                                EFI_COMPONENT_NAME_PROTOCOL instance.

  @param[in]   ControllerHandle The handle of a controller that the driver
                                specified by This is managing.  This handle
                                specifies the controller whose name is to be
                                returned.

  @param[in]   ChildHandle      The handle of the child controller to retrieve
                                the name of.  This is an optional parameter that
                                may be NULL.  It will be NULL for device
                                drivers.  It will also be NULL for a bus drivers
                                that wish to retrieve the name of the bus
                                controller.  It will not be NULL for a bus
                                driver that wishes to retrieve the name of a
                                child controller.

  @param[in]   Language         A pointer to a Null-terminated ASCII string
                                array indicating the language.  This is the
                                language of the driver name that the caller is
                                requesting, and it must match one of the
                                languages specified in SupportedLanguages. The
                                number of languages supported by a driver is up
                                to the driver writer. Language is specified in
                                RFC 4646 or ISO 639-2 language code format.

  @param[out]  ControllerName   A pointer to the Unicode string to return.
                                This Unicode string is the name of the
                                controller specified by ControllerHandle and
                                ChildHandle in the language specified by
                                Language from the point of view of the driver
                                specified by This.

  @retval EFI_SUCCESS           The Unicode string for the user readable name
                                specified by This, ControllerHandle, ChildHandle,
                                and Language was returned in ControllerName.

  @retval EFI_INVALID_PARAMETER ControllerHandle is NULL.

  @retval EFI_INVALID_PARAMETER ChildHandle is not NULL and it is not a valid
                                EFI_HANDLE.

  @retval EFI_INVALID_PARAMETER Language is NULL.

  @retval EFI_INVALID_PARAMETER ControllerName is NULL.

  @retval EFI_UNSUPPORTED       The driver specified by This is not currently
                                managing the controller specified by
                                ControllerHandle and ChildHandle.

  @retval EFI_UNSUPPORTED       The driver specified by This does not support
                                the language specified by Language.

**/
EFI_STATUS
EFIAPI
MnpComponentNameGetControllerName (
  IN     EFI_COMPONENT_NAME_PROTOCOL  *This,
  IN     EFI_HANDLE                   ControllerHandle,
  IN     EFI_HANDLE                   ChildHandle        OPTIONAL,
  IN     CHAR8                        *Language,
  OUT CHAR16                          **ControllerName
  );

#endif
