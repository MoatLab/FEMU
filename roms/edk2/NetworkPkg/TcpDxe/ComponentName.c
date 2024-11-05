/** @file
  Implementation of protocols EFI_COMPONENT_NAME_PROTOCOL and
  EFI_COMPONENT_NAME2_PROTOCOL.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TcpMain.h"

//
// EFI Component Name Functions
//

/**
  Retrieves a Unicode string that is the user-readable name of the driver.

  This function retrieves the user-readable name of a driver in the form of a
  Unicode string. If the driver specified by This has a user-readable name in
  the language specified by Language, then a pointer to the driver name is
  returned in DriverName, and EFI_SUCCESS is returned. If the driver specified
  by This does not support the language specified by Language,
  then EFI_UNSUPPORTED is returned.

  @param[in]  This              A pointer to the EFI_COMPONENT_NAME2_PROTOCOL or
                                EFI_COMPONENT_NAME_PROTOCOL instance.

  @param[in]  Language          A pointer to a Null-terminated ASCII string
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
                                This, and the language specified by Language was
                                returned in DriverName.

  @retval EFI_INVALID_PARAMETER Language or DriverName is NULL.

  @retval EFI_UNSUPPORTED       The driver specified by This does not support
                                the language specified by Language.

**/
EFI_STATUS
EFIAPI
TcpComponentNameGetDriverName (
  IN  EFI_COMPONENT_NAME_PROTOCOL  *This,
  IN  CHAR8                        *Language,
  OUT CHAR16                       **DriverName
  );

/**
  Retrieves a Unicode string that is the user-readable name of the controller
  that is being managed by a driver.

  This function retrieves the user-readable name of the controller specified by
  ControllerHandle and ChildHandle in the form of a Unicode string. If the
  driver specified by This has a user-readable name in the language specified by
  Language, then a pointer to the controller name is returned in ControllerName,
  and EFI_SUCCESS is returned.  If the driver specified by This is not currently
  managing the controller specified by ControllerHandle and ChildHandle,
  then EFI_UNSUPPORTED is returned.  If the driver specified by This does not
  support the language specified by Language, then EFI_UNSUPPORTED is returned.

  @param[in]  This              A pointer to the EFI_COMPONENT_NAME2_PROTOCOL or
                                EFI_COMPONENT_NAME_PROTOCOL instance.

  @param[in]  ControllerHandle  The handle of a controller that the driver
                                specified by This is managing.  This handle
                                specifies the controller whose name is to be
                                returned.

  @param[in]  ChildHandle       The handle of the child controller to retrieve
                                the name of.  This is an optional parameter that
                                may be NULL.  It will be NULL for device
                                drivers.  It will also be NULL for a bus drivers
                                that wish to retrieve the name of the bus
                                controller.  It will not be NULL for a bus
                                driver that wishes to retrieve the name of a
                                child controller.

  @param[in]  Language          A pointer to a Null-terminated ASCII string
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
                                Language, from the point of view of the driver
                                specified by This.

  @retval EFI_SUCCESS           The Unicode string for the user-readable name in
                                the language specified by Language for the
                                driver specified by This was returned in
                                DriverName.

  @retval EFI_INVALID_PARAMETER ControllerHandle is NULL.

  @retval EFI_INVALID_PARAMETER ChildHandle is not NULL, and it is not a valid
                                EFI_HANDLE.

  @retval EFI_INVALID_PARAMETER Language or ControllerName is NULL.

  @retval EFI_UNSUPPORTED       The driver specified by This is not currently
                                managing the controller specified by
                                ControllerHandle and ChildHandle.

  @retval EFI_UNSUPPORTED       The driver specified by This does not support
                                the language specified by Language.

**/
EFI_STATUS
EFIAPI
TcpComponentNameGetControllerName (
  IN  EFI_COMPONENT_NAME_PROTOCOL  *This,
  IN  EFI_HANDLE                   ControllerHandle,
  IN  EFI_HANDLE                   ChildHandle  OPTIONAL,
  IN  CHAR8                        *Language,
  OUT CHAR16                       **ControllerName
  );

///
/// EFI Component Name Protocol
///
GLOBAL_REMOVE_IF_UNREFERENCED EFI_COMPONENT_NAME_PROTOCOL  gTcpComponentName = {
  TcpComponentNameGetDriverName,
  TcpComponentNameGetControllerName,
  "eng"
};

///
/// EFI Component Name 2 Protocol
///
GLOBAL_REMOVE_IF_UNREFERENCED EFI_COMPONENT_NAME2_PROTOCOL  gTcpComponentName2 = {
  (EFI_COMPONENT_NAME2_GET_DRIVER_NAME)TcpComponentNameGetDriverName,
  (EFI_COMPONENT_NAME2_GET_CONTROLLER_NAME)TcpComponentNameGetControllerName,
  "en"
};

GLOBAL_REMOVE_IF_UNREFERENCED EFI_UNICODE_STRING_TABLE  mTcpDriverNameTable[] = {
  {
    "eng;en",
    L"TCP Network Service Driver"
  },
  {
    NULL,
    NULL
  }
};

GLOBAL_REMOVE_IF_UNREFERENCED EFI_UNICODE_STRING_TABLE  *gTcpControllerNameTable = NULL;

/**
  Retrieves a Unicode string that is the user-readable name of the driver.

  This function retrieves the user-readable name of a driver in the form of a
  Unicode string. If the driver specified by This has a user-readable name in
  the language specified by Language, then a pointer to the driver name is
  returned in DriverName, and EFI_SUCCESS is returned. If the driver specified
  by This does not support the language specified by Language,
  then EFI_UNSUPPORTED is returned.

  @param[in]  This              A pointer to the EFI_COMPONENT_NAME2_PROTOCOL or
                                EFI_COMPONENT_NAME_PROTOCOL instance.

  @param[in]  Language          A pointer to a Null-terminated ASCII string
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
                                This, and the language specified by Language was
                                returned in DriverName.

  @retval EFI_INVALID_PARAMETER Language or DriverName is NULL.

  @retval EFI_UNSUPPORTED       The driver specified by This does not support
                                the language specified by Language.

**/
EFI_STATUS
EFIAPI
TcpComponentNameGetDriverName (
  IN  EFI_COMPONENT_NAME_PROTOCOL  *This,
  IN  CHAR8                        *Language,
  OUT CHAR16                       **DriverName
  )
{
  return LookupUnicodeString2 (
           Language,
           This->SupportedLanguages,
           mTcpDriverNameTable,
           DriverName,
           (BOOLEAN)(This == &gTcpComponentName)
           );
}

/**
  Update the component name for the Tcp4 child handle.

  @param  Tcp4[in]                   A pointer to the EFI_TCP4_PROTOCOL.


  @retval EFI_SUCCESS                Update the ControllerNameTable of this instance successfully.
  @retval EFI_INVALID_PARAMETER      The input parameter is invalid.

**/
EFI_STATUS
UpdateTcp4Name (
  IN    EFI_TCP4_PROTOCOL  *Tcp4
  )
{
  EFI_STATUS            Status;
  CHAR16                HandleName[80];
  EFI_TCP4_CONFIG_DATA  Tcp4ConfigData;

  if (Tcp4 == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Format the child name into the string buffer as:
  // TCPv4 (SrcPort=59, DestPort=60, ActiveFlag=TRUE)
  //
  ZeroMem (&Tcp4ConfigData, sizeof (Tcp4ConfigData));
  Status = Tcp4->GetModeData (Tcp4, NULL, &Tcp4ConfigData, NULL, NULL, NULL);
  if (!EFI_ERROR (Status)) {
    UnicodeSPrint (
      HandleName,
      sizeof (HandleName),
      L"TCPv4 (SrcPort=%d, DestPort=%d, ActiveFlag=%s)",
      Tcp4ConfigData.AccessPoint.StationPort,
      Tcp4ConfigData.AccessPoint.RemotePort,
      (Tcp4ConfigData.AccessPoint.ActiveFlag ? L"TRUE" : L"FALSE")
      );
  } else if (Status == EFI_NOT_STARTED) {
    UnicodeSPrint (
      HandleName,
      sizeof (HandleName),
      L"TCPv4 (Not started)"
      );
  } else {
    return Status;
  }

  if (gTcpControllerNameTable != NULL) {
    FreeUnicodeStringTable (gTcpControllerNameTable);
    gTcpControllerNameTable = NULL;
  }

  Status = AddUnicodeString2 (
             "eng",
             gTcpComponentName.SupportedLanguages,
             &gTcpControllerNameTable,
             HandleName,
             TRUE
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return AddUnicodeString2 (
           "en",
           gTcpComponentName2.SupportedLanguages,
           &gTcpControllerNameTable,
           HandleName,
           FALSE
           );
}

/**
  Update the component name for the Tcp6 child handle.

  @param  Tcp6[in]                   A pointer to the EFI_TCP6_PROTOCOL.


  @retval EFI_SUCCESS                Update the ControllerNameTable of this instance successfully.
  @retval EFI_INVALID_PARAMETER      The input parameter is invalid.

**/
EFI_STATUS
UpdateTcp6Name (
  IN    EFI_TCP6_PROTOCOL  *Tcp6
  )
{
  EFI_STATUS            Status;
  CHAR16                HandleName[80];
  EFI_TCP6_CONFIG_DATA  Tcp6ConfigData;

  if (Tcp6 == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Format the child name into the string buffer.
  //
  ZeroMem (&Tcp6ConfigData, sizeof (Tcp6ConfigData));
  Status = Tcp6->GetModeData (Tcp6, NULL, &Tcp6ConfigData, NULL, NULL, NULL);
  if (!EFI_ERROR (Status)) {
    UnicodeSPrint (
      HandleName,
      sizeof (HandleName),
      L"TCPv6(SrcPort=%d, DestPort=%d, ActiveFlag=%d)",
      Tcp6ConfigData.AccessPoint.StationPort,
      Tcp6ConfigData.AccessPoint.RemotePort,
      Tcp6ConfigData.AccessPoint.ActiveFlag
      );
  } else if (Status == EFI_NOT_STARTED) {
    UnicodeSPrint (HandleName, sizeof (HandleName), L"TCPv6(Not started)");
  } else {
    return Status;
  }

  if (gTcpControllerNameTable != NULL) {
    FreeUnicodeStringTable (gTcpControllerNameTable);
    gTcpControllerNameTable = NULL;
  }

  Status = AddUnicodeString2 (
             "eng",
             gTcpComponentName.SupportedLanguages,
             &gTcpControllerNameTable,
             HandleName,
             TRUE
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return AddUnicodeString2 (
           "en",
           gTcpComponentName2.SupportedLanguages,
           &gTcpControllerNameTable,
           HandleName,
           FALSE
           );
}

/**
  Retrieves a Unicode string that is the user-readable name of the controller
  that is being managed by a driver.

  This function retrieves the user-readable name of the controller specified by
  ControllerHandle and ChildHandle in the form of a Unicode string. If the
  driver specified by This has a user-readable name in the language specified by
  Language, then a pointer to the controller name is returned in ControllerName,
  and EFI_SUCCESS is returned.  If the driver specified by This is not currently
  managing the controller specified by ControllerHandle and ChildHandle,
  then EFI_UNSUPPORTED is returned.  If the driver specified by This does not
  support the language specified by Language, then EFI_UNSUPPORTED is returned.

  @param[in]  This              A pointer to the EFI_COMPONENT_NAME2_PROTOCOL or
                                EFI_COMPONENT_NAME_PROTOCOL instance.

  @param[in]  ControllerHandle  The handle of a controller that the driver
                                specified by This is managing.  This handle
                                specifies the controller whose name is to be
                                returned.

  @param[in]  ChildHandle       The handle of the child controller to retrieve
                                the name of.  This is an optional parameter that
                                may be NULL.  It will be NULL for device
                                drivers.  It will also be NULL for a bus drivers
                                that wish to retrieve the name of the bus
                                controller.  It will not be NULL for a bus
                                driver that wishes to retrieve the name of a
                                child controller.

  @param[in]  Language          A pointer to a Null-terminated ASCII string
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
                                Language, from the point of view of the driver
                                specified by This.

  @retval EFI_SUCCESS           The Unicode string for the user-readable name in
                                the language specified by Language for the
                                driver specified by This was returned in
                                DriverName.

  @retval EFI_INVALID_PARAMETER ControllerHandle is NULL.

  @retval EFI_INVALID_PARAMETER ChildHandle is not NULL, and it is not a valid
                                EFI_HANDLE.

  @retval EFI_INVALID_PARAMETER Language or ControllerName is NULL.

  @retval EFI_UNSUPPORTED       The driver specified by This is not currently
                                managing the controller specified by
                                ControllerHandle and ChildHandle.

  @retval EFI_UNSUPPORTED       The driver specified by This does not support
                                the language specified by Language.

**/
EFI_STATUS
EFIAPI
TcpComponentNameGetControllerName (
  IN  EFI_COMPONENT_NAME_PROTOCOL  *This,
  IN  EFI_HANDLE                   ControllerHandle,
  IN  EFI_HANDLE                   ChildHandle  OPTIONAL,
  IN  CHAR8                        *Language,
  OUT CHAR16                       **ControllerName
  )
{
  EFI_STATUS         Status;
  EFI_TCP4_PROTOCOL  *Tcp4;
  EFI_TCP6_PROTOCOL  *Tcp6;

  //
  // Only provide names for child handles.
  //
  if (ChildHandle == NULL) {
    return EFI_UNSUPPORTED;
  }

  //
  // Make sure this driver produced ChildHandle
  //
  Status = EfiTestChildHandle (
             ControllerHandle,
             ChildHandle,
             &gEfiIp6ProtocolGuid
             );
  if (!EFI_ERROR (Status)) {
    //
    // Retrieve an instance of a produced protocol from ChildHandle
    //
    Status = gBS->OpenProtocol (
                    ChildHandle,
                    &gEfiTcp6ProtocolGuid,
                    (VOID **)&Tcp6,
                    NULL,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL
                    );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    //
    // Update the component name for this child handle.
    //
    Status = UpdateTcp6Name (Tcp6);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  //
  // Make sure this driver is currently managing ControllHandle
  //
  Status = EfiTestChildHandle (
             ControllerHandle,
             ChildHandle,
             &gEfiIp4ProtocolGuid
             );
  if (!EFI_ERROR (Status)) {
    //
    // Retrieve an instance of a produced protocol from ChildHandle
    //
    Status = gBS->OpenProtocol (
                    ChildHandle,
                    &gEfiTcp4ProtocolGuid,
                    (VOID **)&Tcp4,
                    NULL,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL
                    );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    //
    // Update the component name for this child handle.
    //
    Status = UpdateTcp4Name (Tcp4);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  return LookupUnicodeString2 (
           Language,
           This->SupportedLanguages,
           gTcpControllerNameTable,
           ControllerName,
           (BOOLEAN)(This == &gTcpComponentName)
           );
}
