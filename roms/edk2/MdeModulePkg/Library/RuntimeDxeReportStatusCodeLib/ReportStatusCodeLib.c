/** @file
  API implementation for instance of Report Status Code Library.

  Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/ReportStatusCodeLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PcdLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiRuntimeLib.h>

#include <Protocol/StatusCode.h>

#include <Guid/StatusCodeDataTypeId.h>
#include <Guid/StatusCodeDataTypeDebug.h>
#include <Guid/EventGroup.h>

EFI_STATUS_CODE_PROTOCOL  *mReportStatusCodeLibStatusCodeProtocol = NULL;
EFI_EVENT                 mReportStatusCodeLibVirtualAddressChangeEvent;
EFI_EVENT                 mReportStatusCodeLibExitBootServicesEvent;
BOOLEAN                   mHaveExitedBootServices = FALSE;

/**
  Locate the report status code service.

  Retrieve ReportStatusCode() API of Report Status Code Protocol.

**/
VOID
InternalGetReportStatusCode (
  VOID
  )
{
  EFI_STATUS  Status;

  if (mReportStatusCodeLibStatusCodeProtocol != NULL) {
    return;
  }

  if (mHaveExitedBootServices) {
    return;
  }

  //
  // Check gBS just in case ReportStatusCode is called before gBS is initialized.
  //
  if ((gBS != NULL) && (gBS->LocateProtocol != NULL)) {
    Status = gBS->LocateProtocol (&gEfiStatusCodeRuntimeProtocolGuid, NULL, (VOID **)&mReportStatusCodeLibStatusCodeProtocol);
    if (EFI_ERROR (Status)) {
      mReportStatusCodeLibStatusCodeProtocol = NULL;
    }
  }
}

/**
  Notification function of EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE.

  @param  Event        Event whose notification function is being invoked.
  @param  Context      Pointer to the notification function's context

**/
VOID
EFIAPI
ReportStatusCodeLibVirtualAddressChange (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  if (mReportStatusCodeLibStatusCodeProtocol == NULL) {
    return;
  }

  EfiConvertPointer (0, (VOID **)&mReportStatusCodeLibStatusCodeProtocol);
}

/**
  Notification function of EVT_SIGNAL_EXIT_BOOT_SERVICES.

  @param  Event        Event whose notification function is being invoked.
  @param  Context      Pointer to the notification function's context

**/
VOID
EFIAPI
ReportStatusCodeLibExitBootServices (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  //
  // Locate the report status code service before enter runtime.
  //
  InternalGetReportStatusCode ();

  mHaveExitedBootServices = TRUE;
}

/**
  The constructor function of Runtime DXE Report Status Code Lib.

  This function allocates memory for extended status code data, caches
  the report status code service, and registers events.

  @param  ImageHandle   The firmware allocated handle for the EFI image.
  @param  SystemTable   A pointer to the EFI System Table.

  @retval EFI_SUCCESS   The constructor always returns EFI_SUCCESS.

**/
EFI_STATUS
EFIAPI
ReportStatusCodeLibConstructor (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  //
  // Cache the report status code service
  //
  InternalGetReportStatusCode ();

  //
  // Register notify function for EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE
  //
  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_NOTIFY,
                  ReportStatusCodeLibVirtualAddressChange,
                  NULL,
                  &gEfiEventVirtualAddressChangeGuid,
                  &mReportStatusCodeLibVirtualAddressChangeEvent
                  );
  ASSERT_EFI_ERROR (Status);

  //
  // Register notify function for EVT_SIGNAL_EXIT_BOOT_SERVICES
  //
  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_NOTIFY,
                  ReportStatusCodeLibExitBootServices,
                  NULL,
                  &gEfiEventExitBootServicesGuid,
                  &mReportStatusCodeLibExitBootServicesEvent
                  );
  ASSERT_EFI_ERROR (Status);

  return EFI_SUCCESS;
}

/**
  The destructor function of Runtime DXE Report Status Code Lib.

  The destructor function frees memory allocated by constructor, and closes related events.
  It will ASSERT() if that related operation fails and it will always return EFI_SUCCESS.

  @param  ImageHandle   The firmware allocated handle for the EFI image.
  @param  SystemTable   A pointer to the EFI System Table.

  @retval EFI_SUCCESS   The constructor always returns EFI_SUCCESS.

**/
EFI_STATUS
EFIAPI
ReportStatusCodeLibDestructor (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  ASSERT (gBS != NULL);
  Status = gBS->CloseEvent (mReportStatusCodeLibVirtualAddressChangeEvent);
  ASSERT_EFI_ERROR (Status);

  Status = gBS->CloseEvent (mReportStatusCodeLibExitBootServicesEvent);
  ASSERT_EFI_ERROR (Status);

  return EFI_SUCCESS;
}

/**
  Internal worker function that reports a status code through the Report Status Code Protocol.

  If status code service is not cached, then this function checks if Report Status Code
  Protocol is available in system.  If Report Status Code Protocol is not available, then
  EFI_UNSUPPORTED is returned.  If Report Status Code Protocol is present, then it is
  cached in mReportStatusCodeLibStatusCodeProtocol. Finally this function reports status
  code through the Report Status Code Protocol.

  @param  Type              Status code type.
  @param  Value             Status code value.
  @param  Instance          Status code instance number.
  @param  CallerId          Pointer to a GUID that identifies the caller of this
                            function.  This is an optional parameter that may be
                            NULL.
  @param  Data              Pointer to the extended data buffer.  This is an
                            optional parameter that may be NULL.

  @retval EFI_SUCCESS       The status code was reported.
  @retval EFI_UNSUPPORTED   Report Status Code Protocol is not available.
  @retval EFI_UNSUPPORTED   Status code type is not supported.

**/
EFI_STATUS
InternalReportStatusCode (
  IN EFI_STATUS_CODE_TYPE   Type,
  IN EFI_STATUS_CODE_VALUE  Value,
  IN UINT32                 Instance,
  IN CONST EFI_GUID         *CallerId OPTIONAL,
  IN EFI_STATUS_CODE_DATA   *Data     OPTIONAL
  )
{
  if ((ReportProgressCodeEnabled () && (((Type) & EFI_STATUS_CODE_TYPE_MASK) == EFI_PROGRESS_CODE)) ||
      (ReportErrorCodeEnabled () && (((Type) & EFI_STATUS_CODE_TYPE_MASK) == EFI_ERROR_CODE)) ||
      (ReportDebugCodeEnabled () && (((Type) & EFI_STATUS_CODE_TYPE_MASK) == EFI_DEBUG_CODE)))
  {
    //
    // If mReportStatusCodeLibStatusCodeProtocol is NULL, then check if Report Status Code Protocol is available in system.
    //
    InternalGetReportStatusCode ();
    if (mReportStatusCodeLibStatusCodeProtocol == NULL) {
      return EFI_UNSUPPORTED;
    }

    //
    // A Report Status Code Protocol is present in system, so pass in all the parameters to the service.
    //
    return mReportStatusCodeLibStatusCodeProtocol->ReportStatusCode (Type, Value, Instance, (EFI_GUID *)CallerId, Data);
  }

  return EFI_UNSUPPORTED;
}

/**
  Converts a status code to an 8-bit POST code value.

  Converts the status code specified by CodeType and Value to an 8-bit POST code
  and returns the 8-bit POST code in PostCode.  If CodeType is an
  EFI_PROGRESS_CODE or CodeType is an EFI_ERROR_CODE, then bits 0..4 of PostCode
  are set to bits 16..20 of Value, and bits 5..7 of PostCode are set to bits
  24..26 of Value., and TRUE is returned.  Otherwise, FALSE is returned.

  If PostCode is NULL, then ASSERT().

  @param  CodeType  The type of status code being converted.
  @param  Value     The status code value being converted.
  @param  PostCode  A pointer to the 8-bit POST code value to return.

  @retval  TRUE   The status code specified by CodeType and Value was converted
                  to an 8-bit POST code and returned in  PostCode.
  @retval  FALSE  The status code specified by CodeType and Value could not be
                  converted to an 8-bit POST code value.

**/
BOOLEAN
EFIAPI
CodeTypeToPostCode (
  IN  EFI_STATUS_CODE_TYPE   CodeType,
  IN  EFI_STATUS_CODE_VALUE  Value,
  OUT UINT8                  *PostCode
  )
{
  //
  // If PostCode is NULL, then ASSERT()
  //
  ASSERT (PostCode != NULL);

  //
  // Convert Value to an 8 bit post code
  //
  if (((CodeType & EFI_STATUS_CODE_TYPE_MASK) == EFI_PROGRESS_CODE) ||
      ((CodeType & EFI_STATUS_CODE_TYPE_MASK) == EFI_ERROR_CODE))
  {
    *PostCode = (UINT8)((((Value & EFI_STATUS_CODE_CLASS_MASK) >> 24) << 5) |
                        (((Value & EFI_STATUS_CODE_SUBCLASS_MASK) >> 16) & 0x1f));
    return TRUE;
  }

  return FALSE;
}

/**
  Extracts ASSERT() information from a status code structure.

  Converts the status code specified by CodeType, Value, and Data to the ASSERT()
  arguments specified by Filename, Description, and LineNumber.  If CodeType is
  an EFI_ERROR_CODE, and CodeType has a severity of EFI_ERROR_UNRECOVERED, and
  Value has an operation mask of EFI_SW_EC_ILLEGAL_SOFTWARE_STATE, extract
  Filename, Description, and LineNumber from the optional data area of the
  status code buffer specified by Data.  The optional data area of Data contains
  a Null-terminated ASCII string for the FileName, followed by a Null-terminated
  ASCII string for the Description, followed by a 32-bit LineNumber.  If the
  ASSERT() information could be extracted from Data, then return TRUE.
  Otherwise, FALSE is returned.

  If Data is NULL, then ASSERT().
  If Filename is NULL, then ASSERT().
  If Description is NULL, then ASSERT().
  If LineNumber is NULL, then ASSERT().

  @param  CodeType     The type of status code being converted.
  @param  Value        The status code value being converted.
  @param  Data         Pointer to status code data buffer.
  @param  Filename     Pointer to the source file name that generated the ASSERT().
  @param  Description  Pointer to the description of the ASSERT().
  @param  LineNumber   Pointer to source line number that generated the ASSERT().

  @retval  TRUE   The status code specified by CodeType, Value, and Data was
                  converted ASSERT() arguments specified by Filename, Description,
                  and LineNumber.
  @retval  FALSE  The status code specified by CodeType, Value, and Data could
                  not be converted to ASSERT() arguments.

**/
BOOLEAN
EFIAPI
ReportStatusCodeExtractAssertInfo (
  IN EFI_STATUS_CODE_TYPE        CodeType,
  IN EFI_STATUS_CODE_VALUE       Value,
  IN CONST EFI_STATUS_CODE_DATA  *Data,
  OUT CHAR8                      **Filename,
  OUT CHAR8                      **Description,
  OUT UINT32                     *LineNumber
  )
{
  EFI_DEBUG_ASSERT_DATA  *AssertData;

  ASSERT (Data        != NULL);
  ASSERT (Filename    != NULL);
  ASSERT (Description != NULL);
  ASSERT (LineNumber  != NULL);

  if (((CodeType & EFI_STATUS_CODE_TYPE_MASK)      == EFI_ERROR_CODE) &&
      ((CodeType & EFI_STATUS_CODE_SEVERITY_MASK)  == EFI_ERROR_UNRECOVERED) &&
      ((Value    & EFI_STATUS_CODE_OPERATION_MASK) == EFI_SW_EC_ILLEGAL_SOFTWARE_STATE))
  {
    AssertData   = (EFI_DEBUG_ASSERT_DATA *)(Data + 1);
    *Filename    = (CHAR8 *)(AssertData + 1);
    *Description = *Filename + AsciiStrLen (*Filename) + 1;
    *LineNumber  = AssertData->LineNumber;
    return TRUE;
  }

  return FALSE;
}

/**
  Extracts DEBUG() information from a status code structure.

  Converts the status code specified by Data to the DEBUG() arguments specified
  by ErrorLevel, Marker, and Format.  If type GUID in Data is
  EFI_STATUS_CODE_DATA_TYPE_DEBUG_GUID, then extract ErrorLevel, Marker, and
  Format from the optional data area of the status code buffer specified by Data.
  The optional data area of Data contains a 32-bit ErrorLevel followed by Marker
  which is 12 UINTN parameters, followed by a Null-terminated ASCII string for
  the Format.  If the DEBUG() information could be extracted from Data, then
  return TRUE.  Otherwise, FALSE is returned.

  If Data is NULL, then ASSERT().
  If ErrorLevel is NULL, then ASSERT().
  If Marker is NULL, then ASSERT().
  If Format is NULL, then ASSERT().

  @param  Data        Pointer to status code data buffer.
  @param  ErrorLevel  Pointer to error level mask for a debug message.
  @param  Marker      Pointer to the variable argument list associated with Format.
  @param  Format      Pointer to a Null-terminated ASCII format string of a
                      debug message.

  @retval  TRUE   The status code specified by Data was converted DEBUG() arguments
                  specified by ErrorLevel, Marker, and Format.
  @retval  FALSE  The status code specified by Data could not be converted to
                  DEBUG() arguments.

**/
BOOLEAN
EFIAPI
ReportStatusCodeExtractDebugInfo (
  IN CONST EFI_STATUS_CODE_DATA  *Data,
  OUT UINT32                     *ErrorLevel,
  OUT BASE_LIST                  *Marker,
  OUT CHAR8                      **Format
  )
{
  EFI_DEBUG_INFO  *DebugInfo;

  ASSERT (Data       != NULL);
  ASSERT (ErrorLevel != NULL);
  ASSERT (Marker     != NULL);
  ASSERT (Format     != NULL);

  //
  // If the GUID type is not EFI_STATUS_CODE_DATA_TYPE_DEBUG_GUID then return FALSE
  //
  if (!CompareGuid (&Data->Type, &gEfiStatusCodeDataTypeDebugGuid)) {
    return FALSE;
  }

  //
  // Retrieve the debug information from the status code record
  //
  DebugInfo = (EFI_DEBUG_INFO *)(Data + 1);

  *ErrorLevel = DebugInfo->ErrorLevel;

  //
  // The first 12 * sizeof (UINT64) bytes following EFI_DEBUG_INFO are for variable arguments
  // of format in DEBUG string. Its address is returned in Marker and has to be 64-bit aligned.
  // It must be noticed that EFI_DEBUG_INFO follows EFI_STATUS_CODE_DATA, whose size is
  // 20 bytes. The size of EFI_DEBUG_INFO is 4 bytes, so we can ensure that Marker
  // returned is 64-bit aligned.
  // 64-bit aligned is a must, otherwise retrieving 64-bit parameter from BASE_LIST will
  // cause unalignment exception.
  //
  *Marker = (BASE_LIST)(DebugInfo + 1);
  *Format = (CHAR8 *)(((UINT64 *)*Marker) + 12);

  return TRUE;
}

/**
  Reports a status code.

  Reports the status code specified by the parameters Type and Value.  Status
  code also require an instance, caller ID, and extended data.  This function
  passed in a zero instance, NULL extended data, and a caller ID of
  gEfiCallerIdGuid, which is the GUID for the module.

  ReportStatusCode()must actively prevent recusrsion.  If ReportStatusCode()
  is called while processing another any other Report Status Code Library function,
  then ReportStatusCode() must return immediately.

  @param  Type   Status code type.
  @param  Value  Status code value.

  @retval  EFI_SUCCESS       The status code was reported.
  @retval  EFI_DEVICE_ERROR  There status code could not be reported due to a
                             device error.
  @retval  EFI_UNSUPPORTED   Report status code is not supported

**/
EFI_STATUS
EFIAPI
ReportStatusCode (
  IN EFI_STATUS_CODE_TYPE   Type,
  IN EFI_STATUS_CODE_VALUE  Value
  )
{
  return InternalReportStatusCode (Type, Value, 0, &gEfiCallerIdGuid, NULL);
}

/**
  Reports a status code with a Device Path Protocol as the extended data.

  Allocates and fills in the extended data section of a status code with the
  Device Path Protocol specified by DevicePath.  This function is responsible
  for allocating a buffer large enough for the standard header and the device
  path.  The standard header is filled in with a GUID of
  gEfiStatusCodeSpecificDataGuid.  The status code is reported with a zero
  instance and a caller ID of gEfiCallerIdGuid.

  ReportStatusCodeWithDevicePath()must actively prevent recursion.  If
  ReportStatusCodeWithDevicePath() is called while processing another any other
  Report Status Code Library function, then ReportStatusCodeWithDevicePath()
  must return EFI_DEVICE_ERROR immediately.

  If DevicePath is NULL, then ASSERT().

  @param  Type        Status code type.
  @param  Value       Status code value.
  @param  DevicePath  Pointer to the Device Path Protocol to be reported.

  @retval  EFI_SUCCESS           The status code was reported with the extended
                                 data specified by DevicePath.
  @retval  EFI_OUT_OF_RESOURCES  There were not enough resources to allocate the
                                 extended data section.
  @retval  EFI_UNSUPPORTED       Report status code is not supported

**/
EFI_STATUS
EFIAPI
ReportStatusCodeWithDevicePath (
  IN EFI_STATUS_CODE_TYPE            Type,
  IN EFI_STATUS_CODE_VALUE           Value,
  IN CONST EFI_DEVICE_PATH_PROTOCOL  *DevicePath
  )
{
  ASSERT (DevicePath != NULL);
  return ReportStatusCodeWithExtendedData (
           Type,
           Value,
           (VOID *)DevicePath,
           GetDevicePathSize (DevicePath)
           );
}

/**
  Reports a status code with an extended data buffer.

  Allocates and fills in the extended data section of a status code with the
  extended data specified by ExtendedData and ExtendedDataSize.  ExtendedData
  is assumed to be one of the data structures specified in Related Definitions.
  These data structure do not have the standard header, so this function is
  responsible for allocating a buffer large enough for the standard header and
  the extended data passed into this function.  The standard header is filled
  in with a GUID of  gEfiStatusCodeSpecificDataGuid.  The status code is reported
  with a zero instance and a caller ID of gEfiCallerIdGuid.

  ReportStatusCodeWithExtendedData()must actively prevent recursion.  If
  ReportStatusCodeWithExtendedData() is called while processing another any other
  Report Status Code Library function, then ReportStatusCodeWithExtendedData()
  must return EFI_DEVICE_ERROR immediately.

  If ExtendedData is NULL, then ASSERT().
  If ExtendedDataSize is 0, then ASSERT().

  @param  Type              Status code type.
  @param  Value             Status code value.
  @param  ExtendedData      Pointer to the extended data buffer to be reported.
  @param  ExtendedDataSize  The size, in bytes, of the extended data buffer to
                            be reported.

  @retval  EFI_SUCCESS           The status code was reported with the extended
                                 data specified by ExtendedData and ExtendedDataSize.
  @retval  EFI_OUT_OF_RESOURCES  There were not enough resources to allocate the
                                 extended data section.
  @retval  EFI_UNSUPPORTED       Report status code is not supported

**/
EFI_STATUS
EFIAPI
ReportStatusCodeWithExtendedData (
  IN EFI_STATUS_CODE_TYPE   Type,
  IN EFI_STATUS_CODE_VALUE  Value,
  IN CONST VOID             *ExtendedData,
  IN UINTN                  ExtendedDataSize
  )
{
  ASSERT (ExtendedData     != NULL);
  ASSERT (ExtendedDataSize != 0);
  return ReportStatusCodeEx (
           Type,
           Value,
           0,
           NULL,
           NULL,
           ExtendedData,
           ExtendedDataSize
           );
}

/**
  Reports a status code with full parameters.

  The function reports a status code.  If ExtendedData is NULL and ExtendedDataSize
  is 0, then an extended data buffer is not reported.  If ExtendedData is not
  NULL and ExtendedDataSize is not 0, then an extended data buffer is allocated.
  ExtendedData is assumed not have the standard status code header, so this function
  is responsible for allocating a buffer large enough for the standard header and
  the extended data passed into this function.  The standard header is filled in
  with a GUID specified by ExtendedDataGuid.  If ExtendedDataGuid is NULL, then a
  GUID of gEfiStatusCodeSpecificDataGuid is used.  The status code is reported with
  an instance specified by Instance and a caller ID specified by CallerId.  If
  CallerId is NULL, then a caller ID of gEfiCallerIdGuid is used.

  ReportStatusCodeEx()must actively prevent recursion. If
  ReportStatusCodeEx() is called while processing another any
  other Report Status Code Library function, then
  ReportStatusCodeEx() must return EFI_DEVICE_ERROR immediately.

  If ExtendedData is NULL and ExtendedDataSize is not zero, then ASSERT().
  If ExtendedData is not NULL and ExtendedDataSize is zero, then ASSERT().

  @param  Type              Status code type.
  @param  Value             Status code value.
  @param  Instance          Status code instance number.
  @param  CallerId          Pointer to a GUID that identifies the caller of this
                            function.  If this parameter is NULL, then a caller
                            ID of gEfiCallerIdGuid is used.
  @param  ExtendedDataGuid  Pointer to the GUID for the extended data buffer.
                            If this parameter is NULL, then a the status code
                            standard header is filled in with
                            gEfiStatusCodeSpecificDataGuid.
  @param  ExtendedData      Pointer to the extended data buffer.  This is an
                            optional parameter that may be NULL.
  @param  ExtendedDataSize  The size, in bytes, of the extended data buffer.

  @retval  EFI_SUCCESS           The status code was reported.
  @retval  EFI_OUT_OF_RESOURCES  There were not enough resources to allocate
                                 the extended data section if it was specified.
  @retval  EFI_UNSUPPORTED       Report status code is not supported

**/
EFI_STATUS
EFIAPI
ReportStatusCodeEx (
  IN EFI_STATUS_CODE_TYPE   Type,
  IN EFI_STATUS_CODE_VALUE  Value,
  IN UINT32                 Instance,
  IN CONST EFI_GUID         *CallerId          OPTIONAL,
  IN CONST EFI_GUID         *ExtendedDataGuid  OPTIONAL,
  IN CONST VOID             *ExtendedData      OPTIONAL,
  IN UINTN                  ExtendedDataSize
  )
{
  EFI_STATUS            Status;
  EFI_STATUS_CODE_DATA  *StatusCodeData;
  UINT64                StatusCodeBuffer[(MAX_EXTENDED_DATA_SIZE / sizeof (UINT64)) + 1];

  ASSERT (!((ExtendedData == NULL) && (ExtendedDataSize != 0)));
  ASSERT (!((ExtendedData != NULL) && (ExtendedDataSize == 0)));

  if (ExtendedDataSize <= (MAX_EXTENDED_DATA_SIZE - sizeof (EFI_STATUS_CODE_DATA))) {
    //
    // Use Buffer instead of allocating if possible.
    //
    StatusCodeData = (EFI_STATUS_CODE_DATA *)StatusCodeBuffer;
  } else {
    if (mHaveExitedBootServices) {
      return EFI_OUT_OF_RESOURCES;
    }

    if ((gBS == NULL) || (gBS->AllocatePool == NULL) || (gBS->FreePool == NULL)) {
      return EFI_UNSUPPORTED;
    }

    //
    // Allocate space for the Status Code Header and its buffer
    //
    StatusCodeData = NULL;
    gBS->AllocatePool (EfiBootServicesData, sizeof (EFI_STATUS_CODE_DATA) + ExtendedDataSize, (VOID **)&StatusCodeData);
    if (StatusCodeData == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
  }

  //
  // Fill in the extended data header
  //
  StatusCodeData->HeaderSize = (UINT16)sizeof (EFI_STATUS_CODE_DATA);
  StatusCodeData->Size       = (UINT16)ExtendedDataSize;
  if (ExtendedDataGuid == NULL) {
    ExtendedDataGuid = &gEfiStatusCodeSpecificDataGuid;
  }

  CopyGuid (&StatusCodeData->Type, ExtendedDataGuid);

  //
  // Fill in the extended data buffer
  //
  if (ExtendedData != NULL) {
    CopyMem (StatusCodeData + 1, ExtendedData, ExtendedDataSize);
  }

  //
  // Report the status code
  //
  if (CallerId == NULL) {
    CallerId = &gEfiCallerIdGuid;
  }

  Status = InternalReportStatusCode (Type, Value, Instance, CallerId, StatusCodeData);

  //
  // Free the allocated buffer
  //
  if (StatusCodeData != (EFI_STATUS_CODE_DATA *)StatusCodeBuffer) {
    gBS->FreePool (StatusCodeData);
  }

  return Status;
}

/**
  Returns TRUE if status codes of type EFI_PROGRESS_CODE are enabled

  This function returns TRUE if the REPORT_STATUS_CODE_PROPERTY_PROGRESS_CODE_ENABLED
  bit of PcdReportStatusCodeProperyMask is set.  Otherwise FALSE is returned.

  @retval  TRUE   The REPORT_STATUS_CODE_PROPERTY_PROGRESS_CODE_ENABLED bit of
                  PcdReportStatusCodeProperyMask is set.
  @retval  FALSE  The REPORT_STATUS_CODE_PROPERTY_PROGRESS_CODE_ENABLED bit of
                  PcdReportStatusCodeProperyMask is clear.

**/
BOOLEAN
EFIAPI
ReportProgressCodeEnabled (
  VOID
  )
{
  return (BOOLEAN)((PcdGet8 (PcdReportStatusCodePropertyMask) & REPORT_STATUS_CODE_PROPERTY_PROGRESS_CODE_ENABLED) != 0);
}

/**
  Returns TRUE if status codes of type EFI_ERROR_CODE are enabled

  This function returns TRUE if the REPORT_STATUS_CODE_PROPERTY_ERROR_CODE_ENABLED
  bit of PcdReportStatusCodeProperyMask is set.  Otherwise FALSE is returned.

  @retval  TRUE   The REPORT_STATUS_CODE_PROPERTY_ERROR_CODE_ENABLED bit of
                  PcdReportStatusCodeProperyMask is set.
  @retval  FALSE  The REPORT_STATUS_CODE_PROPERTY_ERROR_CODE_ENABLED bit of
                  PcdReportStatusCodeProperyMask is clear.

**/
BOOLEAN
EFIAPI
ReportErrorCodeEnabled (
  VOID
  )
{
  return (BOOLEAN)((PcdGet8 (PcdReportStatusCodePropertyMask) & REPORT_STATUS_CODE_PROPERTY_ERROR_CODE_ENABLED) != 0);
}

/**
  Returns TRUE if status codes of type EFI_DEBUG_CODE are enabled

  This function returns TRUE if the REPORT_STATUS_CODE_PROPERTY_DEBUG_CODE_ENABLED
  bit of PcdReportStatusCodeProperyMask is set.  Otherwise FALSE is returned.

  @retval  TRUE   The REPORT_STATUS_CODE_PROPERTY_DEBUG_CODE_ENABLED bit of
                  PcdReportStatusCodeProperyMask is set.
  @retval  FALSE  The REPORT_STATUS_CODE_PROPERTY_DEBUG_CODE_ENABLED bit of
                  PcdReportStatusCodeProperyMask is clear.

**/
BOOLEAN
EFIAPI
ReportDebugCodeEnabled (
  VOID
  )
{
  return (BOOLEAN)((PcdGet8 (PcdReportStatusCodePropertyMask) & REPORT_STATUS_CODE_PROPERTY_DEBUG_CODE_ENABLED) != 0);
}
