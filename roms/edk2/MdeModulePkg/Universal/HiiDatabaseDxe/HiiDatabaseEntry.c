/** @file
This file contains the entry code to the HII database, which is defined by
UEFI 2.1 specification.

Copyright (c) 2007 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "HiiDatabase.h"

//
// Global variables
//
EFI_EVENT  gHiiKeyboardLayoutChanged;
BOOLEAN    gExportAfterReadyToBoot = FALSE;

HII_DATABASE_PRIVATE_DATA  mPrivate = {
  HII_DATABASE_PRIVATE_DATA_SIGNATURE,
  {
    (LIST_ENTRY *)NULL,
    (LIST_ENTRY *)NULL
  },
  {
    (LIST_ENTRY *)NULL,
    (LIST_ENTRY *)NULL
  },
  {
    HiiStringToImage,
    HiiStringIdToImage,
    HiiGetGlyph,
    HiiGetFontInfo
  },
  {
    HiiNewImage,
    HiiGetImage,
    HiiSetImage,
    HiiDrawImage,
    HiiDrawImageId
  },
  {
    HiiNewImageEx,
    HiiGetImageEx,
    HiiSetImageEx,
    HiiDrawImageEx,
    HiiDrawImageIdEx,
    HiiGetImageInfo
  },
  {
    HiiNewString,
    HiiGetString,
    HiiSetString,
    HiiGetLanguages,
    HiiGetSecondaryLanguages
  },
  {
    HiiNewPackageList,
    HiiRemovePackageList,
    HiiUpdatePackageList,
    HiiListPackageLists,
    HiiExportPackageLists,
    HiiRegisterPackageNotify,
    HiiUnregisterPackageNotify,
    HiiFindKeyboardLayouts,
    HiiGetKeyboardLayout,
    HiiSetKeyboardLayout,
    HiiGetPackageListHandle
  },
  {
    HiiConfigRoutingExtractConfig,
    HiiConfigRoutingExportConfig,
    HiiConfigRoutingRouteConfig,
    HiiBlockToConfig,
    HiiConfigToBlock,
    HiiGetAltCfg
  },
  {
    EfiConfigKeywordHandlerSetData,
    EfiConfigKeywordHandlerGetData
  },
  {
    (LIST_ENTRY *)NULL,
    (LIST_ENTRY *)NULL
  },
  0,
  {
    (LIST_ENTRY *)NULL,
    (LIST_ENTRY *)NULL
  },
  EFI_TEXT_ATTR (EFI_LIGHTGRAY,       EFI_BLACK),
  {
    0x00000000,
    0x0000,
    0x0000,
    { 0x00,                           0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00 }
  },
  NULL
};

/**
  The default event handler for gHiiKeyboardLayoutChanged
  event group.

  This is internal function.

  @param Event           The event that triggered this notification function.
  @param Context         Pointer to the notification functions context.

**/
VOID
EFIAPI
KeyboardLayoutChangeNullEvent (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  return;
}

/**
  On Ready To Boot Services Event notification handler.

  To trigger the function that to export the Hii Configuration setting.

  @param[in]  Event     Event whose notification function is being invoked
  @param[in]  Context   Pointer to the notification function's context

**/
VOID
EFIAPI
OnReadyToBoot (
  IN      EFI_EVENT  Event,
  IN      VOID       *Context
  )
{
  //
  // When ready to boot, we begin to export the HiiDatabase date.
  // And hook all the possible HiiDatabase change actions to export data.
  //
  HiiGetDatabaseInfo (&mPrivate.HiiDatabase);
  HiiGetConfigRespInfo (&mPrivate.HiiDatabase);
  gExportAfterReadyToBoot = TRUE;

  gBS->CloseEvent (Event);
}

/**
  Initialize HII Database.


  @param ImageHandle     The image handle.
  @param SystemTable     The system table.

  @retval EFI_SUCCESS    The Hii database is setup correctly.
  @return Other value if failed to create the default event for
          gHiiKeyboardLayoutChanged. Check gBS->CreateEventEx for
          details. Or failed to install the protocols.
          Check gBS->InstallMultipleProtocolInterfaces for details.
          Or failed to create Ready To Boot Event.
          Check EfiCreateEventReadyToBootEx for details.

**/
EFI_STATUS
EFIAPI
InitializeHiiDatabase (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  Handle;
  EFI_EVENT   ReadyToBootEvent;

  //
  // There will be only one HII Database in the system
  // If there is another out there, someone is trying to install us
  // again.  Fail that scenario.
  //
  ASSERT_PROTOCOL_ALREADY_INSTALLED (NULL, &gEfiHiiDatabaseProtocolGuid);
  ASSERT_PROTOCOL_ALREADY_INSTALLED (NULL, &gEfiHiiFontProtocolGuid);
  ASSERT_PROTOCOL_ALREADY_INSTALLED (NULL, &gEfiHiiImageProtocolGuid);
  ASSERT_PROTOCOL_ALREADY_INSTALLED (NULL, &gEfiHiiStringProtocolGuid);
  ASSERT_PROTOCOL_ALREADY_INSTALLED (NULL, &gEfiHiiConfigRoutingProtocolGuid);
  ASSERT_PROTOCOL_ALREADY_INSTALLED (NULL, &gEfiConfigKeywordHandlerProtocolGuid);

  InitializeListHead (&mPrivate.DatabaseList);
  InitializeListHead (&mPrivate.DatabaseNotifyList);
  InitializeListHead (&mPrivate.HiiHandleList);
  InitializeListHead (&mPrivate.FontInfoList);

  //
  // Create a event with EFI_HII_SET_KEYBOARD_LAYOUT_EVENT_GUID group type.
  //
  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_NOTIFY,
                  KeyboardLayoutChangeNullEvent,
                  NULL,
                  &gEfiHiiKeyBoardLayoutGuid,
                  &gHiiKeyboardLayoutChanged
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Handle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiHiiFontProtocolGuid,
                  &mPrivate.HiiFont,
                  &gEfiHiiStringProtocolGuid,
                  &mPrivate.HiiString,
                  &gEfiHiiDatabaseProtocolGuid,
                  &mPrivate.HiiDatabase,
                  &gEfiHiiConfigRoutingProtocolGuid,
                  &mPrivate.ConfigRouting,
                  &gEfiConfigKeywordHandlerProtocolGuid,
                  &mPrivate.ConfigKeywordHandler,
                  NULL
                  );

  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (FeaturePcdGet (PcdSupportHiiImageProtocol)) {
    Status = gBS->InstallMultipleProtocolInterfaces (
                    &Handle,
                    &gEfiHiiImageProtocolGuid,
                    &mPrivate.HiiImage,
                    &gEfiHiiImageExProtocolGuid,
                    &mPrivate.HiiImageEx,
                    NULL
                    );
  }

  if (FeaturePcdGet (PcdHiiOsRuntimeSupport)) {
    Status = EfiCreateEventReadyToBootEx (
               TPL_CALLBACK,
               OnReadyToBoot,
               NULL,
               &ReadyToBootEvent
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  return Status;
}
