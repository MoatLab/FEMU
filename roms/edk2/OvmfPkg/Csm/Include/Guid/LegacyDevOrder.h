/** @file
  Guid of a NV Variable which store the information about the
  FD/HD/CD/NET/BEV order.

Copyright (c) 2011 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __LEGACY_DEV_ORDER_VARIABLE_GUID_H__
#define __LEGACY_DEV_ORDER_VARIABLE_GUID_H__

///
/// Name and Guid of a NV Variable which stores the information about the
/// FD/HD/CD/NET/BEV order
///
#define EFI_LEGACY_DEV_ORDER_VARIABLE_GUID \
  { \
  0xa56074db, 0x65fe, 0x45f7, {0xbd, 0x21, 0x2d, 0x2b, 0xdd, 0x8e, 0x96, 0x52} \
  }

typedef UINT8 BBS_TYPE;

#pragma pack(1)
typedef struct {
  BBS_TYPE    BbsType;
  ///
  /// Length = sizeof (UINT16) + sizeof (Data)
  ///
  UINT16      Length;
  UINT16      Data[1];
} LEGACY_DEV_ORDER_ENTRY;
#pragma pack()

#define VAR_LEGACY_DEV_ORDER  L"LegacyDevOrder"

extern EFI_GUID  gEfiLegacyDevOrderVariableGuid;

#endif
