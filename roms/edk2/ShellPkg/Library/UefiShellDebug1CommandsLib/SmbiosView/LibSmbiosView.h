/** @file
  API for SMBIOS Plug and Play functions, access to SMBIOS table and structures.

  Copyright (c) 2005 - 2015, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _LIB_SMBIOS_VIEW_H_
#define _LIB_SMBIOS_VIEW_H_

#include <IndustryStandard/SmBios.h>

#define DMI_SUCCESS                 0x00
#define DMI_UNKNOWN_FUNCTION        0x81
#define DMI_FUNCTION_NOT_SUPPORTED  0x82
#define DMI_INVALID_HANDLE          0x83
#define DMI_BAD_PARAMETER           0x84
#define DMI_INVALID_SUBFUNCTION     0x85
#define DMI_NO_CHANGE               0x86
#define DMI_ADD_STRUCTURE_FAILED    0x87
#define DMI_READ_ONLY               0x8D
#define DMI_LOCK_NOT_SUPPORTED      0x90
#define DMI_CURRENTLY_LOCKED        0x91
#define DMI_INVALID_LOCK            0x92

#define INVALID_HANDLE  (UINT16) (-1)

#define EFI_SMBIOSERR(val)  EFIERR (0x30000 | val)

#define EFI_SMBIOSERR_FAILURE           EFI_SMBIOSERR (1)
#define EFI_SMBIOSERR_STRUCT_NOT_FOUND  EFI_SMBIOSERR (2)
#define EFI_SMBIOSERR_TYPE_UNKNOWN      EFI_SMBIOSERR (3)
#define EFI_SMBIOSERR_UNSUPPORTED       EFI_SMBIOSERR (4)

/**
  Init the SMBIOS VIEW API's environment for the 32-bit table..

  @retval EFI_SUCCESS  Successful to init the SMBIOS VIEW Lib.
**/
EFI_STATUS
LibSmbiosInit (
  VOID
  );

/**
  Init the SMBIOS VIEW API's environment for the 64-bit table..

  @retval EFI_SUCCESS  Successful to init the SMBIOS VIEW Lib.
**/
EFI_STATUS
LibSmbios64BitInit (
  VOID
  );

/**
  Cleanup the Smbios information.
**/
VOID
LibSmbiosCleanup (
  VOID
  );

/**
  Cleanup the Smbios information.
**/
VOID
LibSmbios64BitCleanup (
  VOID
  );

/**
  Get the entry point structure for the table.

  @param[out] EntryPointStructure  The pointer to populate.
**/
VOID
LibSmbiosGetEPS (
  OUT SMBIOS_TABLE_ENTRY_POINT  **EntryPointStructure
  );

/**
  Get the entry point structure for the 64-bit table.

  @param[out] EntryPointStructure  The pointer to populate.
**/
VOID
LibSmbios64BitGetEPS (
  OUT SMBIOS_TABLE_3_0_ENTRY_POINT  **EntryPointStructure
  );

/**
  Return SMBIOS string for the given string number.

  @param[in] Smbios         Pointer to SMBIOS structure.
  @param[in] StringNumber   String number to return. -1 is used to skip all strings and
                            point to the next SMBIOS structure.

  @return Pointer to string, or pointer to next SMBIOS strcuture if StringNumber == -1
**/
CHAR8 *
LibGetSmbiosString (
  IN  SMBIOS_STRUCTURE_POINTER  *Smbios,
  IN  UINT16                    StringNumber
  );

/**
    Get SMBIOS structure for the given Handle,
    Handle is changed to the next handle or 0xFFFF when the end is
    reached or the handle is not found.

    @param[in, out] Handle     0xFFFF: get the first structure
                               Others: get a structure according to this value.
    @param[out] Buffer         The pointer to the pointer to the structure.
    @param[out] Length         Length of the structure.

    @retval DMI_SUCCESS   Handle is updated with next structure handle or
                          0xFFFF(end-of-list).

    @retval DMI_INVALID_HANDLE  Handle is updated with first structure handle or
                                0xFFFF(end-of-list).
**/
EFI_STATUS
LibGetSmbiosStructure (
  IN  OUT UINT16  *Handle,
  OUT UINT8       **Buffer,
  OUT UINT16      *Length
  );

/**
    Get SMBIOS structure for the given Handle in 64-bit table,
    Handle is changed to the next handle or 0xFFFF when the end is
    reached or the handle is not found.

    @param[in, out] Handle     0xFFFF: get the first structure
                               Others: get a structure according to this value.
    @param[out] Buffer         The pointer to the pointer to the structure.
    @param[out] Length         Length of the structure.

    @retval DMI_SUCCESS   Handle is updated with next structure handle or
                          0xFFFF(end-of-list).

    @retval DMI_INVALID_HANDLE  Handle is updated with first structure handle or
                                0xFFFF(end-of-list).
**/
EFI_STATUS
LibGetSmbios64BitStructure (
  IN  OUT UINT16  *Handle,
  OUT UINT8       **Buffer,
  OUT UINT16      *Length
  );

#endif
