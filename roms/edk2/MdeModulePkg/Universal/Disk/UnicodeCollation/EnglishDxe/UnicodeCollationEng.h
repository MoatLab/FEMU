/** @file
  Head file for Unicode Collation Protocol (English)

Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _UNICODE_COLLATION_ENG_H_
#define _UNICODE_COLLATION_ENG_H_

#include <Uefi.h>

#include <Protocol/UnicodeCollation.h>

#include <Library/DebugLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/PcdLib.h>

//
// Bit mask to indicate the validity of character in FAT file name.
//
#define CHAR_FAT_VALID  0x01

//
// Maximum FAT table size.
//
#define MAP_TABLE_SIZE  0x100

//
// Macro to map character a to upper case.
//
#define TO_UPPER(a)  (CHAR16) ((a) <= 0xFF ? mEngUpperMap[a] : (a))

//
// Macro to map character a to lower case.
//
#define TO_LOWER(a)  (CHAR16) ((a) <= 0xFF ? mEngLowerMap[a] : (a))

//
// Prototypes
//

/**
  Performs a case-insensitive comparison of two Null-terminated strings.

  @param  This Protocol instance pointer.
  @param  Str1 A pointer to a Null-terminated string.
  @param  Str2 A pointer to a Null-terminated string.

  @retval 0   Str1 is equivalent to Str2
  @retval > 0 Str1 is lexically greater than Str2
  @retval < 0 Str1 is lexically less than Str2

**/
INTN
EFIAPI
EngStriColl (
  IN EFI_UNICODE_COLLATION_PROTOCOL  *This,
  IN CHAR16                          *Str1,
  IN CHAR16                          *Str2
  );

/**
  Performs a case-insensitive comparison of a Null-terminated
  pattern string and a Null-terminated string.

  @param  This    Protocol instance pointer.
  @param  String  A pointer to a Null-terminated string.
  @param  Pattern A pointer to a Null-terminated pattern string.

  @retval TRUE    Pattern was found in String.
  @retval FALSE   Pattern was not found in String.

**/
BOOLEAN
EFIAPI
EngMetaiMatch (
  IN EFI_UNICODE_COLLATION_PROTOCOL  *This,
  IN CHAR16                          *String,
  IN CHAR16                          *Pattern
  );

/**
  Converts all the characters in a Null-terminated string to
  lower case characters.

  @param  This   Protocol instance pointer.
  @param  Str    A pointer to a Null-terminated string.

**/
VOID
EFIAPI
EngStrLwr (
  IN EFI_UNICODE_COLLATION_PROTOCOL  *This,
  IN OUT CHAR16                      *Str
  );

/**
  Converts all the characters in a Null-terminated string to upper
  case characters.

  @param  This   Protocol instance pointer.
  @param  Str    A pointer to a Null-terminated string.

**/
VOID
EFIAPI
EngStrUpr (
  IN EFI_UNICODE_COLLATION_PROTOCOL  *This,
  IN OUT CHAR16                      *Str
  );

/**
  Converts an 8.3 FAT file name in an OEM character set to a Null-terminated string.

  @param  This    Protocol instance pointer.
  @param  FatSize The size of the string Fat in bytes.
  @param  Fat     A pointer to a Null-terminated string that contains an 8.3 file
                  name using an 8-bit OEM character set.
  @param  String  A pointer to a Null-terminated string. The string must
                  be preallocated to hold FatSize characters.

**/
VOID
EFIAPI
EngFatToStr (
  IN EFI_UNICODE_COLLATION_PROTOCOL  *This,
  IN UINTN                           FatSize,
  IN CHAR8                           *Fat,
  OUT CHAR16                         *String
  );

/**
  Converts a Null-terminated string to legal characters in a FAT
  filename using an OEM character set.

  @param  This    Protocol instance pointer.
  @param  String  A pointer to a Null-terminated string. The string must
                  be preallocated to hold FatSize characters.
  @param  FatSize The size of the string Fat in bytes.
  @param  Fat     A pointer to a Null-terminated string that contains an 8.3 file
                  name using an OEM character set.

  @retval TRUE    Fat is a Long File Name
  @retval FALSE   Fat is an 8.3 file name

**/
BOOLEAN
EFIAPI
EngStrToFat (
  IN EFI_UNICODE_COLLATION_PROTOCOL  *This,
  IN CHAR16                          *String,
  IN UINTN                           FatSize,
  OUT CHAR8                          *Fat
  );

/**
  The user Entry Point for English module.

  This function initializes unicode character mapping and then installs Unicode
  Collation & Unicode Collation 2 Protocols based on the feature flags.

  @param  ImageHandle    The firmware allocated handle for the EFI image.
  @param  SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS    The entry point is executed successfully.
  @retval other          Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
InitializeUnicodeCollationEng (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

#endif
