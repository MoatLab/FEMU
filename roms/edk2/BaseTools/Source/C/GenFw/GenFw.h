/** @file
Header file for GenFw

Copyright (c) 2010 - 2018, Intel Corporation. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _GEN_FW_H_
#define _GEN_FW_H_

//
// Action for this tool.
//
#define FW_DUMMY_IMAGE                0
#define FW_EFI_IMAGE                  1
#define FW_TE_IMAGE                   2
#define FW_ACPI_IMAGE                 3
#define FW_BIN_IMAGE                  4
#define FW_ZERO_DEBUG_IMAGE           5
#define FW_SET_STAMP_IMAGE            6
#define FW_MCI_IMAGE                  7
#define FW_MERGE_IMAGE                8
#define FW_RELOC_STRIPEED_IMAGE       9
#define FW_HII_PACKAGE_LIST_RCIMAGE   10
#define FW_HII_PACKAGE_LIST_BINIMAGE  11
#define FW_REBASE_IMAGE               12
#define FW_SET_ADDRESS_IMAGE          13

#define DUMP_TE_HEADER  0x11

VOID
SetHiiResourceHeader (
  UINT8   *HiiBinData,
  UINT32  OffsetToFile
  );

INTN
IsElfHeader (
  UINT8  *FileBuffer
  );

BOOLEAN
ConvertElf (
  UINT8  **FileBuffer,
  UINT32 *FileLength
  );

#endif
