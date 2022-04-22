/** @file
  Sample to provide TempRamInitParams data.

  Copyright (c) 2014 - 2021, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/PcdLib.h>
#include <FspEas.h>

typedef struct {
  UINT32    MicrocodeRegionBase;
  UINT32    MicrocodeRegionSize;
  UINT32    CodeRegionBase;
  UINT32    CodeRegionSize;
} FSPT_CORE_UPD;

typedef struct {
  FSP_UPD_HEADER    FspUpdHeader;
  //
  // If platform does not support FSP spec 2.2 remove FSPT_ARCH_UPD structure.
  //
  FSPT_ARCH_UPD     FsptArchUpd;
  FSPT_CORE_UPD     FsptCoreUpd;
} FSPT_UPD_CORE_DATA;

GLOBAL_REMOVE_IF_UNREFERENCED CONST FSPT_UPD_CORE_DATA  FsptUpdDataPtr = {
  {
    0x4450555F54505346,
    //
    // UPD header revision must be equal or greater than 2 when the structure is compliant with FSP spec 2.2.
    //
    0x02,
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
  },
  //
  // If platform does not support FSP spec 2.2 remove FSPT_ARCH_UPD structure.
  //
  {
    0x01,
    {
      0x00, 0x00, 0x00
    },
    0x00000020,
    0x00000000,
    {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    }
  },
  {
    FixedPcdGet32 (PcdCpuMicrocodePatchAddress),
    FixedPcdGet32 (PcdCpuMicrocodePatchRegionSize),
    FixedPcdGet32 (PcdFlashCodeCacheAddress),
    FixedPcdGet32 (PcdFlashCodeCacheSize),
  }
};
