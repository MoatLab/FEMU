/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/import/chips/p10/procedures/hwp/lib/p10_hcd_memmap_homer.H $ */
/*                                                                        */
/* OpenPOWER HostBoot Project                                             */
/*                                                                        */
/* Contributors Listed Below - COPYRIGHT 2015,2019                        */
/* [+] International Business Machines Corp.                              */
/*                                                                        */
/*                                                                        */
/* Licensed under the Apache License, Version 2.0 (the "License");        */
/* you may not use this file except in compliance with the License.       */
/* You may obtain a copy of the License at                                */
/*                                                                        */
/*     http://www.apache.org/licenses/LICENSE-2.0                         */
/*                                                                        */
/* Unless required by applicable law or agreed to in writing, software    */
/* distributed under the License is distributed on an "AS IS" BASIS,      */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or        */
/* implied. See the License for the specific language governing           */
/* permissions and limitations under the License.                         */
/*                                                                        */
/* IBM_PROLOG_END_TAG                                                     */
///
/// @file   p9_hcd_memmap_homer.H
/// @brief  defines region constants of homer.
///

// *HWP HWP Owner:        David Du   <daviddu@us.ibm.com>
// *HWP Backup HWP Owner: Greg Still <stillgs@us.ibm.com>
// *HWP FW Owner:         Prem S Jha <premjha2@in.ibm.com>
// *HWP Team:             PM
// *HWP Level:            2
// *HWP Consumed by:      PM:Hostboot:Phyp

#ifndef __P9_HCD_MEMMAP_HOMER_H__
#define __P9_HCD_MEMMAP_HOMER_H__

#include <p10_hcd_header_defs.H>
#include <p10_hcd_memmap_base.H>

// -------------------------------------------------------------------
// Note: There can be NO semicolons(";") at end of macros in this file
//       There can ONLY have HCD_CONST/HCD_CONST64 macros in this file
//--------------------------------------------------------------------

/// HOMER

HCD_CONST(HOMER_BASE_ADDR,                 0x80000000)
HCD_CONST(IMG_HDR_ALIGN_SIZE,              128)

/// OPMR
HCD_CONST(OPMR_REGION_SIZE,                 ONE_MB )


/// XPMR
HCD_CONST(XPMR_HOMER_OFFSET,               (HOMER_XPMR_REGION_NUM* ONE_MB))
HCD_CONST(HOMER_XPMR_BASE_ADDR,            (HOMER_BASE_ADDR + (XPMR_HOMER_OFFSET)))
HCD_CONST(HOMER_XPMR_HEADER_ADDR,          HOMER_XPMR_BASE_ADDR)
HCD_CONST(HOMER_XGPE_BOOT_COPIER_ADDR,     (HOMER_XPMR_HEADER_ADDR + XPMR_HEADER_SIZE))
HCD_CONST(XGPE_BOOT_COPIER_SIZE,           (ONE_KB))
HCD_CONST(HOMER_XGPE_BOOT_LOADER_OFFSET_ADDR,
          (HOMER_XPMR_HEADER_ADDR + XPMR_BOOT_LOADER_OFFSET_BYTE))
HCD_CONST(HOMER_XGPE_BOOT_LOADER_LENGTH_ADDR,
          (HOMER_XPMR_HEADER_ADDR + XPMR_BOOT_LOADER_LENGTH_BYTE))

/// CPMR

HCD_CONST(HOMER_CPMR_BASE_ADDR,            (HOMER_BASE_ADDR + (CPMR_HOMER_OFFSET)))
HCD_CONST(HOMER_CPMR_HEADER_ADDR,          HOMER_CPMR_BASE_ADDR)
HCD_CONST(HOMER_CPMR_TRACE_ADDR,           (HOMER_CPMR_BASE_ADDR + CPMR_TRACE_REGION_OFFSET))
HCD_CONST(HOMER_CPMR_DEBUG_ADDR,           (HOMER_CPMR_BASE_ADDR + CPMR_DEBUG_REGION_OFFSET))


/// PPMR

HCD_CONST(HOMER_PPMR_BASE_ADDR,            (HOMER_BASE_ADDR + (PPMR_HOMER_OFFSET)))
HCD_CONST(HOMER_PPMR_HEADER_ADDR,          HOMER_PPMR_BASE_ADDR)
HCD_CONST(HOMER_PGPE_BOOT_LOADER_OFFSET_ADDR,
          (HOMER_PPMR_HEADER_ADDR + PPMR_BOOT_LOADER_OFFSET_BYTE))
HCD_CONST(HOMER_PGPE_BOOT_LOADER_LENGTH_ADDR,
          (HOMER_PPMR_HEADER_ADDR + PPMR_BOOT_LOADER_LENGTH_BYTE))
HCD_CONST(HOMER_PGPE_BOOT_COPIER_ADDR,
          (HOMER_PPMR_HEADER_ADDR + PPMR_HEADER_SIZE))

HCD_CONST(HOMER_OCC_PSTATE_PARAM_BLOCK_ADDR,
          (HOMER_PPMR_BASE_ADDR + OCC_PSTATE_PARAM_BLOCK_PPMR_OFFSET))
HCD_CONST(HOMER_PGPE_PSTATE_OUTPUT_TABLES_ADDR,
          (HOMER_PPMR_BASE_ADDR + PGPE_PSTATE_OUTPUT_TABLES_PPMR_OFFSET))
HCD_CONST(HOMER_OCC_WOF_TABLES_ADDR,
          (HOMER_PPMR_BASE_ADDR + OCC_WOF_TABLES_PPMR_OFFSET))

#endif /* __P9_HCD_MEMMAP_HOMER_H__ */
