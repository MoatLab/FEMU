/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/import/chips/p10/procedures/hwp/lib/p10_hcd_memmap_occ_sram.H $ */
/*                                                                        */
/* OpenPOWER HostBoot Project                                             */
/*                                                                        */
/* Contributors Listed Below - COPYRIGHT 2015,2020                        */
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
/// @file   p10_hcd_memmap_occ_sram.H
/// @brief  defines region constants of occ sram.
///

// *HWP HWP Owner:        David Du   <daviddu@us.ibm.com>
// *HWP Backup HWP Owner: Greg Still <stillgs@us.ibm.com>
// *HWP FW Owner:         Prem S Jha <premjha2@in.ibm.com>
// *HWP Team:             PM
// *HWP Level:            2
// *HWP Consumed by:      HB, XGPE,PGPE

#ifndef __HCD_MEMMAP_OCC_SRAM_H__
#define __HCD_MEMMAP_OCC_SRAM_H__

#include <p10_hcd_header_defs.H>
#include <p10_hcd_memmap_base.H>

// -------------------------------------------------------------------
// Note: There can be NO semicolons(";") at end of macros in this file
//       There can ONLY have HCD_CONST/HCD_CONST64 macros in this file
// -------------------------------------------------------------------

/// OCC SRAM

HCD_CONST(OCC_SRAM_BASE_ADDR,                   0xFFF00000)
HCD_CONST(GPE0_SRAM_BASE_ADDR,                  0xFFF01000)
HCD_CONST(GPE1_SRAM_BASE_ADDR,                  0xFFF10000)
HCD_CONST(PGPE_SRAM_BASE_ADDR,                  0xFFF20000)
HCD_CONST(XGPE_SRAM_BASE_ADDR,                  0xFFF30000)
HCD_CONST(OCC_SRAM_SIZE,                        ONE_MB)
HCD_CONST(OCC_SRAM_END_ADDR,                   ( OCC_SRAM_BASE_ADDR + OCC_SRAM_SIZE))

/// Base Addresses for various debug/trace regions in OCC SRAM
HCD_CONST(OCC_SRAM_TRACE_BUF_BASE_ERR,          0xFFFB4000)
HCD_CONST(OCC_SRAM_TRACE_BUF_BASE_INF,          0xFFFB6000)
HCD_CONST(OCC_SRAM_TRACE_BUF_BASE_IMP,          0xFFFB8000)
HCD_CONST(OCC_SRAM_TRACE_BUF_BASE_SSX_PTR,      0xFFF40824)
HCD_CONST(OCC_SRAM_PGPE_REGION_SIZE,            (64 * ONE_KB))
HCD_CONST(OCC_SHARED_SRAM_ADDR_START,
          ((PGPE_SRAM_BASE_ADDR + OCC_SRAM_PGPE_REGION_SIZE) - PGPE_OCC_SHARED_SRAM_SIZE))

// Offset to trace buf ptr and trace buffer size from base
HCD_CONST(GPE_DEBUG_PTR_OFFSET,                      0x180)

// Size of various traces regions in OCC SRAM
HCD_CONST(OCC_SRAM_TRACE_BUF_SSX_SIZE_PTR,      0xFFF40828)
HCD_CONST(OCC_SRAM_TRACE_BUF_ERR_SIZE,          (8 * ONE_KB))
HCD_CONST(OCC_SRAM_TRACE_BUF_INF_SIZE,          (8 * ONE_KB))
HCD_CONST(OCC_SRAM_TRACE_BUF_IMP_SIZE,          (8 * ONE_KB))

HCD_CONST(OCC_SRAM_IPC_REGION_SIZE,             (4 * ONE_KB))
HCD_CONST(OCC_SRAM_GPE0_REGION_SIZE,            (60 * ONE_KB))
HCD_CONST(OCC_SRAM_GPE1_REGION_SIZE,            (64 * ONE_KB))
HCD_CONST(OCC_SRAM_OCC_REGION_SIZE,             (512 * ONE_KB))
HCD_CONST(OCC_SRAM_XGPE_REGION_SIZE,            (64 * ONE_KB))


HCD_CONST(PPE_RESET_VECTOR,                     0x40)
//--------------------------------------------------------------------------------------

/// PGPE Base

HCD_CONST(OCC_SRAM_PGPE_BASE_ADDR, PGPE_SRAM_BASE_ADDR)
HCD_CONST(OCC_SRAM_PGPE_END_ADDR,
          (PGPE_SRAM_BASE_ADDR + OCC_SRAM_PGPE_REGION_SIZE))
HCD_CONST(OCC_SRAM_PGPE_HCODE_RESET_ADDR,
          (PGPE_SRAM_BASE_ADDR + PGPE_HCODE_RESET_ADDR_VAL))
HCD_CONST(OCC_SRAM_PGPE_HEADER_ADDR,
          (OCC_SRAM_PGPE_BASE_ADDR + PGPE_INT_VECTOR_SIZE))
//PGPE image size is sum of various parts hence located here instead of p10_hcd_memmap_base.H
HCD_CONST(PGPE_HCODE_SIZE,                      (OCC_SRAM_PGPE_REGION_SIZE - ( PGPE_OCC_SHARED_SRAM_SIZE +
          PGPE_GLOBAL_PSTATE_PARAM_BLOCK_SIZE + PGPE_SRAM_BOOT_REGION )))
HCD_CONST(PGPE_IMAGE_SIZE,                      (PGPE_HCODE_SIZE + PGPE_GLOBAL_PSTATE_PARAM_BLOCK_SIZE +
          PGPE_OCC_SHARED_SRAM_SIZE + PGPE_SRAM_BOOT_REGION))
HCD_CONST(PGPE_IMAGE_RESERVE_SIZE,
          (OCC_PSTATE_PARAM_BLOCK_PPMR_OFFSET - PGPE_IMAGE_PPMR_OFFSET - PGPE_IMAGE_SIZE))


/// PGPE Boot

HCD_CONST(OCC_SRAM_PGPE_COPY_BOOT_LOADER_SIZE,  ONE_KB)
HCD_CONST(OCC_SRAM_PGPE_COPY_PPMR_HEADER_SIZE,  512)
HCD_CONST(OCC_SRAM_PGPE_BOOT_LOADER_ADDR,
          (OCC_SRAM_END_ADDR - OCC_SRAM_PGPE_COPY_BOOT_LOADER_SIZE))
HCD_CONST(OCC_SRAM_PGPE_BOOT_LOADER_RESET_ADDR,
          (OCC_SRAM_PGPE_BOOT_LOADER_ADDR + PGPE_BOOT_LOADER_RESET_ADDR_VAL))
HCD_CONST(OCC_SRAM_PGPE_PPMR_HEADER_ADDR,
          (OCC_SRAM_PGPE_BOOT_LOADER_ADDR - OCC_SRAM_PGPE_COPY_PPMR_HEADER_SIZE))
HCD_CONST(OCC_SRAM_PGPE_OPTRACE_ADDR, OCC_SRAM_PGPE_BOOT_LOADER_ADDR)
HCD_CONST(OCC_SRAM_PGPE_OPTRACE_SIZE, OCC_SRAM_PGPE_COPY_BOOT_LOADER_SIZE)

/// PGPE Copy

HCD_CONST(OCC_SRAM_PGPE_HCODE_OFFSET_ADDR,
          (OCC_SRAM_PGPE_PPMR_HEADER_ADDR + PPMR_PGPE_HCODE_OFFSET_BYTE))
HCD_CONST(OCC_SRAM_PGPE_HCODE_LENGTH_ADDR,
          (OCC_SRAM_PGPE_PPMR_HEADER_ADDR + PPMR_PGPE_HCODE_LENGTH_BYTE))
HCD_CONST(OCC_SRAM_PGPE_IMAGE_LENGTH_ADDR,
          (OCC_SRAM_PGPE_PPMR_HEADER_ADDR + PPMR_PGPE_SRAM_IMAGE_SIZE_BYTE))

// Misc constants used in PGPE boot loader and boot copier.
HCD_CONST(PGPE_BOOT_COPY_SUCCESS,   0x42432d53 ) // ASCII code for BC-S
HCD_CONST(PGPE_BOOT_COPIER_FAIL,    0x42432d46 ) // ASCII code for BC-F
HCD_CONST(PGPE_BOOT_LOADER_SUCCESS, 0x424c2d53 ) // ASCII code for BL-S
HCD_CONST(PGPE_BOOT_LOADER_FAIL,    0x424c2d46 ) // ASCII code for BL-F

//--------------------------------------------------------------------------------------

// Misc constants used in XGPE boot loader and boot copier.
HCD_CONST(DIVDE_BY_8,  3)
HCD_CONST(DOUBLE_WORD_SIZE,  8)
HCD_CONST(XGPE_IMG_OFFSET_POS,      40)
HCD_CONST(BOOT_COPIER_LEN_ZERO,     0)
HCD_CONST(ENABLE_TRAP,              0)
HCD_CONST(XGPE_BOOT_COPY_SUCCESS,   0x42432d53 ) // ASCII code for BC-S
HCD_CONST(XGPE_BOOT_COPIER_FAIL,    0x42432d46 ) // ASCII code for BC-F
HCD_CONST(XGPE_BOOT_LOADER_SUCCESS, 0x424c2d53 ) // ASCII code for BL-S
HCD_CONST(XGPE_BOOT_LOADER_FAIL,    0x424c2d46 ) // ASCII code for BL-F

/// XGPE Base
HCD_CONST(OCC_SRAM_XGPE_SYSTEM_RESET_ADDR,
          (XGPE_SRAM_BASE_ADDR + XGPE_HCODE_RESET_ADDR_VAL))
HCD_CONST(OCC_SRAM_XGPE_IVPR_ADDR, XGPE_SRAM_BASE_ADDR)
HCD_CONST(OCC_SRAM_XGPE_GPPB_ADDR,
          (PGPE_SRAM_BASE_ADDR + PGPE_HEADER_IMAGE_OFFSET + PGPE_GLOBAL_PSTATE_SRAM_ADDR_BYTE))
HCD_CONST(OCC_SRAM_XGPE_GPPB_LEN,
          (PGPE_SRAM_BASE_ADDR + PGPE_HEADER_IMAGE_OFFSET + PGPE_GLOBAL_PSTATE_PPB_SIZE_BYTE))

/// XGPE Boot
HCD_CONST(OCC_SRAM_XGPE_COPY_BOOT_LOADER_SIZE,  ONE_KB)
HCD_CONST(OCC_SRAM_XGPE_COPY_XPMR_HEADER_SIZE,  512)
HCD_CONST(OCC_SRAM_XGPE_BOOT_LOADER_ADDR,
          (OCC_SRAM_END_ADDR - OCC_SRAM_XGPE_COPY_BOOT_LOADER_SIZE))
HCD_CONST(OCC_SRAM_XGPE_BOOT_LOADER_RESET_ADDR,
          (OCC_SRAM_XGPE_BOOT_LOADER_ADDR + XGPE_BOOT_LOADER_RESET_ADDR_VAL))
HCD_CONST(OCC_SRAM_XGPE_XPMR_HEADER_ADDR,
          (OCC_SRAM_XGPE_BOOT_LOADER_ADDR - OCC_SRAM_XGPE_COPY_XPMR_HEADER_SIZE))

/// XGPE Copy
HCD_CONST(OCC_SRAM_XGPE_HCODE_OFFSET_ADDR,
          (OCC_SRAM_XGPE_XPMR_HEADER_ADDR + XPMR_XGPE_HCODE_OFFSET_BYTE))
HCD_CONST(OCC_SRAM_XGPE_HCODE_LENGTH_ADDR,
          (OCC_SRAM_XGPE_XPMR_HEADER_ADDR + XPMR_XGPE_HCODE_LENGTH_BYTE))
HCD_CONST(OCC_SRAM_XGPE_IMAGE_LENGTH_ADDR,
          (OCC_SRAM_XGPE_XPMR_HEADER_ADDR + XPMR_XGPE_SRAM_IMAGE_SIZE_BYTE))
HCD_CONST(OCC_SRAM_XGPE_HCODE_RESET_ADDR,
          (XGPE_SRAM_BASE_ADDR + XGPE_HCODE_RESET_ADDR_VAL))

#endif /* __HCD_MEMMAP_OCC_SRAM_H__ */
