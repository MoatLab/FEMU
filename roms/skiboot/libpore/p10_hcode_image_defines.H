/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/import/chips/p10/procedures/hwp/lib/p10_hcode_image_defines.H $ */
/*                                                                        */
/* OpenPOWER HostBoot Project                                             */
/*                                                                        */
/* Contributors Listed Below - COPYRIGHT 2019,2020                        */
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
/// @file   p10_hcode_image_defines.H
/// @brief  defines constants associated with hcode image build.
///
// *HWP HWP Owner:      Greg Still <stillgs@us.ibm.com>
// *HWP FW Owner:       Prem S Jha <premjha2@in.ibm.com>
// *HWP Team:           PM
// *HWP Level:          2
// *HWP Consumed by:    Hostboot: HBRT

#ifndef __HW_IMG_DEFINE
#define __HW_IMG_DEFINE

#include <p10_hcd_header_defs.H>
#include <p10_hcd_memmap_base.H>
#include <p10_hcd_memmap_homer.H>
#include <p10_hcd_memmap_occ_sram.H>

//--------------------------------------------------------------------------
// local structs and constants
// -------------------------------------------------------------------------
#ifndef __ASSEMBLER__
#ifdef __cplusplus
#ifndef __PPE_PLAT

#define IMG_HDR_ALIGN_SIZE 32

namespace hcodeImageBuild
{
#endif //__PPE_PLAT
#endif //__cplusplus
#endif //__ASSEMBLER__

/**
 * CPMR Header
 *
 *  This header is only consumed by Hcode Image Build and
 *  lab tools, not by PPE code.  It is generated with assembler
 *  primitives during QME build and placed in HOMER by
 *  Hcode Image Build.
 */

#ifdef __ASSEMBLER__
.macro  .cpmr_header
.section ".cpmr" , "aw"
.balign    8
#else
typedef struct
{
#endif
HCD_HDR_ATTN  ( iv_attnOpcodes,         2);
HCD_HDR_UINT64( iv_cpmrMagicWord,       CPMR_MAGIC_NUMBER);
HCD_HDR_UINT32( iv_buildDate,           0);
HCD_HDR_UINT32( iv_version,             0);
HCD_HDR_UINT8_VEC (iv_reserveFlags, 4,  0);
HCD_HDR_UINT8 ( iv_selfRestoreVer,      0);
HCD_HDR_UINT8 ( iv_stopApiVer,          0);
HCD_HDR_UINT8 ( iv_urmorFix,            0);
HCD_HDR_UINT8 ( iv_fusedMode,           0);
HCD_HDR_UINT32( iv_qmeImgOffset,        0);
HCD_HDR_UINT32( iv_qmeImgLength,        0);
HCD_HDR_UINT32( iv_commonRingOffset,    0);
HCD_HDR_UINT32( iv_commonRingLength,    0);
HCD_HDR_UINT32( iv_localPstateOffset,   0);
HCD_HDR_UINT32( iv_localPstateLength,   0);
HCD_HDR_UINT32( iv_specRingOffset,      0);
HCD_HDR_UINT32( iv_specRingLength,      0);
HCD_HDR_UINT32( iv_scomRestoreOffset,   0);
HCD_HDR_UINT32( iv_scomRestoreLength,   0);
HCD_HDR_UINT32( iv_selfRestoreOffset,   0);
HCD_HDR_UINT32( iv_selfRestoreLength,   0);
HCD_HDR_UINT32( iv_maxCoreL2ScomEntry,  0);
HCD_HDR_UINT32( iv_maxEqL3ScomEntry,    0);
HCD_HDR_UINT32( iv_coreL2ScomOffset,    0);
HCD_HDR_UINT32( iv_coreL2ScomLength,    0);
HCD_HDR_UINT32( iv_eqL3ScomOffset,      0);
HCD_HDR_UINT32( iv_eqL3ScomLength,      0);
HCD_HDR_PAD(CPMR_HEADER_SIZE);
#ifdef __ASSEMBLER__
.endm
#else
} __attribute__((packed, aligned(256))) CpmrHeader_t;
#endif

/**
 * QME Header
 *
 * The QME header is loaded in the QME SRAM so it is "tight" (little extra space)
 * Thus, this "structure" is NOT padded to a specific size and is limited to
 * 64B.  Also, structure member names are preceded with "g_" as these becoming
 * global variables in the QME Hcode.
 */
#ifdef __ASSEMBLER__
.macro  .qme_header
.section ".qme_image_header" , "aw"
.balign    8
#else
typedef struct
{
#endif
HCD_HDR_UINT64( g_qme_magic_number,          QME_MAGIC_NUMBER );
HCD_HDR_UINT32( g_qme_hcode_offset,          0 );
HCD_HDR_UINT32( g_qme_hcode_length,          0 );
HCD_HDR_UINT32( g_qme_common_ring_offset,    0 );
HCD_HDR_UINT32( g_qme_cmn_ring_ovrd_offset,  0 );
HCD_HDR_UINT32( g_qme_common_ring_length,    0 );
HCD_HDR_UINT32( g_qme_pstate_region_offset,  0 );
HCD_HDR_UINT32( g_qme_pstate_region_length,  0 );
HCD_HDR_UINT32( g_qme_inst_spec_ring_offset, 0 );
HCD_HDR_UINT32( g_qme_max_spec_ring_length,  0 );
HCD_HDR_UINT32( g_qme_scom_offset,           0 );
HCD_HDR_UINT32( g_qme_scom_length,           0 );
HCD_HDR_UINT32( g_qme_attr_tank_address,     0 );
HCD_HDR_UINT16( g_qme_location_id,           0 );
HCD_HDR_UINT16( g_qme_reserved ,             0 );
HCD_HDR_UINT32( g_qme_timebase_hz,           0 ); //Retain next field at 8B boundary
HCD_HDR_UINT64( g_qme_cpmr_PhyAddr,          0 );
HCD_HDR_UINT64( g_qme_unsec_cpmr_PhyAddr,    0 );
HCD_HDR_UINT32( g_qme_custom_length,         0 );
HCD_HDR_UINT32( g_qme_elog_addr,             0 );
HCD_HDR_PAD(IMG_HDR_ALIGN_SIZE);
#ifdef __ASSEMBLER__
.endm
#else
//QME Header size is 96B
} __attribute__((packed, aligned(32))) QmeHeader_t;
#endif

#ifndef __ASSEMBLER__

typedef struct QMEImageFlags
{
    uint32_t fused_mode     : 1;
    uint32_t reserved0      : 31;
} QMEImageFlags_t;

#endif //__ASSEMBLER__

#ifdef __ASSEMBLER__
.macro  .ppmr_header
.section ".ppmr" , "aw"
.balign    8
#else
typedef struct
{
#endif
HCD_HDR_UINT64( iv_ppmrMagicWord,       PPMR_MAGIC_NUMBER);
HCD_HDR_UINT32( iv_bootCopierOffset,    0);
HCD_HDR_UINT32( iv_reserved1,           0);
HCD_HDR_UINT32( iv_bootLoaderOffset,    0);
HCD_HDR_UINT32( iv_bootLoaderLength,    0);
HCD_HDR_UINT32( iv_buildDate,           0);
HCD_HDR_UINT32( iv_buildVer,            0);
HCD_HDR_UINT64( iv_reserved2,           0);
HCD_HDR_UINT32( iv_hcodeOffset,         0);
HCD_HDR_UINT32( iv_hcodeLength,         0);
HCD_HDR_UINT32( iv_gpspbOffset,         0);
HCD_HDR_UINT32( iv_gpspbLength,         0);
HCD_HDR_UINT32( iv_lpspbOffset,         0);
HCD_HDR_UINT32( iv_lpspbLength,         0);
HCD_HDR_UINT32( iv_opspbOffset,         0);
HCD_HDR_UINT32( iv_opspbLength,         0);
HCD_HDR_UINT32( iv_pstateOffset,        0);
HCD_HDR_UINT32( iv_pstateLength,        0);
HCD_HDR_UINT32( iv_sramSize,            0);
HCD_HDR_UINT32( iv_progCode,            0);
HCD_HDR_UINT32( iv_wofTableOffset,      0);
HCD_HDR_UINT32( iv_wofTableLength,      0);
HCD_HDR_UINT32( iv_deepOptraceOffset,   0);
HCD_HDR_UINT32( iv_deepOptraceLength,   0);

#ifdef __ASSEMBLER__
.endm
#else
} __attribute__((packed, aligned(32))) PpmrHeader_t;
#endif

#ifdef __ASSEMBLER__
.macro  .pgpe_header
.section ".pgpe_hdr" , "aw"
.balign    8
#else
typedef struct
{
#endif
HCD_HDR_UINT64( g_pgpe_magicWord,           PGPE_MAGIC_NUMBER);
HCD_HDR_UINT32( g_pgpe_sysResetAddress,     0);
HCD_HDR_UINT32( g_pgpe_sharedSramAddress,   0);
HCD_HDR_UINT32( g_pgpe_ivprAddress,         0);
HCD_HDR_UINT32( g_pgpe_sharedLength,        0);
HCD_HDR_UINT32( g_pgpe_buildDate,           0);
HCD_HDR_UINT32( g_pgpe_buildVer,            0);
HCD_HDR_UINT32( g_pgpe_reserved0,           0);
HCD_HDR_UINT32( g_pgpe_timeBaseHz,          0);
HCD_HDR_UINT32( g_pgpe_gpspbSramAddress,    0);
HCD_HDR_UINT32( g_pgpe_hcodeLength,         0);
HCD_HDR_UINT32( g_pgpe_gpspbMemOffset,      0);
HCD_HDR_UINT32( g_pgpe_gpspbMemLength,      0);
HCD_HDR_UINT32( g_pgpe_genPsTableMemOffset, 0);
HCD_HDR_UINT32( g_pgpe_genPsTableMemLength, 0);
HCD_HDR_UINT32( g_pgpe_opspbTableAddress,   0);
HCD_HDR_UINT32( g_pgpe_opspbTableLength,    0);
HCD_HDR_UINT32( g_pgpe_beaconAddress,       0);
HCD_HDR_UINT32( g_pgpe_reserved1,           0);
HCD_HDR_UINT32( g_pgpe_pgpeWofStateAddress, 0);
HCD_HDR_UINT32( g_pgpe_reserved2,           0);
HCD_HDR_UINT32( g_pgpe_wofTableAddress,     0);
HCD_HDR_UINT32( g_pgpe_wofTableLength,      0);
HCD_HDR_UINT32( g_pgpe_reserved3,           0);
HCD_HDR_UINT32( g_pgpe_reserved4,           0);
HCD_HDR_UINT32( g_pgpe_reserved5,           0);
HCD_HDR_UINT32( g_pgpe_opTracePtr,          0);
HCD_HDR_UINT32( g_pgpe_deepOpTraceMemAddress, 0);
HCD_HDR_UINT32( g_pgpe_deepOpTraceLength,     0);
#ifdef __ASSEMBLER__
.endm
#else
} __attribute__((packed, aligned(32))) PgpeHeader_t;
#endif

#ifdef __ASSEMBLER__
.macro  .xpmr_hdr
.section ".xpmr" , "aw"
.balign    8
#else
typedef struct
{
#endif
HCD_HDR_UINT64( iv_xpmrMagicWord,           XPMR_MAGIC_NUMBER);
HCD_HDR_UINT32( iv_bootCopierOffset,    0);
HCD_HDR_UINT32( iv_reserve1,            0);
HCD_HDR_UINT32( iv_bootLoaderOffset,    0);
HCD_HDR_UINT32( iv_bootLoaderLength,    0);
HCD_HDR_UINT32( iv_buildDate,           0);
HCD_HDR_UINT32( iv_version,             0);
HCD_HDR_UINT32( iv_reserve2,            0);
HCD_HDR_UINT32( iv_reserve3,            0);
HCD_HDR_UINT32( iv_xgpeHcodeOffset,     0);
HCD_HDR_UINT32( iv_xgpeHcodeLength,     0);
HCD_HDR_UINT32( iv_xgpeBootProgCode,    0);
HCD_HDR_UINT32( iv_xgpeSramSize,        0);
HCD_HDR_PAD(XPMR_HEADER_SIZE);
#ifdef __ASSEMBLER__
.endm
#else
} __attribute__((packed, aligned(512))) XpmrHeader_t;
#endif

#ifdef __ASSEMBLER__
.macro  .xgpe_header
.section ".xgpe_header" , "aw"
.balign    8
#else
typedef struct
{
#endif
HCD_HDR_UINT64( g_xgpe_magicWord,                XGPE_MAGIC_NUMBER);
HCD_HDR_UINT32( g_xgpe_sysResetAddress,          0 ); //FIXME need to add correct address
HCD_HDR_UINT32( g_xgpe_sharedSramAddress,        0 ); //FIXME need to add correct address
HCD_HDR_UINT32( g_xgpe_ivprAddress,              0 ); //FIXME need to add correct address
HCD_HDR_UINT32( g_xgpe_sharedSramLength,         0 );
HCD_HDR_UINT32( g_xgpe_buildDate,                0 );
HCD_HDR_UINT32( g_xgpe_buildVer,                 0 );
HCD_HDR_UINT16( g_xgpe_xgpeFlags,                0 );
HCD_HDR_UINT16( g_xgpe_reserve1,                 0 );
HCD_HDR_UINT32( g_xgpe_timeBaseHz,               0 );
HCD_HDR_UINT32( g_xgpe_gpspbSramAddress,         0 );
HCD_HDR_UINT32( g_xgpe_hcodeLength,              0 );
HCD_HDR_UINT32( g_xgpe_reserve2,                 0 );
HCD_HDR_UINT32( g_xgpe_gpspbLength,              0 );
HCD_HDR_UINT32( g_xgpe_coreThrottleAssertCnt,    0 );
HCD_HDR_UINT32( g_xgpe_coreThrottleDeAssertCnt,  0 );
HCD_HDR_UINT32( g_xgpe_charactControls,          0 );
HCD_HDR_UINT32( g_xgpe_xgpeOpTracePointer,       0 );
HCD_HDR_UINT32( g_xgpe_xgpeDeepOpTraceMemAddr,   0 );
HCD_HDR_UINT32( g_xgpe_xgpeDeepOpTraceLength, 0 );
HCD_HDR_PAD(IMG_HDR_ALIGN_SIZE);
#ifdef __ASSEMBLER__
.endm
#else
} __attribute__((packed, aligned(32))) XgpeHeader_t;
#endif

#ifndef __ASSEMBLER__

/**
 * @brief   enumerates all return codes associated with hcode image build.
 */
enum ImgBldRetCode_t
{
    IMG_BUILD_SUCCESS           =   0,
    BUILD_FAIL_XGPE_IMAGE       =   1,
    BUILD_FAIL_SELF_REST_IMAGE  =   2,
    BUILD_FAIL_QME_IMAGE        =   3,
    BUILD_FAIL_PGPE_IMAGE       =   4,
    BUILD_FAIL_XGPE_QPMR        =   5,
    BUILD_FAIL_XGPE_BL1         =   6,
    BUILD_FAIL_XGPE_BL2         =   7,
    BUILD_FAIL_XGPE_INT_VECT    =   8,
    BUILD_FAIL_XGPE_HDR         =   9,
    BUILD_FAIL_XGPE_HCODE       =   10,
    BUILD_FAIL_XGPE_CMN_RINGS   =   11,
    BUILD_FAIL_XGPE_SPEC_RINGS  =   12,
    BUILD_FAIL_CPMR_HDR         =   13,
    BUILD_FAIL_SRESET_HNDLR     =   14,
    BUILD_FAIL_THRD_LAUNCHER    =   15,
    BUILD_FAIL_SPR_RESTORE      =   16,
    BUILD_FAIL_SCOM_RESTORE     =   17,
    BUILD_FAIL_QME_IMG_HDR      =   18,
    BUILD_FAIL_QME_HCODE        =   19,
    BUILD_FAIL_CMN_RINGS        =   20,
    BUILD_FAIL_QME_QUAD_PSTATE  =   21,
    BUILD_FAIL_SPEC_RINGS       =   22,
    BUILD_FAIL_INT_VECT         =   23,
    BUILD_FAIL_PGPE_BL1         =   24,
    BUILD_FAIL_PGPE_BL2         =   25,
    BUILD_FAIL_PGPE_HCODE       =   26,
    BUILD_FAIL_OVERRIDE         =   27,
    BUILD_SEC_SIZE_OVERFLOW     =   28,
    BUILD_FAIL_INVALID_SECTN    =   29,
    BUILD_FAIL_RING_EXTRACTN    =   30,
    QME_SRAM_IMG_SIZE_ERR       =   31,
    XGPE_SRAM_IMG_SIZE_ERR      =   32,
    PGPE_SRAM_IMG_SIZE_ERR      =   33,
    BUILD_FAIL_PGPE_PPMR        =   34,
    BUILD_FAIL_XIP_CUST_ERR     =   35,
    BUILD_ERR_INTERNAL          =   0xffff,
};

/**
 * @brief   models SCOM restore header region.
 */
typedef struct
{
    uint16_t     iv_magicMark;
    uint8_t      iv_version;
    uint8_t      iv_reserved1;
    uint8_t      iv_reserved2[4];
    uint16_t     iv_coreOffset;
    uint16_t     iv_coreLength;
    uint16_t     iv_eqOffset;
    uint16_t     iv_eqLength;
    uint16_t     iv_l2Offset;
    uint16_t     iv_l2Length;
    uint16_t     iv_l3Offset;
    uint16_t     iv_l3Length;
} ScomRestoreHeader_t;

/**
 * @brief models a CPU register restoration area in STOP section of homer image.
 */
typedef struct
{
    uint8_t iv_threadRestoreArea[MAX_THREADS_PER_CORE][SMF_CORE_RESTORE_THREAD_AREA_SIZE];
    uint8_t iv_threadSaveArea[MAX_THREADS_PER_CORE][SMF_SELF_SAVE_THREAD_AREA_SIZE];
    uint8_t iv_coreRestoreArea[SMF_CORE_RESTORE_CORE_AREA_SIZE];
    uint8_t iv_coreSaveArea[SMF_CORE_SAVE_CORE_AREA_SIZE];
} SmfSprRestoreRegion_t;

/**
 * @brief   models image section of CPMR in HOMER.
 */
typedef union CPMRSelfRestoreLayout
{
    uint8_t iv_region[SMF_SELF_RESTORE_CODE_SIZE];
    struct
    {
        CpmrHeader_t iv_CPMRHeader;
        uint8_t      iv_exe[SMF_SELF_RESTORE_CODE_SIZE - sizeof(CpmrHeader_t)];
    } elements;
} CPMRSelfRestoreLayout_t;

/**
 * @brief   models image section associated with core self restore in HOMER.
 */
typedef struct
{
    CPMRSelfRestoreLayout_t iv_CPMR_SR;
    uint8_t                 iv_coreSelfRestore[SMF_SELF_RESTORE_CORE_REGS_SIZE];
    uint8_t                 iv_reserve[SCOM_RESTORE_CPMR_OFFSET - SMF_SELF_RESTORE_SIZE_TOTAL];
    uint8_t                 iv_coreScom[SCOM_RESTORE_SIZE_TOTAL];
} SelfRestoreLayout_t;

typedef struct
{
    SelfRestoreLayout_t     iv_selfRestoreRegion;
    uint8_t                 iv_qmeSramRegion[QME_REGION_SIZE];
} CPMRLayout_t;

/**
 * @brief   models image section associated with PGPE in HOMER.
 */
typedef struct
{
    uint8_t iv_ppmrHeader[PPMR_HEADER_SIZE];
    uint8_t iv_bootCopier[PGPE_BOOT_COPIER_SIZE];
    uint8_t iv_bootLoader[PGPE_BOOT_LOADER_SIZE];
    uint8_t iv_pgpeSramRegion[OCC_SRAM_PGPE_REGION_SIZE];
    uint8_t iv_reserve1[OCC_PSTATE_PARAM_BLOCK_PPMR_OFFSET - (PPMR_BOOT_REGION + OCC_SRAM_PGPE_REGION_SIZE)];
    uint8_t iv_occPstateParamBlock[OCC_PSTATE_PARAM_BLOCK_REGION_SIZE];
    uint8_t iv_pstateTable[PGPE_PSTATE_OUTPUT_TABLES_REGION_SIZE];
    uint8_t iv_reserve2[PPMR_RESERVE_PSTATE_TABLE_TO_WOF];
    uint8_t iv_wofTable[OCC_WOF_TABLES_SIZE];
} PPMRLayout_t;

/**
 * @brief   models XPMR in HOMER.
 */
typedef struct
{
    uint8_t iv_xpmrHeader[XPMR_HEADER_SIZE];
    uint8_t iv_bootCopier[XGPE_BOOT_COPIER_LENGTH];
    uint8_t iv_bootLoader[XGPE_BOOT_LOADER_LENGTH];
    uint8_t iv_xgpeSramRegion[XGPE_SRAM_SIZE];
} XPMRLayout_t;

/**
 * @brief   models layout of HOMER.
 */
typedef struct
{
    uint8_t      iv_occHostRegion[OCC_HOST_AREA_SIZE];
    XPMRLayout_t iv_xpmrRegion;
    uint8_t      iv_xpmrReserve[ONE_MB - sizeof( XPMRLayout_t )];
    CPMRLayout_t iv_cpmrRegion;
    uint8_t      iv_cpmrReserve[ONE_MB - sizeof( CPMRLayout_t )];
    PPMRLayout_t iv_ppmrRegion;
    uint8_t      iv_ppmrReserve[ONE_MB - sizeof( PPMRLayout_t )];
} Homerlayout_t;

#ifdef __cplusplus
#ifndef __PPE_PLAT
}// namespace hcodeImageBuild ends
#endif //__PPE_PLAT
#endif //__cplusplus

#endif //__ASSEMBLER__
#endif //__HW_IMG_DEFINE
