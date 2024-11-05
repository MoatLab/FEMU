/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: chips/p10/procedures/utils/stopreg/p10_stop_data_struct.H $   */
/*                                                                        */
/* IBM CONFIDENTIAL                                                       */
/*                                                                        */
/* EKB Project                                                            */
/*                                                                        */
/* COPYRIGHT 2015,2020                                                    */
/* [+] International Business Machines Corp.                              */
/*                                                                        */
/*                                                                        */
/* The source code for this program is not published or otherwise         */
/* divested of its trade secrets, irrespective of what has been           */
/* deposited with the U.S. Copyright Office.                              */
/*                                                                        */
/* IBM_PROLOG_END_TAG                                                     */

///
/// @file   p10_stop_data_struct.H
/// @brief  describes data structures internal to STOP API.
///
// *HWP HW Owner    :  Greg Still <stillgs@us.ibm.com>
// *HWP FW Owner    :  Prem Shanker Jha <premjha2@in.ibm.com>
// *HWP Team        :  PM
// *HWP Level       :  2
// *HWP Consumed by :  HB:HYP
#ifndef __STOP_DATA_STRUCT_
#define __STOP_DATA_STRUCT_

#include "p10_hcd_memmap_base.H"

#ifdef __SKIBOOT__
    #include <skiboot.h>
#endif

#ifdef __FAPI_2_
    #include <fapi2.H>
#endif

#ifdef PPC_HYP

    #define STATIC

#else

    #define STATIC static

#endif


#ifdef __DEBUG_
    #include<stdio.h>
#endif

#ifdef __cplusplus
extern "C" {
namespace stopImageSection
{
#endif

/**
 * @brief   Misc constants pertaining to instruction opcodes.
 */
enum
{
    MAX_SPR_RESTORE_INST        =   0x08,
    SIZE_PER_SPR_RESTORE_INST   =   ((4 * sizeof(uint8_t)) / sizeof(uint32_t)),
    MAX_THREAD_LEVEL_SPRS       =   11,
    MAX_CORE_LEVEL_SPRS         =   6,
    MAX_SPR_BIT_POS             =   30,
    SPR_BIT_POS_8               =    8,
    SPR_BIT_POS_20              =   20,
    SPR_BIT_POS_25              =   25,
    SPR_BIT_POS_27              =   27,
};

/**
 * @brief   various operations supported on SPR restore entry.
 */
enum SprEntryUpdateMode
{
    INIT_SPR_REGION       =   0x01,
    UPDATE_SPR_ENTRY      =   0x02,
};

/**
 * @brief models an individual SCOM restore entry.
 */
typedef struct
{
    uint32_t    iv_scomAddress;
    uint64_t    iv_scomData;
} __attribute__((packed)) ScomEntry_t;

/**
 * @brief   describes details pertaining to SCOM entry
 */
typedef struct
{
    uint32_t    iv_subRegionBaseOffset;
    uint32_t    iv_subRegionLength;
    uint8_t     iv_slotFound;
    uint8_t     iv_lastEntryOffset;
    uint16_t    iv_entryOffset;
    uint8_t     iv_entryMatchOffset;
    uint8_t     iv_matchFound;
    uint8_t     iv_entryLimit;
    uint8_t     iv_reserved;
} ScomEntryDat_t;

/**
 * @brief summarizes attributes associated with a SPR register.
 */
typedef struct
{
    uint32_t iv_sprId;
    bool     iv_isThreadScope;
    uint32_t iv_saveMaskPos;
} StopSprReg_t;

/**
 * @brief   Misc constants.
 */
enum
{
    SIZE_SCOM_ENTRY         =   sizeof( ScomEntry_t ),
    SCOM_ENTRY_START        =   0xDEADDEAD,
    BAD_SAVE_MASK           =   0x007FF000,
    MAX_SPR_INDEX           =   31,
    TEST_BIT_PATTERN        =   0x80000000,
    EP_SELECT_MASK          =   0x000F0000,
    CORE_REGION_MASK        =   0x0000F000,
    SCOM_ENTRY_VALID        =   0x80000000,
    LAST_SCOM_ENTRY         =   0x40000000,
    SWIZZLE_LAST_SCOM_ENTRY =   0x00000040,
    SCOM_ADDR_MASK          =   0x0000FFFF,
    SCOM_ADDR_CHIPLET_MASK  =   0x000FFFFF,
    SCOM_ENTRY_VER          =   0x10000000, //Ver 1.0
    CORE_SECTION_ID_CODE    =   0x00000000, //Core Section Id 0
    L3_SECTION_ID_CODE      =   0x03000000, //L3 Section Id 3 b4:b7
    MAX_SCOM_ENTRY_POS      =   0x10,
    MIN_SUPERCHIPLET_ID     =   0x20,

};

#ifdef __DEBUG_
    #define MY_ERR( _fmt_, _args_...) printf( "\n"); printf( _fmt_, ##_args_)
    #define MY_INF(_fmt_, _args_...)  printf( "\n"); printf( _fmt_, ##_args_)
#else
    #define MY_ERR( _fmt_, _args_...)
    #define MY_INF(_fmt_, _args_...)
#endif

#ifdef __cplusplus
}  // extern "C"

} //namespace stopImageSection ends
#endif //__cplusplus

#endif
