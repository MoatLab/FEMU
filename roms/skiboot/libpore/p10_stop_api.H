/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/import/chips/p10/procedures/utils/stopreg/p10_stop_api.C $ */
/*                                                                        */
/* OpenPOWER HostBoot Project                                             */
/*                                                                        */
/* Contributors Listed Below - COPYRIGHT 2015,2021                        */
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
#ifndef __P10_STOP_IMAGE_API_
#define __P10_STOP_IMAGE_API_

#include <stdint.h>

#ifdef __SKIBOOT__
    #include <skiboot.h>
#endif

///
/// @file   p10_stop_api.H
/// @brief  describes STOP API which  create/manipulate STOP image.
///
// *HWP HW Owner    :  Greg Still <stillgs@us.ibm.com>
// *HWP FW Owner    :  Prem Shanker Jha <premjha2@in.ibm.com>
// *HWP Team        :  PM
// *HWP Level       :  2
// *HWP Consumed by :  HB:HYP

#ifdef __cplusplus
namespace stopImageSection
{
#endif

/**
 * @brief   all SPRs and MSR for which register restore is to be supported.
 * @note    STOP API design has built in support to accomodate 8 register of
 *          scope core and thread each.
 */
typedef enum
{
    PROC_STOP_SPR_DAWR    =    180,   // thread register
    PROC_STOP_SPR_CIABR   =    187,   // thread register
    PROC_STOP_SPR_DAWRX   =    188,   // thread register
    PROC_STOP_SPR_HSPRG0  =    304,   // thread register
    PROC_STOP_SPR_HRMOR   =    313,   // core register
    PROC_STOP_SPR_LPCR    =    318,   // thread register
    PROC_STOP_SPR_HMEER   =    337,   // core register
    PROC_STOP_SPR_PTCR    =    464,   // core register
    PROC_STOP_SPR_USPRG0  =    496,   // thread register
    PROC_STOP_SPR_USPRG1  =    497,   // thread register
    PROC_STOP_SPR_URMOR   =    505,   // core register
    PROC_STOP_SPR_SMFCTRL =    511,   // thread register
    PROC_STOP_SPR_LDBAR   =    850,   // thread register
    PROC_STOP_SPR_PSSCR   =    855,   // thread register
    PROC_STOP_SPR_PMCR    =    884,   // core register
    PROC_STOP_SPR_HID     =   1008,   // core register
    PROC_STOP_SPR_MSR     =   2000,   // thread register

} CpuReg_t;

/**
 * @brief lists all the bad error codes.
 */
typedef enum
{
    STOP_SAVE_SUCCESS                    =  0,
    STOP_SAVE_ARG_INVALID_IMG            =  1,
    STOP_SAVE_ARG_INVALID_REG            =  2,
    STOP_SAVE_ARG_INVALID_THREAD         =  3,
    STOP_SAVE_ARG_INVALID_MODE           =  4,
    STOP_SAVE_ARG_INVALID_CORE           =  5,
    STOP_SAVE_SPR_ENTRY_NOT_FOUND        =  6,
    STOP_SAVE_SPR_ENTRY_UPDATE_FAILED    =  7,
    STOP_SAVE_SCOM_INVALID_OPERATION     =  8,
    STOP_SAVE_SCOM_INVALID_SECTION       =  9,
    STOP_SAVE_SCOM_INVALID_ADDRESS       =  10,
    STOP_SAVE_SCOM_INVALID_CHIPLET       =  11,
    STOP_SAVE_SCOM_ENTRY_UPDATE_FAILED   =  12,
    STOP_SAVE_INVALID_FUSED_CORE_STATUS  =  13,
    STOP_SAVE_FAIL                       =  14,  // for internal failure within firmware.
    STOP_SAVE_SPR_ENTRY_MISSING          =  15,
    STOP_SAVE_MAX_ENTRY_REACHED          =  16,
    STOP_SAVE_SPR_BIT_POS_RESERVE        =  17,
} StopReturnCode_t;

/**
 * @brief summarizes all operations supported on scom entries of STOP image.
 */
typedef enum
{
    //enum members which are project agnostic
    PROC_STOP_SCOM_OP_MIN     =   0,
    PROC_STOP_SCOM_APPEND     =   1,
    PROC_STOP_SCOM_REPLACE    =   2,
    PROC_STOP_SCOM_OR         =   3,
    PROC_STOP_SCOM_AND        =   4,
    PROC_STOP_SCOM_NOOP       =   5,
    PROC_STOP_SCOM_RESET      =   6,
    PROC_STOP_SCOM_OR_APPEND  =   7,
    PROC_STOP_SCOM_AND_APPEND =   8,
    PROC_STOP_SCOM_OP_MAX     =   9,

} ScomOperation_t;

/**
 * @brief All subsections that contain scom entries in a STOP image.
 */
typedef enum
{
    PROC_STOP_SECTION_CORE      =   1,
    PROC_STOP_SECTION_L2        =   1,
    PROC_STOP_SECTION_L3        =   2,
    PROC_STOP_SECTION_CACHE     =   2,
} ScomSection_t;

/**
 * @brief   versions pertaining relvant to STOP API.
 */
typedef enum
{
    STOP_API_VER            =   0x00,
    STOP_API_VER_CONTROL    =   0x02,
} VersionList_t;

/**
 * @brief  Summarizes bit position allocated to SPRs in save bit mask vector.
 */
typedef enum
{
    BIT_POS_CIABR       =   0,
    BIT_POS_DAWR        =   1,
    BIT_POS_DAWRX       =   2,
    BIT_POS_HSPRG0      =   3,
    BIT_POS_LDBAR       =   4,
    BIT_POS_LPCR        =   5,
    BIT_POS_PSSCR       =   6,
    BIT_POS_MSR         =   7,
    BIT_POS_HID         =   21,
    BIT_POS_HMEER       =   22,
    BIT_POS_PMCR        =   23,
    BIT_POS_PTCR        =   24,
    BIT_POS_SMFCTRL     =   28,
    BIT_POS_USPRG0      =   29,
    BIT_POS_USPRG1      =   30,
} SprBitPositionList_t;


#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief   creates SCOM restore entry for a given scom adress in HOMER.
 * @param   i_pImage        points to start address of HOMER image.
 * @param   i_scomAddress   address associated with SCOM restore entry.
 * @param   i_scomData      data associated with SCOM restore entry.
 * @param   i_operation     operation type requested for API.
 * @param   i_section       section of HOMER in which restore entry needs to be created.
 * @return  STOP_SAVE_SUCCESS if API succeeds, error code otherwise.
 * @note    It is an API for creating SCOM restore entry in HOMER. It is agnostic to
 *          generation of POWER processor.
 */

StopReturnCode_t proc_stop_save_scom( void* const   i_pImage,
                                      const uint32_t i_scomAddress,
                                      const uint64_t i_scomData,
                                      const ScomOperation_t i_operation,
                                      const ScomSection_t i_section );

/**
 * @brief       initializes self save restore region of HOMER.
 * @param[in]   i_pImage    points to base of HOMER image.
 * @param[in]   i_corePos   position of the physical core.
 * @return      STOP_SAVE_SUCCESS if API succeeds, error code otherwise.
 * @note        It is an API for initializing self restore region in HOMER. It is agnostic to
 *              generation of POWER processor.
 */
StopReturnCode_t proc_stop_init_cpureg(  void* const i_pImage, const uint32_t i_corePos );

/**
 * @brief       enables self save for a given set of SPRs
 * @param[in]   i_pImage        points to start address of HOMER image.
 * @param[in]   i_pir           PIR value associated with core and thread.
 * @param[in]   i_saveRegVector bit vector representing the SPRs that needs to be self saved.
 * @return      STOP_SAVE_SUCCESS if API succeeds, error code otherwise.
 * @note        It is an API for enabling self save of SPRs  and it is agnostic to
 *              generation of POWER processor.
 */
StopReturnCode_t proc_stop_save_cpureg_control(  void* i_pImage,
        const uint64_t i_pir,
        const uint32_t i_saveRegVector );

/**
 * @brief       creates an SPR restore entry in HOMER
 * @param[in]   i_pImage        points to start address of HOMER image.
 * @param[in]   i_regId         SPR number to be saved in HOMER
 * @param[in]   i_regData       SPR data to be saved in HOMER
 * @param[in]   i_pir           PIR value associated with core and thread.
 * @return      STOP_SAVE_SUCCESS if API succeeds, error code otherwise.
 * @note        It is an API for enabling self save of SPRs  and it is agnostic to
 *              generation of POWER processor.
 */
StopReturnCode_t proc_stop_save_cpureg(  void* const i_pImage,
        const CpuReg_t  i_regId,
        const uint64_t  i_regData,
        const uint64_t  i_pir );

/**
 * @brief       initializes self-save region with specific instruction.
 * @param[in]   i_pImage    points to start address of HOMER image.
 * @param[in]   i_corePos   physical core's relative position within processor chip.
 * @return      STOP_SAVE_SUCCESS  if self-save is initialized successfully,
 *              error code otherwise.
 * @note        API is project agnostic and is intended only for use case of HOMER build.
 *              There is no explicit effort to support any other use case.
 */
StopReturnCode_t proc_stop_init_self_save(  void* const i_pImage, const uint32_t i_corePos );

#ifdef __cplusplus
} // extern "C"
};  // namespace stopImageSection ends
#endif //__cplusplus

#endif //__P10_STOP_IMAGE_API_
