/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/import/chips/p9/procedures/utils/stopreg/p9_stop_api.C $  */
/*                                                                        */
/* OpenPOWER HostBoot Project                                             */
/*                                                                        */
/* Contributors Listed Below - COPYRIGHT 2015,2018                        */
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
/// @file   p9_stop_api.C
/// @brief  implements STOP API which  create/manipulate STOP image.
///
// *HWP HW Owner    :  Greg Still <stillgs@us.ibm.com>
// *HWP FW Owner    :  Prem Shanker Jha <premjha2@in.ibm.com>
// *HWP Team        :  PM
// *HWP Level       :  2
// *HWP Consumed by :  HB:HYP

// *INDENT-OFF*
#ifdef PPC_HYP
    #include <HvPlicModule.H>
#endif

#include "p9_stop_api.H"
#include "p9_cpu_reg_restore_instruction.H"
#include "p9_stop_data_struct.H"
#include <string.h>
#include "p9_stop_util.H"
#ifdef __cplusplus
extern "C" {

namespace stopImageSection
{
#endif
// a true in the table below means register is of scope thread
// whereas a false meanse register is of scope core.

const StopSprReg_t g_sprRegister[] =
{
    { P9_STOP_SPR_CIABR,     true,  0  },
    { P9_STOP_SPR_DAWR,      true,  1  },
    { P9_STOP_SPR_DAWRX,     true,  2  },
    { P9_STOP_SPR_HSPRG0,    true,  3  },
    { P9_STOP_SPR_LDBAR,     true,  4, },
    { P9_STOP_SPR_LPCR,      true,  5  },
    { P9_STOP_SPR_PSSCR,     true,  6  },
    { P9_STOP_SPR_MSR,       true,  7  },
    { P9_STOP_SPR_HRMOR,     false, 20 },
    { P9_STOP_SPR_HID,       false, 21 },
    { P9_STOP_SPR_HMEER,     false, 22 },
    { P9_STOP_SPR_PMCR,      false, 23 },
    { P9_STOP_SPR_PTCR,      false, 24 },
    { P9_STOP_SPR_SMFCTRL,   true,  28 },
    { P9_STOP_SPR_USPRG0,    true,  29 },
    { P9_STOP_SPR_USPRG1,    true,  30 },
    { P9_STOP_SPR_URMOR,     false, 31 },
};

const uint32_t MAX_SPR_SUPPORTED =  17;
const uint32_t LEGACY_CORE_SCOM_SUPPORTED   =   15;
const uint32_t LEGACY_QUAD_SCOM_SUPPORTED   =   63;

//-----------------------------------------------------------------------------

/**
 * @brief       vaildated input arguments passed to p9_stop_save_cpureg_control.
 * @param[in]   i_pImage            point to start of HOMER
 * @param[in]   i_coreId            id of the core
 * @param[in]   i_threadId          id of the thread
 * @param[in]   i_saveMaskVector    SPR save bit mask vector
 * @return      STOP_SAVE_SUCCESS if function succeeds, error code otherwise.
 */
STATIC StopReturnCode_t validateArgumentSaveRegMask( void* const i_pImage,
        uint32_t const i_coreId,
        uint32_t const i_threadId,
        uint64_t i_saveMaskVector )
{
    StopReturnCode_t l_rc   =   STOP_SAVE_SUCCESS;

    do
    {
        if( !i_pImage )
        {
            l_rc    =   STOP_SAVE_ARG_INVALID_IMG;
            break;
        }

        if( i_coreId > MAX_CORE_ID_SUPPORTED )
        {
            l_rc    =   STOP_SAVE_ARG_INVALID_CORE;
            break;
        }

        if( i_threadId > MAX_THREAD_ID_SUPPORTED )
        {
            l_rc    =   STOP_SAVE_ARG_INVALID_THREAD;
            break;
        }

        if( ( 0 == i_saveMaskVector ) || ( BAD_SAVE_MASK & i_saveMaskVector ) )
        {
            l_rc    =  STOP_SAVE_ARG_INVALID_REG;
            break;
        }

    }
    while(0);

    return l_rc;
}

//-----------------------------------------------------------------------------

/**
 * @brief   validates input arguments provided by STOP API caller.
 * @param[in]       i_pImage    pointer to beginning of chip's HOMER image.
 * @param[in]       i_regId             SPR register id
 * @param[in]       i_coreId            core id
 * @param[in|out]   i_pThreadId         points to thread id
 * @param[in|out]   i_pThreadLevelReg   points to scope information of SPR
 * @return  STOP_SAVE_SUCCESS if arguments found valid, error code otherwise.
 * @note    for register of scope core, function shall force io_threadId to
 *          zero.
 */
STATIC StopReturnCode_t validateSprImageInputs( void*   const i_pImage,
        const CpuReg_t i_regId,
        const uint32_t  i_coreId,
        uint32_t*     i_pThreadId,
        bool* i_pThreadLevelReg )
{
    uint32_t index = 0;
    StopReturnCode_t l_rc = STOP_SAVE_SUCCESS;
    bool sprSupported = false;
    *i_pThreadLevelReg = false;

    do
    {
        if( NULL == i_pImage )
        {
            // Error: HOMER image start location is not valid
            // Cannot proceed further. So, let us exit.
            l_rc = STOP_SAVE_ARG_INVALID_IMG;
            MY_ERR( "invalid image location " );

            break;
        }

        // STOP API manages STOP image based on physical core Id. PIR value
        // is interpreted to calculate the physical core number and virtual
        // thread number.
        if( MAX_CORE_ID_SUPPORTED < i_coreId )
        {
            // Error: invalid core number. given core number exceeds maximum
            // cores supported by chip.

            // Physical core number is calculated based on following formula:
            // core id = 4 * quad id (0..5) + core no within quad ( 0..3)
            l_rc = STOP_SAVE_ARG_INVALID_CORE;
            MY_ERR( "invalid core id " );
            break;
        }

        if( MAX_THREAD_ID_SUPPORTED < *i_pThreadId )
        {
            //Error: invalid core thread. Given core thread exceeds maximum
            //threads supported in a core.

            // 64 bit PIR value is interpreted to calculate virtual thread
            // Id. In fuse mode, b61 and b62 gives virtual thread id whereas in
            // non fuse mode, b62 and b63 is read to determine the same.

            l_rc = STOP_SAVE_ARG_INVALID_THREAD;
            MY_ERR( "invalid thread " );
            break;
        }

        for( index = 0; index < MAX_SPR_SUPPORTED; ++index )
        {
            if( i_regId == (CpuReg_t )g_sprRegister[index].iv_sprId )
            {
                // given register is in the list of register supported
                sprSupported = true;
                *i_pThreadLevelReg = g_sprRegister[index].iv_isThreadScope;
                *i_pThreadId = *i_pThreadLevelReg ? *i_pThreadId : 0;
                break;
            }
        }

        if( !sprSupported )
        {
            // Following SPRs are supported
            // trace out all registers supported
            MY_ERR("Register not supported" );
            // error code to caller.
            l_rc = STOP_SAVE_ARG_INVALID_REG;
            break;
        }

    }
    while(0);

    if( l_rc )
    {
        MY_ERR( "image 0x%08x, regId %08d, coreId %d, "
                "threadId %d return code 0x%08x", i_pImage, i_regId,
                i_coreId, *i_pThreadId, l_rc  );
    }

    return l_rc;
}

//-----------------------------------------------------------------------------

/**
 * @brief generates ori instruction code.
 * @param[in]   i_Rs    Source register number
 * @param[in]   i_Ra    destination register number
 * @param[in]   i_data  16 bit immediate data
 * @return  returns 32 bit number representing ori instruction.
 */
STATIC uint32_t getOriInstruction( const uint16_t i_Rs, const uint16_t i_Ra,
                                   const uint16_t i_data )
{
    uint32_t oriInstOpcode = 0;
    oriInstOpcode = 0;
    oriInstOpcode = ORI_OPCODE << 26;
    oriInstOpcode |= i_Rs << 21;
    oriInstOpcode |= i_Ra << 16;
    oriInstOpcode |= i_data;

    return SWIZZLE_4_BYTE(oriInstOpcode);
}

//-----------------------------------------------------------------------------

/**
 * @brief generates 32 bit key used for SPR lookup in core section.
 */
STATIC uint32_t genKeyForSprLookup( const CpuReg_t i_regId )
{
    return getOriInstruction( 0, 0, (uint16_t) i_regId );
}

//-----------------------------------------------------------------------------

/**
 * @brief generates xor instruction code.
 * @param[in] i_Rs  source register number for xor operation
 * @param[in] i_Ra  destination register number for xor operation result
 * @param[in] i_Rb source register number for xor operation
 * @return returns 32 bit number representing xor  immediate instruction.
 */
STATIC uint32_t getXorInstruction( const uint16_t i_Ra, const uint16_t i_Rs,
                                   const uint16_t i_Rb )
{
    uint32_t xorRegInstOpcode;
    xorRegInstOpcode = XOR_CONST << 1;
    xorRegInstOpcode |= OPCODE_31 << 26;
    xorRegInstOpcode |= i_Rs << 21;
    xorRegInstOpcode |= i_Ra << 16;
    xorRegInstOpcode |= i_Rb << 11;

    return SWIZZLE_4_BYTE(xorRegInstOpcode);
}

//-----------------------------------------------------------------------------

/**
 * @brief generates oris instruction code.
 * @param[in] i_Rs      source register number
 * @param[in] i_Ra      destination register number
 * @param[in] i_data    16 bit immediate data
 * @return returns 32 bit number representing oris  immediate instruction.
 */
STATIC uint32_t getOrisInstruction( const uint16_t i_Rs, const uint16_t i_Ra,
                                    const uint16_t i_data )
{
    uint32_t orisInstOpcode;
    orisInstOpcode = 0;
    orisInstOpcode = ORIS_OPCODE << 26;
    orisInstOpcode |= ( i_Rs & 0x001F ) << 21 | ( i_Ra & 0x001F ) << 16;
    orisInstOpcode |= i_data;

    return SWIZZLE_4_BYTE(orisInstOpcode);
}

//-----------------------------------------------------------------------------

/**
 * @brief generates instruction for mtspr
 * @param[in] i_Rs      source register number
 * @param[in] i_Spr represents spr where data is to be moved.
 * @return returns 32 bit number representing mtspr instruction.
 */
STATIC uint32_t getMtsprInstruction( const uint16_t i_Rs, const uint16_t i_Spr )
{
    uint32_t mtsprInstOpcode = 0;
    uint32_t temp = (( i_Spr & 0x03FF ) << 11);
    mtsprInstOpcode = (uint8_t)i_Rs << 21;
    mtsprInstOpcode |= ( temp  & 0x0000F800 ) << 5;
    mtsprInstOpcode |= ( temp & 0x001F0000 ) >> 5;
    mtsprInstOpcode |= MTSPR_BASE_OPCODE;

    return SWIZZLE_4_BYTE(mtsprInstOpcode);
}

//-----------------------------------------------------------------------------

/**
 * @brief generates instruction for mfmsr
 * @param[in]   i_Rt    target register for SPR content.
 * @return  returns 32 bit number representing mfmsr instruction.
 */
STATIC uint32_t getMfmsrInstruction( const uint16_t i_Rt )
{
    uint32_t mfmsrInstOpcode  = ((OPCODE_31 << 26) | (i_Rt << 21) | (MFMSR_CONST));

    return SWIZZLE_4_BYTE(mfmsrInstOpcode);
}

//-----------------------------------------------------------------------------

/**
 * @brief generates rldicr instruction.
 * @param[in] i_Rs      source register number
 * @param[in] i_Ra      destination register number
 * @param[in] i_sh      bit position by which contents of i_Rs are to be shifted
 * @param[in] i_me      bit position up to which mask should be 1.
 * @return returns 32 bit number representing rldicr instruction.
 */
STATIC uint32_t getRldicrInstruction( const uint16_t i_Ra, const uint16_t i_Rs,
                                      const uint16_t i_sh, uint16_t i_me )
{
    uint32_t rldicrInstOpcode = 0;
    rldicrInstOpcode = ((RLDICR_OPCODE << 26 ) | ( i_Rs << 21 ) | ( i_Ra << 16 ));
    rldicrInstOpcode |= ( ( i_sh & 0x001F ) << 11 ) | (RLDICR_CONST << 2 );
    rldicrInstOpcode |= (( i_sh & 0x0020 ) >> 4);
    rldicrInstOpcode |= (i_me & 0x001F ) << 6;
    rldicrInstOpcode |= (i_me & 0x0020 );
    return SWIZZLE_4_BYTE(rldicrInstOpcode);
}

//-----------------------------------------------------------------------------

STATIC uint32_t getMfsprInstruction( const uint16_t i_Rt, const uint16_t i_sprNum )
{
    uint32_t mfsprInstOpcode    =   0;
    mfsprInstOpcode =  (( OPCODE_31 << 26 ) | ( i_Rt << 21 ) | ( i_sprNum << 11 ) | ( MFSPR_CONST << 1 ));
    return SWIZZLE_4_BYTE(mfsprInstOpcode);
}

//-----------------------------------------------------------------------------

STATIC uint32_t getBranchLinkRegInstruction(void)
{
    uint32_t branchConstInstOpcode  =   0;
    branchConstInstOpcode   =   (( OPCODE_18 << 26 ) | ( SELF_SAVE_FUNC_ADD ) | 0x03 );

    return SWIZZLE_4_BYTE(branchConstInstOpcode);
}
//-----------------------------------------------------------------------------

/**
 * @brief looks up entry for given SPR in given thread/core section.
 * @param[in]   i_pThreadSectLoc    start of given thread section or core section.
 * @param[in]   i_lookUpKey         search key for lookup of given SPR entry.
 * @param[in]   i_isThreadReg       true if register is of scope thread, false
 *                                  otherwise.
 * @param[in|out] io_pSprEntryLoc   Input:  NULL
 *                                  Output: location of given entry or end of table.
 * @return      STOP_SAVE_SUCCESS if entry is found, STOP_SAVE_FAIL in case of
 *              an error.
 */
STATIC StopReturnCode_t lookUpSprInImage( uint32_t* i_pThreadSectLoc, const uint32_t i_lookUpKey,
                                          const bool i_isThreadReg, void** io_pSprEntryLoc,
                                          uint8_t i_selfRestVer )
{
    StopReturnCode_t l_rc       =   STOP_SAVE_FAIL;
    uint32_t temp               =   0;
    uint32_t* i_threadSectEnd   =   NULL;
    uint32_t bctr_inst          =   SWIZZLE_4_BYTE(BLR_INST);
    *io_pSprEntryLoc            =   NULL;

    do
    {
        if( !i_pThreadSectLoc )
        {
            MY_ERR( "Bad SPR Start Location" );
            break;
        }

        if( i_selfRestVer )
        {
            temp    =   i_isThreadReg ? (uint32_t)(SMF_CORE_RESTORE_THREAD_AREA_SIZE) :
                                        (uint32_t)(SMF_CORE_RESTORE_CORE_AREA_SIZE);

        }
        else
        {
            temp    =   i_isThreadReg ? (uint32_t)(CORE_RESTORE_THREAD_AREA_SIZE) :
                                        (uint32_t)(CORE_RESTORE_CORE_AREA_SIZE);
        }


        i_threadSectEnd             =   i_pThreadSectLoc + ( temp >> 2 );

        temp = 0;

        while( ( i_pThreadSectLoc <= i_threadSectEnd ) &&
               ( temp != bctr_inst ) )
        {
            temp = *i_pThreadSectLoc;

            if( ( temp == i_lookUpKey ) || ( temp == bctr_inst ) )
            {
                *io_pSprEntryLoc = i_pThreadSectLoc;
                l_rc = STOP_SAVE_SUCCESS;
                break;
            }

            i_pThreadSectLoc = i_pThreadSectLoc + SIZE_PER_SPR_RESTORE_INST;
        }
    }
    while(0);

    return l_rc;
}

//-----------------------------------------------------------------------------

/**
 * @brief updates an SPR STOP image entry.
 * @param[in] i_pSprEntryLocation location of entry.
 * @param[in] i_regId       register Id associated with SPR.
 * @param[in] i_regData     data needs to be written to SPR entry.
 * @return    STOP_SAVE_SUCCESS if update works, STOP_SAVE_FAIL otherwise.
 */
STATIC StopReturnCode_t updateSprEntryInImage( uint32_t* i_pSprEntryLocation,
        const CpuReg_t i_regId,
        const uint64_t i_regData,
        const enum SprEntryUpdateMode i_mode
                                             )
{
    StopReturnCode_t l_rc = STOP_SAVE_SUCCESS;
    uint32_t tempInst       =   0;
    uint64_t tempRegData    =   0;
    bool newEntry           =   true;
    uint16_t regRs          =   0; //to use R0 for SPR restore insruction generation
    uint16_t regRa          =   0;

    do
    {
        if( !i_pSprEntryLocation )
        {
            MY_ERR("invalid location of SPR image entry" );
            l_rc = STOP_SAVE_FAIL;
            break;
        }

        tempInst = genKeyForSprLookup( i_regId );

        if( *i_pSprEntryLocation == tempInst )
        {
            newEntry = false;
        }

        //Add SPR search instruction i.e. "ori r0, r0, SPRID"
        *i_pSprEntryLocation = tempInst;
        i_pSprEntryLocation += SIZE_PER_SPR_RESTORE_INST;

        if( INIT_SPR_REGION  == i_mode )
        {
            //adding inst 'b . + 0x1C'
            *i_pSprEntryLocation = SWIZZLE_4_BYTE(SKIP_SPR_REST_INST);
        }
        else
        {
            //clear R0 i.e. "xor ra, rs, rb"
            tempInst = getXorInstruction( regRs, regRs, regRs );
            *i_pSprEntryLocation = tempInst;
        }


        i_pSprEntryLocation += SIZE_PER_SPR_RESTORE_INST;

        tempRegData = i_regData >> 48;
        //get lower order 16 bits of SPR restore value in R0
        tempInst = getOrisInstruction( regRs, regRa, (uint16_t)tempRegData );
        *i_pSprEntryLocation = tempInst;
        i_pSprEntryLocation += SIZE_PER_SPR_RESTORE_INST;

        tempRegData = ((i_regData >> 32) & 0x0000FFFF );
        //get bit b16-b31 of SPR restore value in R0
        tempInst = getOriInstruction( regRs, regRa, (uint16_t)tempRegData );
        *i_pSprEntryLocation = tempInst;
        i_pSprEntryLocation += SIZE_PER_SPR_RESTORE_INST;

        //Rotate R0 to left by  32 bit position and zero lower order 32 bits.
        //Place the result in R0
        tempInst = getRldicrInstruction(regRa, regRs, 32, 31);
        *i_pSprEntryLocation = tempInst;
        i_pSprEntryLocation += SIZE_PER_SPR_RESTORE_INST;

        tempRegData = ((i_regData >> 16) & 0x000000FFFF );
        //get bit b32-b47 of SPR restore value to R0
        tempInst = getOrisInstruction( regRs, regRa, (uint16_t)tempRegData );
        *i_pSprEntryLocation = tempInst;
        i_pSprEntryLocation += SIZE_PER_SPR_RESTORE_INST;

        tempRegData = (uint16_t)i_regData;
        //get bit b48-b63 of SPR restore value to R0
        tempInst = getOriInstruction( regRs, regRa, (uint16_t)i_regData );
        *i_pSprEntryLocation = tempInst;
        i_pSprEntryLocation += SIZE_PER_SPR_RESTORE_INST;

        if( P9_STOP_SPR_MSR == i_regId )
        {
            //MSR cannot be restored completely with mtmsrd instruction.
            //as it does not update ME, LE and HV bits. In self restore code
            //inorder to restore MSR, contents of R21 is moved to SRR1. It also
            //executes an RFID which causes contents of SRR1 to be copied to
            //MSR. This allows copy of LE bit which are specifically interested
            //in. Instruction below moves contents of MSR Value (in R0 ) to R21.
            tempInst = SWIZZLE_4_BYTE( MR_R0_TO_R21 );
        }
        else if ( P9_STOP_SPR_HRMOR == i_regId )
        {
            //Case HRMOR, move contents of R0 to a placeholder GPR (R10)
            //Thread Launcher expects HRMOR value in R10
            tempInst = SWIZZLE_4_BYTE( MR_R0_TO_R10 );
        }
        else if( P9_STOP_SPR_URMOR == i_regId )
        {
            //Case URMOR, move contents of R0 to a placeholder GPR (R9)
            //Thread Launcher expects URMOR value in R9
            tempInst = SWIZZLE_4_BYTE( MR_R0_TO_R9 );
        }
        else
        {
            // Case other SPRs, move contents of R0 to SPR
            // For a UV system, even HRMOR is treated like any other SPR.
            tempInst =
                getMtsprInstruction( 0, (uint16_t)i_regId );
        }

        *i_pSprEntryLocation = tempInst;

        if( newEntry )
        {
            i_pSprEntryLocation += SIZE_PER_SPR_RESTORE_INST;
            //at the end of SPR restore, add instruction BLR to go back to thread
            //launcher.
            tempInst = SWIZZLE_4_BYTE(BLR_INST);
            *i_pSprEntryLocation = tempInst;
        }
    }
    while(0);

    return l_rc;
}

//-----------------------------------------------------------------------------

STATIC StopReturnCode_t initSelfSaveEntry( void* const i_pImage, uint16_t i_sprNum )
{
    StopReturnCode_t l_rc   =   STOP_SAVE_SUCCESS;
    uint32_t* i_pSprSave    =   (uint32_t*)i_pImage;

    //ori r0, r0, 0x00nn
    *i_pSprSave         =   getOriInstruction( 0, 0, i_sprNum );

    i_pSprSave++;

    //addi r31, r31, 0x20
    *i_pSprSave         =   SWIZZLE_4_BYTE(SKIP_SPR_SELF_SAVE);
    i_pSprSave++;

    //nop
    *i_pSprSave         =   getOriInstruction( 0, 0, 0 );;
    i_pSprSave++;

    //mtlr, r30
    *i_pSprSave         =   SWIZZLE_4_BYTE( MTLR_INST );
    i_pSprSave++;

    //blr
    *i_pSprSave         =   SWIZZLE_4_BYTE(BLR_INST);
    i_pSprSave++;

    return l_rc;
}

//-----------------------------------------------------------------------------

STATIC StopReturnCode_t getSprRegIndexAdjustment( const uint32_t i_saveMaskPos, uint32_t* i_sprAdjIndex )
{
    StopReturnCode_t l_rc = STOP_SAVE_SUCCESS;

    do
    {
        if( (( i_saveMaskPos >= SPR_BIT_POS_8 ) && ( i_saveMaskPos <= SPR_BIT_POS_19 )) ||
            (( i_saveMaskPos >= SPR_BIT_POS_25 ) && ( i_saveMaskPos <= SPR_BIT_POS_27 )) )
        {
            l_rc = STOP_SAVE_SPR_BIT_POS_RESERVE;
            break;
        }

        if( (i_saveMaskPos > SPR_BIT_POS_19) && (i_saveMaskPos < SPR_BIT_POS_25 ) )
        {
            *i_sprAdjIndex    =   12;
        }
        else if( i_saveMaskPos > SPR_BIT_POS_27 )
        {
            *i_sprAdjIndex    =   15;
        }
        else
        {
            *i_sprAdjIndex   =   0;
        }

    }
    while(0);

    return l_rc;
}
//-----------------------------------------------------------------------------
StopReturnCode_t p9_stop_save_cpureg(  void* const i_pImage,
                                       const CpuReg_t  i_regId,
                                       const uint64_t  i_regData,
                                       const uint64_t  i_pir )
{
    StopReturnCode_t l_rc = STOP_SAVE_SUCCESS;    // procedure return code
    HomerSection_t*     chipHomer       =    NULL;
    SmfHomerSection_t*  smfChipHomer    =    NULL;

    do
    {
        uint32_t threadId       =   0;
        uint32_t coreId         =   0;
        uint32_t lookUpKey      =   0;
        void* pSprEntryLocation =   NULL;   // an offset w.r.t. to start of image
        void* pThreadLocation   =   NULL;
        bool threadScopeReg     =   false;
        uint8_t l_urmorFix      =   false;
        uint64_t  l_sprValue    =   0;
        uint8_t l_selfRestVer   =   0;

        MY_INF(">> p9_stop_save_cpureg" );

        l_rc = getCoreAndThread( i_pImage, i_pir, &coreId, &threadId );

        if( l_rc )
        {
            MY_ERR("Failed to determine Core Id and Thread Id from PIR 0x%016llx",
                   i_pir);
            break;
        }

        MY_INF( " PIR 0x%016llx coreId %d threadid %d "
                " registerId %d", i_pir, coreId,
                threadId, i_regId );

        // First of all let us validate all input arguments.
        l_rc =  validateSprImageInputs( i_pImage,
                                        i_regId,
                                        coreId,
                                        &threadId,
                                        &threadScopeReg );

        if( l_rc )
        {
            // Error: bad argument traces out error code
            MY_ERR("Bad input argument rc %d", l_rc );

            break;
        }

        l_urmorFix      =   *(uint8_t*)((uint8_t*)i_pImage + CPMR_HOMER_OFFSET + CPMR_URMOR_FIX_BYTE);
        l_selfRestVer   =   *(uint8_t *)((uint8_t *)i_pImage + CPMR_HOMER_OFFSET + CPMR_SELF_RESTORE_VER_BYTE );

        if( l_selfRestVer )
        {
            smfChipHomer = ( SmfHomerSection_t*)i_pImage;

            if( threadScopeReg )
            {
                pThreadLocation =
                    &(smfChipHomer->iv_coreThreadRestore[coreId].iv_threadRestoreArea[threadId][0]);
            }
            else
            {
                pThreadLocation =
                    &(smfChipHomer->iv_coreThreadRestore[coreId].iv_coreRestoreArea[0]);
            }
        }
        else    //Old fips or OPAL release that doesn't support SMF
        {
            chipHomer = (HomerSection_t*)i_pImage;

            if( threadScopeReg )
            {
                pThreadLocation =
                    &(chipHomer->iv_coreThreadRestore[coreId][threadId].iv_threadArea[0]);
            }
            else
            {
                pThreadLocation =
                    &(chipHomer->iv_coreThreadRestore[coreId][threadId].iv_coreArea[0]);
            }
        }

        if( ( SWIZZLE_4_BYTE(BLR_INST) == *(uint32_t*)pThreadLocation ) ||
            ( SWIZZLE_4_BYTE(ATTN_OPCODE) == *(uint32_t*) pThreadLocation ) )
        {
            // table for given core id doesn't exit. It needs to be
            // defined.
            pSprEntryLocation = pThreadLocation;
        }
        else
        {
            // an SPR restore section for given core already exists
            lookUpKey = genKeyForSprLookup( i_regId );
            l_rc = lookUpSprInImage( (uint32_t*)pThreadLocation,
                                     lookUpKey,
                                     threadScopeReg,
                                     &pSprEntryLocation,
                                     l_selfRestVer );
        }

        if( l_rc )
        {
            MY_ERR("Invalid or corrupt SPR entry. CoreId 0x%08x threadId ",
                   "0x%08x regId 0x%08x lookUpKey 0x%08x pThreadLocation 0x%08x"
                   , coreId, threadId, i_regId, lookUpKey, pThreadLocation );
            break;
        }

        if( ( P9_STOP_SPR_URMOR == i_regId ) && ( l_urmorFix ) )
        {
            l_sprValue  =  i_regData - URMOR_CORRECTION;
        }
        else
        {
            l_sprValue  =  i_regData;
        }

        l_rc = updateSprEntryInImage( (uint32_t*) pSprEntryLocation,
                                      i_regId,
                                      l_sprValue,
                                      UPDATE_SPR_ENTRY );

        if( l_rc )
        {
            MY_ERR( " Failed to update the SPR entry of PIR 0x%08x reg"
                    "0x%08x", i_pir, i_regId );
            break;
        }

    }
    while(0);

    MY_INF("<< p9_stop_save_cpureg" );
    return l_rc;
}

//-----------------------------------------------------------------------------

/**
 * @brief validates all the input arguments.
 * @param[in]   i_pImage       pointer to start of HOMER of image for proc chip.
 * @param[in]   i_scomAddress SCOM address of register.
 * @param[in]   i_chipletId   core or cache chiplet id
 * @param[in]   i_operation   operation requested for SCOM entry.
 * @param[in]   i_section     image section on which operation is to be performed
 * @return      STOP_SAVE_SUCCESS if arguments found valid, error code otherwise.
 * @note        Function does not validate that the given SCOM address really
 *              belongs to the given section.
 */
STATIC StopReturnCode_t validateScomImageInputs( void* const i_pImage,
        const uint32_t i_scomAddress,
        const uint8_t i_chipletId,
        const ScomOperation_t i_operation,
        const ScomSection_t i_section )
{
    StopReturnCode_t l_rc = STOP_SAVE_SUCCESS;

    do
    {
        if( !i_pImage )
        {
            //Error Invalid image pointer
            l_rc = STOP_SAVE_ARG_INVALID_IMG;
            MY_ERR("invalid image location ");
            break;
        }

        if( 0 == i_scomAddress )
        {
            l_rc = STOP_SAVE_SCOM_INVALID_ADDRESS;
            MY_ERR("invalid SCOM address");
            break;
        }

        if(( CACHE_CHIPLET_ID_MIN > i_chipletId ) ||
           ( CORE_CHIPLET_ID_MAX < i_chipletId ))
        {
            l_rc = STOP_SAVE_SCOM_INVALID_CHIPLET;
            MY_ERR("chiplet id not in range");
            break;
        }

        if(( CORE_CHIPLET_ID_MIN >  i_chipletId ) &&
           ( CACHE_CHIPLET_ID_MAX < i_chipletId ))
        {
            l_rc = STOP_SAVE_SCOM_INVALID_CHIPLET;
            MY_ERR("chiplet id not valid");
            break;
        }

        if(( P9_STOP_SCOM_OP_MIN >= i_operation ) ||
           ( P9_STOP_SCOM_OP_MAX <= i_operation ))
        {
            //invalid SCOM image operation requested
            l_rc = STOP_SAVE_SCOM_INVALID_OPERATION;
            MY_ERR("invalid SCOM image operation");
            break;
        }

        if(( P9_STOP_SECTION_MIN >= i_section ) ||
           ( P9_STOP_SECTION_MAX <= i_section ))
        {
            // invalid cache sub section specified
            l_rc = STOP_SAVE_SCOM_INVALID_SECTION;
            MY_ERR("invalid section");
            break;
        }

        if(( i_operation == P9_STOP_SCOM_RESET ) &&
           ( i_chipletId <  CORE_CHIPLET_ID_MIN ))
        {
            // replace requested with a cache chiplet Id
            l_rc = STOP_SAVE_SCOM_INVALID_OPERATION;
            MY_ERR( "reset not supported for cache. chiplet Id 0x%08x",
                    i_chipletId );
            break;
        }

    }
    while(0);

    if( l_rc )
    {
        MY_ERR("image 0x%08x SCOMAddress 0x%08x chipletId 0x%08x operation"
               "0x%08x section 0x%08x", i_pImage, i_scomAddress, i_chipletId,
               i_operation, i_section );
    }

    return l_rc;
}

//-----------------------------------------------------------------------------

/**
 * @brief   edit SCOM entry associated with the given core.
 * @param[in]   i_scomAddr       SCOM address of register.
 * @param[in]   i_scomData      data associated with SCOM register.
 * @param[in]   i_pEntryLocation points to a SCOM entry in HOMER image.
 * @param[in]   i_operation     operation to be performed on SCOM entry.
 * @return      STOP_SAVE_SUCCESS if existing entry is updated, STOP_SAVE_FAIL
 *              otherwise.
 */
STATIC StopReturnCode_t editScomEntry( uint32_t i_scomAddr, uint64_t i_scomData,
                                       ScomEntry_t* i_pEntryLocation,
                                       uint32_t i_operation )
{
    StopReturnCode_t l_rc = STOP_SAVE_SUCCESS;

    do
    {
        if( !i_pEntryLocation )
        {
            //Error: location of SCOM entry is not known
            //therefore no point moving forward
            MY_ERR("SCOM entry location not valid");
            l_rc = STOP_SAVE_FAIL;
            break;
        }

        switch( i_operation )
        {
            case P9_STOP_SCOM_OR:
                i_pEntryLocation->scomEntryData |= i_scomData;
                break;

            case P9_STOP_SCOM_AND:
                i_pEntryLocation->scomEntryData &= i_scomData;
                break;

            case P9_STOP_SCOM_NOOP:
                {
                    uint32_t nopInst = getOriInstruction( 0, 0, 0 );
                    i_pEntryLocation->scomEntryHeader   =   SWIZZLE_4_BYTE(SCOM_ENTRY_START);
                    i_pEntryLocation->scomEntryData     =   nopInst;
                    i_pEntryLocation->scomEntryAddress  =   nopInst;
                }
                break;

            case P9_STOP_SCOM_APPEND:
                i_pEntryLocation->scomEntryHeader       =   SWIZZLE_4_BYTE(SCOM_ENTRY_START);
                i_pEntryLocation->scomEntryData         =   i_scomData;
                i_pEntryLocation->scomEntryAddress      =   i_scomAddr;
                break;
        }

    }
    while(0);

    return l_rc;
}

//-----------------------------------------------------------------------------

/**
 * @brief   update SCOM entry associated with the given core.
 * @param[in]   i_scomAddr   SCOM address of register.
 * @param[in]   i_scomData   data associated with SCOM register.
 * @param[in]   i_scomEntry  points to a SCOM entry in cache section of HOMER image.
 * @return      STOP_SAVE_SUCCESS if new  entry is added, STOP_SAVE_FAIL otherwise.
 * @note        adds an entry at a given location. It can be used to add entry in
 *              place of NOP, at the end of table or as first entry of the cache
 *              sub-section(L2, L3 or EQ ).
 */
STATIC StopReturnCode_t updateScomEntry( uint32_t i_scomAddr, uint64_t i_scomData,
        ScomEntry_t* i_scomEntry   )
{
    StopReturnCode_t l_rc = STOP_SAVE_SUCCESS;

    do
    {
        if( !i_scomEntry )
        {
            MY_ERR( "cache entry cannot be located");
            l_rc = STOP_SAVE_SCOM_ENTRY_UPDATE_FAILED;
            break;
        }

        i_scomEntry->scomEntryHeader    =   SWIZZLE_4_BYTE(SCOM_ENTRY_START); // done for now
        i_scomEntry->scomEntryAddress   =   i_scomAddr;
        i_scomEntry->scomEntryData      =   i_scomData;

    }
    while(0);

    return l_rc;
}

//-----------------------------------------------------------------------------
/**
 * @brief populates SCOM restore entry header with version and layout info.
 * @param[in]   i_scomEntry     points to SCOM restore entry
 * @param[in]   i_imageVer      SGPE image version
 * @param[in]   i_maxScomEntry  max SCOM entries supported
 */

STATIC void updateEntryHeader( ScomEntry_t* i_scomEntry ,
                               uint32_t i_imageVer,
                               uint32_t i_maxScomEntry )
{
    uint32_t l_temp = 0;

    if( i_imageVer >= STOP_API_VER_CONTROL )
    {
        l_temp = ( 0x000000ff & i_maxScomEntry );
        l_temp |= ( STOP_API_VER  & 0x7 ) << 28;
        i_scomEntry->scomEntryHeader = SWIZZLE_4_BYTE(l_temp);

        MY_INF("SCOM Restore Header 0x%08x", l_temp );
    }
}

//-----------------------------------------------------------------------------

StopReturnCode_t p9_stop_save_scom( void* const   i_pImage,
                                    const uint32_t i_scomAddress,
                                    const uint64_t i_scomData,
                                    const ScomOperation_t i_operation,
                                    const ScomSection_t i_section )
{
    StopReturnCode_t l_rc = STOP_SAVE_SUCCESS;
    uint32_t entryLimit =   0;
    uint8_t chipletId   =   0;
    uint32_t nopInst    =   0;
    uint32_t index      =   0;
    uint32_t imageVer   =   0;
    uint32_t entrySwzHeader = 0;
    uint32_t l_maxScomRestoreEntry = 0;
    ScomEntry_t* pScomEntry      =  NULL;
    ScomEntry_t* pEntryLocation  =  NULL;
    ScomEntry_t* pNopLocation    =  NULL;
    ScomEntry_t* pEditScomHeader =  NULL;
    StopCacheSection_t* pStopCacheScomStart =   NULL;
    ScomEntry_t* pTableEndLocationtable     =   NULL;
    uint32_t swizzleAddr;
    uint64_t swizzleData;
    uint32_t swizzleAttn;
    uint32_t swizzleBlr     =   SWIZZLE_4_BYTE(BLR_INST);
    bool     cacheEntry     =   true;

    MY_INF(">> p9_stop_save_scom");

    //Reads SGPE image version info from QPMR Header in HOMER
    //For backward compatibility, for base version of SGPE Hcode,
    //STOP API retains default behavior but adds version specific
    //details in each entry in later versions.
    imageVer       =  *(uint32_t*)((uint8_t*)i_pImage + QPMR_HOMER_OFFSET + QPMR_BUILD_VER_BYTE);
    imageVer       =  SWIZZLE_4_BYTE(imageVer);


    do
    {
        chipletId   =   i_scomAddress >> 24;
        chipletId   =   chipletId & 0x3F;

        l_rc        =   validateScomImageInputs( i_pImage, i_scomAddress, chipletId, i_operation, i_section );

        if( l_rc )
        {
            MY_ERR( "invalid argument: aborting");
            break;
        }

        if( chipletId >= CORE_CHIPLET_ID_MIN )
        {
            // chiplet is core. So, let us find the start address of SCOM area
            // pertaining to a core in STOP image.
            l_maxScomRestoreEntry   =
                *(uint32_t*)((uint8_t*)i_pImage + CPMR_HOMER_OFFSET + CPMR_MAX_SCOM_REST_PER_CORE_BYTE);
            pScomEntry              =   CORE_ID_SCOM_START(i_pImage, chipletId )
            cacheEntry              =   false;

            if( !l_maxScomRestoreEntry )
            {
                //Old HB and new STOP API case. Retain legacy Number
                l_maxScomRestoreEntry   =  SWIZZLE_4_BYTE(LEGACY_CORE_SCOM_SUPPORTED);
            }
        }
        else
        {
            l_maxScomRestoreEntry   =
                *(uint32_t*)((uint8_t*)i_pImage + QPMR_HOMER_OFFSET + QPMR_QUAD_MAX_SCOM_ENTRY_BYTE);

            if( !l_maxScomRestoreEntry )
            {
                // Incase of a bad HOMER header initialization, fall back on legacy number.
                l_maxScomRestoreEntry   =  SWIZZLE_4_BYTE(LEGACY_QUAD_SCOM_SUPPORTED);
            }
            // chiplet is a cache. let us find start address of cache section
            // associated with given chiplet. A cache section associated with
            // given chiplet is split in to L2, L3 and EQ area.
            pStopCacheScomStart = CACHE_SECTN_START(i_pImage,
                                                    chipletId);
        }

        l_maxScomRestoreEntry   =   SWIZZLE_4_BYTE(l_maxScomRestoreEntry);

        if(( !pStopCacheScomStart ) && ( !pScomEntry) )
        {
            //Error invalid pointer to SCOM entry in cache or core section
            //of STOP image.
            MY_ERR("invalid start location for chiplet %d",
                   chipletId );
            break;
        }

        switch( i_section )
        {
            case P9_STOP_SECTION_EQ_SCOM:
                pScomEntry = pStopCacheScomStart->nonCacheArea;
                entryLimit = MAX_EQ_SCOM_ENTRIES;
                break;

            case P9_STOP_SECTION_L2:
                pScomEntry = pStopCacheScomStart->l2CacheArea;
                entryLimit = MAX_L2_SCOM_ENTRIES;
                break;

            case P9_STOP_SECTION_L3:
                pScomEntry = pStopCacheScomStart->l3CacheArea;
                entryLimit = MAX_L3_SCOM_ENTRIES;
                break;

            case P9_STOP_SECTION_CORE_SCOM:
                //macro CORE_ID_SCOM_START already gives start of scom
                //entry for given core. entry limit too is assigned thereafter.
                //Handling for core and cache segment is different for scom
                //entries. It is because scom entries are organized differently
                //in core and cache segment.

                entryLimit  =   l_maxScomRestoreEntry;
                break;

            default:
                l_rc = STOP_SAVE_SCOM_INVALID_SECTION;
                break;
        }


        if(( imageVer > LEGACY_SCOM_RESTORE_VER ) && ( cacheEntry ) )
        {
            //STOP API migrated to newer algorithm for creation of entries

            pScomEntry  =   CACHE_SCOM_ADDR(i_pImage,
                                            chipletId,
                                            l_maxScomRestoreEntry )

            entryLimit  =   l_maxScomRestoreEntry;
        }

        if(( !pScomEntry ) || ( l_rc ) )
        {
            // Error Invalid pointer to cache entry
            MY_ERR("invalid subsection %d or internal firmware failure",
                   i_section );
            l_rc = STOP_SAVE_FAIL;
            break;
        }

        nopInst                 =   getOriInstruction( 0, 0, 0 );
        pEntryLocation          =   NULL;
        pNopLocation            =   NULL;
        pTableEndLocationtable  =   NULL;
        swizzleAddr             =   SWIZZLE_4_BYTE(i_scomAddress);
        swizzleData             =   SWIZZLE_8_BYTE(i_scomData);
        swizzleAttn             =   SWIZZLE_4_BYTE(ATTN_OPCODE);

        for( index = 0; index < entryLimit; ++index )
        {
            uint32_t entrySwzAddress = pScomEntry[index].scomEntryAddress;
            entrySwzHeader  = SWIZZLE_4_BYTE(pScomEntry[index].scomEntryHeader);

            if( ( swizzleAddr == entrySwzAddress ) && ( !pEntryLocation ) )

            {
                pEntryLocation = &pScomEntry[index];
            }

            if( (( nopInst == entrySwzAddress ) ||
                 ( swizzleAttn == entrySwzAddress ) ||
                 ( swizzleBlr == entrySwzAddress )) && ( !pNopLocation ) )
            {
                pNopLocation = &pScomEntry[index];
            }

            // if entry is either 0xDEADDEAD or has SCOM entry limit in LSB of header
            // place is already occupied
            if( ( SCOM_ENTRY_START == entrySwzHeader ) ||
                ( entrySwzHeader & 0x000000FF ) )
            {
                continue;
            }

            pTableEndLocationtable = &pScomEntry[index];
            break;
        }

        if( ( !pEntryLocation ) && ( !pTableEndLocationtable ) )
        {
            MY_ERR(" exhausted all location available for section"
                   "0x%08x scom address 0x%08x",
                   i_section, i_scomAddress );
            l_rc = STOP_SAVE_SCOM_ENTRY_UPDATE_FAILED;
            break;
        }

        switch( i_operation )
        {
            case P9_STOP_SCOM_APPEND:
                {
                    ScomEntry_t* pScomAppend = NULL;

                    if( pNopLocation )
                    {
                        pScomAppend = pNopLocation;
                    }
                    else
                    {
                        pScomAppend = pTableEndLocationtable;
                    }

                    l_rc = updateScomEntry ( swizzleAddr,
                                             swizzleData, pScomAppend );

                    pEditScomHeader = pScomAppend;
                }
                break;

            case P9_STOP_SCOM_REPLACE:
                {
                    ScomEntry_t* scomReplace = NULL;

                    if( pEntryLocation )
                    {
                        scomReplace = pEntryLocation;
                    }
                    else
                    {
                        scomReplace = pTableEndLocationtable;
                    }

                    l_rc = updateScomEntry( swizzleAddr,
                                            swizzleData, scomReplace );

                    pEditScomHeader = scomReplace;
                }
                break;

            case P9_STOP_SCOM_OR:
            case P9_STOP_SCOM_AND:
            case P9_STOP_SCOM_NOOP:

                if( pEntryLocation )
                {
                    l_rc = editScomEntry( swizzleAddr,
                                          swizzleData,
                                          pEntryLocation,
                                          i_operation );

                    pEditScomHeader = pEntryLocation;
                }
                else
                {
                    //Invalid operation requested.
                    MY_ERR( "entry not found edit chiplet Id 0x%08x "
                            "swizzle addr 0x%08x ",
                            chipletId, swizzleAddr );

                    l_rc = STOP_SAVE_SCOM_INVALID_OPERATION;
                }

                break;

            case P9_STOP_SCOM_RESET:

                if( P9_STOP_SECTION_CORE_SCOM ==  i_section )
                {
                    memset( pScomEntry, 0x00, CORE_SCOM_RESTORE_SIZE_PER_CORE );
                }

                break;

            case P9_STOP_SCOM_OR_APPEND:
            case P9_STOP_SCOM_AND_APPEND:
                {
                    uint32_t tempOperation  = P9_STOP_SCOM_APPEND;
                    ScomEntry_t* editAppend = NULL;

                    if( NULL == pEntryLocation )
                    {
                        editAppend = pTableEndLocationtable;
                    }
                    else
                    {
                        editAppend = pEntryLocation;

                        if( P9_STOP_SCOM_OR_APPEND == i_operation )
                        {
                            tempOperation = P9_STOP_SCOM_OR;
                        }
                        else
                        {
                            tempOperation = P9_STOP_SCOM_AND;
                        }
                    }

                    l_rc = editScomEntry( swizzleAddr,
                                          swizzleData,
                                          editAppend,
                                          tempOperation );

                    pEditScomHeader = editAppend;
                }
                break;

            default:
                l_rc = STOP_SAVE_SCOM_INVALID_OPERATION;
                break;
        }
    }
    while(0);

    if( l_rc )
    {
        MY_ERR("SCOM image operation 0x%08x failed for chiplet 0x%08x addr"
               "0x%08x", i_operation, chipletId ,
               i_scomAddress );
    }
    else
    {
        //Update SCOM Restore entry with version and memory layout
        //info
        updateEntryHeader( pEditScomHeader, imageVer, l_maxScomRestoreEntry );
    }

    MY_INF("<< p9_stop_save_scom");
    return l_rc;
}

//-----------------------------------------------------------------------------

/**
 * @brief   searches a self save entry of an SPR in self-save segment.
 * @param[in]   i_sprBitPos         bit position associated with SPR in save mask vector.
 * @param[in]   l_pSprSaveStart     start location of SPR save segment
 * @param[in]   i_searchLength      length of SPR save segment
 * @param[in]   i_pSaveSprLoc       start location of save entry for a given SPR.
 * @return      STOP_SAVE_SUCCESS if look up succeeds, error code otherwise.
 */
STATIC StopReturnCode_t lookUpSelfSaveSpr( uint32_t i_sprBitPos, uint32_t* l_pSprSaveStart,
                                    uint32_t  i_searchLength, uint32_t** i_pSaveSprLoc )
{
    int32_t l_saveWordLength    =   (int32_t)(i_searchLength >> 2);
    uint32_t l_oriInst          =   getOriInstruction( 0, 0, i_sprBitPos );
    StopReturnCode_t l_rc       =   STOP_SAVE_FAIL;

    while( l_saveWordLength > 0 )
    {
        if( l_oriInst == *l_pSprSaveStart )
        {
            *i_pSaveSprLoc   =   l_pSprSaveStart;
            l_rc             =   STOP_SAVE_SUCCESS;
            break;
        }

        l_pSprSaveStart++;
        l_saveWordLength--;
    }

    return l_rc;
}

//-----------------------------------------------------------------------------

/**
 * @brief   searches a self save entry of an SPR in self-save segment.
 * @param[in]   i_pSaveReg  start of editable location of a SPR save entry.
 * @param[in]   i_sprNum    Id of the SPR for which entry needs to be edited.
 * @return      STOP_SAVE_SUCCESS if look up succeeds, error code otherwise.
 */
STATIC StopReturnCode_t updateSelfSaveEntry( uint32_t* i_pSaveReg, uint16_t i_sprNum )
{
    StopReturnCode_t l_rc   =   STOP_SAVE_SUCCESS;

    do
    {
        if( !i_pSaveReg )
        {
            l_rc    =   STOP_SAVE_FAIL;
            MY_ERR( "Failed to update self save area for SPR 0x%04x", i_sprNum );
            break;
        }

        if( P9_STOP_SPR_MSR == i_sprNum )
        {
            *i_pSaveReg     =    getMfmsrInstruction( 1 );
        }
        else
        {
            *i_pSaveReg     =   getMfsprInstruction( 1, i_sprNum );
        }

        i_pSaveReg++;

        *i_pSaveReg         =   getBranchLinkRegInstruction( );
    }
    while(0);

    return l_rc;
}

//-----------------------------------------------------------------------------

StopReturnCode_t p9_stop_save_cpureg_control(  void* i_pImage,
        const uint64_t i_pir,
        const uint32_t i_saveRegVector )
{
    StopReturnCode_t l_rc   =   STOP_SAVE_SUCCESS;
    uint32_t l_coreId       =   0;
    uint32_t l_threadId     =   0;
    uint32_t l_sprPos       =   0;
    uint32_t l_sprIndex     =   0;
    uint32_t l_lookupLength =   0;
    uint32_t l_lookUpKey    =   0;
    uint32_t* l_pSaveStart          =   NULL;
    uint32_t* l_pRestoreStart       =   NULL;
    uint32_t* l_pSprSave            =   NULL;
    void* l_pTempLoc                =   NULL;
    SmfHomerSection_t* l_pHomer     =   NULL;
    uint8_t l_selfRestVer           =   0;

    do
    {
        l_rc    =   getCoreAndThread( i_pImage, i_pir, &l_coreId, &l_threadId );

        if( l_rc )
        {
            MY_ERR( "Error in getting core no 0x%08x and thread no 0x%08x from PIR 0x%016lx",
                    l_coreId, l_threadId, i_pir );
            break;
        }

        l_rc    =   validateArgumentSaveRegMask( i_pImage, l_coreId, l_threadId, i_saveRegVector );

        if( l_rc )
        {
            MY_ERR( "Invalid argument rc 0x%08x", (uint32_t) l_rc );
            break;
        }

        l_pHomer        =   ( SmfHomerSection_t * )i_pImage;
        l_selfRestVer   =   *(uint8_t *)((uint8_t *)i_pImage + CPMR_HOMER_OFFSET + CPMR_SELF_RESTORE_VER_BYTE );

        for( l_sprIndex = 0; l_sprIndex < MAX_SPR_SUPPORTED; l_sprIndex++ )
        {
            l_sprPos    =    g_sprRegister[l_sprIndex].iv_saveMaskPos;

            //Check if a given SPR needs to be self-saved each time on STOP entry

            if( i_saveRegVector & ( TEST_BIT_PATTERN >> l_sprPos ) )
            {

                if( g_sprRegister[l_sprIndex].iv_isThreadScope )
                {
                    l_lookupLength  =   SMF_SELF_SAVE_THREAD_AREA_SIZE;
                    l_pSaveStart    =
                        (uint32_t*)&l_pHomer->iv_coreThreadRestore[l_coreId].iv_threadSaveArea[l_threadId][0];
                    l_pRestoreStart =
                        (uint32_t*)&l_pHomer->iv_coreThreadRestore[l_coreId].iv_threadRestoreArea[l_threadId][0];
                }
                else
                {
                    l_lookupLength  =   SMF_CORE_SAVE_CORE_AREA_SIZE;
                    l_pSaveStart    =   (uint32_t*)&l_pHomer->iv_coreThreadRestore[l_coreId].iv_coreSaveArea[0];
                    l_pRestoreStart =   (uint32_t*)&l_pHomer->iv_coreThreadRestore[l_coreId].iv_coreRestoreArea[0];
                }

                // an SPR restore section for given core already exists
                l_lookUpKey   =   genKeyForSprLookup( ( CpuReg_t )g_sprRegister[l_sprIndex].iv_sprId );

                l_rc          =   lookUpSprInImage( (uint32_t*)l_pRestoreStart, l_lookUpKey,
                                                    g_sprRegister[l_sprIndex].iv_isThreadScope, &l_pTempLoc,
                                                    l_selfRestVer  );

                if( l_rc )
                {
                    //SPR specified in the save mask but there is no restore entry present in the memory
                    //Self-Save instruction will edit it during STOP entry to make it a valid entry

                    l_rc = p9_stop_save_cpureg( i_pImage,
                                                (CpuReg_t)g_sprRegister[l_sprIndex].iv_sprId,
                                                0x00,       //creates a dummy entry
                                                i_pir );
                }

                //Find if SPR-Save eye catcher exist in self-save segment of SPR restore region.
                l_rc  =   lookUpSelfSaveSpr( l_sprPos, l_pSaveStart, l_lookupLength, &l_pSprSave );

                if( l_rc )
                {
                    MY_INF( "Failed to find SPR No %02d save entry", l_sprPos );
                    l_rc    =  STOP_SAVE_SPR_ENTRY_MISSING;
                    break;
                }

                l_pSprSave++; //point to next instruction location

                //update specific instructions of self save region to enable saving for SPR
                l_rc    =   updateSelfSaveEntry( l_pSprSave, g_sprRegister[l_sprIndex].iv_sprId );

            }// end if( i_saveRegVector..)
        }// end for
    }
    while(0);

    return l_rc;
}

//-----------------------------------------------------------------------------------------------------

StopReturnCode_t p9_stop_init_cpureg(  void* const i_pImage, const uint32_t i_corePos )
{
    StopReturnCode_t    l_rc        =   STOP_SAVE_SUCCESS;
    uint32_t* l_pRestoreStart       =   NULL;
    void* l_pTempLoc                =   NULL;
    SmfHomerSection_t* l_pHomer     =   NULL;
    uint32_t l_threadPos            =   0;
    uint32_t l_lookUpKey            =   0;
    uint32_t l_sprIndex             =   0;
    uint8_t l_selfRestVer           =   0;

    MY_INF( ">> p9_stop_init_cpureg" );

    do
    {
        if( !i_pImage )
        {
            l_rc    =   STOP_SAVE_ARG_INVALID_IMG;
            break;
        }

        if( i_corePos > MAX_CORE_ID_SUPPORTED )
        {
            l_rc    =  STOP_SAVE_ARG_INVALID_CORE;
            break;
        }

        l_pHomer        =   ( SmfHomerSection_t * ) i_pImage;
        l_selfRestVer   =   *(uint8_t *)((uint8_t *)i_pImage + CPMR_HOMER_OFFSET + CPMR_SELF_RESTORE_VER_BYTE );

        for( l_sprIndex = 0; l_sprIndex < MAX_SPR_SUPPORTED; l_sprIndex++ )
        {
            //Check if a given SPR needs to be self-saved each time on STOP entry

            l_lookUpKey     =   genKeyForSprLookup( ( CpuReg_t )g_sprRegister[l_sprIndex].iv_sprId );

            if( g_sprRegister[l_sprIndex].iv_isThreadScope )
            {
                for( l_threadPos = 0; l_threadPos < MAX_THREADS_PER_CORE; l_threadPos++ )
                {
                    l_pRestoreStart =
                        (uint32_t*)&l_pHomer->iv_coreThreadRestore[i_corePos].iv_threadRestoreArea[l_threadPos][0];

                    l_rc    =   lookUpSprInImage( (uint32_t*)l_pRestoreStart, l_lookUpKey,
                                                  g_sprRegister[l_sprIndex].iv_isThreadScope,
                                                  &l_pTempLoc,
                                                  l_selfRestVer );

                    if( l_rc )
                    {
                        MY_ERR( "Thread SPR lookup failed in p9_stop_init_cpureg SPR %d Core %d Thread %d Index %d",
                                g_sprRegister[l_sprIndex].iv_sprId, i_corePos, l_threadPos, l_sprIndex );
                        break;
                    }

                    l_rc = updateSprEntryInImage( (uint32_t*) l_pTempLoc,
                                                  ( CpuReg_t )g_sprRegister[l_sprIndex].iv_sprId,
                                                  0x00,
                                                  INIT_SPR_REGION );

                    if( l_rc )
                    {
                        MY_ERR( "Thread SPR region init failed. Core %d SPR Id %d",
                                i_corePos, g_sprRegister[l_sprIndex].iv_sprId );
                        break;
                    }

                }//end for thread

                if( l_rc )
                {
                    break;
                }

            }//end if SPR threadscope
            else
            {
                l_pRestoreStart     =   (uint32_t*)&l_pHomer->iv_coreThreadRestore[i_corePos].iv_coreRestoreArea[0];

                l_rc                =   lookUpSprInImage( (uint32_t*)l_pRestoreStart, l_lookUpKey,
                                        g_sprRegister[l_sprIndex].iv_isThreadScope,
                                        &l_pTempLoc, l_selfRestVer );

                if( l_rc )
                {
                    MY_ERR( "Core SPR lookup failed in p9_stop_init_cpureg" );
                    break;
                }

                l_rc    =   updateSprEntryInImage( (uint32_t*) l_pTempLoc,
                                                   ( CpuReg_t )g_sprRegister[l_sprIndex].iv_sprId,
                                                   0x00,
                                                   INIT_SPR_REGION );

                if( l_rc )
                {
                    MY_ERR( "Core SPR region init failed. Core %d SPR Id %d SPR Index %d",
                            i_corePos, g_sprRegister[l_sprIndex].iv_sprId, l_sprIndex );
                    break;
                }

            }// end else

        }// end for l_sprIndex

    }
    while(0);

    MY_INF( "<< p9_stop_init_cpureg" );
    return l_rc;
}

//-----------------------------------------------------------------------------------------------------

StopReturnCode_t p9_stop_init_self_save(  void* const i_pImage, const uint32_t i_corePos )
{
    StopReturnCode_t    l_rc        =   STOP_SAVE_SUCCESS;
    uint32_t* l_pSaveStart          =   NULL;
    SmfHomerSection_t *  l_pHomer   =   NULL;
    uint32_t l_threadPos            =   0;
    uint32_t l_sprBitPos            =   0;
    uint32_t l_sprIndexAdj          =   0;
    MY_INF( ">> p9_stop_init_self_save" );

    do
    {
        if( !i_pImage )
        {
            l_rc    =   STOP_SAVE_ARG_INVALID_IMG;
            break;
        }

        if( i_corePos > MAX_CORE_ID_SUPPORTED )
        {
            l_rc    =  STOP_SAVE_ARG_INVALID_CORE;
            break;
        }

        l_pHomer    =   ( SmfHomerSection_t*) i_pImage;

        for( l_threadPos = 0; l_threadPos < MAX_THREADS_PER_CORE; l_threadPos++ )
        {
            l_pSaveStart    =
                (uint32_t*)&l_pHomer->iv_coreThreadRestore[i_corePos].iv_threadSaveArea[l_threadPos][0];

            //Adding instruction 'mflr r30'
            *l_pSaveStart   =   SWIZZLE_4_BYTE(MFLR_R30);
            l_pSaveStart++;

            for( l_sprBitPos  = 0; l_sprBitPos <= MAX_SPR_BIT_POS; l_sprBitPos++ )
            {
                l_rc = getSprRegIndexAdjustment( l_sprBitPos, &l_sprIndexAdj );

                if( STOP_SAVE_SPR_BIT_POS_RESERVE == l_rc )
                {
                    //Failed to find SPR index adjustment
                    continue;
                }

                if( !g_sprRegister[l_sprBitPos - l_sprIndexAdj].iv_isThreadScope )
                {
                    continue;
                }

                //Initialize self save region with SPR save entry for each thread
                //level SPR
                l_rc    =   initSelfSaveEntry( l_pSaveStart,
                                               g_sprRegister[l_sprBitPos - l_sprIndexAdj].iv_saveMaskPos );

                if( l_rc )
                {
                    MY_ERR( "Failed to init thread self-save region for core %d thread %d",
                            i_corePos, l_threadPos );
                    break;
                }

                l_pSaveStart++;
                l_pSaveStart++;
                l_pSaveStart++;
            }

        }// for thread = 0;

        if( l_rc )
        {
            //breakout if saw an error while init of thread SPR region
            break;
        }

        l_pSaveStart    =
            (uint32_t*)&l_pHomer->iv_coreThreadRestore[i_corePos].iv_coreSaveArea[0];

        *l_pSaveStart   =   SWIZZLE_4_BYTE(MFLR_R30);
        l_pSaveStart++;

        for( l_sprBitPos = 0;  l_sprBitPos <=  MAX_SPR_BIT_POS; l_sprBitPos++ )
        {
            l_rc = getSprRegIndexAdjustment( l_sprBitPos, &l_sprIndexAdj );

            if( STOP_SAVE_SPR_BIT_POS_RESERVE == l_rc )
            {
                //Failed to find SPR index adjustment
                continue;
            }

            if( g_sprRegister[l_sprBitPos - l_sprIndexAdj].iv_isThreadScope )
            {
                continue;
            }

            //Initialize self save region with SPR save entry for each core
            //level SPR
            l_rc    =   initSelfSaveEntry( l_pSaveStart,
                                           g_sprRegister[l_sprBitPos - l_sprIndexAdj].iv_saveMaskPos );

            if( l_rc )
            {
                MY_ERR( "Failed to init core self-save region for core %d thread %d",
                        i_corePos, l_threadPos );
                break;
            }

            l_pSaveStart++;
            l_pSaveStart++;
            l_pSaveStart++;
        }
    }
    while(0);

    MY_INF( "<< p9_stop_init_self_save" );
    return l_rc;
}

#ifdef __cplusplus
} //namespace stopImageSection ends

}  //extern "C"
#endif
