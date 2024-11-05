/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: chips/p10/procedures/utils/stopreg/p10_stop_api.C $           */
/*                                                                        */
/* IBM CONFIDENTIAL                                                       */
/*                                                                        */
/* EKB Project                                                            */
/*                                                                        */
/* COPYRIGHT 2015,2019                                                    */
/* [+] International Business Machines Corp.                              */
/*                                                                        */
/*                                                                        */
/* The source code for this program is not published or otherwise         */
/* divested of its trade secrets, irrespective of what has been           */
/* deposited with the U.S. Copyright Office.                              */
/*                                                                        */
/* IBM_PROLOG_END_TAG                                                     */

///
/// @file   p10_stop_api.C
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

#include "p10_stop_api.H"
#include "p10_cpu_reg_restore_instruction.H"
#include "p10_stop_data_struct.H"
#include <string.h>
#include "p10_stop_util.H"
#include "p10_hcode_image_defines.H"
#ifdef __cplusplus
extern "C" {

using namespace hcodeImageBuild;
namespace stopImageSection
{
#endif
// a true in the table below means register is of scope thread
// whereas a false meanse register is of scope core.

const StopSprReg_t g_sprRegister_p10[] =
{
    { PROC_STOP_SPR_CIABR,     true,  0   },
    { PROC_STOP_SPR_DAWR,      true,  1   },
    { PROC_STOP_SPR_DAWRX,     true,  2   },
    { PROC_STOP_SPR_HSPRG0,    true,  3   },
    { PROC_STOP_SPR_LDBAR,     true,  4,  },
    { PROC_STOP_SPR_LPCR,      true,  5   },
    { PROC_STOP_SPR_PSSCR,     true,  6   },
    { PROC_STOP_SPR_MSR,       true,  7   },
    { PROC_STOP_SPR_HRMOR,     false, 255 },
    { PROC_STOP_SPR_HID,       false, 21  },
    { PROC_STOP_SPR_HMEER,     false, 22  },
    { PROC_STOP_SPR_PMCR,      false, 23  },
    { PROC_STOP_SPR_PTCR,      false, 24  },
    { PROC_STOP_SPR_SMFCTRL,   true,  28  },
    { PROC_STOP_SPR_USPRG0,    true,  29  },
    { PROC_STOP_SPR_USPRG1,    true,  30  },
    { PROC_STOP_SPR_URMOR,     false, 255 },
};

const uint32_t MAX_SPR_SUPPORTED_P10                =   17;
const uint32_t DEFAULT_CORE_SCOM_SUPPORTED      =   15;
const uint32_t DEFAULT_QUAD_SCOM_SUPPORTED      =  255;

//-----------------------------------------------------------------------------

/**
 * @brief       validated input arguments passed to proc_stop_save_cpureg_control.
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

        for( index = 0; index < MAX_SPR_SUPPORTED_P10; ++index )
        {
            if( i_regId == (CpuReg_t )g_sprRegister_p10[index].iv_sprId )
            {
                // given register is in the list of register supported
                sprSupported = true;
                *i_pThreadLevelReg = g_sprRegister_p10[index].iv_isThreadScope;
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
        MY_ERR( "regId %08d, coreId %d, "
                "threadId %d return code 0x%08x", i_regId,
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
    return getOriInstruction( 24, 0, (uint16_t) i_regId );
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
    uint32_t mfmsrInstOpcode  = ((OPCODE_31 << 26) | (i_Rt << 21) | ((MFMSR_CONST)<< 1));

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
    uint32_t mfsprInstOpcode = 0;
    uint32_t temp = (( i_sprNum & 0x03FF ) << 11);
    mfsprInstOpcode = (uint8_t)i_Rt << 21;
    mfsprInstOpcode |= (( temp  & 0x0000F800 ) << 5);
    mfsprInstOpcode |= (( temp  & 0x001F0000 ) >> 5);
    mfsprInstOpcode |= MFSPR_BASE_OPCODE;

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
                                          const bool i_isThreadReg, void** io_pSprEntryLoc )
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

        temp    =   i_isThreadReg ? (uint32_t)(SMF_CORE_RESTORE_THREAD_AREA_SIZE) :
                                    (uint32_t)(SMF_CORE_RESTORE_CORE_AREA_SIZE);

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

        if( PROC_STOP_SPR_MSR == i_regId )
        {
            //MSR cannot be restored completely with mtmsrd instruction.
            //as it does not update ME, LE and HV bits. In self restore code
            //inorder to restore MSR, contents of R21 is moved to SRR1. It also
            //executes an RFID which causes contents of SRR1 to be copied to
            //MSR. This allows copy of LE bit which are specifically interested
            //in. Instruction below moves contents of MSR Value (in R0 ) to R21.
            tempInst = SWIZZLE_4_BYTE( MR_R0_TO_R21 );
        }
        else if ( PROC_STOP_SPR_HRMOR == i_regId )
        {
            //Case HRMOR, move contents of R0 to a placeholder GPR (R10)
            //Thread Launcher expects HRMOR value in R10
            tempInst = SWIZZLE_4_BYTE( MR_R0_TO_R10 );
        }
        else if( PROC_STOP_SPR_URMOR == i_regId )
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
        if( (( i_saveMaskPos >= SPR_BIT_POS_8 ) && ( i_saveMaskPos <= SPR_BIT_POS_20 )) ||
            (( i_saveMaskPos >= SPR_BIT_POS_25 ) && ( i_saveMaskPos <= SPR_BIT_POS_27 )) )
        {
            l_rc = STOP_SAVE_SPR_BIT_POS_RESERVE;
            break;
        }

        if( (i_saveMaskPos > SPR_BIT_POS_20) && (i_saveMaskPos < SPR_BIT_POS_25) )
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

/**
 * @brief   returns core region and relative id wrt to quad
 * @param[in]   i_scomAddress       scom address associated with a core
 * @param[in]   o_scomRegion        SCOM region in HOMER
 * @param[in]   o_coreRelativeInst  core relative id
 * @return      STOP_SAVE_SUCCESS if function succeeds, error code otherwise
 */
STATIC StopReturnCode_t decodeScomAddress( const uint32_t i_scomAddress, uint32_t * o_scomRegion,
                                    uint32_t * o_coreRelativeInst )
{
    StopReturnCode_t l_rc       =   STOP_SAVE_SUCCESS;
    uint32_t l_regionSelect     =   ( i_scomAddress & CORE_REGION_MASK );
    uint32_t l_endPoint         =   ( i_scomAddress & EP_SELECT_MASK );
    l_endPoint                  =   ( l_endPoint >> 16 );
    l_regionSelect              =   l_regionSelect >> 12;

    if( 1 == l_endPoint )
    {
        *o_scomRegion   =   PROC_STOP_SECTION_L3;
    }
    else if ( 2 == l_endPoint )
    {
        *o_scomRegion   =   PROC_STOP_SECTION_CORE;
    }

    switch( l_regionSelect )
    {
        case 8:
            *o_coreRelativeInst  =   0;
            break;

        case 4:
            *o_coreRelativeInst  =   1;
            break;

        case 2:
            *o_coreRelativeInst  =   2;
            break;

        case 1:
            *o_coreRelativeInst  =   3;
            break;

        default:
            l_rc    =   STOP_SAVE_SCOM_INVALID_ADDRESS;
            break;
    }

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
    StopReturnCode_t l_rc   =   STOP_SAVE_SUCCESS;
    uint32_t l_scomRegion   =   0;
    uint32_t l_coreId       =   0;

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

        if(( CACHE_CHIPLET_ID_MIN >  i_chipletId ) ||
           ( CACHE_CHIPLET_ID_MAX < i_chipletId ))
        {
            l_rc = STOP_SAVE_SCOM_INVALID_CHIPLET;
            MY_ERR("chiplet id not valid");
            break;
        }

        if(( PROC_STOP_SCOM_OP_MIN >= i_operation ) ||
           ( PROC_STOP_SCOM_OP_MAX <= i_operation ))
        {
            //invalid SCOM image operation requested
            l_rc = STOP_SAVE_SCOM_INVALID_OPERATION;
            MY_ERR("invalid SCOM image operation");
            break;
        }

        l_rc    =   decodeScomAddress( i_scomAddress, &l_scomRegion, &l_coreId );

        if( l_rc )
        {
            MY_ERR( "Bad Scom Address 0x%08x", i_chipletId );
            break;
        }

        if( PROC_STOP_SECTION_CORE == l_scomRegion )
        {
            if( ( i_section != PROC_STOP_SECTION_CORE ) ||
                ( i_section != PROC_STOP_SECTION_L2 ) )
            {
                MY_ERR( "SCOM adress doesn't match with section type passed,"
                        " EP : %d , Section Type %d", l_scomRegion, i_section );
                l_rc    =   STOP_SAVE_SCOM_INVALID_SECTION;
                break;
            }
        }

        if( PROC_STOP_SECTION_L3 == l_scomRegion )
        {
            if( ( i_section != PROC_STOP_SECTION_L3 ) ||
                ( i_section != PROC_STOP_SECTION_CACHE ) )
            {
                MY_ERR( "SCOM adress doesn't match with section type passed,"
                        " EP : %d , Section Type %d", l_scomRegion, i_section );
                l_rc    =   STOP_SAVE_SCOM_INVALID_SECTION;
                break;
            }
        }
    }
    while(0);

    if( l_rc )
    {
        MY_ERR("SCOMAddress 0x%08x chipletId 0x%08x operation"
               "0x%08x section 0x%08x", i_scomAddress, i_chipletId,
               i_operation, i_section );
    }

    return l_rc;
}

//-----------------------------------------------------------------------------

/**
 * @brief   determines HOMER region  for SCOM restore entry request.
 * @param[in] i_pImage          points to base of HOMER image.
 * @param[in] i_sectn           SCOM restore section
 * @param[in] i_instanceId      core instance id
 * @param[out]o_entryDat        meta data pertaining to SCOM restore entry analysis
 * @return    STOP_SAVE_SUCCESS if HWP succeeds, error code otherwise.
 */
STATIC StopReturnCode_t lookUpScomRestoreRegion( void * i_pImage, const ScomSection_t i_sectn, uint32_t i_instanceId,
                                                 ScomEntryDat_t  * o_entryDat )
{
    StopReturnCode_t    l_rc        =   STOP_SAVE_SUCCESS;
    CpmrHeader_t * l_pCpmrHdr       =   NULL;
    ScomRestoreHeader_t *l_scomHdr  =   NULL;
    uint32_t l_relativeCorePos   =  0;
    uint32_t l_offset   =   0;
    uint32_t l_quadId   =   0;
    uint32_t l_scomLen  =   0;

    MY_INF( ">>lookUpScomRestoreRegion" );

    o_entryDat->iv_subRegionBaseOffset  =   0;
    o_entryDat->iv_subRegionLength      =   0;
    l_quadId            =   ( i_instanceId >> 2 );

    l_relativeCorePos   =   i_instanceId % MAX_CORES_PER_QUAD;
    l_pCpmrHdr          =   ( CpmrHeader_t *) ( (uint8_t *) i_pImage + CPMR_HOMER_OFFSET );
    l_scomLen           =   SWIZZLE_4_BYTE(l_pCpmrHdr->iv_maxCoreL2ScomEntry) +
                            SWIZZLE_4_BYTE(l_pCpmrHdr->iv_maxEqL3ScomEntry);
    l_scomLen           =   ( l_scomLen * SCOM_RESTORE_ENTRY_SIZE );

    l_offset            =   ( l_scomLen * l_quadId * MAX_CORES_PER_QUAD  ) + SCOM_RESTORE_HOMER_OFFSET;

    MY_INF( "QUAD_ID 0x%08x BASE OFFSET 0x%08x", l_quadId, l_offset );

    l_scomHdr           =   ( ScomRestoreHeader_t *) ( (uint8_t *) i_pImage + l_offset );

    if( ( PROC_STOP_SECTION_CORE == i_sectn ) || ( PROC_STOP_SECTION_L2 == i_sectn ) )
    {
        MY_INF( "Core Offset 0x%04x", SWIZZLE_2_BYTE(l_scomHdr->iv_coreOffset) );
        l_offset       +=   SWIZZLE_2_BYTE(l_scomHdr->iv_coreOffset);
        o_entryDat->iv_subRegionLength  =   SWIZZLE_2_BYTE(l_scomHdr->iv_coreLength);
        l_offset       +=   ( SWIZZLE_4_BYTE(l_pCpmrHdr->iv_maxCoreL2ScomEntry) * l_relativeCorePos );
    }
    else if( ( PROC_STOP_SECTION_L3 == i_sectn ) || ( PROC_STOP_SECTION_CACHE == i_sectn ) )
    {
        MY_INF( "Cache Offset 0x%04x", SWIZZLE_2_BYTE(l_scomHdr->iv_l3Offset) );
        l_offset       +=   SWIZZLE_2_BYTE(l_scomHdr->iv_l3Offset);
        o_entryDat->iv_subRegionLength  =   SWIZZLE_2_BYTE(l_scomHdr->iv_l3Length);
        l_offset       +=   ( SWIZZLE_4_BYTE(l_pCpmrHdr->iv_maxEqL3ScomEntry) * l_relativeCorePos );
    }
    else
    {
        o_entryDat->iv_subRegionBaseOffset  =  0;
        l_rc  =  STOP_SAVE_SCOM_INVALID_SECTION;
    }

    if( !l_rc )
    {
        o_entryDat->iv_subRegionBaseOffset   =   l_offset;
    }

    MY_INF( "SCOM Section Offset 0x%08x", l_offset );

    MY_INF( "<<lookUpScomRestoreRegion" );
    return  l_rc;
}

//-----------------------------------------------------------------------------

/**
 * @brief analyzes SCOM restore region and collects some data.
 * @param[in] i_pImage          points to base of HOMER image
 * @param[in] i_sectn           id associated with SCOM restore sub-region.
 * @param[in] i_scomAddress     fully qualified SCOM address
 * @param[in] o_pScomDat        meta data associated with entry analysis
 * @return    STOP_SAVE_SUCCESS if HWP succeeds, error code otherwise.
 */
STATIC StopReturnCode_t lookUpScomRestoreEntry( void * i_pImage, const ScomSection_t i_sectn,
                                                uint32_t i_scomAddress, ScomEntryDat_t * o_pScomDat )
{
    StopReturnCode_t    l_rc    =   STOP_SAVE_SUCCESS;
    ScomEntry_t * l_pScom       =   NULL;
    CpmrHeader_t * l_pCpmrHdr   =   NULL;
    uint8_t * l_pScomByte       =   NULL;
    uint32_t l_entryLimit       =   0;
    uint8_t  l_entry            =   0;
    uint32_t l_temp             =   0;

    MY_INF( ">> lookUpScomRestoreEntry" );

    o_pScomDat->iv_slotFound        =   0x00;
    o_pScomDat->iv_entryOffset      =   0x00;
    o_pScomDat->iv_lastEntryOffset  =   0x00;
    o_pScomDat->iv_entryMatchOffset =   0x00;
    o_pScomDat->iv_matchFound       =   0x00;
    l_pCpmrHdr          =   ( CpmrHeader_t * ) ( (uint8_t *) i_pImage + CPMR_HOMER_OFFSET );
    l_pScomByte         =   ( uint8_t * )( (uint8_t *) i_pImage + o_pScomDat->iv_subRegionBaseOffset );
    l_pScom   =   (ScomEntry_t *)( l_pScomByte );

    switch( i_sectn )
    {
        case PROC_STOP_SECTION_CORE:
            l_entryLimit    =   SWIZZLE_4_BYTE(l_pCpmrHdr->iv_maxCoreL2ScomEntry);
            break;

        case PROC_STOP_SECTION_L3:
            l_entryLimit    =   SWIZZLE_4_BYTE(l_pCpmrHdr->iv_maxEqL3ScomEntry);
            break;

            default:
            l_rc    =   STOP_SAVE_SCOM_INVALID_SECTION;
            break;
    }

    if( l_rc )
    {
        return l_rc;
    }

    for( l_entry  = 0; l_entry < l_entryLimit; l_entry++ )
    {
        if( !( l_pScom->iv_scomAddress & SWIZZLE_4_BYTE(SCOM_ENTRY_VALID) ) )
        {
            o_pScomDat->iv_slotFound       =   0x01;
            o_pScomDat->iv_entryOffset     =   l_entry;
            break;
        }

        l_pScom++;
    }

    l_pScom   =   (ScomEntry_t *)( l_pScomByte );

    for( l_entry  = 0; l_entry < l_entryLimit; l_entry++ )
    {
        if( l_pScom->iv_scomAddress & SWIZZLE_4_BYTE(LAST_SCOM_ENTRY) )
        {
            o_pScomDat->iv_lastEntryOffset   =   l_entry;
            MY_INF( "SCOM Restore Entry Limit 0x%08x",
                    o_pScomDat->iv_lastEntryOffset );
            break;
        }
        l_pScom++;
    }

    l_pScom   =   (ScomEntry_t *)( l_pScomByte );

    for( l_entry  = 0; l_entry < l_entryLimit; l_entry++ )
    {
        l_temp  =   l_pScom->iv_scomAddress & SWIZZLE_4_BYTE(SCOM_ADDR_MASK);

        if( SWIZZLE_4_BYTE((i_scomAddress & SCOM_ADDR_MASK)) == l_temp  )
        {
            o_pScomDat->iv_entryMatchOffset  =   l_entry;
            o_pScomDat->iv_matchFound        =   0x01;
            MY_INF( "Existing Entry Slot No 0x%08x", l_entry );
            break;
        }
        l_pScom++;
    }

    o_pScomDat->iv_entryLimit  =   l_entryLimit;

    MY_INF( "<< lookUpScomRestoreEntry" );
    return l_rc;
}

//-----------------------------------------------------------------------------

#define UNUSED(x) (void)(x)

/**
 * @brief   edits a SCOM restore entry associated with the given core.
 * @param[in]   i_pScom          points to SCOM restore location
 * @param[in]   i_scomAddr       SCOM address of register.
 * @param[in]   i_scomData       data associated with SCOM register.
 * @param[in]   i_operation      operation to be performed on SCOM entry.
 * @param[in]   i_pScomDat       points to meta data associated with entry analysis
 * @return      STOP_SAVE_SUCCESS if existing entry is updated, STOP_SAVE_FAIL
 *              otherwise.
 */
STATIC StopReturnCode_t editScomEntry( uint8_t * i_pScom, uint32_t i_scomAddr,
                                       uint64_t i_scomData, ScomOperation_t i_operation,
                                       ScomEntryDat_t * i_pScomDat )
{
    StopReturnCode_t l_rc   =   STOP_SAVE_SUCCESS;
    ScomEntry_t * l_pScom   =   (ScomEntry_t *)i_pScom;
    UNUSED(i_scomAddr);

    MY_INF( ">> editScomEntry " );

    l_pScom                 =   l_pScom + i_pScomDat->iv_entryMatchOffset;

    switch( i_operation )
    {
        case PROC_STOP_SCOM_OR:
        case PROC_STOP_SCOM_OR_APPEND:
            l_pScom->iv_scomData    |=   SWIZZLE_8_BYTE(i_scomData);
            break;

        case PROC_STOP_SCOM_AND:
        case PROC_STOP_SCOM_AND_APPEND:
            l_pScom->iv_scomData    &=   SWIZZLE_8_BYTE(i_scomData);
            break;

        case PROC_STOP_SCOM_REPLACE:
            l_pScom->iv_scomData    =    SWIZZLE_8_BYTE(i_scomData);
            break;

            default:
            break;
    }

    MY_INF( "<< editScomEntry " );
    return l_rc;
}

//-----------------------------------------------------------------------------

/**
 * @brief   update SCOM restore entry list associated with the given core.
 * @param[in]   i_pImage     points to base of HOMER image.
 * @param[in]   i_scomAddr   address of SCOM register.
 * @param[in]   i_scomData   data associated with SCOM register.
 * @param[in]   i_sectn      SCOM restore section in HOMER.
 * @param[in]   i_operation  operation type requested on restore entry.
 * @param[in]   i_pScomDat   points entry analysis meta data.
 * @return      STOP_SAVE_SUCCESS if new  entry is added, STOP_SAVE_FAIL otherwise.
 */
STATIC StopReturnCode_t updateScomEntry( void * i_pImage, uint32_t i_scomAddr,
                                uint64_t i_scomData, const ScomSection_t i_sectn,
                                ScomOperation_t i_operation, ScomEntryDat_t * i_pScomDat )
{
    StopReturnCode_t l_rc   =   STOP_SAVE_SUCCESS;
    CpmrHeader_t * l_pCpmrHdr   =   NULL;
    ScomEntry_t * l_pScom       =   NULL;
    uint32_t l_maxScomEntry     =   0;
    l_pCpmrHdr          =   ( CpmrHeader_t * ) ( (uint8_t *) i_pImage + CPMR_HOMER_OFFSET );
    l_pScom             =   ( ScomEntry_t * )( (uint8_t *) i_pImage + i_pScomDat->iv_subRegionBaseOffset );
    switch( i_operation )
    {
        case PROC_STOP_SCOM_OR_APPEND:
        case PROC_STOP_SCOM_AND_APPEND:
        case PROC_STOP_SCOM_APPEND:
        case PROC_STOP_SCOM_REPLACE:

            l_pScom     =   l_pScom + i_pScomDat->iv_lastEntryOffset;

            if( i_pScomDat->iv_entryLimit > i_pScomDat->iv_lastEntryOffset )
            {
                l_pScom->iv_scomAddress    &= ~(SWIZZLE_LAST_SCOM_ENTRY);
                l_pScom++;  // takes us to offset stored in iv_entryOffset
                l_pScom->iv_scomAddress     =   i_scomAddr & SCOM_ADDR_MASK;
                l_pScom->iv_scomAddress    |=  (SCOM_ENTRY_VALID | LAST_SCOM_ENTRY | SCOM_ENTRY_VER);

                if( PROC_STOP_SECTION_CORE == i_sectn )
                {
                    l_maxScomEntry              =   SWIZZLE_4_BYTE(l_pCpmrHdr->iv_maxCoreL2ScomEntry);
                    l_pScom->iv_scomAddress    |=   CORE_SECTION_ID_CODE;
                }
                else
                {
                    l_maxScomEntry              =   SWIZZLE_4_BYTE(l_pCpmrHdr->iv_maxEqL3ScomEntry);
                    l_pScom->iv_scomAddress    |=   L3_SECTION_ID_CODE;
                }

                l_pScom->iv_scomAddress    |=   ( l_maxScomEntry << MAX_SCOM_ENTRY_POS );
                l_pScom->iv_scomAddress     =   SWIZZLE_4_BYTE(l_pScom->iv_scomAddress);
                l_pScom->iv_scomData        =   SWIZZLE_8_BYTE(i_scomData);

                MY_INF( "SCOM Data 0x%08x", SWIZZLE_4_BYTE(l_pScom->iv_scomAddress) );
            }
            else
            {
                MY_ERR( "Current Entry Count 0x%08x More than Max Entry Count 0x%08x",
                         i_pScomDat->iv_lastEntryOffset, i_pScomDat->iv_entryLimit );
                l_rc    =   STOP_SAVE_MAX_ENTRY_REACHED;
            }

            break;
            default:
            break;
    }

    return l_rc;
}

//-----------------------------------------------------------------------------

/**
 * @brief   searches a self save entry of an SPR in self-save segment.
 * @param[in]   i_sprBitPos         bit position associated with SPR in save mask vector.
 * @param[in]   i_pSprSaveStart     start location of SPR save segment
 * @param[in]   i_searchLength      length of SPR save segment
 * @param[in]   i_pSaveSprLoc       start location of save entry for a given SPR.
 * @return      STOP_SAVE_SUCCESS if look up succeeds, error code otherwise.
 */
STATIC StopReturnCode_t lookUpSelfSaveSpr( uint32_t i_sprBitPos, uint32_t* i_pSprSaveStart,
                                    uint32_t  i_searchLength, uint32_t** i_pSaveSprLoc )
{
    int32_t l_saveWordLength    =   (int32_t)(i_searchLength >> 2);
    uint32_t l_oriInst          =   getOriInstruction( 0, 0, i_sprBitPos );
    StopReturnCode_t l_rc       =   STOP_SAVE_FAIL;

    while( l_saveWordLength > 0 )
    {
        if( l_oriInst == *i_pSprSaveStart )
        {
            *i_pSaveSprLoc   =   i_pSprSaveStart;
            l_rc             =   STOP_SAVE_SUCCESS;
            break;
        }

        i_pSprSaveStart++;
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

        if( PROC_STOP_SPR_MSR == i_sprNum )
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

StopReturnCode_t proc_stop_init_cpureg(  void* const i_pImage, const uint32_t i_corePos )
{

    StopReturnCode_t    l_rc            =   STOP_SAVE_SUCCESS;
    uint32_t* l_pRestoreStart           =   NULL;
    void* l_pTempLoc                    =   NULL;
    Homerlayout_t* l_pHomer             =   NULL;
    SmfSprRestoreRegion_t * l_pSprRest  =   NULL;
    uint32_t l_threadPos                =   0;
    uint32_t l_lookUpKey                =   0;
    uint32_t l_sprIndex                 =   0;

    MY_INF( ">> proc_stop_init_cpureg" );

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

        l_pHomer        =   ( Homerlayout_t * ) i_pImage;

        for( l_sprIndex = 0; l_sprIndex < MAX_SPR_SUPPORTED_P10; l_sprIndex++ )
        {
            //Check if a given SPR needs to be self-saved each time on STOP entry

            l_lookUpKey     =   genKeyForSprLookup( ( CpuReg_t )g_sprRegister_p10[l_sprIndex].iv_sprId );
            l_pSprRest      =
                    ( SmfSprRestoreRegion_t * ) &l_pHomer->iv_cpmrRegion.iv_selfRestoreRegion.iv_coreSelfRestore[0];

            l_pSprRest     +=   i_corePos;

            if( g_sprRegister_p10[l_sprIndex].iv_isThreadScope )
            {
                for( l_threadPos = 0; l_threadPos < MAX_THREADS_PER_CORE; l_threadPos++ )
                {
                    l_pRestoreStart =
                        (uint32_t*)&l_pSprRest->iv_threadRestoreArea[l_threadPos][0];


                    l_rc    =   lookUpSprInImage( (uint32_t*)l_pRestoreStart, l_lookUpKey,
                                                  g_sprRegister_p10[l_sprIndex].iv_isThreadScope,
                                                  &l_pTempLoc );

                    if( l_rc )
                    {
                        MY_ERR( "Thread SPR lookup failed in proc_stop_init_cpureg SPR %d Core %d Thread %d Index %d",
                                g_sprRegister_p10[l_sprIndex].iv_sprId, i_corePos, l_threadPos, l_sprIndex );
                        break;
                    }

                    l_rc = updateSprEntryInImage( (uint32_t*) l_pTempLoc,
                                                  ( CpuReg_t )g_sprRegister_p10[l_sprIndex].iv_sprId,
                                                  0x00,
                                                  INIT_SPR_REGION );

                    if( l_rc )
                    {
                        MY_ERR( "Thread SPR region init failed. Core %d SPR Id %d",
                                i_corePos, g_sprRegister_p10[l_sprIndex].iv_sprId );
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
                l_pRestoreStart     =   (uint32_t*)&l_pSprRest->iv_coreRestoreArea[0];

                l_rc                =   lookUpSprInImage( (uint32_t*)l_pRestoreStart, l_lookUpKey,
                                        g_sprRegister_p10[l_sprIndex].iv_isThreadScope, &l_pTempLoc );

                if( l_rc )
                {
                    MY_ERR( "Core SPR lookup failed in proc_stop_init_cpureg" );
                    break;
                }

                l_rc    =   updateSprEntryInImage( (uint32_t*) l_pTempLoc,
                                                   ( CpuReg_t )g_sprRegister_p10[l_sprIndex].iv_sprId,
                                                   0x00,
                                                   INIT_SPR_REGION );

                if( l_rc )
                {
                    MY_ERR( "Core SPR region init failed. Core %d SPR Id %d SPR Index %d",
                            i_corePos, g_sprRegister_p10[l_sprIndex].iv_sprId, l_sprIndex );
                    break;
                }

            }// end else

        }// end for l_sprIndex

    }
    while(0);

    MY_INF( "<< proc_stop_init_cpureg" );

    return l_rc;
}

//-----------------------------------------------------------------------------------------------------

StopReturnCode_t proc_stop_save_scom( void* const   i_pImage,
                                      const uint32_t i_scomAddress,
                                      const uint64_t i_scomData,
                                      const ScomOperation_t i_operation,
                                      const ScomSection_t i_section )
{
    StopReturnCode_t l_rc   =   STOP_SAVE_SUCCESS;
    uint32_t l_quadId       =   0;
    uint32_t l_coreId       =   0;
    uint32_t l_coreRegion   =   0;
    uint8_t * l_pScom       =   NULL;
    ScomEntryDat_t  l_entryDat;

    MY_INF( ">> proc_stop_save_scom" );

    do
    {
        l_quadId   =   i_scomAddress >> 24;
        l_quadId   =   l_quadId & 0x3F;

        l_rc       =   validateScomImageInputs( i_pImage, i_scomAddress,
                                                 l_quadId, i_operation, i_section );
        if( l_rc )
        {
            MY_ERR( "invalid argument: aborting");
            break;
        }

        l_rc       =   decodeScomAddress( i_scomAddress, &l_coreRegion, &l_coreId );

        if( l_rc )
        {
            MY_ERR( "Failed To get Core Details For Address 0x%08x", i_scomAddress );
            break;
        }

        //Converting Superchiplet Id to instance number
        l_quadId    =   l_quadId - MIN_SUPERCHIPLET_ID;

        //getting core position relative to the chip
        l_coreId    += ( l_quadId << 2 );

        MY_INF( "Quad Id 0x%08x COre Id 0x%08x", l_quadId, l_coreId );

        // Let us find the start address of SCOM area

        l_rc       =   lookUpScomRestoreRegion( i_pImage,
                                                i_section,
                                                l_coreId,
                                                &l_entryDat );
        if( l_rc )
        {
            MY_ERR( "Failed To Find SCOM Section Requested 0x%08x",
                    ( uint32_t) i_section );
            break;
        }

        l_pScom     =   (uint8_t *)( (uint8_t *)i_pImage + l_entryDat.iv_subRegionBaseOffset );

        l_rc    =   lookUpScomRestoreEntry( i_pImage,
                                            i_section,
                                            i_scomAddress,
                                            &l_entryDat );
        if( l_rc )
        {
            MY_ERR( "Failed To Find SCOM Entry Slot 0x%08x", (uint32_t) l_rc );
            break;
        }

        switch( i_operation )
        {
            case PROC_STOP_SCOM_APPEND:
                l_rc    =   updateScomEntry( i_pImage,
                                             i_scomAddress,
                                             i_scomData,
                                             i_section,
                                             i_operation,
                                             &l_entryDat );
                break;

            case PROC_STOP_SCOM_OR:
            case PROC_STOP_SCOM_AND:
            //case PROC_STOP_SCOM_NOOP:

                if( l_entryDat.iv_matchFound )
                {
                    l_rc    =   editScomEntry( l_pScom,
                                               i_scomAddress,
                                               i_scomData,
                                               i_operation,
                                               &l_entryDat );
                }

                break;

            case PROC_STOP_SCOM_RESET:

                l_rc       =   lookUpScomRestoreRegion( i_pImage,
                                                        PROC_STOP_SECTION_CORE,
                                                        l_coreId,
                                                        &l_entryDat );
                if( l_rc )
                {
                    MY_ERR( "Failed To Reset SCOM Section Requested 0x%08x",
                            ( uint32_t) i_section );
                    break;
                }

                memset( (uint8_t *)((uint8_t *)i_pImage + l_entryDat.iv_subRegionBaseOffset),
                        0x00, l_entryDat.iv_subRegionLength );

                l_rc       =   lookUpScomRestoreRegion( i_pImage,
                                                        PROC_STOP_SECTION_CACHE,
                                                        l_coreId,
                                                        &l_entryDat );
                if( l_rc )
                {
                    MY_ERR( "Failed To Reset SCOM Section Requested 0x%08x",
                            ( uint32_t) i_section );
                    break;
                }

                memset( (uint8_t *)((uint8_t *)i_pImage + l_entryDat.iv_subRegionBaseOffset),
                        0x00, l_entryDat.iv_subRegionLength );

                break;

            case PROC_STOP_SCOM_OR_APPEND:
            case PROC_STOP_SCOM_AND_APPEND:
            case PROC_STOP_SCOM_REPLACE:

                if( l_entryDat.iv_matchFound )
                {
                    l_rc    =   editScomEntry( l_pScom,
                                               i_scomAddress,
                                               i_scomData,
                                               i_operation,
                                               &l_entryDat );
                }
                else
                {
                    l_rc    =   updateScomEntry( i_pImage,
                                                 i_scomAddress,
                                                 i_scomData,
                                                 i_section,
                                                 i_operation,
                                                 &l_entryDat );
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
               "0x%08x", i_operation, l_quadId ,
               i_scomAddress );
    }
    else
    {

    }

    MY_INF( "<< proc_stop_save_scom" );

    return l_rc;
}

//-----------------------------------------------------------------------------------------------------

StopReturnCode_t proc_stop_save_cpureg_control(  void* i_pImage,
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
    uint32_t * l_pTempWord          =   NULL;
    Homerlayout_t* l_pHomer         =   NULL;
    SmfSprRestoreRegion_t * l_pSpr  =   NULL;
    MY_INF(">> proc_stop_save_cpureg_control" );

    do
    {
        l_rc    =   getCoreAndThread_p10( i_pImage, i_pir, &l_coreId, &l_threadId );

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

        l_pHomer        =   ( Homerlayout_t * )i_pImage;
        l_pSpr          =   ( SmfSprRestoreRegion_t *) &l_pHomer->iv_cpmrRegion.iv_selfRestoreRegion.iv_coreSelfRestore[0];
        l_pSpr         +=   l_coreId;

        for( l_sprIndex = 0; l_sprIndex < MAX_SPR_SUPPORTED_P10; l_sprIndex++ )
        {
            l_sprPos    =    g_sprRegister_p10[l_sprIndex].iv_saveMaskPos;

            if( l_sprPos > MAX_SPR_BIT_POS )
            {
                continue;
            }

            //Check if a given SPR needs to be self-saved each time on STOP entry

            if( i_saveRegVector & ( TEST_BIT_PATTERN >> l_sprPos ) )
            {

                if( g_sprRegister_p10[l_sprIndex].iv_isThreadScope )
                {
                    l_lookupLength  =   SMF_SELF_SAVE_THREAD_AREA_SIZE;
                    l_pSaveStart    =
                        (uint32_t*)&l_pSpr->iv_threadSaveArea[l_threadId][0];
                    l_pRestoreStart =
                        (uint32_t*)&l_pSpr->iv_threadRestoreArea[l_threadId][0];
                }
                else
                {
                    l_lookupLength  =   SMF_CORE_SAVE_CORE_AREA_SIZE;
                    l_pSaveStart    =   (uint32_t*)&l_pSpr->iv_coreSaveArea[0];
                    l_pRestoreStart =   (uint32_t*)&l_pSpr->iv_coreRestoreArea[0];
                }

                // an SPR restore section for given core already exists
                l_lookUpKey   =   genKeyForSprLookup( ( CpuReg_t )g_sprRegister_p10[l_sprIndex].iv_sprId );

                l_rc          =   lookUpSprInImage( (uint32_t*)l_pRestoreStart, l_lookUpKey,
                                                    g_sprRegister_p10[l_sprIndex].iv_isThreadScope, &l_pTempLoc );

                if( l_rc )
                {
                    //SPR specified in the save mask but there is no restore entry present in the memory
                    //Self-Save instruction will edit it during STOP entry to make it a valid entry

                    l_rc = proc_stop_save_cpureg( i_pImage,
                                                (CpuReg_t)g_sprRegister_p10[l_sprIndex].iv_sprId,
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
                l_rc    =   updateSelfSaveEntry( l_pSprSave, g_sprRegister_p10[l_sprIndex].iv_sprId );

                if( l_rc )
                {
                    MY_ERR( "Failed to update self save instructions for 0x%08x",
                            (uint32_t) g_sprRegister_p10[l_sprIndex].iv_sprId );
                }

                if( l_pTempLoc )
                {
                    l_pTempWord      =   (uint32_t *)l_pTempLoc;
                    l_pTempWord++;
                    *l_pTempWord     =   getXorInstruction( 0, 0, 0 );
                }

            }// end if( i_saveRegVector..)
        }// end for
    }
    while(0);

    MY_INF("<< proc_stop_save_cpureg_control" );

    return l_rc;

}

//-----------------------------------------------------------------------------------------------------

StopReturnCode_t proc_stop_save_cpureg(  void* const i_pImage,
                                       const CpuReg_t  i_regId,
                                       const uint64_t  i_regData,
                                       const uint64_t  i_pir )
{
    StopReturnCode_t       l_rc         =   STOP_SAVE_SUCCESS;    // procedure return code
    SmfSprRestoreRegion_t* l_sprRegion  =   NULL;
    Homerlayout_t* l_pHomer             =   NULL;

    MY_INF(">> proc_stop_save_cpureg" );

    do
    {
        uint32_t threadId       =   0;
        uint32_t coreId         =   0;
        uint32_t lookUpKey      =   0;
        void* pSprEntryLocation =   NULL;   // an offset w.r.t. to start of image
        void* pThreadLocation   =   NULL;
        bool threadScopeReg     =   false;

        l_rc = getCoreAndThread_p10( i_pImage, i_pir, &coreId, &threadId );

        if( l_rc )
        {
            MY_ERR("Failed to determine Core Id and Thread Id from PIR 0x%016lx",
                   i_pir);
            break;
        }

        MY_INF( " PIR 0x%016lx coreId %d threadid %d "
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


        l_pHomer        =   ( Homerlayout_t *) i_pImage;
        l_sprRegion     =   ( SmfSprRestoreRegion_t* )&l_pHomer->iv_cpmrRegion.iv_selfRestoreRegion.iv_coreSelfRestore[0];
        l_sprRegion    +=   coreId;

        if( threadScopeReg )
        {
            pThreadLocation     =   (uint32_t *)&l_sprRegion->iv_threadRestoreArea[threadId][0];
        }
        else
        {
            pThreadLocation     =   (uint32_t *)&l_sprRegion->iv_coreRestoreArea[0];
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
                                     &pSprEntryLocation );
        }

        if( l_rc )
        {
            MY_ERR("Invalid or corrupt SPR entry. CoreId 0x%08x threadId "
                   "0x%08x regId 0x%08x lookUpKey 0x%08x "
                   , coreId, threadId, i_regId, lookUpKey );
            break;
        }

        l_rc = updateSprEntryInImage( (uint32_t*) pSprEntryLocation,
                                      i_regId,
                                      i_regData,
                                      UPDATE_SPR_ENTRY );

        if( l_rc )
        {
            MY_ERR( " Failed to update the SPR entry of PIR 0x%016lx reg"
                    "0x%08x", (uint64_t)i_pir, i_regId );
            break;
        }

    }
    while(0);

    MY_INF("<< proc_stop_save_cpureg" );

    return l_rc;
}

//-----------------------------------------------------------------------------------------------------

StopReturnCode_t proc_stop_init_self_save(  void* const i_pImage, const uint32_t i_corePos )
{

    SmfSprRestoreRegion_t * l_pSelfSave =   NULL;
    StopReturnCode_t    l_rc        =   STOP_SAVE_SUCCESS;
    uint32_t* l_pSaveStart          =   NULL;
    Homerlayout_t *  l_pHomer       =   NULL;
    uint32_t l_threadPos            =   0;
    uint32_t l_sprBitPos            =   0;
    uint32_t l_sprIndexAdj          =   0;

    MY_INF(">> proc_stop_init_self_save" );

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

        l_pHomer    =   ( Homerlayout_t* ) i_pImage;
        l_pSelfSave =
                ( SmfSprRestoreRegion_t  *) &l_pHomer->iv_cpmrRegion.iv_selfRestoreRegion.iv_coreSelfRestore[0];

        l_pSelfSave +=  i_corePos;

        for( l_threadPos = 0; l_threadPos < MAX_THREADS_PER_CORE; l_threadPos++ )
        {
            l_pSaveStart    =
                (uint32_t*)&l_pSelfSave->iv_threadSaveArea[l_threadPos][0];

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

                if( !g_sprRegister_p10[l_sprBitPos - l_sprIndexAdj].iv_isThreadScope )
                {
                    continue;
                }

                //Initialize self save region with SPR save entry for each thread
                //level SPR
                l_rc    =   initSelfSaveEntry( l_pSaveStart,
                                               g_sprRegister_p10[l_sprBitPos - l_sprIndexAdj].iv_saveMaskPos );

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
                (uint32_t*)&l_pSelfSave->iv_coreSaveArea[0];

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

            if( g_sprRegister_p10[l_sprBitPos - l_sprIndexAdj].iv_isThreadScope )
            {
                continue;
            }

            //Initialize self save region with SPR save entry for each core
            //level SPR
            l_rc    =   initSelfSaveEntry( l_pSaveStart,
                                           g_sprRegister_p10[l_sprBitPos - l_sprIndexAdj].iv_saveMaskPos );

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

    MY_INF("<< proc_stop_init_self_save" );

    return l_rc;
}

//-----------------------------------------------------------------------------------------------------
#ifdef __cplusplus
} //namespace stopImageSection ends
}  //extern "C"
#endif
