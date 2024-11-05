/* IBM_PROLOG_BEGIN_TAG                                                   */
/* This is an automatically generated prolog.                             */
/*                                                                        */
/* $Source: src/import/chips/p10/procedures/utils/stopreg/p10_cpu_reg_restore_instruction.H $ */
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
/// @file   p10_cpu_reg_restore_instruction.H
/// @brief  enumerates all the opcodes used for SPR restoration.
///
// *HWP HW Owner    :  Greg Still <stillgs@us.ibm.com>
// *HWP FW Owner    :  Prem Shanker Jha <premjha2@in.ibm.com>
// *HWP Team        :  PM
// *HWP Level       :  2
// *HWP Consumed by :  HB:HYP

#ifndef __REG_RESTORE_INSTRUCTION_H
#define __REG_RESTORE_INSTRUCTION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {

namespace stopImageSection
{
#endif

/**
 * @brief enumerates opcodes for few instructions.
 */
enum
{
    ORI_OPCODE          =   24,
    RFI_OPCODE          =   19,
    RFI_CONST           =   50,
    MFMSR_CONST         =   83,
    ORIS_OPCODE         =   25,
    OPCODE_31           =   31,
    XOR_CONST           =   316,
    RLDICR_OPCODE       =   30,
    RLDICR_CONST        =   1,
    MTSPR_CONST1        =   467,
    MTMSRD_CONST1       =   178,
    MR_R0_TO_R10        =   0x7c0a0378, //mr r10, r0
    MR_R0_TO_R21        =   0x7c150378, //mr r21, r0
    MR_R0_TO_R9         =   0x7c090378, //mr r9, r0
    URMOR_CORRECTION    =   0x7d397ba6,
    MFSPR_CONST         =   339,
    BLR_INST            =   0x4e800020,
    MTSPR_BASE_OPCODE   =   0x7c0003a6,
    MFSPR_BASE_OPCODE   =   0x7c0002a6,
    ATTN_OPCODE         =   0x00000200,
    OPCODE_18           =   18,
    SELF_SAVE_FUNC_ADD  =   0x2300,
    SELF_SAVE_OFFSET    =   0x180,
    SKIP_SPR_REST_INST  =   0x4800001c, //b . +0x01c
    MFLR_R30            =   0x7fc802a6,
    SKIP_SPR_SELF_SAVE  =   0x3bff0020, //addi r31 r31, 0x20
    MTLR_INST           =   0x7fc803a6  //mtlr r30
};

#ifdef __cplusplus
} // namespace stopImageSection ends

} // extern "C"
#endif //__cplusplus

#endif //__REG_RESTORE_INSTRUCTION_H
