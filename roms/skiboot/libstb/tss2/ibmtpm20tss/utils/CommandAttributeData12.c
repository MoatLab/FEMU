/********************************************************************************/
/*										*/
/*			  Command Attributes Table for TPM 1.2			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2018 - 2019				*/
/*										*/
/********************************************************************************/


#include <ibmtss/tpmconstants12.h>

#include "CommandAttributes.h"
#if defined COMPRESSED_LISTS
#   define      PAD_LIST    0
#else
#   define      PAD_LIST    1
#endif

// This is the command code attribute array for GetCapability(). Both this array and
// s_commandAttributes provides command code attributes, but tuned for different purpose

/* bitfield is:
   
   command index
   reserved
   nv
   extensive
   flushed
   cHandles not included in HMAC
   rHandle not included in HMAC
   V
   reserved, flags TPM 1.2 command
*/
   
#include "tssccattributes.h"
const TPMA_CC_TSS    s_ccAttr12 [] = {
    
    /*                                  R  N  E  F  C  R  V  R */

    {{TPM_ORD_ActivateIdentity,		0, 0, 0, 0, 1, 0, 0, 1}},
    {{TPM_ORD_ContinueSelfTest,		0, 0, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_CreateEndorsementKeyPair,	0, 1, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_CreateWrapKey,		0, 0, 0, 0, 1, 0, 0, 1}},
    {{TPM_ORD_Extend,			0, 0, 0, 0, 1, 0, 0, 1}},
    {{TPM_ORD_FlushSpecific,		0, 0, 0, 0, 1, 0, 0, 1}},
    {{TPM_ORD_GetCapability,		0, 0, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_LoadKey2, 		0, 0, 0, 0, 1, 1, 0, 1}},
    {{TPM_ORD_MakeIdentity, 		0, 0, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_NV_DefineSpace, 		1, 1, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_NV_ReadValueAuth,		1, 0, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_NV_ReadValue,		1, 0, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_NV_WriteValue,		1, 1, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_NV_WriteValueAuth,	1, 1, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_OIAP, 			0, 0, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_OSAP, 			0, 0, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_OwnerReadInternalPub,	0, 0, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_OwnerSetDisable, 		0, 1, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_PcrRead,			0, 0, 0, 0, 1, 0, 0, 1}},
    {{TPM_ORD_PCR_Reset,		0, 0, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_ReadPubek, 		0, 0, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_Quote2, 			0, 0, 0, 0, 1, 0, 0, 1}},
    {{TPM_ORD_Sign, 			0, 0, 0, 0, 1, 0, 0, 1}},
    {{TPM_ORD_Startup, 			0, 1, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_TakeOwnership,		0, 0, 0, 0, 0, 0, 0, 1}},
    {{TPM_ORD_Init, 			0, 0, 0, 0, 0, 0, 0, 1}},

    {{0x0000, 				0, 0, 0, 0, 0, 0, 0, 0}},     // kg - terminator?
};

