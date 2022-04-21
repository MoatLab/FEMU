/********************************************************************************/
/*										*/
/*			  Command Attributes	   				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CommandAttributes.h 1289 2018-07-30 16:31:47Z kgoldman $	*/
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
/*  (c) Copyright IBM Corp. and others, 2012-2018				*/
/*										*/
/********************************************************************************/

#ifndef COMMANDATTRIBUTES_H
#define COMMANDATTRIBUTES_H

#include <ibmtss/TPM_Types.h>

#define IS_IMPLEMENTED 	0x0001
#define HANDLE_1_USER 	0x0002
#define HANDLE_1_ADMIN	0x0004
#define HANDLE_1_DUP	0x0008
#define HANDLE_2_USER	0x0010
#define PP_COMMAND	0x0020
#define PP_REQUIRED	0x0040
#define ALLOW_TRIAL	0x0080
#define NO_SESSIONS	0x0100
#define DECRYPT_2	0x0200
#define DECRYPT_4	0x0400
#define ENCRYPT_2	0x0800
#define ENCRYPT_4	0x1000
#define R_HANDLE	0x2000

typedef UINT32 COMMAND_ATTRIBUTES;

typedef union {
    struct {
	uint32_t commandCode;
	uint8_t reserved1;
	uint8_t nv;
	uint8_t extensive;
	uint8_t flushed;
	uint8_t cHandles;
	uint8_t rHandle;
	uint8_t V;
	uint8_t tpm12Ordinal;	/* kgold - was reserved, flags TPM 1.2 ordinal */
    };
    /* must be a union so the below 'bitfield' structure intiializer works */
    uint8_t dummy;
} TPMA_CC_TSS;

extern const TPMA_CC_TSS s_ccAttr [];
#ifdef TPM_TPM12
extern const TPMA_CC_TSS s_ccAttr12 [];
#endif

extern const COMMAND_ATTRIBUTES    s_commandAttributes [];

#endif

