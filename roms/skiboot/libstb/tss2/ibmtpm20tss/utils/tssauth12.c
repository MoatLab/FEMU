/********************************************************************************/
/*										*/
/*			     TPM 1.2 TSS Authorization				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2018 - 2019.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* This layer handles command and response packet authorization parameters. */

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <ibmtss/tsserror.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>

#include <ibmtss/tsstransmit.h>
#include "tssproperties.h"
#include <ibmtss/tssresponsecode.h>

#include <ibmtss/tpmtypes12.h>
#include <ibmtss/tpmconstants12.h>
#include <ibmtss/tssmarshal12.h>
#include <ibmtss/Unmarshal12_fp.h>

#include "tssauth12.h"

extern int tssVerbose;
extern int tssVverbose;

typedef struct MARSHAL_TABLE {
    TPM_CC 			commandCode;
    const char 			*commandText;
    MarshalInFunction_t 	marshalInFunction;	/* marshal input command */
    UnmarshalOutFunction_t 	unmarshalOutFunction;	/* unmarshal output response */
#ifndef TPM_TSS_NOCMDCHECK
    UnmarshalInFunction_t	unmarshalInFunction;	/* unmarshal input command for parameter
							   checking */
#endif
} MARSHAL_TABLE;

static const MARSHAL_TABLE marshalTable12 [] = {
				 
    {TPM_ORD_ActivateIdentity,"TPM_ORD_ActivateIdentity",
     (MarshalInFunction_t)TSS_ActivateIdentity_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_ActivateIdentity_Out_Unmarshalu,
     (UnmarshalInFunction_t)ActivateIdentity_In_Unmarshal},

    {TPM_ORD_ContinueSelfTest,"TPM_ORD_ContinueSelfTest",
     (MarshalInFunction_t)NULL,
     (UnmarshalOutFunction_t)NULL,
     (UnmarshalInFunction_t)NULL},

    {TPM_ORD_CreateEndorsementKeyPair,"TPM_ORD_CreateEndorsementKeyPair",
     (MarshalInFunction_t)TSS_CreateEndorsementKeyPair_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_CreateEndorsementKeyPair_Out_Unmarshalu,
     (UnmarshalInFunction_t)CreateEndorsementKeyPair_In_Unmarshal},

    {TPM_ORD_CreateWrapKey,"TPM_ORD_CreateWrapKey",
     (MarshalInFunction_t)TSS_CreateWrapKey_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_CreateWrapKey_Out_Unmarshalu,
     (UnmarshalInFunction_t)CreateWrapKey_In_Unmarshal},

    {TPM_ORD_Extend,"TPM_ORD_Extend",
     (MarshalInFunction_t)TSS_Extend_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_Extend_Out_Unmarshalu,
     (UnmarshalInFunction_t)Extend_In_Unmarshal},

    {TPM_ORD_FlushSpecific,"TPM_ORD_FlushSpecific",
     (MarshalInFunction_t)TSS_FlushSpecific_In_Marshalu,
     (UnmarshalOutFunction_t)NULL,
     (UnmarshalInFunction_t)FlushSpecific_In_Unmarshal},

    {TPM_ORD_GetCapability,"TPM_ORD_GetCapability",
     (MarshalInFunction_t)TSS_GetCapability12_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_GetCapability12_Out_Unmarshalu,
     (UnmarshalInFunction_t)GetCapability12_In_Unmarshal},

    {TPM_ORD_LoadKey2,"TPM_ORD_LoadKey2",
     (MarshalInFunction_t)TSS_LoadKey2_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_LoadKey2_Out_Unmarshalu,
     (UnmarshalInFunction_t)LoadKey2_In_Unmarshal},

    {TPM_ORD_MakeIdentity,"TPM_ORD_MakeIdentity",
     (MarshalInFunction_t)TSS_MakeIdentity_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_MakeIdentity_Out_Unmarshalu,
     (UnmarshalInFunction_t)MakeIdentity_In_Unmarshal},

    {TPM_ORD_NV_DefineSpace,"TPM_ORD_NV_DefineSpace",
     (MarshalInFunction_t)TSS_NV_DefineSpace12_In_Marshalu,
     NULL,
     (UnmarshalInFunction_t)NV_DefineSpace12_In_Unmarshal},

    {TPM_ORD_NV_ReadValueAuth,"TPM_ORD_NV_ReadValueAuth",
     (MarshalInFunction_t)TSS_NV_ReadValueAuth_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_NV_ReadValueAuth_Out_Unmarshalu,
     (UnmarshalInFunction_t)NV_ReadValueAuth_In_Unmarshal},

    {TPM_ORD_NV_ReadValue,"TPM_ORD_NV_ReadValue",
     (MarshalInFunction_t)TSS_NV_ReadValue_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_NV_ReadValue_Out_Unmarshalu,
     (UnmarshalInFunction_t)NV_ReadValue_In_Unmarshal},

    {TPM_ORD_NV_WriteValue,"TPM_ORD_NV_WriteValue",
     (MarshalInFunction_t)TSS_NV_WriteValue_In_Marshalu,
     NULL,
     (UnmarshalInFunction_t)NV_WriteValue_In_Unmarshal},

    {TPM_ORD_NV_WriteValueAuth,"TPM_ORD_NV_WriteValueAuth",
     (MarshalInFunction_t)TSS_NV_WriteValueAuth_In_Marshalu,
     NULL,
     (UnmarshalInFunction_t)NV_WriteValueAuth_In_Unmarshal},

    {TPM_ORD_OIAP,"TPM_ORD_OIAP",
     (MarshalInFunction_t)NULL,
     (UnmarshalOutFunction_t)TSS_OIAP_Out_Unmarshalu,
     (UnmarshalInFunction_t)NULL},

    {TPM_ORD_OSAP,"TPM_ORD_OSAP",
     (MarshalInFunction_t)TSS_OSAP_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_OSAP_Out_Unmarshalu,
     (UnmarshalInFunction_t)OSAP_In_Unmarshal},

    {TPM_ORD_OwnerReadInternalPub,"TPM_ORD_OwnerReadInternalPub",
     (MarshalInFunction_t)TSS_OwnerReadInternalPub_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_OwnerReadInternalPub_Out_Unmarshalu,
     (UnmarshalInFunction_t)OwnerReadInternalPub_In_Unmarshal},

    {TPM_ORD_OwnerSetDisable,"TPM_ORD_OwnerSetDisable",
     (MarshalInFunction_t)TSS_OwnerSetDisable_In_Marshalu,
     NULL,
     (UnmarshalInFunction_t)OwnerSetDisable_In_Unmarshal},

    {TPM_ORD_MakeIdentity,"TPM_ORD_MakeIdentity",
     (MarshalInFunction_t)TSS_MakeIdentity_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_MakeIdentity_Out_Unmarshalu,
     (UnmarshalInFunction_t)MakeIdentity_In_Unmarshal},

    {TPM_ORD_PcrRead,"TPM_ORD_PcrRead",
     (MarshalInFunction_t)TSS_PcrRead12_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_PcrRead12_Out_Unmarshalu,
     (UnmarshalInFunction_t)PcrRead12_In_Unmarshal},

    {TPM_ORD_PCR_Reset,"TPM_ORD_PCR_Reset",
     (MarshalInFunction_t)TSS_PCR_Reset12_In_Marshalu,
     NULL,
     (UnmarshalInFunction_t)PCR_Reset12_In_Unmarshal},

    {TPM_ORD_Quote2,"TPM_ORD_Quote2",
     (MarshalInFunction_t)TSS_Quote2_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_Quote2_Out_Unmarshalu,
     (UnmarshalInFunction_t)Quote2_In_Unmarshal},

    {TPM_ORD_ReadPubek,"TPM_ORD_ReadPubek",
     (MarshalInFunction_t)TSS_ReadPubek_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_ReadPubek_Out_Unmarshalu,
     (UnmarshalInFunction_t)ReadPubek_In_Unmarshal},

    {TPM_ORD_Sign,"TPM_ORD_Sign",
     (MarshalInFunction_t)TSS_Sign12_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_Sign12_Out_Unmarshalu,
     (UnmarshalInFunction_t)Sign12_In_Unmarshal},

    {TPM_ORD_Startup,"TPM_ORD_Startup",
     (MarshalInFunction_t)TSS_Startup12_In_Marshalu,
     NULL,
     (UnmarshalInFunction_t)Startup12_In_Unmarshal},

    {TPM_ORD_TakeOwnership,"TPM_ORD_TakeOwnership",
     (MarshalInFunction_t)TSS_TakeOwnership_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_TakeOwnership_Out_Unmarshalu,
     (UnmarshalInFunction_t)TakeOwnership_In_Unmarshal},

     {TPM_ORD_Init,"TPM_ORD_Init",
     NULL,
     NULL,
     NULL},
};

/* TSS_MarshalTable12_Process() indexes into the command marshal table, and saves the marshal and
   unmarshal functions */


static TPM_RC TSS_MarshalTable12_Process(TSS_AUTH_CONTEXT *tssAuthContext,
					 TPM_CC commandCode)
{
    TPM_RC rc = 0;
    size_t index;
    int found = FALSE;

    /* get the command index in the dispatch table */
    for (index = 0 ; index < (sizeof(marshalTable12) / sizeof(MARSHAL_TABLE)) ; (index)++) {
	if (marshalTable12[index].commandCode == commandCode) {
	    found = TRUE;
	    break;
	}
    }
    if (found) {
	tssAuthContext->commandCode = commandCode;
	tssAuthContext->commandText = marshalTable12[index].commandText;
	tssAuthContext->marshalInFunction = marshalTable12[index].marshalInFunction;
	tssAuthContext->unmarshalOutFunction = marshalTable12[index].unmarshalOutFunction;
#ifndef TPM_TSS_NOCMDCHECK
	tssAuthContext->unmarshalInFunction = marshalTable12[index].unmarshalInFunction;
#endif
    }
    else {
	if (tssVerbose) printf("TSS_MarshalTable12_Process: "
			       "commandCode %08x not found in marshal table\n",
			       commandCode);
	rc = TSS_RC_COMMAND_UNIMPLEMENTED;
    }
    return rc;
}

/* TSS_Marshal12() marshals the input parameters into the TSS Authorization context.

   It also sets other member of the context in preparation for the rest of the sequence.  
*/

TPM_RC TSS_Marshal12(TSS_AUTH_CONTEXT *tssAuthContext,
		     COMMAND_PARAMETERS *in,
		     TPM_CC commandCode)
{
    TPM_RC 		rc = 0;
    TPM_TAG 		tag = TPM_TAG_RQU_COMMAND;	/* default until sessions are added */
    uint8_t 		*buffer;			/* for marshaling */
    uint8_t 		*bufferu;			/* for test unmarshaling */
    uint32_t 		size;
    
    /* index from command code to table and save marshal and unmarshal functions for this command */
    if (rc == 0) {
	rc = TSS_MarshalTable12_Process(tssAuthContext, commandCode);
    }
    /* get the number of command and response handles from the TPM table */
    if (rc == 0) {
	tssAuthContext->tpmCommandIndex = CommandCodeToCommandIndex12(commandCode);
	if (tssAuthContext->tpmCommandIndex == UNIMPLEMENTED_COMMAND_INDEX) {
	    if (tssVerbose) printf("TSS_Marshal12: "
				   "commandCode %08x not found in command attributes table\n",
				   commandCode);
	    rc = TSS_RC_COMMAND_UNIMPLEMENTED;
	}
    }
    if (rc == 0) {
	tssAuthContext->commandHandleCount =
	    getCommandHandleCount12(tssAuthContext->tpmCommandIndex);
	tssAuthContext->responseHandleCount =
	    getresponseHandleCount12(tssAuthContext->tpmCommandIndex);
    }
    if (rc == 0) {
	/* make a copy of the command buffer and size since the marshal functions move them */
	buffer = tssAuthContext->commandBuffer;
	size = MAX_COMMAND_SIZE;
	/* marshal header, preliminary tag and command size */
	rc = TSS_UINT16_Marshalu(&tag, &tssAuthContext->commandSize, &buffer, &size);
    }
    if (rc == 0) {
	uint32_t commandSize = tssAuthContext->commandSize;
	rc = TSS_UINT32_Marshalu(&commandSize, &tssAuthContext->commandSize, &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&commandCode, &tssAuthContext->commandSize, &buffer, &size);
    }    
    if (rc == 0) {
	/* save pointer to marshaled data for test unmarshal */
	bufferu = buffer +
		  tssAuthContext->commandHandleCount * sizeof(TPM_HANDLE);
	/* if there is a marshal function */
	if (tssAuthContext->marshalInFunction != NULL) {
	    /* if there is a structure to marshal */
	    if (in != NULL) {
		rc = tssAuthContext->marshalInFunction(in, &tssAuthContext->commandSize,
						       &buffer, &size);
	    }
	    /* caller error, no structure supplied to marshal */
	    else {
		if (tssVerbose)
		    printf("TSS_Marshal12: Command %08x requires command parameter structure\n",
			   commandCode);
		rc = TSS_RC_IN_PARAMETER;	
	    }
	}
	/* if there is no marshal function */
	else {
	    /* caller error, supplied structure but there is no marshal function */
	    if (in != NULL) {
		if (tssVerbose)
		    printf("TSS_Marshal12: Command %08x does not take command parameter structure\n",
			   commandCode);
		rc = TSS_RC_IN_PARAMETER;	
	    }
	    /* no marshal function and no command parameter structure is OK */
	}
    }
#ifndef TPM_TSS_NOCMDCHECK
    /* unmarshal to validate the input parameters */
    if ((rc == 0) && (tssAuthContext->unmarshalInFunction != NULL)) {
	COMMAND_PARAMETERS target;
	TPM_HANDLE 	handles[MAX_HANDLE_NUM];
	size = MAX_COMMAND_SIZE;
	rc = tssAuthContext->unmarshalInFunction(&target, &bufferu, &size, handles);
	if ((rc != 0) && tssVerbose) {
	    printf("TSS_Marshal12: Invalid command parameter\n");
	}
    }
#endif
    /* back fill the correct commandSize */
    if (rc == 0) {
	uint16_t written = 0;		/* dummy */
	uint32_t commandSize = tssAuthContext->commandSize;
	buffer = tssAuthContext->commandBuffer + sizeof(TPMI_ST_COMMAND_TAG);
	TSS_UINT32_Marshalu(&commandSize, &written, &buffer, NULL);
    }
    /* record the interim cpBuffer and cpBufferSize before adding authorizations */
    if (rc == 0) {
	uint32_t notCpBufferSize;
	
	/* cpBuffer does not include the header and handles */
	notCpBufferSize = sizeof(TPMI_ST_COMMAND_TAG) + sizeof (uint32_t) + sizeof(TPM_CC) +
			  (sizeof(TPM_HANDLE) * tssAuthContext->commandHandleCount);

	tssAuthContext->cpBuffer = tssAuthContext->commandBuffer + notCpBufferSize;
	tssAuthContext->cpBufferSize = tssAuthContext->commandSize - notCpBufferSize;
    }
    return rc;
}

/* TSS_Unmarshal12() unmarshals the response parameter.

   It returns an error if either there is no unmarshal function and out is not NULL or if there is
   an unmarshal function and out is not NULL.

   If there is no unmarshal function and out is NULL, the function is a noop.
*/

TPM_RC TSS_Unmarshal12(TSS_AUTH_CONTEXT *tssAuthContext,
		       RESPONSE_PARAMETERS *out)
{
    TPM_RC 	rc = 0;
    TPM_TAG 	tag;
    uint8_t 	*buffer;    
    uint32_t 	size;

    /* if there is an unmarshal function */
    if (tssAuthContext->unmarshalOutFunction != NULL) {
	/* if there is a structure to unmarshal */
	if (out != NULL) {
	    if (rc == 0) {
		/* get the response tag, determines whether there are response authorizations to
		   unmarshal */
		/* tag not required for TPM 1.2, where there is no parameterSize to skip, but the
		   response unmarshal function uses a common prototype */
		buffer = tssAuthContext->responseBuffer;
		size = tssAuthContext->responseSize;
		rc = TSS_TPM_TAG_Unmarshalu(&tag, &buffer, &size);
	    }
	    if (rc == 0) {
		/* move the buffer and size past the header */
		buffer = tssAuthContext->responseBuffer +
			 sizeof(TPM_TAG) + sizeof(uint32_t) + sizeof(TPM_RC);
		size = tssAuthContext->responseSize -
		       (sizeof(TPM_TAG) + sizeof(uint32_t) + sizeof(TPM_RC));
		rc = tssAuthContext->unmarshalOutFunction(out, tag, &buffer, &size);
	    }
	}
	/* caller error, no structure supplied to unmarshal */
	else {
	    if (tssVerbose)
		printf("TSS_Unmarshal12: Command %08x requires response parameter structure\n",
		       tssAuthContext->commandCode);
	    rc = TSS_RC_OUT_PARAMETER;
	}
    }
    /* if there is no unmarshal function */
    else {
	/* caller error, structure supplied but no unmarshal function */
	if (out != NULL) {
	    if (tssVerbose)
		printf("TSS_Unmarshal12: Command %08x does not take response parameter structure\n",
		       tssAuthContext->commandCode);
	    rc = TSS_RC_OUT_PARAMETER;
	}
	/* no unmarshal function and no response parameter structure is OK */
    }
    return rc;
}

/* TSS_SetCmdAuths12() appends a list of TPMS_AUTH12_COMMAND structures to the command buffer.  It
   back fills the tag and paramSize.

*/

TPM_RC TSS_SetCmdAuths12(TSS_AUTH_CONTEXT 	*tssAuthContext,
			 size_t 		numSessions,
			 TPMS_AUTH12_COMMAND 	*authC[])
{
    TPM_RC 		rc = 0;
    size_t		i = 0;
    TPM_TAG 		tag;
    uint32_t 		cpBufferSize;
    uint8_t 		*cpBuffer;
    uint8_t 		*buffer;

    if (rc == 0) {
	/* record the number of authorizations for the response */
	tssAuthContext->authCount = numSessions;
	switch (numSessions) {
	  case 0:
	    tag = TPM_TAG_RQU_COMMAND;
	    break;
	  case 1:
	    tag = TPM_TAG_RQU_AUTH1_COMMAND;
	    break;
	  case 2:
	    tag = TPM_TAG_RQU_AUTH2_COMMAND;
	    break;
	  default:
	    if (tssVerbose) printf("TSS_SetCmdAuths12: Invalid number of sessions %u\n",
				   (unsigned int)numSessions);
	    rc = TSS_RC_MALFORMED_RESPONSE;
	}
    }
    /* back fill the tag */
    if (rc == 0) {
	uint16_t written = 0;		/* dummy */
	buffer = tssAuthContext->commandBuffer;
	TSS_UINT16_Marshalu(&tag, &written, &buffer, NULL);
    }
    /* get cpBuffer, command parameters */
    if (rc == 0) {
	rc = TSS_GetCpBuffer(tssAuthContext, &cpBufferSize, &cpBuffer);
    }
    /* index to the beginning of the authorization area, and range check the command buffer */
    if (rc == 0) {
	cpBuffer += cpBufferSize;
    }
    for (i = 0 ; (rc == 0) && (i < numSessions) ; i++) {
	uint16_t written = 0;
	uint32_t size = MAX_COMMAND_SIZE - cpBufferSize;
	/* marshal authHandle */
	if (rc == 0) {
	    rc = TSS_UINT32_Marshalu(&authC[i]->sessionHandle, &written, &cpBuffer, &size); 
	}
	/* marshal nonceOdd */
	if (rc == 0) {
	    rc = TSS_Array_Marshalu(authC[i]->nonce, SHA1_DIGEST_SIZE,
				   &written, &cpBuffer, &size); 
	}
	/* marshal attributes */
	if (rc == 0) {
	    rc = TSS_UINT8_Marshalu(&authC[i]->sessionAttributes.val, &written, &cpBuffer, &size);
	}
	/* marshal HMAC */
	if (rc == 0) {
	    rc = TSS_Array_Marshalu(authC[i]->hmac, SHA1_DIGEST_SIZE,
				   &written, &cpBuffer, &size); 
	}
    }	
    if (rc == 0) {
	uint16_t written = 0;		/* dummy */
	uint32_t commandSize;
	/* record command stream used size */
	tssAuthContext->commandSize = cpBuffer - tssAuthContext->commandBuffer;
	/* back fill the correct commandSize */
	buffer = tssAuthContext->commandBuffer + sizeof(TPMI_ST_COMMAND_TAG);
	commandSize = tssAuthContext->commandSize;
	TSS_UINT32_Marshalu(&commandSize, &written, &buffer, NULL);
    }
    return rc;
}

/* TSS_GetRspAuths12() unmarshals a response buffer into a list of list of TPMS_AUTH12_RESPONSE
   structures.  This should not be called if the TPM returned a non-success response code.

   Returns an error if the number of response auths requested is not equal to the number of command
   auths, including zero.

   If the response tag is TPM_TAG_RSP_COMMAND, the function is a noop (except for error checking).
*/

TPM_RC TSS_GetRspAuths12(TSS_AUTH_CONTEXT 	*tssAuthContext,
			 size_t 		numSessions,
			 TPMS_AUTH12_RESPONSE	*authR[])
{
    TPM_RC 	rc = 0;
    size_t	i;
    TPM_TAG 	tag;
    uint32_t 	oneAuthAreaSize = SHA1_DIGEST_SIZE + 1 + SHA1_DIGEST_SIZE;
    uint32_t 	authBufferSize;
    uint8_t 	*authBuffer;

    /* range check the response buffer size before the subtraction below */
    if (rc == 0) {
	if ((sizeof(TPM_TAG) + sizeof(uint32_t) + sizeof(TPM_RC) +
	     (numSessions * oneAuthAreaSize)) <= tssAuthContext->responseSize) {
	    authBufferSize = tssAuthContext->responseSize -
			     (sizeof(TPM_TAG) + sizeof(uint32_t) + sizeof(TPM_RC));  
	}
	else {
	    if (tssVerbose) printf("TSS_GetRspAuths12: Invalid response size %u\n",
				   (unsigned int)tssAuthContext->responseSize);
	    rc = TSS_RC_MALFORMED_RESPONSE;
	}
    }
    /* unmarshal the response tag */
    if (rc == 0) {
	uint32_t size = tssAuthContext->responseSize;
  	uint8_t *buffer = tssAuthContext->responseBuffer;
	rc = TSS_TPM_TAG_Unmarshalu(&tag, &buffer, &size);
    }
    /* sanity check the response tag, range checking below */
    if (rc == 0) {
	switch (tag) {
	  case TPM_TAG_RSP_COMMAND:
	    if (numSessions != 0) {
		if (tssVerbose) printf("TSS_GetRspAuths12: Invalid number of sessions %u\n",
				       (unsigned int)numSessions);
		rc = TSS_RC_MALFORMED_RESPONSE;
	    }
	    break;
	  case TPM_TAG_RSP_AUTH1_COMMAND:
	    authBuffer = tssAuthContext->responseBuffer + tssAuthContext->responseSize 	/* end */
			 - oneAuthAreaSize;	/* minus one auth area */
	    authBufferSize = oneAuthAreaSize;
	    if (numSessions != 1) {
		if (tssVerbose) printf("TSS_GetRspAuths12: Invalid number of sessions %u\n",
				       (unsigned int)numSessions);
		rc = TSS_RC_MALFORMED_RESPONSE;
	    }
	    break;
	  case TPM_TAG_RSP_AUTH2_COMMAND:
	    authBuffer = tssAuthContext->responseBuffer + tssAuthContext->responseSize 	/* end */
			 - oneAuthAreaSize - oneAuthAreaSize ;	/* minus two auth areas */
	    authBufferSize = oneAuthAreaSize + oneAuthAreaSize;
	    if (numSessions != 2) {
		if (tssVerbose) printf("TSS_GetRspAuths12: Invalid number of sessions %u\n",
				       (unsigned int)numSessions);
		rc = TSS_RC_MALFORMED_RESPONSE;
	    }
	    break;
	  default:
	    if (tssVerbose) printf("TSS_GetRspAuths12: Bad tag %04x\n", tag);
	    rc = TSS_RC_MALFORMED_RESPONSE;
	    break;
	}
    }
    /* unmarshal into the TPMS_AUTH12_RESPONSE structures */
    for (i = 0 ; (rc == 0) && (i < numSessions) ; i++) {
	/* TPM 1.2 has fixed size auth area - nonceEven + continue + auth HMAC */
	if (rc == 0) {
	    rc = TSS_Array_Unmarshalu(authR[i]->nonce,
				     SHA1_DIGEST_SIZE, &authBuffer, &authBufferSize);
	}	
	if (rc == 0) {
	    rc = TSS_UINT8_Unmarshalu(&authR[i]->sessionAttributes.val, &authBuffer, &authBufferSize);
	}	
	if (rc == 0) {
	    rc = TSS_Array_Unmarshalu(authR[i]->hmac,
				     SHA1_DIGEST_SIZE, &authBuffer, &authBufferSize);
	}	
    }	
    return rc;
}

/* TSS_GetRpBuffer12() returns a pointer to the response parameter area.

   NOTE could move to execute so it only has to be done once.
*/

TPM_RC TSS_GetRpBuffer12(TSS_AUTH_CONTEXT *tssAuthContext,
			 uint32_t 	*rpBufferSize,
			 uint8_t 	**rpBuffer,
			 size_t		numSessions)
{
    TPM_RC 	rc = 0;
    uint32_t	headerSize = sizeof(TPM_TAG) + sizeof (uint32_t) + sizeof(TPM_RC) +
			     (sizeof(TPM_HANDLE) * tssAuthContext->responseHandleCount);
    uint32_t 	oneAuthAreaSize = SHA1_DIGEST_SIZE + 1 + SHA1_DIGEST_SIZE;
    
    if (rc == 0) {
	*rpBuffer = tssAuthContext->responseBuffer + headerSize;

	if (headerSize + (numSessions * oneAuthAreaSize) <= tssAuthContext->responseSize) {
	    *rpBufferSize =
		tssAuthContext->responseSize - headerSize - (numSessions * oneAuthAreaSize);
	}
	else {
	    if (tssVerbose) printf("TSS_GetRpBuffer12: "
				   "response size %u too small for number of sessions %u\n",
				   tssAuthContext->responseSize, (unsigned int)numSessions);
	    rc = TSS_RC_MALFORMED_RESPONSE;
	}
    }
    return rc;
}

/* TSS_SetEncAuth() are called from the TPM 1.2 command pre-processor to record the location(s) of
   the encrypted authorizations.

   Cannot range check here, because command parameters have not been marshaled yet.
   
   NOTE: This is a bit of a hack, depending on the location being a fixed distance from the
   beginning or end of the command buffer.  It could break if there is both a variable size argument
   before and a variable number of authorizations or variable size argument after the location.

   If this occurs, the pointers nust be set during marshaling, but this is more intrusive, requiring
   TSS_AUTH_CONTEXT to be passed into the marshaling code.

*/

TPM_RC TSS_SetEncAuthOffset0(TSS_AUTH_CONTEXT *tssAuthContext,
			     int16_t offset)
{
    tssAuthContext->encAuthOffset0 = offset;
    return 0;
}
TPM_RC TSS_SetEncAuthOffset1(TSS_AUTH_CONTEXT *tssAuthContext,
			     int16_t offset)
{
    tssAuthContext->encAuthOffset1 = offset;
    return 0;
}
TPM_RC TSS_GetEncAuths(TSS_AUTH_CONTEXT *tssAuthContext,
		       uint8_t		**encAuth0,
		       uint8_t		**encAuth1)
{
    TPM_RC rc = 0;
    
    if (tssAuthContext->encAuthOffset0 > 0) {
	if ((uint16_t)tssAuthContext->encAuthOffset0 < tssAuthContext->cpBufferSize) {
	    *encAuth0 = tssAuthContext->commandBuffer + tssAuthContext->encAuthOffset0;
	}
	else {
	    if (tssVerbose) printf("TSS_GetEncAuths: "
				   "encAuthOffset0 %d too large for command buffer %u\n",
				   tssAuthContext->encAuthOffset0, tssAuthContext->cpBufferSize);
	    rc = TSS_RC_MALFORMED_RESPONSE;
	}
    }
    else if (tssAuthContext->encAuthOffset0 < 0) {
	if ((uint16_t)(-tssAuthContext->encAuthOffset0) < tssAuthContext->commandSize) {
	    *encAuth0 = tssAuthContext->commandBuffer +
			tssAuthContext->commandSize + tssAuthContext->encAuthOffset0;
	}
	else {
	    if (tssVerbose) printf("TSS_GetEncAuths: "
				   "encAuthOffset0 %d too large for command buffer %u\n",
				   tssAuthContext->encAuthOffset0, tssAuthContext->commandSize);
	    rc = TSS_RC_MALFORMED_RESPONSE;
	}
    }
    else {
	*encAuth0 = NULL;
    }
    if (tssAuthContext->encAuthOffset1 > 0) {
	if ((uint16_t)tssAuthContext->encAuthOffset1 < tssAuthContext->cpBufferSize) {
	    *encAuth1 = tssAuthContext->commandBuffer + tssAuthContext->encAuthOffset1;
	}
	else {
	    if (tssVerbose) printf("TSS_GetEncAuths: "
				   "encAuthOffset1 %u too large for command buffer %u\n",
				   tssAuthContext->encAuthOffset1, tssAuthContext->cpBufferSize);
	    rc = TSS_RC_MALFORMED_RESPONSE;
	}
    }
    else if (tssAuthContext->encAuthOffset1 < 0) {
	if ((uint16_t)(-tssAuthContext->encAuthOffset1) < tssAuthContext->commandSize) {
	    *encAuth1 = tssAuthContext->commandBuffer +
			tssAuthContext->commandSize + tssAuthContext->encAuthOffset1;
	}
	else {
	    if (tssVerbose) printf("TSS_GetEncAuths: "
				   "encAuthOffset1 %d too large for command buffer %u\n",
				   tssAuthContext->encAuthOffset1, tssAuthContext->commandSize);
	    rc = TSS_RC_MALFORMED_RESPONSE;
	}
    }
    else {
	*encAuth1 = NULL;
    }
    return rc;
}

TPM_RC TSS_SetSessionNumber(TSS_AUTH_CONTEXT *tssAuthContext,
			   uint16_t sessionNumber)
{
    TPM_RC	rc = 0;
    
    tssAuthContext->sessionNumber = sessionNumber;
    if (sessionNumber > 1) {
	if (tssVerbose) printf("TSS_SetSessionNumber: %u out of range\n",
			       sessionNumber);
	rc = TSS_RC_SESSION_NUMBER;
    }
    return rc;
}
TPM_RC TSS_GetSessionNumber(TSS_AUTH_CONTEXT *tssAuthContext,
			    uint16_t *sessionNumber)
{
    *sessionNumber = tssAuthContext->sessionNumber;
    return 0;
}
