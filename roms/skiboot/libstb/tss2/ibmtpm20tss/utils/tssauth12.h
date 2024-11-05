/********************************************************************************/
/*										*/
/*			     TSS Authorization 					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: tssauth12.h 1257 2018-06-27 20:52:08Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2018.						*/
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

/* This is not a public header.  It should not be used by applications. */

#ifndef TSS_AUTH12_H
#define TSS_AUTH12_H

#include <ibmtss/tss.h>
#include "Commands12_fp.h"
#include "tssccattributes12.h"

/* command and response authorization structures adapted for TPM 1.2 */

typedef struct {
    TPM_AUTHHANDLE 	sessionHandle;		/* the session handle */
    TPM_NONCE		nonce;			/* the session nonce, may be the Empty Buffer */
    TPMA_SESSION	sessionAttributes;	/* the session attributes */
    TPM_AUTHDATA	hmac;			/* authorization HMAC */
} TPMS_AUTH12_COMMAND;


typedef struct {
    TPM_NONCE		nonce;			/* the session nonce, may be the Empty Buffer */
    TPMA_SESSION	sessionAttributes;	/* the session attributes */
    TPM_AUTHDATA 	hmac;			/* authorization HMAC */
} TPMS_AUTH12_RESPONSE;

TPM_RC TSS_Marshal12(TSS_AUTH_CONTEXT *tssAuthContext,
		     COMMAND_PARAMETERS *in,
		     TPM_CC commandCode);

TPM_RC TSS_Unmarshal12(TSS_AUTH_CONTEXT *tssAuthContext,
		     RESPONSE_PARAMETERS *out);

TPM_RC TSS_SetCmdAuths12(TSS_AUTH_CONTEXT 	*tssAuthContext,
			 size_t			numSessions,
			 TPMS_AUTH12_COMMAND 	*authC[]);
TPM_RC TSS_GetRspAuths12(TSS_AUTH_CONTEXT *tssAuthContext,
			 size_t 		numSessions,
			 TPMS_AUTH12_RESPONSE	*authR[]);
TPM_RC TSS_GetRpBuffer12(TSS_AUTH_CONTEXT *tssAuthContext,
		       uint32_t *rpBufferSize,
			 uint8_t **rpBuffer,
			 size_t	numSessions);
TPM_RC TSS_SetEncAuthOffset0(TSS_AUTH_CONTEXT *tssAuthContext,
			     int16_t offset);
TPM_RC TSS_SetEncAuthOffset1(TSS_AUTH_CONTEXT *tssAuthContext,
			     int16_t offset);
TPM_RC TSS_GetEncAuths(TSS_AUTH_CONTEXT *tssAuthContext,
		       uint8_t		**encAuth0,
		       uint8_t		**encAuth1);
TPM_RC TSS_SetSessionNumber(TSS_AUTH_CONTEXT *tssAuthContext,
			    uint16_t sessionNumber);
TPM_RC TSS_GetSessionNumber(TSS_AUTH_CONTEXT *tssAuthContext,
			    uint16_t *sessionNumber);

#endif
