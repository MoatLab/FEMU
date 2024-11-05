/********************************************************************************/
/*										*/
/*			     TSS Authorization 					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: tssauth.h 1257 2018-06-27 20:52:08Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2019.					*/
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

#ifndef TSS_AUTH_H
#define TSS_AUTH_H

#include <ibmtss/tss.h>
#include "tssccattributes.h"

/* Generic functions to marshal and unmarshal Part 3 ordinal command and response parameters */

typedef TPM_RC (*MarshalInFunction_t)(COMMAND_PARAMETERS *source,
				      uint16_t *written, BYTE **buffer, uint32_t *size);
typedef TPM_RC (*UnmarshalOutFunction_t)(RESPONSE_PARAMETERS *target,
					 TPM_ST tag, BYTE **buffer, uint32_t *size);
typedef TPM_RC (*UnmarshalInFunction_t)(COMMAND_PARAMETERS *target,
					BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);

/* The context for the entire command processor.  Update TSS_InitAuthContext() when changing
   this structure */

typedef struct TSS_AUTH_CONTEXT {
    uint8_t 		commandBuffer [MAX_COMMAND_SIZE];
    uint8_t 		responseBuffer [MAX_RESPONSE_SIZE];
    const char 		*commandText;
    COMMAND_INDEX    	tpmCommandIndex;	/* index into attributes table */
    TPM_CC 		commandCode;
    TPM_RC 		responseCode;
    size_t		commandHandleCount;
    uint32_t 		responseHandleCount;
    uint16_t		authCount;		/* authorizations in command */
    uint16_t 		commandSize;
    uint32_t 		cpBufferSize;
    uint8_t 		*cpBuffer;
    uint32_t 		responseSize;
    MarshalInFunction_t    marshalInFunction;
    UnmarshalOutFunction_t unmarshalOutFunction;
#ifndef TPM_TSS_NOCMDCHECK	/* disable command parameter checking */
    UnmarshalInFunction_t  unmarshalInFunction;
#endif
#ifdef TPM_TPM12
    uint16_t		sessionNumber;		/* session used for ADIP, zero based */
    int16_t		encAuthOffset0;		/* offset to first TPM_ENCAUTH parameter */
    int16_t		encAuthOffset1;		/* offset to second TPM_ENCAUTH parameter if not NULL */
#endif
} TSS_AUTH_CONTEXT;

TPM_RC TSS_AuthCreate(TSS_AUTH_CONTEXT **tssAuthContext);

void TSS_InitAuthContext(TSS_AUTH_CONTEXT *tssAuthContext);

TPM_RC TSS_AuthDelete(TSS_AUTH_CONTEXT *tssAuthContext);

TPM_CC TSS_GetCommandCode(TSS_AUTH_CONTEXT *tssAuthContext);

TPM_RC TSS_GetCpBuffer(TSS_AUTH_CONTEXT *tssAuthContext,
		       uint32_t *cpBufferSize,
		       uint8_t **cpBuffer);


TPM_RC TSS_GetCommandHandleCount(TSS_AUTH_CONTEXT *tssAuthContext,
				 size_t *commandHandleCount);

TPM_RC TSS_AuthExecute(TSS_CONTEXT *tssContext);

#endif
