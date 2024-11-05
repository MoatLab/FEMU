/********************************************************************************/
/*										*/
/*			   TSS Primary API 					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
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

#ifndef TSS_H
#define TSS_H

#include <ibmtss/TPM_Types.h>
#include <ibmtss/Parameters.h>
#include <ibmtss/Parameters12.h>

/* include this as a convenience to applications */
#include <ibmtss/tsserror.h>
#include <ibmtss/tssprint.h>

typedef struct TSS_CONTEXT TSS_CONTEXT; 
   
#define TPM_TRACE_LEVEL		1
#define TPM_DATA_DIR		2
#define TPM_COMMAND_PORT	3
#define TPM_PLATFORM_PORT	4
#define TPM_SERVER_NAME		5
#define TPM_INTERFACE_TYPE	6
#define TPM_DEVICE		7
#define TPM_ENCRYPT_SESSIONS	8
#define TPM_SERVER_TYPE		9

#ifdef __cplusplus
extern "C" {
#endif

    /* extra parameters as required */

    /* TPM 2.0 */

    typedef struct {
	const char 		*bindPassword;
	TPM2B_DIGEST 		salt;
    } StartAuthSession_Extra;
	
    typedef union {
	StartAuthSession_Extra 	StartAuthSession;
    } EXTRA_PARAMETERS;

    /* TPM 1.2 */

    typedef struct {
	const char 	*usagePassword;
    } OSAP_Extra;
	
    typedef union {
	OSAP_Extra 	OSAP;
    } EXTRA12_PARAMETERS;
    
    LIB_EXPORT
    TPM_RC TSS_Create(TSS_CONTEXT **tssContext);

    LIB_EXPORT
    TPM_RC TSS_Delete(TSS_CONTEXT *tssContext);

    LIB_EXPORT
    TPM_RC TSS_Execute(TSS_CONTEXT *tssContext,
		       RESPONSE_PARAMETERS *out,	
		       COMMAND_PARAMETERS *in,
		       EXTRA_PARAMETERS *extra,
		       TPM_CC commandCode,
		       ...);

    LIB_EXPORT
    TPM_RC TSS_SetProperty(TSS_CONTEXT *tssContext,
			   int property,
			   const char *value);

#ifdef __cplusplus
}
#endif

#endif
