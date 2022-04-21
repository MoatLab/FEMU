/********************************************************************************/
/*										*/
/*			    TSS Primary API 					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2018.					*/
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

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <ibmtss/tss.h>
#include "tssproperties.h"
#include <ibmtss/tsstransmit.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>
#ifndef TPM_TSS_NOCRYPTO
#include <ibmtss/tsscrypto.h>
#include <ibmtss/tsscryptoh.h>
#endif
#include <ibmtss/tssprintcmd.h>
#ifdef TPM_TPM20
#include "tss20.h"
#endif
#ifdef TPM_TPM12
#include "tss12.h"
#endif

/* local prototypes */

static TPM_RC TSS_Context_Init(TSS_CONTEXT *tssContext);

extern int tssVerbose;
extern int tssVverbose;
extern int tssFirstCall;

/* TSS_Create() creates and initializes the TSS Context.  It does NOT open a connection to the
   TPM.*/

TPM_RC TSS_Create(TSS_CONTEXT **tssContext)
{
    TPM_RC		rc = 0;

    /* allocate the high level TSS structure */
    if (rc == 0) {
	/* set to NULL for backward compatibility, caller may not have set tssContext to NULL before
	   the call */
	*tssContext = NULL;
	rc = TSS_Malloc((unsigned char **)tssContext, sizeof(TSS_CONTEXT));
    }
    /* initialize the high level TSS structure */
    if (rc == 0) {
	rc = TSS_Context_Init(*tssContext);
	/* the likely cause of a failure is a bad environment variable */
	if (rc != 0) {
	    if (tssVerbose) printf("TSS_Create: TSS_Context_Init() failed\n");
	    free(*tssContext);
	    *tssContext = NULL;
	}
    }
    /* allocate and initialize the lower layer TSS context */
    if (rc == 0) {
	rc = TSS_AuthCreate(&((*tssContext)->tssAuthContext));
    }
    return rc;
}

/* TSS_Context_Init() on first call is used for any global library initialization.

   On every call, it initializes the TSS context.
*/

static TPM_RC TSS_Context_Init(TSS_CONTEXT *tssContext)
{
    TPM_RC		rc = 0;
#ifndef TPM_TSS_NOCRYPTO
#ifndef TPM_TSS_NOFILE
    size_t		tssSessionEncKeySize;
    size_t		tssSessionDecKeySize;
#endif
#endif
    /* at the first call to the TSS, initialize global variables */
    if (tssFirstCall) {		/* tssFirstCall is a library global */
#ifndef TPM_TSS_NOCRYPTO
	/* crypto module initializations, crypto library specific */
	if (rc == 0) {
	    rc = TSS_Crypto_Init();
	}
#endif
	/* TSS properties that are global, not per TSS context */
	if (rc == 0) {
	    rc = TSS_GlobalProperties_Init();
	}
	tssFirstCall = FALSE;
    }
    /* TSS properties that are per context */
    if (rc == 0) {
	rc = TSS_Properties_Init(tssContext);
    }
#ifndef TPM_TSS_NOCRYPTO
#ifndef TPM_TSS_NOFILE
    /* crypto library dependent code to allocate the session state encryption and decryption keys.
       They are probably always the same size, but it's safer not to assume that. */
    if (rc == 0) {
	rc = TSS_AES_GetEncKeySize(&tssSessionEncKeySize);
    }
    if (rc == 0) {
	rc = TSS_AES_GetDecKeySize(&tssSessionDecKeySize);
    }
    if (rc == 0) {
        rc = TSS_Malloc((uint8_t **)&tssContext->tssSessionEncKey, tssSessionEncKeySize);
    }
    if (rc == 0) {
        rc = TSS_Malloc((uint8_t **)&tssContext->tssSessionDecKey, tssSessionDecKeySize);
    }
    /* build the session encryption and decryption keys */
    if (rc == 0) {
	rc = TSS_AES_KeyGenerate(tssContext->tssSessionEncKey,
				 tssContext->tssSessionDecKey);
    }
#endif
#endif
    return rc;
}

/* TSS_Delete() closes an open TPM connection, then free the TSS context memory.
 */

TPM_RC TSS_Delete(TSS_CONTEXT *tssContext)
{
    TPM_RC rc = 0;

    if (tssContext != NULL) {
	TSS_AuthDelete(tssContext->tssAuthContext);
#ifdef TPM_TSS_NOFILE
	{
	    size_t i;
	    for (i = 0 ; i < (sizeof(tssContext->sessions) / sizeof(TSS_SESSIONS)) ; i++) {
		tssContext->sessions[i].sessionHandle = TPM_RH_NULL;
		/* erase any secrets */
		memset(tssContext->sessions[i].sessionData,
		       0, tssContext->sessions[i].sessionDataLength);
		free(tssContext->sessions[i].sessionData);
		tssContext->sessions[i].sessionData = NULL;
		tssContext->sessions[i].sessionDataLength = 0;
	    }
	}
#endif
#ifndef TPM_TSS_NOCRYPTO
#ifndef TPM_TSS_NOFILE
	free(tssContext->tssSessionEncKey);
	free(tssContext->tssSessionDecKey);
#endif
#endif
	rc = TSS_Close(tssContext);
	free(tssContext);
    }
    return rc;
}

/* TSS_Execute() performs the complete command / response process.

   It sends the command specified by commandCode and the parameters 'in', returning the response
   parameters 'out'.

   ... varargs are

   TPMI_SH_AUTH_SESSION sessionHandle,
   const char *password,
   unsigned int sessionAttributes

   Terminates with TPM_RH_NULL, NULL, 0

   Processes up to MAX_SESSION_NUM sessions.
*/

TPM_RC TSS_Execute(TSS_CONTEXT *tssContext,
		   RESPONSE_PARAMETERS *out,
		   COMMAND_PARAMETERS *in,
		   EXTRA_PARAMETERS *extra,
		   TPM_CC commandCode,
		   ...)
{
    TPM_RC		rc = 0;
    va_list		ap;
    int 		tpm20Command;
    int 		tpm12Command;

    if (rc == 0) {
	tpm20Command = (((commandCode >= TPM_CC_FIRST) && (commandCode <=TPM_CC_LAST)) || /* base */
			((commandCode >= 0x20000000) && (commandCode <= 0x2000ffff)));	/* vendor */
	tpm12Command = ((commandCode <= 0x000000ff) ||		/* base */
			((commandCode >= 0x40000000) && (commandCode <= 0x4000ffff)));	/* TSC */
	if (!tpm20Command && !tpm12Command) {
	    if (tssVerbose) printf("TSS_Execute: commandCode %08x unsupported\n",
				   commandCode);
	    rc = TSS_RC_COMMAND_UNIMPLEMENTED;
	    
	}
	if (tpm20Command && tpm12Command) {
	    if (tssVerbose) printf("TSS_Execute: commandCode %08x is both TPM 1.2 and TPM 2.0\n",
				   commandCode);
	    rc = TSS_RC_FAIL;
	}
    }
    if (rc == 0) {
	va_start(ap, commandCode);
	if (tpm20Command) {
#ifdef TPM_TPM20
	    tssContext->tpm12Command = FALSE;
	    rc = TSS_Execute20(tssContext,
			       out,
			       in,
			       (EXTRA_PARAMETERS *)extra,
			       commandCode,
			       ap);
#else
	    if (tssVerbose) printf("TSS_Execute: commandCode is TPM 1.2, TSS is TPM 2.0 only\n");
	    rc = TSS_RC_COMMAND_UNIMPLEMENTED;
#endif
	}
	if (tpm12Command) {
#ifdef TPM_TPM12
	    tssContext->tpm12Command = TRUE;
	    rc = TSS_Execute12(tssContext,
			       out,
			       in,
			       (EXTRA12_PARAMETERS *)extra,
			       commandCode,
			       ap);
#else
	    if (tssVerbose) printf("TSS_Execute: commandCode is TPM 2.0, TSS is TPM 1.2 only\n");
	    rc = TSS_RC_COMMAND_UNIMPLEMENTED;
#endif
	}	
	va_end(ap);
    }
    return rc;
}


