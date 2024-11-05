/********************************************************************************/
/*										*/
/*			    NV Write Application				*/
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

/* 
   Demo application, and test of "no file TSS"

   Create an EK for the salt

   Start a session, salt with EK

   Define an NV index, salted session

   Flush the session

   Start a session, salt with EK, bind to unwritten NV index

   Write NV, changes the Name, bound, salt, encrypt session

   Start a session, salt with EK, bind to written NV index
   
   Write NV, bound, salt, encrypt session

   Undefine NV index

   Flush EK
*/

#define NVINDEX 0x01000000
#define NVPWD	"pwd" 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssutils.h>
#include "ekutils.h"
#include "cryptoutils.h"

static TPM_RC nvReadPublic(TSS_CONTEXT *tssContext);
static TPM_RC startSession(TSS_CONTEXT *tssContext,
			   TPMI_SH_AUTH_SESSION *sessionHandle,
			   TPMI_DH_OBJECT tpmKey,
			   TPMI_DH_ENTITY bind);
static TPM_RC flush(TSS_CONTEXT *tssContext,
		    TPMI_DH_CONTEXT flushHandle);
static TPM_RC defineSpace(TSS_CONTEXT *tssContext,
			  TPMI_SH_AUTH_SESSION sessionHandle);
static TPM_RC nvWrite(TSS_CONTEXT *tssContext,
		      TPMI_SH_AUTH_SESSION sessionHandle);
static TPM_RC undefineSpace(TSS_CONTEXT *tssContext,
			    TPMI_SH_AUTH_SESSION sessionHandle);
			   
static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    TSS_CONTEXT			*tssContext = NULL;
    int 			pwSession = FALSE;		/* default HMAC session */
    TPM_HANDLE 			ekKeyHandle = TPM_RH_NULL;	/* primary key handle */
    TPMI_SH_AUTH_SESSION 	sessionHandle = TPM_RH_NULL;
 
    int				i;    /* argc iterator */

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-pwsess") == 0) {
	    pwSession = TRUE;
	}
	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    tssUtilsVerbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
#ifdef TPM_TSS_NOCRYPTO
    if (!pwSession) {
	printf("\n-pwsess is required when compiled for no crypto\n");
	printUsage();
    }
#endif
    /* Start a TSS context */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Create a TSS context\n");
	rc = TSS_Create(&tssContext);
    }
#ifndef TPM_TSS_NOCRYPTO
    /* createprimary first for salt.  processPrimary() also reads the EK certificate and validates
       it against the primary key.   It doesn't walk the certificate chain.  */
    if (rc == 0) {
	if (!pwSession) {
	    if (tssUtilsVerbose) printf("INFO: Create a primary EK for the salt\n");
	    rc = processPrimary(tssContext,
				&ekKeyHandle,
				EK_CERT_RSA_INDEX, EK_NONCE_RSA_INDEX, EK_TEMPLATE_RSA_INDEX,
				TRUE, tssUtilsVerbose);		/* do not flush */
	}
    }
#endif	/* TPM_TSS_NOCRYPTO */
    /* start a session, salt with EK, unbound */
    if (rc == 0) {
	if (!pwSession) {
	    if (tssUtilsVerbose) printf("INFO: Start a salt session\n");
	    rc = startSession(tssContext,
			      &sessionHandle,
			      ekKeyHandle, TPM_RH_NULL);	/* salt, no bind */
	}
	else {
	    sessionHandle = TPM_RS_PW;
	}
    }
    /* Probe to see if the index already exists.  NOTE: A real application would test that the
       NV metadata or Name was correct for the application. */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Read the NV index at %08x\n", NVINDEX);
	rc = nvReadPublic(tssContext);
	/* on failure, define the index */
	if (rc != 0) {
	    if (tssUtilsVerbose) printf("INFO: Create the NV index at %08x\n", NVINDEX);
	    rc = defineSpace(tssContext, sessionHandle);
	}
    }
    /* flush the salt session */
    if (!pwSession) {
	if (tssUtilsVerbose) printf("INFO: Flush the salt session\n");
	flush(tssContext, sessionHandle);
    }
    /* start a session, salt with EK, bind with unwritten NV index */
    if (rc == 0) {
	if (!pwSession) {
	    if (tssUtilsVerbose) printf("INFO: Start a salt and bind session\n");
	    rc = startSession(tssContext,
			      &sessionHandle,
			      ekKeyHandle, NVINDEX);	/* salt, bind */
	}
	else {
	    sessionHandle = TPM_RS_PW;
	}
    }
    /* first write, changes the Name (flushes the session)*/
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Write the index and written bit\n");
	rc = nvWrite(tssContext, sessionHandle);
    }
    /* start a session, salt, bind.  The previous session can't be used (with no password) since the
       first write changed the Name.  Thus the session is no longer bound to the index.  The write
       could specify a password, but the point is to test bind. */
    if (rc == 0) {
	if (!pwSession) {
	    if (tssUtilsVerbose) printf("INFO: Start a salt and bind session\n");
	    rc = startSession(tssContext,
			      &sessionHandle,
			      ekKeyHandle, NVINDEX);	/* salt, bind */
	}
	else {
	    sessionHandle = TPM_RS_PW;
	}
    }
    /* second write, note that the Name change is tracked */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Write the index\n");
	rc = nvWrite(tssContext, sessionHandle);
    }
    /* undefine NV index */
    if (tssUtilsVerbose) printf("INFO: Undefine the index\n");
    undefineSpace(tssContext, TPM_RS_PW);
    /* flush the session */
    if (!pwSession) {
	if (tssUtilsVerbose) printf("INFO: Flush the session\n");
	flush(tssContext, sessionHandle);
	/* flush the primary key */
	if (tssUtilsVerbose) printf("INFO: Flush the primary key\n");
	flush(tssContext, ekKeyHandle);
    }
    {
	TPM_RC rc1;
	if (tssUtilsVerbose) printf("INFO: Delete the TSS context\n");
	rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	printf("writeapp: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("writeapp: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static TPM_RC nvReadPublic(TSS_CONTEXT *tssContext)
{
    TPM_RC			rc = 0;
    NV_ReadPublic_In 		in;
    NV_ReadPublic_Out		out;

    if (rc == 0) {
	in.nvIndex = NVINDEX;
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_NV_ReadPublic,
			 TPM_RH_NULL, NULL, 0);
    }
    return rc;
}

static TPM_RC startSession(TSS_CONTEXT *tssContext,
			   TPMI_SH_AUTH_SESSION *sessionHandle,
			   TPMI_DH_OBJECT tpmKey,		/* salt key */
			   TPMI_DH_ENTITY bind)			/* bind object */
{
    TPM_RC			rc = 0;
    StartAuthSession_In 	startAuthSessionIn;
    StartAuthSession_Out 	startAuthSessionOut;
    StartAuthSession_Extra	startAuthSessionExtra;
     
    /*	Start an authorization session */
    if (rc == 0) {
	startAuthSessionIn.tpmKey = tpmKey;		/* salt key */
	startAuthSessionIn.bind = bind;			/* bind object */
	startAuthSessionExtra.bindPassword = NVPWD;	/* bind password */
	startAuthSessionIn.sessionType = TPM_SE_HMAC;	/* HMAC session */
	startAuthSessionIn.authHash = TPM_ALG_SHA256;	/* HMAC SHA-256 */
	startAuthSessionIn.symmetric.algorithm = TPM_ALG_AES;	/* parameter encryption */
	startAuthSessionIn.symmetric.keyBits.aes = 128;
	startAuthSessionIn.symmetric.mode.aes = TPM_ALG_CFB;
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&startAuthSessionOut, 
			 (COMMAND_PARAMETERS *)&startAuthSessionIn,
			 (EXTRA_PARAMETERS *)&startAuthSessionExtra,
			 TPM_CC_StartAuthSession,
			 TPM_RH_NULL, NULL, 0);
	*sessionHandle = startAuthSessionOut.sessionHandle;
    }
    return rc;
}

static TPM_RC flush(TSS_CONTEXT *tssContext,
		    TPMI_DH_CONTEXT flushHandle)
{
    TPM_RC			rc = 0;
    FlushContext_In 		in;

    if (rc == 0) {
	in.flushHandle = flushHandle;
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
    }
    return rc;
}

static TPM_RC defineSpace(TSS_CONTEXT *tssContext,
			  TPMI_SH_AUTH_SESSION sessionHandle)
{
    TPM_RC			rc = 0;
    NV_DefineSpace_In 		in;

    if (rc == 0) {
	rc = TSS_TPM2B_StringCopy(&in.auth.b,
				  NVPWD, sizeof(in.auth.t.buffer));
    }
    if (rc == 0) {
	in.authHandle = TPM_RH_OWNER;
	in.publicInfo.nvPublic.authPolicy.t.size = 0;	/* default empty policy */
	in.publicInfo.nvPublic.nvIndex = NVINDEX;	/* the handle of the data area */
	in.publicInfo.nvPublic.nameAlg = TPM_ALG_SHA256;/* hash algorithm used to compute the name */
	in.publicInfo.nvPublic.attributes.val = TPMA_NVA_NO_DA |
						TPMA_NVA_AUTHWRITE | TPMA_NVA_AUTHREAD |
						TPMA_NVA_ORDINARY;
	in.publicInfo.nvPublic.dataSize = 1;
	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_NV_DefineSpace,
			 /* Empty owner auth */
			 sessionHandle, NULL, TPMA_SESSION_CONTINUESESSION,
			 TPM_RH_NULL, NULL, 0);
	
    }
    return rc;
}

static TPM_RC nvWrite(TSS_CONTEXT *tssContext,
		      TPMI_SH_AUTH_SESSION sessionHandle)
{
    TPM_RC			rc = 0;
    NV_Write_In			nvWriteIn;
    const char 			*pwd;

    /* NV write */
    if (rc == 0) {
	nvWriteIn.authHandle = NVINDEX;		/* use index authorization */
	nvWriteIn.nvIndex = NVINDEX;		/* NV index to write */
	nvWriteIn.data.t.size = 1;		/* one byte */
	nvWriteIn.data.t.buffer[0] = 0xff;	/* data */
	nvWriteIn.offset = 0;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	/* password session */
	if (sessionHandle == TPM_RS_PW) {
	    pwd = NVPWD;
	}
	/* NULL password, bound (password ignored), encrypt the data */
	else {
	    pwd = NULL;
	}
	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&nvWriteIn,	
			 NULL,
			 TPM_CC_NV_Write,
			 sessionHandle, pwd, TPMA_SESSION_DECRYPT,
			 TPM_RH_NULL, NULL, 0);
    }
    return rc;
}

static TPM_RC undefineSpace(TSS_CONTEXT *tssContext,
			    TPMI_SH_AUTH_SESSION sessionHandle)
{
    TPM_RC		rc = 0;
    NV_UndefineSpace_In in;
    
    if (rc == 0) {
	in.authHandle = TPM_RH_OWNER;
	in.nvIndex = NVINDEX;
	rc = TSS_Execute(tssContext,
			 NULL,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_NV_UndefineSpace,
			 sessionHandle, NULL, TPMA_SESSION_CONTINUESESSION,
			 TPM_RH_NULL, NULL, 0);
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("writeapp\n");
    printf("\n");
    printf("writeapp is a sample NV write application.  Provisions an NV location,\n");
    printf("then does two writes with password 'pwd' using a bound, salted\n");
    printf("HMAC session using AES CFB parameter encryption.\n");
    printf("\n");
    printf("Used to test minimal TSS build\n");
    printf("\n");
    printf("\t[-pwsess\tUse a password session, no HMAC or parameter encryption]\n");
    printf("\n");
    exit(1);	
}
