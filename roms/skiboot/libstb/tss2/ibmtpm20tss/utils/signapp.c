/********************************************************************************/
/*										*/
/*			    Sign Application					*/
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

   Prerequisite: A provisioned EK certificate.  Use 'clientek' in the acs directory to provision a
   software TPM EK certificate.

   Program steps:

   Create an EK.  The EK would not normally be the storage root key, but this demonstrates use of a
   policy session, creating an EK primary key using the EK template, and validation of the EK
   against the EK certificate.

   Start a policy session, salt with EK

   Create a signing key, salted policy session
   
   Load the signing key, salted policy session

   Start an HMAC session, salt with EK, bind to signing key

   Sign a message, verify the signature

   Flush the signing key

   Flush the EK
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Windows 10 crypto API clashes with openssl */
#ifdef TPM_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/Unmarshal_fp.h>
#include "ekutils.h"
#include "objecttemplates.h"

#define KEYPWD	"keypwd" 

static TPM_RC startSession(TSS_CONTEXT *tssContext,
			   TPMI_SH_AUTH_SESSION *sessionHandle,
			   TPM_SE sessionType,
			   TPMI_DH_OBJECT tpmKey,
			   TPMI_DH_ENTITY bind,
			   const char *bindPassword);
static TPM_RC policyRestart(TSS_CONTEXT *tssContext,
			    TPMI_SH_AUTH_SESSION sessionHandle);
static TPM_RC policyCommandCode(TSS_CONTEXT *tssContext,
				TPM_CC	commandCode,
				TPMI_SH_AUTH_SESSION sessionHandle);
static TPM_RC policyAuthValue(TSS_CONTEXT *tssContext,
			      TPMI_SH_AUTH_SESSION sessionHandle);
static TPM_RC policyPassword(TSS_CONTEXT *tssContext,
			     TPMI_SH_AUTH_SESSION sessionHandle);
static TPM_RC policySecret(TSS_CONTEXT *tssContext,
			   TPMI_DH_ENTITY authHandle,
			   TPMI_SH_AUTH_SESSION sessionHandle);
static TPM_RC policyGetDigest(TSS_CONTEXT *tssContext,
			      TPMI_SH_AUTH_SESSION sessionHandle);
static TPM_RC createKey(TSS_CONTEXT *tssContext,
			TPM2B_PRIVATE *outPrivate,
			TPM2B_PUBLIC *outPublic,
			TPMI_SH_AUTH_SESSION policySessionHandle,
			TPM_HANDLE parentHandle,
			const char *keyPassword,
			int pwSession);
static TPM_RC loadKey(TSS_CONTEXT *tssContext,
		      TPM_HANDLE *keyHandle,
		      TPM_HANDLE parentHandle,
		      TPMI_SH_AUTH_SESSION policySessionHandle,
		      TPM2B_PRIVATE *outPrivate,
		      TPM2B_PUBLIC *outPublic,
		      int pwSession);
static TPM_RC sign(TSS_CONTEXT *tssContext,
		   TPMT_SIGNATURE *signature,
		   TPM_HANDLE keyHandle,
		   TPMI_SH_AUTH_SESSION sessionHandle,
		   uint32_t sizeInBytes,
		   TPMT_HA *messageDigest);
static TPM_RC verify(TSS_CONTEXT *tssContext,
		     TPM_HANDLE keyHandle,
		     uint32_t sizeInBytes,
		     TPMT_HA *messageDigest,
		     TPMT_SIGNATURE *signature);
static TPM_RC flush(TSS_CONTEXT *tssContext,
		    TPMI_DH_CONTEXT flushHandle);
static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    int 			pwSession = FALSE;		/* default HMAC session */
    const char 			*messageString = NULL;
    uint32_t 			sizeInBytes;
    TPMT_HA 			messageDigest;			/* digest of the message */
    TPMI_SH_AUTH_SESSION 	policySessionHandle = TPM_RH_NULL;
    TPMI_SH_AUTH_SESSION 	sessionHandle = TPM_RH_NULL;
    TPM_HANDLE 			ekKeyHandle = TPM_RH_NULL;	/* primary key handle */
    TPM2B_PRIVATE 		outPrivate;
    TPM2B_PUBLIC 		outPublic;
    TPM_HANDLE 			keyHandle = TPM_RH_NULL;	/* signing key handle */
    TPMT_SIGNATURE		signature;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-pwsess") == 0) {
	    pwSession = TRUE;
	}
	else if (strcmp(argv[i],"-ic") == 0) {
	    i++;
	    if (i < argc) {
		messageString = argv[i];
	    }
	    else {
		printf("-ic option needs a value\n");
		printUsage();
	    }
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
    if (messageString == NULL) {
	printf("Missing message -ic\n");
	printUsage();
    }
    /* hash the message file */
    if (rc == 0) {
	messageDigest.hashAlg = TPM_ALG_SHA256;
	/* hash algorithm mapped to size */
	sizeInBytes = TSS_GetDigestSize(messageDigest.hashAlg);
	rc = TSS_Hash_Generate(&messageDigest,
			       strlen(messageString), messageString,
			       0, NULL);
    }
    /* Start a TSS context */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Create a TSS context\n");
	rc = TSS_Create(&tssContext);
    }
    /* createprimary first for salt.  processPrimary() also reads the EK certificate and validates
       it against the primary key.  It doesn't walk the certificate chain.  */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Create a primary EK for the salt\n");
	rc = processPrimary(tssContext,
			    &ekKeyHandle,
			    EK_CERT_RSA_INDEX, EK_NONCE_RSA_INDEX, EK_TEMPLATE_RSA_INDEX,
			    TRUE, tssUtilsVerbose);		/* do not flush */
	if (tssUtilsVerbose) printf("INFO: Primary EK handle %08x\n", ekKeyHandle);
    }
    /* start a policy session */
    if (rc == 0) {
	TPM_HANDLE	saltHandle;
	if (tssUtilsVerbose) printf("INFO: Start a policy session\n");
	if (!pwSession) {
	    saltHandle = ekKeyHandle;
	}
	else {
	    saltHandle = TPM_RH_NULL;	/* primary key handle */
	}
	rc = startSession(tssContext,
			  &policySessionHandle,
			  TPM_SE_POLICY,
			  saltHandle, TPM_RH_NULL,	/* salt, no bind */
			  NULL);			/* no bind password */
	if (tssUtilsVerbose) printf("INFO: Policy session %08x\n", policySessionHandle);
    }
    /* EK needs policy secret with endorsement auth */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Satisfy the policy session %08x\n", policySessionHandle);
	rc = policySecret(tssContext,
			  TPM_RH_ENDORSEMENT,
			  policySessionHandle);
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Dump the policy session %08x\n", policySessionHandle);
	rc = policyGetDigest(tssContext,
			     policySessionHandle);
    }
    /* Create the signing key */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Create a signing key under the EK %08x\n", ekKeyHandle);
	rc = createKey(tssContext,
		       &outPrivate,
		       &outPublic,
		       policySessionHandle,	/* continue */
		       ekKeyHandle,		/* parent */
		       KEYPWD,			/* password for the signing key */
		       pwSession);
    }
    /* reuse the policy session to load the signing key under the EK storage key */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Restart the policy session %08x\n", policySessionHandle);
	rc = policyRestart(tssContext,
			   policySessionHandle);
    }
    /* EK needs policy secret with endorsement auth */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Satisfy the policy session %08x\n", policySessionHandle);
	rc = policySecret(tssContext,
			  TPM_RH_ENDORSEMENT,
			  policySessionHandle);
    }
    /* Load the signing key.  flush the policy session. */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Load a signing key under the EK %08x\n", ekKeyHandle);
	rc = loadKey(tssContext,
		     &keyHandle,		/* signing key */
		     ekKeyHandle,		/* parent */
		     policySessionHandle,	/* no flush */
		     &outPrivate,
		     &outPublic,
		     pwSession);
	if (tssUtilsVerbose) printf("INFO: Loaded key handle %08x\n", keyHandle);
    }
    /* start an HMAC session, salt with EK, bind with signing key */
    if (rc == 0) {
	if (!pwSession) {
	    if (tssUtilsVerbose) printf("INFO: Start a salt and bind session\n");
	    rc = startSession(tssContext,
			      &sessionHandle,	/* salt, bind */
			      TPM_SE_HMAC,
			      ekKeyHandle,	/* salt */
			      keyHandle,	/* bind */
			      KEYPWD);		/* bind with signing key password */

	    if (tssUtilsVerbose) printf("INFO: Salt and bind session %08x\n", sessionHandle);
	}
	else {
	    sessionHandle = TPM_RS_PW;
	}
    }
    /*
      sign and verify using an HMAC or password
    */
    /* Sign the message digest */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Sign with the signing key %08x\n", keyHandle);
	rc = sign(tssContext,
		  &signature,
		  keyHandle,		/* signing key */
		  sessionHandle,	/* continue */
		  sizeInBytes,		/* hash algorithm mapped to size */
		  &messageDigest);	/* digest of the message */
    }
    /* Verify the signature */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Verify the signature %08x\n", keyHandle);
	rc = verify(tssContext,
		    keyHandle,		/* verification public key */
		    sizeInBytes,	/* hash algorithm mapped to size */
		    &messageDigest,	/* digest of the message */
		    &signature);
    }
    /*
      sign and verify using a policy session, policy authvalue or policy password
    */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Restart the policy session %08x\n", policySessionHandle);
	rc = policyRestart(tssContext,
			   policySessionHandle);
    }
    /* policy command code */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Satisfy the policy session %08x\n", policySessionHandle);
	rc = policyCommandCode(tssContext,
			       TPM_CC_Sign,
			       policySessionHandle);
    }
    /* policy authvalue or policypassword */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Satisfy the policy session %08x\n", policySessionHandle);
	if (!pwSession) {
	    rc = policyAuthValue(tssContext,
				 policySessionHandle);
	}
	else {
	    rc = policyPassword(tssContext,
				policySessionHandle);
	}
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Dump the policy session %08x\n", policySessionHandle);
	rc = policyGetDigest(tssContext,
			     policySessionHandle);
    }
    /* Sign the message digest */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Sign with the signing key %08x\n", keyHandle);
	rc = sign(tssContext,
		  &signature,
		  keyHandle,		/* signing key */
		  policySessionHandle,	/* continue */
		  sizeInBytes,		/* hash algorithm mapped to size */
		  &messageDigest);	/* digest of the message */
    }
    /* Verify the signature */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("INFO: Verify the signature %08x\n", keyHandle);
	rc = verify(tssContext,
		    keyHandle,		/* verification public key */
		    sizeInBytes,	/* hash algorithm mapped to size */
		    &messageDigest,	/* digest of the message */
		    &signature);
    }
    /* flush the policy session, normally fails */
    if (policySessionHandle != TPM_RH_NULL) {
	if (tssUtilsVerbose) printf("INFO: Flush the policy session %08x\n", policySessionHandle);
	flush(tssContext, policySessionHandle);
    }
    /* flush the salt and bind session */
    if (!pwSession) {
	if (sessionHandle != TPM_RH_NULL) {
	    if (tssUtilsVerbose) printf("INFO: Flush the salt session %08x\n", sessionHandle);
	    flush(tssContext, sessionHandle);
	}
    }
    /* flush the primary key */
    if (ekKeyHandle != TPM_RH_NULL) {
	if (tssUtilsVerbose) printf("INFO: Flush the primary key %08x\n", ekKeyHandle);
	flush(tssContext, ekKeyHandle);
    }
    /* flush the signing key */
    if (keyHandle != TPM_RH_NULL) {
	if (tssUtilsVerbose) printf("INFO: Flush the signing key %08x\n", keyHandle);
	flush(tssContext, keyHandle);
    }
    {  
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	printf("signapp: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("signapp: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* startSession() starts either a policy or HMAC session.

   If tpmKey is not null, a salted session is used.

   If bind is not null, a bind session is used.
*/

static TPM_RC startSession(TSS_CONTEXT *tssContext,
			   TPMI_SH_AUTH_SESSION *sessionHandle,
			   TPM_SE sessionType,			/* policy or HMAC */
			   TPMI_DH_OBJECT tpmKey,		/* salt key, can be null */
			   TPMI_DH_ENTITY bind,			/* bind object, can be null */
			   const char *bindPassword)		/* bind object password, can be null */
{
    TPM_RC			rc = 0;
    StartAuthSession_In 	startAuthSessionIn;
    StartAuthSession_Out 	startAuthSessionOut;
    StartAuthSession_Extra	startAuthSessionExtra;
     
    /*	Start an authorization session */
    if (rc == 0) {
	startAuthSessionIn.tpmKey = tpmKey;			/* salt key */
	startAuthSessionIn.bind = bind;				/* bind object */
	startAuthSessionExtra.bindPassword = bindPassword;	/* bind object password */
	startAuthSessionIn.sessionType = sessionType;		/* HMAC or policy session */
	startAuthSessionIn.authHash = TPM_ALG_SHA256;		/* HMAC algorithm */
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

static TPM_RC policyRestart(TSS_CONTEXT *tssContext,
			    TPMI_SH_AUTH_SESSION sessionHandle)
{
    TPM_RC			rc = 0;
    PolicyRestart_In 		policyRestartIn;

    if (rc == 0) {
    	policyRestartIn.sessionHandle = sessionHandle;
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&policyRestartIn,
			 NULL,
			 TPM_CC_PolicyRestart,
			 TPM_RH_NULL, NULL, 0);
    }
    return rc;
}

static TPM_RC policyCommandCode(TSS_CONTEXT *tssContext,
				TPM_CC	commandCode,
				TPMI_SH_AUTH_SESSION sessionHandle)
{
    TPM_RC			rc = 0;
    PolicyCommandCode_In 	policyCommandCodeIn;

    if (rc == 0) {
 	policyCommandCodeIn.policySession = sessionHandle;
	policyCommandCodeIn.code = commandCode;
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&policyCommandCodeIn,
			 NULL,
			 TPM_CC_PolicyCommandCode,
			 TPM_RH_NULL, NULL, 0);
    }
    return rc;
}

static TPM_RC policyAuthValue(TSS_CONTEXT *tssContext,
			      TPMI_SH_AUTH_SESSION sessionHandle)
{
    TPM_RC		rc = 0;
    PolicyAuthValue_In 	policyAuthValueIn;

    if (rc == 0) {
	policyAuthValueIn.policySession = sessionHandle;
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&policyAuthValueIn,
			 NULL,
			 TPM_CC_PolicyAuthValue,
			 TPM_RH_NULL, NULL, 0);
    }
    return rc;
}

static TPM_RC policyPassword(TSS_CONTEXT *tssContext,
			     TPMI_SH_AUTH_SESSION sessionHandle)
{
    TPM_RC		rc = 0;
    PolicyPassword_In 	policyPasswordIn;

    if (rc == 0) {
 	policyPasswordIn.policySession = sessionHandle;
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&policyPasswordIn,
			 NULL,
			 TPM_CC_PolicyPassword,
			 TPM_RH_NULL, NULL, 0);
    }
    return rc;
}

/* policySecret() runs policy secret against the session.  It assumes that the secret (the
   endorsement authorization in this example) is Empty.

*/

static TPM_RC policySecret(TSS_CONTEXT *tssContext,
			   TPMI_DH_ENTITY authHandle,
			   TPMI_SH_AUTH_SESSION sessionHandle)
{
    TPM_RC			rc = 0;
    PolicySecret_In 		policySecretIn;
    PolicySecret_Out 		policySecretOut;
     
    if (rc == 0) {
	policySecretIn.authHandle = authHandle;
	policySecretIn.policySession = sessionHandle;
	policySecretIn.nonceTPM.b.size = 0;
	policySecretIn.cpHashA.b.size = 0;
	policySecretIn.policyRef.b.size = 0;
	policySecretIn.expiration = 0;
    }   
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&policySecretOut, 
			 (COMMAND_PARAMETERS *)&policySecretIn,
			 NULL,
			 TPM_CC_PolicySecret,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
    }
    return rc;
}

/* policyGetDigest() traces the session policy digest for debugging.  It should be the same as the
   policy in the EK template.
   
*/

static TPM_RC policyGetDigest(TSS_CONTEXT *tssContext,
			      TPMI_SH_AUTH_SESSION sessionHandle)
{
    TPM_RC			rc = 0;
    PolicyGetDigest_In 		policyGetDigestIn;
    PolicyGetDigest_Out 	policyGetDigestOut;
     
    if (rc == 0) {
	policyGetDigestIn.policySession = sessionHandle;
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&policyGetDigestOut, 
			 (COMMAND_PARAMETERS *)&policyGetDigestIn,
			 NULL,
			 TPM_CC_PolicyGetDigest,
			 TPM_RH_NULL, NULL, 0);
    }
    if (tssUtilsVerbose) TSS_PrintAll("policyGetDigest",
			      policyGetDigestOut.policyDigest.t.buffer,
			      policyGetDigestOut.policyDigest.t.size);
    return rc;
}

/* createKey() creates a signing key under the EK storage key parentHandle.

   policySessionHandle is a previously satisfied policy session.  continue is SET.

   A command decrypt session is used to transfer the signing key userAuth encrypted.  A response
   encrypt session is used just as a demo.

*/

static TPM_RC createKey(TSS_CONTEXT *tssContext,
			TPM2B_PRIVATE *outPrivate,
			TPM2B_PUBLIC *outPublic,
			TPMI_SH_AUTH_SESSION policySessionHandle,
			TPM_HANDLE parentHandle,
			const char *keyPassword,
			int pwSession)
{
    TPM_RC	rc = 0;
    Create_In 	createIn;
    Create_Out 	createOut;
    int 	attributes;
    /* hard code the policy since this test is also used for the no file support case */
    const uint8_t policy[] = {0x7e, 0xa1, 0x0d, 0xe0, 0x05, 0xfc, 0xb2, 0x1d,
			      0x44, 0xf2, 0x4b, 0xc8, 0xf7, 0x4c, 0x28, 0xa8,
			      0xb9, 0xed, 0xf1, 0x4b, 0x1c, 0x53, 0xea, 0x4c,
			      0xcf, 0x3c, 0x5a, 0x4c, 0xe3, 0x8c, 0x75, 0x6e};
    if (rc == 0) {
	createIn.parentHandle = parentHandle;
	rc = TSS_TPM2B_StringCopy(&createIn.inSensitive.sensitive.userAuth.b,
				  keyPassword,
				  sizeof(createIn.inSensitive.sensitive.userAuth.t.buffer));
    }
    /* policy command code sign + policy authvalue or policy password */
    if (rc == 0) {
	memcpy(&createIn.inPublic.publicArea.authPolicy.b.buffer, policy, sizeof(policy));
	createIn.inPublic.publicArea.authPolicy.b.size = sizeof(policy);
    }
    if (rc == 0) {
	createIn.inSensitive.sensitive.data.t.size = 0;
	createIn.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
	createIn.inPublic.publicArea.type = TPM_ALG_RSA;	/* for the RSA template */
	createIn.inPublic.publicArea.objectAttributes.val = 0;
	createIn.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
	createIn.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	createIn.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	createIn.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	createIn.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
	createIn.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
	createIn.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	createIn.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	createIn.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
	createIn.inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
	createIn.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
	createIn.inPublic.publicArea.unique.rsa.t.size = 0;
	createIn.outsideInfo.t.size = 0;
	createIn.creationPCR.count = 0;
	if (pwSession) {
	    attributes = TPMA_SESSION_CONTINUESESSION;
	}
	else {
	    attributes = TPMA_SESSION_ENCRYPT | TPMA_SESSION_DECRYPT | TPMA_SESSION_CONTINUESESSION;
	}
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&createOut,
			 (COMMAND_PARAMETERS *)&createIn,
			 NULL,
			 TPM_CC_Create,
			 policySessionHandle, NULL, attributes, 
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	*outPrivate = createOut.outPrivate;
	*outPublic = createOut.outPublic;
    }
    return rc;
}

/* loadKey() loads the signing key under the EK storage key parentHandle.

   policySessionHandle is a previously satisfied policy session.  continue is SET.

   A command decrypt and response encrypt session is used just as a demo.
*/

static TPM_RC loadKey(TSS_CONTEXT *tssContext,
		      TPM_HANDLE *keyHandle,
		      TPM_HANDLE parentHandle,
		      TPMI_SH_AUTH_SESSION policySessionHandle,
		      TPM2B_PRIVATE *outPrivate,
		      TPM2B_PUBLIC *outPublic,
		      int pwSession)
{
    TPM_RC	rc = 0;
    Load_In 	loadIn;
    Load_Out 	loadOut;
    int 	attributes;

    if (rc == 0) {
	loadIn.parentHandle = parentHandle;
	loadIn.inPrivate = *outPrivate;
	loadIn.inPublic = *outPublic;
	if (pwSession) {
	    attributes = TPMA_SESSION_CONTINUESESSION;
	}
	else {
	    attributes = TPMA_SESSION_DECRYPT | TPMA_SESSION_CONTINUESESSION;
	}
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&loadOut,
			 (COMMAND_PARAMETERS *)&loadIn,
			 NULL,
			 TPM_CC_Load,
			 policySessionHandle, NULL, attributes,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	*keyHandle = loadOut.objectHandle;
    }
    return rc;
}

/* sign() signs messageDigest with the signing key keyHandle.

   sessionHandle is a salt and bind session. continue is SET.

   Note that the signing key password is not supplied here.  It is supplied when the bind session is
   created.

*/

static TPM_RC sign(TSS_CONTEXT *tssContext,
		   TPMT_SIGNATURE *signature,
		   TPM_HANDLE keyHandle,
		   TPMI_SH_AUTH_SESSION sessionHandle,
		   uint32_t sizeInBytes,	/* hash algorithm mapped to size */
		   TPMT_HA *messageDigest)	/* digest of the message */
{
    TPM_RC			rc = 0;
    Sign_In 			signIn;
    Sign_Out 			signOut;
    const char 			*pwd;
    TPM_HT 			handleType = (TPM_HT) ((sessionHandle & HR_RANGE_MASK) >> HR_SHIFT);

    if (rc == 0) {
	signIn.keyHandle = keyHandle;
	signIn.digest.t.size = sizeInBytes;
	memcpy(&signIn.digest.t.buffer, (uint8_t *)&messageDigest->digest, sizeInBytes);
	signIn.inScheme.scheme = TPM_ALG_RSASSA;
	signIn.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
	signIn.validation.tag = TPM_ST_HASHCHECK;	/* optional, to make a ticket */
	signIn.validation.hierarchy = TPM_RH_NULL;
	signIn.validation.digest.t.size = 0;
	/* password session */
	if (sessionHandle == TPM_RS_PW) {
	    pwd = KEYPWD;
	}
	/* policy session is policy password or policy authvalue */
	else if (handleType == TPM_HT_POLICY_SESSION) {
	    pwd = KEYPWD;
	}
	/* HMAC session - bound (password ignored) */
	else {
	    pwd = NULL;
	}
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&signOut,
			 (COMMAND_PARAMETERS *)&signIn,
			 NULL,
			 TPM_CC_Sign,
			 /* bind, observe that no password is required here */
			 sessionHandle, pwd, TPMA_SESSION_CONTINUESESSION,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	*signature = signOut.signature;
    }
    return rc;
}

/* verify() verifies the signature against the message digest using the previously loaded key in
   keyHandle.

 */

static TPM_RC verify(TSS_CONTEXT *tssContext,
		     TPM_HANDLE keyHandle,
		     uint32_t sizeInBytes,	/* hash algorithm mapped to size */
		     TPMT_HA *messageDigest,	/* digest of the message */
		     TPMT_SIGNATURE *signature)
{
    TPM_RC			rc = 0;
    VerifySignature_In 		verifySignatureIn;
    VerifySignature_Out 	verifySignatureOut;

    if (rc == 0) {
	verifySignatureIn.keyHandle = keyHandle;
	verifySignatureIn.digest.t.size = sizeInBytes;
	memcpy(&verifySignatureIn.digest.t.buffer, (uint8_t *)&messageDigest->digest, sizeInBytes);
	verifySignatureIn.signature = *signature;
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&verifySignatureOut,
			 (COMMAND_PARAMETERS *)&verifySignatureIn,
			 NULL,
			 TPM_CC_VerifySignature,
			 TPM_RH_NULL, NULL, 0);
    }
    return rc;
}

/* flush() flushes some handle, either a session or the signing key in this demo.

 */

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

static void printUsage(void)
{
    printf("\n");
    printf("signapp\n");
    printf("\n");
    printf("Runs a TPM2_Sign application, including creating a primary storage key\n");
    printf("and creating and loading a signing key\n");
    printf("\n");
    printf("\t-ic\tinput message to hash and sign\n");
    printf("\n");
    printf("\t[-pwsess\tUse a password session, no HMAC or parameter encryption]\n");
    printf("\n");
    exit(1);	
}
