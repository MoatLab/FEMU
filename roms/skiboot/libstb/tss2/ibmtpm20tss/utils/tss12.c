/********************************************************************************/
/*										*/
/*			    TSS Primary API for TPM 1.2				*/
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

#include "tssauth.h"
#include <ibmtss/tss.h>
#include "tssproperties.h"
#include <ibmtss/tsstransmit.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tssprintcmd.h>
#include <ibmtss/tpmconstants12.h>
#include "tss12.h"
#include "tssauth12.h"

/* Files:

   hxxxxxxxx.bin - session context
*/

/* NOTE Synchronize with

   TSS_HmacSession12_InitContext
   TSS_HmacSession12_Unmarshal
   TSS_HmacSession12_Marshal
*/

typedef struct TSS_HMAC12_CONTEXT {
    TPM_AUTHHANDLE		authHandle;		/* the authorization session handle */
    TPM_NONCE			nonceEven;		/* from the TPM in response */
    TPM_NONCE			nonceEvenOSAP;		/* from the TPM for OSAP in response */
    TPMT_HA 			sharedSecret;		/* from KDF at OSAP session creation */
    /* uint16 */
    /* LSB is type of entityValue */
    /* MSB is ADIP encryption scheme */
    TPM_ENTITY_TYPE 		entityType;		/* The type of entity in use */
    UINT32 			entityValue; 		/* The selection value based on entityType,
							   e.g. a keyHandle #, TPM_RH_NULL for OIAP
							   session  */
    /* Items below this line are for the lifetime of one command.  They are not saved and loaded. */
    TPM_NONCE			nonceOdd;		/* from the TSS in command */
    TPM_NONCE			nonceOddOSAP;		/* from the TSS for OSAP in command */
    /* for TPM 1.2, OIAP SHA-1 of password, OSAP sharedSecret */
    TPMT_HA 			hmacKey;
} TSS_HMAC12_CONTEXT;


/* functions for command pre- and post- processing */

typedef TPM_RC (*TSS_PreProcessFunction_t)(TSS_CONTEXT *tssContext,
					   COMMAND_PARAMETERS *in,
					   EXTRA12_PARAMETERS *extra);
typedef TPM_RC (*TSS_ChangeAuthFunction_t)(TSS_CONTEXT *tssContext,
					   TSS_HMAC12_CONTEXT *session,
					   size_t handleNumber,
					   COMMAND_PARAMETERS *in);
typedef TPM_RC (*TSS_PostProcessFunction_t)(TSS_CONTEXT *tssContext,
					    COMMAND_PARAMETERS *in,
					    RESPONSE_PARAMETERS *out,
					    EXTRA12_PARAMETERS *extra);

static TPM_RC TSS_PR_CreateWrapKey(TSS_CONTEXT *tssContext,
				   CreateWrapKey_In *in,
				   void *extra);
static TPM_RC TSS_PR_MakeIdentity(TSS_CONTEXT *tssContext,
				  MakeIdentity_In *in,
				  void *extra);
static TPM_RC TSS_PR_NV_DefineSpace(TSS_CONTEXT *tssContext,
				    NV_DefineSpace_In *in,
				    void *extra);
#if 0
static TPM_RC TSS_PR_Seal(TSS_CONTEXT *tssContext,
			  Seal_in *In,
			  void *extra);
static TPM_RC TSS_PR_Sealx(TSS_CONTEXT *tssContext,
			   Sealx_in *In,
			   void *extra);

#endif
static TPM_RC TSS_PO_FlushSpecific(TSS_CONTEXT *tssContext,
				   FlushSpecific_In *in,
				   void *out,
				   void *extra);
static TPM_RC TSS_PR_OSAP(TSS_CONTEXT *tssContext,
			  OSAP_In *in,
			  OSAP_Extra *extra);
static TPM_RC TSS_PO_OIAP(TSS_CONTEXT *tssContext,
			  void *in,
			  OIAP_Out *out,
			  void *extra);
static TPM_RC TSS_PO_OSAP(TSS_CONTEXT *tssContext,
			  OSAP_In *in,
			  OSAP_Out *out,
			  OSAP_Extra *extra);

typedef struct TSS_TABLE {
    TPM_CC 			commandCode;
    TSS_PreProcessFunction_t	preProcessFunction;
    TSS_ChangeAuthFunction_t	changeAuthFunction;
    TSS_PostProcessFunction_t 	postProcessFunction;
} TSS_TABLE;

/* FIXME offsets
   changeauth +16, createownerdel, createkeydel -45
   createwrapkey +14, +34
   cmkcreatekey, changeauthowner +14
   changeauth 16
*/

/* session handles numbers
   #0 of 1 seal, sealx, createwrapkey, cmk_create, changeauthowner, del_ckd, del_cod, nv_define, createctr
   #1 of 2 changeauth
*/
   

static const TSS_TABLE tssTable [] = {
				 
    {TPM_ORD_Init, NULL, NULL, NULL},
    {TPM_ORD_ActivateIdentity, NULL, NULL, NULL},
    {TPM_ORD_ContinueSelfTest, NULL, NULL, NULL},
    {TPM_ORD_CreateWrapKey, (TSS_PreProcessFunction_t)TSS_PR_CreateWrapKey, NULL, NULL},
    {TPM_ORD_CreateEndorsementKeyPair, NULL, NULL, NULL},
    {TPM_ORD_Extend, NULL, NULL, NULL},
    {TPM_ORD_FlushSpecific, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_FlushSpecific},
    {TPM_ORD_GetCapability, NULL, NULL, NULL},
    {TPM_ORD_MakeIdentity, (TSS_PreProcessFunction_t)TSS_PR_MakeIdentity, NULL, NULL},
    {TPM_ORD_OIAP, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_OIAP},
    {TPM_ORD_OSAP, (TSS_PreProcessFunction_t)TSS_PR_OSAP, NULL, (TSS_PostProcessFunction_t)TSS_PO_OSAP},
    {TPM_ORD_OwnerReadInternalPub, NULL, NULL, NULL},
    {TPM_ORD_NV_DefineSpace, (TSS_PreProcessFunction_t)TSS_PR_NV_DefineSpace, NULL, NULL},
    {TPM_ORD_NV_ReadValue, NULL, NULL, NULL},
    {TPM_ORD_NV_ReadValueAuth, NULL, NULL, NULL},
    {TPM_ORD_NV_WriteValue, NULL, NULL, NULL},
    {TPM_ORD_NV_WriteValueAuth, NULL, NULL, NULL},
    {TPM_ORD_PcrRead, NULL, NULL, NULL},
    {TPM_ORD_PCR_Reset, NULL, NULL, NULL},
#if 0
    {TPM_ORD_Seal, (TSS_PreProcessFunction_t)TSS_PR_Seal, NULL, NULL},
    {TPM_ORD_Sealx, (TSS_PreProcessFunction_t)TSS_PR_Sealx, NULL, NULL},
#endif
    {TPM_ORD_Startup, NULL, NULL, NULL},
};

/* local prototypes */


static TPM_RC TSS_Execute12_valist(TSS_CONTEXT *tssContext,
				   COMMAND_PARAMETERS *in,
				   va_list ap);

static TPM_RC TSS_Command_PreProcessor(TSS_CONTEXT *tssContext,
				       TPM_CC commandCode,
				       COMMAND_PARAMETERS *in,
				       EXTRA12_PARAMETERS *extra);
static TPM_RC TSS_Response_PostProcessor(TSS_CONTEXT *tssContext,
					 COMMAND_PARAMETERS *in,
					 RESPONSE_PARAMETERS *out,
					 EXTRA12_PARAMETERS *extra);

static TPM_RC TSS_HmacSession12_GetContext(TSS_HMAC12_CONTEXT **session);
static void TSS_HmacSession12_InitContext(TSS_HMAC12_CONTEXT *session);
static void TSS_HmacSession12_FreeContext(TSS_HMAC12_CONTEXT *session);
static TPM_RC TSS_HmacSession12_SaveSession(TSS_CONTEXT *tssContext,
					    TSS_HMAC12_CONTEXT *session);
static TPM_RC TSS_HmacSession12_LoadSession(TSS_CONTEXT *tssContext,
					    TSS_HMAC12_CONTEXT *session,
					    TPM_AUTHHANDLE authHandle);
static TPM_RC TSS_HmacSession12_Marshal(TSS_HMAC12_CONTEXT *source,
					uint16_t *written,
					uint8_t **buffer,
					uint32_t *size);
static TPM_RC TSS_HmacSession12_DeleteSession(TSS_CONTEXT *tssContext,
					      TPM_AUTHHANDLE handle);
static TPM_RC TSS_HmacSession12_Unmarshal(TSS_HMAC12_CONTEXT *target,
					  uint8_t **buffer, uint32_t *size);
static TPM_RC TSS_HmacSession12_SetHMAC(TSS_AUTH_CONTEXT *tssAuthContext,
					size_t numSessions,
					TSS_HMAC12_CONTEXT *session[],
					TPMS_AUTH12_COMMAND *authCommand[],
					TPM_AUTHHANDLE sessionHandle[],
					unsigned int sessionAttributes[]);
static TPM_RC TSS_HmacSession12_Verify(TSS_AUTH_CONTEXT *tssAuthContext,
				       size_t		numSessions,
				       TSS_HMAC12_CONTEXT *session[],
				       TPMS_AUTH12_RESPONSE *authResponse[]);
static TPM_RC TSS_HmacSession12_Continue(TSS_CONTEXT *tssContext,
					 TSS_HMAC12_CONTEXT *session,
					 TPMS_AUTH12_RESPONSE *authR);
static TPM_RC TSS_Command_Decrypt(TSS_AUTH_CONTEXT *tssAuthContext,
				  struct TSS_HMAC12_CONTEXT *session[],
				  TPM_AUTHHANDLE sessionHandle[]);
static TPM_RC TSS_Command_DecryptXor(TSS_AUTH_CONTEXT *tssAuthContext,
				     TSS_HMAC12_CONTEXT *session,
				     uint8_t *encAuth,
				     int parameterNumber);

extern int tssVerbose;
extern int tssVverbose;

/* TSS_Execute12() performs the complete command / response process.

   It sends the command specified by commandCode and the parameters 'in', returning the response
   parameters 'out'.

   ... varargs are

   TPM_AUTHHANDLE authHandle,
   const char *password,
   unsigned int sessionAttributes

   Terminates with TPM_RH_NULL, NULL, 0

   Processes up to MAX_SESSION_NUM sessions.
*/

TPM_RC TSS_Execute12(TSS_CONTEXT *tssContext,
		     RESPONSE_PARAMETERS *out,
		     COMMAND_PARAMETERS *in,
		     EXTRA12_PARAMETERS *extra,
		     TPM_CC commandCode,
		     va_list ap)
{
    TPM_RC		rc = 0;

    /* create a TSS authorization context */
    if (rc == 0) {
	TSS_InitAuthContext(tssContext->tssAuthContext);
    }
    /* handle any command specific command pre-processing */
    if (rc == 0) {
	rc = TSS_Command_PreProcessor(tssContext,
				      commandCode,
				      in,
				      extra);
    }
    /* marshal input parameters */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute12: Command %08x marshal\n", commandCode);
	rc = TSS_Marshal12(tssContext->tssAuthContext,
			   in,
			   commandCode);
    }
    /* execute the command */
    if (rc == 0) {
	rc = TSS_Execute12_valist(tssContext, in, ap);
    }
    /* unmarshal the response parameters */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute12: Command %08x unmarshal\n", commandCode);
	rc = TSS_Unmarshal12(tssContext->tssAuthContext, out);
    }
    /* handle any command specific response post-processing */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute12: Command %08x post processor\n", commandCode);
	rc = TSS_Response_PostProcessor(tssContext,
					in,
					out,
					extra);
    }
    return rc;
}

/* TSS_Execute12_valist() transmits the marshaled command and receives the marshaled response.

   varargs are TPM_AUTHHANDLE sessionHandle, const char *password, unsigned int sessionAttributes

   Terminates with sessionHandle TPM_RH_NULL

   Processes up to MAX_SESSION_NUM sessions.  It handles HMAC generation and command and response
   parameter encryption.  It loads each session context, rolls nonces, and saves or deletes the
   session context.
*/

static TPM_RC TSS_Execute12_valist(TSS_CONTEXT *tssContext,
				   COMMAND_PARAMETERS *in,
				   va_list ap)
{
    TPM_RC		rc = 0;
    size_t		i = 0;
    size_t		numSessions = 0;

    /* the vararg parameters */
    TPM_AUTHHANDLE 	sessionHandle[MAX_SESSION_NUM];
    const char 		*password[MAX_SESSION_NUM];
    unsigned int	sessionAttributes[MAX_SESSION_NUM];

    /* structures filled in */
    TPMS_AUTH12_COMMAND authCommand[MAX_SESSION_NUM];
    TPMS_AUTH12_RESPONSE authResponse[MAX_SESSION_NUM];
    
    /* pointer to the above structures as used */
    TPMS_AUTH12_COMMAND *authC[MAX_SESSION_NUM];
    TPMS_AUTH12_RESPONSE *authR[MAX_SESSION_NUM];

    /* TSS sessions */
    TSS_HMAC12_CONTEXT 	*session[MAX_SESSION_NUM];

    in = in;
    ap = ap;
    
    /* Step 1: initialization */
    if (tssVverbose) printf("TSS_Execute12_valist: Step 1: initialization\n");
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) ; i++) {
	authC[i] = NULL;		/* array of TPMS_AUTH12_COMMAND structures, NULL for
					   TSS_SetCmdAuths */
	authR[i] = NULL;		/* array of TPMS_AUTH12_RESPONSE structures, NULL for
					   TSS_GetRspAuths */
	session[i] = NULL;		/* for free, used for HMAC and encrypt/decrypt sessions */
	/* the varargs list inputs */
	sessionHandle[i] = TPM_RH_NULL;
	password[i] = NULL;
	sessionAttributes[i] = 0;
    }
    /* Step 2: gather the command authorizations */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) ; i++) {
 	sessionHandle[i] = va_arg(ap, TPM_AUTHHANDLE);		/* first vararg is the session
								   handle */
	password[i] = va_arg(ap, const char *);			/* second vararg is the password */
	sessionAttributes[i] = va_arg(ap, unsigned int);	/* third argument is
								   sessionAttributes */
	sessionAttributes[i] &= 0xff;				/* is uint8_t */

	if (sessionHandle[i] != TPM_RH_NULL) {			/* varargs termination value */ 

	    if (tssVverbose) printf("TSS_Execute12_valist: Step 2: authorization %u\n",
				    (unsigned int)i);
	    if (tssVverbose) printf("TSS_Execute12_valist: session %u handle %08x\n",
				    (unsigned int)i, sessionHandle[i]);
	    /* make used, non-NULL for command and response varargs */
	    authC[i] = &authCommand[i];
	    authR[i] = &authResponse[i];

	    /* initialize a TSS HMAC session */
	    if (rc == 0) {
		rc = TSS_HmacSession12_GetContext(&session[i]);
	    }
	    /* load the session created by either OIAP or OSAP */
	    if (rc == 0) {
		rc = TSS_HmacSession12_LoadSession(tssContext, session[i], sessionHandle[i]);
	    }
	    if (rc == 0) {
		if (session[i]->entityValue == TPM_RH_NULL) {	/* if OIAP, use password */
		    if (password[i] != NULL) {	/* if a password was specified, hash it */
			/* hash the password, algorithm set to SHA-1 at initialization */
			rc = TSS_Hash_Generate(&session[i]->hmacKey,
					       strlen(password[i]), (unsigned char *)password[i],
					       0, NULL);
		    }
		    /* TPM 1.2 convention seems to use all zeros as a well known auth */
		    else {
			memset((uint8_t *)&session[i]->hmacKey.digest, 0, SHA1_DIGEST_SIZE);
		    }
		}
		else {		/* use shared secret from OSAP setup */
		    memcpy((uint8_t *)&session[i]->hmacKey.digest,
			   (uint8_t *)&session[i]->sharedSecret.digest, SHA1_DIGEST_SIZE);
		}
	    }
	}
	else {
	    numSessions = i;	/* record the number of auth sessions */
	    break;
	}
    }
    /* Step 3: Roll nonceOdd, save in the session context for the response */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	if (tssVverbose)
	    printf("TSS_Execute12_valist: Step 3: nonceOdd for session %08x\n", sessionHandle[i]);
	if (rc == 0) {
	    rc = TSS_RandBytes(session[i]->nonceOdd, SHA1_DIGEST_SIZE);
	    memcpy(authC[i]->nonce, session[i]->nonceOdd, SHA1_DIGEST_SIZE);
	}
    }
    /* Step 4: Calculate the HMAC key */
    /* not needed for TPM 1.2, HMAC key is either hash of password or OSAP shared secret, calculated
       in previous step */
    /* Step 5: TPM_ENCAUTH encryption */
    if ((rc == 0) && (numSessions > 0)) {
	if (tssVverbose) printf("TSS_Execute12_valist: Step 5: command ADIP encrypt\n");
	rc = TSS_Command_Decrypt(tssContext->tssAuthContext,
				 session,
				 sessionHandle);
    }
    /* Step 6: for each HMAC session, calculate cpHash, calculate the HMAC, and set it in
       TPMS_AUTH12_COMMAND */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute12_valist: Step 6: calculate HMACs\n");
	rc = TSS_HmacSession12_SetHMAC(tssContext->tssAuthContext,	/* TSS auth context */
				       numSessions, 
				       session,		/* TSS session contexts */
				       authC,		/* output: command authorizations */
				       sessionHandle,	/* list of session handles for the command */
				       sessionAttributes /* attributes for this command */
				       );
    }
    /* Step 7: set the command authorizations in the TSS command stream */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute12_valist: Step 7: set command authorizations\n");
	rc = TSS_SetCmdAuths12(tssContext->tssAuthContext,
			       numSessions, 
			       authC);
    }
    /* Step 8: process the command.  Normally returns the TPM response code. */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute12_valist: Step 8: process the command\n");
	rc = TSS_AuthExecute(tssContext);
    }
    /* Step 9: get the response authorizations from the TSS response stream */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute12_valist: Step 9: get response authorizations\n");
	rc = TSS_GetRspAuths12(tssContext->tssAuthContext,
			       numSessions, 
			       authR);
    }
    /* Step 10: process the response authorizations, validate the HMAC */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute12_valist: Step 10: verify HMAC\n");
#if 0
	for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	    rc = TSS_Command_ChangeAuthProcessor(tssContext, session[i], i, in);
	}
#endif
	if (rc == 0) {
	    rc = TSS_HmacSession12_Verify(tssContext->tssAuthContext, /* authorization
									 context */
					  numSessions, 
					  session,	/* TSS session context */
					  authR);	/* input: response authorization */
	}
    }
    /* Step 12: process the response continue flag */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	if (tssVverbose) printf("TSS_Execute12_valist: Step 12: process continue flag %08x\n",
				sessionHandle[i]);
	rc = TSS_HmacSession12_Continue(tssContext, session[i], authR[i]);
    }
    /* cleanup */
    for (i = 0 ; i < MAX_SESSION_NUM ; i++) {
	TSS_HmacSession12_FreeContext(session[i]);
    }
    return rc;
}

/*
  HMAC Session
*/

/* TSS_HmacSession12_GetContext() allocates and initializes a TSS_HMAC12_CONTEXT structure */

static TPM_RC TSS_HmacSession12_GetContext(TSS_HMAC12_CONTEXT **session)
{
    TPM_RC rc = 0;

    if (rc == 0) {
        rc = TSS_Malloc((uint8_t **)session, sizeof(TSS_HMAC12_CONTEXT));
    }
    if (rc == 0) {
	TSS_HmacSession12_InitContext(*session);
    }
    return rc;
}

/* TSS_HmacSession12_InitContext() initializes a TSS_HMAC12_CONTEXT structure */

static void TSS_HmacSession12_InitContext(TSS_HMAC12_CONTEXT *session)
{
    session->authHandle = TPM_RH_NULL;
    memset(session->nonceEven, 0, SHA1_DIGEST_SIZE);
    memset(session->nonceEvenOSAP, 0, SHA1_DIGEST_SIZE);
    memset(&session->sharedSecret.digest, 0, SHA1_DIGEST_SIZE);
    memset(session->nonceOdd, 0, SHA1_DIGEST_SIZE);
    memset(session->nonceOddOSAP, 0, SHA1_DIGEST_SIZE);
    session->hmacKey.hashAlg = TPM_ALG_SHA1;
    memset((uint8_t *)&session->hmacKey.digest, 0, SHA1_DIGEST_SIZE);
    return;
}

/* TSS_HmacSession12_FreeContext() initializes (to erase secrets) and frees a TSS_HMAC12_CONTEXT
   structure */

static void TSS_HmacSession12_FreeContext(TSS_HMAC12_CONTEXT *session)
{
    if (session != NULL) {
	TSS_HmacSession12_InitContext(session);
	free(session);
    }
    return;
}

/* TSS_HmacSession12_SaveSession() marshals, optionally encrypts, and saves a TSS_HMAC12_CONTEXT
   structure */ 

static TPM_RC TSS_HmacSession12_SaveSession(TSS_CONTEXT *tssContext,
					    TSS_HMAC12_CONTEXT *session)
{
    TPM_RC	rc = 0;
    uint8_t 	*buffer = NULL;		/* marshaled TSS_HMAC12_CONTEXT */
    uint16_t	written = 0;
    char	sessionFilename[TPM_DATA_DIR_PATH_LENGTH];
    uint8_t 	*outBuffer = NULL;
    uint32_t 	outLength;
    
    if (tssVverbose) printf("TSS_HmacSession12_SaveSession: handle %08x\n", session->authHandle);
    if (rc == 0) {
	rc = TSS_Structure_Marshal(&buffer,	/* freed @1 */
				   &written,
				   session,
				   (MarshalFunction_t)TSS_HmacSession12_Marshal);
    }
    if (rc == 0) {
	/* if the flag is set, encrypt the session state before store */
	if (tssContext->tssEncryptSessions) {
	    rc = TSS_AES_Encrypt(tssContext->tssSessionEncKey,
				 &outBuffer,   	/* output, freed @2 */
				 &outLength,	/* output */
				 buffer,	/* input */
				 written);	/* input */
	}
	/* else store the session state in plaintext */
	else {
	    outBuffer = buffer;
	    outLength = written;
	}
    }
    /* save the session in a hard coded file name hxxxxxxxx.bin where xxxxxxxx is the session
       handle */
    if (rc == 0) {
	sprintf(sessionFilename, "%s/h%08x.bin",
		tssContext->tssDataDirectory, session->authHandle);
    }
    if (rc == 0) {
	rc = TSS_File_WriteBinaryFile(outBuffer,
				      outLength,
				      sessionFilename);
    }
    if (tssContext->tssEncryptSessions) {
	free(outBuffer);	/* @2 */
    }
    free(buffer);		/* @1 */
    return rc;
}

/* TSS_HmacSession12_LoadSession() loads and decrypts an HMAC existing session saved by:

   OIAP and OSAP
   an update after a TPM response
*/

static TPM_RC TSS_HmacSession12_LoadSession(TSS_CONTEXT *tssContext,
					    TSS_HMAC12_CONTEXT *session,
					    TPM_AUTHHANDLE authHandle)
{
    TPM_RC		rc = 0;
    uint8_t 		*buffer = NULL;
    uint8_t 		*buffer1 = NULL;
    size_t 		length = 0;
    char		sessionFilename[TPM_DATA_DIR_PATH_LENGTH];
    unsigned char *inData = NULL;		/* output */
    uint32_t inLength;				/* output */

    if (tssVverbose) printf("TSS_HmacSession12_LoadSession: handle %08x\n", authHandle);
    /* load the session from a hard coded file name hxxxxxxxx.bin where xxxxxxxx is the session
       handle */
    if (rc == 0) {
	sprintf(sessionFilename, "%s/h%08x.bin", tssContext->tssDataDirectory, authHandle);
	rc = TSS_File_ReadBinaryFile(&buffer,     /* freed @1 */
				     &length,
				     sessionFilename);
    }
    if (rc == 0) {
	/* if the flag is set, decrypt the session state before unmarshal */
	if (tssContext->tssEncryptSessions) {
	    rc = TSS_AES_Decrypt(tssContext->tssSessionDecKey,
				 &inData,   	/* output, freed @2 */
				 &inLength,	/* output */
				 buffer,	/* input */
				 length);	/* input */
	}
	/* else the session was loaded in plaintext */
	else {
	    inData = buffer;
	    inLength = length;
	}
    }
    if (rc == 0) {
	uint32_t ilength = inLength;
	buffer1 = inData;
	rc = TSS_HmacSession12_Unmarshal(session, &buffer1, &ilength);
    }
    if (tssContext->tssEncryptSessions) {
	free(inData);	/* @2 */
    }
    free(buffer);	/* @1 */
    return rc;
}

/* TSS_HmacSession12_DeleteSession() deletes the file corresponding to the HMAC session */

static TPM_RC TSS_HmacSession12_DeleteSession(TSS_CONTEXT *tssContext,
					      TPM_AUTHHANDLE handle)
{
    TPM_RC		rc = 0;
    char		filename[TPM_DATA_DIR_PATH_LENGTH];

    /* delete the Name */
    if (rc == 0) {
	sprintf(filename, "%s/h%08x.bin", tssContext->tssDataDirectory, handle);
	if (tssVverbose) printf("TSS_HmacSession12_DeleteSession: delete session file %s\n", filename);
	rc = TSS_File_DeleteFile(filename);
    }
    return rc;
}

/* TSS_HmacSession12_Marshal() serializes a TSS_HMAC12_CONTEXT
 */

static TPM_RC TSS_HmacSession12_Marshal(TSS_HMAC12_CONTEXT *source,
					uint16_t *written,
					uint8_t **buffer,
					uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->nonceEven, SHA1_DIGEST_SIZE, written, buffer,  size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->nonceEvenOSAP, SHA1_DIGEST_SIZE, written, buffer,  size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu((uint8_t *)&source->sharedSecret.digest, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->entityType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->entityValue, written, buffer, size);
    }
    return rc;
}

/* TSS_HmacSession12_Unmarshal() deserializes a TSS_HMAC12_CONTEXT */

static TPM_RC TSS_HmacSession12_Unmarshal(TSS_HMAC12_CONTEXT *target,
					  uint8_t **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->authHandle, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->nonceEven, SHA1_DIGEST_SIZE, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->nonceEvenOSAP, SHA1_DIGEST_SIZE, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)&target->sharedSecret.digest, SHA1_DIGEST_SIZE, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Unmarshalu(&target->entityType, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->entityValue, buffer, size);
    }
    return rc;
}

/* TSS_HmacSession12_SetHMAC() is used for a command.  It sets all the values in one
   TPMS_AUTH12_COMMAND, ready for marshaling into the command packet.

   - gets cpBuffer
   - generates cpHash
   - generates the HMAC
   - copies the result into authCommand

   The HMAC key is already in the session structure.
*/

static TPM_RC TSS_HmacSession12_SetHMAC(TSS_AUTH_CONTEXT *tssAuthContext,	/* authorization context */
					size_t		numSessions,
					TSS_HMAC12_CONTEXT *session[],
					
					TPMS_AUTH12_COMMAND *authCommand[],	/* output: command
										   authorization */
					TPM_AUTHHANDLE sessionHandle[], 	/* session handles in
										   command */
					unsigned int sessionAttributes[])	/* attributes for this
										   command */
{
    TPM_RC		rc = 0;
    unsigned int	i = 0;
    TPMT_HA 		cpHash;
    TPMT_HA 		hmac;

    /* Step 6: calculate cpHash.  For TPM 1.2, it is the same for all sessions. Name is not used */
    if ((rc == 0) && (numSessions > 0))	{
	uint32_t cpBufferSize;
	uint8_t *cpBuffer;
	TPM_CC commandCode = TSS_GetCommandCode(tssAuthContext);
	TPM_CC commandCodeNbo = htonl(commandCode);
	
	rc = TSS_GetCpBuffer(tssAuthContext, &cpBufferSize, &cpBuffer);
	if (tssVverbose) TSS_PrintAll("TSS_HmacSession12_SetHMAC: cpBuffer",
				      cpBuffer, cpBufferSize);
	/* Create cpHash - digest of inputs above the double line. */
	cpHash.hashAlg = TPM_ALG_SHA1;
	rc = TSS_Hash_Generate(&cpHash,
			       sizeof(TPM_CC), &commandCodeNbo,		/* 1S */
			       cpBufferSize, cpBuffer, 			/* 2S - ... */
			       0, NULL);
	if (rc == 0) {
	    if (tssVverbose) TSS_PrintAll("TSS_HmacSession12_SetHMAC: cpHash",
					  (uint8_t *)&cpHash.digest,
					  SHA1_DIGEST_SIZE);
	}
    }
    for (i = 0 ; (rc == 0) && (i < numSessions) ; i++) {
	uint8_t sessionAttr8;
	TPM2B_KEY hmacKey;
	
	if (tssVverbose) printf("TSS_HmacSession12_SetHMAC: Step 6 session %08x\n",
				sessionHandle[i]);
	/* sessionHandle */
	authCommand[i]->sessionHandle = session[i]->authHandle;
	/* attributes come from command */
	sessionAttr8 = (uint8_t)sessionAttributes[i];
	authCommand[i]->sessionAttributes.val = sessionAttr8;

	if (tssVverbose) printf("TSS_HmacSession12_SetHMAC: calculate HMAC\n");
	/* auth HMAC = HMAC(cpHash | nonceEven, nonceOdd, attributes */

	/* convert the TPMT_HA hmacKey to a TPM2B_KEY hmac key */
	if (rc == 0) {
	    rc = TSS_TPM2B_Create(&hmacKey.b,
				  (uint8_t *)&session[i]->hmacKey.digest, SHA1_DIGEST_SIZE,
				  sizeof(hmacKey.t.buffer));
	}
	if (rc == 0) {
	    hmac.hashAlg = TPM_ALG_SHA1;
	    rc = TSS_HMAC_Generate(&hmac,			/* output hmac */
				   &hmacKey,			/* input key */
				   SHA1_DIGEST_SIZE, (uint8_t *)&cpHash.digest,
				   SHA1_DIGEST_SIZE, session[i]->nonceEven,
				   SHA1_DIGEST_SIZE, session[i]->nonceOdd,
				   sizeof(uint8_t), &sessionAttr8,
				   0, NULL);
	}
	if (rc == 0) {
	    if (tssVverbose) {
		TSS_PrintAll("TSS_HmacSession12_SetHMAC: HMAC key",
			     (uint8_t *)&session[i]->hmacKey.digest, SHA1_DIGEST_SIZE);
		TSS_PrintAll("TSS_HmacSession12_SetHMAC: cpHash",
			     (uint8_t *)&cpHash.digest, SHA1_DIGEST_SIZE);
		TSS_PrintAll("TSS_HmacSession12_Set: nonceEven",
			     session[i]->nonceEven, SHA1_DIGEST_SIZE);
		TSS_PrintAll("TSS_HmacSession12_SetHMAC: nonceOdd",
			     session[i]->nonceOdd, SHA1_DIGEST_SIZE);
		TSS_PrintAll("TSS_HmacSession12_SetHMAC: sessionAttributes",
			     &sessionAttr8, sizeof(uint8_t));
		TSS_PrintAll("TSS_HmacSession12_SetHMAC: HMAC",
			     (uint8_t *)&hmac.digest, SHA1_DIGEST_SIZE);
	    }
	}
	/* copy HMAC into authCommand TPM2B_AUTH hmac */
	if (rc == 0) {
	    memcpy(authCommand[i]->hmac, (uint8_t *)&hmac.digest, SHA1_DIGEST_SIZE);
	}
    }
    return rc;
}

/* TSS_HmacSession12_Verify() is used for a response.  It uses the values in TPMS_AUTH12_RESPONSE to
   validate the response HMAC */

static TPM_RC TSS_HmacSession12_Verify(TSS_AUTH_CONTEXT *tssAuthContext,	/* authorization
										   context */
				       size_t		numSessions,
				       TSS_HMAC12_CONTEXT *session[],		/* TSS session
										   context */
				       TPMS_AUTH12_RESPONSE *authResponse[])	/* input: response
										   authorization */
{
    TPM_RC		rc = 0;
    unsigned int	i = 0;
    TPMT_HA 		rpHash;
    TPMT_HA 		actualHmac;

    /* Step 10: calculate rpHash.  For TPM 1.2, it is the same for all sessions. Name is not used */
    if ((rc == 0) && (numSessions > 0))	{
	uint32_t rpBufferSize;
	uint8_t *rpBuffer;
	TPM_CC commandCode = TSS_GetCommandCode(tssAuthContext);
	TPM_CC commandCodeNbo = htonl(commandCode);
	
	rc = TSS_GetRpBuffer12(tssAuthContext, &rpBufferSize, &rpBuffer, numSessions);
	if (tssVverbose) TSS_PrintAll("TSS_HmacSession12_Verify: rpBuffer",
				      rpBuffer, rpBufferSize);
	/* Create rpHash - digest of inputs above the double line. */
	rpHash.hashAlg = TPM_ALG_SHA1;
	rc = TSS_Hash_Generate(&rpHash,
			       sizeof(TPM_RC),  &rc,			/* 1S */
			       sizeof(TPM_CC), &commandCodeNbo,		/* 2S */
			       rpBufferSize, rpBuffer, 			/* 3S - ... */
			       0, NULL);
	if (rc == 0) {
	    if (tssVverbose) TSS_PrintAll("TSS_HmacSession12_Verify: rpHash",
					  (uint8_t *)&rpHash.digest,
					  SHA1_DIGEST_SIZE);
	}
    }
    for (i = 0 ; (rc == 0) && (i < numSessions) ; i++) {
	uint8_t sessionAttr8;
	TPM2B_KEY hmacKey;
	if (tssVverbose) printf("TSS_HmacSession12_Verify: Step 10 session %u handle %08x\n",
				i, session[i]->authHandle);
	/* attributes come from response */
	sessionAttr8 = (uint8_t)authResponse[i]->sessionAttributes.val;
	/* save nonceEven in the session context */
	if (rc == 0) {
	    memcpy(session[i]->nonceEven, authResponse[i]->nonce, SHA1_DIGEST_SIZE);
	}
	if (rc == 0) {
	    memcpy((uint8_t *)&actualHmac.digest, &authResponse[i]->hmac,
		   SHA1_DIGEST_SIZE);
	}
	/* convert the TPMT_HA hmacKey to a TPM2B_KEY hmac key */
	if (rc == 0) {
	    rc = TSS_TPM2B_Create(&hmacKey.b,
				  (uint8_t *)&session[i]->hmacKey.digest, SHA1_DIGEST_SIZE,
				  sizeof(hmacKey.t.buffer));
	}
	/* verify the HMAC */
	if (rc == 0) {
	    if (tssVverbose) {
		TSS_PrintAll("TSS_HmacSession12_Verify: HMAC key",
			     (uint8_t *)&session[i]->hmacKey.digest, SHA1_DIGEST_SIZE);
		TSS_PrintAll("TSS_HmacSession12_Verify: rpHash",
			     (uint8_t *)&rpHash.digest, SHA1_DIGEST_SIZE);
		TSS_PrintAll("TSS_HmacSession12_Verify: nonceEven",
			     session[i]->nonceEven, SHA1_DIGEST_SIZE);
		TSS_PrintAll("TSS_HmacSession12_Verify: nonceOdd",
			     session[i]->nonceOdd, SHA1_DIGEST_SIZE);
		TSS_PrintAll("TSS_HmacSession12_Verify: sessionAttributes",
			     &sessionAttr8, sizeof(uint8_t));
		TSS_PrintAll("TSS_HmacSession12_Verify: response HMAC",
			     (uint8_t *)&authResponse[i]->hmac, SHA1_DIGEST_SIZE);
	    }
	    actualHmac.hashAlg = TPM_ALG_SHA1;
	    rc = TSS_HMAC_Verify(&actualHmac,			/* input response hmac */
				 &hmacKey,			/* input HMAC key */
				 SHA1_DIGEST_SIZE,
				 /* rpHash */
				 SHA1_DIGEST_SIZE, (uint8_t *)&rpHash.digest,
				 /* new is nonceEven */
				 SHA1_DIGEST_SIZE, session[i]->nonceEven,
				 /* old is nonceOdd */
				 SHA1_DIGEST_SIZE, session[i]->nonceOdd,
				 /* 1 byte, no endian conversion */
				 sizeof(uint8_t), &authResponse[i]->sessionAttributes.val,
				 0, NULL);
	    if (rc == 0) {
		if (tssVverbose) printf("TSS_HmacSession12_Verify: session %u verified\n", i);
	    }
	    else {
		if (tssVerbose) TSS_PrintAll("TSS_HmacSession12_Verify: HMAC verify failed, actual",
					     (uint8_t *)&actualHmac.digest, SHA1_DIGEST_SIZE);
	    }
	}
    }
    return rc;
}

/* TSS_HmacSession12_Continue() handles the response continueSession flag.  It either saves the
   updated session or deletes the session state. */

static TPM_RC TSS_HmacSession12_Continue(TSS_CONTEXT *tssContext,
					 TSS_HMAC12_CONTEXT *session,
					 TPMS_AUTH12_RESPONSE *authR)
{
    TPM_RC		rc = 0;

    if (rc == 0) {
	/* if continue set */
	if (authR->sessionAttributes.val & TPMA_SESSION_CONTINUESESSION) {
	    /* save the session */
	    rc = TSS_HmacSession12_SaveSession(tssContext, session);
	}
	else {		/* continue clear */
	    /* delete the session state */
	    rc = TSS_HmacSession12_DeleteSession(tssContext, session->authHandle);
	}
    }
    return rc;
}

/* TSS_Command_Decrypt() does the command ADIP encryption (the TPM does the decrypt).

   It does common error checking, then calls algorithm specific functions.  Currently, only XOR is
   implemented.

*/

static TPM_RC TSS_Command_Decrypt(TSS_AUTH_CONTEXT *tssAuthContext,
				  TSS_HMAC12_CONTEXT *session[],
				  TPM_AUTHHANDLE sessionHandle[])
{
    TPM_RC			rc = 0;
    uint16_t 			sessionNumber;
    uint8_t			*encAuth0;
    uint8_t			*encAuth1;
    TSS_HMAC12_CONTEXT		*decryptSession;
    int				done = FALSE;
    int 			isXor;			/* true for XOR, false for AES */
    
    /* which session is the OSAP session used for the encryption */
    if (rc == 0) {
	rc = TSS_GetSessionNumber(tssAuthContext,
				  &sessionNumber);
    }
    if (rc == 0) {
	if (sessionNumber == 0xffff) {
	    done = TRUE;
	}
    }
    /* get the session used for the encryption */
    if ((rc == 0) && !done) {
	decryptSession = session[sessionNumber];
	isXor = (session[sessionNumber]->entityType & 0xff00) == (TPM_ET_XOR << 8);
	if (!isXor) {
	    if (tssVerbose) printf("TSS_Command_Decrypt: bad entityType %04x for session %08x\n",
				   session[sessionNumber]->entityType,
				   sessionHandle[sessionNumber]);
	    rc = TSS_RC_BAD_DECRYPT_ALGORITHM;
	}
	else {
	    if (tssVverbose) printf("TSS_Command_Decrypt: using session %08x\n",
				    sessionHandle[sessionNumber]);
	}

    }
    /* get pointers to the parameters to be encrypted */ 
    if ((rc == 0) && !done) {
	rc = TSS_GetEncAuths(tssAuthContext,
			     &encAuth0,
			     &encAuth1);
    }
    if ((rc == 0) && !done) {
	if (tssVverbose) printf("TSS_Command_Decrypt: TPM_ENC_AUTH's at %p, %p\n",
				encAuth0, encAuth1);
    }
    if ((rc == 0) && !done && (encAuth0 != NULL)) {
	rc = TSS_Command_DecryptXor(tssAuthContext, decryptSession, encAuth0, 0);
    }
    if ((rc == 0) && !done && (encAuth1 != NULL)) {
	rc = TSS_Command_DecryptXor(tssAuthContext, decryptSession, encAuth1, 1);
    }
    return rc;
}

/*
  pad = sha1(shared secret || lastnonceeven)
  enc = xor (auth, pad)
*/

static TPM_RC TSS_Command_DecryptXor(TSS_AUTH_CONTEXT *tssAuthContext,
				     TSS_HMAC12_CONTEXT *session,
				     uint8_t *encAuth,
				     int parameterNumber)
{
    TPM_RC		rc = 0;
    TPMT_HA 		padHash;
    unsigned int	i;

    tssAuthContext = tssAuthContext;
    /* generate the pad */
    if (rc == 0) {
	padHash.hashAlg = TPM_ALG_SHA1;
	if (parameterNumber == 0) {
	    rc = TSS_Hash_Generate(&padHash,
				   SHA1_DIGEST_SIZE, (uint8_t *)&session->sharedSecret.digest,
				   SHA1_DIGEST_SIZE, session->nonceEven,
				   0, NULL);
	}
	else {
	    rc = TSS_Hash_Generate(&padHash,
				   SHA1_DIGEST_SIZE, (uint8_t *)&session->sharedSecret.digest,
				   SHA1_DIGEST_SIZE, session->nonceOdd,
				   0, NULL);
	}
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptXor: pad",
				      (uint8_t *)&padHash.digest,
				      SHA1_DIGEST_SIZE);
	if (tssVverbose) printf("TSS_Command_DecryptXor: parameter %u\n",
				parameterNumber);
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptXor: plaintext",
				      encAuth, SHA1_DIGEST_SIZE);
    }
    /* do the XOR */
    if (rc == 0) {
	for (i = 0 ; i < SHA1_DIGEST_SIZE ; i++) {
	    *(encAuth + i) = *(encAuth + i) ^ padHash.digest.sha1[i];
	}
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptXor: ciphertext",
				      encAuth, SHA1_DIGEST_SIZE);
    }    
    return rc;
}

/*
  Command Pre-Processor
*/

static TPM_RC TSS_Command_PreProcessor(TSS_CONTEXT *tssContext,
				       TPM_CC commandCode,
				       COMMAND_PARAMETERS *in,
				       EXTRA12_PARAMETERS *extra)
{
    TPM_RC 			rc = 0;
    size_t 			index;
    int 			found;
    TSS_PreProcessFunction_t 	preProcessFunction = NULL;

    /* search the table for a pre-processing function */
    if (rc == 0) {
	found = FALSE;
	for (index = 0 ; (index < (sizeof(tssTable) / sizeof(TSS_TABLE))) && !found ; index++) {
	    if (tssTable[index].commandCode == commandCode) {
		found = TRUE;
		break;	/* don't increment index if found */
	    }
	}
    }
    /* found false means there is no pre-processing function.  This permits the table to be smaller
       if desired. */
    if ((rc == 0) && found) {
	preProcessFunction = tssTable[index].preProcessFunction;
	/* there could also be an entry that is currently NULL, nothing to do */
	if (preProcessFunction == NULL) {
	    found = FALSE;
	}
    }
    /* call the pre processing function */
    if ((rc == 0) && found) {
	rc = preProcessFunction(tssContext, in, extra);
    }
    return rc;
}

/*
  Command specific pre processing functions
*/

static TPM_RC TSS_PR_CreateWrapKey(TSS_CONTEXT *tssContext,
				   CreateWrapKey_In *in,
				   void *extra)
{
    TPM_RC	rc = 0;
    in = in;
    extra = extra;
    if (tssVverbose) printf("TSS_PR_CreateWrapKey\n");
    /* TPM_ENCAUTH is predictable distance from start */
    if (rc == 0) {
	rc = TSS_SetEncAuthOffset0(tssContext->tssAuthContext,
				   sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_RESULT) +
				   sizeof(TPM_KEY_HANDLE));
    }
    if (rc == 0) {
	rc = TSS_SetEncAuthOffset1(tssContext->tssAuthContext,
				   sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_RESULT) +
				   sizeof(TPM_KEY_HANDLE) +
				   SHA1_DIGEST_SIZE);
    }
    if (rc == 0) {
	rc = TSS_SetSessionNumber(tssContext->tssAuthContext, 0);
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_PR_CreateWrapKey: ADIP offset at %lu and %lu\n",
				(unsigned long)(sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_RESULT) +
						sizeof(TPM_KEY_HANDLE)),
				(unsigned long)(sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_RESULT) +
						sizeof(TPM_KEY_HANDLE) +
						SHA1_DIGEST_SIZE));
    }
    return rc;
}

static TPM_RC TSS_PR_MakeIdentity(TSS_CONTEXT *tssContext,
				  MakeIdentity_In *in,
				  void *extra)
{
    TPM_RC	rc = 0;
    in = in;
    extra = extra;
    if (tssVverbose) printf("TSS_PR_MakeIdentity\n");
    /* TPM_ENCAUTH is predictable distance from start */
    if (rc == 0) {
	rc = TSS_SetEncAuthOffset0(tssContext->tssAuthContext,
				   sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_RESULT));
    }
    if (rc == 0) {
	rc = TSS_SetSessionNumber(tssContext->tssAuthContext, 1);
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_PR_MakeIdentity: ADIP offset at %lu\n",
				(unsigned long)(sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_RESULT)));
    }
    return rc;
}

static TPM_RC TSS_PR_NV_DefineSpace(TSS_CONTEXT *tssContext,
				    NV_DefineSpace_In *in,
				    void *extra)
{
    TPM_RC	rc = 0;
    in = in;
    extra = extra;
    if (tssVverbose) printf("TSS_PR_NV_DefineSpace\n");
    /* TPM_ENCAUTH is predictable distance from end */
    if (rc == 0) {
	rc = TSS_SetEncAuthOffset0(tssContext->tssAuthContext,
				   -SHA1_DIGEST_SIZE);		/* encauth */
		
    }
    if (rc == 0) {
	rc = TSS_SetSessionNumber(tssContext->tssAuthContext, 0);
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_PR_NV_DefineSpace: ADIP offset at %d\n",
				-SHA1_DIGEST_SIZE);
    }
    return rc;
}

static TPM_RC TSS_PR_OSAP(TSS_CONTEXT *tssContext,
			  OSAP_In *in,
			  OSAP_Extra *extra)
{
    TPM_RC	rc = 0;
    tssContext = tssContext;
    extra = extra;

    if (tssVverbose) printf("TSS_PR_OSAP\n");
    /* generate nonceOddOSAP */
    if (rc == 0) {
	rc = TSS_RandBytes((unsigned char *)in->nonceOddOSAP, SHA1_DIGEST_SIZE);
    }
    return rc;
}

#if 0
static TPM_RC TSS_PR_Seal(TSS_CONTEXT *tssContext,
			  Seal_in *In,
			  void *extra)
{
    TPM_RC	rc = 0;
    in = in;
    extra = extra;
    if (tssVverbose) printf("TSS_PR_Seal\n");
    /* TPM_ENCAUTH is predictable distance from start */
    if (rc == 0) {
	rc = TSS_SetEncAuthOffset0(tssContext->tssAuthContext,
				   sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_RESULT) +
				   sizeof(TPM_KEY_HANDLE));
    }
    if (rc == 0) {
	rc = TSS_SetSessionNumber(tssContext->tssAuthContext, 0);
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_PR_Seal: ADIP offset at %u\n",
				sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_RESULT) +
				sizeof(TPM_KEY_HANDLE));
    }
    return rc;
}

static TPM_RC TSS_PR_Sealx(TSS_CONTEXT *tssContext,
			   Sealx_in *In,
			   void *extra)
{
    TPM_RC	rc = 0;
    in = in;
    extra = extra;
    if (tssVverbose) printf("TSS_PR_Sealx\n");
    /* TPM_ENCAUTH is predictable distance from start */
    if (rc == 0) {
	rc = TSS_SetEncAuthOffset0(tssContext->tssAuthContext,
				   sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_RESULT) +
				   sizeof(TPM_KEY_HANDLE));
	rc = TSS_SetSessionNumber(tssContext->tssAuthContext, 0);
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_PR_Seal: ADIP offset at %u\n",
				sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_RESULT) +
				sizeof(TPM_KEY_HANDLE));
    }
    return rc;
}

#endif

/*
  Response Post Processor
*/

/* TSS_Response_PostProcessor() handles any response specific post processing
 */

static TPM_RC TSS_Response_PostProcessor(TSS_CONTEXT *tssContext,
					 COMMAND_PARAMETERS *in,
					 RESPONSE_PARAMETERS *out,
					 EXTRA12_PARAMETERS *extra)
{
    TPM_RC 			rc = 0;
    size_t 			index;
    int 			found;
    TSS_PostProcessFunction_t 	postProcessFunction = NULL;

    /* search the table for a post processing function */
    if (rc == 0) {
	TPM_CC commandCode = TSS_GetCommandCode(tssContext->tssAuthContext);
	found = FALSE;
	for (index = 0 ; (index < (sizeof(tssTable) / sizeof(TSS_TABLE))) && !found ; index++) {
	    if (tssTable[index].commandCode == commandCode) {
		found = TRUE;
		break;	/* don't increment index if found */
	    }
	}
    }
    /* found false means there is no post processing function.  This permits the table to be smaller
       if desired. */
    if ((rc == 0) && found) {
	postProcessFunction = tssTable[index].postProcessFunction;
	/* there could also be an entry that it currently NULL, nothing to do */
	if (postProcessFunction == NULL) {
	    found = FALSE;
	}
    }
    /* call the function */
    if ((rc == 0) && found) {
	rc = postProcessFunction(tssContext, in, out, extra);
    }
    return rc;
}

/*
  Command specific post processing functions
*/

static TPM_RC TSS_PO_FlushSpecific(TSS_CONTEXT *tssContext,
				   FlushSpecific_In *in,
				   void *out,
				   void *extra)
{
    TPM_RC	rc = 0;
    out = out;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_FlushSpecific: handle %08x\n", in->handle);
    if ((rc == 0) && (in->resourceType == TPM_RT_AUTH)) {
	rc = TSS_HmacSession12_DeleteSession(tssContext, in->handle);
    }
    return rc;
}  

static TPM_RC TSS_PO_OIAP(TSS_CONTEXT *tssContext,
			  void *in,
			  OIAP_Out *out,
			  void *extra)
{
    TPM_RC 		rc = 0;
    TSS_HMAC12_CONTEXT 	*session = NULL;

    in = in;
    extra = extra;
    /* allocate a TSS_HMAC_CONTEXT session context */
    if (rc == 0) {
	rc = TSS_HmacSession12_GetContext(&session);
    }
    if (rc == 0) {
	/* store OIAP ordinal outputs */
	session->authHandle = out->authHandle;
	session->entityValue = TPM_RH_NULL;	/* distinguish OIAP form OSAP */
	memcpy(session->nonceEven, out->nonceEven, SHA1_DIGEST_SIZE);
    }
    /* persist the session */
    if (rc == 0) {
	rc = TSS_HmacSession12_SaveSession(tssContext, session);
    }
    TSS_HmacSession12_FreeContext(session);
    return rc;
}

static TPM_RC TSS_PO_OSAP(TSS_CONTEXT *tssContext,
			  OSAP_In *in,
			  OSAP_Out *out,
			  OSAP_Extra *extra)
{
    TPM_RC 		rc = 0;
    TSS_HMAC12_CONTEXT 	*session = NULL;
    TPM2B_KEY		hmacKey;
    TPMT_HA 		usageAuth;		/* digest of the OSAP password */

    /* allocate a TSS_HMAC_CONTEXT session context */
    if (rc == 0) {
	rc = TSS_HmacSession12_GetContext(&session);
    }
    if (rc == 0) {
	session->entityType = in->entityType;
	session->entityValue = in->entityValue;		/* mark OSAP session */
	memcpy(session->nonceOddOSAP, in->nonceOddOSAP, SHA1_DIGEST_SIZE);
	/* store OSAP ordinal outputs */
	session->authHandle = out->authHandle;
	memcpy(session->nonceEven, out->nonceEven, SHA1_DIGEST_SIZE);
	memcpy(session->nonceEvenOSAP, out->nonceEvenOSAP, SHA1_DIGEST_SIZE);
    }
    /* SHA1 hash the usageAuth */
    if (rc == 0) {
	if (extra->usagePassword != NULL) {	/* if a password was specified, hash it */
	    usageAuth.hashAlg = TPM_ALG_SHA1;
	    rc = TSS_Hash_Generate(&usageAuth,
				   strlen(extra->usagePassword),
				   (unsigned char *)extra->usagePassword,
				   0, NULL);
	}
	/* TPM 1.2 convention seems to use all zeros as a well known auth */
	else {
	    memset((uint8_t *)&usageAuth.digest, 0, SHA1_DIGEST_SIZE);
	}
    }
    /* convert the TPMT_HA hash to a TPM2B_KEY hmac key */
    if (rc == 0) {
	rc = TSS_TPM2B_Create(&hmacKey.b, (uint8_t *)&usageAuth.digest, SHA1_DIGEST_SIZE,
			      sizeof(hmacKey.t.buffer));
    }
    /* calculate the sharedSecret */
    if (rc == 0) {
	session->sharedSecret.hashAlg = TPM_ALG_SHA1;
	rc = TSS_HMAC_Generate(&session->sharedSecret,		/* output hmac */
			       &hmacKey,			/* input key */
			       SHA1_DIGEST_SIZE, session->nonceEvenOSAP,
			       SHA1_DIGEST_SIZE, in->nonceOddOSAP,
			       0, NULL);
    }
    if ((rc == 0) && tssVverbose) {
	printf("TSS_PO_OSAP: out->authHandle %08x\n",out->authHandle);
	printf("TSS_PO_OSAP: in->entityType %08x\n", in->entityType);
	printf("TSS_PO_OSAP: in->entityValue %08x\n", in->entityValue);
	TSS_PrintAll("TSS_PO_OSAP: session->nonceEven",
		     session->nonceEven, SHA1_DIGEST_SIZE);
	TSS_PrintAll("TSS_PO_OSAP: session->nonceEvenOSAP",
		     session->nonceEvenOSAP, SHA1_DIGEST_SIZE);
	TSS_PrintAll("TSS_PO_OSAP: session->nonceOddOSAP",
		     session->nonceOddOSAP, SHA1_DIGEST_SIZE);
	TSS_PrintAll("TSS_PO_OSAP: usageAuth",
		     (uint8_t *)&usageAuth.digest, SHA1_DIGEST_SIZE);
	TSS_PrintAll("TSS_PO_OSAP: sharedSecret",
		     (uint8_t *)&session->sharedSecret.digest, SHA1_DIGEST_SIZE);
    }
    /* persist the session */
    if (rc == 0) {
	rc = TSS_HmacSession12_SaveSession(tssContext, session);
    }
    TSS_HmacSession12_FreeContext(session);
    return rc;
}
