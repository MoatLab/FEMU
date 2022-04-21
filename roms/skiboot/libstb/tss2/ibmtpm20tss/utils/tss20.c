/********************************************************************************/
/*										*/
/*			    TSS Primary API for TPM 2.0				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2018 - 2020					*/
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
#include "tssauth20.h"
#include <ibmtss/tss.h>
#include "tssproperties.h"
#include <ibmtss/tsstransmit.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>
#include "tssccattributes.h"
#ifndef TPM_TSS_NOCRYPTO
#include <ibmtss/tsscrypto.h>
#include <ibmtss/tsscryptoh.h>
#endif
#include <ibmtss/tssprintcmd.h>
#include "tss20.h"

/* Files:

   h01xxxxxx.bin - NV index name
   h02xxxxxx.bin - hmac session context
   h03xxxxxx.bin - policy session context
   h80xxxxxx.bin - transient object name

   cxxxx...xxxx.bin - context blob name
*/

/* NOTE Synchronize with

   TSS_HmacSession_InitContext
   TSS_HmacSession_Unmarshal
   TSS_HmacSession_Marshal
*/

struct TSS_HMAC_CONTEXT {
    TPMI_SH_AUTH_SESSION	sessionHandle;		/* the session handle */
    TPMI_ALG_HASH		authHashAlg;		/* hash algorithm to use for the session */
#ifndef TPM_TSS_NOCRYPTO
    uint32_t           		sizeInBytes;		/* hash algorithm mapped to size */
#endif	/* TPM_TSS_NOCRYPTO */
    TPMT_SYM_DEF 		symmetric;		/* the algorithm and key size for parameter
							   encryption */
    TPMI_DH_ENTITY 		bind;			/* bind handle */
    TPM2B_NAME			bindName;		/* Name corresponding to the the bind
							   handle */
    TPM2B_AUTH			bindAuthValue;		/* password corresponding to the bind
							   handle */
#ifndef TPM_TSS_NOCRYPTO
    TPM2B_NONCE 		nonceTPM;		/* from TPM in response */
    TPM2B_NONCE			nonceCaller;		/* from caller in command */
    TPM2B_DIGEST		sessionKey;		/* from KDFa at session creation */
#endif	/* TPM_TSS_NOCRYPTO */
    TPM_SE			sessionType;		/* HMAC (0), policy (1), or trial policy */
    uint8_t			isPasswordNeeded;	/* flag set by policy password */
    uint8_t			isAuthValueNeeded;	/* flag set by policy authvalue */
    /* Items below this line are for the lifetime of one command.  They are not saved and loaded. */
    TPM2B_KEY			hmacKey;		/* HMAC key calculated for each command */
#ifndef TPM_TSS_NOCRYPTO
    TPM2B_KEY			sessionValue;		/* KDFa secret for parameter encryption */
#endif	/* TPM_TSS_NOCRYPTO */
} TSS_HMAC_CONTEXT;

/* functions for command pre- and post- processing */

typedef TPM_RC (*TSS_PreProcessFunction_t)(TSS_CONTEXT *tssContext,
					   COMMAND_PARAMETERS *in,
					   EXTRA_PARAMETERS *extra);
typedef TPM_RC (*TSS_ChangeAuthFunction_t)(TSS_CONTEXT *tssContext,
					   struct TSS_HMAC_CONTEXT *session,
					   size_t handleNumber,
					   COMMAND_PARAMETERS *in);
typedef TPM_RC (*TSS_PostProcessFunction_t)(TSS_CONTEXT *tssContext,
					    COMMAND_PARAMETERS *in,
					    RESPONSE_PARAMETERS *out,
					    EXTRA_PARAMETERS *extra);

static TPM_RC TSS_PR_StartAuthSession(TSS_CONTEXT *tssContext,
				      StartAuthSession_In *in,
				      StartAuthSession_Extra *extra);
static TPM_RC TSS_PR_NV_DefineSpace(TSS_CONTEXT *tssContext,
				    NV_DefineSpace_In *in,
				    void *extra);

static TPM_RC TSS_CA_HierarchyChangeAuth(TSS_CONTEXT *tssContext,
					 struct TSS_HMAC_CONTEXT *session,
					 size_t handleNumber,
					 HierarchyChangeAuth_In *in);
static TPM_RC TSS_CA_NV_UndefineSpaceSpecial(TSS_CONTEXT *tssContext,
					     struct TSS_HMAC_CONTEXT *session,
					     size_t handleNumber,
					     NV_UndefineSpaceSpecial_In *in);
static TPM_RC TSS_CA_NV_ChangeAuth(TSS_CONTEXT *tssContext,
				   struct TSS_HMAC_CONTEXT *session,
				   size_t handleNumber,
				   NV_ChangeAuth_In *in);


static TPM_RC TSS_PO_StartAuthSession(TSS_CONTEXT *tssContext,
				      StartAuthSession_In *in,
				      StartAuthSession_Out *out,
				      StartAuthSession_Extra *extra);
static TPM_RC TSS_PO_ContextSave(TSS_CONTEXT *tssContext,
				 ContextSave_In *in,
				 ContextSave_Out *out,
				 void *extra);
static TPM_RC TSS_PO_ContextLoad(TSS_CONTEXT *tssContext,
				 ContextLoad_In *in,
				 ContextLoad_Out *out,
				 void *extra);
static TPM_RC TSS_PO_FlushContext(TSS_CONTEXT *tssContext,
				  FlushContext_In *in,
				  void *out,
				  void *extra);
static TPM_RC TSS_PO_EvictControl(TSS_CONTEXT *tssContext,
				  EvictControl_In *in,
				  void *out,
				  void *extra);
static TPM_RC TSS_PO_Load(TSS_CONTEXT *tssContext,
			  Load_In *in,
			  Load_Out *out,
			  void *extra);
static TPM_RC TSS_PO_LoadExternal(TSS_CONTEXT *tssContext,
				  LoadExternal_In *in,
				  LoadExternal_Out *out,
				  void *extra);
static TPM_RC TSS_PO_ReadPublic(TSS_CONTEXT *tssContext,
				ReadPublic_In *in,
				ReadPublic_Out *out,
				void *extra);
static TPM_RC TSS_PO_CreateLoaded(TSS_CONTEXT *tssContext,
				  CreateLoaded_In *in,
				  CreateLoaded_Out *out,
				  void *extra);
static TPM_RC TSS_PO_HMAC_Start(TSS_CONTEXT *tssContext,
				HMAC_Start_In *in,
				HMAC_Start_Out *out,
				void *extra);
static TPM_RC TSS_PO_HashSequenceStart(TSS_CONTEXT *tssContext,
				       HashSequenceStart_In *in,
				       HashSequenceStart_Out *out,
				       void *extra);
static TPM_RC TSS_PO_SequenceComplete(TSS_CONTEXT *tssContext,
				      SequenceComplete_In *in,
				      SequenceComplete_Out *out,
				      void *extra);
static TPM_RC TSS_PO_EventSequenceComplete(TSS_CONTEXT *tssContext,
					   EventSequenceComplete_In *in,
					   EventSequenceComplete_Out *out,
					   void *extra);
static TPM_RC TSS_PO_PolicyAuthValue(TSS_CONTEXT *tssContext,
				     PolicyAuthValue_In *in,
				     void *out,
				     void *extra);
static TPM_RC TSS_PO_PolicyPassword(TSS_CONTEXT *tssContext,
				    PolicyPassword_In *in,
				    void *out,
				    void *extra);
static TPM_RC TSS_PO_CreatePrimary(TSS_CONTEXT *tssContext,
				   CreatePrimary_In *in,
				   CreatePrimary_Out *out,
				   void *extra);
static TPM_RC TSS_PO_NV_DefineSpace(TSS_CONTEXT *tssContext,
				    NV_DefineSpace_In *in,
				    void *out,
				    void *extra);
static TPM_RC TSS_PO_NV_ReadPublic(TSS_CONTEXT *tssContext,
				   NV_ReadPublic_In *in,
				   NV_ReadPublic_Out *out,
				   void *extra);
static TPM_RC TSS_PO_NV_UndefineSpace(TSS_CONTEXT *tssContext,
				      NV_UndefineSpace_In *in,
				      void *out,
				      void *extra);
static TPM_RC TSS_PO_NV_UndefineSpaceSpecial(TSS_CONTEXT *tssContext,
					     NV_UndefineSpaceSpecial_In *in,
					     void *out,
					     void *extra);
static TPM_RC TSS_PO_NV_Write(TSS_CONTEXT *tssContext,
			      NV_Write_In *in,
			      void *out,
			      void *extra);
static TPM_RC TSS_PO_NV_WriteLock(TSS_CONTEXT *tssContext,
				  NV_WriteLock_In *in,
				  void *out,
				  void *extra);
static TPM_RC TSS_PO_NV_ReadLock(TSS_CONTEXT *tssContext,
				 NV_ReadLock_In *in,
				 void *out,
				 void *extra);

typedef struct TSS_TABLE {
    TPM_CC 			commandCode;
    TSS_PreProcessFunction_t	preProcessFunction;
    TSS_ChangeAuthFunction_t	changeAuthFunction;
    TSS_PostProcessFunction_t 	postProcessFunction;
} TSS_TABLE;

/* This table indexes from the command to pre- and post- processing functions.  A missing entry is
   not an error, and indicates a command with no functions. */

static const TSS_TABLE tssTable [] = {
				 
    {TPM_CC_Startup, NULL, NULL, NULL},
    {TPM_CC_Shutdown, NULL, NULL, NULL},
    {TPM_CC_SelfTest, NULL, NULL, NULL},
    {TPM_CC_IncrementalSelfTest, NULL, NULL, NULL},
    {TPM_CC_GetTestResult, NULL, NULL, NULL},
    {TPM_CC_StartAuthSession, (TSS_PreProcessFunction_t)TSS_PR_StartAuthSession, NULL, (TSS_PostProcessFunction_t)TSS_PO_StartAuthSession},
    {TPM_CC_PolicyRestart, NULL, NULL, NULL},
    {TPM_CC_Create, NULL, NULL, NULL},
    {TPM_CC_Load, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_Load},
    {TPM_CC_LoadExternal, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_LoadExternal},
    {TPM_CC_ReadPublic, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_ReadPublic},
    {TPM_CC_ActivateCredential, NULL, NULL, NULL},
    {TPM_CC_MakeCredential, NULL, NULL, NULL},
    {TPM_CC_Unseal, NULL, NULL, NULL},
    {TPM_CC_ObjectChangeAuth, NULL, NULL, NULL},
    {TPM_CC_CreateLoaded, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_CreateLoaded},
    {TPM_CC_Duplicate, NULL, NULL, NULL},
    {TPM_CC_Rewrap, NULL, NULL, NULL},
    {TPM_CC_Import, NULL, NULL, NULL},
    {TPM_CC_RSA_Encrypt, NULL, NULL, NULL},
    {TPM_CC_RSA_Decrypt, NULL, NULL, NULL},
    {TPM_CC_ECDH_KeyGen, NULL, NULL, NULL},
    {TPM_CC_ECDH_ZGen, NULL, NULL, NULL},
    {TPM_CC_ECC_Parameters, NULL, NULL, NULL},
    {TPM_CC_ZGen_2Phase, NULL, NULL, NULL},
    {TPM_CC_EncryptDecrypt, NULL, NULL, NULL},
    {TPM_CC_EncryptDecrypt2, NULL, NULL, NULL},
    {TPM_CC_Hash, NULL, NULL, NULL},
    {TPM_CC_HMAC, NULL, NULL, NULL},
    {TPM_CC_GetRandom, NULL, NULL, NULL},
    {TPM_CC_StirRandom, NULL, NULL, NULL},
    {TPM_CC_HMAC_Start, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_HMAC_Start},
    {TPM_CC_HashSequenceStart, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_HashSequenceStart},
    {TPM_CC_SequenceUpdate, NULL, NULL, NULL},
    {TPM_CC_SequenceComplete, NULL,NULL, (TSS_PostProcessFunction_t)TSS_PO_SequenceComplete},
    {TPM_CC_EventSequenceComplete, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_EventSequenceComplete},
    {TPM_CC_Certify, NULL, NULL, NULL},
    {TPM_CC_CertifyX509, NULL, NULL, NULL},
    {TPM_CC_CertifyCreation, NULL, NULL, NULL},
    {TPM_CC_Quote, NULL, NULL, NULL},
    {TPM_CC_GetSessionAuditDigest, NULL, NULL, NULL},
    {TPM_CC_GetCommandAuditDigest, NULL, NULL, NULL},
    {TPM_CC_GetTime, NULL, NULL, NULL},
    {TPM_CC_Commit, NULL, NULL, NULL},
    {TPM_CC_EC_Ephemeral, NULL, NULL, NULL},
    {TPM_CC_VerifySignature, NULL, NULL, NULL},
    {TPM_CC_Sign, NULL, NULL, NULL},
    {TPM_CC_SetCommandCodeAuditStatus, NULL, NULL, NULL},
    {TPM_CC_PCR_Extend, NULL, NULL, NULL},
    {TPM_CC_PCR_Event, NULL, NULL, NULL},
    {TPM_CC_PCR_Read, NULL, NULL, NULL},
    {TPM_CC_PCR_Allocate, NULL, NULL, NULL},
    {TPM_CC_PCR_SetAuthPolicy, NULL, NULL, NULL},
    {TPM_CC_PCR_SetAuthValue, NULL, NULL, NULL},
    {TPM_CC_PCR_Reset, NULL, NULL, NULL},
    {TPM_CC_PolicySigned, NULL, NULL, NULL},
    {TPM_CC_PolicySecret, NULL, NULL, NULL},
    {TPM_CC_PolicyTicket, NULL, NULL, NULL},
    {TPM_CC_PolicyOR, NULL, NULL, NULL},
    {TPM_CC_PolicyPCR, NULL, NULL, NULL},
    {TPM_CC_PolicyLocality, NULL, NULL, NULL},
    {TPM_CC_PolicyNV, NULL, NULL, NULL},
    {TPM_CC_PolicyAuthorizeNV, NULL, NULL, NULL},
    {TPM_CC_PolicyCounterTimer, NULL, NULL, NULL},
    {TPM_CC_PolicyCommandCode, NULL, NULL, NULL},
    {TPM_CC_PolicyPhysicalPresence, NULL, NULL, NULL},
    {TPM_CC_PolicyCpHash, NULL, NULL, NULL},
    {TPM_CC_PolicyNameHash, NULL, NULL, NULL},
    {TPM_CC_PolicyDuplicationSelect, NULL, NULL, NULL},
    {TPM_CC_PolicyAuthorize, NULL, NULL, NULL},
    {TPM_CC_PolicyAuthValue, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_PolicyAuthValue},
    {TPM_CC_PolicyPassword, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_PolicyPassword},
    {TPM_CC_PolicyGetDigest, NULL, NULL, NULL},
    {TPM_CC_PolicyNvWritten, NULL, NULL, NULL},
    {TPM_CC_PolicyTemplate, NULL, NULL, NULL},
    {TPM_CC_CreatePrimary, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_CreatePrimary},
    {TPM_CC_HierarchyControl, NULL, NULL, NULL},
    {TPM_CC_SetPrimaryPolicy, NULL, NULL, NULL},
    {TPM_CC_ChangePPS, NULL, NULL, NULL},
    {TPM_CC_ChangeEPS, NULL, NULL, NULL},
    {TPM_CC_Clear, NULL, NULL, NULL},
    {TPM_CC_ClearControl, NULL, NULL, NULL},
    {TPM_CC_HierarchyChangeAuth, NULL, (TSS_ChangeAuthFunction_t)TSS_CA_HierarchyChangeAuth, NULL},
    {TPM_CC_DictionaryAttackLockReset, NULL, NULL, NULL},
    {TPM_CC_DictionaryAttackParameters, NULL, NULL, NULL},
    {TPM_CC_PP_Commands, NULL, NULL, NULL},
    {TPM_CC_SetAlgorithmSet, NULL, NULL, NULL},
    {TPM_CC_ContextSave, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_ContextSave},
    {TPM_CC_ContextLoad, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_ContextLoad},
    {TPM_CC_FlushContext, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_FlushContext},
    {TPM_CC_EvictControl, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_EvictControl},
    {TPM_CC_ReadClock, NULL, NULL, NULL},
    {TPM_CC_ClockSet, NULL, NULL, NULL},
    {TPM_CC_ClockRateAdjust, NULL, NULL, NULL},
    {TPM_CC_GetCapability, NULL, NULL, NULL},
    {TPM_CC_TestParms, NULL, NULL, NULL},
    {TPM_CC_NV_DefineSpace, (TSS_PreProcessFunction_t)TSS_PR_NV_DefineSpace, NULL,  (TSS_PostProcessFunction_t)TSS_PO_NV_DefineSpace},
    {TPM_CC_NV_UndefineSpace, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_UndefineSpace},
    {TPM_CC_NV_UndefineSpaceSpecial, NULL, (TSS_ChangeAuthFunction_t)TSS_CA_NV_UndefineSpaceSpecial, (TSS_PostProcessFunction_t)TSS_PO_NV_UndefineSpaceSpecial},
    {TPM_CC_NV_ReadPublic, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_ReadPublic},
    {TPM_CC_NV_Write, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_Write},
    {TPM_CC_NV_Increment, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_Write},
    {TPM_CC_NV_Extend, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_Write},
    {TPM_CC_NV_SetBits, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_Write},
    {TPM_CC_NV_WriteLock, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_WriteLock},
    {TPM_CC_NV_GlobalWriteLock, NULL, NULL, NULL},
    {TPM_CC_NV_Read, NULL, NULL, NULL},
    {TPM_CC_NV_ReadLock, NULL, NULL, (TSS_PostProcessFunction_t)TSS_PO_NV_ReadLock},
    {TPM_CC_NV_ChangeAuth, NULL, (TSS_ChangeAuthFunction_t)TSS_CA_NV_ChangeAuth, NULL},
    {TPM_CC_NV_Certify, NULL, NULL, NULL}
};

#ifndef TPM_TSS_NO_PRINT

typedef void (*TSS_InPrintFunction_t)(COMMAND_PARAMETERS *in, unsigned int indent);

typedef struct TSS_PRINT_TABLE {
    TPM_CC 			commandCode;
    TSS_InPrintFunction_t	inPrintFunction;
} TSS_PRINT_TABLE;

/* This table indexes from the command to print functions.  A missing entry is
   not an error, and indicates a command with no function. */

static const TSS_PRINT_TABLE tssPrintTable [] = {
				 
    {TPM_CC_Startup, (TSS_InPrintFunction_t)Startup_In_Print},
    {TPM_CC_Shutdown, (TSS_InPrintFunction_t)Shutdown_In_Print},
    {TPM_CC_SelfTest, (TSS_InPrintFunction_t)SelfTest_In_Print},
    {TPM_CC_IncrementalSelfTest, (TSS_InPrintFunction_t)IncrementalSelfTest_In_Print},
    {TPM_CC_GetTestResult, NULL},
    {TPM_CC_StartAuthSession, (TSS_InPrintFunction_t)StartAuthSession_In_Print},
    {TPM_CC_PolicyRestart, (TSS_InPrintFunction_t)PolicyRestart_In_Print},
    {TPM_CC_Create,(TSS_InPrintFunction_t)Create_In_Print},
    {TPM_CC_Load, (TSS_InPrintFunction_t)Load_In_Print},
    {TPM_CC_LoadExternal, (TSS_InPrintFunction_t)LoadExternal_In_Print},
    {TPM_CC_ReadPublic, (TSS_InPrintFunction_t)ReadPublic_In_Print},
    {TPM_CC_ActivateCredential, (TSS_InPrintFunction_t)ActivateCredential_In_Print},
    {TPM_CC_MakeCredential, (TSS_InPrintFunction_t)MakeCredential_In_Print},
    {TPM_CC_Unseal, (TSS_InPrintFunction_t)Unseal_In_Print},
    {TPM_CC_ObjectChangeAuth, (TSS_InPrintFunction_t)ObjectChangeAuth_In_Print},
    {TPM_CC_CreateLoaded, (TSS_InPrintFunction_t)CreateLoaded_In_Print},
    {TPM_CC_Duplicate, (TSS_InPrintFunction_t)Duplicate_In_Print},
    {TPM_CC_Rewrap, (TSS_InPrintFunction_t)Rewrap_In_Print},
    {TPM_CC_Import, (TSS_InPrintFunction_t)Import_In_Print},
    {TPM_CC_RSA_Encrypt, (TSS_InPrintFunction_t)RSA_Encrypt_In_Print},
    {TPM_CC_RSA_Decrypt, (TSS_InPrintFunction_t)RSA_Decrypt_In_Print},
    {TPM_CC_ECDH_KeyGen, (TSS_InPrintFunction_t)ECDH_KeyGen_In_Print},
    {TPM_CC_ECDH_ZGen, (TSS_InPrintFunction_t)ECDH_ZGen_In_Print},
    {TPM_CC_ECC_Parameters, (TSS_InPrintFunction_t)ECC_Parameters_In_Print},
    {TPM_CC_ZGen_2Phase, (TSS_InPrintFunction_t)ZGen_2Phase_In_Print},
    {TPM_CC_EncryptDecrypt, (TSS_InPrintFunction_t)EncryptDecrypt_In_Print},
    {TPM_CC_EncryptDecrypt2, (TSS_InPrintFunction_t)EncryptDecrypt2_In_Print},
    {TPM_CC_Hash, (TSS_InPrintFunction_t)Hash_In_Print},
    {TPM_CC_HMAC, (TSS_InPrintFunction_t)HMAC_In_Print},
    {TPM_CC_GetRandom, (TSS_InPrintFunction_t)GetRandom_In_Print},
    {TPM_CC_StirRandom, (TSS_InPrintFunction_t)StirRandom_In_Print},
    {TPM_CC_HMAC_Start, (TSS_InPrintFunction_t)HMAC_Start_In_Print},
    {TPM_CC_HashSequenceStart, (TSS_InPrintFunction_t)HashSequenceStart_In_Print},
    {TPM_CC_SequenceUpdate, (TSS_InPrintFunction_t)SequenceUpdate_In_Print},
    {TPM_CC_SequenceComplete, (TSS_InPrintFunction_t)SequenceComplete_In_Print},
    {TPM_CC_EventSequenceComplete, (TSS_InPrintFunction_t)EventSequenceComplete_In_Print},
    {TPM_CC_Certify, (TSS_InPrintFunction_t)Certify_In_Print},
    {TPM_CC_CertifyX509, (TSS_InPrintFunction_t)CertifyX509_In_Print},
    {TPM_CC_CertifyCreation, (TSS_InPrintFunction_t)CertifyCreation_In_Print},
    {TPM_CC_Quote, (TSS_InPrintFunction_t)Quote_In_Print},
    {TPM_CC_GetSessionAuditDigest, (TSS_InPrintFunction_t)GetSessionAuditDigest_In_Print},
    {TPM_CC_GetCommandAuditDigest, (TSS_InPrintFunction_t)GetCommandAuditDigest_In_Print},
    {TPM_CC_GetTime, (TSS_InPrintFunction_t)GetTime_In_Print},
    {TPM_CC_Commit, (TSS_InPrintFunction_t)Commit_In_Print},
    {TPM_CC_EC_Ephemeral, (TSS_InPrintFunction_t)EC_Ephemeral_In_Print},
    {TPM_CC_VerifySignature, (TSS_InPrintFunction_t)VerifySignature_In_Print},
    {TPM_CC_Sign, (TSS_InPrintFunction_t)Sign_In_Print},
    {TPM_CC_SetCommandCodeAuditStatus, (TSS_InPrintFunction_t)SetCommandCodeAuditStatus_In_Print},
    {TPM_CC_PCR_Extend, (TSS_InPrintFunction_t)PCR_Extend_In_Print},
    {TPM_CC_PCR_Event, (TSS_InPrintFunction_t)PCR_Event_In_Print},
    {TPM_CC_PCR_Read, (TSS_InPrintFunction_t)PCR_Read_In_Print},
    {TPM_CC_PCR_Allocate, (TSS_InPrintFunction_t)PCR_Allocate_In_Print},
    {TPM_CC_PCR_SetAuthPolicy, (TSS_InPrintFunction_t)PCR_SetAuthPolicy_In_Print},
    {TPM_CC_PCR_SetAuthValue, (TSS_InPrintFunction_t)PCR_SetAuthValue_In_Print},
    {TPM_CC_PCR_Reset, (TSS_InPrintFunction_t)PCR_Reset_In_Print},
    {TPM_CC_PolicySigned, (TSS_InPrintFunction_t)PolicySigned_In_Print},
    {TPM_CC_PolicySecret, (TSS_InPrintFunction_t)PolicySecret_In_Print},
    {TPM_CC_PolicyTicket, (TSS_InPrintFunction_t)PolicyTicket_In_Print},
    {TPM_CC_PolicyOR, (TSS_InPrintFunction_t)PolicyOR_In_Print},
    {TPM_CC_PolicyPCR, (TSS_InPrintFunction_t)PolicyPCR_In_Print},
    {TPM_CC_PolicyLocality, (TSS_InPrintFunction_t)PolicyLocality_In_Print},
    {TPM_CC_PolicyNV, (TSS_InPrintFunction_t)PolicyNV_In_Print},
    {TPM_CC_PolicyAuthorizeNV, (TSS_InPrintFunction_t)PolicyAuthorizeNV_In_Print},
    {TPM_CC_PolicyCounterTimer, (TSS_InPrintFunction_t)PolicyCounterTimer_In_Print},
    {TPM_CC_PolicyCommandCode, (TSS_InPrintFunction_t)PolicyCommandCode_In_Print},
    {TPM_CC_PolicyPhysicalPresence, (TSS_InPrintFunction_t)PolicyPhysicalPresence_In_Print},
    {TPM_CC_PolicyCpHash, (TSS_InPrintFunction_t)PolicyCpHash_In_Print},
    {TPM_CC_PolicyNameHash, (TSS_InPrintFunction_t)PolicyNameHash_In_Print},
    {TPM_CC_PolicyDuplicationSelect, (TSS_InPrintFunction_t)PolicyDuplicationSelect_In_Print},
    {TPM_CC_PolicyAuthorize, (TSS_InPrintFunction_t)PolicyAuthorize_In_Print},
    {TPM_CC_PolicyAuthValue, (TSS_InPrintFunction_t)PolicyAuthValue_In_Print},
    {TPM_CC_PolicyPassword, (TSS_InPrintFunction_t)PolicyPassword_In_Print},
    {TPM_CC_PolicyGetDigest, (TSS_InPrintFunction_t)PolicyGetDigest_In_Print},
    {TPM_CC_PolicyNvWritten, (TSS_InPrintFunction_t)PolicyNvWritten_In_Print},
    {TPM_CC_PolicyTemplate, (TSS_InPrintFunction_t)PolicyTemplate_In_Print},
    {TPM_CC_CreatePrimary, (TSS_InPrintFunction_t)CreatePrimary_In_Print},
    {TPM_CC_HierarchyControl, (TSS_InPrintFunction_t)HierarchyControl_In_Print},
    {TPM_CC_SetPrimaryPolicy, (TSS_InPrintFunction_t)SetPrimaryPolicy_In_Print},
    {TPM_CC_ChangePPS, (TSS_InPrintFunction_t)ChangePPS_In_Print},
    {TPM_CC_ChangeEPS, (TSS_InPrintFunction_t)ChangeEPS_In_Print},
    {TPM_CC_Clear, (TSS_InPrintFunction_t)Clear_In_Print},
    {TPM_CC_ClearControl, (TSS_InPrintFunction_t)ClearControl_In_Print},
    {TPM_CC_HierarchyChangeAuth, (TSS_InPrintFunction_t)HierarchyChangeAuth_In_Print},
    {TPM_CC_DictionaryAttackLockReset, (TSS_InPrintFunction_t)DictionaryAttackLockReset_In_Print},
    {TPM_CC_DictionaryAttackParameters, (TSS_InPrintFunction_t)DictionaryAttackParameters_In_Print},
    {TPM_CC_PP_Commands, (TSS_InPrintFunction_t)PP_Commands_In_Print},
    {TPM_CC_SetAlgorithmSet, (TSS_InPrintFunction_t)SetAlgorithmSet_In_Print},
    {TPM_CC_ContextSave, (TSS_InPrintFunction_t)ContextSave_In_Print},
    {TPM_CC_ContextLoad, (TSS_InPrintFunction_t)ContextLoad_In_Print},
    {TPM_CC_FlushContext, (TSS_InPrintFunction_t)FlushContext_In_Print},
    {TPM_CC_EvictControl, (TSS_InPrintFunction_t)EvictControl_In_Print},
    {TPM_CC_ReadClock, (TSS_InPrintFunction_t)NULL},
    {TPM_CC_ClockSet, (TSS_InPrintFunction_t)ClockSet_In_Print},
    {TPM_CC_ClockRateAdjust, (TSS_InPrintFunction_t)ClockRateAdjust_In_Print},
    {TPM_CC_GetCapability, (TSS_InPrintFunction_t)GetCapability_In_Print},
    {TPM_CC_TestParms, (TSS_InPrintFunction_t)TestParms_In_Print},
    {TPM_CC_NV_DefineSpace, (TSS_InPrintFunction_t)NV_DefineSpace_In_Print},
    {TPM_CC_NV_UndefineSpace, (TSS_InPrintFunction_t)NV_UndefineSpace_In_Print},
    {TPM_CC_NV_UndefineSpaceSpecial, (TSS_InPrintFunction_t)NV_UndefineSpaceSpecial_In_Print},
    {TPM_CC_NV_ReadPublic, (TSS_InPrintFunction_t)NV_ReadPublic_In_Print},
    {TPM_CC_NV_Write, (TSS_InPrintFunction_t)NV_Write_In_Print},
    {TPM_CC_NV_Increment, (TSS_InPrintFunction_t)NV_Increment_In_Print},
    {TPM_CC_NV_Extend, (TSS_InPrintFunction_t)NV_Extend_In_Print},
    {TPM_CC_NV_SetBits, (TSS_InPrintFunction_t)NV_SetBits_In_Print},
    {TPM_CC_NV_WriteLock, (TSS_InPrintFunction_t)NV_WriteLock_In_Print},
    {TPM_CC_NV_GlobalWriteLock, (TSS_InPrintFunction_t)NV_GlobalWriteLock_In_Print},
    {TPM_CC_NV_Read, (TSS_InPrintFunction_t)NV_Read_In_Print},
    {TPM_CC_NV_ReadLock, (TSS_InPrintFunction_t)NV_ReadLock_In_Print},
    {TPM_CC_NV_ChangeAuth, (TSS_InPrintFunction_t)NV_ChangeAuth_In_Print},
    {TPM_CC_NV_Certify, (TSS_InPrintFunction_t)NV_Certify_In_Print}
};

#endif /* TPM_TSS_NO_PRINT */

/* local prototypes */

static TPM_RC TSS_Execute_valist(TSS_CONTEXT *tssContext,
				 COMMAND_PARAMETERS *in,
				 va_list ap);


static TPM_RC TSS_PwapSession_Set(TPMS_AUTH_COMMAND *authCommand,
				  const char *password);
static TPM_RC TSS_PwapSession_Verify(TPMS_AUTH_RESPONSE *authResponse);

static TPM_RC TSS_HmacSession_GetContext(struct TSS_HMAC_CONTEXT **session);
static void   TSS_HmacSession_InitContext(struct TSS_HMAC_CONTEXT *session);
static void   TSS_HmacSession_FreeContext(struct TSS_HMAC_CONTEXT *session);

#ifndef TPM_TSS_NOCRYPTO
static TPM_RC TSS_HmacSession_SetSessionKey(TSS_CONTEXT *tssContext,
					    struct TSS_HMAC_CONTEXT *session,
					    TPM2B_DIGEST *salt,
					    TPMI_DH_ENTITY bind,
					    TPM2B_AUTH *bindAuthValue);
static TPM_RC TSS_HmacSession_SetNonceCaller(struct TSS_HMAC_CONTEXT *session,
					     TPMS_AUTH_COMMAND 	*authC);
static TPM_RC TSS_HmacSession_SetHmacKey(TSS_CONTEXT *tssContext,
					 struct TSS_HMAC_CONTEXT *session,
					 size_t handleNumber,
					 const char *password);
#endif	/* TPM_TSS_NOCRYPTO */
static TPM_RC TSS_HmacSession_SetHMAC(TSS_AUTH_CONTEXT *tssAuthContext,
				      struct TSS_HMAC_CONTEXT *session[],
				      TPMS_AUTH_COMMAND *authCommand[],
				      TPMI_SH_AUTH_SESSION sessionHandle[],
				      unsigned int sessionAttributes[],
				      const char *password[],
				      TPM2B_NAME *name0,		  
				      TPM2B_NAME *name1,		  
				      TPM2B_NAME *name2);
#ifndef TPM_TSS_NOCRYPTO
static TPM_RC TSS_HmacSession_Verify(TSS_AUTH_CONTEXT *tssAuthContext,
				     struct TSS_HMAC_CONTEXT *session,
				     TPMS_AUTH_RESPONSE *authResponse);
#endif	/* TPM_TSS_NOCRYPTO */
static TPM_RC TSS_HmacSession_Continue(TSS_CONTEXT *tssContext,
				       struct TSS_HMAC_CONTEXT *session,
				       TPMS_AUTH_RESPONSE *authR);


static TPM_RC TSS_HmacSession_SaveSession(TSS_CONTEXT *tssContext,
					  struct TSS_HMAC_CONTEXT *session);
static TPM_RC TSS_HmacSession_LoadSession(TSS_CONTEXT *tssContext,
					  struct TSS_HMAC_CONTEXT *session,
					  TPMI_SH_AUTH_SESSION	sessionHandle);
#ifdef TPM_TSS_NOFILE
static TPM_RC TSS_HmacSession_SaveData(TSS_CONTEXT *tssContext,
				       TPMI_SH_AUTH_SESSION sessionHandle,
				       uint32_t outLength,
				       uint8_t *outBuffer);
static TPM_RC TSS_HmacSession_LoadData(TSS_CONTEXT *tssContext,
				       uint32_t *inLength, uint8_t **inData,
				       TPMI_SH_AUTH_SESSION sessionHandle);
static TPM_RC TSS_HmacSession_DeleteData(TSS_CONTEXT *tssContext,
					 TPMI_SH_AUTH_SESSION sessionHandle);
static TPM_RC TSS_HmacSession_GetSlotForHandle(TSS_CONTEXT *tssContext,
					       size_t *slotIndex,
					       TPMI_SH_AUTH_SESSION sessionHandle);
#endif
static TPM_RC TSS_HmacSession_Marshal(struct TSS_HMAC_CONTEXT *source,
				      uint16_t *written, uint8_t **buffer, uint32_t *size);
static TPM_RC TSS_HmacSession_Unmarshal(struct TSS_HMAC_CONTEXT *target,
					uint8_t **buffer, uint32_t *size);

static TPM_RC TSS_Name_GetAllNames(TSS_CONTEXT *tssContext,
				   TPM2B_NAME **names);
static TPM_RC TSS_Name_GetName(TSS_CONTEXT *tssContext,
			       TPM2B_NAME *name,
			       TPM_HANDLE  handle);
static TPM_RC TSS_Name_Store(TSS_CONTEXT *tssContext,
			     TPM2B_NAME *name,
			     TPM_HANDLE handle,
			     const char *string);
static TPM_RC TSS_Name_Load(TSS_CONTEXT *tssContext,
			    TPM2B_NAME *name,
			    TPM_HANDLE handle,
			    const char *string);
static TPM_RC TSS_Name_Copy(TSS_CONTEXT *tssContext,
			    TPM_HANDLE outHandle,
			    const char *outString,
			    TPM_HANDLE inHandle,
			    const char *inString);
static TPM_RC TSS_Public_Store(TSS_CONTEXT *tssContext,
			       TPM2B_PUBLIC *public,
			       TPM_HANDLE handle,
			       const char *string);
static TPM_RC TSS_Public_Load(TSS_CONTEXT *tssContext,
			      TPM2B_PUBLIC *public,
			      TPM_HANDLE handle,
			      const char *string);
static TPM_RC TSS_Public_Copy(TSS_CONTEXT *tssContext,
			      TPM_HANDLE outHandle,
			      const char *outString,
			      TPM_HANDLE inHandle,
			      const char *inString);
#ifdef TPM_TSS_NOFILE
static TPM_RC TSS_ObjectPublic_GetSlotForHandle(TSS_CONTEXT *tssContext,
						size_t *slotIndex,
						TPM_HANDLE handle);
static TPM_RC TSS_ObjectPublic_DeleteData(TSS_CONTEXT *tssContext, TPM_HANDLE handle);
#endif
static TPM_RC TSS_DeleteHandle(TSS_CONTEXT *tssContext,
			       TPM_HANDLE handle);
#ifndef TPM_TSS_NOCRYPTO
static TPM_RC TSS_ObjectPublic_GetName(TPM2B_NAME *name,
				       TPMT_PUBLIC *tpmtPublic);

static TPM_RC TSS_NVPublic_Store(TSS_CONTEXT *tssContext,
				 TPMS_NV_PUBLIC *nvPublic,
				 TPMI_RH_NV_INDEX handle);
static TPM_RC TSS_NVPublic_Load(TSS_CONTEXT *tssContext,
				TPMS_NV_PUBLIC *nvPublic,
				TPMI_RH_NV_INDEX handle);
#endif
static TPM_RC TSS_NVPublic_Delete(TSS_CONTEXT *tssContext,
				  TPMI_RH_NV_INDEX nvIndex);
#ifdef TPM_TSS_NOFILE
static TPM_RC TSS_NvPublic_GetSlotForHandle(TSS_CONTEXT *tssContext,
					    size_t *slotIndex,
					    TPMI_RH_NV_INDEX nvIndex);
#endif

static TPM_RC TSS_Command_Decrypt(TSS_AUTH_CONTEXT *tssAuthContext,
				  struct TSS_HMAC_CONTEXT *session[],
				  TPMI_SH_AUTH_SESSION sessionHandle[],
				  unsigned int sessionAttributes[]);
#ifndef TPM_TSS_NOCRYPTO
static TPM_RC TSS_Command_DecryptXor(TSS_AUTH_CONTEXT *tssAuthContext,
				     struct TSS_HMAC_CONTEXT *session);
static TPM_RC TSS_Command_DecryptAes(TSS_AUTH_CONTEXT *tssAuthContext,
				     struct TSS_HMAC_CONTEXT *session);

#endif	/* TPM_TSS_NOCRYPTO */
static TPM_RC TSS_Response_Encrypt(TSS_AUTH_CONTEXT *tssAuthContext,
				   struct TSS_HMAC_CONTEXT *session[],
				   TPMI_SH_AUTH_SESSION sessionHandle[],
				   unsigned int sessionAttributes[]);
#ifndef TPM_TSS_NOCRYPTO
static TPM_RC TSS_Response_EncryptXor(TSS_AUTH_CONTEXT *tssAuthContext,
				      struct TSS_HMAC_CONTEXT *session);
static TPM_RC TSS_Response_EncryptAes(TSS_AUTH_CONTEXT *tssAuthContext,
				      struct TSS_HMAC_CONTEXT *session);

static TPM_RC TSS_Command_ChangeAuthProcessor(TSS_CONTEXT *tssContext,
					      struct TSS_HMAC_CONTEXT *session,
					      size_t handleNumber,
					      COMMAND_PARAMETERS *in);
#endif	/* TPM_TSS_NOCRYPTO */

static TPM_RC TSS_Command_PreProcessor(TSS_CONTEXT *tssContext,
				       TPM_CC commandCode,
				       COMMAND_PARAMETERS *in,
				       EXTRA_PARAMETERS *extra);
static TPM_RC TSS_Response_PostProcessor(TSS_CONTEXT *tssContext,
					 COMMAND_PARAMETERS *in,
					 RESPONSE_PARAMETERS *out,
					 EXTRA_PARAMETERS *extra);

static TPM_RC TSS_Sessions_GetDecryptSession(unsigned int *isDecrypt,
					     unsigned int *decryptSession,
					     TPMI_SH_AUTH_SESSION sessionHandle[],
					     unsigned int sessionAttributes[]);
static TPM_RC TSS_Sessions_GetEncryptSession(unsigned int *isEncrypt,
					     unsigned int *encryptSession,
					     TPMI_SH_AUTH_SESSION sessionHandle[],
					     unsigned int sessionAttributes[]);

#ifndef TPM_TSS_NOFILE
static TPM_RC TSS_HashToString(char *str, uint8_t *digest);
#endif
#ifndef TPM_TSS_NOCRYPTO
#ifndef TPM_TSS_NORSA
static TPM_RC TSS_RSA_Salt(TPM2B_DIGEST 		*salt,
			   TPM2B_ENCRYPTED_SECRET	*encryptedSalt,
			   TPMT_PUBLIC			*publicArea);
#endif /* TPM_TSS_NORSA */
#endif /* TPM_TSS_NOCRYPTO */
extern int tssVerbose;
extern int tssVverbose;
extern int tssFirstCall;


TPM_RC TSS_Execute20(TSS_CONTEXT *tssContext,
		     RESPONSE_PARAMETERS *out,
		     COMMAND_PARAMETERS *in,
		     EXTRA_PARAMETERS *extra,
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
	if (tssVverbose) printf("TSS_Execute20: Command %08x marshal\n", commandCode);
	rc = TSS_Marshal(tssContext->tssAuthContext,
			 in,
			 commandCode);
    }
    /* execute the command */
    if (rc == 0) {
	rc = TSS_Execute_valist(tssContext, in, ap);
    }
    /* unmarshal the response parameters */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute20: Command %08x unmarshal\n", commandCode);
	rc = TSS_Unmarshal(tssContext->tssAuthContext, out);
    }
    /* handle any command specific response post-processing */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute20: Command %08x post processor\n", commandCode);
	rc = TSS_Response_PostProcessor(tssContext,
					in,
					out,
					extra);
    }
    return rc;
}

/* TSS_Execute_valist() transmits the marshaled command and receives the marshaled response.

   varargs are TPMI_SH_AUTH_SESSION sessionHandle, const char *password, unsigned int
   sessionAttributes

   Terminates with sessionHandle TPM_RH_NULL

   Processes up to MAX_SESSION_NUM sessions.  It handles HMAC generation and command and response
   parameter encryption.  It loads each session context, rolls nonces, and saves or deletes the
   session context.
*/

static TPM_RC TSS_Execute_valist(TSS_CONTEXT *tssContext,
				 COMMAND_PARAMETERS *in,
				 va_list ap)
{
    TPM_RC		rc = 0;
    int 		done;
    int 		haveNames = FALSE;	/* names are common to all HMAC sessions */
    size_t		i = 0;

    /* the vararg parameters */
    TPMI_SH_AUTH_SESSION sessionHandle[MAX_SESSION_NUM];
    const char 		*password[MAX_SESSION_NUM];
    unsigned int	sessionAttributes[MAX_SESSION_NUM]; 

    /* structures filled in */
    TPMS_AUTH_COMMAND 	*authCommand[MAX_SESSION_NUM];
    TPMS_AUTH_RESPONSE 	*authResponse[MAX_SESSION_NUM];
    
    /* pointer to the above structures as used */
    TPMS_AUTH_COMMAND 	*authC[MAX_SESSION_NUM];
    TPMS_AUTH_RESPONSE 	*authR[MAX_SESSION_NUM];

    /* TSS sessions */
    struct TSS_HMAC_CONTEXT *session[MAX_SESSION_NUM];
    TPM2B_NAME *names[MAX_SESSION_NUM];
	
    
    for (i = 0 ; i < MAX_SESSION_NUM ; i++) {
	authCommand[i] = NULL;		/* for safe free */
	authResponse[i] = NULL;		/* for safe free */
 	names[i] = NULL;		/* for safe free */
	authC[i] = NULL;		/* array of TPMS_AUTH_COMMAND structures, NULL for
					   TSS_SetCmdAuths */
	authR[i] = NULL;		/* array of TPMS_AUTH_RESPONSE structures, NULL for
					   TSS_GetRspAuths */
	session[i] = NULL;		/* for free, used for HMAC and encrypt/decrypt sessions */
	/* the varargs list inputs */
	sessionHandle[i] = TPM_RH_NULL;
	password[i] = NULL;
	sessionAttributes[i] = 0;
    }
    /* Step 1: initialization */
    if (tssVverbose) printf("TSS_Execute_valist: Step 1: initialization\n");
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) ; i++) {
	if (rc == 0) {
	    rc = TSS_Malloc((unsigned char **)&authCommand[i],	/* freed @1 */
			    sizeof(TPMS_AUTH_COMMAND));
	}
	if (rc == 0) {
	    rc = TSS_Malloc((unsigned char **)&authResponse[i],	/* freed @2 */
			    sizeof(TPMS_AUTH_RESPONSE));
	}
	if (rc == 0) {
	    rc = TSS_Malloc((unsigned char **)&names[i],	/* freed @3 */
			    sizeof(TPM2B_NAME));
	}
	if (rc == 0) {
	    names[i]->b.size = 0;	/* to ignore unused names in cpHash calculation */
	}
    }
    /* Step 2: gather the command authorizations

       Process PWAP immediately
       For HMAC, get the session context
    */
    done = FALSE;
    for (i = 0 ; (rc == 0) && !done && (i < MAX_SESSION_NUM) ; i++) {
 	sessionHandle[i] = va_arg(ap, TPMI_SH_AUTH_SESSION);	/* first vararg is the session
								   handle */
	password[i]= va_arg(ap, const char *);			/* second vararg is the password */
	sessionAttributes[i] = va_arg(ap, unsigned int);	/* third argument is
								   sessionAttributes */
	sessionAttributes[i] &= 0xff;				/* is uint8_t */

	if (sessionHandle[i] != TPM_RH_NULL) {			/* varargs termination value */ 

	    if (tssVverbose) printf("TSS_Execute_valist: Step 2: authorization %u\n",
				    (unsigned int)i);
	    if (tssVverbose) printf("TSS_Execute_valist: session %u handle %08x\n",
				    (unsigned int)i, sessionHandle[i]);
	    /* make used, non-NULL for command and response varargs */
	    authC[i] = authCommand[i];
	    authR[i] = authResponse[i];

	    /* if password session, populate authC with password, etc. immediately */
	    if (sessionHandle[i] == TPM_RS_PW) {
		rc = TSS_PwapSession_Set(authC[i], password[i]);
	    }
	    /* if HMAC or encrypt/decrypt session  */
	    else {
		/* initialize a TSS HMAC session */
		if (rc == 0) {
		    rc = TSS_HmacSession_GetContext(&session[i]);
		}
		/* load the session created by startauthsession */
		if (rc == 0) {
		    rc = TSS_HmacSession_LoadSession(tssContext, session[i], sessionHandle[i]);
		}
		/* if there is at least one HMAC session, get the names corresponding to the
		   handles */
		if ((session[i]->sessionType == TPM_SE_HMAC) ||		/* HMAC session. OR */
		    ((session[i]->sessionType == TPM_SE_POLICY) &&	/* Policy session AND */

#ifndef TPM_TSS_NOCRYPTO
		     ((session[i]->isAuthValueNeeded) || 		/* PolicyAuthValue ran, OR */
		      (session[i]->sessionKey.b.size != 0)))		/* Already session key (bind or salt) */
#else
		    (session[i]->isAuthValueNeeded))		/* PolicyAuthValue ran, OR */
#endif	/* TPM_TSS_NOCRYPTO */
		    ) {	
		    if ((rc == 0) && !haveNames) {
			rc = TSS_Name_GetAllNames(tssContext, names);
			haveNames = TRUE;	/* get only once, minor optimization */
		    }
		}
	    }
	}
	else {
	    done = TRUE;
	}
    }
    /* Step 3: Roll nonceCaller, save in the session context for the response */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	if (sessionHandle[i] != TPM_RS_PW) {		/* no nonce for password sessions */
	    if (tssVverbose)
		printf("TSS_Execute_valist: Step 3: nonceCaller %08x\n", sessionHandle[i]);
#ifndef TPM_TSS_NOCRYPTO
	    rc = TSS_HmacSession_SetNonceCaller(session[i], authC[i]);
#else
	    authC[i]->nonce.b.size = 16;
	    memset(&authC[i]->nonce.b.buffer, 0, 16);
#endif	/* TPM_TSS_NOCRYPTO */
	}
    }
    
#ifndef TPM_TSS_NOCRYPTO
    /* Step 4: Calculate the HMAC key */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	if (sessionHandle[i] != TPM_RS_PW) {		/* no HMAC key for password sessions */
	    if (tssVverbose) printf("TSS_Execute_valist: Step 4: Session %u HMAC key for %08x\n",
				    (unsigned int)i, sessionHandle[i]);
	    rc = TSS_HmacSession_SetHmacKey(tssContext, session[i], i, password[i]);
	}
    }
#endif	/* TPM_TSS_NOCRYPTO */
    /* Step 5: command parameter encryption */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute_valist: Step 5: command encrypt\n");
	rc = TSS_Command_Decrypt(tssContext->tssAuthContext,
				 session,
				 sessionHandle,
				 sessionAttributes);
    }
    /* Step 6: for each HMAC session, calculate cpHash, calculate the HMAC, and set it in
       TPMS_AUTH_COMMAND */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute_valist: Step 6 calculate HMACs\n");
	rc = TSS_HmacSession_SetHMAC(tssContext->tssAuthContext,	/* TSS auth context */
				     session,		/* TSS session contexts */
				     authC,		/* output: command authorizations */
				     sessionHandle,	/* list of session handles for the command */
				     sessionAttributes, /* attributes for this command */
				     password,		/* for plaintext password sessions */
				     names[0],		/* Name */
				     names[1],		/* Name */
				     names[2]);		/* Name */
    }
    /* Step 7: set the command authorizations in the TSS command stream */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute_valist: Step 7 set command authorizations\n");
	rc = TSS_SetCmdAuths(tssContext->tssAuthContext,
			     authC[0],
			     authC[1],
			     authC[2],
			     NULL);
    }
    /* Step 8: process the command.  Normally returns the TPM response code. */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute_valist: Step 8: process the command\n");
	rc = TSS_AuthExecute(tssContext);
    }
    /* Step 9: get the response authorizations from the TSS response stream */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute_valist: Step 9 get response authorizations\n");
	rc = TSS_GetRspAuths(tssContext->tssAuthContext,
			     authR[0],
			     authR[1],
			     authR[2],
			     NULL);
    }
    /* Step 10: process the response authorizations, validate the HMAC */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	if (tssVverbose)
	    printf("TSS_Execute_valist: Step 10: process response authorization %08x\n",
		   sessionHandle[i]);
	if (sessionHandle[i] == TPM_RS_PW) {
	    rc = TSS_PwapSession_Verify(authR[i]);
	}
	/* HMAC session */
	else {
#ifndef TPM_TSS_NOCRYPTO
	    /* save nonceTPM in the session context */
	    if (rc == 0) {
		rc = TSS_TPM2B_Copy(&session[i]->nonceTPM.b, &authR[i]->nonce.b, sizeof(TPMU_HA));
	    }
#endif	/* TPM_TSS_NOCRYPTO */
	    /* the HMAC key is already part of the TSS session context.  For policy sessions with
	       policy password, the response hmac is empty. */
	    if ((session[i]->sessionType == TPM_SE_HMAC) ||
		((session[i]->sessionType == TPM_SE_POLICY) && (session[i]->isAuthValueNeeded))) {
#ifndef TPM_TSS_NOCRYPTO
		if (rc == 0) {
		    rc = TSS_Command_ChangeAuthProcessor(tssContext, session[i], i, in);
		}
		if (rc == 0) {
		    rc = TSS_HmacSession_Verify(tssContext->tssAuthContext, /* authorization
									       context */
						session[i],	/* TSS session context */
						authR[i]);	/* input: response authorization */
		}
#else
		in = in;
		if (tssVerbose)
		    printf("TSS_Execute_valist: "
			   "Error, HMAC verify with no crypto not implemented\n");
		rc = TSS_RC_NOT_IMPLEMENTED;
#endif	/* TPM_TSS_NOCRYPTO */
	    }
	}
    }
    /* Step 11: process the audit flag */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	if ((sessionHandle[i] != TPM_RS_PW) &&
	    (session[i]->bind != TPM_RH_NULL) &&
	    (authR[i]->sessionAttributes.val & TPMA_SESSION_AUDIT)) {
	    if (tssVverbose) printf("TSS_Execute_valist: Step 11: process bind audit flag %08x\n",
				    sessionHandle[i]);
	    /* if bind audit session, bind value is lost and further use requires authValue */
	    session[i]->bind = TPM_RH_NULL;
	}
    }
    /* Step 12: process the response continue flag */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	if (sessionHandle[i] != TPM_RS_PW) {
	    if (tssVverbose) printf("TSS_Execute_valist: Step 12: process continue flag %08x\n",
				    sessionHandle[i]);
	    rc = TSS_HmacSession_Continue(tssContext, session[i], authR[i]);
	}
    }
    /* Step 13: response parameter decryption */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Execute_valist: Step 13: response decryption\n");
	rc = TSS_Response_Encrypt(tssContext->tssAuthContext,
				  session,
				  sessionHandle,
				  sessionAttributes);
    }
    /* cleanup */
    for (i = 0 ; i < MAX_SESSION_NUM ; i++) {
	TSS_HmacSession_FreeContext(session[i]);
	free(authCommand[i]);		/* @1 */
 	free(authResponse[i]);		/* @2 */
	free(names[i]);			/* @3 */
    }
    return rc;
}

/*
  PWAP - Password Session
*/

/* TSS_PwapSession_Set() sets all members of the TPMS_AUTH_COMMAND structure for a PWAP session.
 */

static TPM_RC TSS_PwapSession_Set(TPMS_AUTH_COMMAND *authCommand,
				  const char *password)
{
    TPM_RC		rc = 0;
    
    if (rc == 0) {
	authCommand->sessionHandle = TPM_RS_PW;
	authCommand->nonce.t.size = 0;
	authCommand->sessionAttributes.val = 0;
    }
    if (password != NULL) {
	rc = TSS_TPM2B_StringCopy(&authCommand->hmac.b,
				  password, sizeof(authCommand->hmac.t.buffer));
    }
    else {
	authCommand->hmac.t.size = 0;
    }
    return rc;
}

/* TSS_PwapSession_Verify() verifies the PWAP session response. */

static TPM_RC TSS_PwapSession_Verify(TPMS_AUTH_RESPONSE *authResponse)
{
    TPM_RC		rc = 0;

    if (rc == 0) {
	if (authResponse->nonce.t.size != 0) {
	    if (tssVerbose) printf("TSS_PwapSession_Verify: nonce size %u not zero\n",
				   authResponse->nonce.t.size);
	    rc = TSS_RC_BAD_PWAP_NONCE;
	}
    }
    if (rc == 0) {
	if (authResponse->sessionAttributes.val != TPMA_SESSION_CONTINUESESSION) {
	    if (tssVerbose) printf("TSS_PwapSession_Verify: continue %02x not set\n",
				   authResponse->sessionAttributes.val);
	    rc = TSS_RC_BAD_PWAP_ATTRIBUTES;
	}
    }
    if (rc == 0) {
	if (authResponse->hmac.t.size != 0) {
	    if (tssVerbose) printf("TSS_PwapSession_Verify: HMAC size %u not zero\n",
				   authResponse->hmac.t.size);
	    rc = TSS_RC_BAD_PWAP_HMAC;
	}
    }
    return rc;
}

/*
  HMAC Session
*/

static TPM_RC TSS_HmacSession_GetContext(struct TSS_HMAC_CONTEXT **session)
{
    TPM_RC rc = 0;

    if (rc == 0) {
        rc = TSS_Malloc((uint8_t **)session, sizeof(TSS_HMAC_CONTEXT));
    }
    if (rc == 0) {
	TSS_HmacSession_InitContext(*session);
    }
    return rc;
}

static void TSS_HmacSession_InitContext(struct TSS_HMAC_CONTEXT *session)
{
    session->sessionHandle = TPM_RH_NULL;
    session->authHashAlg = TPM_ALG_NULL;
#ifndef TPM_TSS_NOCRYPTO
    session->sizeInBytes = 0;
#endif
    session->symmetric.algorithm = TPM_ALG_NULL;
    session->bind = TPM_RH_NULL;
    session->bindName.b.size = 0;
    session->bindAuthValue.t.size = 0;
#ifndef TPM_TSS_NOCRYPTO
    memset(session->nonceTPM.t.buffer, 0, sizeof(TPMU_HA));
    session->nonceTPM.b.size = 0;
    memset(session->nonceCaller.t.buffer, 0, sizeof(TPMU_HA));
    session->nonceCaller.b.size = 0;
    memset(session->sessionKey.t.buffer, 0, sizeof(TPMU_HA));
    session->sessionKey.b.size = 0;
#endif
    session->sessionType = 0;
    session->isPasswordNeeded = FALSE;
    session->isAuthValueNeeded = FALSE;
    memset(session->hmacKey.t.buffer, 0, sizeof(TPMU_HA) + sizeof(TPMU_HA));
    session->hmacKey.b.size = 0;
#ifndef TPM_TSS_NOCRYPTO
    memset(session->sessionValue.t.buffer, 0, sizeof(TPMU_HA) + sizeof(TPMU_HA));
    session->sessionValue.b.size = 0;
#endif
}

void TSS_HmacSession_FreeContext(struct TSS_HMAC_CONTEXT *session)
{
    if (session != NULL) {
	TSS_HmacSession_InitContext(session);
	free(session);
    }
    return;
}

/* TSS_HmacSession_SetSessionKey() is called by the StartAuthSession post processor to calculate and
   store the session key

   19.6.8	sessionKey Creation
*/

#ifndef TPM_TSS_NOCRYPTO

static TPM_RC TSS_HmacSession_SetSessionKey(TSS_CONTEXT *tssContext,
					    struct TSS_HMAC_CONTEXT *session,
					    TPM2B_DIGEST *salt,
					    TPMI_DH_ENTITY bind,
					    TPM2B_AUTH *bindAuthValue)
{
    TPM_RC		rc = 0;
    TPM2B_KEY 		key;		/* HMAC key for the KDFa */

    if (rc == 0) {
	/* save the bind handle, non-null indicates a bound session */
	session->bind = bind;
	/* if bind, save the bind Name in the session context.  The handle might change, but the
	   name will not */
	if ((rc == 0) && (bind != TPM_RH_NULL)) {
	    rc = TSS_Name_GetName(tssContext, &session->bindName, bind);
	}
    }
    if (rc == 0) {
        if ((bind != TPM_RH_NULL) ||
	    (salt->b.size != 0)) {

	    /* session key is bindAuthValue || salt */
	    /* copy bindAuthValue.  This is set during the post processor to either the supplied
	       bind password or Empty */
	    if (rc == 0) {
		rc = TSS_TPM2B_Copy(&key.b, &bindAuthValue->b, sizeof(TPMU_HA) + sizeof(TPMT_HA));
	    }
	    /* copy salt.  This is set during the postprocessor to either the salt from the
	       preprocessor or empty. */
	    if (rc == 0) {
		rc = TSS_TPM2B_Append(&key.b, &salt->b, sizeof(TPMU_HA) + sizeof(TPMT_HA));
	    }
	    if (rc == 0) {
		if (tssVverbose) TSS_PrintAll("TSS_HmacSession_SetSessionKey: KDFa HMAC key",
					      key.b.buffer, key.b.size);
	    }
	    /* KDFa for the session key */
	    if (rc == 0) {
		rc = TSS_KDFA(session->sessionKey.b.buffer,
			      session->authHashAlg,
			      &key.b,
			      "ATH",
			      &session->nonceTPM.b,
			      &session->nonceCaller.b,
			      session->sizeInBytes * 8);
	    }
	    if (rc == 0) {
		session->sessionKey.b.size = session->sizeInBytes;
		if (tssVverbose)
		    TSS_PrintAll("TSS_HmacSession_SetSessionKey: Session key",
				 session->sessionKey.b.buffer, session->sessionKey.b.size);
	    }
	}
	else {
	    session->sessionKey.b.size = 0;
	}
    }
    return rc;
}

#endif	/* TPM_TSS_NOCRYPTO */

/* TSS_HmacSession_SaveSession() saves a session in two cases:

   The initial session from startauthsession
   The updated session a TPM response
*/


static TPM_RC TSS_HmacSession_SaveSession(TSS_CONTEXT *tssContext,
					  struct TSS_HMAC_CONTEXT *session)
{
    TPM_RC	rc = 0;
    uint8_t 	*buffer = NULL;		/* marshaled TSS_HMAC_CONTEXT */
    uint16_t	written = 0;
#ifndef TPM_TSS_NOFILE
    char	sessionFilename[TPM_DATA_DIR_PATH_LENGTH];
    uint8_t *outBuffer = NULL;
    uint32_t outLength;
#endif
    
    if (tssVverbose) printf("TSS_HmacSession_SaveSession: handle %08x\n", session->sessionHandle);
    if (rc == 0) {
	rc = TSS_Structure_Marshal(&buffer,	/* freed @1 */
				   &written,
				   session,
				   (MarshalFunction_t)TSS_HmacSession_Marshal);
    }
#ifndef TPM_TSS_NOFILE
    if (rc == 0) {
#ifndef TPM_TSS_NOCRYPTO
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
#endif	/* TPM_TSS_NOCRYPTO */
	    outBuffer = buffer;
	    outLength = written;
#ifndef TPM_TSS_NOCRYPTO
	}
#endif	/* TPM_TSS_NOCRYPTO */
    }
    /* save the session in a hard coded file name hxxxxxxxx.bin where xxxxxxxx is the session
       handle */
    if (rc == 0) {
	sprintf(sessionFilename, "%s/h%08x.bin",
		tssContext->tssDataDirectory, session->sessionHandle);
    }
    if (rc == 0) {
	rc = TSS_File_WriteBinaryFile(outBuffer,
				      outLength,
				      sessionFilename);
    }
    if (tssContext->tssEncryptSessions) {
	free(outBuffer);	/* @2 */
    }
#else		/* no file support, save to context */
    if (rc == 0) {
	rc = TSS_HmacSession_SaveData(tssContext,
				      session->sessionHandle,
				      written, buffer);
    }
#endif
    free(buffer);	/* @1 */
    return rc;
}

/* TSS_HmacSession_LoadSession() loads an existing HMAC session context saved by:

   startauthsession
   an update after a TPM response
*/

static TPM_RC TSS_HmacSession_LoadSession(TSS_CONTEXT *tssContext,
					  struct TSS_HMAC_CONTEXT *session,
					  TPMI_SH_AUTH_SESSION	sessionHandle)
{
    TPM_RC		rc = 0;
    uint8_t 		*buffer = NULL;
    uint8_t 		*buffer1 = NULL;
#ifndef TPM_TSS_NOFILE
    size_t 		length = 0;
    char		sessionFilename[TPM_DATA_DIR_PATH_LENGTH];
#endif    
    unsigned char 	*inData = NULL;		/* output */
    uint32_t 		inLength;		/* output */

    if (tssVverbose) printf("TSS_HmacSession_LoadSession: handle %08x\n", sessionHandle);
#ifndef TPM_TSS_NOFILE
    /* load the session from a hard coded file name hxxxxxxxx.bin where xxxxxxxx is the session
       handle */
    if (rc == 0) {
	sprintf(sessionFilename, "%s/h%08x.bin", tssContext->tssDataDirectory, sessionHandle);
	rc = TSS_File_ReadBinaryFile(&buffer,     /* freed @1 */
				     &length,
				     sessionFilename);
    }
    if (rc == 0) {
#ifndef TPM_TSS_NOCRYPTO
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
#endif	/* TPM_TSS_NOCRYPTO */
	    inData = buffer;
	    inLength = length;
#ifndef TPM_TSS_NOCRYPTO
	}
#endif	/* TPM_TSS_NOCRYPTO */
    }
#else		/* no file support, load from context */
    if (rc == 0) {
	rc = TSS_HmacSession_LoadData(tssContext,
				      &inLength, &inData,
				      sessionHandle);
    }
#endif
    if (rc == 0) {
	uint32_t ilength = inLength;
	buffer1 = inData;
	rc = TSS_HmacSession_Unmarshal(session, &buffer1, &ilength);
    }
#ifndef TPM_TSS_NOFILE
    if (tssContext->tssEncryptSessions) {
	free(inData);	/* @2 */
    }
#endif
    free(buffer);	/* @1 */
    return rc;
}

#ifdef TPM_TSS_NOFILE

static TPM_RC TSS_HmacSession_SaveData(TSS_CONTEXT *tssContext,
				       TPMI_SH_AUTH_SESSION sessionHandle,
				       uint32_t outLength,
				       uint8_t *outBuffer)
{
    TPM_RC	rc = 0;
    size_t	slotIndex;

    /* if this handle is already used, overwrite the slot */
    if (rc == 0) {
	rc = TSS_HmacSession_GetSlotForHandle(tssContext, &slotIndex, sessionHandle);
	if (rc != 0) {
	    rc = TSS_HmacSession_GetSlotForHandle(tssContext, &slotIndex, TPM_RH_NULL);
	    if (rc == 0) {
		tssContext->sessions[slotIndex].sessionHandle = sessionHandle;
	    }
	    else {
		if (tssVerbose)
		    printf("TSS_HmacSession_SaveData: Error, no slot available for handle %08x\n",
			   sessionHandle);
	    }
	}
    }
    /* reallocate memory and adjust the size */
    if (rc == 0) {
	rc = TSS_Realloc(&tssContext->sessions[slotIndex].sessionData, outLength);
    }
    if (rc == 0) {
	tssContext->sessions[slotIndex].sessionDataLength = outLength;
	memcpy(tssContext->sessions[slotIndex].sessionData, outBuffer, outLength);
    }
    return rc;
}

static TPM_RC TSS_HmacSession_LoadData(TSS_CONTEXT *tssContext,
				       uint32_t *inLength, uint8_t **inData,
				       TPMI_SH_AUTH_SESSION sessionHandle)
{
    TPM_RC	rc = 0;
    size_t	slotIndex;

    if (rc == 0) {
	rc = TSS_HmacSession_GetSlotForHandle(tssContext, &slotIndex, sessionHandle);
	if (rc != 0) {
	    if (tssVerbose)
		printf("TSS_HmacSession_LoadData: Error, no slot found for handle %08x\n",
		       sessionHandle);
	}
    }
    if (rc == 0) {
	*inLength = tssContext->sessions[slotIndex].sessionDataLength;
	*inData = tssContext->sessions[slotIndex].sessionData;
    }
    return rc;
}

static TPM_RC TSS_HmacSession_DeleteData(TSS_CONTEXT *tssContext,
					 TPMI_SH_AUTH_SESSION sessionHandle)
{
    TPM_RC	rc = 0;
    size_t	slotIndex;

    if (rc == 0) {
	rc = TSS_HmacSession_GetSlotForHandle(tssContext, &slotIndex, sessionHandle);
	if (rc != 0) {
	    if (tssVerbose)
		printf("TSS_HmacSession_DeleteData: Error, no slot found for handle %08x\n",
		       sessionHandle);
	}
    }    
    if (rc == 0) {
	tssContext->sessions[slotIndex].sessionHandle = TPM_RH_NULL;
	/* erase any secrets */
	memset(tssContext->sessions[slotIndex].sessionData, 0,
	       tssContext->sessions[slotIndex].sessionDataLength);
	free(tssContext->sessions[slotIndex].sessionData);
	tssContext->sessions[slotIndex].sessionData = NULL;
	tssContext->sessions[slotIndex].sessionDataLength = 0;
    }
    return rc;
}

/* TSS_HmacSession_GetSlotForHandle() finds the session slot corresponding to the session handle.

   Returns non-zero if no slot is found.
*/

static TPM_RC TSS_HmacSession_GetSlotForHandle(TSS_CONTEXT *tssContext,
					       size_t *slotIndex,
					       TPMI_SH_AUTH_SESSION sessionHandle)
{
    size_t 	i;

    /* search all slots for handle */
    for (i = 0 ; i < (sizeof(tssContext->sessions) / sizeof(TSS_SESSIONS)) ; i++) {
	if (tssContext->sessions[i].sessionHandle == sessionHandle) {
	    *slotIndex = i;
	    return 0;
	}
    }
    return TSS_RC_NO_SESSION_SLOT;
}

#endif

static TPM_RC TSS_HmacSession_Marshal(struct TSS_HMAC_CONTEXT *source,
					uint16_t *written,
					uint8_t **buffer,
					uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_TPMI_SH_AUTH_SESSION_Marshalu(&source->sessionHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->authHashAlg, written, buffer, size);
    }
#ifndef TPM_TSS_NOCRYPTO
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->sizeInBytes, written, buffer, size);
    }
#endif
    if (rc == 0) {
	rc = TSS_TPMT_SYM_DEF_Marshalu(&source->symmetric, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_ENTITY_Marshalu(&source->bind, written, buffer, size);
    }   
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshalu(&source->bindName, written, buffer, size);
    }
#ifdef TPM_WINDOWS
    /* FIXME Why does a VS release build need a printf here? */
    if (tssVverbose) printf("");
#endif
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshalu(&source->bindAuthValue, written, buffer, size);
    }
#ifndef TPM_TSS_NOCRYPTO
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshalu(&source->nonceTPM, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshalu(&source->nonceCaller, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->sessionKey, written, buffer, size);
    }
#endif
    if (rc == 0) {
	rc = TSS_TPM_SE_Marshalu(&source->sessionType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->isPasswordNeeded, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->isAuthValueNeeded, written, buffer, size);
    }  
    return rc;
}

static TPM_RC TSS_HmacSession_Unmarshal(struct TSS_HMAC_CONTEXT *target,
					uint8_t **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_TPMI_SH_AUTH_SESSION_Unmarshalu(&target->sessionHandle, buffer, size, NO);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->authHashAlg, buffer, size, NO);
    }
#ifndef TPM_TSS_NOCRYPTO
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->sizeInBytes, buffer, size);
    }
#endif
    if (rc == 0) {
	rc = TSS_TPMT_SYM_DEF_Unmarshalu(&target->symmetric, buffer, size, YES);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_ENTITY_Unmarshalu(&target->bind, buffer, size, YES);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->bindName, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Unmarshalu(&target->bindAuthValue, buffer, size);
    }
#ifndef TPM_TSS_NOCRYPTO
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Unmarshalu(&target->nonceTPM, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Unmarshalu(&target->nonceCaller, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->sessionKey, buffer, size);
    }
#endif
    if (rc == 0) {
	rc = TSS_TPM_SE_Unmarshalu(&target->sessionType, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&target->isPasswordNeeded, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&target->isAuthValueNeeded, buffer, size);
    }
    return rc;
}

/*
  Name handling
*/

/* TSS_Name_GetAllNames() files in the names array based on the handles marshaled into the TSS
   context command stream. */

static TPM_RC TSS_Name_GetAllNames(TSS_CONTEXT *tssContext,
				   TPM2B_NAME **names)
{
    TPM_RC	rc = 0;
    size_t	i;
    size_t	commandHandleCount;	/* number of handles in the command stream */
    TPM_HANDLE  commandHandle;

    /* get the number of handles in the command stream */
    if (rc == 0) {
	rc = TSS_GetCommandHandleCount(tssContext->tssAuthContext, &commandHandleCount);
	if (tssVverbose) printf("TSS_Name_GetAllNames: commandHandleCount %u\n",
				(unsigned int)commandHandleCount);
    }
    for (i = 0 ; (rc == 0) && (i < commandHandleCount) ; i++) {
	/* get a handle from the command stream */
	if (rc == 0) {
	    rc = TSS_GetCommandHandle(tssContext->tssAuthContext,
				      &commandHandle,
				      i);
	}
	/* get the Name corresponding to the handle */
	if (rc == 0) {
	    if (tssVverbose) printf("TSS_Name_GetAllNames: commandHandle %u %08x\n",
				    (unsigned int)i, commandHandle);
	    rc = TSS_Name_GetName(tssContext, names[i], commandHandle);
	}
    }
    return rc;
}

/* TSS_Name_GetName() gets the Name associated with the handle */

static TPM_RC TSS_Name_GetName(TSS_CONTEXT *tssContext,
			       TPM2B_NAME *name,
			       TPM_HANDLE  handle)
{
    TPM_RC	rc = 0;
    TPM_HT 	handleType;

    if (tssVverbose) printf("TSS_Name_GetName: Handle %08x\n", handle);
    handleType = (TPM_HT) ((handle & HR_RANGE_MASK) >> HR_SHIFT);

    /* Table 3 - Equations for Computing Entity Names */
    switch (handleType) {
	/* for these, the Name is simply the handle value */
      case TPM_HT_PCR:
      case TPM_HT_HMAC_SESSION:
      case TPM_HT_POLICY_SESSION:
      case TPM_HT_PERMANENT:
	rc = TSS_TPM2B_CreateUint32(&name->b, handle, sizeof(name->t.name));
	break;
	/* for NV, the Names was calculated at NV read public */
      case TPM_HT_NV_INDEX:
	/* for objects, the Name was returned at creation or load */
      case TPM_HT_TRANSIENT:
      case TPM_HT_PERSISTENT:
	rc = TSS_Name_Load(tssContext, name, handle, NULL);
	break;
      default:
	if (tssVerbose) printf("TSS_Name_GetName: not implemented for handle %08x\n", handle);
	rc = TSS_RC_NAME_NOT_IMPLEMENTED;
	break;
    }
    if (rc == 0) {
	if (tssVverbose)
	    TSS_PrintAll("TSS_Name_GetName: ",
			 name->t.name, name->t.size);
    }
    
    return rc;
}

/* TSS_Name_Store() stores the 'name' parameter in a file.

   If handle is not 0, the handle is used as the file name.

   If 'string' is not NULL, the string is used as the file name.
*/

#ifndef TPM_TSS_NOFILE

static TPM_RC TSS_Name_Store(TSS_CONTEXT *tssContext,
			     TPM2B_NAME *name,
			     TPM_HANDLE handle,
			     const char *string)
{
    TPM_RC 	rc = 0;
    char 	nameFilename[TPM_DATA_DIR_PATH_LENGTH];

    if (rc == 0) {
	if (string == NULL) {
	    if (handle != 0) {
		sprintf(nameFilename, "%s/h%08x.bin", tssContext->tssDataDirectory, handle);
	    }
	    else {
		if (tssVerbose) printf("TSS_Name_Store: handle and string are both null");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
	else {
	    if (handle == 0) {
		sprintf(nameFilename, "%s/h%s.bin", tssContext->tssDataDirectory, string);
	    }
	    else {
		if (tssVerbose) printf("TSS_Name_Store: handle and string are both not null");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Name_Store: File %s\n", nameFilename);
	rc = TSS_File_WriteBinaryFile(name->b.buffer, name->b.size, nameFilename);
    }
    return rc;
}

#endif

/* TSS_Name_Load() loads the 'name' from a file.

   If handle is not 0, the handle is used as the file name.

   If 'string' is not NULL, the string is used as the file name.
*/
   
#ifndef TPM_TSS_NOFILE

static TPM_RC TSS_Name_Load(TSS_CONTEXT *tssContext,
			    TPM2B_NAME *name,
			    TPM_HANDLE handle,
			    const char *string)
{
    TPM_RC 		rc = 0;
    char 		nameFilename[TPM_DATA_DIR_PATH_LENGTH];
		
    if (rc == 0) {
	if (string == NULL) {
	    if (handle != 0) {
		sprintf(nameFilename, "%s/h%08x.bin", tssContext->tssDataDirectory, handle);
	    }
	    else {
		if (tssVerbose) printf("TSS_Name_Load: handle and string are both null\n");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
	else {
	    if (handle == 0) {
		sprintf(nameFilename, "%s/h%s.bin", tssContext->tssDataDirectory, string);
	    }
	    else {
		if (tssVerbose) printf("TSS_Name_Load: handle and string are both not null\n");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Name_Load: File %s\n", nameFilename);
	rc = TSS_File_Read2B(&name->b,
			     sizeof(name->t.name),
			     nameFilename);
    }
    return rc;
}

#endif

/* TSS_Name_Store() stores the 'name' parameter the TSS context.
   
*/

#ifdef TPM_TSS_NOFILE

static TPM_RC TSS_Name_Store(TSS_CONTEXT *tssContext,
			     TPM2B_NAME *name,
			     TPM_HANDLE handle,
			     const char *string)
{
    TPM_RC 	rc = 0;
    TPM_HT 	handleType;
    size_t	slotIndex;

    if (tssVverbose) printf("TSS_Name_Store: Handle %08x\n", handle);
    handleType = (TPM_HT) ((handle & HR_RANGE_MASK) >> HR_SHIFT);

    switch (handleType) {
      case TPM_HT_NV_INDEX:
	/* for NV, the Name was returned at creation */
	rc = TSS_NvPublic_GetSlotForHandle(tssContext, &slotIndex, handle);
	if (rc != 0) {
	    rc = TSS_NvPublic_GetSlotForHandle(tssContext, &slotIndex, TPM_RH_NULL);
	    if (rc == 0) {
		tssContext->nvPublic[slotIndex].nvIndex = handle;
	    }
	    else {
		if (tssVerbose)
		    printf("TSS_Name_Store: Error, no slot available for handle %08x\n", handle);
	    }
	}
	if (rc == 0) {
	    tssContext->nvPublic[slotIndex].name = *name;
	}
	break;
      case TPM_HT_TRANSIENT:
      case TPM_HT_PERSISTENT:
	if (rc == 0) {
	    if (string == NULL) {
		if (handle != 0) {
		    /* if this handle is already used, overwrite the slot */
		    rc = TSS_ObjectPublic_GetSlotForHandle(tssContext, &slotIndex, handle);
		    if (rc != 0) {
			rc = TSS_ObjectPublic_GetSlotForHandle(tssContext, &slotIndex, TPM_RH_NULL);
			if (rc == 0) {
			    tssContext->objectPublic[slotIndex].objectHandle = handle;
			}
			else {
			    if (tssVerbose)
				printf("TSS_Name_Store: "
				       "Error, no slot available for handle %08x\n",
				       handle);
			}
		    }
		}
		else {
		    if (tssVerbose) printf("TSS_Name_Store: handle and string are both null");
		    rc = TSS_RC_NAME_FILENAME;
		}
	    }
	    else {
		if (handle == 0) {
		    if (tssVerbose) printf("TSS_Name_Store: string unimplemented");
		    rc = TSS_RC_NAME_FILENAME;
		}
		else {
		    if (tssVerbose) printf("TSS_Name_Store: handle and string are both not null");
		    rc = TSS_RC_NAME_FILENAME;
		}
	    }
	}
	if (rc == 0) {
	    tssContext->objectPublic[slotIndex].name = *name;
	}
	break;
      default:
	if (tssVerbose) printf("TSS_Name_Store: handle type %02x unimplemented", handleType);
	rc = TSS_RC_NAME_FILENAME;
    }
    return rc;
}

#endif

/* TSS_Name_Load() loads the 'name' from the TSS context.
   
*/
   
#ifdef TPM_TSS_NOFILE

static TPM_RC TSS_Name_Load(TSS_CONTEXT *tssContext,
			    TPM2B_NAME *name,
			    TPM_HANDLE handle,
			    const char *string)
{
    TPM_RC 	rc = 0;
    TPM_HT 	handleType;
    size_t	slotIndex;

    string = string;
    
    if (tssVverbose) printf("TSS_Name_Load: Handle %08x\n", handle);
    handleType = (TPM_HT) ((handle & HR_RANGE_MASK) >> HR_SHIFT);

    switch (handleType) {
      case TPM_HT_NV_INDEX:
	rc = TSS_NvPublic_GetSlotForHandle(tssContext, &slotIndex, handle);
	if (rc != 0) {
	    if (tssVerbose)
		printf("TSS_Name_Load: Error, no slot found for handle %08x\n", handle);
	}
	if (rc == 0) {
	    *name = tssContext->nvPublic[slotIndex].name;
	}
	break;
      case TPM_HT_TRANSIENT:
      case TPM_HT_PERSISTENT:
	rc = TSS_ObjectPublic_GetSlotForHandle(tssContext, &slotIndex, handle);
	if (rc != 0) {
	    if (tssVerbose)
		printf("TSS_Name_Load: Error, no slot found for handle %08x\n", handle);
	}
	if (rc == 0) {
	    *name = tssContext->objectPublic[slotIndex].name;
	}
	break;
      default:
	if (tssVerbose) printf("TSS_Name_Load: handle type %02x unimplemented", handleType);
	rc = TSS_RC_NAME_FILENAME;
	
    }
    return rc;
}

#endif

/* TSS_Name_Copy() copies the name from either inHandle or inString to either outHandle or
   outString */

static TPM_RC TSS_Name_Copy(TSS_CONTEXT *tssContext,
			    TPM_HANDLE outHandle,
			    const char *outString,
			    TPM_HANDLE inHandle,
			    const char *inString)
{
    TPM_RC 		rc = 0;
    TPM2B_NAME 		name;
    
    if (rc == 0) {
	rc = TSS_Name_Load(tssContext, &name, inHandle, inString);
    }
    if (rc == 0) {
	rc = TSS_Name_Store(tssContext, &name, outHandle, outString);
    }
    return rc;
}

/* TSS_Public_Store() stores the 'public' parameter in a file.

   If handle is not 0, the handle is used as the file name.

   If 'string' is not NULL, the string is used as the file name.
*/

#ifndef TPM_TSS_NOFILE

static TPM_RC TSS_Public_Store(TSS_CONTEXT *tssContext,
			       TPM2B_PUBLIC *public,
			       TPM_HANDLE handle,
			       const char *string)
{
    TPM_RC 	rc = 0;
    char 	publicFilename[TPM_DATA_DIR_PATH_LENGTH];

    if (rc == 0) {
	if (string == NULL) {
	    if (handle != 0) {		/* store by handle */
		sprintf(publicFilename, "%s/hp%08x.bin", tssContext->tssDataDirectory, handle);
	    }
	    else {
		if (tssVerbose) printf("TSS_Public_Store: handle and string are both null");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
	else {
	    if (handle == 0) {		/* store by string */
		sprintf(publicFilename, "%s/hp%s.bin", tssContext->tssDataDirectory, string);
	    }
	    else {
		if (tssVerbose) printf("TSS_Public_Store: handle and string are both not null");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Public_Store: File %s\n", publicFilename);
	rc = TSS_File_WriteStructure(public,
				     (MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshalu,
				     publicFilename);
    }
    return rc;
}

#endif

/* TSS_Public_Load() loads the 'public' parameter from a file.

   If handle is not 0, the handle is used as the file name.

   If 'string' is not NULL, the string is used as the file name.
*/
   
#ifndef TPM_TSS_NOFILE

static TPM_RC TSS_Public_Load(TSS_CONTEXT *tssContext,
			      TPM2B_PUBLIC *public,
			      TPM_HANDLE handle,
			      const char *string)
{
    TPM_RC 	rc = 0;
    char 	publicFilename[TPM_DATA_DIR_PATH_LENGTH];
		
    if (rc == 0) {
	if (string == NULL) {
	    if (handle != 0) {
		sprintf(publicFilename, "%s/hp%08x.bin", tssContext->tssDataDirectory, handle);
	    }
	    else {
		if (tssVerbose) printf("TSS_Public_Load: handle and string are both null\n");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
	else {
	    if (handle == 0) {
		sprintf(publicFilename, "%s/hp%s.bin", tssContext->tssDataDirectory, string);
	    }
	    else {
		if (tssVerbose) printf("TSS_Public_Load: handle and string are both not null\n");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
    }
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Public_Load: File %s\n", publicFilename);
	rc = TSS_File_ReadStructureFlag(public,
					(UnmarshalFunctionFlag_t)TSS_TPM2B_PUBLIC_Unmarshalu,
					TRUE,			/* NULL permitted */
					publicFilename);
    }
    return rc;
}

#endif 	/* TPM_TSS_NOFILE */

/* TSS_Public_Copy() copies the TPM2B_PUBLIC from either inHandle or inString to either outHandle or
   outString */

static TPM_RC TSS_Public_Copy(TSS_CONTEXT *tssContext,
			      TPM_HANDLE outHandle,
			      const char *outString,
			      TPM_HANDLE inHandle,
			      const char *inString)
{
    TPM_RC 		rc = 0;
    TPM2B_PUBLIC 	public;
    
    if (rc == 0) {
	rc = TSS_Public_Load(tssContext, &public, inHandle, inString);
    }
    if (rc == 0) {
	rc = TSS_Public_Store(tssContext, &public, outHandle, outString);
    }
    return rc;
}

/* TSS_Public_Store() stores the 'public' parameter in the TSS context. 
 */
   
#ifdef TPM_TSS_NOFILE

static TPM_RC TSS_Public_Store(TSS_CONTEXT *tssContext,
			       TPM2B_PUBLIC *public,
			       TPM_HANDLE handle,
			       const char *string)
{
    TPM_RC 	rc = 0;
    size_t	slotIndex;

    if (rc == 0) {
	if (string == NULL) {
	    if (handle != 0) {
		/* if this handle is already used, overwrite the slot */
		rc = TSS_ObjectPublic_GetSlotForHandle(tssContext, &slotIndex, handle);
		if (rc != 0) {
		    rc = TSS_ObjectPublic_GetSlotForHandle(tssContext, &slotIndex, TPM_RH_NULL);
		    if (rc == 0) {
			tssContext->objectPublic[slotIndex].objectHandle = handle;
		    }
		    else {
			if (tssVerbose)
			    printf("TSS_Public_Store: Error, no slot available for handle %08x\n",
				   handle);
		    }
		}
	    }
	    else {
		if (tssVerbose) printf("TSS_Public_Store: handle and string are both null");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
	else {
	    if (handle == 0) {
		if (tssVerbose) printf("TSS_Public_Store: string not implemented yet");
		rc = TSS_RC_NAME_FILENAME;
	    }
	    else {
		if (tssVerbose) printf("TSS_Public_Store: handle and string are both not null");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
    }
    if (rc == 0) {
	tssContext->objectPublic[slotIndex].objectPublic = *public;
    }
    return rc;
}

#endif

/* TSS_Public_Load() loaded the object public from the TSS context.
   
 */
   
#ifdef TPM_TSS_NOFILE

static TPM_RC TSS_Public_Load(TSS_CONTEXT *tssContext,
			      TPM2B_PUBLIC *public,
			      TPM_HANDLE handle,
			      const char *string)
{
    TPM_RC 	rc = 0;
    size_t	slotIndex;
		
    if (rc == 0) {
	if (string == NULL) {
	    if (handle != 0) {
		rc = TSS_ObjectPublic_GetSlotForHandle(tssContext, &slotIndex, handle);
		if (rc != 0) {
		    if (tssVerbose)
			printf("TSS_Public_Load: Error, no slot found for handle %08x\n",
			       handle);
		}
	    }
	    else {
		if (tssVerbose) printf("TSS_Public_Load: handle and string are both null\n");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
	else {
	    if (handle == 0) {
		if (tssVerbose) printf("TSS_Public_Load: string not implemented yet");
		rc = TSS_RC_NAME_FILENAME;
	    }
	    else {
		if (tssVerbose) printf("TSS_Public_Load: handle and string are both not null\n");
		rc = TSS_RC_NAME_FILENAME;
	    }
	}
    }
    if (rc == 0) {
	*public = tssContext->objectPublic[slotIndex].objectPublic;
    }
    return rc;
}

#endif 	/* TPM_TSS_NOFILE */

#ifdef TPM_TSS_NOFILE

/* TSS_ObjectPublic_GetSlotForHandle() finds the object public slot corresponding to the handle.

   Returns non-zero if no slot is found.
*/

static TPM_RC TSS_ObjectPublic_GetSlotForHandle(TSS_CONTEXT *tssContext,
						size_t *slotIndex,
						TPM_HANDLE handle)
{
    size_t 	i;

    /* search all slots for handle */
    for (i = 0 ; i < (sizeof(tssContext->sessions) / sizeof(TSS_SESSIONS)) ; i++) {
	if (tssContext->objectPublic[i].objectHandle == handle) {
	    *slotIndex = i;
	    return 0;
	}
    }
    return TSS_RC_NO_OBJECTPUBLIC_SLOT;
}	

#endif

#ifdef TPM_TSS_NOFILE

static TPM_RC TSS_ObjectPublic_DeleteData(TSS_CONTEXT *tssContext, TPM_HANDLE handle)
{
    TPM_RC	rc = 0;
    size_t	slotIndex;

    if (rc == 0) {
	rc = TSS_ObjectPublic_GetSlotForHandle(tssContext, &slotIndex, handle);
	if (rc != 0) {
	    if (tssVerbose)
		printf("TSS_ObjectPublic_DeleteData: Error, no slot found for handle %08x\n",
		       handle);
	}
    }    
    if (rc == 0) {
	tssContext->objectPublic[slotIndex].objectHandle = TPM_RH_NULL;
    }
    return rc;
}

#endif


/* TSS_DeleteHandle() removes retained state stored by the TSS for a handle 
 */

static TPM_RC TSS_DeleteHandle(TSS_CONTEXT *tssContext,
			       TPM_HANDLE handle)
{
    TPM_RC		rc = 0;
    TPM_HT 		handleType;
#ifndef TPM_TSS_NOFILE
    char		filename[TPM_DATA_DIR_PATH_LENGTH];
#endif

    handleType = (TPM_HT) ((handle & HR_RANGE_MASK) >> HR_SHIFT);
#ifndef TPM_TSS_NOFILE
    /* delete the Name */
    if (rc == 0) {
	sprintf(filename, "%s/h%08x.bin", tssContext->tssDataDirectory, handle);
	if (tssVverbose) printf("TSS_DeleteHandle: delete Name file %s\n", filename);
	rc = TSS_File_DeleteFile(filename);
    }
    /* delete the public if it exists */
    if (rc == 0) {
	if ((handleType == TPM_HT_TRANSIENT) ||
	    (handleType == TPM_HT_PERSISTENT)) {
	    sprintf(filename, "%s/hp%08x.bin", tssContext->tssDataDirectory, handle);
	    if (tssVverbose) printf("TSS_DeleteHandle: delete public file %s\n", filename);
	    TSS_File_DeleteFile(filename);
	}
    }
#else
    /* sessions persist in the context and can be deleted */
    if (rc == 0) {
	switch (handleType) {
	  case TPM_HT_NV_INDEX:
	    rc = TSS_RC_NOT_IMPLEMENTED;
	    break;
	  case TPM_HT_HMAC_SESSION:
	  case TPM_HT_POLICY_SESSION:
	    if (tssVverbose) printf("TSS_DeleteHandle: delete session state %08x\n", handle);
	    rc = TSS_HmacSession_DeleteData(tssContext, handle);
	    break;
	  case TPM_HT_TRANSIENT:
	  case TPM_HT_PERSISTENT:
	    rc = TSS_ObjectPublic_DeleteData(tssContext, handle);
	    break;
	}
    }
#endif
    return rc;
}

#ifndef TPM_TSS_NOCRYPTO

/* TSS_ObjectPublic_GetName() calculates the Name from the TPMT_PUBLIC.  The Name provides security,
   because the Name returned from the TPM2_ReadPublic cannot be trusted.
*/

static TPM_RC TSS_ObjectPublic_GetName(TPM2B_NAME *name,
				       TPMT_PUBLIC *tpmtPublic)
{
    TPM_RC 	rc = 0;
    
    uint16_t 	written = 0;
    TPMT_HA	digest;
    uint32_t 	sizeInBytes = 0;
    uint8_t 	*buffer = NULL;

    if (rc == 0) {
	rc = TSS_Malloc(&buffer, MAX_RESPONSE_SIZE);	/* freed @1 */
    }
    /* marshal the TPMT_PUBLIC */
    if (rc == 0) {
	uint32_t 	size = MAX_RESPONSE_SIZE;
	uint8_t 	*buffer1 = buffer;
	rc = TSS_TPMT_PUBLIC_Marshalu(tpmtPublic, &written, &buffer1, &size);
    }
    /* hash the public area */
    if (rc == 0) {
	sizeInBytes = TSS_GetDigestSize(tpmtPublic->nameAlg);
	digest.hashAlg = tpmtPublic->nameAlg;	/* Name digest algorithm */
	/* generate the TPMT_HA */
	rc = TSS_Hash_Generate(&digest,	
			       written, buffer,
			       0, NULL);
    }
    if (rc == 0) {
	TPMI_ALG_HASH nameAlgNbo;
	/* copy the digest */
	memcpy(name->t.name + sizeof(TPMI_ALG_HASH), (uint8_t *)&digest.digest, sizeInBytes);
	/* copy the hash algorithm */
	nameAlgNbo = htons(tpmtPublic->nameAlg);
	memcpy(name->t.name, (uint8_t *)&nameAlgNbo, sizeof(TPMI_ALG_HASH));
	/* set the size */
	name->t.size = sizeInBytes + sizeof(TPMI_ALG_HASH);
    }
    free(buffer);	/* @1 */
    return rc;
}

#endif	/* TPM_TSS_NOCRYPTO */


/* TSS_NVPublic_Store() stores the NV public data in a file.

 */

#ifndef TPM_TSS_NOFILE
#ifndef TPM_TSS_NOCRYPTO

static TPM_RC TSS_NVPublic_Store(TSS_CONTEXT *tssContext,
				 TPMS_NV_PUBLIC *nvPublic,
				 TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC 	rc = 0;
    char 	nvpFilename[TPM_DATA_DIR_PATH_LENGTH];

    if (rc == 0) {
	sprintf(nvpFilename, "%s/nvp%08x.bin", tssContext->tssDataDirectory, nvIndex);
	rc = TSS_File_WriteStructure(nvPublic,
				     (MarshalFunction_t)TSS_TPMS_NV_PUBLIC_Marshalu,
				     nvpFilename);
    }
    return rc;
}

#endif
#endif

/* TSS_NVPublic_Load() loads the NV public from a file.

 */

#ifndef TPM_TSS_NOFILE
#ifndef TPM_TSS_NOCRYPTO

static TPM_RC TSS_NVPublic_Load(TSS_CONTEXT *tssContext,
				TPMS_NV_PUBLIC *nvPublic,
				TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC 	rc = 0;
    char 	nvpFilename[TPM_DATA_DIR_PATH_LENGTH];

    if (rc == 0) {
	sprintf(nvpFilename, "%s/nvp%08x.bin", tssContext->tssDataDirectory, nvIndex);
	rc = TSS_File_ReadStructure(nvPublic,
				    (UnmarshalFunction_t)TSS_TPMS_NV_PUBLIC_Unmarshalu,
				    nvpFilename);
    }
    return rc;
}

#endif
#endif

#ifndef TPM_TSS_NOFILE

static TPM_RC TSS_NVPublic_Delete(TSS_CONTEXT *tssContext,
				  TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC 	rc = 0;
    char 	nvpFilename[TPM_DATA_DIR_PATH_LENGTH];
    
    if (rc == 0) {
	sprintf(nvpFilename, "%s/nvp%08x.bin", tssContext->tssDataDirectory, nvIndex);
	rc = TSS_File_DeleteFile(nvpFilename);
    }
    return rc;
}

#endif

#ifdef TPM_TSS_NOFILE
#ifndef TPM_TSS_NOCRYPTO

/* TSS_NVPublic_Store() stores the NV public data in a file.

 */

static TPM_RC TSS_NVPublic_Store(TSS_CONTEXT *tssContext,
				 TPMS_NV_PUBLIC *nvPublic,
				 TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC 	rc = 0;
    size_t	slotIndex;

    if (rc == 0) {
	rc = TSS_NvPublic_GetSlotForHandle(tssContext, &slotIndex, nvIndex);
	if (rc != 0) {
	    rc = TSS_NvPublic_GetSlotForHandle(tssContext, &slotIndex, TPM_RH_NULL);
	    if (rc == 0) {
		tssContext->nvPublic[slotIndex].nvIndex = nvIndex;
	    }
	    else {
		if (tssVerbose)
		    printf("TSS_NVPublic_Store: Error, no slot available for handle %08x\n",
			   nvIndex);
	    }
	}
    }
    if (rc == 0) {
	tssContext->nvPublic[slotIndex].nvPublic = *nvPublic;
    }
    return rc;
}

#endif
#endif

#ifdef TPM_TSS_NOFILE
#ifndef TPM_TSS_NOCRYPTO

/* TSS_NVPublic_Load() loads the NV public from a file.

 */

static TPM_RC TSS_NVPublic_Load(TSS_CONTEXT *tssContext,
				TPMS_NV_PUBLIC *nvPublic,
				TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC 	rc = 0;
    size_t	slotIndex;

    if (rc == 0) {
	rc = TSS_NvPublic_GetSlotForHandle(tssContext, &slotIndex, nvIndex);
	if (rc != 0) {
	    if (tssVerbose)
		printf("TSS_NVPublic_Load: Error, no slot found for handle %08x\n",
		       nvIndex);
	}
    }
    if (rc == 0) {
	*nvPublic = tssContext->nvPublic[slotIndex].nvPublic;
    }
    return rc;
}

#endif
#endif

#ifdef TPM_TSS_NOFILE

static TPM_RC TSS_NVPublic_Delete(TSS_CONTEXT *tssContext,
				  TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC 	rc = 0;
    size_t	slotIndex;
    
    if (rc == 0) {
	rc = TSS_NvPublic_GetSlotForHandle(tssContext, &slotIndex, nvIndex);
	if (rc != 0) {
	    if (tssVerbose)
		printf("TSS_NVPublic_Delete: Error, no slot found for handle %08x\n",
		       nvIndex);
	}
    }
    if (rc == 0) {
	tssContext->nvPublic[slotIndex].nvIndex = TPM_RH_NULL;
    }
    return rc;
}

#endif

#ifdef TPM_TSS_NOFILE

/* TSS_NvPublic_GetSlotForHandle() finds the object public slot corresponding to the handle.

   Returns non-zero if no slot is found.
*/

static TPM_RC TSS_NvPublic_GetSlotForHandle(TSS_CONTEXT *tssContext,
					    size_t *slotIndex,
					    TPMI_RH_NV_INDEX nvIndex)
{
    size_t 	i;

    /* search all slots for handle */
    for (i = 0 ; i < (sizeof(tssContext->nvPublic) / sizeof(TSS_NVPUBLIC)) ; i++) {
	if (tssContext->nvPublic[i].nvIndex == nvIndex) {
	    *slotIndex = i;
	    return 0;
	}
    }
    return TSS_RC_NO_NVPUBLIC_SLOT;
}	

#endif

/* TSS_NVPublic_GetName() calculates the Name from the TPMS_NV_PUBLIC.  The Name provides security,
   because the Name returned from the TPM2_NV_ReadPublic cannot be trusted.
*/

#ifndef TPM_TSS_NOCRYPTO

static TPM_RC TSS_NVPublic_GetName(TPM2B_NAME *name,
				   TPMS_NV_PUBLIC *nvPublic)
{
    TPM_RC 	rc = 0;
    
    uint16_t 	written = 0;
    TPMT_HA	digest;
    uint32_t 	sizeInBytes = 0;
    uint8_t 	*buffer = NULL;

    if (rc == 0) {
	rc = TSS_Malloc(&buffer, MAX_RESPONSE_SIZE);	/* freed @1 */
    }
    /* marshal the TPMS_NV_PUBLIC */
    if (rc == 0) {
	uint32_t 	size = MAX_RESPONSE_SIZE;
	uint8_t 	*buffer1 = buffer;
	rc = TSS_TPMS_NV_PUBLIC_Marshalu(nvPublic, &written, &buffer1, &size);
    }
    /* hash the public area */
    if (rc == 0) {
	sizeInBytes = TSS_GetDigestSize(nvPublic->nameAlg);
	digest.hashAlg = nvPublic->nameAlg;	/* Name digest algorithm */
	/* generate the TPMT_HA */
	rc = TSS_Hash_Generate(&digest,	
			       written, buffer,
			       0, NULL);
    }
    if (rc == 0) {
	TPMI_ALG_HASH nameAlgNbo;
	/* copy the digest */
	memcpy(name->t.name + sizeof(TPMI_ALG_HASH), (uint8_t *)&digest.digest, sizeInBytes);
	/* copy the hash algorithm */
	nameAlgNbo = htons(nvPublic->nameAlg);
	memcpy(name->t.name, (uint8_t *)&nameAlgNbo, sizeof(TPMI_ALG_HASH));
	/* set the size */
	name->t.size = sizeInBytes + sizeof(TPMI_ALG_HASH);
    }
    free(buffer);	/* @1 */
    return rc;
}

#endif

#ifndef TPM_TSS_NOCRYPTO

static TPM_RC TSS_HmacSession_SetNonceCaller(struct TSS_HMAC_CONTEXT *session,
					     TPMS_AUTH_COMMAND 	*authC)
{
    TPM_RC		rc = 0;

    /* generate a new nonceCaller */
    if (rc == 0) {
	session->nonceCaller.b.size = session->sizeInBytes;
	rc = TSS_RandBytes(session->nonceCaller.t.buffer, session->sizeInBytes);
    }
    /* nonceCaller for the command */
    if (rc == 0) {
	rc = TSS_TPM2B_Copy(&authC->nonce.b, &session->nonceCaller.b, sizeof(TPMU_HA));
    }
    return rc;
}

#endif	/* TPM_TSS_NOCRYPTO */

#ifndef TPM_TSS_NOCRYPTO

/* TSS_HmacSession_SetHmacKey() calculates the session HMAC key.

   handleNumber is index into the session area.  The first sessions, the authorization sessions,
   have a corresponding handle in the command handle.
*/

static TPM_RC TSS_HmacSession_SetHmacKey(TSS_CONTEXT *tssContext,
					 struct TSS_HMAC_CONTEXT *session,
					 size_t handleNumber,	/* index into the handle area */
					 const char *password)
{
    TPM_RC		rc = 0;
    TPM_HANDLE 		commandHandle;		/* from handle area, for bound session */
    TPM2B_NAME		name;
    TPM2B_AUTH 		authValue;
    int 		bindMatch = FALSE;
    int 		done = FALSE;		/* done with authorization sessions */

    /*
      authHMAC = HMAC sessionAlg ((sessionKey || authValue), 
      (pHash || nonceNewer || nonceOlder 
      { || nonceTPMdecrypt } { || nonceTPMencrypt }
      || sessionAttributes))
    */
    /* HMAC key is sessionKey || authValue */
    /* copy the session key to HMAC key */
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_HmacSession_SetHmacKey: sessionKey",
				      session->sessionKey.b.buffer, session->sessionKey.b.size);
	rc = TSS_TPM2B_Copy(&session->hmacKey.b,
			    &session->sessionKey.b, sizeof(TPMU_HA) + sizeof(TPMT_HA));
    }
    /* copy the session key to sessionValue */
    if (rc == 0) {
	rc = TSS_TPM2B_Copy(&session->sessionValue.b,
			    &session->sessionKey.b, sizeof(TPMU_HA) + sizeof(TPMT_HA));
    }
    if (rc == 0) {
	if (tssVverbose)
	    TSS_PrintAll("TSS_HmacSession_SetHmacKey: preliminary sessionValue",
			 session->sessionValue.b.buffer, session->sessionValue.b.size);
    }
    /* This value is an EmptyAuth if the HMAC is being computed to authorize an action on the
       object to which the session is bound.
    */
    /* The first sessions are authorization sessions.  They can have a bind entity.  All others can
       be encrypt or decrypt sessions, but the authValue is not included in the session key.
    */
    if (rc == 0) {
	AUTH_ROLE authRole = TSS_GetAuthRole(tssContext->tssAuthContext, handleNumber);
	if (authRole == AUTH_NONE) {
	    if (tssVverbose) printf("TSS_HmacSession_SetHmacKey: Done, not auth session\n");
	    done = TRUE;	/* not an authorization session, could be audit or
				   encrypt/decrypt */
	}
    }
    /* If not an authorization session, there is no authValue to append to the HMAC key or encrypt
       sessionValue, regardless of the binding.  Below is for auth sessions. */
    if (!done) {
	/* First, if there was a bind handle, check if the name matches.  Else bindMatch remains
	   FALSE. */
	if (session->bind != TPM_RH_NULL) {
	    /* get the handle for this session */
	    if (tssVverbose)
		printf("TSS_HmacSession_SetHmacKey: Processing bind handle %08x\n", session->bind);
	    if (rc == 0) {
		rc = TSS_GetCommandHandle(tssContext->tssAuthContext,
					  &commandHandle,
					  handleNumber);
	    }
	    /* get the Name corresponding to the handle */
	    if (rc == 0) {
		if (tssVverbose)
		    printf("TSS_HmacSession_SetHmacKey: commandHandle %08x bindHandle %08x\n",
			   commandHandle, session->bind);
		rc = TSS_Name_GetName(tssContext, &name, commandHandle);
	    }
	    /* compare the authorized object name to the bind object name */
	    if (rc == 0) {
		bindMatch = TSS_TPM2B_Compare(&name.b, &session->bindName.b);
		if (tssVverbose) printf("TSS_HmacSession_SetHmacKey: bind match %u\n", bindMatch);
	    }
	}
	/* Second, append password to session key for HMAC key if required */

	/* When performing an HMAC for authorization, the HMAC key is normally the concatenation of
	   the entity's authValue to the sessions sessionKey (created at
	   TPM2_StartAuthSession(). However, if the authorization is for the entity to
	   which the session is bound, the authValue is not included in the HMAC key. When
	   a policy requires that an HMAC be computed, it is always concatenated.
	*/
	if ((rc == 0) &&
	    /* append if HMAC session and not bind match */
	    (((session->sessionType == TPM_SE_HMAC) && !bindMatch) ||
	     /* append if policy and policy authvalue */
	     ((session->sessionType == TPM_SE_POLICY) && session->isAuthValueNeeded)) &&
	    (password != NULL)	/* if password is NULL, nothing to append. */

	    ) {
	    
	    if (tssVverbose)
		printf("TSS_HmacSession_SetHmacKey: Appending authValue to HMAC key\n");
	    /* convert the password to an authvalue */
	    if (rc == 0) {
		rc = TSS_TPM2B_StringCopy(&authValue.b, password, sizeof(authValue.t.buffer));
	    }
	    /* append the authvalue to the session key to create the hmac key */
	    if (rc == 0) {
		rc = TSS_TPM2B_Append(&session->hmacKey.b, &authValue.b,
				      sizeof(TPMU_HA) + sizeof(TPMT_HA));
	    }
	}
	/* Third, append password to session key for sessionValue

	   If a session is also being used for authorization, sessionValue (see 21.2 and 21.3) is
	   sessionKey || authValue. The binding of the session is ignored. If the session is not
	   being used for authorization, sessionValue is sessionKey.
	 */
	/* NOTE This step occurs even if there is a bind match. That is, the password is effectively
	   appended twice. */
	if (rc == 0) {
	    /* if not bind, sessionValue is sessionKey || authValue (same as HMAC key) */
	    if (!bindMatch) {
		if (tssVverbose)
		    printf("TSS_HmacSession_SetHmacKey: "
			   "No bind, appending authValue to sessionValue\n");
		/* convert the password to an authvalue */
		if (rc == 0) {
		    rc = TSS_TPM2B_StringCopy(&authValue.b, password, sizeof(authValue.t.buffer));
		}
		if (rc == 0) {
		    rc = TSS_TPM2B_Append(&session->sessionValue.b, &authValue.b,
					  sizeof(TPMU_HA) + sizeof(TPMT_HA));
		}
	    }
	    /* if bind, sessionValue is sessionKey || bindAuthValue */
	    else {
		if (tssVverbose)
		    printf("TSS_HmacSession_SetHmacKey: "
			   "Bind, appending bind authValue to sessionValue\n");
		if (rc == 0) {
		    rc = TSS_TPM2B_Append(&session->sessionValue.b, &session->bindAuthValue.b,
					  sizeof(TPMU_HA) + sizeof(TPMT_HA));
		}
	    }
	    if (rc == 0) {
		if (tssVverbose)
		    TSS_PrintAll("TSS_HmacSession_SetHmacKey: bindAuthValue",
				 session->bindAuthValue.b.buffer, session->bindAuthValue.b.size);
	    }
	}
    }
    if (rc == 0) {
	if (tssVverbose)
	    TSS_PrintAll("TSS_HmacSession_SetHmacKey: hmacKey",
			 session->hmacKey.b.buffer, session->hmacKey.b.size);
	if (tssVverbose)
	    TSS_PrintAll("TSS_HmacSession_SetHmacKey: sessionValue",
			 session->sessionValue.b.buffer, session->sessionValue.b.size);
    }
    return rc;
}
    
#endif	/* TPM_TSS_NOCRYPTO */

/* TSS_HmacSession_SetHMAC() is used for a command.  It sets all the values in one
   TPMS_AUTH_COMMAND, ready for marshaling into the command packet.

   - gets cpBuffer
   - generates cpHash
   - generates the HMAC
   - copies the result into authCommand

   Unused names must have size 0.

   The HMAC key is already in the session structure.
*/

static TPM_RC TSS_HmacSession_SetHMAC(TSS_AUTH_CONTEXT *tssAuthContext,	/* authorization context */
				      struct TSS_HMAC_CONTEXT *session[],
				      TPMS_AUTH_COMMAND *authCommand[],	/* output: command
									   authorization */
				      TPMI_SH_AUTH_SESSION sessionHandle[], /* session handles in
									       command */
				      unsigned int sessionAttributes[],	/* attributes for this
									   command */
				      const char *password[],
				      TPM2B_NAME *name0,		/* up to 3 names */
				      TPM2B_NAME *name1,	/* unused names have length 0 */
				      TPM2B_NAME *name2)
{
    TPM_RC		rc = 0;
    unsigned int	i = 0;
#ifndef TPM_TSS_NOCRYPTO
    TPMT_HA 		cpHash;
    TPMT_HA 		hmac;
    TPM2B_NONCE	nonceTPMDecrypt;
    TPM2B_NONCE	nonceTPMEncrypt;
    cpHash.hashAlg = TPM_ALG_NULL;	/* for cpHash calculation optimization */
#endif	/* TPM_TSS_NOCRYPTO */


    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) && (sessionHandle[i] != TPM_RH_NULL) ; i++) {
	uint8_t sessionAttr8;
	if (tssVverbose) printf("TSS_HmacSession_SetHMAC: Step 6 session %08x\n", sessionHandle[i]);
	/* password sessions were serviced in step 2. */
	if (sessionHandle[i] == TPM_RS_PW) {
	    continue;
	}
	if (tssVverbose) printf("TSS_HmacSession_SetHMAC: sessionType %02x\n",
				session[i]->sessionType);
	if (tssVverbose) printf("TSS_HmacSession_SetHMAC: isPasswordNeeded %02x\n",
				session[i]->isPasswordNeeded);
	if (tssVverbose) printf("TSS_HmacSession_SetHMAC: isAuthValueNeeded %02x\n",
				session[i]->isAuthValueNeeded);
	/* sessionHandle */
	authCommand[i]->sessionHandle = session[i]->sessionHandle;
	/* attributes come from command */
	sessionAttr8 = (uint8_t)sessionAttributes[i];
	authCommand[i]->sessionAttributes.val = sessionAttr8;

	/* policy session with policy password handled below, no hmac.  isPasswordNeeded is never
	   true for an HMAC session, so don't need to test session type here. */
	if (!(session[i]->isPasswordNeeded)) {
	    /* HMAC session */ 
	    if ((session[i]->sessionType == TPM_SE_HMAC) ||
		/* policy session with TPM2_PolicyAuthValue */
		((session[i]->sessionType == TPM_SE_POLICY) && (session[i]->isAuthValueNeeded)) ||
		/* salted session */
		(session[i]->hmacKey.t.size != 0)
		) {
		/* needs HMAC */
#ifndef TPM_TSS_NOCRYPTO
		if (tssVverbose) printf("TSS_HmacSession_SetHMAC: calculate HMAC\n");
		/* calculate cpHash.  Performance optimization: If there is more than one session,
		   and the hash algorithm is the same, use the previously calculated version. */
		if ((rc == 0) && (cpHash.hashAlg != session[i]->authHashAlg)) {
		    uint32_t cpBufferSize;
		    uint8_t *cpBuffer;
		    TPM_CC commandCode;
		    TPM_CC commandCodeNbo;
	
		    rc = TSS_GetCpBuffer(tssAuthContext,
					 &cpBufferSize,
					 &cpBuffer);
		    if (tssVverbose) TSS_PrintAll("TSS_HmacSession_SetHMAC: cpBuffer",
						  cpBuffer, cpBufferSize);
		    cpHash.hashAlg = session[i]->authHashAlg;
    
		    /* cpHash = hash(commandCode [ || authName1		*/
		    /*                           [ || authName2		*/
		    /*                           [ || authName3 ]]]	*/
		    /*                           [ || parameters])	*/
		    /* A cpHash can contain just a commandCode only if the lone session is */
		    /* an audit session. */

		    commandCode = TSS_GetCommandCode(tssAuthContext);
		    commandCodeNbo = htonl(commandCode);
		    rc = TSS_Hash_Generate(&cpHash,		/* largest size of a digest */
					   sizeof(TPM_CC), &commandCodeNbo,
					   name0->b.size, &name0->b.buffer,
					   name1->b.size, &name1->b.buffer,
					   name2->b.size, &name2->b.buffer,
					   cpBufferSize, cpBuffer,
					   0, NULL);
		}
		if (i == 0) {
		    unsigned int 	isDecrypt = 0;	/* count number of sessions with decrypt
							   set */
		    unsigned int	decryptSession = 0;	/* which one is decrypt */
		    unsigned int 	isEncrypt = 0;	/* count number of sessions with decrypt
							   set */
		    unsigned int	encryptSession = 0;	/* which one is decrypt */
		    nonceTPMDecrypt.t.size = 0;
		    nonceTPMEncrypt.t.size = 0;
		    /* if a different session is being used for parameter decryption, then the
		       nonceTPM for that session is included in the HMAC of the first authorization
		       session */
		    if (rc == 0) {
			rc = TSS_Sessions_GetDecryptSession(&isDecrypt,
							    &decryptSession,
							    sessionHandle,
							    sessionAttributes);
		    }
		    if ((rc == 0) && isDecrypt && (decryptSession != 0)) {
			rc = TSS_TPM2B_Copy(&nonceTPMDecrypt.b,
					    &session[decryptSession]->nonceTPM.b, sizeof(TPMU_HA));
		    }
		    /* if a different session is being used for parameter encryption, then the
		       nonceTPM for that session is included in the HMAC of the first authorization
		       session */
		    if (rc == 0) {
			rc = TSS_Sessions_GetEncryptSession(&isEncrypt,
							    &encryptSession,
							    sessionHandle,
							    sessionAttributes);
		    }
		    /* Don't include the same nonce twice */
		    if ((rc == 0) && isEncrypt && (encryptSession != 0)) {
			if (!isDecrypt || (encryptSession != decryptSession)) {
			    rc = TSS_TPM2B_Copy(&nonceTPMEncrypt.b, 
						&session[encryptSession]->nonceTPM.b,
						sizeof(TPMU_HA));
			}
		    }
		}
		/* for other than the first session, those nonces are not used */
		else {
		    nonceTPMDecrypt.t.size = 0;
		    nonceTPMEncrypt.t.size = 0;
		}
		/* */
		if (rc == 0) {
		    hmac.hashAlg = session[i]->authHashAlg;
		    rc = TSS_HMAC_Generate(&hmac,				/* output hmac */
					   &session[i]->hmacKey,		/* input key */
					   session[i]->sizeInBytes, (uint8_t *)&cpHash.digest,
					   /* new is nonceCaller */
					   session[i]->nonceCaller.b.size,
					   &session[i]->nonceCaller.b.buffer,
					   /* old is previous nonceTPM */
					   session[i]->nonceTPM.b.size,
					   &session[i]->nonceTPM.b.buffer,
					   /* nonceTPMDecrypt */
					   nonceTPMDecrypt.b.size, nonceTPMDecrypt.b.buffer,
					   /* nonceTPMEncrypt */
					   nonceTPMEncrypt.b.size, nonceTPMEncrypt.b.buffer,
					   /* 1 byte, no endian conversion */
					   sizeof(uint8_t), &sessionAttr8,
					   0, NULL);
		    if (tssVverbose) {
			TSS_PrintAll("TSS_HmacSession_SetHMAC: HMAC key",
				     session[i]->hmacKey.t.buffer, session[i]->hmacKey.t.size);
			TSS_PrintAll("TSS_HmacSession_SetHMAC: cpHash",
				     (uint8_t *)&cpHash.digest, session[i]->sizeInBytes);
			TSS_PrintAll("TSS_HmacSession_Set: nonceCaller",
				     session[i]->nonceCaller.b.buffer,
				     session[i]->nonceCaller.b.size);
			TSS_PrintAll("TSS_HmacSession_SetHMAC: nonceTPM",
				     session[i]->nonceTPM.b.buffer, session[i]->nonceTPM.b.size);
			TSS_PrintAll("TSS_HmacSession_SetHMAC: nonceTPMDecrypt",
				     nonceTPMDecrypt.b.buffer, nonceTPMDecrypt.b.size);
			TSS_PrintAll("TSS_HmacSession_SetHMAC: nonceTPMEncrypt",
				     nonceTPMEncrypt.b.buffer, nonceTPMEncrypt.b.size);
			TSS_PrintAll("TSS_HmacSession_SetHMAC: sessionAttributes",
				     &sessionAttr8, sizeof(uint8_t));
			TSS_PrintAll("TSS_HmacSession_SetHMAC: HMAC",
				     (uint8_t *)&hmac.digest, session[i]->sizeInBytes);
		    }
		}
		/* copy HMAC into authCommand TPM2B_AUTH hmac */
		if (rc == 0) {
		    rc = TSS_TPM2B_Create(&authCommand[i]->hmac.b,
					  (uint8_t *)&hmac.digest,
					  session[i]->sizeInBytes,
					  sizeof(authCommand[i]->hmac.t.buffer));
		}
#else
		tssAuthContext = tssAuthContext;
		name0 = name0;
		name1 = name1;
		name2 = name2;
		if (tssVerbose)
		    printf("TSS_HmacSession_SetHMAC: Error, with no crypto not implemented\n");
		rc = TSS_RC_NOT_IMPLEMENTED;
#endif	/* TPM_TSS_NOCRYPTO */
	    }
	    /* not HMAC, not policy requiring password or hmac */
	    else {
		authCommand[i]->hmac.b.size = 0;
	    }
	}
	/* For a policy session that contains TPM2_PolicyPassword(), the password takes precedence
	   and must be present in hmac. */
	else {		/* isPasswordNeeded true */
	    if (tssVverbose) printf("TSS_HmacSession_SetHMAC: use password\n");
	    /* nonce has already been set */
	    rc = TSS_TPM2B_StringCopy(&authCommand[i]->hmac.b,
				      password[i], sizeof(authCommand[i]->hmac.t.buffer));
	}
    }
    return rc;
}


#ifndef TPM_TSS_NOCRYPTO

/* TSS_HmacSession_Verify() is used for a response.  It uses the values in TPMS_AUTH_RESPONSE to
   validate the response HMAC
*/

static TPM_RC TSS_HmacSession_Verify(TSS_AUTH_CONTEXT *tssAuthContext,	/* authorization context */
				     struct TSS_HMAC_CONTEXT *session,	/* TSS session context */
				     TPMS_AUTH_RESPONSE *authResponse)	/* input: response authorization */
{
    TPM_RC		rc = 0;
    uint32_t		rpBufferSize;
    uint8_t 		*rpBuffer;
    TPMT_HA 		rpHash;
    TPMT_HA 		actualHmac;

    /* get the rpBuffer */
    if (rc == 0) {
	rc = TSS_GetRpBuffer(tssAuthContext, &rpBufferSize, &rpBuffer);
	if (tssVverbose) TSS_PrintAll("TSS_HmacSession_Verify: rpBuffer",
				      rpBuffer, rpBufferSize);
    }
    /* calculate rpHash */
    if (rc == 0) {
	TPM_CC commandCode;
	TPM_CC commandCodeNbo;
	rpHash.hashAlg = session->authHashAlg;
	
	commandCode = TSS_GetCommandCode(tssAuthContext);
	commandCodeNbo = htonl(commandCode);
	
	/* rpHash = HsessionAlg (responseCode || commandCode {|| parameters })	 */
	rc = TSS_Hash_Generate(&rpHash,			/* largest size of a digest */
			       sizeof(TPM_RC), &rc,	/* RC is always 0, no need to endian
							   convert */
			       sizeof(TPM_CC), &commandCodeNbo,
			       rpBufferSize, rpBuffer,
			       0, NULL);
    }
    /* construct the actual HMAC as TPMT_HA */
    if (rc == 0) {
	actualHmac.hashAlg = session->authHashAlg;
	if (authResponse->hmac.t.size != session->sizeInBytes) {
	    if (tssVerbose)
		printf("TSS_HmacSession_Verify: HMAC size %u inconsistent with algorithm %u\n",
		       authResponse->hmac.t.size, session->sizeInBytes);
	    rc = TSS_RC_HMAC_SIZE;
	}
    }
    if (rc == 0) {
	memcpy((uint8_t *)&actualHmac.digest, &authResponse->hmac.t.buffer,
	       authResponse->hmac.t.size);
    }
    /* verify the HMAC */
    if (rc == 0) {
	if (tssVverbose) {
	    TSS_PrintAll("TSS_HmacSession_Verify: HMAC key",
			 session->hmacKey.t.buffer, session->hmacKey.t.size);
	    TSS_PrintAll("TSS_HmacSession_Verify: rpHash",
			 (uint8_t *)&rpHash.digest, session->sizeInBytes);
	    TSS_PrintAll("TSS_HmacSession_Verify: nonceTPM",
			 session->nonceTPM.b.buffer, session->nonceTPM.b.size);
	    TSS_PrintAll("TSS_HmacSession_Verify: nonceCaller",
			 session->nonceCaller.b.buffer, session->nonceCaller.b.size);
	    TSS_PrintAll("TSS_HmacSession_Verify: sessionAttributes",
			 &authResponse->sessionAttributes.val, sizeof(uint8_t));
	    TSS_PrintAll("TSS_HmacSession_Verify: response HMAC",
			 (uint8_t *)&authResponse->hmac.t.buffer, session->sizeInBytes);
	}
	rc = TSS_HMAC_Verify(&actualHmac,		/* input response hmac */
			     &session->hmacKey,		/* input HMAC key */
			     session->sizeInBytes,
			     /* rpHash */
			     session->sizeInBytes, (uint8_t *)&rpHash.digest,
			     /* new is nonceTPM */
			     session->nonceTPM.b.size, &session->nonceTPM.b.buffer,
			     /* old is nonceCaller */
			     session->nonceCaller.b.size, &session->nonceCaller.b.buffer,
			     /* 1 byte, no endian conversion */
			     sizeof(uint8_t), &authResponse->sessionAttributes.val,
			     0, NULL);
    }
    return rc;
}

#endif 	/* TPM_TSS_NOCRYPTO */

/* TSS_HmacSession_Continue() handles the response continueSession flag.  It either saves the
   updated session or deletes the session state. */

static TPM_RC TSS_HmacSession_Continue(TSS_CONTEXT *tssContext,
				       struct TSS_HMAC_CONTEXT *session,
				       TPMS_AUTH_RESPONSE *authR)
{
    TPM_RC		rc = 0;

    if (rc == 0) {
	/* if continue set */
	if (authR->sessionAttributes.val & TPMA_SESSION_CONTINUESESSION) {
	    /* clear the policy flags in preparation for the next use */
	    session->isPasswordNeeded = FALSE;
	    session->isAuthValueNeeded = FALSE;
	    /* save the session */
	    rc = TSS_HmacSession_SaveSession(tssContext, session);
	}
	else {		/* continue clear */
	    /* delete the session state */
	    rc = TSS_DeleteHandle(tssContext, session->sessionHandle);
	}
    }
    return rc;
}

/* TSS_Sessions_GetDecryptSession() searches for a command decrypt session.  If found, returns
   isDecrypt TRUE, and the session number in decryptSession.

*/

static TPM_RC TSS_Sessions_GetDecryptSession(unsigned int *isDecrypt,
					     unsigned int *decryptSession,
					     TPMI_SH_AUTH_SESSION sessionHandle[],
					     unsigned int sessionAttributes[])
{
    TPM_RC		rc = 0;
    unsigned int 	i = 0;

    /* count the number of command decrypt sessions */
    *isDecrypt = 0;		/* number of sessions with decrypt set */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) &&
	     (sessionHandle[i] != TPM_RH_NULL) &&
	     (sessionHandle[i] != TPM_RS_PW) ;
	     i++) {
	if (sessionAttributes[i] & TPMA_SESSION_DECRYPT) {
	    (*isDecrypt)++;		/* count number of decrypt sessions */
	    *decryptSession = i;	/* record which one it was */
	}
    }
    /* how many decrypt sessions were found */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Sessions_GetDecryptSession: Found %u decrypt sessions at %u\n",
				*isDecrypt, *decryptSession);
	if (*isDecrypt > 1) {
	    if (tssVerbose)
		printf("TSS_Sessions_GetDecryptSession: Error, found %u decrypt sessions\n",
		       *isDecrypt);
	    rc = TSS_RC_DECRYPT_SESSIONS;
	}
    }
    return rc;
}

/* TSS_Sessions_GetEncryptSession() searches for a response encrypt session.  If found, returns
   isEncrypt TRUE, and the session number in encryptSession.

*/

static TPM_RC TSS_Sessions_GetEncryptSession(unsigned int *isEncrypt,
					     unsigned int *encryptSession,
					     TPMI_SH_AUTH_SESSION sessionHandle[],
					     unsigned int sessionAttributes[])
{
    TPM_RC		rc = 0;
    unsigned int 	i = 0;

    /* count the number of command encrypt sessions */
    *isEncrypt = 0;		/* number of sessions with encrypt set */
    for (i = 0 ; (rc == 0) && (i < MAX_SESSION_NUM) &&
	     (sessionHandle[i] != TPM_RH_NULL) &&
	     (sessionHandle[i] != TPM_RS_PW) ;
	 i++) {
	if (sessionAttributes[i] & TPMA_SESSION_ENCRYPT) {
	    (*isEncrypt)++;		/* count number of encrypt sessions */
	    *encryptSession = i;	/* record which one it was */
	}
    }
    /* how many encrypt sessions were found */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Sessions_GetEncryptSession: Found %u encrypt sessions at %u\n",
				*isEncrypt, *encryptSession);
	if (*isEncrypt > 1) {
	    if (tssVerbose)
		printf("TSS_Sessions_GetEncryptSession: Error, found %u encrypt sessions\n",
		       *isEncrypt);
	    rc = TSS_RC_ENCRYPT_SESSIONS;
	}
    }
    return rc;
}

/* TSS_Command_Decrypt() determines whether any sessions are command decrypt sessions.  If so, it
   encrypts the first command parameter.

   It does common error checking, then calls algorithm specific functions.

*/

static TPM_RC TSS_Command_Decrypt(TSS_AUTH_CONTEXT *tssAuthContext,
				  struct TSS_HMAC_CONTEXT *session[],
				  TPMI_SH_AUTH_SESSION sessionHandle[],
				  unsigned int	sessionAttributes[])
{
    TPM_RC		rc = 0;
    unsigned int 	isDecrypt = 0;		/* count number of sessions with decrypt set */
    unsigned int	decryptSession = 0;	/* which session is decrypt */

    /* determine if there is a decrypt session */
    if (rc == 0) {
	rc = TSS_Sessions_GetDecryptSession(&isDecrypt,
					    &decryptSession,
					    sessionHandle,
					    sessionAttributes);
    }
#ifndef TPM_TSS_NOCRYPTO
    {
	COMMAND_INDEX   tpmCommandIndex;	/* index into TPM table */
	TPM_CC 		commandCode;
	int		decryptSize;		/* size of TPM2B size, 2 if there is a TPM2B, 0 if
						   not */
	uint32_t 	paramSize;		/* size of the parameter to encrypt */	
	uint8_t 	*decryptParamBuffer;
	/* can the command parameter be encrypted */
	if ((rc == 0) && isDecrypt) {
	    /* get the commandCode, stored in TSS during marshal */
	    commandCode  = TSS_GetCommandCode(tssAuthContext);
	    /* get the index into the TPM command attributes table */
	    tpmCommandIndex = CommandCodeToCommandIndex(commandCode);
	    /* can this be a decrypt command (this is size of TPM2B size, not size of parameter) */
	    decryptSize = getDecryptSize(tpmCommandIndex);
	    if (decryptSize != 2) {		/* only handle TPM2B */
		printf("TSS_Command_Decrypt: Error, command cannot be encrypted\n");
		rc = TSS_RC_NO_DECRYPT_PARAMETER;
	    }
	}
	/* get the TPM2B parameter to encrypt */
	if ((rc == 0) && isDecrypt) {
	    rc = TSS_GetCommandDecryptParam(tssAuthContext, &paramSize, &decryptParamBuffer);
	}
	/* if the size of the parameter to encrypt is zero, nothing to encrypt */
	if ((rc == 0) && isDecrypt) {
	    if (paramSize == 0) {
		isDecrypt = FALSE;	/* none, done with this function */
	    }
	}
	/* error checking complete, do the encryption */
	if ((rc == 0) && isDecrypt) {
	    switch (session[decryptSession]->symmetric.algorithm) {
	      case TPM_ALG_XOR:
		rc = TSS_Command_DecryptXor(tssAuthContext, session[decryptSession]);
		break;
	      case TPM_ALG_AES:
		rc = TSS_Command_DecryptAes(tssAuthContext, session[decryptSession]);
		break;
	      default:
		if (tssVerbose) printf("TSS_Command_Decrypt: Error, algorithm %04x not implemented\n",
				       session[decryptSession]->symmetric.algorithm);
		rc = TSS_RC_BAD_DECRYPT_ALGORITHM;
		break;
	    }
	}
    }
#else
    tssAuthContext = tssAuthContext;
    session = session;
    if ((rc == 0) && isDecrypt) {
	if (tssVerbose)
	    printf("TSS_Command_Decrypt: Error, with no crypto not implemented\n");
	rc = TSS_RC_NOT_IMPLEMENTED;
    }
#endif
    return rc;
}

#ifndef TPM_TSS_NOCRYPTO

/* NOTE: if AES also works, do in place encryption */

static TPM_RC TSS_Command_DecryptXor(TSS_AUTH_CONTEXT *tssAuthContext,
				     struct TSS_HMAC_CONTEXT *session)
{
    TPM_RC		rc = 0;
    unsigned int	i;
    uint32_t 		paramSize;
    uint8_t 		*decryptParamBuffer;
    uint8_t 		*mask = NULL;
    uint8_t 		*encryptParamBuffer = NULL;

    /* get the TPM2B parameter to encrypt */
    if (rc == 0) {
	rc = TSS_GetCommandDecryptParam(tssAuthContext, &paramSize, &decryptParamBuffer);
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptXor: decrypt in",
				      decryptParamBuffer, paramSize);
    }    
    if (rc == 0) {
	rc = TSS_Malloc(&mask, paramSize);
    }
    if (rc == 0) {
	rc = TSS_Malloc(&encryptParamBuffer, paramSize);
    }
    /* generate the XOR pad */
    /* 21.2	XOR Parameter Obfuscation

       XOR(parameter, hashAlg, sessionValue, nonceNewer, nonceOlder)

       parameter	a variable sized buffer containing the parameter to be obfuscated
       hashAlg		the hash algorithm associated with the session
       sessionValue	the session-specific HMAC key
       nonceNewer	for commands, this will be nonceCaller and for responses it will be nonceTPM
       nonceOlder	for commands, this will be nonceTPM and for responses it will be nonceCaller

       11.4.6.3	XOR Obfuscation

       XOR(data, hashAlg, key, contextU, contextV)
       
       mask = KDFa (hashAlg, key, "XOR", contextU, contextV, data.size * 8)
    */
    /* KDFa for the XOR mask */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Command_DecryptXor: hashAlg %04x\n", session->authHashAlg);
	if (tssVverbose) printf("TSS_Command_DecryptXor: sizeInBits %04x\n", paramSize * 8);
	if (tssVverbose)
	    TSS_PrintAll("TSS_Command_DecryptXor: sessionKey",
			 session->sessionKey.b.buffer, session->sessionKey.b.size);
	if (tssVverbose)
	    TSS_PrintAll("TSS_Command_DecryptXor: sessionValue",
			 session->sessionValue.b.buffer, session->sessionValue.b.size);
	rc = TSS_KDFA(mask,
		      session->authHashAlg,
		      &session->sessionValue.b,
		      "XOR",
		      &session->nonceCaller.b,
		      &session->nonceTPM.b,
		      paramSize * 8);
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptXor: mask",
				      mask, paramSize);
    }
    /* XOR */
    for (i = 0 ; (rc == 0) && (i < paramSize ) ; i++)  {
	encryptParamBuffer[i] = decryptParamBuffer[i] ^ mask[i];
    }
    if (rc == 0) {
	rc = TSS_SetCommandDecryptParam(tssAuthContext, paramSize, encryptParamBuffer);
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptXor: encrypt out",
				      encryptParamBuffer, paramSize);
    }
    free(mask);
    free(encryptParamBuffer);
    return rc;
}

#endif	/* TPM_TSS_NOCRYPTO */

#ifndef TPM_TSS_NOCRYPTO

/* NOTE: if AES also works, do in place encryption */

static TPM_RC TSS_Command_DecryptAes(TSS_AUTH_CONTEXT *tssAuthContext,
				     struct TSS_HMAC_CONTEXT *session)
{
    TPM_RC		rc = 0;
    uint32_t 		paramSize;
    uint8_t 		*decryptParamBuffer;
    uint8_t 		*encryptParamBuffer = NULL;
    TPM2B_IV		iv;
    uint32_t           	kdfaBits;
    uint16_t		keySizeinBytes;
    uint8_t		symParmString[MAX_SYM_KEY_BYTES + MAX_SYM_BLOCK_SIZE];	/* AES key + IV */
    
    /* get the TPM2B parameter to encrypt */
    if (rc == 0) {
	rc = TSS_GetCommandDecryptParam(tssAuthContext, &paramSize, &decryptParamBuffer);
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptAes: decrypt in",
				      decryptParamBuffer, paramSize);
    }    
    if (rc == 0) {
	rc = TSS_Malloc(&encryptParamBuffer, paramSize);	/* free @1 */
    }
    /* generate the encryption key and IV */
    /* 21.3	CFB Mode Parameter Encryption

       KDFa (hashAlg, sessionValue, "CFB", nonceNewer, nonceOlder, bits)	(34)

       hashAlg		the hash algorithm associated with the session
       sessionValue	the session-specific HMAC key
       "CFB"		label to differentiate use of KDFa() (see 4.2)
       nonceNewer	nonceCaller for a command and nonceTPM for a response
       nonceOlder	nonceTPM for a command and nonceCaller for a response
       bits		the number of bits required for the symmetric key plus an IV
    */
    if (rc == 0) {
	iv.t.size = TSS_Sym_GetBlockSize(session->symmetric.algorithm,
					 session->symmetric.keyBits.aes);
	/* generate random values for both the AES key and the IV */
	kdfaBits = session->symmetric.keyBits.aes + (iv.t.size * 8);

	if (tssVverbose) printf("TSS_Command_DecryptAes: hashAlg %04x\n",
				session->authHashAlg);
	if (tssVverbose) printf("TSS_Command_DecryptAes: AES key bits %u\n",
				session->symmetric.keyBits.aes);
	if (tssVverbose) printf("TSS_Command_DecryptAes: kdfaBits %04x\n",
				kdfaBits);
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptAes: session key",
				      session->sessionKey.b.buffer, session->sessionKey.b.size);

	rc = TSS_KDFA(&symParmString[0],
		      session->authHashAlg,
		      &session->sessionValue.b,
		      "CFB",
		      &session->nonceCaller.b,
		      &session->nonceTPM.b,
		      kdfaBits);
    }
    /* copy the latter part of the kdf output to the IV */
    if (rc == 0) {
	keySizeinBytes = session->symmetric.keyBits.aes / 8;
	memcpy(iv.t.buffer, &symParmString[keySizeinBytes], iv.t.size);
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptAes: IV",
				      iv.t.buffer, iv.t.size);
    }
    /* AES CFB encrypt the command */
    if (rc == 0) {
	TPM_RC crc;
	crc = TSS_AES_EncryptCFB(encryptParamBuffer,			/* output */
				 session->symmetric.keyBits.aes,	/* 128 */
				 symParmString,				/* key */
				 iv.t.buffer,				/* IV */
				 paramSize,				/* length */
				 (uint8_t *)decryptParamBuffer);	/* input */
	if (crc != 0) {
	    if (tssVerbose) printf("TSS_Command_DecryptAes: AES encrypt failed\n");
	    rc = TSS_RC_AES_ENCRYPT_FAILURE;
	}
    }		 
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Command_DecryptAes: encrypt out",
				      encryptParamBuffer, paramSize);
    }
    if (rc == 0) {
	rc = TSS_SetCommandDecryptParam(tssAuthContext, paramSize, encryptParamBuffer);
    }
    free(encryptParamBuffer);	/* @1 */
    return rc;
}    

#endif	/* TPM_TSS_NOCRYPTO */

static TPM_RC TSS_Response_Encrypt(TSS_AUTH_CONTEXT *tssAuthContext,
				   struct TSS_HMAC_CONTEXT *session[],
				   TPMI_SH_AUTH_SESSION sessionHandle[],
				   unsigned int sessionAttributes[])
{
    TPM_RC		rc = 0;
    unsigned int 	isEncrypt = 0;		/* count number of sessions with decrypt set */
    unsigned int	encryptSession = 0;	/* which one is decrypt */
    
    /* determine if there is an encrypt session */
    if (rc == 0) {
	rc = TSS_Sessions_GetEncryptSession(&isEncrypt,
					    &encryptSession,
					    sessionHandle,
					    sessionAttributes);
    }
#ifndef TPM_TSS_NOCRYPTO
    {
	COMMAND_INDEX   tpmCommandIndex;	/* index into TPM table */
	TPM_CC 		commandCode;
	int		encryptSize;		/* size of TPM2B size, 2 if there is a TPM2B, 0 if
						   not */
	uint32_t 	paramSize;		/* size of the parameter to decrypt */	
	uint8_t 	*encryptParamBuffer;
	/* can the response parameter be decrypted */
	if ((rc == 0) && isEncrypt) {
	    /* get the commandCode, stored in TSS during marshal */
	    commandCode  = TSS_GetCommandCode(tssAuthContext);
	    /* get the index into the TPM command attributes table */
	    tpmCommandIndex = CommandCodeToCommandIndex(commandCode);
	    /* can this be a decrypt command */
	    encryptSize = getEncryptSize(tpmCommandIndex);
	    if (encryptSize == 0) {
		if (tssVerbose) printf("TSS_Response_Encrypt: "
				       "Error, response cannot be encrypted\n");
		rc = TSS_RC_NO_ENCRYPT_PARAMETER;
	    }
	}
	/* get the TPM2B parameter to decrypt */
	if ((rc == 0) && isEncrypt) {
	    rc = TSS_GetResponseEncryptParam(tssAuthContext, &paramSize, &encryptParamBuffer);
	}
	/* if the size of the parameter to decrypt is zero, nothing to decrypt */
	if ((rc == 0) && isEncrypt) {
	    if (paramSize == 0) {
		isEncrypt = FALSE;	/* none, done with this function */
	    }
	}
	/* error checking complete, do the decryption */
	if ((rc == 0) && isEncrypt) {
	    switch (session[encryptSession]->symmetric.algorithm) {
	      case TPM_ALG_XOR:
		rc = TSS_Response_EncryptXor(tssAuthContext, session[encryptSession]);
		break;
	      case TPM_ALG_AES:
		rc = TSS_Response_EncryptAes(tssAuthContext, session[encryptSession]);
		break;
	      default:
		if (tssVerbose) printf("TSS_Response_Encrypt: "
				       "Error, algorithm %04x not implemented\n",
				       session[encryptSession]->symmetric.algorithm);
		rc = TSS_RC_BAD_ENCRYPT_ALGORITHM;
		break;
	    }
	}
    }
#else
    tssAuthContext = tssAuthContext;
    session = session;
    if ((rc == 0) && isEncrypt) {
	if (tssVerbose)
	    printf("TSS_Response_Encrypt: Error, with no crypto not implemented\n");
	rc = TSS_RC_NOT_IMPLEMENTED;
    }
#endif
    return rc;
}

#ifndef TPM_TSS_NOCRYPTO

/* NOTE: if CFB also works, do in place decryption */

static TPM_RC TSS_Response_EncryptXor(TSS_AUTH_CONTEXT *tssAuthContext,
				      struct TSS_HMAC_CONTEXT *session)
{
    TPM_RC		rc = 0;
    unsigned int	i;
    uint32_t 		paramSize;
    uint8_t 		*encryptParamBuffer;
    uint8_t 		*mask = NULL;
    uint8_t 		*decryptParamBuffer = NULL;

    /* get the TPM2B parameter to decrypt */
    if (rc == 0) {
	rc = TSS_GetResponseEncryptParam(tssAuthContext,
					 &paramSize, &encryptParamBuffer);
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Response_EncryptXor: encrypt in",
				      encryptParamBuffer, paramSize);
    }    
    if (rc == 0) {
	rc = TSS_Malloc(&mask, paramSize);			/* freed @1 */
    }
    if (rc == 0) {
	rc = TSS_Malloc(&decryptParamBuffer, paramSize);	/* freed @2 */
    }
    /* generate the XOR pad */
    /* 21.2	XOR Parameter Obfuscation

       XOR(parameter, hashAlg, sessionValue, nonceNewer, nonceOlder)

       parameter	a variable sized buffer containing the parameter to be obfuscated
       hashAlg		the hash algorithm associated with the session
       sessionValue	the session-specific HMAC key
       nonceNewer	for commands, this will be nonceCaller and for responses it will be nonceTPM
       nonceOlder	for commands, this will be nonceTPM and for responses it will be nonceCaller

       
       11.4.6.3	XOR Obfuscation

       XOR(data, hashAlg, key, contextU, contextV)
       
       mask = KDFa (hashAlg, key, "XOR", contextU, contextV, data.size * 8)
    */
    /* KDFa for the XOR mask */
    if (rc == 0) {
	if (tssVverbose) printf("TSS_Response_EncryptXor: hashAlg %04x\n", session->authHashAlg);
	if (tssVverbose) printf("TSS_Response_EncryptXor: sizeInBits %04x\n", paramSize * 8);
	if (tssVverbose) TSS_PrintAll("TSS_Response_EncryptXor: session key",
				      session->sessionKey.b.buffer, session->sessionKey.b.size);
	rc = TSS_KDFA(mask,
		      session->authHashAlg,
		      &session->sessionValue.b,
		      "XOR",
		      &session->nonceTPM.b,
		      &session->nonceCaller.b,
		      paramSize * 8);
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Response_EncryptXor: mask",
				      mask, paramSize);
    }
    /* XOR */
    for (i = 0 ; (rc == 0) && (i < paramSize ) ; i++)  {
	decryptParamBuffer[i] = encryptParamBuffer[i] ^ mask[i];
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Response_EncryptXor: decrypt out",
				      decryptParamBuffer, paramSize);
    }
    if (rc == 0) {
	rc = TSS_SetResponseDecryptParam(tssAuthContext,
					 paramSize, decryptParamBuffer);
    }
    free(mask);			/* @1 */
    free(decryptParamBuffer);	/* @2 */
    return rc;
}

#endif	/* TPM_TSS_NOCRYPTO */

#ifndef TPM_TSS_NOCRYPTO

/* NOTE: if CFB also works, do in place decryption */

static TPM_RC TSS_Response_EncryptAes(TSS_AUTH_CONTEXT *tssAuthContext,
				      struct TSS_HMAC_CONTEXT *session)
{
    TPM_RC		rc = 0;
    uint32_t 		paramSize;
    uint8_t 		*encryptParamBuffer;
    uint8_t 		*decryptParamBuffer = NULL;
    TPM2B_IV		iv;
    uint32_t           	kdfaBits;
    uint16_t		keySizeinBytes;
    uint8_t		symParmString[MAX_SYM_KEY_BYTES + MAX_SYM_BLOCK_SIZE];	/* AES key + IV */

    /* get the TPM2B parameter to decrypt */
    if (rc == 0) {
	rc = TSS_GetResponseEncryptParam(tssAuthContext,
					 &paramSize, &encryptParamBuffer);
    }
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Response_EncryptAes: encrypt in",
				      encryptParamBuffer, paramSize);
    }    
    if (rc == 0) {
	rc = TSS_Malloc(&decryptParamBuffer, paramSize);	/* freed @1 */
    }
    /* generate the encryption key and IV */
    /* 21.3	CFB Mode Parameter Encryption

       KDFa (hashAlg, sessionValue, "CFB", nonceNewer, nonceOlder, bits)	(34)
    */
    if (rc == 0) {
	
	iv.t.size = TSS_Sym_GetBlockSize(session->symmetric.algorithm,
					 session->symmetric.keyBits.aes);
	/* generate random values for both the AES key and the IV */
	kdfaBits = session->symmetric.keyBits.aes + (iv.t.size * 8);

	if (tssVverbose) printf("TSS_Response_EncryptAes: hashAlg %04x\n",
				session->authHashAlg);
	if (tssVverbose) printf("TSS_Response_EncryptAes: AES key bits %u\n",
				session->symmetric.keyBits.aes);
	if (tssVverbose) printf("TSS_Response_EncryptAes: kdfaBits %04x\n",
				kdfaBits);
	if (tssVverbose) TSS_PrintAll("TSS_Response_EncryptAes: session key",
				      session->sessionKey.b.buffer, session->sessionKey.b.size);
	
	rc = TSS_KDFA(&symParmString[0],
		      session->authHashAlg,
		      &session->sessionValue.b,
		      "CFB",
		      &session->nonceTPM.b,
		      &session->nonceCaller.b,
		      kdfaBits);
    }
    /* copy the latter part of the kdf output to the IV */
    if (rc == 0) {
	keySizeinBytes = session->symmetric.keyBits.aes / 8;
	memcpy(iv.t.buffer, &symParmString[keySizeinBytes], iv.t.size);
	if (tssVverbose) TSS_PrintAll("TSS_Response_EncryptAes: IV",
				      iv.t.buffer, iv.t.size);
    }
    /* AES CFB decrypt the response */
    if (rc == 0) {
	TPM_RC crc;
	crc = TSS_AES_DecryptCFB(decryptParamBuffer,			/* output */
				 session->symmetric.keyBits.aes,	/* 128 */
				 symParmString,				/* key */
				 iv.t.buffer,				/* IV */
				 paramSize,				/* length */
				 (uint8_t *)encryptParamBuffer);	/* input */
	if (crc != 0) {
	    if (tssVerbose) printf("TSS_Response_EncryptAes: AES decrypt failed\n");
	    rc = TSS_RC_AES_DECRYPT_FAILURE;
	}
    }		 
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_Response_EncryptAes: decrypt out",
				      decryptParamBuffer, paramSize);
    }
    if (rc == 0) {
	rc = TSS_SetResponseDecryptParam(tssAuthContext,
					 paramSize, decryptParamBuffer);
    }
    free(decryptParamBuffer);	/* @1 */
    return rc;
}

#endif	/* TPM_TSS_NOCRYPTO */

/*
  Command Change Authorization Processor
*/

#ifndef TPM_TSS_NOCRYPTO

static TPM_RC TSS_Command_ChangeAuthProcessor(TSS_CONTEXT *tssContext,
					      struct TSS_HMAC_CONTEXT *session,
					      size_t handleNumber,
					      COMMAND_PARAMETERS *in)
{
    TPM_RC 			rc = 0;
    size_t 			index;
    int 			found;
    TSS_ChangeAuthFunction_t 	changeAuthFunction = NULL;

    TPM_CC commandCode = TSS_GetCommandCode(tssContext->tssAuthContext);

    /* search the table for a change authorization processing function */
    if (rc == 0) {
	found = FALSE;
	for (index = 0 ; (index < (sizeof(tssTable) / sizeof(TSS_TABLE))) && !found ; index++) {
	    if (tssTable[index].commandCode == commandCode) {
		found = TRUE;
		break;	/* don't increment index if found */
	    }
	}
    }
    /* found false means there is no change authorization function.  This permits the table to be
       smaller if desired. */
    if ((rc == 0) && found) {
	changeAuthFunction = tssTable[index].changeAuthFunction;
	/* there could also be an entry that is currently NULL, nothing to do */
	if (changeAuthFunction == NULL) {
	    found = FALSE;
	}
    }
    /* call the processing function */
    if ((rc == 0) && found) {
	rc = changeAuthFunction(tssContext, session, handleNumber, in);
    }
    return rc;
}

#endif	/* TPM_TSS_NOCRYPTO */

static TPM_RC TSS_CA_HierarchyChangeAuth(TSS_CONTEXT *tssContext,
					 struct TSS_HMAC_CONTEXT *session,
					 size_t handleNumber,
					 HierarchyChangeAuth_In *in)
{
    TPM_RC 		rc = 0;
    char		*password = NULL;
    
    if (tssVverbose) printf("TSS_CA_HierarchyChangeAuth\n");
    if (in->newAuth.t.size == 0) {
	password = NULL;
    }
    else {
	if (rc == 0) {
	    rc = TSS_Malloc((uint8_t **)&password,	/* freed @1 */
			    in->newAuth.t.size + 1);
	}
	if (rc == 0) {
	    /* copy the password */
	    memcpy(password, in->newAuth.t.buffer, in->newAuth.t.size);
	    password[in->newAuth.t.size] = '\0';	/* nul terminate string */
	}
    }
#ifndef TPM_TSS_NOCRYPTO
    if (rc == 0) {
	rc = TSS_HmacSession_SetHmacKey(tssContext,
					session,
					handleNumber,
					password);
    }
#else
    tssContext = tssContext;
    session = session;
    handleNumber = handleNumber;
#endif	/* TPM_TSS_NOCRYPTO */
    free(password);	/* @1 */
    return rc;
}

static TPM_RC TSS_CA_NV_ChangeAuth(TSS_CONTEXT *tssContext,
				   struct TSS_HMAC_CONTEXT *session,
				   size_t handleNumber,
				   NV_ChangeAuth_In *in)
{
    TPM_RC 		rc = 0;
    char		*password = NULL;

    if (tssVverbose) printf("TSS_CA_NV_ChangeAuth\n");
    if (in->newAuth.t.size == 0) {
	password = NULL;
    }
    else {
	if (rc == 0) {
	    rc = TSS_Malloc((uint8_t **)&password,	/* freed @1 */
			    in->newAuth.t.size + 1);
	}
	if (rc == 0) {
	    /* copy the password */
	    memcpy(password, in->newAuth.t.buffer, in->newAuth.t.size);
	    password[in->newAuth.t.size] = '\0';	/* nul terminate string */
	}
    }
#ifndef TPM_TSS_NOCRYPTO
    if (rc == 0) {
	rc = TSS_HmacSession_SetHmacKey(tssContext,
					session,
					handleNumber,
					password);
    }
#else
    tssContext = tssContext;
    session = session;
    handleNumber = handleNumber;
#endif	/* TPM_TSS_NOCRYPTO */
    free(password);	/* @1 */
    return rc;
}

static TPM_RC TSS_CA_NV_UndefineSpaceSpecial(TSS_CONTEXT *tssContext,
					     struct TSS_HMAC_CONTEXT *session,
					     size_t handleNumber,
					     NV_UndefineSpaceSpecial_In *in)
{
    TPM_RC 		rc = 0;
    
    in = in;
    if (tssVverbose) printf("TSS_CA_NV_UndefineSpaceSpecial\n");
#ifndef TPM_TSS_NOCRYPTO
    if (rc == 0) {
	/* the nvIndex authorization, the zeroth authorization, has special handling */
	if (handleNumber == 0) {
	    /* the Empty Buffer is used as the authValue when generating the response HMAC */
	    rc = TSS_HmacSession_SetHmacKey(tssContext,
					    session,
					    handleNumber,
					    NULL);		/* password */
	}
    }
#else
    tssContext = tssContext;
    session = session;
    handleNumber = handleNumber;
#endif	/* TPM_TSS_NOCRYPTO */
    return rc;
}

/*
  Command Pre-Processor
*/

static TPM_RC TSS_Command_PreProcessor(TSS_CONTEXT *tssContext,
				       TPM_CC commandCode,
				       COMMAND_PARAMETERS *in,
				       EXTRA_PARAMETERS *extra)
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
	/* call the pre processing function if there is one */
	if (preProcessFunction != NULL) {
	    rc = preProcessFunction(tssContext, in, extra);
	}
    }
#ifndef TPM_TSS_NO_PRINT
    if ((rc == 0) && tssVverbose) {
	found = FALSE;
	for (index = 0 ;
	     (index < (sizeof(tssPrintTable) / sizeof(TSS_PRINT_TABLE))) && !found ;
	     index++) {
	    if (tssPrintTable[index].commandCode == commandCode) {
		found = TRUE;
		break;	/* don't increment index if found */
	    }
	}
    }
    /* found false means there is no print function.  This permits the table to be smaller
       if desired. */
    if ((rc == 0) && tssVverbose && found) {
	TSS_InPrintFunction_t inPrintFunction = tssPrintTable[index].inPrintFunction;
	/* call the pre processing function if there is one */
	if (inPrintFunction != NULL) {
	    printf("TSS_Command_PreProcessor: Input parameters\n");
	    inPrintFunction(in, 8);	/* hard code indent 8 */
	}
    }
#endif /* TPM_TSS_NO_PRINT */
    return rc;
}

/*
  Command specific pre processing functions
*/

/* TSS_PR_StartAuthSession handles StartAuthSession pre processing.

   If the salt key in->tpmKey is not NULL and an RSA key, the preprocessor supplies the encrypted
   salt.  It passes the unencrypted salt to the post processor for session key processing.

   An input salt (encrypted or unencrypted) is ignored.

   Returns an error if the key is not an RSA key.
*/

static TPM_RC TSS_PR_StartAuthSession(TSS_CONTEXT *tssContext,
				      StartAuthSession_In *in,
				      StartAuthSession_Extra *extra)
{
    TPM_RC 			rc = 0;
    
    if (tssVverbose) printf("TSS_PR_StartAuthSession\n");

    /* if (tssVverbose) StartAuthSession_In_Print(in, 8); */
    
#ifndef TPM_TSS_NOCRYPTO
    /* generate nonceCaller */
    if (rc == 0) {
	/* the size is determined by the session hash algorithm */
	in->nonceCaller.t.size = TSS_GetDigestSize(in->authHash);
	if (in->nonceCaller.t.size == 0) {
	    if (tssVerbose) printf("TSS_PR_StartAuthSession: hash algorithm %04x not implemented\n",
				   in->authHash);
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    if (rc == 0) {
	rc = TSS_RandBytes((unsigned char *)&in->nonceCaller.t.buffer, in->nonceCaller.t.size);
    }
#else
    in->nonceCaller.t.size = 16;
    memset(&in->nonceCaller.t.buffer, 0, 16);
#endif	/* TPM_TSS_NOCRYPTO */
	/* initialize to handle unsalted session */
    in->encryptedSalt.t.size = 0;
    if (extra != NULL) {		/* extra NULL is handled at the port processor */
	extra->salt.t.size = 0;
    }
    /* if the caller requests a salted session */
    if (in->tpmKey != TPM_RH_NULL) {
#ifndef TPM_TSS_NOCRYPTO
	TPM2B_PUBLIC		bPublic;
	
	if (rc == 0) {
	    if (extra == NULL) {
		if (tssVerbose)
		    printf("TSS_PR_StartAuthSession: salt session requires extra parameter\n");
		rc = TSS_RC_NULL_PARAMETER;
	    }
	}
	/* get the tpmKey public key */
	if (rc == 0) {
	    rc = TSS_Public_Load(tssContext, &bPublic, in->tpmKey, NULL);
	}
	/* generate the salt and encrypted salt based on the asymmetric key type */
	if (rc == 0) {
	    switch (bPublic.publicArea.type) {
#ifndef TPM_TSS_NOECC
	      case TPM_ALG_ECC:
		rc = TSS_ECC_Salt(&extra->salt,
				  &in->encryptedSalt,
				  &bPublic.publicArea);
		break;
#endif	/* TPM_TSS_NOECC */
#ifndef TPM_TSS_NORSA
	      case TPM_ALG_RSA:
		rc = TSS_RSA_Salt(&extra->salt,
				  &in->encryptedSalt,
				  &bPublic.publicArea);
		break;
#endif 	/* TPM_TSS_NORSA */
	      default:
		if (tssVerbose)
		    printf("TSS_PR_StartAuthSession: public key type %04x not supported\n",
			   bPublic.publicArea.type);
		rc = TSS_RC_BAD_SALT_KEY;
	    }
	}
#else
	tssContext = tssContext;
	rc = TSS_RC_NOT_IMPLEMENTED;
#endif	/* TPM_TSS_NOCRYPTO */
    }
    return rc;
}

#ifndef TPM_TSS_NOCRYPTO
#ifndef TPM_TSS_NORSA

/* TSS_RSA_Salt() returns both the plaintext and excrypted salt, based on the salt key bPublic. */

static TPM_RC TSS_RSA_Salt(TPM2B_DIGEST 		*salt,
			   TPM2B_ENCRYPTED_SECRET	*encryptedSalt,
			   TPMT_PUBLIC			*publicArea)
{
    TPM_RC		rc = 0;

    if (rc == 0) {
	{
	    /* error conditions when true */
	    int b1 = publicArea->type != TPM_ALG_RSA;
	    int b2 = publicArea->objectAttributes.val & TPMA_OBJECT_SIGN;
	    int b3 = !(publicArea->objectAttributes.val & TPMA_OBJECT_DECRYPT);
	    int b4 = (publicArea->parameters.rsaDetail.exponent != 0) &&
		     /* some HW TPMs return 010001 for the RSA EK with the default IWG template */
		     (publicArea->parameters.rsaDetail.exponent != RSA_DEFAULT_PUBLIC_EXPONENT);
	    /* TSS support checks */
	    if (b1 || b2 || b3 || b4) {
		if (tssVerbose)
		    printf("TSS_RSA_Salt: public key attributes not supported\n");
		rc = TSS_RC_BAD_SALT_KEY;
	    }
	}
    }    
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_RSA_Salt: public key",
				      publicArea->unique.rsa.t.buffer,
				      publicArea->unique.rsa.t.size);
    }
    /* generate a salt */
    if (rc == 0) {
	/* The size of the secret value is limited to the size of the digest produced by the
	   nameAlg of the object that is associated with the public key used for OAEP
	   encryption. */
	salt->t.size = TSS_GetDigestSize(publicArea->nameAlg);
	if (tssVverbose) printf("TSS_RSA_Salt: "
				"Hash algorithm %04x Salt size %u\n",
				publicArea->nameAlg, salt->t.size);
	/* place the salt in extra so that it can be retrieved by post processor */
	rc = TSS_RandBytes((uint8_t *)&salt->t.buffer, salt->t.size);
    }
    /* In TPM2_StartAuthSession(), when tpmKey is an RSA key, the secret value (salt) is
       encrypted using OAEP as described in B.4. The string "SECRET" (see 4.5) is used as
       the L value and the nameAlg of the encrypting key is used for the hash algorithm. The
       data value in OAEP-encrypted blob (salt) is used to compute sessionKey. */
    if (rc == 0) {
	if (tssVverbose) TSS_PrintAll("TSS_RSA_Salt: salt",
				      (uint8_t *)&salt->t.buffer,
				      salt->t.size);
    }
    /* encrypt the salt */
    if (rc == 0) {
	/* public exponent */
	unsigned char earr[3] = {0x01, 0x00, 0x01};
	/* encrypt the salt with the tpmKey public key */
	rc = TSS_RSAPublicEncrypt((uint8_t *)&encryptedSalt->t.secret,   /* encrypted data */
				  publicArea->unique.rsa.t.size,  /* size of encrypted data buffer */
				  (uint8_t *)&salt->t.buffer, /* decrypted data */
				  salt->t.size,
				  publicArea->unique.rsa.t.buffer,  /* public modulus */
				  publicArea->unique.rsa.t.size,
				  earr, 		/* public exponent */
				  sizeof(earr),
				  (unsigned char *)"SECRET",	/* encoding parameter */
				  sizeof("SECRET"),
				  publicArea->nameAlg);
    }    
    if (rc == 0) {
	encryptedSalt->t.size = publicArea->unique.rsa.t.size;
	if (tssVverbose) TSS_PrintAll("TSS_RSA_Salt: RSA encrypted salt",
				      encryptedSalt->t.secret,
				      encryptedSalt->t.size);
    }
    return rc;
}

#endif /* TPM_TSS_NORSA */
#endif /* TPM_TSS_NOCRYPTO */

static TPM_RC TSS_PR_NV_DefineSpace(TSS_CONTEXT *tssContext,
				    NV_DefineSpace_In *in,
				    void *extra)
{
    TPM_RC 	rc = 0;
    tssContext = tssContext;
    extra = extra;

    if (tssVverbose) printf("TSS_PR_NV_DefineSpace\n");
    /* Test that TPMA_NVA_POLICY_DELETE is only set when a policy is also set.  Otherwise, the index
       cannot ever be deleted, even with Platform Authorization. If the application really wants to
       do this, set the policy to one that cannot be satisfied, e.g., all 0xff's. */
    if (rc == 0) {
	if (in->publicInfo.nvPublic.attributes.val & TPMA_NVA_POLICY_DELETE) {
	    if (in->publicInfo.nvPublic.authPolicy.b.size == 0) {
		if (tssVverbose) printf("TSS_PR_NV_DefineSpace POLICY_DELETE requires a policy\n");
		rc = TSS_RC_IN_PARAMETER;
	    }
	}
    }
    return rc;
}

/*
  Response Post Processor
*/

/* TSS_Response_PostProcessor() handles any response specific post processing
 */

static TPM_RC TSS_Response_PostProcessor(TSS_CONTEXT *tssContext,
					 COMMAND_PARAMETERS *in,
					 RESPONSE_PARAMETERS *out,
					 EXTRA_PARAMETERS *extra)
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

/* TSS_PO_StartAuthSession handles StartAuthSession post processing.  It:

   creates a TSS HMAC session

   saves the session handle, hash algorithm, and symmetric algorithm, nonceCaller and nonceTPM
   
   It calculates the session key and saves it

   Finally, it marshals the session and stores it
*/

static TPM_RC TSS_PO_StartAuthSession(TSS_CONTEXT *tssContext,
				      StartAuthSession_In *in,
				      StartAuthSession_Out *out,
				      StartAuthSession_Extra *extra)
{
    TPM_RC 			rc = 0;
    struct TSS_HMAC_CONTEXT 	*session = NULL;
    TPM2B_DIGEST 		salt;
    
    if (tssVverbose) printf("TSS_PO_StartAuthSession\n");
    /* allocate a TSS_HMAC_CONTEXT session context */
    if (rc == 0) {
	rc = TSS_HmacSession_GetContext(&session);
    }
    if (rc == 0) {
	session->sessionHandle = out->sessionHandle;
	session->authHashAlg = in->authHash;
#ifndef TPM_TSS_NOCRYPTO
	session->sizeInBytes = TSS_GetDigestSize(session->authHashAlg);
#endif
	session->symmetric = in->symmetric;
	session->sessionType = in->sessionType;
    }
    /* if not a bind session or if no bind password was supplied */
    if (rc == 0) {
	if ((extra == NULL) || (in->bind == TPM_RH_NULL) || (extra->bindPassword == NULL)) {
	    session->bindAuthValue.b.size = 0;
	}
	else {
	    rc = TSS_TPM2B_StringCopy(&session->bindAuthValue.b,
				      extra->bindPassword, sizeof(session->bindAuthValue.t.buffer));
	}
    }
    if (rc == 0) {
	/* if the caller did not supply extra, the salt must be empty */
	if (extra == NULL) {
	    salt.b.size = 0;
	}
	/* if the caller supplied extra, the preprocessor sets salt to empty (unsalted) or the
	   plaintext salt value */
	else {
	    rc = TSS_TPM2B_Copy(&salt.b, &extra->salt.b, sizeof(TPMT_HA));
	}
    }
#ifndef TPM_TSS_NOCRYPTO
    if (rc == 0) {
	rc = TSS_TPM2B_Copy(&session->nonceTPM.b, &out->nonceTPM.b, sizeof(TPMT_HA));
    }
    if (rc == 0) {
	rc = TSS_TPM2B_Copy(&session->nonceCaller.b, &in->nonceCaller.b, sizeof(TPMT_HA));
    }
    if (rc == 0) {
	rc = TSS_HmacSession_SetSessionKey(tssContext, session,
					   &salt,
					   in->bind, &session->bindAuthValue);
    }
#endif	/* TPM_TSS_NOCRYPTO */
    if (rc == 0) {
	rc = TSS_HmacSession_SaveSession(tssContext, session);
    }
    TSS_HmacSession_FreeContext(session);
    return rc;
}

/* TSS_PO_ContextSave() saves the name of an object in a filename that is a hash of the contextBlob.

   This permits the name to be found during ContextLoad.
*/

static TPM_RC TSS_PO_ContextSave(TSS_CONTEXT *tssContext,
				 ContextSave_In *in,
				 ContextSave_Out *out,
				 void *extra)
{
    TPM_RC 		rc = 0;
#ifndef TPM_TSS_NOFILE
    TPMT_HA 		cpHash;		/* largest size of a digest */
    char		string[65];	/*  sha256 hash * 2 + 1 */
    TPM_HT 		handleType;
    int			done = FALSE;
#endif

    in = in;
    extra = extra;

#ifndef TPM_TSS_NOFILE
    if (tssVverbose) printf("TSS_PO_ContextSave: handle %08x\n", in->saveHandle);
    /* only for objects and sequence objects, not sessions */
    if (rc == 0) {
	handleType = (TPM_HT) ((in->saveHandle & HR_RANGE_MASK) >> HR_SHIFT);
	if (handleType != TPM_HT_TRANSIENT) {
	    done = TRUE;
	}
    }
    if ((rc == 0) && !done) {
	cpHash.hashAlg = TPM_ALG_SHA256;	/* arbitrary choice */
	rc = TSS_Hash_Generate(&cpHash,
			       out->context.contextBlob.b.size, out->context.contextBlob.b.buffer,
			       0, NULL);
    }
    /* convert a hash of the context blob to a string */
    if ((rc == 0) && !done) {
	rc = TSS_HashToString(string, cpHash.digest.sha256);
    }
    if ((rc == 0) && !done) {
	rc = TSS_Name_Copy(tssContext,
			   0, string,			/* to context */
			   in->saveHandle, NULL);	/* from handle */
    }
    /* get the public key of the object being context saved */
    /* save the public key under the context */
    if ((rc == 0) && !done) {
	rc = TSS_Public_Copy(tssContext,
			     0,
			     string,
			     in->saveHandle,
			     NULL);
    }
#else
    tssContext = tssContext;
    out = out;
#endif
    return rc;
}

static TPM_RC TSS_PO_ContextLoad(TSS_CONTEXT *tssContext,
				 ContextLoad_In *in,
				 ContextLoad_Out *out,
				 void *extra)
{
    TPM_RC 		rc = 0;
#ifndef TPM_TSS_NOFILE
    TPMT_HA 		cpHash;		/* largest size of a digest */
    char		string[65];	/*  sha256 hash * 2 + 1 */
    TPM_HT 		handleType;
    int			done = FALSE;
#endif

    out = out;
    extra = extra;

#ifndef TPM_TSS_NOFILE
    if (tssVverbose) printf("TSS_PO_ContextLoad: handle %08x\n", out->loadedHandle);
    /* only for objects and sequence objects, not sessions */
    if (rc == 0) {
	handleType = (TPM_HT) ((out->loadedHandle & HR_RANGE_MASK) >> HR_SHIFT);
	if (handleType != TPM_HT_TRANSIENT) {
	    done = TRUE;
	}
    }
    if ((rc == 0) && !done) {
	cpHash.hashAlg = TPM_ALG_SHA256;	/* arbitrary choice */
	rc = TSS_Hash_Generate(&cpHash,
			       in->context.contextBlob.b.size, in->context.contextBlob.b.buffer,
			       0, NULL);
    }
    /* convert a hash of the context blob to a string */
    if ((rc == 0) && !done) {
	rc = TSS_HashToString(string, cpHash.digest.sha256);
    }
    /* get the Name of the object being context loaded */
    /* write the name with the loaded context's handle */
    if ((rc == 0) && !done) {
	rc = TSS_Name_Copy(tssContext,
			   out->loadedHandle, NULL,	/* to handle */
			   0, string);			/* from context */	
    }
    /* get the public key of the object being context loaded */
    /* write the public key with the loaded context's handle */
    if ((rc == 0) && !done) {
	rc = TSS_Public_Copy(tssContext,
			     out->loadedHandle,
			     NULL,
			     0,
			     string);
    }
#else
    tssContext = tssContext;
    in = in; 
#endif
    return rc;
}

/* TSS_HashToString() converts a SHA-256 binary hash (really any 32-byte value) to a string 

   string must be 65 bytes: 32*2 + 1

   NOTE: Hard coded to SHA256
*/

#ifndef TPM_TSS_NOFILE

static TPM_RC TSS_HashToString(char *str, uint8_t *digest)
{
    size_t i;

    for (i = 0 ; i < SHA256_DIGEST_SIZE ; i++) {
	sprintf(str +(i*2), "%02x", digest[i]);
    }
    if (tssVverbose) printf("TSS_HashToString: %s\n", str);
    return 0;
}

#endif

/* TSS_PO_FlushContext() removes persistent state associated with the handle */

static TPM_RC TSS_PO_FlushContext(TSS_CONTEXT *tssContext,
				  FlushContext_In *in,
				  void *out,
				  void *extra)
{
    TPM_RC 			rc = 0;

    out = out;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_FlushContext: flushHandle %08x\n", in->flushHandle);
    if (rc == 0) {
	rc = TSS_DeleteHandle(tssContext, in->flushHandle);
    }
    return rc;
}

/* TSS_PO_EvictControl() removes persistent state associated with the handle */

static TPM_RC TSS_PO_EvictControl(TSS_CONTEXT *tssContext,
				  EvictControl_In *in,
				  void *out,
				  void *extra)
{
    TPM_RC 			rc = 0;

    out = out;
    extra = extra;
    
    if (tssVverbose) printf("TSS_PO_EvictControl: object %08x persistent %08x\n",
			    in->objectHandle, in->persistentHandle);
    /* if it successfully made a persistent copy */
    if (in->objectHandle != in->persistentHandle) {
	/* TPM2B_PUBLIC	bPublic; */
	if (rc == 0) {
	    rc = TSS_Name_Copy(tssContext,
			       in->persistentHandle, NULL,	/* to persistent handle */
			       in->objectHandle, NULL);		/* from transient handle */	
	}
	/* get the transient object public key */
	/* copy it to the persistent object public key */
	if (rc == 0) {
	    rc = TSS_Public_Copy(tssContext,
				 in->persistentHandle,
				 NULL,
				 in->objectHandle,
				 NULL);
	}
    }
    /* if it successfully evicted the persistent object */
    else {
	if (rc == 0) {
	    rc = TSS_DeleteHandle(tssContext, in->persistentHandle);
	}
    }
    return rc;
}

/* TSS_PO_Load() saves the Name returned for the loaded object.  It saves the TPM2B_PUBLIC */

static TPM_RC TSS_PO_Load(TSS_CONTEXT *tssContext,
			  Load_In *in,
			  Load_Out *out,
			  void *extra)
{
    TPM_RC 	rc = 0;

    in = in;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_Load: handle %08x\n", out->objectHandle);
    /* use handle as file name */
    if (rc == 0) {
	rc = TSS_Name_Store(tssContext, &out->name, out->objectHandle, NULL);
    }
    if (rc == 0) {
	rc = TSS_Public_Store(tssContext, &in->inPublic, out->objectHandle, NULL);
    }
    return rc;
}

/* TSS_PO_LoadExternal() saves the Name returned for the loaded object */

static TPM_RC TSS_PO_LoadExternal(TSS_CONTEXT *tssContext,
				  LoadExternal_In *in,
				  LoadExternal_Out *out,
				  void *extra)
{
    TPM_RC 	rc = 0;

    in = in;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_LoadExternal: handle %08x\n", out->objectHandle);
    /* use handle as file name */
    if (rc == 0) {
	rc = TSS_Name_Store(tssContext, &out->name, out->objectHandle, NULL);
    }
    if (rc == 0) {
	rc = TSS_Public_Store(tssContext, &in->inPublic, out->objectHandle, NULL);
    }
    return rc;
}

/* TSS_PO_ReadPublic() saves the Name returned for the loaded object */

static TPM_RC TSS_PO_ReadPublic(TSS_CONTEXT *tssContext,
				ReadPublic_In *in,
				ReadPublic_Out *out,
				void *extra)
{
    TPM_RC 	rc = 0;

    in = in;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_ReadPublic: handle %08x\n", in->objectHandle);
    /* if the TSS is compiled without crypto support, it cannot recalculate the Name from the public
       area. It has to trust the response from the TPM.  This should be OK since a 'no crypto' TSS
       is used when there is a tructed path to the TPM. */
#ifndef TPM_TSS_NOCRYPTO
    /* validate the Name against the public area */
    /* Name = nameAlg || HnameAlg (handle->publicArea)
       where
       nameAlg	algorithm used to compute Name
       HnameAlg	hash using the nameAlg parameter in the object associated with handle
       publicArea 	contents of the TPMT_PUBLIC associated with handle
    */
    {
	TPM2B_NAME name;
	if (rc == 0) {
	    rc = TSS_ObjectPublic_GetName(&name, &out->outPublic.publicArea);
	}
	if (rc == 0) {
	    if (name.t.size != out->name.t.size) {
		if (tssVerbose)
		    printf("TSS_PO_ReadPublic: TPMT_PUBLIC does not match TPM2B_NAME\n");
		rc = TSS_RC_MALFORMED_PUBLIC;
	    }
	    else {
		int irc;
		irc = memcmp(name.t.name, out->name.t.name, out->name.t.size);
		if (irc != 0) {
		    if (tssVerbose)
			printf("TSS_PO_ReadPublic: TPMT_PUBLIC does not match TPM2B_NAME\n");
		    rc = TSS_RC_MALFORMED_PUBLIC;
		}
	    }
	}
    }
#endif
    /* use handle as file name */
    if (rc == 0) {
	rc = TSS_Name_Store(tssContext, &out->name, in->objectHandle, NULL);
    }
    if (rc == 0) {
	rc = TSS_Public_Store(tssContext, &out->outPublic, in->objectHandle, NULL);
    }
    return rc;
}

/* TSS_PO_Load() saves the Name returned for the loaded object.  It saves the TPM2B_PUBLIC */

static TPM_RC TSS_PO_CreateLoaded(TSS_CONTEXT *tssContext,
				  CreateLoaded_In *in,
				  CreateLoaded_Out *out,
				  void *extra)
{
    TPM_RC 	rc = 0;

    in = in;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_CreateLoaded: handle %08x\n", out->objectHandle);
    /* use handle as file name */
    if (rc == 0) {
	rc = TSS_Name_Store(tssContext, &out->name, out->objectHandle, NULL);
    }
    if (rc == 0) {
	rc = TSS_Public_Store(tssContext, &out->outPublic, out->objectHandle, NULL);
    }
    return rc;
}

/* TSS_PO_HashSequenceStart() saves the Name returned for the started sequence object */

static TPM_RC TSS_PO_HashSequenceStart(TSS_CONTEXT *tssContext,
				       HashSequenceStart_In *in,
				       HashSequenceStart_Out *out,
				       void *extra)
{
    TPM_RC 	rc = 0;
    TPM2B_NAME 	name;

    in = in;
    extra = extra;

    if (tssVverbose) printf("TSS_PO_HashSequenceStart\n");
    /* Part 1 Table 3 The Name of a sequence object is an Empty Buffer */
    if (rc == 0) {
	name.b.size = 0;
	/* use handle as file name */
	rc = TSS_Name_Store(tssContext, &name, out->sequenceHandle, NULL);
    }
    return rc;
}


/* TSS_PO_HMAC_Start() saves the Name returned for the started sequence object */

static TPM_RC TSS_PO_HMAC_Start(TSS_CONTEXT *tssContext,
				HMAC_Start_In *in,
				HMAC_Start_Out *out,
				void *extra)
{
    TPM_RC 	rc = 0;
    TPM2B_NAME 	name;

    in = in;
    extra = extra;

    if (tssVverbose) printf("TSS_PO_HMAC_Start\n");
    /* Part 1 Table 3 The Name of a sequence object is an Empty Buffer */
    if (rc == 0) {
	name.b.size = 0;
	/* use handle as file name */
	rc = TSS_Name_Store(tssContext, &name, out->sequenceHandle, NULL);
    }
    return rc;
}

static TPM_RC TSS_PO_SequenceComplete(TSS_CONTEXT *tssContext,
				      SequenceComplete_In *in,
				      SequenceComplete_Out *out,
				      void *extra)
{
    TPM_RC 	rc = 0;

    out = out;
    extra = extra;

    if (tssVverbose) printf("TSS_PO_SequenceComplete: sequenceHandle %08x\n", in->sequenceHandle);
    if (rc == 0) {
	rc = TSS_DeleteHandle(tssContext, in->sequenceHandle);
    }
    return rc;
}
static TPM_RC TSS_PO_EventSequenceComplete(TSS_CONTEXT *tssContext,
					   EventSequenceComplete_In *in,
					   EventSequenceComplete_Out *out,
					   void *extra)
{
    TPM_RC 	rc = 0;
    out = out;
    extra = extra;
    if (tssVverbose)
	printf("TSS_PO_EventSequenceComplete: sequenceHandle %08x\n", in->sequenceHandle);
    if (rc == 0) {
	rc = TSS_DeleteHandle(tssContext, in->sequenceHandle);
    }
    return rc;
}

static TPM_RC TSS_PO_PolicyAuthValue(TSS_CONTEXT *tssContext,
				     PolicyAuthValue_In *in,
				     void *out,
				     void *extra)
{
    TPM_RC 			rc = 0;
    struct TSS_HMAC_CONTEXT 	*session = NULL;
    
    out = out;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_PolicyAuthValue\n");
    if (rc == 0) {
	rc = TSS_Malloc((unsigned char **)&session, sizeof(TSS_HMAC_CONTEXT));	/* freed @1 */
    }
    if (rc == 0) {
	rc = TSS_HmacSession_LoadSession(tssContext, session, in->policySession);
    }
    if (rc == 0) {
	session->isPasswordNeeded = FALSE;
	session->isAuthValueNeeded = TRUE;
	rc = TSS_HmacSession_SaveSession(tssContext, session);
    }
    free(session);		/* @1 */
    return rc;
}

static TPM_RC TSS_PO_PolicyPassword(TSS_CONTEXT *tssContext,
				    PolicyPassword_In *in,
				    void *out,
				    void *extra)
{
    TPM_RC 			rc = 0;
    struct TSS_HMAC_CONTEXT 	*session = NULL;

    out = out;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_PolicyPassword\n");
    if (rc == 0) {
	rc = TSS_Malloc((unsigned char **)&session, sizeof(TSS_HMAC_CONTEXT));	/* freed @1 */
    }
    if (rc == 0) {
	rc = TSS_HmacSession_LoadSession(tssContext, session, in->policySession);
    }
    if (rc == 0) {
	session->isPasswordNeeded = TRUE;
	session->isAuthValueNeeded = FALSE;
	rc = TSS_HmacSession_SaveSession(tssContext, session);
    }
    free(session);		/* @1 */
    return rc;
}

static TPM_RC TSS_PO_CreatePrimary(TSS_CONTEXT *tssContext,
				   CreatePrimary_In *in,
				   CreatePrimary_Out *out,
				   void *extra)
{
    TPM_RC 			rc = 0;

    in = in;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_CreatePrimary: handle %08x\n", out->objectHandle);
    /* use handle as file name */
    if (rc == 0) {
	rc = TSS_Name_Store(tssContext, &out->name, out->objectHandle, NULL);
    }
    if (rc == 0) {
	rc = TSS_Public_Store(tssContext, &out->outPublic, out->objectHandle, NULL);
    }
    return rc;
}

static TPM_RC TSS_PO_NV_DefineSpace(TSS_CONTEXT *tssContext,
				    NV_DefineSpace_In *in,
				    void *out,
				    void *extra)
{
    TPM_RC 	rc = 0;

    if (tssVverbose) printf("TSS_PO_NV_DefineSpace\n");
#ifndef TPM_TSS_NOCRYPTO
    {
	TPM2B_NAME name;
	/* calculate the Name from the input public area */
	/* Name = nameAlg || HnameAlg (handle->nvPublicArea)
	   where
	   nameAlg	algorithm used to compute Name
	   HnameAlg hash using the nameAlg parameter in the NV Index location associated with handle
	   nvPublicArea	contents of the TPMS_NV_PUBLIC associated with handle
	*/
	/* calculate the Name from the input TPMS_NV_PUBLIC */
	if (rc == 0) {
	    rc = TSS_NVPublic_GetName(&name, &in->publicInfo.nvPublic);
	}
	/* use handle as file name */
	if (rc == 0) {
	    rc = TSS_Name_Store(tssContext, &name, in->publicInfo.nvPublic.nvIndex, NULL);
	}
	if (rc == 0) {
	    rc = TSS_NVPublic_Store(tssContext, &in->publicInfo.nvPublic,
				    in->publicInfo.nvPublic.nvIndex); 
	}
    }
#else
    tssContext = tssContext;
    in = in;
#endif
    out = out;
    extra = extra;
    return rc;
}


static TPM_RC TSS_PO_NV_ReadPublic(TSS_CONTEXT *tssContext,
				   NV_ReadPublic_In *in,
				   NV_ReadPublic_Out *out,
				   void *extra)
{
    TPM_RC 	rc = 0;

    if (tssVverbose) printf("TSS_PO_NV_ReadPublic\n");
    
    /* validate the Name against the public area */
    /* Name = nameAlg || HnameAlg (handle->nvPublicArea)
       where
       nameAlg	algorithm used to compute Name
       HnameAlg hash using the nameAlg parameter in the NV Index location associated with handle
       nvPublicArea	contents of the TPMS_NV_PUBLIC associated with handle
    */
#ifndef TPM_TSS_NOCRYPTO
    {
	TPM2B_NAME name;
	/* calculate the Name from the TPMS_NV_PUBLIC */
	if (rc == 0) {
	    rc = TSS_NVPublic_GetName(&name, &out->nvPublic.nvPublic);
	}
	if (rc == 0) {
	    if (name.t.size != out->nvName.t.size) {
		if (tssVerbose)
		    printf("TSS_PO_NV_ReadPublic: TPMT_NV_PUBLIC does not match TPM2B_NAME\n");
		rc = TSS_RC_MALFORMED_NV_PUBLIC;
	    }
	    else {
		int irc;
		irc = memcmp(name.t.name, out->nvName.t.name, out->nvName.t.size);
		if (irc != 0) {
		    if (tssVerbose)
			printf("TSS_PO_NV_ReadPublic: TPMT_NV_PUBLIC does not match TPM2B_NAME\n");
		    rc = TSS_RC_MALFORMED_NV_PUBLIC;
		}
	    }
	}
	/* use handle as file name */
	if (rc == 0) {
	    rc = TSS_Name_Store(tssContext, &out->nvName, in->nvIndex, NULL);
	}
	if (rc == 0) {
	    rc = TSS_NVPublic_Store(tssContext, &out->nvPublic.nvPublic, in->nvIndex); 
	}
    }
#else
    tssContext = tssContext;
    in = in;
    out = out;
#endif
    extra = extra;
    return rc;
}

static TPM_RC TSS_PO_NV_UndefineSpace(TSS_CONTEXT *tssContext,
				      NV_UndefineSpace_In *in,
				      void *out,
				      void *extra)
{
    TPM_RC 			rc = 0;

    out = out;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_NV_UndefineSpace\n");
#ifndef TPM_TSS_NOCRYPTO
    /* Don't check return code. */
    TSS_DeleteHandle(tssContext, in->nvIndex);
    TSS_NVPublic_Delete(tssContext, in->nvIndex);
#else
    tssContext = tssContext;
    in = in;
#endif
    return rc;
}

static TPM_RC TSS_PO_NV_UndefineSpaceSpecial(TSS_CONTEXT *tssContext,
					     NV_UndefineSpaceSpecial_In *in,
					     void *out,
					     void *extra)
{
    TPM_RC 			rc = 0;

    out = out;
    extra = extra;
    if (tssVverbose) printf("TSS_PO_NV_UndefineSpaceSpecial\n");
    /* Don't check return code.  The name will only exist if NV_ReadPublic has been issued */
    TSS_DeleteHandle(tssContext, in->nvIndex);
    TSS_NVPublic_Delete(tssContext, in->nvIndex);
    return rc;
}

/* TSS_PO_NV_Write() handles the Name and NVPublic update for the 4 NV write commands: write,
   increment, extend, and setbits */

static TPM_RC TSS_PO_NV_Write(TSS_CONTEXT *tssContext,
			      NV_Write_In *in,
			      void *out,
			      void *extra)
{
    TPM_RC 			rc = 0;
    
    if (tssVverbose) printf("TSS_PO_NV_Write, Increment, Extend, SetBits:\n");

#ifndef TPM_TSS_NOCRYPTO
    {
	TPMS_NV_PUBLIC 		nvPublic;
	TPM2B_NAME 		name;		/* new name */
	
	if (rc == 0) {
	    rc = TSS_NVPublic_Load(tssContext, &nvPublic, in->nvIndex);
	}
	/* if the previous store had written clear */
	if (!(nvPublic.attributes.val & TPMA_NVA_WRITTEN)) {
	    if (rc == 0) {
		/* set the written bit */
		nvPublic.attributes.val |= TPMA_NVA_WRITTEN;
		/* save the TPMS_NV_PUBLIC */
		rc = TSS_NVPublic_Store(tssContext, &nvPublic, in->nvIndex);
	    }
	    /* calculate the name */
	    if (rc == 0) {
		rc = TSS_NVPublic_GetName(&name, &nvPublic);
	    }
	    /* save the name */
	    if (rc == 0) {
		/* use handle as file name */
		rc = TSS_Name_Store(tssContext, &name, in->nvIndex, NULL);
	    }
	    /* if there is a failure. delete the name and NVPublic */
	    if (rc != 0) {
		TSS_DeleteHandle(tssContext, in->nvIndex);
		TSS_NVPublic_Delete(tssContext, in->nvIndex);
	    }
	}
    }
#else
    tssContext = tssContext;
    in = in;
#endif
    out = out;
    extra = extra;
    return rc;
}

/* TSS_PO_NV_WriteLock() handles the Name and NVPublic update for the write lock command */

static TPM_RC TSS_PO_NV_WriteLock(TSS_CONTEXT *tssContext,
				  NV_WriteLock_In *in,
				  void *out,
				  void *extra)
{
    TPM_RC 			rc = 0;
   
    if (tssVverbose) printf("TSS_PO_NV_WriteLock:\n");

#ifndef TPM_TSS_NOCRYPTO
    {
	TPMS_NV_PUBLIC 		nvPublic;
	TPM2B_NAME 		name;		/* new name */
	
 	if (rc == 0) {
	    rc = TSS_NVPublic_Load(tssContext, &nvPublic, in->nvIndex);
	}
	/* if the previous store had write lock clear */
	if (!(nvPublic.attributes.val & TPMA_NVA_WRITELOCKED)) {
	    if (rc == 0) {
		/* set the write lock bit */
		nvPublic.attributes.val |= TPMA_NVA_WRITELOCKED;
		/* save the TPMS_NV_PUBLIC */
		rc = TSS_NVPublic_Store(tssContext, &nvPublic, in->nvIndex);
	    }
	    /* calculate the name */
	    if (rc == 0) {
		rc = TSS_NVPublic_GetName(&name, &nvPublic);
	    }
	    /* save the name */
	    if (rc == 0) {
		/* use handle as file name */
		rc = TSS_Name_Store(tssContext, &name, in->nvIndex, NULL);
	    }
	    /* if there is a failure. delete the name and NVPublic */
	    if (rc != 0) {
		TSS_DeleteHandle(tssContext, in->nvIndex);
		TSS_NVPublic_Delete(tssContext, in->nvIndex);
	    }
	}
    }
#else
    tssContext = tssContext;
    in = in;
#endif
    out = out;
    extra = extra;
    return rc;
}

/* TSS_PO_NV_WriteLock() handles the Name and NVPublic update for the read lock command */

static TPM_RC TSS_PO_NV_ReadLock(TSS_CONTEXT *tssContext,
				 NV_ReadLock_In *in,
				 void *out,
				 void *extra)
{
    TPM_RC 			rc = 0;
    
    if (tssVverbose) printf("TSS_PO_NV_ReadLock:");

#ifndef TPM_TSS_NOCRYPTO
    {
	TPMS_NV_PUBLIC 		nvPublic;
	TPM2B_NAME 			name;		/* new name */

	if (rc == 0) {
	    rc = TSS_NVPublic_Load(tssContext, &nvPublic, in->nvIndex);
	}
	/* if the previous store had read lock clear */
	if (!(nvPublic.attributes.val & TPMA_NVA_READLOCKED)) {
	    if (rc == 0) {
		/* set the read lock bit */
		nvPublic.attributes.val |= TPMA_NVA_READLOCKED;
		/* save the TPMS_NV_PUBLIC */
		rc = TSS_NVPublic_Store(tssContext, &nvPublic, in->nvIndex);
	    }
	    /* calculate the name */
	    if (rc == 0) {
		rc = TSS_NVPublic_GetName(&name, &nvPublic);
	    }
	    /* save the name */
	    if (rc == 0) {
		/* use handle as file name */
		rc = TSS_Name_Store(tssContext, &name, in->nvIndex, NULL);
	    }
	    /* if there is a failure. delete the name and NVPublic */
	    if (rc != 0) {
		TSS_DeleteHandle(tssContext, in->nvIndex);
		TSS_NVPublic_Delete(tssContext, in->nvIndex);
	    }
	}
    }
#else
    tssContext = tssContext;
    in = in;
#endif
    out = out;
    extra = extra;
    return rc;
}

