/********************************************************************************/
/*										*/
/*			     TPM 2.0 TSS Authorization				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2020.					*/
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

#include "tssntc.h"
#include "tssauth.h"
#include "tssauth20.h"

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

static const MARSHAL_TABLE marshalTable [] = {
				 
    {TPM_CC_Startup, "TPM2_Startup",
     (MarshalInFunction_t)TSS_Startup_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)Startup_In_Unmarshal
#endif
    },
    {TPM_CC_Shutdown, "TPM2_Shutdown",
     (MarshalInFunction_t)TSS_Shutdown_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)Shutdown_In_Unmarshal
#endif
    },
    {TPM_CC_SelfTest, "TPM2_SelfTest",
     (MarshalInFunction_t)TSS_SelfTest_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)SelfTest_In_Unmarshal
#endif
    },
    {TPM_CC_IncrementalSelfTest, "TPM2_IncrementalSelfTest",
     (MarshalInFunction_t)TSS_IncrementalSelfTest_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_IncrementalSelfTest_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)IncrementalSelfTest_In_Unmarshal
#endif
    },
    {TPM_CC_GetTestResult, "TPM2_GetTestResult",
     NULL,
     (UnmarshalOutFunction_t)TSS_GetTestResult_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,NULL
#endif
    },
    {TPM_CC_StartAuthSession, "TPM2_StartAuthSession",
     (MarshalInFunction_t)TSS_StartAuthSession_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_StartAuthSession_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)StartAuthSession_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyRestart, "TPM2_PolicyRestart",
     (MarshalInFunction_t)TSS_PolicyRestart_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyRestart_In_Unmarshal
#endif
    },
    {TPM_CC_Create, "TPM2_Create",
     (MarshalInFunction_t)TSS_Create_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_Create_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)Create_In_Unmarshal
#endif
    },
    {TPM_CC_Load, "TPM2_Load",
     (MarshalInFunction_t)TSS_Load_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_Load_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)Load_In_Unmarshal
#endif
    },
    {TPM_CC_LoadExternal, "TPM2_LoadExternal",
     (MarshalInFunction_t)TSS_LoadExternal_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_LoadExternal_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)LoadExternal_In_Unmarshal
#endif
    },
    {TPM_CC_ReadPublic, "TPM2_ReadPublic",
     (MarshalInFunction_t)TSS_ReadPublic_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_ReadPublic_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)ReadPublic_In_Unmarshal
#endif
    },
    {TPM_CC_ActivateCredential, "TPM2_ActivateCredential",
     (MarshalInFunction_t)TSS_ActivateCredential_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_ActivateCredential_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)ActivateCredential_In_Unmarshal
#endif
    },
    {TPM_CC_MakeCredential, "TPM2_MakeCredential",
     (MarshalInFunction_t)TSS_MakeCredential_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_MakeCredential_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)MakeCredential_In_Unmarshal
#endif
    },
    {TPM_CC_Unseal, "TPM2_Unseal",
     (MarshalInFunction_t)TSS_Unseal_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_Unseal_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)Unseal_In_Unmarshal
#endif
    },
    {TPM_CC_ObjectChangeAuth, "TPM2_ObjectChangeAuth",
     (MarshalInFunction_t)TSS_ObjectChangeAuth_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_ObjectChangeAuth_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)ObjectChangeAuth_In_Unmarshal
#endif
    },
    {TPM_CC_CreateLoaded, "TPM2_CreateLoaded",
     (MarshalInFunction_t)TSS_CreateLoaded_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_CreateLoaded_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)CreateLoaded_In_Unmarshal
#endif
    },
    {TPM_CC_Duplicate, "TPM2_Duplicate",
     (MarshalInFunction_t)TSS_Duplicate_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_Duplicate_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)Duplicate_In_Unmarshal
#endif
    },
    {TPM_CC_Rewrap, "TPM2_Rewrap",
     (MarshalInFunction_t)TSS_Rewrap_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_Rewrap_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)Rewrap_In_Unmarshal
#endif
    },
    {TPM_CC_Import, "TPM2_Import",
     (MarshalInFunction_t)TSS_Import_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_Import_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)Import_In_Unmarshal
#endif
    },
    {TPM_CC_RSA_Encrypt, "TPM2_RSA_Encrypt",
     (MarshalInFunction_t)TSS_RSA_Encrypt_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_RSA_Encrypt_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)RSA_Encrypt_In_Unmarshal
#endif
    },
    {TPM_CC_RSA_Decrypt, "TPM2_RSA_Decrypt",
     (MarshalInFunction_t)TSS_RSA_Decrypt_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_RSA_Decrypt_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)RSA_Decrypt_In_Unmarshal
#endif
    },
    {TPM_CC_ECDH_KeyGen, "TPM2_ECDH_KeyGen",
     (MarshalInFunction_t)TSS_ECDH_KeyGen_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_ECDH_KeyGen_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)ECDH_KeyGen_In_Unmarshal
#endif
    },
    {TPM_CC_ECDH_ZGen, "TPM2_ECDH_ZGen",
     (MarshalInFunction_t)TSS_ECDH_ZGen_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_ECDH_ZGen_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)ECDH_ZGen_In_Unmarshal
#endif
    },
    {TPM_CC_ECC_Parameters, "TPM2_ECC_Parameters",
     (MarshalInFunction_t)TSS_ECC_Parameters_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_ECC_Parameters_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)ECC_Parameters_In_Unmarshal
#endif
    },
    {TPM_CC_ZGen_2Phase, "TPM2_ZGen_2Phase",
     (MarshalInFunction_t)TSS_ZGen_2Phase_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_ZGen_2Phase_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)ZGen_2Phase_In_Unmarshal
#endif
    },
    {TPM_CC_EncryptDecrypt, "TPM2_EncryptDecrypt",
     (MarshalInFunction_t)TSS_EncryptDecrypt_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_EncryptDecrypt_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)EncryptDecrypt_In_Unmarshal
#endif
    },
    {TPM_CC_EncryptDecrypt2, "TPM2_EncryptDecrypt2",
     (MarshalInFunction_t)TSS_EncryptDecrypt2_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_EncryptDecrypt2_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)EncryptDecrypt2_In_Unmarshal
#endif
    },
    {TPM_CC_Hash, "TPM2_Hash",
     (MarshalInFunction_t)TSS_Hash_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_Hash_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)Hash_In_Unmarshal
#endif
    },
    {TPM_CC_HMAC, "TPM2_HMAC",
     (MarshalInFunction_t)TSS_HMAC_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_HMAC_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)HMAC_In_Unmarshal
#endif
    },
    {TPM_CC_GetRandom, "TPM2_GetRandom",
     (MarshalInFunction_t)TSS_GetRandom_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_GetRandom_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)GetRandom_In_Unmarshal
#endif
    },
    {TPM_CC_StirRandom, "TPM2_StirRandom",
     (MarshalInFunction_t)TSS_StirRandom_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)StirRandom_In_Unmarshal
#endif
    },
    {TPM_CC_HMAC_Start, "TPM2_HMAC_Start",
     (MarshalInFunction_t)TSS_HMAC_Start_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_HMAC_Start_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)HMAC_Start_In_Unmarshal
#endif
    },
    {TPM_CC_HashSequenceStart, "TPM2_HashSequenceStart",
     (MarshalInFunction_t)TSS_HashSequenceStart_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_HashSequenceStart_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)HashSequenceStart_In_Unmarshal
#endif
    },
    {TPM_CC_SequenceUpdate, "TPM2_SequenceUpdate",
     (MarshalInFunction_t)TSS_SequenceUpdate_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)SequenceUpdate_In_Unmarshal
#endif
    },
    {TPM_CC_SequenceComplete, "TPM2_SequenceComplete",
     (MarshalInFunction_t)TSS_SequenceComplete_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_SequenceComplete_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)SequenceComplete_In_Unmarshal
#endif
    },
    {TPM_CC_EventSequenceComplete, "TPM2_EventSequenceComplete",
     (MarshalInFunction_t)TSS_EventSequenceComplete_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_EventSequenceComplete_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)EventSequenceComplete_In_Unmarshal
#endif
    },
    {TPM_CC_Certify, "TPM2_Certify",
     (MarshalInFunction_t)TSS_Certify_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_Certify_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)Certify_In_Unmarshal
#endif
    },
    {TPM_CC_CertifyX509, "TPM2_CertifyX509",
     (MarshalInFunction_t)TSS_CertifyX509_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_CertifyX509_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)CertifyX509_In_Unmarshal
#endif
    },
    {TPM_CC_CertifyCreation, "TPM2_CertifyCreation",
     (MarshalInFunction_t)TSS_CertifyCreation_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_CertifyCreation_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)CertifyCreation_In_Unmarshal
#endif
    },
    {TPM_CC_Quote, "TPM2_Quote",
     (MarshalInFunction_t)TSS_Quote_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_Quote_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)Quote_In_Unmarshal
#endif
    },
    {TPM_CC_GetSessionAuditDigest, "TPM2_GetSessionAuditDigest",
     (MarshalInFunction_t)TSS_GetSessionAuditDigest_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_GetSessionAuditDigest_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)GetSessionAuditDigest_In_Unmarshal
#endif
    },
    {TPM_CC_GetCommandAuditDigest, "TPM2_GetCommandAuditDigest",
     (MarshalInFunction_t)TSS_GetCommandAuditDigest_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_GetCommandAuditDigest_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)GetCommandAuditDigest_In_Unmarshal
#endif
    },
    {TPM_CC_GetTime, "TPM2_GetTime",
     (MarshalInFunction_t)TSS_GetTime_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_GetTime_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)GetTime_In_Unmarshal
#endif
    },
    {TPM_CC_Commit, "TPM2_Commit",
     (MarshalInFunction_t)TSS_Commit_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_Commit_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)Commit_In_Unmarshal
#endif
    },
    {TPM_CC_EC_Ephemeral, "TPM2_EC_Ephemeral",
     (MarshalInFunction_t)TSS_EC_Ephemeral_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_EC_Ephemeral_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)EC_Ephemeral_In_Unmarshal
#endif
    },
    {TPM_CC_VerifySignature, "TPM2_VerifySignature",
     (MarshalInFunction_t)TSS_VerifySignature_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_VerifySignature_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)VerifySignature_In_Unmarshal
#endif
    },
    {TPM_CC_Sign, "TPM2_Sign",
     (MarshalInFunction_t)TSS_Sign_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_Sign_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)Sign_In_Unmarshal
#endif
    },
    {TPM_CC_SetCommandCodeAuditStatus, "TPM2_SetCommandCodeAuditStatus",
     (MarshalInFunction_t)TSS_SetCommandCodeAuditStatus_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)SetCommandCodeAuditStatus_In_Unmarshal
#endif
    },
    {TPM_CC_PCR_Extend, "TPM2_PCR_Extend",
     (MarshalInFunction_t)TSS_PCR_Extend_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PCR_Extend_In_Unmarshal
#endif
    },
    {TPM_CC_PCR_Event, "TPM2_PCR_Event",
     (MarshalInFunction_t)TSS_PCR_Event_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_PCR_Event_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PCR_Event_In_Unmarshal
#endif
    },
    {TPM_CC_PCR_Read, "TPM2_PCR_Read",
     (MarshalInFunction_t)TSS_PCR_Read_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_PCR_Read_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PCR_Read_In_Unmarshal
#endif
    },
    {TPM_CC_PCR_Allocate, "TPM2_PCR_Allocate",
     (MarshalInFunction_t)TSS_PCR_Allocate_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_PCR_Allocate_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PCR_Allocate_In_Unmarshal
#endif
    },
    {TPM_CC_PCR_SetAuthPolicy, "TPM2_PCR_SetAuthPolicy",
     (MarshalInFunction_t)TSS_PCR_SetAuthPolicy_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PCR_SetAuthPolicy_In_Unmarshal
#endif
    },
    {TPM_CC_PCR_SetAuthValue, "TPM2_PCR_SetAuthValue",
     (MarshalInFunction_t)TSS_PCR_SetAuthValue_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PCR_SetAuthValue_In_Unmarshal
#endif
    },
    {TPM_CC_PCR_Reset, "TPM2_PCR_Reset",
     (MarshalInFunction_t)TSS_PCR_Reset_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PCR_Reset_In_Unmarshal
#endif
    },
    {TPM_CC_PolicySigned, "TPM2_PolicySigned",
     (MarshalInFunction_t)TSS_PolicySigned_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_PolicySigned_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicySigned_In_Unmarshal
#endif
    },
    {TPM_CC_PolicySecret, "TPM2_PolicySecret",
     (MarshalInFunction_t)TSS_PolicySecret_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_PolicySecret_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicySecret_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyTicket, "TPM2_PolicyTicket",
     (MarshalInFunction_t)TSS_PolicyTicket_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyTicket_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyOR, "TPM2_PolicyOR",
     (MarshalInFunction_t)TSS_PolicyOR_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyOR_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyPCR, "TPM2_PolicyPCR",
     (MarshalInFunction_t)TSS_PolicyPCR_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyPCR_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyLocality, "TPM2_PolicyLocality",
     (MarshalInFunction_t)TSS_PolicyLocality_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyLocality_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyNV, "TPM2_PolicyNV",
     (MarshalInFunction_t)TSS_PolicyNV_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyNV_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyAuthorizeNV, "TPM2_PolicyAuthorizeNV",
     (MarshalInFunction_t)TSS_PolicyAuthorizeNV_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyAuthorizeNV_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyCounterTimer, "TPM2_PolicyCounterTimer",
     (MarshalInFunction_t)TSS_PolicyCounterTimer_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyCounterTimer_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyCommandCode, "TPM2_PolicyCommandCode",
     (MarshalInFunction_t)TSS_PolicyCommandCode_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyCommandCode_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyPhysicalPresence, "TPM2_PolicyPhysicalPresence",
     (MarshalInFunction_t)TSS_PolicyPhysicalPresence_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyPhysicalPresence_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyCpHash, "TPM2_PolicyCpHash",
     (MarshalInFunction_t)TSS_PolicyCpHash_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyCpHash_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyNameHash, "TPM2_PolicyNameHash",
     (MarshalInFunction_t)TSS_PolicyNameHash_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyNameHash_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyDuplicationSelect, "TPM2_PolicyDuplicationSelect",
     (MarshalInFunction_t)TSS_PolicyDuplicationSelect_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyDuplicationSelect_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyAuthorize, "TPM2_PolicyAuthorize",
     (MarshalInFunction_t)TSS_PolicyAuthorize_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyAuthorize_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyAuthValue, "TPM2_PolicyAuthValue",
     (MarshalInFunction_t)TSS_PolicyAuthValue_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyAuthValue_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyPassword, "TPM2_PolicyPassword",
     (MarshalInFunction_t)TSS_PolicyPassword_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyPassword_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyGetDigest, "TPM2_PolicyGetDigest",
     (MarshalInFunction_t)TSS_PolicyGetDigest_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_PolicyGetDigest_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyGetDigest_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyNvWritten, "TPM2_PolicyNvWritten",
     (MarshalInFunction_t)TSS_PolicyNvWritten_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyNvWritten_In_Unmarshal
#endif
    },
    {TPM_CC_PolicyTemplate, "TPM2_PolicyTemplate",
     (MarshalInFunction_t)TSS_PolicyTemplate_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PolicyTemplate_In_Unmarshal
#endif
    },
    {TPM_CC_CreatePrimary, "TPM2_CreatePrimary",
     (MarshalInFunction_t)TSS_CreatePrimary_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_CreatePrimary_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)CreatePrimary_In_Unmarshal
#endif
    },
    {TPM_CC_HierarchyControl, "TPM2_HierarchyControl",
     (MarshalInFunction_t)TSS_HierarchyControl_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)HierarchyControl_In_Unmarshal
#endif
    },
    {TPM_CC_SetPrimaryPolicy, "TPM2_SetPrimaryPolicy",
     (MarshalInFunction_t)TSS_SetPrimaryPolicy_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)SetPrimaryPolicy_In_Unmarshal
#endif
    },
    {TPM_CC_ChangePPS, "TPM2_ChangePPS",
     (MarshalInFunction_t)TSS_ChangePPS_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)ChangePPS_In_Unmarshal
#endif
    },
    {TPM_CC_ChangeEPS, "TPM2_ChangeEPS",
     (MarshalInFunction_t)TSS_ChangeEPS_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)ChangeEPS_In_Unmarshal
#endif
    },
    {TPM_CC_Clear, "TPM2_Clear",
     (MarshalInFunction_t)TSS_Clear_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)Clear_In_Unmarshal
#endif
    },
    {TPM_CC_ClearControl, "TPM2_ClearControl",
     (MarshalInFunction_t)TSS_ClearControl_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)ClearControl_In_Unmarshal
#endif
    },
    {TPM_CC_HierarchyChangeAuth, "TPM2_HierarchyChangeAuth",
     (MarshalInFunction_t)TSS_HierarchyChangeAuth_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)HierarchyChangeAuth_In_Unmarshal
#endif
    },
    {TPM_CC_DictionaryAttackLockReset, "TPM2_DictionaryAttackLockReset",
     (MarshalInFunction_t)TSS_DictionaryAttackLockReset_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)DictionaryAttackLockReset_In_Unmarshal
#endif
    },
    {TPM_CC_DictionaryAttackParameters, "TPM2_DictionaryAttackParameters",
     (MarshalInFunction_t)TSS_DictionaryAttackParameters_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)DictionaryAttackParameters_In_Unmarshal
#endif
    },
    {TPM_CC_PP_Commands, "TPM2_PP_Commands",
     (MarshalInFunction_t)TSS_PP_Commands_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)PP_Commands_In_Unmarshal
#endif
    },
    {TPM_CC_SetAlgorithmSet, "TPM2_SetAlgorithmSet",
     (MarshalInFunction_t)TSS_SetAlgorithmSet_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)SetAlgorithmSet_In_Unmarshal
#endif
    },
    {TPM_CC_ContextSave, "TPM2_ContextSave",
     (MarshalInFunction_t)TSS_ContextSave_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_ContextSave_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)ContextSave_In_Unmarshal
#endif
    },
    {TPM_CC_ContextLoad, "TPM2_ContextLoad",
     (MarshalInFunction_t)TSS_ContextLoad_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_ContextLoad_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)ContextLoad_In_Unmarshal
#endif
    },
    {TPM_CC_FlushContext, "TPM2_FlushContext",
     (MarshalInFunction_t)TSS_FlushContext_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)FlushContext_In_Unmarshal
#endif
    },
    {TPM_CC_EvictControl, "TPM2_EvictControl",
     (MarshalInFunction_t)TSS_EvictControl_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)EvictControl_In_Unmarshal
#endif
    },
    {TPM_CC_ReadClock, "TPM2_ReadClock",
     NULL,
     (UnmarshalOutFunction_t)TSS_ReadClock_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,NULL
#endif
    },
    {TPM_CC_ClockSet, "TPM2_ClockSet",
     (MarshalInFunction_t)TSS_ClockSet_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)ClockSet_In_Unmarshal
#endif
    },
    {TPM_CC_ClockRateAdjust, "TPM2_ClockRateAdjust",
     (MarshalInFunction_t)TSS_ClockRateAdjust_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)ClockRateAdjust_In_Unmarshal
#endif
    },
    {TPM_CC_GetCapability, "TPM2_GetCapability",
     (MarshalInFunction_t)TSS_GetCapability_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_GetCapability_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)GetCapability_In_Unmarshal
#endif
    },
    {TPM_CC_TestParms, "TPM2_TestParms",
     (MarshalInFunction_t)TSS_TestParms_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)TestParms_In_Unmarshal
#endif
    },
    {TPM_CC_NV_DefineSpace, "TPM2_NV_DefineSpace",
     (MarshalInFunction_t)TSS_NV_DefineSpace_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)NV_DefineSpace_In_Unmarshal
#endif
    },
    {TPM_CC_NV_UndefineSpace, "TPM2_NV_UndefineSpace",
     (MarshalInFunction_t)TSS_NV_UndefineSpace_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)NV_UndefineSpace_In_Unmarshal
#endif
    },
    {TPM_CC_NV_UndefineSpaceSpecial, "TPM2_NV_UndefineSpaceSpecial",
     (MarshalInFunction_t)TSS_NV_UndefineSpaceSpecial_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)NV_UndefineSpaceSpecial_In_Unmarshal
#endif
    },
    {TPM_CC_NV_ReadPublic, "TPM2_NV_ReadPublic",
     (MarshalInFunction_t)TSS_NV_ReadPublic_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_NV_ReadPublic_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)NV_ReadPublic_In_Unmarshal
#endif
    },
    {TPM_CC_NV_Write, "TPM2_NV_Write",
     (MarshalInFunction_t)TSS_NV_Write_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)NV_Write_In_Unmarshal
#endif
    },
    {TPM_CC_NV_Increment, "TPM2_NV_Increment",
     (MarshalInFunction_t)TSS_NV_Increment_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)NV_Increment_In_Unmarshal
#endif
    },
    {TPM_CC_NV_Extend, "TPM2_NV_Extend",
     (MarshalInFunction_t)TSS_NV_Extend_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)NV_Extend_In_Unmarshal
#endif
    },
    {TPM_CC_NV_SetBits, "TPM2_NV_SetBits",
     (MarshalInFunction_t)TSS_NV_SetBits_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)NV_SetBits_In_Unmarshal
#endif
    },
    {TPM_CC_NV_WriteLock, "TPM2_NV_WriteLock",
     (MarshalInFunction_t)TSS_NV_WriteLock_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)NV_WriteLock_In_Unmarshal
#endif
    },
    {TPM_CC_NV_GlobalWriteLock, "TPM2_NV_GlobalWriteLock",
     (MarshalInFunction_t)TSS_NV_GlobalWriteLock_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)NV_GlobalWriteLock_In_Unmarshal
#endif
    },
    {TPM_CC_NV_Read, "TPM2_NV_Read",
     (MarshalInFunction_t)TSS_NV_Read_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_NV_Read_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)NV_Read_In_Unmarshal
#endif
    },
    {TPM_CC_NV_ReadLock, "TPM2_NV_ReadLock",
     (MarshalInFunction_t)TSS_NV_ReadLock_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)NV_ReadLock_In_Unmarshal
#endif
    },
    {TPM_CC_NV_ChangeAuth, "TPM2_NV_ChangeAuth",
     (MarshalInFunction_t)TSS_NV_ChangeAuth_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)NV_ChangeAuth_In_Unmarshal
#endif
    },
    {TPM_CC_NV_Certify, "TPM2_NV_Certify",
     (MarshalInFunction_t)TSS_NV_Certify_In_Marshalu,
     (UnmarshalOutFunction_t)TSS_NV_Certify_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)NV_Certify_In_Unmarshal
#endif
    },
#ifdef TPM_TSS_NUVOTON
    {NTC2_CC_PreConfig,"NTC2_CC_PreConfig",
     (MarshalInFunction_t)TSS_NTC2_PreConfig_In_Marshalu,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,(UnmarshalInFunction_t)TSS_NTC2_PreConfig_In_Unmarshalu
#endif
    },
    {NTC2_CC_LockPreConfig,"NTC2_CC_LockPreConfig",
     NULL,
     NULL
#ifndef TPM_TSS_NOCMDCHECK
     ,NULL
#endif
    },
    {NTC2_CC_GetConfig,"NTC2_CC_GetConfig",
     NULL,
     (UnmarshalOutFunction_t)TSS_NTC2_GetConfig_Out_Unmarshalu
#ifndef TPM_TSS_NOCMDCHECK
     ,NULL
#endif
    },
     
#endif	/* TPM_TSS_NUVOTON */
};

/* TSS_MarshalTable_Process() indexes into the command marshal table, and saves the marshal and
   unmarshal functions */

static TPM_RC TSS_MarshalTable_Process(TSS_AUTH_CONTEXT *tssAuthContext,
				       TPM_CC commandCode)
{
    TPM_RC rc = 0;
    size_t index;
    int found = FALSE;

    /* get the command index in the dispatch table */
    for (index = 0 ; index < (sizeof(marshalTable) / sizeof(MARSHAL_TABLE)) ; (index)++) {
	if (marshalTable[index].commandCode == commandCode) {
	    found = TRUE;
	    break;
	}
    }
    if (found) {
	tssAuthContext->commandCode = commandCode;
	tssAuthContext->commandText = marshalTable[index].commandText;
	tssAuthContext->marshalInFunction = marshalTable[index].marshalInFunction;
	tssAuthContext->unmarshalOutFunction = marshalTable[index].unmarshalOutFunction;
#ifndef TPM_TSS_NOCMDCHECK
	tssAuthContext->unmarshalInFunction = marshalTable[index].unmarshalInFunction;
#endif
    }
    else {
	if (tssVerbose) printf("TSS_MarshalTable_Process: "
			       "commandCode %08x not found in marshal table\n",
			       commandCode);
	rc = TSS_RC_COMMAND_UNIMPLEMENTED;
    }
    return rc;
}

/* TSS_Marshal() marshals the input parameters into the TSS Authorization context.

   It also sets other member of the context in preparation for the rest of the sequence.  
*/

TPM_RC TSS_Marshal(TSS_AUTH_CONTEXT *tssAuthContext,
		   COMMAND_PARAMETERS *in,
		   TPM_CC commandCode)
{
    TPM_RC 		rc = 0;
    TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;	/* default until sessions are added */
    uint8_t 		*buffer;			/* for marshaling */
#ifndef TPM_TSS_NOCMDCHECK
    uint8_t 		*bufferu;			/* for test unmarshaling */
#endif
    uint32_t 		size;
    
    /* index from command code to table and save items for this command */
    if (rc == 0) {
	rc = TSS_MarshalTable_Process(tssAuthContext, commandCode);
    }
    /* get the number of command and response handles from the TPM table */
    if (rc == 0) {
	tssAuthContext->tpmCommandIndex = CommandCodeToCommandIndex(commandCode);
	if (tssAuthContext->tpmCommandIndex == UNIMPLEMENTED_COMMAND_INDEX) {
	    if (tssVerbose) printf("TSS_Marshal: "
				   "commandCode %08x not found in command attributes table\n",
				   commandCode);
	    rc = TSS_RC_COMMAND_UNIMPLEMENTED;
	}
    }
    if (rc == 0) {
	tssAuthContext->commandHandleCount =
	    getCommandHandleCount(tssAuthContext->tpmCommandIndex);
	tssAuthContext->responseHandleCount =
	    getresponseHandleCount(tssAuthContext->tpmCommandIndex);
    }
    if (rc == 0) {
	/* make a copy of the command buffer and size since the marshal functions move them */
	buffer = tssAuthContext->commandBuffer;
	size = sizeof(tssAuthContext->commandBuffer);
	/* marshal header, preliminary tag and command size */
	rc = TSS_TPMI_ST_COMMAND_TAG_Marshalu(&tag, &tssAuthContext->commandSize, &buffer, &size);
    }
    if (rc == 0) {
	uint32_t commandSize = tssAuthContext->commandSize;
	rc = TSS_UINT32_Marshalu(&commandSize, &tssAuthContext->commandSize, &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_TPM_CC_Marshalu(&commandCode, &tssAuthContext->commandSize, &buffer, &size);
    }    
    if (rc == 0) {
#ifndef TPM_TSS_NOCMDCHECK
	/* save pointer to marshaled data for test unmarshal */
	bufferu = buffer +
		  tssAuthContext->commandHandleCount * sizeof(TPM_HANDLE);
#endif
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
		    printf("TSS_Marshal: Command %08x requires command parameter structure\n",
			   commandCode);
		rc = TSS_RC_IN_PARAMETER;	
	    }
	}
	/* if there is no marshal function */
	else {
	    /* caller error, supplied structure but there is no marshal function */
	    if (in != NULL) {
		if (tssVerbose)
		    printf("TSS_Marshal: Command %08x does not take command parameter structure\n",
			   commandCode);
		rc = TSS_RC_IN_PARAMETER;	
	    }
	    /* no marshal function and no command parameter structure is OK */
	}
    }
#ifndef TPM_TSS_NOCMDCHECK
    /* unmarshal to validate the input parameters */
    if ((rc == 0) && (tssAuthContext->unmarshalInFunction != NULL)) {
	COMMAND_PARAMETERS *target = NULL;
	TPM_HANDLE 	handles[MAX_HANDLE_NUM];
	if (rc == 0) {
	    rc = TSS_Malloc((unsigned char **)&target,
			    sizeof(COMMAND_PARAMETERS));	/* freed @1 */
	}
	if (rc == 0) {
	    size = sizeof(tssAuthContext->commandBuffer) -
		   (tssAuthContext->commandHandleCount * sizeof(TPM_HANDLE));
	    rc = tssAuthContext->unmarshalInFunction(target, &bufferu, &size, handles);
	    if ((rc != 0) && tssVerbose) {
		printf("TSS_Marshal: Invalid command parameter\n");
	    }
	}
	free(target);		/* @1 */
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

/* TSS_Unmarshal() unmarshals the response parameter.

   It returns an error if either there is no unmarshal function and out is not NULL or if there is
   an unmarshal function and out is not NULL.

   If there is no unmarshal function and out is NULL, the function is a noop.
*/

TPM_RC TSS_Unmarshal(TSS_AUTH_CONTEXT *tssAuthContext,
		     RESPONSE_PARAMETERS *out)
{
    TPM_RC 	rc = 0;
    TPM_ST 	tag;
    uint8_t 	*buffer;    
    uint32_t 	size;

    /* if there is an unmarshal function */
    if (tssAuthContext->unmarshalOutFunction != NULL) {
	/* if there is a structure to unmarshal */
	if (out != NULL) {
	    if (rc == 0) {
		/* get the response tag, determines whether there is a response parameterSize to
		   unmarshal */
		buffer = tssAuthContext->responseBuffer;
		size = tssAuthContext->responseSize;
		rc = TSS_TPM_ST_Unmarshalu(&tag, &buffer, &size);
	    }
	    if (rc == 0) {
		/* move the buffer and size past the header */
		buffer = tssAuthContext->responseBuffer +
			 sizeof(TPM_ST) + sizeof(uint32_t) + sizeof(TPM_RC);
		size = tssAuthContext->responseSize -
		       (sizeof(TPM_ST) + sizeof(uint32_t) + sizeof(TPM_RC));
		rc = tssAuthContext->unmarshalOutFunction(out, tag, &buffer, &size);
	    }
	}
	/* caller error, no structure supplied to unmarshal */
	else {
	    if (tssVerbose)
		printf("TSS_Unmarshal: Command %08x requires response parameter structure\n",
		       tssAuthContext->commandCode);
	    rc = TSS_RC_OUT_PARAMETER;
	}
    }
    /* if there is no unmarshal function */
    else {
	/* caller error, structure supplied but no unmarshal function */
	if (out != NULL) {
	    if (tssVerbose)
		printf("TSS_Unmarshal: Command %08x does not take response parameter structure\n",
		       tssAuthContext->commandCode);
	    rc = TSS_RC_OUT_PARAMETER;
	}
	/* no unmarshal function and no response parameter structure is OK */
    }
    return rc;
}

/* TSS_SetCmdAuths() adds a list of TPMS_AUTH_COMMAND structures to the command buffer.

   The arguments are a NULL terminated list of TPMS_AUTH_COMMAND * structures.
 */

TPM_RC TSS_SetCmdAuths(TSS_AUTH_CONTEXT *tssAuthContext, ...)
{
    TPM_RC 		rc = 0;
    va_list		ap;
    uint16_t 		authorizationSize;	/* does not include 4 bytes of size */   
    TPMS_AUTH_COMMAND 	*authCommand = NULL;
    int 		done;
    uint32_t 		cpBufferSize;
    uint8_t 		*cpBuffer;
    uint8_t 		*buffer;

    /* calculate size of authorization area */
    done = FALSE;
    authorizationSize = 0;
    va_start(ap, tssAuthContext);
    while ((rc == 0) && !done){
	authCommand = va_arg(ap, TPMS_AUTH_COMMAND *);
	if (authCommand != NULL) {
	    rc = TSS_TPMS_AUTH_COMMAND_Marshalu(authCommand, &authorizationSize, NULL, NULL);
	}
	else {
	    done = TRUE;
	}
    }
    va_end(ap);
    /* command called with authorizations */
    if (authorizationSize != 0) {
	/* back fill the tag TPM_ST_SESSIONS */
	if (rc == 0) {
	    uint16_t written = 0;		/* dummy */
	    TPMI_ST_COMMAND_TAG tag = TPM_ST_SESSIONS;
	    buffer = tssAuthContext->commandBuffer;
	    TSS_TPMI_ST_COMMAND_TAG_Marshalu(&tag, &written, &buffer, NULL);
	}
	/* get cpBuffer, command parameters */
	if (rc == 0) {
	    rc = TSS_GetCpBuffer(tssAuthContext, &cpBufferSize, &cpBuffer);
	}
	/* new authorization area range check, will cpBuffer move overflow */
	if (rc == 0) {
	    if (cpBuffer +
		cpBufferSize +
		sizeof (uint32_t) +		/* authorizationSize */
		authorizationSize		/* authorization area */
		> tssAuthContext->commandBuffer + sizeof(tssAuthContext->commandBuffer)) {
	
		if (tssVerbose)
		    printf("TSS_SetCmdAuths: Command authorizations overflow command buffer\n");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
	/* move the cpBuffer to make space for the authorization area and its size */
	if (rc == 0) {
	    memmove(cpBuffer + sizeof (uint32_t) + authorizationSize,	/* to here */
		    cpBuffer,						/* from here */
		    cpBufferSize);
	}
	/* marshal the authorizationSize area, where cpBuffer was before move */
	if (rc == 0) {
	    uint32_t authorizationSize32 = authorizationSize;
	    uint16_t written = 0;		/* dummy */
	    TSS_UINT32_Marshalu(&authorizationSize32, &written, &cpBuffer, NULL);
	}
	/* marshal the command authorization areas */
	done = FALSE;
	authorizationSize = 0;
	va_start(ap, tssAuthContext);
	while ((rc == 0) && !done){
	    authCommand = va_arg(ap, TPMS_AUTH_COMMAND *);
	    if (authCommand != NULL) {
		rc = TSS_TPMS_AUTH_COMMAND_Marshalu(authCommand, &authorizationSize, &cpBuffer, NULL);
		tssAuthContext->authCount++; /* count the number of authorizations for the
						response */
	    }
	    else {
		done = TRUE;
	    }
	}
	va_end(ap);
	if (rc == 0) {
	    uint16_t written = 0;		/* dummy */
	    uint32_t commandSize;
	    /* mark cpBuffer new location, size doesn't change */
	    tssAuthContext->cpBuffer += sizeof (uint32_t) + authorizationSize;
	    /* record command stream used size */
	    tssAuthContext->commandSize += sizeof (uint32_t) + authorizationSize;
	    /* back fill the correct commandSize */
	    buffer = tssAuthContext->commandBuffer + sizeof(TPMI_ST_COMMAND_TAG);
	    commandSize = tssAuthContext->commandSize;
	    TSS_UINT32_Marshalu(&commandSize, &written, &buffer, NULL);
	}
    }
    return rc;
}

/* TSS_GetRspAuths() unmarshals a response buffer into a NULL terminated list of TPMS_AUTH_RESPONSE
   structures.  This should not be called if the TPM returned a non-success response code.

   Returns an error if the number of response auths requested is not equal to the number of command
   auths, including zero.

   If the response tag is not TPM_ST_SESSIONS, the function is a noop (except for error checking).
 */

TPM_RC TSS_GetRspAuths(TSS_AUTH_CONTEXT *tssAuthContext, ...)
{
    TPM_RC 	rc = 0;
    va_list	ap;
    TPMS_AUTH_RESPONSE 	*authResponse = NULL;
    uint32_t 	size;
    uint8_t 	*buffer;
    TPM_ST 	tag;
    int 	done;
    uint16_t	authCount = 0;		/* authorizations in response */
    uint32_t 	parameterSize;
    
    /* unmarshal the response tag */
    if (rc == 0) {
	size = tssAuthContext->responseSize;
  	buffer = tssAuthContext->responseBuffer;
	rc = TSS_TPM_ST_Unmarshalu(&tag, &buffer, &size);
    }
    /* check that the tag indicates that there are sessions */
    if ((rc == 0) && (tag == TPM_ST_SESSIONS)) {
	/* offset the buffer past the header and handles, and get the response parameterSize */
	if (rc == 0) {
	    uint32_t offsetSize = sizeof(TPM_ST) +  + sizeof (uint32_t) + sizeof(TPM_RC) +
				  (sizeof(TPM_HANDLE) * tssAuthContext->responseHandleCount);
	    buffer = tssAuthContext->responseBuffer + offsetSize;
	    size = tssAuthContext->responseSize - offsetSize;
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, &buffer, &size);
	}
	if (rc == 0) {
	    if (parameterSize > (uint32_t)size) {
		if (tssVerbose)	printf("TSS_GetRspAuths: Invalid response parameterSize %u\n",
				       parameterSize);
		rc = TSS_RC_MALFORMED_RESPONSE;
	    }
	}
	if (rc == 0) {
	    /* index past the response parameters to the authorization area */
	    buffer += parameterSize;
	    size -= parameterSize;
	}
	/* unmarshal the response authorization area */
	done = FALSE;
	va_start(ap, tssAuthContext);
	while ((rc == 0) && !done){
	    authResponse = va_arg(ap, TPMS_AUTH_RESPONSE *);
	    if (authResponse != NULL) {
		rc = TSS_TPMS_AUTH_RESPONSE_Unmarshalu(authResponse, &buffer, &size);
		authCount++;
	    }
	    else {
		done = TRUE;
	    }
	}
	va_end(ap);
	/* check for extra bytes at the end of the response */
	if (rc == 0) {
	    if (size != 0) {
		if (tssVerbose)
		    printf("TSS_GetRspAuths: Extra bytes at the end of response authorizations\n");
		rc = TSS_RC_MALFORMED_RESPONSE;
	    }
	}
    }
    /* check that the same number was requested as were sent in the command.  Check for zero if not
       TPM_ST_SESSIONS */
    if (rc == 0) {
	if (tssAuthContext->authCount != authCount) {
	    if (tssVerbose)
		printf("TSS_GetRspAuths: "
		       "Response authorizations requested does not equal number in command\n");
	    rc = TSS_RC_MALFORMED_RESPONSE;
	}
    }
    return rc;
}

/* TSS_GetCommandDecryptParam() returns the size and pointer to the first marshaled TPM2B */

TPM_RC TSS_GetCommandDecryptParam(TSS_AUTH_CONTEXT *tssAuthContext,
				  uint32_t *decryptParamSize,
				  uint8_t **decryptParamBuffer)
{
    TPM_RC 	rc = 0;
    /* the first parameter is the TPM2B */
    uint32_t cpBufferSize;
    uint8_t *cpBuffer;

    if (rc == 0) {
	rc = TSS_GetCpBuffer(tssAuthContext, &cpBufferSize, &cpBuffer);
    }
    /* extract contents of the first TPM2B */
    if (rc == 0) {
	*decryptParamSize = ntohs(*(uint16_t *)cpBuffer);
	*decryptParamBuffer = cpBuffer + sizeof(uint16_t);
    }
    /* sanity range check */
    if (rc == 0) {
	if (((*decryptParamBuffer + *decryptParamSize) >
	     (tssAuthContext->commandBuffer + tssAuthContext->commandSize)) ||
	    ((*decryptParamSize + sizeof(uint16_t) > tssAuthContext->cpBufferSize))) {
	    if (tssVerbose) printf("TSS_GetCommandDecryptParam: Malformed decrypt parameter "
				   "size %u cpBufferSize %u commandSize %u\n",
				   *decryptParamSize, tssAuthContext->cpBufferSize,
				   tssAuthContext->commandSize);
	    rc = TSS_RC_BAD_ENCRYPT_SIZE;
	}
    }
    return rc;
}

TPM_RC TSS_SetCommandDecryptParam(TSS_AUTH_CONTEXT *tssAuthContext,
				  uint32_t encryptParamSize,
				  uint8_t *encryptParamBuffer)
{
    TPM_RC 	rc = 0;
    /* the first parameter is the TPM2B */
    uint32_t decryptParamSize;
    uint8_t *decryptParamBuffer;

    if (rc == 0) {
	rc = TSS_GetCommandDecryptParam(tssAuthContext,
					&decryptParamSize,
					&decryptParamBuffer);
    }
    /* the encrypt data overwrites the already marshaled data */
    if (rc == 0) {
	if (decryptParamSize != encryptParamSize) {
	    if (tssVerbose)
		printf("TSS_SetCommandDecryptParam: Different encrypt and decrypt size\n");
	    rc = TSS_RC_BAD_ENCRYPT_SIZE;
	}
    }
    /* skip the 2B size, copy the data */
    if (rc == 0) {
	memcpy(decryptParamBuffer, encryptParamBuffer, encryptParamSize);
    }
    return rc;
}

/* TSS_GetAuthRole() returns AUTH_NONE if the handle in the handle area cannot be an authorization
   handle. */

AUTH_ROLE TSS_GetAuthRole(TSS_AUTH_CONTEXT *tssAuthContext,
			  size_t handleIndex)
{
    AUTH_ROLE authRole;
    authRole = getCommandAuthRole(tssAuthContext->tpmCommandIndex, handleIndex);
    return authRole;
}

/* TSS_GetCommandHandle() gets the command handle at the index.  Index is a zero based count, not a
   byte count.

   Returns 0 if the index exceeds the number of handles.
*/

TPM_RC TSS_GetCommandHandle(TSS_AUTH_CONTEXT *tssAuthContext,
			    TPM_HANDLE *commandHandle,
			    size_t index)
{
    TPM_RC 	rc = 0;
    uint8_t 	*buffer;
    uint32_t 	size;
   
    
    if (rc == 0) {
	if (index >= tssAuthContext->commandHandleCount) {
	    if (tssVerbose) printf("TSS_GetCommandHandle: index %u too large for command\n",
				   (unsigned int)index);
	    rc = TSS_RC_BAD_HANDLE_NUMBER;
	}
    }
    if (rc == 0) {
	/* index into the command handle */
	buffer = tssAuthContext->commandBuffer +
		 sizeof(TPMI_ST_COMMAND_TAG) + sizeof (uint32_t) + sizeof(TPM_CC) +
		 (sizeof(TPM_HANDLE) * index);
	size = sizeof(TPM_HANDLE);
	rc = TSS_TPM_HANDLE_Unmarshalu(commandHandle, &buffer, &size);
    }
    return rc;
}
    
/* TSS_GetRpBuffer() returns a pointer to the response parameter area.

   NOTE could move to execute so it only has to be done once.
*/

TPM_RC TSS_GetRpBuffer(TSS_AUTH_CONTEXT *tssAuthContext,
		       uint32_t *rpBufferSize,
		       uint8_t **rpBuffer)
{
    TPM_RC 	rc = 0;
    TPM_ST 	tag;			/* response tag */
    uint32_t 	offsetSize;		/* to beginning of parameter area, to parameterSize */
    uint32_t 	size;			/* tmp for unmarshal */
    uint8_t 	*buffer;		/* tmp for unmarshal */
    uint32_t 	parameterSize;		/* response parameter (if sessions) */
     
    /* unmarshal the response tag */
    if (rc == 0) {
	/* offset to parameterSize or parameters */
	offsetSize = sizeof(TPM_ST) + sizeof (uint32_t) + sizeof(TPM_RC) +
		     (sizeof(TPM_HANDLE) * tssAuthContext->responseHandleCount);

	size = tssAuthContext->responseSize;
  	buffer = tssAuthContext->responseBuffer;
	rc = TSS_TPM_ST_Unmarshalu(&tag, &buffer, &size);	/* does value checking */
    }
    /* no sessions -> no parameterSize */
    if (tag == TPM_ST_NO_SESSIONS) {
	if (rc == 0) {
	    if (offsetSize > tssAuthContext->responseSize) {
		if (tssVerbose)
		    printf("TSS_GetRpBuffer: offset %u past response buffer %u\n",
			   offsetSize, tssAuthContext->responseSize);
		rc = TSS_RC_MALFORMED_RESPONSE;
	    }
	}
	if (rc == 0) {			/* subtract now safe from above range check */
	    *rpBufferSize = tssAuthContext->responseSize - offsetSize;
	    *rpBuffer = tssAuthContext->responseBuffer + offsetSize;
	}
    }
    /* sessions -> parameterSize */
    else {
	/* validate that there are enough response bytes for uint32_t parameterSize */
	if (rc == 0) {
	    if ((offsetSize + sizeof(uint32_t)) > tssAuthContext->responseSize) {
		if (tssVerbose)
		    printf("TSS_GetRpBuffer: offset %u past response buffer %u\n",
			   offsetSize, tssAuthContext->responseSize);
		rc = TSS_RC_MALFORMED_RESPONSE;
	    }
	}
	/* unmarshal the parameterSize */
	if (rc == 0) {
	    size = tssAuthContext->responseSize - offsetSize;
	    buffer = tssAuthContext->responseBuffer + offsetSize;
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, &buffer, &size);
	    offsetSize += sizeof(uint32_t);	/* move offset past parameterSize, to rpBuffer */
	}
	/* range check parameterSize */
	/* first, check that addition willl not overflow */
	if (rc == 0) {
	    if (parameterSize > (0xffffffff - offsetSize)) {
		if (tssVerbose) printf("TSS_GetRpBuffer: parameterSize %u too large\n",
				       parameterSize);
		rc = TSS_RC_MALFORMED_RESPONSE;
	    }
	}
	/* second, range check parameterSize vs. entire response buffer */
	if (rc == 0) {
	    if ((offsetSize + parameterSize) > tssAuthContext->responseSize) {
		if (tssVerbose)
		    printf("TSS_GetRpBuffer: parameterSize %u past response buffer %u\n",
			   parameterSize, tssAuthContext->responseSize);
		rc = TSS_RC_MALFORMED_RESPONSE;
	    }
	}
	/* assignment safe after above checks */
	if (rc == 0) {
	    *rpBufferSize = parameterSize;	/* by definition when there are auth sessions */
	    *rpBuffer = tssAuthContext->responseBuffer + offsetSize;
	}
    }
    return rc;
}

/* TSS_GetResponseEncryptParam() returns the first TPM2B in the response area.

   The caller should ensure that the first response parameter is a TPM2B.
*/

TPM_RC TSS_GetResponseEncryptParam(TSS_AUTH_CONTEXT *tssAuthContext,
				   uint32_t *encryptParamSize,
				   uint8_t **encryptParamBuffer)
{
    TPM_RC 	rc = 0;
    /* the first parameter is the TPM2B */
    uint32_t rpBufferSize;
    uint8_t *rpBuffer;

    if (rc == 0) {
	rc = TSS_GetRpBuffer(tssAuthContext, &rpBufferSize, &rpBuffer);
    }
    /* extract contents of the first TPM2B */
    if (rc == 0) {
	*encryptParamSize = ntohs(*(uint16_t *)rpBuffer);
	*encryptParamBuffer = rpBuffer + sizeof(uint16_t);
    }
    /* sanity range check */
    if (rc == 0) {
	if (((*encryptParamBuffer + *encryptParamSize) >
	     (tssAuthContext->responseBuffer + tssAuthContext->responseSize)) ||
	    ((*encryptParamSize + sizeof(uint16_t) > rpBufferSize))) {
	    if (tssVerbose) printf("TSS_GetResponseEncryptParam: Malformed encrypt parameter "
				   "size %u rpBufferSize %u responseSize %u\n",
				   *encryptParamSize, rpBufferSize,
				   tssAuthContext->responseSize);
	    rc = TSS_RC_MALFORMED_RESPONSE;
	}
    }
    return rc;
}

/* TSS_SetResponseDecryptParam() copies the decryptParamBuffer into the first TPM2B in the response
   area.

   The caller should ensure that the first response parameter is a TPM2B.
*/

TPM_RC TSS_SetResponseDecryptParam(TSS_AUTH_CONTEXT *tssAuthContext,
				   uint32_t decryptParamSize,
				   uint8_t *decryptParamBuffer)
{
    TPM_RC 	rc = 0;
    /* the first parameter is the TPM2B */
    uint32_t encryptParamSize;
    uint8_t *encryptParamBuffer;

    if (rc == 0) {
	rc = TSS_GetResponseEncryptParam(tssAuthContext,
					 &encryptParamSize,
					 &encryptParamBuffer);
    }
    /* the decrypt data overwrites the already marshaled data */
    if (rc == 0) {
	if (decryptParamSize != encryptParamSize) {
	    if (tssVerbose)
		printf("TSS_SetCommandDecryptParam: Different encrypt and decrypt size\n");
	    rc = TSS_RC_BAD_ENCRYPT_SIZE;
	}
    }
    /* skip the 2B size, copy the data */
    if (rc == 0) {
	memcpy(encryptParamBuffer, decryptParamBuffer, decryptParamSize);
    }
    return rc;
}

