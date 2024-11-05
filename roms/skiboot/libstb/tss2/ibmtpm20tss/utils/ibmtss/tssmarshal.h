/********************************************************************************/
/*										*/
/*			 TSS Marshal and Unmarshal    				*/
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

/* This is a semi-public header. The API should be stable, but is less guaranteed.

   It is useful for applications that have to marshal / unmarshal
   structures for file save / load.
*/

#ifndef TSSMARSHAL_H
#define TSSMARSHAL_H

#include "BaseTypes.h"
#include <ibmtss/TPM_Types.h>

#include "ActivateCredential_fp.h"
#include "CertifyCreation_fp.h"
#include "CertifyX509_fp.h"
#include "Certify_fp.h"
#include "ChangeEPS_fp.h"
#include "ChangePPS_fp.h"
#include "ClearControl_fp.h"
#include "Clear_fp.h"
#include "ClockRateAdjust_fp.h"
#include "ClockSet_fp.h"
#include "Commit_fp.h"
#include "Commit_fp.h"
#include "ContextLoad_fp.h"
#include "ContextSave_fp.h"
#include "CreatePrimary_fp.h"
#include "Create_fp.h"
#include "CreateLoaded_fp.h"
#include "DictionaryAttackLockReset_fp.h"
#include "DictionaryAttackParameters_fp.h"
#include "Duplicate_fp.h"
#include "ECC_Parameters_fp.h"
#include "ECDH_KeyGen_fp.h"
#include "ECDH_ZGen_fp.h"
#include "EC_Ephemeral_fp.h"
#include "EncryptDecrypt_fp.h"
#include "EncryptDecrypt2_fp.h"
#include "EventSequenceComplete_fp.h"
#include "EvictControl_fp.h"
#include "FlushContext_fp.h"
#include "GetCapability_fp.h"
#include "GetCommandAuditDigest_fp.h"
#include "GetRandom_fp.h"
#include "GetSessionAuditDigest_fp.h"
#include "GetTestResult_fp.h"
#include "GetTime_fp.h"
#include "HMAC_Start_fp.h"
#include "HMAC_fp.h"
#include "HashSequenceStart_fp.h"
#include "Hash_fp.h"
#include "HierarchyChangeAuth_fp.h"
#include "HierarchyControl_fp.h"
#include "Import_fp.h"
#include "IncrementalSelfTest_fp.h"
#include "LoadExternal_fp.h"
#include "Load_fp.h"
#include "MakeCredential_fp.h"
#include "NV_Certify_fp.h"
#include "NV_ChangeAuth_fp.h"
#include "NV_DefineSpace_fp.h"
#include "NV_Extend_fp.h"
#include "NV_GlobalWriteLock_fp.h"
#include "NV_Increment_fp.h"
#include "NV_ReadLock_fp.h"
#include "NV_ReadPublic_fp.h"
#include "NV_Read_fp.h"
#include "NV_SetBits_fp.h"
#include "NV_UndefineSpaceSpecial_fp.h"
#include "NV_UndefineSpace_fp.h"
#include "NV_WriteLock_fp.h"
#include "NV_Write_fp.h"
#include "ObjectChangeAuth_fp.h"
#include "PCR_Allocate_fp.h"
#include "PCR_Event_fp.h"
#include "PCR_Extend_fp.h"
#include "PCR_Read_fp.h"
#include "PCR_Reset_fp.h"
#include "PCR_SetAuthPolicy_fp.h"
#include "PCR_SetAuthValue_fp.h"
#include "PP_Commands_fp.h"
#include "PolicyAuthValue_fp.h"
#include "PolicyAuthorize_fp.h"
#include "PolicyAuthorizeNV_fp.h"
#include "PolicyCommandCode_fp.h"
#include "PolicyCounterTimer_fp.h"
#include "PolicyCpHash_fp.h"
#include "PolicyDuplicationSelect_fp.h"
#include "PolicyGetDigest_fp.h"
#include "PolicyLocality_fp.h"
#include "PolicyNV_fp.h"
#include "PolicyAuthorizeNV_fp.h"
#include "PolicyNvWritten_fp.h"
#include "PolicyNameHash_fp.h"
#include "PolicyOR_fp.h"
#include "PolicyPCR_fp.h"
#include "PolicyPassword_fp.h"
#include "PolicyPhysicalPresence_fp.h"
#include "PolicyRestart_fp.h"
#include "PolicySecret_fp.h"
#include "PolicySigned_fp.h"
#include "PolicyTemplate_fp.h"
#include "PolicyTicket_fp.h"
#include "Quote_fp.h"
#include "RSA_Decrypt_fp.h"
#include "RSA_Encrypt_fp.h"
#include "ReadClock_fp.h"
#include "ReadPublic_fp.h"
#include "Rewrap_fp.h"
#include "SelfTest_fp.h"
#include "SequenceComplete_fp.h"
#include "SequenceUpdate_fp.h"
#include "SetAlgorithmSet_fp.h"
#include "SetCommandCodeAuditStatus_fp.h"
#include "SetPrimaryPolicy_fp.h"
#include "Shutdown_fp.h"
#include "Sign_fp.h"
#include "StartAuthSession_fp.h"
#include "Startup_fp.h"
#include "StirRandom_fp.h"
#include "TestParms_fp.h"
#include "Unseal_fp.h"
#include "VerifySignature_fp.h"
#include "ZGen_2Phase_fp.h"

#ifdef __cplusplus
extern "C" {
#endif

    /* Recommended functions */
    
    TPM_RC
    TSS_Startup_In_Marshalu(const Startup_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Shutdown_In_Marshalu(const Shutdown_In  *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_SelfTest_In_Marshalu(const SelfTest_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_IncrementalSelfTest_In_Marshalu(const IncrementalSelfTest_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_StartAuthSession_In_Marshalu(const StartAuthSession_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyRestart_In_Marshalu(const PolicyRestart_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Create_In_Marshalu(const Create_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Load_In_Marshalu(const Load_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_LoadExternal_In_Marshalu(const LoadExternal_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ReadPublic_In_Marshalu(const ReadPublic_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ActivateCredential_In_Marshalu(const ActivateCredential_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_MakeCredential_In_Marshalu(const MakeCredential_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Unseal_In_Marshalu(const Unseal_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ObjectChangeAuth_In_Marshalu(const ObjectChangeAuth_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CreateLoaded_In_Marshalu(const CreateLoaded_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Duplicate_In_Marshalu(const Duplicate_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Rewrap_In_Marshalu(const Rewrap_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Import_In_Marshalu(const Import_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_RSA_Encrypt_In_Marshalu(const RSA_Encrypt_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_RSA_Decrypt_In_Marshalu(const RSA_Decrypt_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ECDH_KeyGen_In_Marshalu(const ECDH_KeyGen_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ECDH_ZGen_In_Marshalu(const ECDH_ZGen_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ECC_Parameters_In_Marshalu(const ECC_Parameters_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ZGen_2Phase_In_Marshalu(const ZGen_2Phase_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_EncryptDecrypt_In_Marshalu(const EncryptDecrypt_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_EncryptDecrypt2_In_Marshalu(const EncryptDecrypt2_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Hash_In_Marshalu(const Hash_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_HMAC_In_Marshalu(const HMAC_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_GetRandom_In_Marshalu(const GetRandom_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_StirRandom_In_Marshalu(const StirRandom_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_HMAC_Start_In_Marshalu(const HMAC_Start_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_HashSequenceStart_In_Marshalu(const HashSequenceStart_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_SequenceUpdate_In_Marshalu(const SequenceUpdate_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_SequenceComplete_In_Marshalu(const SequenceComplete_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_EventSequenceComplete_In_Marshalu(const EventSequenceComplete_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Certify_In_Marshalu(const Certify_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CertifyCreation_In_Marshalu(const CertifyCreation_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CertifyX509_In_Marshalu(const CertifyX509_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Quote_In_Marshalu(const Quote_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_GetSessionAuditDigest_In_Marshalu(const GetSessionAuditDigest_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_GetCommandAuditDigest_In_Marshalu(const GetCommandAuditDigest_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_GetTime_In_Marshalu(const GetTime_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Commit_In_Marshalu(const Commit_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_EC_Ephemeral_In_Marshalu(const EC_Ephemeral_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_VerifySignature_In_Marshalu(const VerifySignature_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Sign_In_Marshalu(const Sign_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_SetCommandCodeAuditStatus_In_Marshalu(const SetCommandCodeAuditStatus_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PCR_Extend_In_Marshalu(const PCR_Extend_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PCR_Event_In_Marshalu(const PCR_Event_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PCR_Read_In_Marshalu(const PCR_Read_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PCR_Allocate_In_Marshalu(const PCR_Allocate_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PCR_SetAuthPolicy_In_Marshalu(const PCR_SetAuthPolicy_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PCR_SetAuthValue_In_Marshalu(const PCR_SetAuthValue_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PCR_Reset_In_Marshalu(const PCR_Reset_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicySigned_In_Marshalu(const PolicySigned_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicySecret_In_Marshalu(const PolicySecret_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyTicket_In_Marshalu(const PolicyTicket_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyOR_In_Marshalu(const PolicyOR_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyPCR_In_Marshalu(const PolicyPCR_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyLocality_In_Marshalu(const PolicyLocality_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyNV_In_Marshalu(const PolicyNV_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyAuthorizeNV_In_Marshalu(const PolicyAuthorizeNV_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyCounterTimer_In_Marshalu(const PolicyCounterTimer_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyCommandCode_In_Marshalu(const PolicyCommandCode_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyPhysicalPresence_In_Marshalu(const PolicyPhysicalPresence_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyCpHash_In_Marshalu(const PolicyCpHash_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyNameHash_In_Marshalu(const PolicyNameHash_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyDuplicationSelect_In_Marshalu(const PolicyDuplicationSelect_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyAuthorize_In_Marshalu(const PolicyAuthorize_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyAuthValue_In_Marshalu(const PolicyAuthValue_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyPassword_In_Marshalu(const PolicyPassword_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyGetDigest_In_Marshalu(const PolicyGetDigest_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyNvWritten_In_Marshalu(const PolicyNvWritten_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyTemplate_In_Marshalu(const PolicyTemplate_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CreatePrimary_In_Marshalu(const CreatePrimary_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_HierarchyControl_In_Marshalu(const HierarchyControl_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_SetPrimaryPolicy_In_Marshalu(const SetPrimaryPolicy_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ChangePPS_In_Marshalu(const ChangePPS_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ChangeEPS_In_Marshalu(const ChangeEPS_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Clear_In_Marshalu(const Clear_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ClearControl_In_Marshalu(const ClearControl_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_HierarchyChangeAuth_In_Marshalu(const HierarchyChangeAuth_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_DictionaryAttackLockReset_In_Marshalu(const DictionaryAttackLockReset_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_DictionaryAttackParameters_In_Marshalu(const DictionaryAttackParameters_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PP_Commands_In_Marshalu(const PP_Commands_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_SetAlgorithmSet_In_Marshalu(const SetAlgorithmSet_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ContextSave_In_Marshalu(const ContextSave_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ContextLoad_In_Marshalu(const ContextLoad_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_FlushContext_In_Marshalu(const FlushContext_In *source, UINT16 *written, BYTE **buffer, uint32_t *size) ;
    TPM_RC
    TSS_EvictControl_In_Marshalu(const EvictControl_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ClockSet_In_Marshalu(const ClockSet_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ClockRateAdjust_In_Marshalu(const ClockRateAdjust_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_GetCapability_In_Marshalu(const GetCapability_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TestParms_In_Marshalu(const TestParms_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_DefineSpace_In_Marshalu(const NV_DefineSpace_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_UndefineSpace_In_Marshalu(const NV_UndefineSpace_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_UndefineSpaceSpecial_In_Marshalu(const NV_UndefineSpaceSpecial_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_ReadPublic_In_Marshalu(const NV_ReadPublic_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_Write_In_Marshalu(const NV_Write_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_Increment_In_Marshalu(const NV_Increment_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_Extend_In_Marshalu(const NV_Extend_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_SetBits_In_Marshalu(const NV_SetBits_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_WriteLock_In_Marshalu(const NV_WriteLock_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_GlobalWriteLock_In_Marshalu(const NV_GlobalWriteLock_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_Read_In_Marshalu(const NV_Read_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_ReadLock_In_Marshalu(const NV_ReadLock_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_ChangeAuth_In_Marshalu(const NV_ChangeAuth_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_Certify_In_Marshalu(const NV_Certify_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);

    /* Deprecated functions */
    
    TPM_RC
    TSS_Startup_In_Marshal(const Startup_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Shutdown_In_Marshal(const Shutdown_In  *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_SelfTest_In_Marshal(const SelfTest_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_IncrementalSelfTest_In_Marshal(const IncrementalSelfTest_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_StartAuthSession_In_Marshal(const StartAuthSession_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyRestart_In_Marshal(const PolicyRestart_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Create_In_Marshal(const Create_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Load_In_Marshal(const Load_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_LoadExternal_In_Marshal(const LoadExternal_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ReadPublic_In_Marshal(const ReadPublic_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ActivateCredential_In_Marshal(const ActivateCredential_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_MakeCredential_In_Marshal(const MakeCredential_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Unseal_In_Marshal(const Unseal_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ObjectChangeAuth_In_Marshal(const ObjectChangeAuth_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_CreateLoaded_In_Marshal(const CreateLoaded_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Duplicate_In_Marshal(const Duplicate_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Rewrap_In_Marshal(const Rewrap_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Import_In_Marshal(const Import_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_RSA_Encrypt_In_Marshal(const RSA_Encrypt_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_RSA_Decrypt_In_Marshal(const RSA_Decrypt_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ECDH_KeyGen_In_Marshal(const ECDH_KeyGen_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ECDH_ZGen_In_Marshal(const ECDH_ZGen_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ECC_Parameters_In_Marshal(const ECC_Parameters_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ZGen_2Phase_In_Marshal(const ZGen_2Phase_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_EncryptDecrypt_In_Marshal(const EncryptDecrypt_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_EncryptDecrypt2_In_Marshal(const EncryptDecrypt2_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Hash_In_Marshal(const Hash_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_HMAC_In_Marshal(const HMAC_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_GetRandom_In_Marshal(const GetRandom_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_StirRandom_In_Marshal(const StirRandom_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_HMAC_Start_In_Marshal(const HMAC_Start_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_HashSequenceStart_In_Marshal(const HashSequenceStart_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_SequenceUpdate_In_Marshal(const SequenceUpdate_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_SequenceComplete_In_Marshal(const SequenceComplete_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_EventSequenceComplete_In_Marshal(const EventSequenceComplete_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Certify_In_Marshal(const Certify_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_CertifyCreation_In_Marshal(const CertifyCreation_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_CertifyX509_In_Marshal(const CertifyX509_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Quote_In_Marshal(const Quote_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_GetSessionAuditDigest_In_Marshal(const GetSessionAuditDigest_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_GetCommandAuditDigest_In_Marshal(const GetCommandAuditDigest_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_GetTime_In_Marshal(const GetTime_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Commit_In_Marshal(const Commit_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_EC_Ephemeral_In_Marshal(const EC_Ephemeral_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_VerifySignature_In_Marshal(const VerifySignature_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Sign_In_Marshal(const Sign_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_SetCommandCodeAuditStatus_In_Marshal(const SetCommandCodeAuditStatus_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PCR_Extend_In_Marshal(const PCR_Extend_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PCR_Event_In_Marshal(const PCR_Event_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PCR_Read_In_Marshal(const PCR_Read_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PCR_Allocate_In_Marshal(const PCR_Allocate_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PCR_SetAuthPolicy_In_Marshal(const PCR_SetAuthPolicy_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PCR_SetAuthValue_In_Marshal(const PCR_SetAuthValue_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PCR_Reset_In_Marshal(const PCR_Reset_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicySigned_In_Marshal(const PolicySigned_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicySecret_In_Marshal(const PolicySecret_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyTicket_In_Marshal(const PolicyTicket_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyOR_In_Marshal(const PolicyOR_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyPCR_In_Marshal(const PolicyPCR_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyLocality_In_Marshal(const PolicyLocality_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyNV_In_Marshal(const PolicyNV_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyAuthorizeNV_In_Marshal(const PolicyAuthorizeNV_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyCounterTimer_In_Marshal(const PolicyCounterTimer_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyCommandCode_In_Marshal(const PolicyCommandCode_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyPhysicalPresence_In_Marshal(const PolicyPhysicalPresence_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyCpHash_In_Marshal(const PolicyCpHash_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyNameHash_In_Marshal(const PolicyNameHash_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyDuplicationSelect_In_Marshal(const PolicyDuplicationSelect_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyAuthorize_In_Marshal(const PolicyAuthorize_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyAuthValue_In_Marshal(const PolicyAuthValue_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyPassword_In_Marshal(const PolicyPassword_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyGetDigest_In_Marshal(const PolicyGetDigest_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyNvWritten_In_Marshal(const PolicyNvWritten_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyTemplate_In_Marshal(const PolicyTemplate_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_CreatePrimary_In_Marshal(const CreatePrimary_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_HierarchyControl_In_Marshal(const HierarchyControl_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_SetPrimaryPolicy_In_Marshal(const SetPrimaryPolicy_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ChangePPS_In_Marshal(const ChangePPS_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ChangeEPS_In_Marshal(const ChangeEPS_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Clear_In_Marshal(const Clear_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ClearControl_In_Marshal(const ClearControl_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_HierarchyChangeAuth_In_Marshal(const HierarchyChangeAuth_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_DictionaryAttackLockReset_In_Marshal(const DictionaryAttackLockReset_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_DictionaryAttackParameters_In_Marshal(const DictionaryAttackParameters_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PP_Commands_In_Marshal(const PP_Commands_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_SetAlgorithmSet_In_Marshal(const SetAlgorithmSet_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ContextSave_In_Marshal(const ContextSave_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ContextLoad_In_Marshal(const ContextLoad_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_FlushContext_In_Marshal(const FlushContext_In *source, UINT16 *written, BYTE **buffer, INT32 *size) ;
    TPM_RC
    TSS_EvictControl_In_Marshal(const EvictControl_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ClockSet_In_Marshal(const ClockSet_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ClockRateAdjust_In_Marshal(const ClockRateAdjust_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_GetCapability_In_Marshal(const GetCapability_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_TestParms_In_Marshal(const TestParms_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_DefineSpace_In_Marshal(const NV_DefineSpace_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_UndefineSpace_In_Marshal(const NV_UndefineSpace_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_UndefineSpaceSpecial_In_Marshal(const NV_UndefineSpaceSpecial_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_ReadPublic_In_Marshal(const NV_ReadPublic_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_Write_In_Marshal(const NV_Write_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_Increment_In_Marshal(const NV_Increment_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_Extend_In_Marshal(const NV_Extend_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_SetBits_In_Marshal(const NV_SetBits_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_WriteLock_In_Marshal(const NV_WriteLock_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_GlobalWriteLock_In_Marshal(const NV_GlobalWriteLock_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_Read_In_Marshal(const NV_Read_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_ReadLock_In_Marshal(const NV_ReadLock_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_ChangeAuth_In_Marshal(const NV_ChangeAuth_In *source, UINT16 *written, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_Certify_In_Marshal(const NV_Certify_In *source, UINT16 *written, BYTE **buffer, INT32 *size);

    /* Recommended functions */
    
    TPM_RC
    TSS_IncrementalSelfTest_Out_Unmarshalu(IncrementalSelfTest_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_GetTestResult_Out_Unmarshalu(GetTestResult_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_StartAuthSession_Out_Unmarshalu(StartAuthSession_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Create_Out_Unmarshalu(Create_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Load_Out_Unmarshalu(Load_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_LoadExternal_Out_Unmarshalu(LoadExternal_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ReadPublic_Out_Unmarshalu(ReadPublic_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ActivateCredential_Out_Unmarshalu(ActivateCredential_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_MakeCredential_Out_Unmarshalu(MakeCredential_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Unseal_Out_Unmarshalu(Unseal_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ObjectChangeAuth_Out_Unmarshalu(ObjectChangeAuth_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CreateLoaded_Out_Unmarshalu(CreateLoaded_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Duplicate_Out_Unmarshalu(Duplicate_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Rewrap_Out_Unmarshalu(Rewrap_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Import_Out_Unmarshalu(Import_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_RSA_Encrypt_Out_Unmarshalu(RSA_Encrypt_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_RSA_Decrypt_Out_Unmarshalu(RSA_Decrypt_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ECDH_KeyGen_Out_Unmarshalu(ECDH_KeyGen_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ECDH_ZGen_Out_Unmarshalu(ECDH_ZGen_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ECC_Parameters_Out_Unmarshalu(ECC_Parameters_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ZGen_2Phase_Out_Unmarshalu(ZGen_2Phase_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_EncryptDecrypt_Out_Unmarshalu(EncryptDecrypt_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_EncryptDecrypt2_Out_Unmarshalu(EncryptDecrypt2_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Hash_Out_Unmarshalu(Hash_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_HMAC_Out_Unmarshalu(HMAC_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_GetRandom_Out_Unmarshalu(GetRandom_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_HMAC_Start_Out_Unmarshalu(HMAC_Start_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_HashSequenceStart_Out_Unmarshalu(HashSequenceStart_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_SequenceComplete_Out_Unmarshalu(SequenceComplete_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_EventSequenceComplete_Out_Unmarshalu(EventSequenceComplete_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Certify_Out_Unmarshalu(Certify_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CertifyCreation_Out_Unmarshalu(CertifyCreation_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CertifyX509_Out_Unmarshalu(CertifyX509_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Quote_Out_Unmarshalu(Quote_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_GetSessionAuditDigest_Out_Unmarshalu(GetSessionAuditDigest_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_GetCommandAuditDigest_Out_Unmarshalu(GetCommandAuditDigest_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_GetTime_Out_Unmarshalu(GetTime_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Commit_Out_Unmarshalu(Commit_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_EC_Ephemeral_Out_Unmarshalu(EC_Ephemeral_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_VerifySignature_Out_Unmarshalu(VerifySignature_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Sign_Out_Unmarshalu(Sign_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PCR_Event_Out_Unmarshalu(PCR_Event_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PCR_Read_Out_Unmarshalu(PCR_Read_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PCR_Allocate_Out_Unmarshalu(PCR_Allocate_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicySigned_Out_Unmarshalu(PolicySigned_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicySecret_Out_Unmarshalu(PolicySecret_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PolicyGetDigest_Out_Unmarshalu(PolicyGetDigest_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CreatePrimary_Out_Unmarshalu(CreatePrimary_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ContextSave_Out_Unmarshalu(ContextSave_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ContextLoad_Out_Unmarshalu(ContextLoad_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ReadClock_Out_Unmarshalu(ReadClock_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_GetCapability_Out_Unmarshalu(GetCapability_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_ReadPublic_Out_Unmarshalu(NV_ReadPublic_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_Read_Out_Unmarshalu(NV_Read_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_Certify_Out_Unmarshalu(NV_Certify_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);

    /* Deprecated functions */
    
    TPM_RC
    TSS_IncrementalSelfTest_Out_Unmarshal(IncrementalSelfTest_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_GetTestResult_Out_Unmarshal(GetTestResult_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_StartAuthSession_Out_Unmarshal(StartAuthSession_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Create_Out_Unmarshal(Create_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Load_Out_Unmarshal(Load_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_LoadExternal_Out_Unmarshal(LoadExternal_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ReadPublic_Out_Unmarshal(ReadPublic_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ActivateCredential_Out_Unmarshal(ActivateCredential_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_MakeCredential_Out_Unmarshal(MakeCredential_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Unseal_Out_Unmarshal(Unseal_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ObjectChangeAuth_Out_Unmarshal(ObjectChangeAuth_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_CreateLoaded_Out_Unmarshal(CreateLoaded_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Duplicate_Out_Unmarshal(Duplicate_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Rewrap_Out_Unmarshal(Rewrap_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Import_Out_Unmarshal(Import_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_RSA_Encrypt_Out_Unmarshal(RSA_Encrypt_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_RSA_Decrypt_Out_Unmarshal(RSA_Decrypt_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ECDH_KeyGen_Out_Unmarshal(ECDH_KeyGen_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ECDH_ZGen_Out_Unmarshal(ECDH_ZGen_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ECC_Parameters_Out_Unmarshal(ECC_Parameters_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ZGen_2Phase_Out_Unmarshal(ZGen_2Phase_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_EncryptDecrypt_Out_Unmarshal(EncryptDecrypt_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_EncryptDecrypt2_Out_Unmarshal(EncryptDecrypt2_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Hash_Out_Unmarshal(Hash_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_HMAC_Out_Unmarshal(HMAC_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_GetRandom_Out_Unmarshal(GetRandom_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_HMAC_Start_Out_Unmarshal(HMAC_Start_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_HashSequenceStart_Out_Unmarshal(HashSequenceStart_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_SequenceComplete_Out_Unmarshal(SequenceComplete_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_EventSequenceComplete_Out_Unmarshal(EventSequenceComplete_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Certify_Out_Unmarshal(Certify_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_CertifyCreation_Out_Unmarshal(CertifyCreation_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Quote_Out_Unmarshal(Quote_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_GetSessionAuditDigest_Out_Unmarshal(GetSessionAuditDigest_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_GetCommandAuditDigest_Out_Unmarshal(GetCommandAuditDigest_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_GetTime_Out_Unmarshal(GetTime_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Commit_Out_Unmarshal(Commit_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_EC_Ephemeral_Out_Unmarshal(EC_Ephemeral_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_VerifySignature_Out_Unmarshal(VerifySignature_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_Sign_Out_Unmarshal(Sign_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PCR_Event_Out_Unmarshal(PCR_Event_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PCR_Read_Out_Unmarshal(PCR_Read_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PCR_Allocate_Out_Unmarshal(PCR_Allocate_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicySigned_Out_Unmarshal(PolicySigned_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicySecret_Out_Unmarshal(PolicySecret_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_PolicyGetDigest_Out_Unmarshal(PolicyGetDigest_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_CreatePrimary_Out_Unmarshal(CreatePrimary_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ContextSave_Out_Unmarshal(ContextSave_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ContextLoad_Out_Unmarshal(ContextLoad_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_ReadClock_Out_Unmarshal(ReadClock_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_GetCapability_Out_Unmarshal(GetCapability_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_ReadPublic_Out_Unmarshal(NV_ReadPublic_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_Read_Out_Unmarshal(NV_Read_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);
    TPM_RC
    TSS_NV_Certify_Out_Unmarshal(NV_Certify_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size);

    /* Recommended functions */
    
    LIB_EXPORT TPM_RC
    TSS_UINT8_Marshalu(const UINT8 *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_INT8_Marshalu(const INT8 *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_UINT16_Marshalu(const UINT16 *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_UINT32_Marshalu(const uint32_t *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_INT32_Marshalu(const INT32 *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_UINT64_Marshalu(const UINT64 *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_Array_Marshalu(const BYTE *source, UINT16 sourceSize, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_Marshalu(const TPM2B *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_KEY_BITS_Marshalu(const TPM_KEY_BITS *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_GENERATED_Marshalu(const TPM_GENERATED *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_ALG_ID_Marshalu(const TPM_ALG_ID *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_ECC_CURVE_Marshalu(const TPM_ECC_CURVE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_RC_Marshalu(const TPM_RC *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_CLOCK_ADJUST_Marshalu(const TPM_CLOCK_ADJUST *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_EO_Marshalu(const TPM_EO *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_ST_Marshalu(const TPM_ST *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_SU_Marshalu(const TPM_ST *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_SE_Marshalu(const TPM_SE  *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_CAP_Marshalu(const TPM_CAP *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_PT_Marshalu(const TPM_PT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_PT_PCR_Marshalu(const TPM_PT_PCR *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_HANDLE_Marshalu(const TPM_HANDLE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_ALGORITHM_Marshalu(const TPMA_ALGORITHM *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_OBJECT_Marshalu(const TPMA_OBJECT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_SESSION_Marshalu(const TPMA_SESSION *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_LOCALITY_Marshalu(const TPMA_LOCALITY *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_CC_Marshalu(const TPM_CC *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_CC_Marshalu(const TPMA_CC *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_YES_NO_Marshalu(const TPMI_YES_NO *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_OBJECT_Marshalu(const TPMI_DH_OBJECT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_PERSISTENT_Marshalu(const TPMI_DH_PERSISTENT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_ENTITY_Marshalu(const TPMI_DH_ENTITY *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_PCR_Marshalu(const TPMI_DH_PCR  *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_SH_AUTH_SESSION_Marshalu(const TPMI_SH_AUTH_SESSION *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_SH_HMAC_Marshalu(const TPMI_SH_HMAC *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_SH_POLICY_Marshalu(const TPMI_SH_POLICY*source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_CONTEXT_Marshalu(const TPMI_DH_CONTEXT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_SAVED_Marshalu(const TPMI_DH_SAVED *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_HIERARCHY_Marshalu(const TPMI_RH_HIERARCHY *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_ENABLES_Marshalu(const TPMI_RH_ENABLES *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_HIERARCHY_AUTH_Marshalu(const TPMI_RH_HIERARCHY_AUTH *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_HIERARCHY_POLICY_Marshalu(const TPMI_RH_HIERARCHY_POLICY *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_PLATFORM_Marshalu(const TPMI_RH_PLATFORM *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_ENDORSEMENT_Marshalu(const TPMI_RH_ENDORSEMENT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_PROVISION_Marshalu(const TPMI_RH_PROVISION *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_CLEAR_Marshalu(const TPMI_RH_CLEAR *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_NV_AUTH_Marshalu(const TPMI_RH_NV_AUTH *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_LOCKOUT_Marshalu(const TPMI_RH_LOCKOUT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_NV_INDEX_Marshalu(const TPMI_RH_NV_INDEX *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_HASH_Marshalu(const TPMI_ALG_HASH *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_SYM_Marshalu(const TPMI_ALG_SYM *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_SYM_OBJECT_Marshalu(const TPMI_ALG_SYM_OBJECT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_SYM_MODE_Marshalu(const TPMI_ALG_SYM_MODE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_KDF_Marshalu(const TPMI_ALG_KDF *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_SIG_SCHEME_Marshalu(const TPMI_ALG_SIG_SCHEME *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ECC_KEY_EXCHANGE_Marshalu(const TPMI_ECC_KEY_EXCHANGE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ST_COMMAND_TAG_Marshalu(const TPMI_ST_COMMAND_TAG *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_MAC_SCHEME_Marshalu(const TPMI_ALG_MAC_SCHEME *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_CIPHER_MODE_Marshalu(const TPMI_ALG_CIPHER_MODE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_HA_Marshalu(const TPMU_HA *source, UINT16 *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_HA_Marshalu(const TPMT_HA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_DIGEST_Marshalu(const TPM2B_DIGEST *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_DATA_Marshalu(const TPM2B_DATA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_NONCE_Marshalu(const TPM2B_NONCE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_AUTH_Marshalu(const TPM2B_AUTH *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_OPERAND_Marshalu(const TPM2B_OPERAND *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_EVENT_Marshalu(const TPM2B_EVENT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_MAX_BUFFER_Marshalu(const TPM2B_MAX_BUFFER *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_MAX_NV_BUFFER_Marshalu(const TPM2B_MAX_NV_BUFFER *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_TIMEOUT_Marshalu(const TPM2B_TIMEOUT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_IV_Marshalu(const TPM2B_IV *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_NAME_Marshalu(const TPM2B_NAME *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_PCR_SELECTION_Marshalu(const TPMS_PCR_SELECTION *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_TK_CREATION_Marshalu(const TPMT_TK_CREATION *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_TK_VERIFIED_Marshalu(const TPMT_TK_VERIFIED *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_TK_AUTH_Marshalu(const TPMT_TK_AUTH *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_TK_HASHCHECK_Marshalu(const TPMT_TK_HASHCHECK *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ALG_PROPERTY_Marshalu(const TPMS_ALG_PROPERTY *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_TAGGED_PROPERTY_Marshalu(const TPMS_TAGGED_PROPERTY *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_TAGGED_PCR_SELECT_Marshalu(const TPMS_TAGGED_PCR_SELECT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_CC_Marshalu(const TPML_CC *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_CCA_Marshalu(const TPML_CCA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_ALG_Marshalu(const TPML_ALG *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_HANDLE_Marshalu(const TPML_HANDLE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_DIGEST_Marshalu(const TPML_DIGEST *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_DIGEST_VALUES_Marshalu(const TPML_DIGEST_VALUES *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_PCR_SELECTION_Marshalu(const TPML_PCR_SELECTION *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_ALG_PROPERTY_Marshalu(const TPML_ALG_PROPERTY *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_TAGGED_TPM_PROPERTY_Marshalu(const TPML_TAGGED_TPM_PROPERTY *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_TAGGED_PCR_PROPERTY_Marshalu(const TPML_TAGGED_PCR_PROPERTY *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_ECC_CURVE_Marshalu(const TPML_ECC_CURVE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_CAPABILITIES_Marshalu(const TPMU_CAPABILITIES *source, UINT16 *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CAPABILITY_DATA_Marshalu(const TPMS_CAPABILITY_DATA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CLOCK_INFO_Marshalu(const TPMS_CLOCK_INFO *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_TIME_INFO_Marshalu(const TPMS_TIME_INFO *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_TIME_ATTEST_INFO_Marshalu(const TPMS_TIME_ATTEST_INFO *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CERTIFY_INFO_Marshalu(const TPMS_CERTIFY_INFO *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_QUOTE_INFO_Marshalu(const TPMS_QUOTE_INFO *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_COMMAND_AUDIT_INFO_Marshalu(const TPMS_COMMAND_AUDIT_INFO *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SESSION_AUDIT_INFO_Marshalu(const TPMS_SESSION_AUDIT_INFO *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CREATION_INFO_Marshalu(const TPMS_CREATION_INFO *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_NV_CERTIFY_INFO_Marshalu(const TPMS_NV_CERTIFY_INFO *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ST_ATTEST_Marshalu(const TPMI_ST_ATTEST *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_ATTEST_Marshalu(const TPMU_ATTEST  *source, UINT16 *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ATTEST_Marshalu(const TPMS_ATTEST  *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_ATTEST_Marshalu(const TPM2B_ATTEST *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_AUTH_COMMAND_Marshalu(const TPMS_AUTH_COMMAND *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_AES_KEY_BITS_Marshalu(const TPMI_AES_KEY_BITS *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SYM_KEY_BITS_Marshalu(const TPMU_SYM_KEY_BITS *source, UINT16 *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SYM_MODE_Marshalu(const TPMU_SYM_MODE *source, UINT16 *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_SYM_DEF_Marshalu(const TPMT_SYM_DEF *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_SYM_DEF_OBJECT_Marshalu(const TPMT_SYM_DEF_OBJECT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_SYM_KEY_Marshalu(const TPM2B_SYM_KEY *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_LABEL_Marshalu(const TPM2B_LABEL *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_DERIVE_Marshalu(const TPMS_DERIVE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SYMCIPHER_PARMS_Marshalu(const TPMS_SYMCIPHER_PARMS *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_SENSITIVE_DATA_Marshalu(const TPM2B_SENSITIVE_DATA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SENSITIVE_CREATE_Marshalu(const TPMS_SENSITIVE_CREATE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_SENSITIVE_CREATE_Marshalu(const TPM2B_SENSITIVE_CREATE  *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_HASH_Marshalu(const TPMS_SCHEME_HASH *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_ECDAA_Marshalu(const TPMS_SCHEME_ECDAA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_KEYEDHASH_SCHEME_Marshalu(const TPMI_ALG_KEYEDHASH_SCHEME *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_HMAC_Marshalu(const TPMS_SCHEME_HMAC *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_XOR_Marshalu(const TPMS_SCHEME_XOR *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SCHEME_KEYEDHASH_Marshalu(const TPMU_SCHEME_KEYEDHASH *source, UINT16 *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_KEYEDHASH_SCHEME_Marshalu(const TPMT_KEYEDHASH_SCHEME *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_RSASSA_Marshalu(const TPMS_SIG_SCHEME_RSASSA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_RSAPSS_Marshalu(const TPMS_SIG_SCHEME_RSAPSS *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_ECDSA_Marshalu(const TPMS_SIG_SCHEME_ECDSA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_SM2_Marshalu(const TPMS_SIG_SCHEME_SM2 *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_ECSCHNORR_Marshalu(const TPMS_SIG_SCHEME_ECSCHNORR *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_ECDAA_Marshalu(const TPMS_SIG_SCHEME_ECDAA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SIG_SCHEME_Marshalu(const TPMU_SIG_SCHEME *source, UINT16 *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_SIG_SCHEME_Marshalu(const TPMT_SIG_SCHEME *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ENC_SCHEME_OAEP_Marshalu(const TPMS_ENC_SCHEME_OAEP *source, UINT16 *written, BYTE **buffer, uint32_t *size)
#ifdef __ULTRAVISOR__
	__attribute__ ((const))
#endif
	;
    LIB_EXPORT TPM_RC
    TSS_TPMS_ENC_SCHEME_RSAES_Marshalu(const TPMS_ENC_SCHEME_RSAES *source, UINT16 *written, BYTE **buffer, uint32_t *size)
#ifdef __ULTRAVISOR__
	__attribute__ ((const))
#endif
	;
    LIB_EXPORT TPM_RC
    TSS_TPMS_KEY_SCHEME_ECDH_Marshalu(const TPMS_KEY_SCHEME_ECDH *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_KEY_SCHEME_ECMQV_Marshalu(const TPMS_KEY_SCHEME_ECMQV *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_MGF1_Marshalu(const TPMS_SCHEME_MGF1 *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_KDF1_SP800_56A_Marshalu(const TPMS_SCHEME_KDF1_SP800_56A *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_KDF2_Marshalu(const TPMS_SCHEME_KDF2 *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_KDF1_SP800_108_Marshalu(const TPMS_SCHEME_KDF1_SP800_108 *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_KDF_SCHEME_Marshalu(const TPMU_KDF_SCHEME *source, UINT16 *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_KDF_SCHEME_Marshalu(const TPMT_KDF_SCHEME *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_ASYM_SCHEME_Marshalu(const TPMU_ASYM_SCHEME  *source, UINT16 *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_RSA_SCHEME_Marshalu(const TPMI_ALG_RSA_SCHEME *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_RSA_SCHEME_Marshalu(const TPMT_RSA_SCHEME *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_RSA_DECRYPT_Marshalu(const TPMI_ALG_RSA_DECRYPT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_RSA_DECRYPT_Marshalu(const TPMT_RSA_DECRYPT  *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_PUBLIC_KEY_RSA_Marshalu(const TPM2B_PUBLIC_KEY_RSA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RSA_KEY_BITS_Marshalu(const TPMI_RSA_KEY_BITS *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_PRIVATE_KEY_RSA_Marshalu(const TPM2B_PRIVATE_KEY_RSA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_ECC_PARAMETER_Marshalu(const TPM2B_ECC_PARAMETER *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ECC_POINT_Marshalu(const TPMS_ECC_POINT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_ECC_POINT_Marshalu(const TPM2B_ECC_POINT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_ECC_SCHEME_Marshalu(const TPMI_ALG_ECC_SCHEME *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ECC_CURVE_Marshalu(const TPMI_ECC_CURVE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_ECC_SCHEME_Marshalu(const TPMT_ECC_SCHEME *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ALGORITHM_DETAIL_ECC_Marshalu(const TPMS_ALGORITHM_DETAIL_ECC *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_RSA_Marshalu(const TPMS_SIGNATURE_RSA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_RSASSA_Marshalu(const TPMS_SIGNATURE_RSASSA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_RSAPSS_Marshalu(const TPMS_SIGNATURE_RSAPSS *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_ECC_Marshalu(const TPMS_SIGNATURE_ECC *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_ECDSA_Marshalu(const TPMS_SIGNATURE_ECDSA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_ECDAA_Marshalu(const TPMS_SIGNATURE_ECDAA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_SM2_Marshalu(const TPMS_SIGNATURE_SM2 *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_ECSCHNORR_Marshalu(const TPMS_SIGNATURE_ECSCHNORR *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SIGNATURE_Marshalu(const TPMU_SIGNATURE *source, UINT16 *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_SIGNATURE_Marshalu(const TPMT_SIGNATURE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_ENCRYPTED_SECRET_Marshalu(const TPM2B_ENCRYPTED_SECRET *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_PUBLIC_Marshalu(const TPMI_ALG_PUBLIC *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_PUBLIC_ID_Marshalu(const TPMU_PUBLIC_ID *source, UINT16 *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    LIB_EXPORT TPM_RC
    TSS_TPMS_KEYEDHASH_PARMS_Marshalu(const TPMS_KEYEDHASH_PARMS *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_RSA_PARMS_Marshalu(const TPMS_RSA_PARMS *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ECC_PARMS_Marshalu(const TPMS_ECC_PARMS *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_PUBLIC_PARMS_Marshalu(const TPMU_PUBLIC_PARMS *source, UINT16 *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_PUBLIC_PARMS_Marshalu(const TPMT_PUBLIC_PARMS *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_PUBLIC_Marshalu(const TPMT_PUBLIC *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_PUBLIC_D_Marshalu(const TPMT_PUBLIC *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_PUBLIC_Marshalu(const TPM2B_PUBLIC *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_TEMPLATE_Marshalu(const TPM2B_TEMPLATE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SENSITIVE_COMPOSITE_Marshalu(const TPMU_SENSITIVE_COMPOSITE *source, UINT16 *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_SENSITIVE_Marshalu(const TPMT_SENSITIVE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_SENSITIVE_Marshalu(const TPM2B_SENSITIVE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_PRIVATE_Marshalu(const TPM2B_PRIVATE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_ID_OBJECT_Marshalu(const TPM2B_ID_OBJECT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_NV_Marshalu(const TPMA_NV *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_NV_PUBLIC_Marshalu(const TPMS_NV_PUBLIC *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_NV_PUBLIC_Marshalu(const TPM2B_NV_PUBLIC *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_CONTEXT_SENSITIVE_Marshalu(const TPM2B_CONTEXT_SENSITIVE *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_CONTEXT_DATA_Marshalu(const TPM2B_CONTEXT_DATA  *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CONTEXT_Marshalu(const TPMS_CONTEXT *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CREATION_DATA_Marshalu(const TPMS_CREATION_DATA *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_CREATION_DATA_Marshalu(const TPM2B_CREATION_DATA *source, UINT16 *written, BYTE **buffer, uint32_t *size);

    /* Deprecated functions */
    
    LIB_EXPORT TPM_RC
    TSS_UINT8_Marshal(const UINT8 *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_INT8_Marshal(const INT8 *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_UINT16_Marshal(const UINT16 *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_UINT32_Marshal(const UINT32 *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_INT32_Marshal(const INT32 *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_UINT64_Marshal(const UINT64 *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_Array_Marshal(const BYTE *source, UINT16 sourceSize, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_Marshal(const TPM2B *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_KEY_BITS_Marshal(const TPM_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_GENERATED_Marshal(const TPM_GENERATED *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_ALG_ID_Marshal(const TPM_ALG_ID *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_ECC_CURVE_Marshal(const TPM_ECC_CURVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_RC_Marshal(const TPM_RC *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_CLOCK_ADJUST_Marshal(const TPM_CLOCK_ADJUST *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_EO_Marshal(const TPM_EO *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_ST_Marshal(const TPM_ST *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_SU_Marshal(const TPM_ST *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_SE_Marshal(const TPM_SE  *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_CAP_Marshal(const TPM_CAP *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_PT_Marshal(const TPM_PT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_PT_PCR_Marshal(const TPM_PT_PCR *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_HANDLE_Marshal(const TPM_HANDLE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_ALGORITHM_Marshal(const TPMA_ALGORITHM *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_OBJECT_Marshal(const TPMA_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_SESSION_Marshal(const TPMA_SESSION *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_LOCALITY_Marshal(const TPMA_LOCALITY *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_CC_Marshal(const TPM_CC *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_CC_Marshal(const TPMA_CC *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_YES_NO_Marshal(const TPMI_YES_NO *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_OBJECT_Marshal(const TPMI_DH_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_PERSISTENT_Marshal(const TPMI_DH_PERSISTENT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_ENTITY_Marshal(const TPMI_DH_ENTITY *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_PCR_Marshal(const TPMI_DH_PCR  *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_SH_AUTH_SESSION_Marshal(const TPMI_SH_AUTH_SESSION *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_SH_HMAC_Marshal(const TPMI_SH_HMAC *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_SH_POLICY_Marshal(const TPMI_SH_POLICY*source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_CONTEXT_Marshal(const TPMI_DH_CONTEXT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_HIERARCHY_Marshal(const TPMI_RH_HIERARCHY *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_ENABLES_Marshal(const TPMI_RH_ENABLES *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_HIERARCHY_AUTH_Marshal(const TPMI_RH_HIERARCHY_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_PLATFORM_Marshal(const TPMI_RH_PLATFORM *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_ENDORSEMENT_Marshal(const TPMI_RH_ENDORSEMENT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_PROVISION_Marshal(const TPMI_RH_PROVISION *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_CLEAR_Marshal(const TPMI_RH_CLEAR *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_NV_AUTH_Marshal(const TPMI_RH_NV_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_LOCKOUT_Marshal(const TPMI_RH_LOCKOUT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_NV_INDEX_Marshal(const TPMI_RH_NV_INDEX *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_HASH_Marshal(const TPMI_ALG_HASH *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_SYM_Marshal(const TPMI_ALG_SYM *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_SYM_OBJECT_Marshal(const TPMI_ALG_SYM_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_SYM_MODE_Marshal(const TPMI_ALG_SYM_MODE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_KDF_Marshal(const TPMI_ALG_KDF *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_SIG_SCHEME_Marshal(const TPMI_ALG_SIG_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ECC_KEY_EXCHANGE_Marshal(const TPMI_ECC_KEY_EXCHANGE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ST_COMMAND_TAG_Marshal(const TPMI_ST_COMMAND_TAG *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_MAC_SCHEME_Marshal(const TPMI_ALG_MAC_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_CIPHER_MODE_Marshal(const TPMI_ALG_CIPHER_MODE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_HA_Marshal(const TPMU_HA *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_HA_Marshal(const TPMT_HA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_DIGEST_Marshal(const TPM2B_DIGEST *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_DATA_Marshal(const TPM2B_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_NONCE_Marshal(const TPM2B_NONCE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_AUTH_Marshal(const TPM2B_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_OPERAND_Marshal(const TPM2B_OPERAND *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_EVENT_Marshal(const TPM2B_EVENT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_MAX_BUFFER_Marshal(const TPM2B_MAX_BUFFER *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_MAX_NV_BUFFER_Marshal(const TPM2B_MAX_NV_BUFFER *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_TIMEOUT_Marshal(const TPM2B_TIMEOUT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_IV_Marshal(const TPM2B_IV *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_NAME_Marshal(const TPM2B_NAME *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_PCR_SELECTION_Marshal(const TPMS_PCR_SELECTION *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_TK_CREATION_Marshal(const TPMT_TK_CREATION *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_TK_VERIFIED_Marshal(const TPMT_TK_VERIFIED *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_TK_AUTH_Marshal(const TPMT_TK_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_TK_HASHCHECK_Marshal(const TPMT_TK_HASHCHECK *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ALG_PROPERTY_Marshal(const TPMS_ALG_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_TAGGED_PROPERTY_Marshal(const TPMS_TAGGED_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_TAGGED_PCR_SELECT_Marshal(const TPMS_TAGGED_PCR_SELECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_CC_Marshal(const TPML_CC *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_CCA_Marshal(const TPML_CCA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_ALG_Marshal(const TPML_ALG *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_HANDLE_Marshal(const TPML_HANDLE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_DIGEST_Marshal(const TPML_DIGEST *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_DIGEST_VALUES_Marshal(const TPML_DIGEST_VALUES *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_PCR_SELECTION_Marshal(const TPML_PCR_SELECTION *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_ALG_PROPERTY_Marshal(const TPML_ALG_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_TAGGED_TPM_PROPERTY_Marshal(const TPML_TAGGED_TPM_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_TAGGED_PCR_PROPERTY_Marshal(const TPML_TAGGED_PCR_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_ECC_CURVE_Marshal(const TPML_ECC_CURVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_CAPABILITIES_Marshal(const TPMU_CAPABILITIES *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CAPABILITY_DATA_Marshal(const TPMS_CAPABILITY_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CLOCK_INFO_Marshal(const TPMS_CLOCK_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_TIME_INFO_Marshal(const TPMS_TIME_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_TIME_ATTEST_INFO_Marshal(const TPMS_TIME_ATTEST_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CERTIFY_INFO_Marshal(const TPMS_CERTIFY_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_QUOTE_INFO_Marshal(const TPMS_QUOTE_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_COMMAND_AUDIT_INFO_Marshal(const TPMS_COMMAND_AUDIT_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SESSION_AUDIT_INFO_Marshal(const TPMS_SESSION_AUDIT_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CREATION_INFO_Marshal(const TPMS_CREATION_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_NV_CERTIFY_INFO_Marshal(const TPMS_NV_CERTIFY_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ST_ATTEST_Marshal(const TPMI_ST_ATTEST *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_ATTEST_Marshal(const TPMU_ATTEST  *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ATTEST_Marshal(const TPMS_ATTEST  *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_ATTEST_Marshal(const TPM2B_ATTEST *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_AUTH_COMMAND_Marshal(const TPMS_AUTH_COMMAND *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_AES_KEY_BITS_Marshal(const TPMI_AES_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SYM_KEY_BITS_Marshal(const TPMU_SYM_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SYM_MODE_Marshal(const TPMU_SYM_MODE *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_SYM_DEF_Marshal(const TPMT_SYM_DEF *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_SYM_DEF_OBJECT_Marshal(const TPMT_SYM_DEF_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_SYM_KEY_Marshal(const TPM2B_SYM_KEY *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_LABEL_Marshal(const TPM2B_LABEL *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_DERIVE_Marshal(const TPMS_DERIVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SYMCIPHER_PARMS_Marshal(const TPMS_SYMCIPHER_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_SENSITIVE_DATA_Marshal(const TPM2B_SENSITIVE_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SENSITIVE_CREATE_Marshal(const TPMS_SENSITIVE_CREATE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_SENSITIVE_CREATE_Marshal(const TPM2B_SENSITIVE_CREATE  *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_HASH_Marshal(const TPMS_SCHEME_HASH *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_ECDAA_Marshal(const TPMS_SCHEME_ECDAA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_KEYEDHASH_SCHEME_Marshal(const TPMI_ALG_KEYEDHASH_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_HMAC_Marshal(const TPMS_SCHEME_HMAC *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_XOR_Marshal(const TPMS_SCHEME_XOR *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SCHEME_KEYEDHASH_Marshal(const TPMU_SCHEME_KEYEDHASH *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_KEYEDHASH_SCHEME_Marshal(const TPMT_KEYEDHASH_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_RSASSA_Marshal(const TPMS_SIG_SCHEME_RSASSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_RSAPSS_Marshal(const TPMS_SIG_SCHEME_RSAPSS *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_ECDSA_Marshal(const TPMS_SIG_SCHEME_ECDSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_SM2_Marshal(const TPMS_SIG_SCHEME_SM2 *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_ECSCHNORR_Marshal(const TPMS_SIG_SCHEME_ECSCHNORR *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_ECDAA_Marshal(const TPMS_SIG_SCHEME_ECDAA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SIG_SCHEME_Marshal(const TPMU_SIG_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_SIG_SCHEME_Marshal(const TPMT_SIG_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ENC_SCHEME_OAEP_Marshal(const TPMS_ENC_SCHEME_OAEP *source, UINT16 *written, BYTE **buffer, INT32 *size)
#ifdef __ULTRAVISOR__
	__attribute__ ((const))
#endif
	;
    LIB_EXPORT TPM_RC
    TSS_TPMS_ENC_SCHEME_RSAES_Marshal(const TPMS_ENC_SCHEME_RSAES *source, UINT16 *written, BYTE **buffer, INT32 *size)
#ifdef __ULTRAVISOR__
	__attribute__ ((const))
#endif
	;
    LIB_EXPORT TPM_RC
    TSS_TPMS_KEY_SCHEME_ECDH_Marshal(const TPMS_KEY_SCHEME_ECDH *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_KEY_SCHEME_ECMQV_Marshal(const TPMS_KEY_SCHEME_ECMQV *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_MGF1_Marshal(const TPMS_SCHEME_MGF1 *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_KDF1_SP800_56A_Marshal(const TPMS_SCHEME_KDF1_SP800_56A *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_KDF2_Marshal(const TPMS_SCHEME_KDF2 *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_KDF1_SP800_108_Marshal(const TPMS_SCHEME_KDF1_SP800_108 *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_KDF_SCHEME_Marshal(const TPMU_KDF_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_KDF_SCHEME_Marshal(const TPMT_KDF_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_ASYM_SCHEME_Marshal(const TPMU_ASYM_SCHEME  *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_RSA_SCHEME_Marshal(const TPMI_ALG_RSA_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_RSA_SCHEME_Marshal(const TPMT_RSA_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_RSA_DECRYPT_Marshal(const TPMI_ALG_RSA_DECRYPT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_RSA_DECRYPT_Marshal(const TPMT_RSA_DECRYPT  *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_PUBLIC_KEY_RSA_Marshal(const TPM2B_PUBLIC_KEY_RSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RSA_KEY_BITS_Marshal(const TPMI_RSA_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_PRIVATE_KEY_RSA_Marshal(const TPM2B_PRIVATE_KEY_RSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_ECC_PARAMETER_Marshal(const TPM2B_ECC_PARAMETER *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ECC_POINT_Marshal(const TPMS_ECC_POINT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_ECC_POINT_Marshal(const TPM2B_ECC_POINT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_ECC_SCHEME_Marshal(const TPMI_ALG_ECC_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ECC_CURVE_Marshal(const TPMI_ECC_CURVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_ECC_SCHEME_Marshal(const TPMT_ECC_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ALGORITHM_DETAIL_ECC_Marshal(const TPMS_ALGORITHM_DETAIL_ECC *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_RSA_Marshal(const TPMS_SIGNATURE_RSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_RSASSA_Marshal(const TPMS_SIGNATURE_RSASSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_RSAPSS_Marshal(const TPMS_SIGNATURE_RSAPSS *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_ECC_Marshal(const TPMS_SIGNATURE_ECC *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_ECDSA_Marshal(const TPMS_SIGNATURE_ECDSA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_ECDAA_Marshal(const TPMS_SIGNATURE_ECDAA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_SM2_Marshal(const TPMS_SIGNATURE_SM2 *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_ECSCHNORR_Marshal(const TPMS_SIGNATURE_ECSCHNORR *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SIGNATURE_Marshal(const TPMU_SIGNATURE *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_SIGNATURE_Marshal(const TPMT_SIGNATURE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_ENCRYPTED_SECRET_Marshal(const TPM2B_ENCRYPTED_SECRET *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_PUBLIC_Marshal(const TPMI_ALG_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_PUBLIC_ID_Marshal(const TPMU_PUBLIC_ID *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMS_KEYEDHASH_PARMS_Marshal(const TPMS_KEYEDHASH_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_RSA_PARMS_Marshal(const TPMS_RSA_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ECC_PARMS_Marshal(const TPMS_ECC_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_PUBLIC_PARMS_Marshal(const TPMU_PUBLIC_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_PUBLIC_PARMS_Marshal(const TPMT_PUBLIC_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_PUBLIC_Marshal(const TPMT_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_PUBLIC_D_Marshal(const TPMT_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_PUBLIC_Marshal(const TPM2B_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_TEMPLATE_Marshal(const TPM2B_TEMPLATE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SENSITIVE_COMPOSITE_Marshal(const TPMU_SENSITIVE_COMPOSITE *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_SENSITIVE_Marshal(const TPMT_SENSITIVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_SENSITIVE_Marshal(const TPM2B_SENSITIVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_PRIVATE_Marshal(const TPM2B_PRIVATE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_ID_OBJECT_Marshal(const TPM2B_ID_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_NV_Marshal(const TPMA_NV *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_NV_PUBLIC_Marshal(const TPMS_NV_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_NV_PUBLIC_Marshal(const TPM2B_NV_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_CONTEXT_SENSITIVE_Marshal(const TPM2B_CONTEXT_SENSITIVE *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_CONTEXT_DATA_Marshal(const TPM2B_CONTEXT_DATA  *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CONTEXT_Marshal(const TPMS_CONTEXT *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CREATION_DATA_Marshal(const TPMS_CREATION_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_CREATION_DATA_Marshal(const TPM2B_CREATION_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size);

#ifdef __cplusplus
}
#endif

#endif
