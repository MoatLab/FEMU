/********************************************************************************/
/*										*/
/*			     Structure Print Utilities				*/
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

/* This is a semi-public header. The API is not guaranteed to be stable, and the format of the
   output is subject to change

   It is useful for application debug.
*/

#ifndef TSSPRINTCMD_H
#define TSSPRINTCMD_H

#include <ibmtss/tss.h>

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

    void ActivateCredential_In_Print(ActivateCredential_In *in, unsigned int indent);
    void CertifyCreation_In_Print(CertifyCreation_In *in, unsigned int indent);
    void CertifyX509_In_Print(CertifyX509_In *in, unsigned int indent);
    void Certify_In_Print(Certify_In *in, unsigned int indent);
    void ChangeEPS_In_Print(ChangeEPS_In *in, unsigned int indent);
    void ChangePPS_In_Print(ChangePPS_In *in, unsigned int indent);
    void ClearControl_In_Print(ClearControl_In *in, unsigned int indent);
    void Clear_In_Print(Clear_In *in, unsigned int indent);
    void ClockRateAdjust_In_Print(ClockRateAdjust_In *in, unsigned int indent);
    void ClockSet_In_Print(ClockSet_In *in, unsigned int indent);
    void Commit_In_Print(Commit_In *in, unsigned int indent);
    void ContextLoad_In_Print(ContextLoad_In *in, unsigned int indent);
    void ContextSave_In_Print(ContextSave_In *in, unsigned int indent);
    void Create_In_Print(Create_In *in, unsigned int indent);
    void CreateLoaded_In_Print(CreateLoaded_In *in, unsigned int indent);
    void CreatePrimary_In_Print(CreatePrimary_In *in, unsigned int indent);
    void DictionaryAttackLockReset_In_Print(DictionaryAttackLockReset_In *in, unsigned int indent);
    void DictionaryAttackParameters_In_Print(DictionaryAttackParameters_In *in, unsigned int indent);
    void Duplicate_In_Print(Duplicate_In *in, unsigned int indent);
    void ECC_Parameters_In_Print(ECC_Parameters_In *in, unsigned int indent);
    void ECDH_KeyGen_In_Print(ECDH_KeyGen_In *in, unsigned int indent);
    void ECDH_ZGen_In_Print(ECDH_ZGen_In *in, unsigned int indent);
    void EC_Ephemeral_In_Print(EC_Ephemeral_In *in, unsigned int indent);
    void EncryptDecrypt_In_Print(EncryptDecrypt_In *in, unsigned int indent);
    void EncryptDecrypt2_In_Print(EncryptDecrypt2_In *in, unsigned int indent);
    void EventSequenceComplete_In_Print(EventSequenceComplete_In *in, unsigned int indent);
    void EvictControl_In_Print(EvictControl_In *in, unsigned int indent);
    void FlushContext_In_Print(FlushContext_In *in, unsigned int indent);
    void GetCapability_In_Print(GetCapability_In *in, unsigned int indent);
    void GetCommandAuditDigest_In_Print(GetCommandAuditDigest_In *in, unsigned int indent);
    void GetRandom_In_Print(GetRandom_In *in, unsigned int indent);
    void GetSessionAuditDigest_In_Print(GetSessionAuditDigest_In *in, unsigned int indent);
    void GetTime_In_Print(GetTime_In *in, unsigned int indent);
    void HMAC_Start_In_Print(HMAC_Start_In *in, unsigned int indent);
    void HMAC_In_Print(HMAC_In *in, unsigned int indent);
    void HashSequenceStart_In_Print(HashSequenceStart_In *in, unsigned int indent);
    void Hash_In_Print(Hash_In *in, unsigned int indent);
    void HierarchyChangeAuth_In_Print(HierarchyChangeAuth_In *in, unsigned int indent);
    void HierarchyControl_In_Print(HierarchyControl_In *in, unsigned int indent);
    void Import_In_Print(Import_In *in, unsigned int indent);
    void IncrementalSelfTest_In_Print(IncrementalSelfTest_In *in, unsigned int indent);
    void LoadExternal_In_Print(LoadExternal_In *in, unsigned int indent);
    void Load_In_Print(Load_In *in, unsigned int indent);
    void MakeCredential_In_Print(MakeCredential_In *in, unsigned int indent);
    void NTC2_PreConfig_In_Print(NTC2_PreConfig_In *in, unsigned int indent);
    void NV_Certify_In_Print(NV_Certify_In *in, unsigned int indent);
    void NV_ChangeAuth_In_Print(NV_ChangeAuth_In *in, unsigned int indent);
    void NV_DefineSpace_In_Print(NV_DefineSpace_In *in, unsigned int indent);
    void NV_Extend_In_Print(NV_Extend_In *in, unsigned int indent);
    void NV_GlobalWriteLock_In_Print(NV_GlobalWriteLock_In *in, unsigned int indent);
    void NV_Increment_In_Print(NV_Increment_In *in, unsigned int indent);
    void NV_ReadLock_In_Print(NV_ReadLock_In *in, unsigned int indent);
    void NV_ReadPublic_In_Print(NV_ReadPublic_In *in, unsigned int indent);
    void NV_Read_In_Print(NV_Read_In *in, unsigned int indent);
    void NV_SetBits_In_Print(NV_SetBits_In *in, unsigned int indent);
    void NV_UndefineSpaceSpecial_In_Print(NV_UndefineSpaceSpecial_In *in, unsigned int indent);
    void NV_UndefineSpace_In_Print(NV_UndefineSpace_In *in, unsigned int indent);
    void NV_WriteLock_In_Print(NV_WriteLock_In *in, unsigned int indent);
    void NV_Write_In_Print(NV_Write_In *in, unsigned int indent);
    void ObjectChangeAuth_In_Print(ObjectChangeAuth_In *in, unsigned int indent);
    void PCR_Allocate_In_Print(PCR_Allocate_In *in, unsigned int indent);
    void PCR_Event_In_Print(PCR_Event_In *in, unsigned int indent);
    void PCR_Extend_In_Print(PCR_Extend_In *in, unsigned int indent);
    void PCR_Read_In_Print(PCR_Read_In *in, unsigned int indent);
    void PCR_Reset_In_Print(PCR_Reset_In *in, unsigned int indent);
    void PCR_SetAuthPolicy_In_Print(PCR_SetAuthPolicy_In *in, unsigned int indent);
    void PCR_SetAuthValue_In_Print(PCR_SetAuthValue_In *in, unsigned int indent);
    void PP_Commands_In_Print(PP_Commands_In *in, unsigned int indent);
    void PolicyAuthValue_In_Print(PolicyAuthValue_In *in, unsigned int indent);
    void PolicyAuthorizeNV_In_Print(PolicyAuthorizeNV_In *in, unsigned int indent);
    void PolicyAuthorize_In_Print(PolicyAuthorize_In *in, unsigned int indent);
    void PolicyCommandCode_In_Print(PolicyCommandCode_In *in, unsigned int indent);
    void PolicyCounterTimer_In_Print(PolicyCounterTimer_In *in, unsigned int indent);
    void PolicyCpHash_In_Print(PolicyCpHash_In *in, unsigned int indent);
    void PolicyDuplicationSelect_In_Print(PolicyDuplicationSelect_In *in, unsigned int indent);
    void PolicyGetDigest_In_Print(PolicyGetDigest_In *in, unsigned int indent);
    void PolicyLocality_In_Print(PolicyLocality_In *in, unsigned int indent);
    void PolicyNV_In_Print(PolicyNV_In *in, unsigned int indent);
    void PolicyNameHash_In_Print(PolicyNameHash_In *in, unsigned int indent);
    void PolicyNvWritten_In_Print(PolicyNvWritten_In *in, unsigned int indent);
    void PolicyOR_In_Print(PolicyOR_In *in, unsigned int indent);
    void PolicyPCR_In_Print(PolicyPCR_In *in, unsigned int indent);
    void PolicyPassword_In_Print(PolicyPassword_In *in, unsigned int indent);
    void PolicyPhysicalPresence_In_Print(PolicyPhysicalPresence_In *in, unsigned int indent);
    void PolicyRestart_In_Print(PolicyRestart_In *in, unsigned int indent);
    void PolicySecret_In_Print(PolicySecret_In *in, unsigned int indent);
    void PolicySigned_In_Print(PolicySigned_In *in, unsigned int indent);
    void PolicyTemplate_In_Print(PolicyTemplate_In *in, unsigned int indent);
    void PolicyTicket_In_Print(PolicyTicket_In *in, unsigned int indent);
    void Quote_In_Print(Quote_In *in, unsigned int indent);
    void RSA_Decrypt_In_Print(RSA_Decrypt_In *in, unsigned int indent);
    void RSA_Encrypt_In_Print(RSA_Encrypt_In *in, unsigned int indent);
    void ReadPublic_In_Print(ReadPublic_In *in, unsigned int indent);
    void Rewrap_In_Print(Rewrap_In *in, unsigned int indent);
    void SelfTest_In_Print(SelfTest_In *in, unsigned int indent);
    void SequenceComplete_In_Print(SequenceComplete_In *in, unsigned int indent);
    void SequenceUpdate_In_Print(SequenceUpdate_In *in, unsigned int indent);
    void SetAlgorithmSet_In_Print(SetAlgorithmSet_In *in, unsigned int indent);
    void SetCommandCodeAuditStatus_In_Print(SetCommandCodeAuditStatus_In *in, unsigned int indent);
    void SetPrimaryPolicy_In_Print(SetPrimaryPolicy_In *in, unsigned int indent);
    void Shutdown_In_Print(Shutdown_In *in, unsigned int indent);
    void Sign_In_Print(Sign_In *in, unsigned int indent);
    void StartAuthSession_In_Print(StartAuthSession_In *in, unsigned int indent);
    void Startup_In_Print(Startup_In *in, unsigned int indent);
    void StirRandom_In_Print(StirRandom_In *in, unsigned int indent);
    void TestParms_In_Print(TestParms_In *in, unsigned int indent);
    void Unseal_In_Print(Unseal_In *in, unsigned int indent);
    void VerifySignature_In_Print(VerifySignature_In *in, unsigned int indent);
    void ZGen_2Phase_In_Print(ZGen_2Phase_In *in, unsigned int indent);
    
#ifdef __cplusplus
}
#endif

#endif

