/********************************************************************************/
/*										*/
/*			     Command Print Utilities				*/
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

#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

#include <ibmtss/tssprintcmd.h>

void ActivateCredential_In_Print(ActivateCredential_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_ActivateCredential\n", indent, "");
    TSS_TPM_HANDLE_Print("activateHandle", in->activateHandle, indent);
    TSS_TPM_HANDLE_Print("keyHandle", in->keyHandle, indent);
    TSS_TPM2B_Print("credentialBlob", indent, &in->credentialBlob.b);
    TSS_TPM2B_Print("TPM2B_ENCRYPTED_SECRET secret", indent, &in->secret.b);
    return;
}
void CertifyCreation_In_Print(CertifyCreation_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_CertifyCreation\n", indent, "");
    TSS_TPM_HANDLE_Print("signHandle", in->signHandle, indent);
    TSS_TPM_HANDLE_Print("objectHandle", in->objectHandle, indent);
    TSS_TPM2B_Print("qualifyingData", indent, &in->qualifyingData.b);
    TSS_TPM2B_Print("creationHash", indent, &in->creationHash.b);
    printf("%*s" "inScheme\n", indent, "");
    TSS_TPMT_SIG_SCHEME_Print(&in->inScheme, indent);
    printf("%*s" "creationTicket\n", indent, "");
    TSS_TPMT_TK_CREATION_Print(&in->creationTicket, indent+2);
    return;
}
void Certify_In_Print(Certify_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_Certify\n", indent, "");
    TSS_TPM_HANDLE_Print("objectHandle", in->objectHandle, indent);
    TSS_TPM_HANDLE_Print("signHandle", in->signHandle, indent);
    TSS_TPM2B_Print("qualifyingData", indent, &in->qualifyingData.b);
    printf("%*s" "inScheme\n", indent, "");
    TSS_TPMT_SIG_SCHEME_Print(&in->inScheme, indent);
    return;
}
void CertifyX509_In_Print(CertifyX509_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_CertifyX509\n", indent, "");
    TSS_TPM_HANDLE_Print("objectHandle", in->objectHandle, indent);
    TSS_TPM_HANDLE_Print("signHandle", in->signHandle, indent);
    TSS_TPM2B_Print("reserved", indent, &in->reserved.b);
    printf("%*s" "inScheme\n", indent, "");
    TSS_TPMT_SIG_SCHEME_Print(&in->inScheme, indent);
    TSS_TPM2B_Print("partialCertificate", indent, &in->partialCertificate.b);
    return;
}
void ChangeEPS_In_Print(ChangeEPS_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_ChangeEPS\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    return;
}
void ChangePPS_In_Print(ChangePPS_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_ChangePPS\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    return;
}
void ClearControl_In_Print(ClearControl_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_ClearControl\n", indent, "");
    TSS_TPM_HANDLE_Print("auth", in->auth, indent);
    TSS_TPMI_YES_NO_Print("disable", in->disable, indent);
    return;
}
void Clear_In_Print(Clear_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_Clear\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    return;
}
void ClockRateAdjust_In_Print(ClockRateAdjust_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_ClockRateAdjust\n", indent, "");
    TSS_TPM_HANDLE_Print("auth", in->auth, indent);
    TSS_TPM_CLOCK_ADJUST_Print("rateAdjust", in->rateAdjust, indent);
    return;
}
void ClockSet_In_Print(ClockSet_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_ClockSet\n", indent, "");
    TSS_TPM_HANDLE_Print("auth", in->auth, indent);
    printf("%*s" "newTime %"PRIu64"\n", indent, "", in->newTime);
    return;
}
void Commit_In_Print(Commit_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_Commit\n", indent, "");
    TSS_TPM_HANDLE_Print("signHandle", in->signHandle, indent);
    TSS_TPM2B_ECC_POINT_Print("P1", &in->P1, indent);
    TSS_TPM2B_Print("s2", indent, &in->s2.b);
    TSS_TPM2B_Print("y2", indent, &in->y2.b);
    return;
}
void ContextLoad_In_Print(ContextLoad_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_ContextLoad\n", indent, "");
    TSS_TPMS_CONTEXT_Print(&in->context, indent);
    return;
}
void ContextSave_In_Print(ContextSave_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_ContextSave\n", indent, "");
    TSS_TPM_HANDLE_Print("saveHandle", in->saveHandle, indent);
    return;
}
void Create_In_Print(Create_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_Create\n", indent, "");
    TSS_TPM_HANDLE_Print("parentHandle", in->parentHandle, indent);
    TSS_TPM2B_SENSITIVE_CREATE_Print("inSensitive", &in->inSensitive, indent);
    TSS_TPM2B_PUBLIC_Print("inPublic", &in->inPublic, indent);
    TSS_TPM2B_Print("outsideInfo", indent, &in->outsideInfo.b);
    TSS_TPML_PCR_SELECTION_Print(&in->creationPCR, indent);
    return;
}
void CreateLoaded_In_Print(CreateLoaded_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_CreateLoaded\n", indent, "");
    TSS_TPM_HANDLE_Print("parentHandle", in->parentHandle, indent);
    TSS_TPM2B_SENSITIVE_CREATE_Print("inSensitive", &in->inSensitive, indent);
    TSS_TPM2B_Print("inPublic", indent, &in->inPublic.b);
    return;
}
void CreatePrimary_In_Print(CreatePrimary_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_CreatePrimary\n", indent, "");
    TSS_TPM_HANDLE_Print("primaryHandle", in->primaryHandle, indent);
    TSS_TPM2B_SENSITIVE_CREATE_Print("inSensitive", &in->inSensitive, indent);
    TSS_TPM2B_PUBLIC_Print("inPublic", &in->inPublic, indent);
    TSS_TPM2B_Print("outsideInfo", indent, &in->outsideInfo.b);
    TSS_TPML_PCR_SELECTION_Print(&in->creationPCR, indent);
    return;
}
void DictionaryAttackLockReset_In_Print(DictionaryAttackLockReset_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_DictionaryAttackLockReset\n", indent, "");
    TSS_TPM_HANDLE_Print("lockHandle", in->lockHandle, indent);
    return;
}
void DictionaryAttackParameters_In_Print(DictionaryAttackParameters_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_DictionaryAttackParameters\n", indent, "");
    TSS_TPM_HANDLE_Print("lockHandle", in->lockHandle, indent);
    printf("%*s" "newMaxTries %u\n", indent, "", in->newMaxTries);
    printf("%*s" "newRecoveryTime %u\n", indent, "", in->newRecoveryTime);
    printf("%*s" "lockoutRecovery %u\n", indent, "", in->lockoutRecovery);
    return;
}
void Duplicate_In_Print(Duplicate_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_Duplicate\n", indent, "");
    TSS_TPM_HANDLE_Print("objectHandle", in->objectHandle, indent);
    TSS_TPM_HANDLE_Print("newParentHandle", in->newParentHandle, indent);
    TSS_TPM2B_Print("encryptionKeyIn", indent, &in->encryptionKeyIn.b);
    printf("%*s" "symmetricAlg\n", indent, "");
    TSS_TPMT_SYM_DEF_OBJECT_Print(&in->symmetricAlg, indent);
    return;
}
void ECC_Parameters_In_Print(ECC_Parameters_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_ECC_Parameters\n", indent, "");
    TSS_TPMI_ECC_CURVE_Print("curveID", in->curveID, indent);
    return;
}
void ECDH_KeyGen_In_Print(ECDH_KeyGen_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_ECDH_KeyGen\n", indent, "");
    TSS_TPM_HANDLE_Print("keyHandle", in->keyHandle, indent);
    return;
}
void ECDH_ZGen_In_Print(ECDH_ZGen_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_ECDH_ZGen\n", indent, "");
    TSS_TPM_HANDLE_Print("keyHandle", in->keyHandle, indent);
    TSS_TPM2B_ECC_POINT_Print("inPoint", &in->inPoint, indent);
    return;
}
void EC_Ephemeral_In_Print(EC_Ephemeral_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_EC_Ephemeral\n", indent, "");
    TSS_TPMI_ECC_CURVE_Print("curveID", in->curveID, indent);
    return;
}
void EncryptDecrypt_In_Print(EncryptDecrypt_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_EncryptDecrypt\n", indent, "");
    TSS_TPM_HANDLE_Print("keyHandle", in->keyHandle, indent);
    TSS_TPMI_YES_NO_Print("decrypt", in->decrypt, indent);
    TSS_TPM_ALG_ID_Print("mode", in->mode, indent);
    TSS_TPM2B_Print("ivIn", indent, &in->ivIn.b);
    TSS_TPM2B_Print("inData", indent, &in->inData.b);
    return;
}
void EncryptDecrypt2_In_Print(EncryptDecrypt2_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_EncryptDecrypt2\n", indent, "");
    TSS_TPM_HANDLE_Print("keyHandle", in->keyHandle, indent);
    TSS_TPM2B_Print("inData", indent, &in->inData.b);
    TSS_TPMI_YES_NO_Print("decrypt", in->decrypt, indent);
    TSS_TPM_ALG_ID_Print("mode", in->mode, indent);
    TSS_TPM2B_Print("ivIn", indent, &in->ivIn.b);
    return;
}
void EventSequenceComplete_In_Print(EventSequenceComplete_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_EventSequenceComplete\n", indent, "");
    TSS_TPM_HANDLE_Print("pcrHandle", in->pcrHandle, indent);
    TSS_TPM_HANDLE_Print("sequenceHandle", in->sequenceHandle, indent);
    TSS_TPM2B_Print("buffer", indent, &in->buffer.b);
    return;
}
void EvictControl_In_Print(EvictControl_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_EvictControl\n", indent, "");
    TSS_TPM_HANDLE_Print("auth", in->auth, indent);
    TSS_TPM_HANDLE_Print("objectHandle", in->objectHandle, indent);
    TSS_TPM_HANDLE_Print("persistentHandle", in->persistentHandle, indent);
    return;
}
void FlushContext_In_Print(FlushContext_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_FlushContext\n", indent, "");
    TSS_TPM_HANDLE_Print("flushHandle", in->flushHandle, indent);
    return;
}
void GetCapability_In_Print(GetCapability_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_GetCapability\n", indent, "");
    TSS_TPM_CAP_Print("capability", in->capability, indent);
    printf("%*s" "property %08x\n", indent, "", in->property);
    printf("%*s" "propertyCount %u\n", indent, "", in->propertyCount);
    return;
}
void GetCommandAuditDigest_In_Print(GetCommandAuditDigest_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_GetCommandAuditDigest\n", indent, "");
    TSS_TPM_HANDLE_Print("privacyHandle", in->privacyHandle, indent);
    TSS_TPM_HANDLE_Print("signHandle", in->signHandle, indent);
    TSS_TPM2B_Print("qualifyingData", indent, &in->qualifyingData.b);
    printf("%*s" "inScheme\n", indent, "");
    TSS_TPMT_SIG_SCHEME_Print(&in->inScheme, indent);
    return;
}
void GetRandom_In_Print(GetRandom_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_GetRandom\n", indent, "");
    printf("%*s" "bytesRequested %u\n", indent, "", in->bytesRequested);
    return;
}
void GetSessionAuditDigest_In_Print(GetSessionAuditDigest_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_GetSessionAuditDigest\n", indent, "");
    TSS_TPM_HANDLE_Print("privacyAdminHandle", in->privacyAdminHandle, indent);
    TSS_TPM_HANDLE_Print("signHandle", in->signHandle, indent);
    TSS_TPM_HANDLE_Print("sessionHandle", in->sessionHandle, indent);
    TSS_TPM2B_Print("qualifyingData", indent, &in->qualifyingData.b);
    printf("%*s" "inScheme\n", indent, "");
    TSS_TPMT_SIG_SCHEME_Print(&in->inScheme, indent);
    return;
}
void GetTime_In_Print(GetTime_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_GetTime\n", indent, "");
    TSS_TPM_HANDLE_Print("privacyAdminHandle", in->privacyAdminHandle, indent);
    TSS_TPM_HANDLE_Print("signHandle", in->signHandle, indent);
    TSS_TPM2B_Print("qualifyingData", indent, &in->qualifyingData.b);
    printf("%*s" "inScheme\n", indent, "");
    TSS_TPMT_SIG_SCHEME_Print(&in->inScheme, indent);
    return;
}
void HMAC_Start_In_Print(HMAC_Start_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_HMAC_Start\n", indent, "");
    TSS_TPM_HANDLE_Print("handle", in->handle, indent);
    TSS_TPM2B_Print("auth", indent, &in->auth.b);
    TSS_TPM_ALG_ID_Print("hashAlg", in->hashAlg, indent);
    return;
}
void HMAC_In_Print(HMAC_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_HMAC\n", indent, "");
    TSS_TPM_HANDLE_Print("handle", in->handle, indent);
    TSS_TPM2B_Print("buffer", indent, &in->buffer.b);
    TSS_TPM_ALG_ID_Print("hashAlg", in->hashAlg, indent);
    return;
}
void HashSequenceStart_In_Print(HashSequenceStart_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_HashSequenceStart\n", indent, "");
    TSS_TPM2B_Print("auth", indent, &in->auth.b);
    TSS_TPM_ALG_ID_Print("hashAlg", in->hashAlg, indent);
    return;
}
void Hash_In_Print(Hash_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_Hash\n", indent, "");
    TSS_TPM2B_Print("data", indent, &in->data.b);
    TSS_TPM_ALG_ID_Print("hashAlg", in->hashAlg, indent);
    TSS_TPM_HANDLE_Print("hierarchy", in->hierarchy, indent);
    return;
}
void HierarchyChangeAuth_In_Print(HierarchyChangeAuth_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_HierarchyChangeAuth\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM2B_Print("newAuth", indent, &in->newAuth.b);
    return;
}
void HierarchyControl_In_Print(HierarchyControl_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_HierarchyControl\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM_HANDLE_Print("enable", in->enable, indent);
    TSS_TPMI_YES_NO_Print("state", in->state, indent);
    return;
}
void Import_In_Print(Import_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_Import\n", indent, "");
    TSS_TPM_HANDLE_Print("parentHandle", in->parentHandle, indent);
    TSS_TPM2B_Print("encryptionKey", indent, &in->encryptionKey.b);
    TSS_TPM2B_PUBLIC_Print("objectPublic", &in->objectPublic, indent);
    TSS_TPM2B_Print("duplicate", indent, &in->duplicate.b);
    TSS_TPM2B_Print("inSymSeed", indent, &in->inSymSeed.b);
    printf("%*s" "symmetricAlg\n", indent, "");
    TSS_TPMT_SYM_DEF_OBJECT_Print(&in->symmetricAlg, indent);
    return;
}
void IncrementalSelfTest_In_Print(IncrementalSelfTest_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_IncrementalSelfTest\n", indent, "");
    TSS_TPML_ALG_Print(&in->toTest, indent);
    return;
}
void LoadExternal_In_Print(LoadExternal_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_LoadExternal\n", indent, "");
    if (in->inPrivate.t.size != 0) {	/* if there is a private area */
	TSS_TPMT_SENSITIVE_Print(&in->inPrivate.t.sensitiveArea, indent);
    }
    TSS_TPM2B_PUBLIC_Print("inPublic", &in->inPublic, indent);
    TSS_TPM_HANDLE_Print("hierarchy", in->hierarchy, indent);
    return;
}
void Load_In_Print(Load_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_Load\n", indent, "");
    TSS_TPM_HANDLE_Print("parentHandle", in->parentHandle, indent);
    TSS_TPM2B_Print("inPrivate", indent, &in->inPrivate.b);
    TSS_TPM2B_PUBLIC_Print("inPublic", &in->inPublic, indent);
    return;
}
void MakeCredential_In_Print(MakeCredential_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_MakeCredential\n", indent, "");
    TSS_TPM_HANDLE_Print("handle", in->handle, indent);
    TSS_TPM2B_Print("credential", indent, &in->credential.b);
    TSS_TPM2B_Print("objectName", indent, &in->objectName.b);
    return;
}
#if 0
void NTC2_PreConfig_In_Print(NTC2_PreConfig_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_NTC2_PreConfig\n", indent, "");
    NTC2_CFG_STRUCT preConfig;
    return;
}
#endif
void NV_Certify_In_Print(NV_Certify_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_NV_Certify\n", indent, "");
    TSS_TPM_HANDLE_Print("signHandle", in->signHandle, indent);
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM_HANDLE_Print("nvIndex", in->nvIndex, indent);
    TSS_TPM2B_Print("qualifyingData", indent, &in->qualifyingData.b);
    printf("%*s" "inScheme\n", indent, "");
    TSS_TPMT_SIG_SCHEME_Print(&in->inScheme, indent);
    printf("%*s" "size %u\n", indent, "", in->size);
    printf("%*s" "offset %u\n", indent, "", in->offset);
    return;
}
void NV_ChangeAuth_In_Print(NV_ChangeAuth_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_NV_ChangeAuth\n", indent, "");
    TSS_TPM_HANDLE_Print("nvIndex", in->nvIndex, indent);
    TSS_TPM2B_Print("newAuth", indent, &in->newAuth.b);
    return;
}
void NV_DefineSpace_In_Print(NV_DefineSpace_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_NV_DefineSpace\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM2B_Print("auth", indent, &in->auth.b);
    printf("%*s" "publicInfo\n", indent, "");
    TSS_TPM2B_NV_PUBLIC_Print(&in->publicInfo, indent);
    return;
}
void NV_Extend_In_Print(NV_Extend_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_NV_Extend\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM_HANDLE_Print("nvIndex", in->nvIndex, indent);
    TSS_TPM2B_Print("data", indent, &in->data.b);
    return;
}
void NV_GlobalWriteLock_In_Print(NV_GlobalWriteLock_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_NV_GlobalWriteLock\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    return;
}
void NV_Increment_In_Print(NV_Increment_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_NV_Increment\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM_HANDLE_Print("nvIndex", in->nvIndex, indent);
    return;
}
void NV_ReadLock_In_Print(NV_ReadLock_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_NV_ReadLock\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM_HANDLE_Print("nvIndex", in->nvIndex, indent);
    return;
}
void NV_ReadPublic_In_Print(NV_ReadPublic_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_NV_ReadPublic\n", indent, "");
    TSS_TPM_HANDLE_Print("nvIndex", in->nvIndex, indent);
    return;
}
void NV_Read_In_Print(NV_Read_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_NV_Read\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM_HANDLE_Print("nvIndex", in->nvIndex, indent);
    printf("%*s" "size %u\n", indent, "", in->size);
    printf("%*s" "offset %u\n", indent, "", in->offset);
    return;
}
void NV_SetBits_In_Print(NV_SetBits_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_NV_SetBits\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM_HANDLE_Print("nvIndex", in->nvIndex, indent);
    printf("%*s" "bits %"PRIx64"\n", indent, "", in->bits);
    return;
}
void NV_UndefineSpaceSpecial_In_Print(NV_UndefineSpaceSpecial_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_NV_UndefineSpaceSpecial\n", indent, "");
    TSS_TPM_HANDLE_Print("nvIndex", in->nvIndex, indent);
    TSS_TPM_HANDLE_Print("platform", in->platform, indent);
    return;
}
void NV_UndefineSpace_In_Print(NV_UndefineSpace_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_NV_UndefineSpace\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM_HANDLE_Print("nvIndex", in->nvIndex, indent);
    return;
}    
void NV_WriteLock_In_Print(NV_WriteLock_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_NV_WriteLock\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM_HANDLE_Print("nvIndex", in->nvIndex, indent);
    return;
}
void NV_Write_In_Print(NV_Write_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_NV_Write\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM_HANDLE_Print("nvIndex", in->nvIndex, indent);
    TSS_TPM2B_Print("data", indent, &in->data.b);
    printf("%*s" "offset %u\n", indent, "", in->offset);
    return;
}
void ObjectChangeAuth_In_Print(ObjectChangeAuth_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_ObjectChangeAuth\n", indent, "");
    TSS_TPM_HANDLE_Print("objectHandle", in->objectHandle, indent);
    TSS_TPM_HANDLE_Print("parentHandle", in->parentHandle, indent);
    TSS_TPM2B_Print("newAuth", indent, &in->newAuth.b);
    return;
}
void PCR_Allocate_In_Print(PCR_Allocate_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PCR_Allocate\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPML_PCR_SELECTION_Print(&in->pcrAllocation, indent);
    return;
}
void PCR_Event_In_Print(PCR_Event_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PCR_Event\n", indent, "");
    TSS_TPM_HANDLE_Print("pcrHandle", in->pcrHandle, indent);
    TSS_TPM2B_Print("eventData", indent, &in->eventData.b);
    return;
}
void PCR_Extend_In_Print(PCR_Extend_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PCR_Extend\n", indent, "");
    TSS_TPM_HANDLE_Print("pcrHandle", in->pcrHandle, indent);
    TSS_TPML_DIGEST_VALUES_Print(&in->digests, indent);
    return;
}
void PCR_Read_In_Print(PCR_Read_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PCR_Read\n", indent, "");
    TSS_TPML_PCR_SELECTION_Print(&in->pcrSelectionIn, indent);
    return;
}
void PCR_Reset_In_Print(PCR_Reset_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PCR_Reset\n", indent, "");
    TSS_TPM_HANDLE_Print("pcrHandle", in->pcrHandle, indent);
    return;
}
void PCR_SetAuthPolicy_In_Print(PCR_SetAuthPolicy_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PCR_SetAuthPolicy\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM2B_Print("authPolicy", indent, &in->authPolicy.b);
    TSS_TPM_ALG_ID_Print("hashAlg", in->hashAlg, indent);
    TSS_TPM_HANDLE_Print("pcrNum", in->pcrNum, indent);
    return;
}
void PCR_SetAuthValue_In_Print(PCR_SetAuthValue_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PCR_SetAuthValue\n", indent, "");
    TSS_TPM_HANDLE_Print("pcrHandle", in->pcrHandle, indent);
    TSS_TPM2B_Print("auth", indent, &in->auth.b);
    return;
}
void PP_Commands_In_Print(PP_Commands_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PP_Commands\n", indent, "");
    TSS_TPM_HANDLE_Print("auth", in->auth, indent);
    TSS_TPML_CC_Print(&in->setList, indent);
    TSS_TPML_CC_Print(&in->clearList, indent);
    return;
}
void PolicyAuthValue_In_Print(PolicyAuthValue_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyAuthValue\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    return;
}
void PolicyAuthorizeNV_In_Print(PolicyAuthorizeNV_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyAuthorizeNV\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM_HANDLE_Print("nvIndex", in->nvIndex, indent);
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    return;
}
void PolicyAuthorize_In_Print(PolicyAuthorize_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyAuthorize\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    TSS_TPM2B_Print("approvedPolicy", indent, &in->approvedPolicy.b);
    TSS_TPM2B_Print("policyRef", indent, &in->policyRef.b);
    TSS_TPM2B_Print("keySign", indent, &in->keySign.b);
    printf("%*s" "checkTicket\n", indent, "");
    TSS_TPMT_TK_VERIFIED_Print(&in->checkTicket, indent+2);
    return;
}
void PolicyCommandCode_In_Print(PolicyCommandCode_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyCommandCode\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    TSS_TPM_CC_Print("code", in->code, indent);
    return;
}
void PolicyCounterTimer_In_Print(PolicyCounterTimer_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyCounterTimer\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    TSS_TPM2B_Print("operandB", indent, &in->operandB.b);
    printf("%*s" "offset %u\n", indent, "", in->offset);
    TSS_TPM_EO_Print("operation", in->operation, indent);
    return;
}
void PolicyCpHash_In_Print(PolicyCpHash_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyCpHash\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    TSS_TPM2B_Print("cpHashA", indent, &in->cpHashA.b);
    return;
}
void PolicyDuplicationSelect_In_Print(PolicyDuplicationSelect_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyDuplicationSelect\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    TSS_TPM2B_Print("objectName", indent, &in->objectName.b);
    TSS_TPM2B_Print("newParentName", indent, &in->newParentName.b);
    TSS_TPMI_YES_NO_Print("includeObject", in->includeObject, indent);
    return;
}
void PolicyGetDigest_In_Print(PolicyGetDigest_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyGetDigest\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    return;
}
void PolicyLocality_In_Print(PolicyLocality_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyLocality\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    TSS_TPMA_LOCALITY_Print(in->locality, indent);
    return;
}
void PolicyNV_In_Print(PolicyNV_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyNV\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM_HANDLE_Print("nvIndex", in->nvIndex, indent);
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    TSS_TPM2B_Print("operandB", indent, &in->operandB.b);
    printf("%*s" "offset %u\n", indent, "", in->offset);
    TSS_TPM_EO_Print("operation", in->operation, indent);
    return;
}
void PolicyNameHash_In_Print(PolicyNameHash_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyNameHash\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    TSS_TPM2B_Print("nameHash", indent, &in->nameHash.b);
    return;
}
void PolicyNvWritten_In_Print(PolicyNvWritten_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyNvWritten\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    TSS_TPMI_YES_NO_Print("writtenSet", in->writtenSet, indent);
    return;
}
void PolicyOR_In_Print(PolicyOR_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyOR\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    printf("%*s" "pHashList\n", indent, "");
    TSS_TPML_DIGEST_Print(&in->pHashList, indent+2);
    return;
}
void PolicyPCR_In_Print(PolicyPCR_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyPCR\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    TSS_TPM2B_Print("pcrDigest", indent, &in->pcrDigest.b);
    TSS_TPML_PCR_SELECTION_Print(&in->pcrs, indent);
    return;
}
void PolicyPassword_In_Print(PolicyPassword_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyPassword\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    return;
}
void PolicyPhysicalPresence_In_Print(PolicyPhysicalPresence_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyPhysicalPresence\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    return;
}
void PolicyRestart_In_Print(PolicyRestart_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyRestart\n", indent, "");
    TSS_TPM_HANDLE_Print("sessionHandle", in->sessionHandle, indent);
    return;
}
void PolicySecret_In_Print(PolicySecret_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicySecret\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    TSS_TPM2B_Print("nonceTPM", indent, &in->nonceTPM.b);
    TSS_TPM2B_Print("cpHashA", indent, &in->cpHashA.b);
    TSS_TPM2B_Print("policyRef", indent, &in->policyRef.b);
    printf("%*s" "expiration %d\n", indent, "", in->expiration);
    return;
}
void PolicySigned_In_Print(PolicySigned_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicySigned\n", indent, "");
    TSS_TPM_HANDLE_Print("authObject", in->authObject, indent);
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    TSS_TPM2B_Print("nonceTPM", indent, &in->nonceTPM.b);
    TSS_TPM2B_Print("cpHashA", indent, &in->cpHashA.b);
    TSS_TPM2B_Print("policyRef", indent, &in->policyRef.b);
    printf("%*s" "expiration %d\n", indent, "", in->expiration);
    printf("%*s" "auth\n", indent, "");
    TSS_TPMT_SIGNATURE_Print(&in->auth, indent+2);
    return;
}
void PolicyTemplate_In_Print(PolicyTemplate_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyTemplate\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    TSS_TPM2B_Print("templateHash", indent, &in->templateHash.b);
    return;
}
void PolicyTicket_In_Print(PolicyTicket_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_PolicyTicket\n", indent, "");
    TSS_TPM_HANDLE_Print("policySession", in->policySession, indent);
    TSS_TPM2B_Print("timeout", indent, &in->timeout.b);
    TSS_TPM2B_Print("cpHashA", indent, &in->cpHashA.b);
    TSS_TPM2B_Print("policyRef", indent, &in->policyRef.b);
    TSS_TPM2B_Print("authName", indent, &in->authName.b);
    printf("%*s" "ticket\n", indent, "");
    TSS_TPMT_TK_AUTH_Print(&in->ticket, indent+2);
    return;
}
void Quote_In_Print(Quote_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_Quote\n", indent, "");
    TSS_TPM_HANDLE_Print("signHandle", in->signHandle, indent);
    TSS_TPM2B_Print("qualifyingData", indent, &in->qualifyingData.b);
    printf("%*s" "inScheme\n", indent, "");
    TSS_TPMT_SIG_SCHEME_Print(&in->inScheme, indent);
    TSS_TPML_PCR_SELECTION_Print(&in->PCRselect, indent);
    return;
}
void RSA_Decrypt_In_Print(RSA_Decrypt_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_RSA_Decrypt\n", indent, "");
    TSS_TPM_HANDLE_Print("keyHandle", in->keyHandle, indent);
    TSS_TPM2B_Print("cipherText", indent, &in->cipherText.b); 
    printf("%*s" "inScheme\n", indent, "");
    TSS_TPMT_RSA_DECRYPT_Print(&in->inScheme, indent);
    TSS_TPM2B_Print("label", indent, &in->label.b);
    return;
}
void RSA_Encrypt_In_Print(RSA_Encrypt_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_RSA_Encrypt\n", indent, "");
    TSS_TPM_HANDLE_Print("keyHandle", in->keyHandle, indent);
    TSS_TPM2B_Print("message", indent, &in->message.b);
    printf("%*s" "inScheme\n", indent, "");
    TSS_TPMT_RSA_DECRYPT_Print(&in->inScheme, indent);
    TSS_TPM2B_Print("label", indent, &in->label.b);
    return;
}
void ReadPublic_In_Print(ReadPublic_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_ReadPublic\n", indent, "");
    TSS_TPM_HANDLE_Print("objectHandle", in->objectHandle, indent);
    return;
}
void Rewrap_In_Print(Rewrap_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_Rewrap\n", indent, "");
    TSS_TPM_HANDLE_Print("oldParent", in->oldParent, indent);
    TSS_TPM_HANDLE_Print("newParent", in->newParent, indent);
    TSS_TPM2B_Print("inDuplicate", indent, &in->inDuplicate.b);
    TSS_TPM2B_Print("name", indent, &in->name.b);
    TSS_TPM2B_Print("inSymSeed", indent, &in->inSymSeed.b);
    return;
}
void SelfTest_In_Print(SelfTest_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_SelfTest\n", indent, "");
    TSS_TPMI_YES_NO_Print("fullTest", in->fullTest, indent);
    return;
}
void SequenceComplete_In_Print(SequenceComplete_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_SequenceComplete\n", indent, "");
    TSS_TPM_HANDLE_Print("sequenceHandle", in->sequenceHandle, indent);
    TSS_TPM2B_Print("buffer", indent, &in->buffer.b);
    TSS_TPM_HANDLE_Print("hierarchy", in->hierarchy, indent);
    return;
}
void SequenceUpdate_In_Print(SequenceUpdate_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_SequenceUpdate\n", indent, "");
    TSS_TPM_HANDLE_Print("sequenceHandle", in->sequenceHandle, indent);
    TSS_TPM2B_Print("buffer", indent, &in->buffer.b);
    return;
}
void SetAlgorithmSet_In_Print(SetAlgorithmSet_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_SetAlgorithmSet\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    printf("%*s" "algorithmSet %08x\n", indent, "", in->algorithmSet);
    return;
}
void SetCommandCodeAuditStatus_In_Print(SetCommandCodeAuditStatus_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_SetCommandCodeAuditStatus\n", indent, "");
    TSS_TPM_HANDLE_Print("auth", in->auth, indent);
    TSS_TPM_ALG_ID_Print("auditAlg", in->auditAlg, indent);
    TSS_TPML_CC_Print(&in->setList, indent);
    TSS_TPML_CC_Print(&in->clearList, indent);
    return;
}
void SetPrimaryPolicy_In_Print(SetPrimaryPolicy_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_SetPrimaryPolicy\n", indent, "");
    TSS_TPM_HANDLE_Print("authHandle", in->authHandle, indent);
    TSS_TPM2B_Print("authPolicy", indent, &in->authPolicy.b);
    TSS_TPM_ALG_ID_Print("hashAlg", in->hashAlg, indent);
    return;
}
void Shutdown_In_Print(Shutdown_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_Shutdown\n", indent, "");
    TSS_TPM_SU_Print("shutdownType", in->shutdownType, indent);
    return;
}
void Sign_In_Print(Sign_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_Sign\n", indent, "");
    TSS_TPM_HANDLE_Print("keyHandle", in->keyHandle, indent);
    TSS_TPM2B_Print("digest", indent, &in->digest.b);
    printf("%*s" "inScheme\n", indent, "");
    TSS_TPMT_SIG_SCHEME_Print(&in->inScheme, indent);
    printf("%*s" "validation\n", indent, "");
    TSS_TPMT_TK_HASHCHECK_Print(&in->validation, indent+2);
    return;
}
void StartAuthSession_In_Print(StartAuthSession_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_StartAuthSession\n", indent, "");
    TSS_TPM_HANDLE_Print("tpmKey", in->tpmKey, indent);
    TSS_TPM_HANDLE_Print("bind", in->bind, indent);
    TSS_TPM2B_Print("nonceCaller", indent, &in->nonceCaller.b);
    TSS_TPM2B_Print("encryptedSalt", indent, &in->encryptedSalt.b);
    TSS_TPM_SE_Print("sessionType", in->sessionType, indent);
    TSS_TPMT_SYM_DEF_Print(&in->symmetric, indent);
    TSS_TPM_ALG_ID_Print("authHash", in->authHash, indent);
    return;
}
void Startup_In_Print(Startup_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_Startup\n", indent, "");
    TSS_TPM_SU_Print("startupType", in->startupType, indent);
    return;
}
void StirRandom_In_Print(StirRandom_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_StirRandom\n", indent, "");
    TSS_TPM2B_Print("inData", indent, &in->inData.b);
    return;
}
void TestParms_In_Print(TestParms_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_TestParms\n", indent, "");
    TSS_TPMT_PUBLIC_PARMS_Print(&in->parameters, indent);
    return;
}
void Unseal_In_Print(Unseal_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_Unseal\n", indent, "");
    TSS_TPM_HANDLE_Print("itemHandle", in->itemHandle, indent);
    return;
}
void VerifySignature_In_Print(VerifySignature_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_VerifySignature\n", indent, "");
    TSS_TPM_HANDLE_Print("keyHandle", in->keyHandle, indent);
    TSS_TPM2B_Print("digest", indent, &in->digest.b);
    printf("%*s" "signature\n", indent, "");
    TSS_TPMT_SIGNATURE_Print(&in->signature, indent);
    return;
}
void ZGen_2Phase_In_Print(ZGen_2Phase_In *in, unsigned int indent)
{
    printf("%*s" "TPM2_ZGen_2Phase\n", indent, "");
    TSS_TPM_HANDLE_Print("keyA", in->keyA, indent);
    TSS_TPM2B_ECC_POINT_Print("inQsB", &in->inQsB, indent);
    TSS_TPM2B_ECC_POINT_Print("inQsB", &in->inQeB, indent);
    TSS_TPM_ALG_ID_Print("inScheme", in->inScheme, indent);
    printf("%*s" "counter %u\n", indent, "", in->counter);
    return;
}
