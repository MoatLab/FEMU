/********************************************************************************/
/*										*/
/*			 TSS Marshal and Unmarshal    				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tssmarshal12.h 1286 2018-07-27 19:20:16Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2018.						*/
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

#ifndef TSSMARSHAL12_H
#define TSSMARSHAL12_H

#include "BaseTypes.h"
#include <ibmtss/TPM_Types.h>

#include <ibmtss/Parameters12.h>
#include <ibmtss/tpmstructures12.h>

#ifdef __cplusplus
extern "C" {
#endif

    TPM_RC
    TSS_ActivateIdentity_In_Marshalu(const ActivateIdentity_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CreateEndorsementKeyPair_In_Marshalu(const CreateEndorsementKeyPair_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CreateWrapKey_In_Marshalu(const CreateWrapKey_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Extend_In_Marshalu(const Extend_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_FlushSpecific_In_Marshalu(const FlushSpecific_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_GetCapability12_In_Marshalu(const GetCapability12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_LoadKey2_In_Marshalu(const LoadKey2_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_MakeIdentity_In_Marshalu(const MakeIdentity_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_DefineSpace12_In_Marshalu(const NV_DefineSpace12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_ReadValueAuth_In_Marshalu(const NV_ReadValueAuth_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_ReadValue_In_Marshalu(const NV_ReadValue_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_WriteValue_In_Marshalu(const NV_WriteValue_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_WriteValueAuth_In_Marshalu(const NV_WriteValueAuth_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_OwnerReadInternalPub_In_Marshalu(const OwnerReadInternalPub_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_OwnerSetDisable_In_Marshalu(const OwnerSetDisable_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_OSAP_In_Marshalu(const OSAP_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PcrRead12_In_Marshalu(const PcrRead12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PCR_Reset12_In_Marshalu(const PCR_Reset12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Quote2_In_Marshalu(const Quote2_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ReadPubek_In_Marshalu(const ReadPubek_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Sign12_In_Marshalu(const Sign12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Startup12_In_Marshalu(const Startup12_In *source, UINT16 *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TakeOwnership_In_Marshalu(const TakeOwnership_In *source, uint16_t *written, BYTE **buffer, uint32_t *size);

    TPM_RC
    TSS_ActivateIdentity_Out_Unmarshalu(ActivateIdentity_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CreateEndorsementKeyPair_Out_Unmarshalu(CreateEndorsementKeyPair_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_CreateWrapKey_Out_Unmarshalu(CreateWrapKey_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Extend_Out_Unmarshalu(Extend_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_GetCapability12_Out_Unmarshalu(GetCapability12_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_LoadKey2_Out_Unmarshalu(LoadKey2_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_MakeIdentity_Out_Unmarshalu(MakeIdentity_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_ReadValueAuth_Out_Unmarshalu(NV_ReadValueAuth_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_NV_ReadValue_Out_Unmarshalu(NV_ReadValue_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_OIAP_Out_Unmarshalu(OIAP_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_OSAP_Out_Unmarshalu(OSAP_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_OwnerReadInternalPub_Out_Unmarshalu(OwnerReadInternalPub_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_PcrRead12_Out_Unmarshalu(PcrRead12_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Quote2_Out_Unmarshalu(Quote2_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_ReadPubek_Out_Unmarshalu(ReadPubek_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_Sign12_Out_Unmarshalu(Sign12_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TakeOwnership_Out_Unmarshalu(TakeOwnership_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size);

    TPM_RC
    TSS_TPM_STARTUP_TYPE_Marshalu(const TPM_STARTUP_TYPE *source, uint16_t *written, BYTE **buffer, uint32_t *size);

    TPM_RC
    TSS_TPM_VERSION_Marshalu(const TPM_VERSION*source, uint16_t *written, BYTE **buffer, uint32_t *size);

    TPM_RC
    TSS_TPM_PCR_SELECTION_Marshalu(const TPM_PCR_SELECTION *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_PCR_INFO_SHORT_Marshalu(const TPM_PCR_INFO_SHORT *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM4B_TPM_PCR_INFO_LONG_Marshalu(const TPM_PCR_INFO_LONG *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_PCR_INFO_LONG_Marshalu(const TPM_PCR_INFO_LONG *source, uint16_t *written, BYTE **buffer, uint32_t *size);

    TPM_RC
    TSS_TPM_SYMMETRIC_KEY_Marshalu(const TPM_SYMMETRIC_KEY *source, uint16_t *written, BYTE **buffer, uint32_t *size);

    TPM_RC
    TSS_TPM_RSA_KEY_PARMS_Marshalu(const TPM_RSA_KEY_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPMU_PARMS_Marshalu(const TPMU_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    TPM_RC
    TSS_TPM4B_TPMU_PARMS_Marshalu(const TPMU_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector);
    TPM_RC
    TSS_TPM_KEY_PARMS_Marshalu(const TPM_KEY_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_STORE_PUBKEY_Marshalu(const TPM_STORE_PUBKEY *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_KEY12_PUBKEY_Marshalu(const TPM_KEY12 *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_PUBKEY_Marshalu(const TPM_PUBKEY *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_KEY12_Marshalu(const TPM_KEY12 *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_QUOTE_INFO2_Marshalu(const TPM_QUOTE_INFO2 *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_EK_BLOB_Marshalu(const TPM_EK_BLOB *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_EK_BLOB_ACTIVATE_Marshalu(const TPM_EK_BLOB_ACTIVATE *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_NV_ATTRIBUTES_Marshalu(const TPM_NV_ATTRIBUTES *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_NV_DATA_PUBLIC_Marshalu(const TPM_NV_DATA_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_CAP_VERSION_INFO_Marshalu(const TPM_CAP_VERSION_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size);

#ifdef __cplusplus
}
#endif

#endif
