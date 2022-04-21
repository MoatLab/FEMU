/********************************************************************************/
/*										*/
/*			 TSS Marshal and Unmarshal    				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tssmarshal12.c 1285 2018-07-27 18:33:41Z kgoldman $		*/
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

#ifdef TPM_TPM12

#include <string.h>

#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsserror.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/Unmarshal12_fp.h>
#include <ibmtss/tssmarshal12.h>

/* The marshaling functions are slightly different from the TPM side.  The TPM assumes that all
   structures are trusted, and so has no error checking.  The TSS side makes no such assumption.

   The prototype pattern is:

   Return:

   An extra return code, TSS_RC_INSUFFICIENT_BUFFER, indicates that the supplied buffer size is too
   small.  The TPM functions assert.

   'source' is the structure to be marshaled, the same as the TPM functions.
   'written' is the __additional__ number of bytes written, the value that the TPM returns.
   'buffer' is the buffer written, the same as the TPM functions.
   ' size' is the remaining size of the buffer, the same as the TPM functions.

   If 'buffer' is NULL, 'written' is updated but no marshaling is performed.  This is used in a two
   pass pattern, where the first pass returns the size of the buffer to be malloc'ed.

   If 'size' is NULL, the source is unmarshaled without a size check.  The caller must ensure that
   the buffer is sufficient, often due to a malloc after the first pass.  */

/*Unmarshal
  Command parameter marshaling
*/

TPM_RC
TSS_ActivateIdentity_In_Marshalu(const ActivateIdentity_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->idKeyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->blobSize, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->blob, source->blobSize, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_CreateEndorsementKeyPair_In_Marshalu(const CreateEndorsementKeyPair_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->antiReplay, TPM_NONCE_SIZE, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_TPM_KEY_PARMS_Marshalu(&source->keyInfo, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_CreateWrapKey_In_Marshalu(const CreateWrapKey_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->parentHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->dataUsageAuth, SHA1_DIGEST_SIZE, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->dataMigrationAuth, SHA1_DIGEST_SIZE, written, buffer, size);	
    }
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Marshalu(&source->keyInfo, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_Extend_In_Marshalu(const Extend_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->pcrNum, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->inDigest, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_FlushSpecific_In_Marshalu(const FlushSpecific_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->handle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->resourceType, written, buffer, size);
    }
    return rc;
}						  

TPM_RC
TSS_GetCapability12_In_Marshalu(const GetCapability12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->capArea, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->subCapSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->subCap, source->subCapSize, written, buffer, size);	
    }
    return rc;
}						  

TPM_RC
TSS_LoadKey2_In_Marshalu(const LoadKey2_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->parentHandle, written, buffer, size);
    }
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Marshalu(&source->inKey, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_MakeIdentity_In_Marshalu(const MakeIdentity_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->identityAuth, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->labelPrivCADigest, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Marshalu(&source->idKeyParams, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_NV_DefineSpace12_In_Marshalu(const NV_DefineSpace12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_NV_DATA_PUBLIC_Marshalu(&source->pubInfo, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->encAuth, SHA1_DIGEST_SIZE, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_NV_ReadValueAuth_In_Marshalu(const NV_ReadValueAuth_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->nvIndex , written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->offset, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->dataSize, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_NV_ReadValue_In_Marshalu(const NV_ReadValue_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->nvIndex , written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->offset, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->dataSize, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_NV_WriteValue_In_Marshalu(const NV_WriteValue_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->nvIndex , written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->offset, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->dataSize, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->data, source->dataSize, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_NV_WriteValueAuth_In_Marshalu(const NV_WriteValueAuth_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->nvIndex , written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->offset, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->dataSize, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->data, source->dataSize, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_OwnerReadInternalPub_In_Marshalu(const OwnerReadInternalPub_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->keyHandle, written, buffer, size);
    }
    return rc;
}						  
 
TPM_RC
TSS_OwnerSetDisable_In_Marshalu(const OwnerSetDisable_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->disableState, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_OSAP_In_Marshalu(const OSAP_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->entityType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->entityValue, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->nonceOddOSAP, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    return rc;
}						  
 
TPM_RC
TSS_PcrRead12_In_Marshalu(const PcrRead12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->pcrIndex, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_PCR_Reset12_In_Marshalu(const PCR_Reset12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
    	rc = TSS_TPM_PCR_SELECTION_Marshalu(&source->pcrSelection, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_Quote2_In_Marshalu(const Quote2_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->externalData, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
    	rc = TSS_TPM_PCR_SELECTION_Marshalu(&source->targetPCR, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->addVersion, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_ReadPubek_In_Marshalu(const ReadPubek_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->antiReplay, TPM_NONCE_SIZE, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_Sign12_In_Marshalu(const Sign12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->areaToSignSize, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->areaToSign, source->areaToSignSize, written, buffer, size);	
    }
    return rc;
}

TPM_RC
TSS_Startup12_In_Marshalu(const Startup12_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_STARTUP_TYPE_Marshalu(&source->startupType, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TakeOwnership_In_Marshalu(const TakeOwnership_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->protocolID, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->encOwnerAuthSize, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->encOwnerAuth, source->encOwnerAuthSize, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->encSrkAuthSize, written, buffer, size);	
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->encSrkAuth, source->encSrkAuthSize, written, buffer, size);	
    }
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Marshalu(&source->srkParams, written, buffer, size);
    }
    return rc;
}

/*
  Response parameter unmarshaling
*/

TPM_RC
TSS_ActivateIdentity_Out_Unmarshalu(ActivateIdentity_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_TPM_SYMMETRIC_KEY_Unmarshalu(&target->symmetricKey, buffer, size);
    } 
    return rc;
}

TPM_RC
TSS_CreateEndorsementKeyPair_Out_Unmarshalu(CreateEndorsementKeyPair_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_TPM_PUBKEY_Unmarshalu(&target->pubEndorsementKey, buffer, size);
    } 
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->checksum, SHA1_DIGEST_SIZE, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_CreateWrapKey_Out_Unmarshalu(CreateWrapKey_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_TPM_KEY12_Unmarshalu(&target->wrappedKey, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_Extend_Out_Unmarshalu(Extend_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->outDigest, SHA1_DIGEST_SIZE, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_GetCapability12_Out_Unmarshalu(GetCapability12_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->respSize, buffer, size);
    }
    if (rc == 0) {
	if (target->respSize > sizeof(target->resp)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->resp, target->respSize, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_LoadKey2_Out_Unmarshalu(LoadKey2_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->inkeyHandle, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_MakeIdentity_Out_Unmarshalu(MakeIdentity_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Unmarshalu(&target->idKey, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->identityBindingSize, buffer, size);
    }
    if (rc == 0) {
	if (target->identityBindingSize > sizeof(target->identityBinding)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->identityBinding, target->identityBindingSize, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_NV_ReadValueAuth_Out_Unmarshalu(NV_ReadValueAuth_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->dataSize, buffer, size);
    }
    if (rc == 0) {
	if (target->dataSize > sizeof(target->data)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->data, target->dataSize, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_NV_ReadValue_Out_Unmarshalu(NV_ReadValue_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->dataSize, buffer, size);
    }
    if (rc == 0) {
	if (target->dataSize > sizeof(target->data)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->data, target->dataSize, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_OIAP_Out_Unmarshalu(OIAP_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->authHandle, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->nonceEven, SHA1_DIGEST_SIZE, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_OSAP_Out_Unmarshalu(OSAP_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->authHandle, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->nonceEven, SHA1_DIGEST_SIZE, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->nonceEvenOSAP, SHA1_DIGEST_SIZE, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_OwnerReadInternalPub_Out_Unmarshalu(OwnerReadInternalPub_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_TPM_PUBKEY_Unmarshalu(&target->publicPortion, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_PcrRead12_Out_Unmarshalu(PcrRead12_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->outDigest, SHA1_DIGEST_SIZE, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_Quote2_Out_Unmarshalu(Quote2_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
    	rc = TSS_TPM_PCR_INFO_SHORT_Unmarshalu(&target->pcrData, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->versionInfoSize, buffer, size);
    }
    if (rc == 0) {
    	rc = TSS_TPM_CAP_VERSION_INFO_Unmarshalu(&target->versionInfo, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->sigSize, buffer, size);
    }
    if (rc == 0) {
	if (target->sigSize > sizeof(target->sig)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->sig, target->sigSize, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_Sign12_Out_Unmarshalu(Sign12_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->sigSize, buffer, size);
    }
    if (rc == 0) {
	if (target->sigSize > sizeof(target->sig)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->sig, target->sigSize, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_ReadPubek_Out_Unmarshalu(ReadPubek_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
    	rc = TSS_TPM_PUBKEY_Unmarshalu(&target->pubEndorsementKey, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->checksum, SHA1_DIGEST_SIZE, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TakeOwnership_Out_Unmarshalu(TakeOwnership_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    tag = tag;
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Unmarshalu(&target->srkPub, buffer, size);
    }
    return rc;
}

/*
  Structure marshaling
*/

TPM_RC
TSS_TPM_STARTUP_TYPE_Marshalu(const TPM_STARTUP_TYPE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* 5.0 */


TPM_RC
TSS_TPM_VERSION_Marshalu(const TPM_VERSION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->major, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->minor, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->revMajor, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->revMinor, written, buffer, size);
    }
    return rc;
}

/* 8.0 */

TPM_RC
TSS_TPM_PCR_SELECTION_Marshalu(const TPM_PCR_SELECTION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{ 
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->sizeOfSelect, written, buffer, size);   
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->pcrSelect, source->sizeOfSelect, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPM_PCR_INFO_LONG_Marshalu(const TPM_PCR_INFO_LONG *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{ 
    TPM_RC rc = 0;
    if (rc == 0) {
	uint16_t tag = TPM_TAG_PCR_INFO_LONG;
	rc = TSS_UINT16_Marshalu(&tag, written, buffer, size);                      
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->localityAtCreation, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->localityAtRelease, written, buffer, size);   
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_SELECTION_Marshalu(&source->creationPCRSelection, written, buffer, size); 
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_SELECTION_Marshalu(&source->releasePCRSelection, written, buffer, size); 
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->digestAtCreation, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->digestAtRelease, SHA1_DIGEST_SIZE, written, buffer, size); 
    }
    return rc;
}

TPM_RC
TSS_TPM_PCR_INFO_SHORT_Marshalu(const TPM_PCR_INFO_SHORT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{ 
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_PCR_SELECTION_Marshalu(&source->pcrSelection, written, buffer, size); 
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->localityAtRelease, written, buffer, size);   
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->digestAtRelease, SHA1_DIGEST_SIZE, written, buffer, size); 
    }
    return rc;
}

TPM_RC
TSS_TPM4B_TPM_PCR_INFO_LONG_Marshalu(const TPM_PCR_INFO_LONG *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;

    if (buffer != NULL) {
	sizePtr = *buffer;
	*buffer += sizeof(uint32_t);	/* skip size */
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_INFO_LONG_Marshalu(source, &sizeWritten, buffer, size);
    }
    if (rc == 0) {
	uint32_t sizeWritten32;
	*written += sizeWritten;
	sizeWritten32 = sizeWritten;	/* back fill size */
	if (buffer != NULL) {
	    rc = TSS_UINT32_Marshalu(&sizeWritten32, written, &sizePtr, size);
	}
	else {
	    *written += sizeof(uint32_t);
	}
    }
    return rc;
}

/* 9.0 */

TPM_RC
TSS_TPM_SYMMETRIC_KEY_Marshalu(const TPM_SYMMETRIC_KEY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->algId, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->encScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->size, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->data, source->size, written, buffer, size);
    }
    return rc;
}

/* 10.0 */

TPM_RC
TSS_TPM_RSA_KEY_PARMS_Marshalu(const TPM_RSA_KEY_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->keyLength, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->numPrimes, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->exponentSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->exponent, source->exponentSize, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPMU_PARMS_Marshalu(const TPMU_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
      case TPM_ALG_RSA:		/* A structure of type TPM_RSA_KEY_PARMS */
	rc = TSS_TPM_RSA_KEY_PARMS_Marshalu(&source->rsaParms, written, buffer, size);
	break;
      case TPM_ALG_AES128:	/* A structure of type TPM_SYMMETRIC_KEY_PARMS */
	/* not implemented yet */
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

TPM_RC
TSS_TPM4B_TPMU_PARMS_Marshalu(const TPMU_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;

    if (buffer != NULL) {
	sizePtr = *buffer;
	*buffer += sizeof(uint32_t);	/* skip size */
    }
    if (rc == 0) {
	rc = TSS_TPMU_PARMS_Marshalu(source, &sizeWritten, buffer, size, selector);
    }
    if (rc == 0) {
	uint32_t sizeWritten32;
	*written += sizeWritten;
	sizeWritten32 = sizeWritten;	/* back fill size */
	if (buffer != NULL) {
	    rc = TSS_UINT32_Marshalu(&sizeWritten32, written, &sizePtr, size);
	}
	else {
	    *written += sizeof(uint32_t);
	}
    }
    return rc;
}

TPM_RC
TSS_TPM_KEY_PARMS_Marshalu(const TPM_KEY_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->algorithmID, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->encScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->sigScheme, written, buffer, size); 
    }
    if (rc == 0) {
	rc = TSS_TPM4B_TPMU_PARMS_Marshalu(&source->parms, written, buffer, size, source->algorithmID);	
    }
    return rc;
}

TPM_RC
TSS_TPM_STORE_PUBKEY_Marshalu(const TPM_STORE_PUBKEY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->keyLength, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->key, source->keyLength, written, buffer, size);
    }
    return rc;
}						  

TPM_RC
TSS_TPM_KEY12_PUBKEY_Marshalu(const TPM_KEY12 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_KEY_PARMS_Marshalu(&source->algorithmParms, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_STORE_PUBKEY_Marshalu(&source->pubKey, written, buffer, size);
    }
    return rc;
}						  

TPM_RC
TSS_TPM_PUBKEY_Marshalu(const TPM_PUBKEY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_KEY_PARMS_Marshalu(&source->algorithmParms, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_STORE_PUBKEY_Marshalu(&source->pubKey, written, buffer, size);
    }
    return rc;
}						  

TPM_RC
TSS_TPM_KEY12_Marshalu(const TPM_KEY12 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	uint16_t tag = TPM_TAG_KEY12;
	rc = TSS_UINT16_Marshalu(&tag, written, buffer, size);
    }
    if (rc == 0) {
	uint16_t fill = 0;
	rc = TSS_UINT16_Marshalu(&fill, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->keyUsage, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->keyFlags, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->authDataUsage, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_KEY_PARMS_Marshalu(&source->algorithmParms, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM4B_TPM_PCR_INFO_LONG_Marshalu(&source->PCRInfo, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_STORE_PUBKEY_Marshalu(&source->pubKey, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_STORE_PUBKEY_Marshalu(&source->encData, written, buffer, size);
    }
    return rc;
}

/* 11.0 */

TPM_RC
TSS_TPM_QUOTE_INFO2_Marshalu(const TPM_QUOTE_INFO2 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	uint16_t tag = TPM_TAG_QUOTE_INFO2;
	rc = TSS_UINT16_Marshalu(&tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->fixed, 4, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->externalData, TPM_NONCE_SIZE, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_INFO_SHORT_Marshalu(&source->infoShort, written, buffer, size);
    }
    return rc;
}

/* 12.0 */

TPM_RC
TSS_TPM_EK_BLOB_Marshalu(const TPM_EK_BLOB *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	uint16_t tag = TPM_TAG_EK_BLOB;
	rc = TSS_UINT16_Marshalu(&tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->ekType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->blobSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->blob, source->blobSize, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPM_EK_BLOB_ACTIVATE_Marshalu(const TPM_EK_BLOB_ACTIVATE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	uint16_t tag = TPM_TAG_EK_BLOB_ACTIVATE;
	rc = TSS_UINT16_Marshalu(&tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_SYMMETRIC_KEY_Marshalu(&source->sessionKey, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->idDigest, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_INFO_SHORT_Marshalu(&source->pcrInfo, written, buffer, size);
    }
    return rc;
}

/* 19.0 */

TPM_RC
TSS_TPM_NV_ATTRIBUTES_Marshalu(const TPM_NV_ATTRIBUTES *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0; 
    if (rc == 0) {
	uint16_t tag = TPM_TAG_NV_ATTRIBUTES;
	rc = TSS_UINT16_Marshalu(&tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->attributes, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPM_NV_DATA_PUBLIC_Marshalu(const TPM_NV_DATA_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	uint16_t tag = TPM_TAG_NV_DATA_PUBLIC;
	rc = TSS_UINT16_Marshalu(&tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_INFO_SHORT_Marshalu(&source->pcrInfoRead, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_INFO_SHORT_Marshalu(&source->pcrInfoWrite, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_NV_ATTRIBUTES_Marshalu(&source->permission, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->bReadSTClear, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->bWriteSTClear, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->bWriteDefine, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->dataSize, written, buffer, size);
    }
    return rc;
}

/* 21.0 */

TPM_RC
TSS_TPM_CAP_VERSION_INFO_Marshalu(const TPM_CAP_VERSION_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_VERSION_Marshalu(&source->version, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->specLevel, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->errataRev, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->tpmVendorID, 4, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->vendorSpecificSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->vendorSpecific, source->vendorSpecificSize, written, buffer, size);
    }
    return rc;
} ;

#endif		/* TPM_TPM12 */
