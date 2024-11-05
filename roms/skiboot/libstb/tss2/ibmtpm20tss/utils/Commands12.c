/********************************************************************************/
/*                                                                              */
/*                              	                                   	*/
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
/*            $Id: Commands12.c 1285 2018-07-27 18:33:41Z kgoldman $         	*/
/*                                                                              */
/* (c) Copyright IBM Corporation 2018						*/
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

#include "Commands12_fp.h"
#include <ibmtss/Parameters.h>

#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/Unmarshal12_fp.h>

COMMAND_PARAMETERS in;
RESPONSE_PARAMETERS out;

/*
  In_Unmarshal
*/

TPM_RC
ActivateIdentity_In_Unmarshal(ActivateIdentity_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;
    handles = handles;

    if (rc == 0) {
	target->idKeyHandle = handles[0];
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->blobSize, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    if (rc == 0) {
	if (target->blobSize > sizeof(target->blob)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->blob, target->blobSize, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_2);
	}
    }
    return rc;
}

TPM_RC
CreateEndorsementKeyPair_In_Unmarshal(CreateEndorsementKeyPair_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;
    handles = handles;

    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->antiReplay, TPM_NONCE_SIZE, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    if (rc == 0) {
	rc = TSS_TPM_KEY_PARMS_Unmarshalu(&target->keyInfo, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_2);
	}
    }
    return rc;
}

TPM_RC
CreateWrapKey_In_Unmarshal(CreateWrapKey_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;

    if (rc == 0) {
	target->parentHandle = handles[0];
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->dataUsageAuth, SHA1_DIGEST_SIZE, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->dataMigrationAuth, SHA1_DIGEST_SIZE, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_2);
	}
    }
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Unmarshalu(&target->keyInfo, buffer, size);
    	if (rc != 0) {
    	    rc += (TPM_RC_P + TPM_RC_3);
    	}
    }
    return rc;
}

TPM_RC
Extend_In_Unmarshal(Extend_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;
    if (rc == 0) {
	target->pcrNum = handles[0];
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->inDigest, SHA1_DIGEST_SIZE, buffer, size);
    	if (rc != 0) {
    	    rc += (TPM_RC_P + TPM_RC_1);
    	}
    }
    return rc;
}

TPM_RC
FlushSpecific_In_Unmarshal(FlushSpecific_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;
    if (rc == 0) {
	target->handle = handles[0];
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->resourceType, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    return rc;
}

TPM_RC
GetCapability12_In_Unmarshal(GetCapability12_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;
    handles = handles;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->capArea, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->subCapSize, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_2);
	}
    }
    if (rc == 0) {
	if (target->subCapSize > sizeof(target->subCap)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->subCap, target->subCapSize, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_3);
	}
    }
    return rc;
}

TPM_RC
LoadKey2_In_Unmarshal(LoadKey2_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;

    if (rc == 0) {
	target->parentHandle = handles[0];
    }
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Unmarshalu(&target->inKey, buffer, size);
    	if (rc != 0) {
    	    rc += (TPM_RC_P + TPM_RC_1);
    	}
    }
    return rc;
}

TPM_RC
MakeIdentity_In_Unmarshal(MakeIdentity_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;
    handles = handles;

    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->identityAuth, SHA1_DIGEST_SIZE, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->labelPrivCADigest, SHA1_DIGEST_SIZE, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_2);
	}
    }
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Unmarshalu(&target->idKeyParams, buffer, size);
    	if (rc != 0) {
    	    rc += (TPM_RC_P + TPM_RC_3);
    	}
    }
    return rc;
}

TPM_RC
NV_DefineSpace12_In_Unmarshal(NV_DefineSpace12_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;
    handles = handles;

    if (rc == 0) {
	rc = TSS_TPM_NV_DATA_PUBLIC_Unmarshalu(&target->pubInfo, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->encAuth, SHA1_DIGEST_SIZE, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_2);
	}
    }
    return rc;
}

TPM_RC
NV_ReadValueAuth_In_Unmarshal(NV_ReadValueAuth_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;

    if (rc == 0) {
	target->nvIndex = handles[0];
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->offset, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->dataSize, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_2);
	}
    }
    return rc;
}

TPM_RC
NV_ReadValue_In_Unmarshal(NV_ReadValue_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;

    if (rc == 0) {
	target->nvIndex = handles[0];
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->offset, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->dataSize, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_2);
	}
    }
    return rc;
}

TPM_RC
NV_WriteValue_In_Unmarshal(NV_WriteValue_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;

    if (rc == 0) {
	target->nvIndex = handles[0];
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->offset, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->dataSize, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_2);
	}
    }
    if (rc == 0) {
	if (target->dataSize > sizeof(target->data)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->data, target->dataSize, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_3);
	}
    }
    return rc;
}

TPM_RC
NV_WriteValueAuth_In_Unmarshal(NV_WriteValueAuth_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;

    if (rc == 0) {
	target->nvIndex = handles[0];
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->offset, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->dataSize, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_2);
	}
    }
    if (rc == 0) {
	if (target->dataSize > sizeof(target->data)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->data, target->dataSize, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_3);
	}
    }
    return rc;
}

TPM_RC
OSAP_In_Unmarshal(OSAP_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;
    handles = handles;

    if (rc == 0) {
	rc = TSS_UINT16_Unmarshalu(&target->entityType, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->entityValue, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_2);
	}
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->nonceOddOSAP, SHA1_DIGEST_SIZE, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_3);
	}
    }
    return rc;
}

TPM_RC
OwnerSetDisable_In_Unmarshal(OwnerSetDisable_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;
    handles = handles;

    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&target->disableState, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    return rc;
}

TPM_RC
OwnerReadInternalPub_In_Unmarshal(OwnerReadInternalPub_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;
    handles = handles;
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->keyHandle , buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    return rc;
}

TPM_RC
PcrRead12_In_Unmarshal(PcrRead12_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;
    buffer = buffer;
    size = size;

    if (rc == 0) {
	target->pcrIndex = handles[0];
    }
    return rc;
}

TPM_RC
PCR_Reset12_In_Unmarshal(PCR_Reset12_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;
    handles = handles;

    if (rc == 0) {
    	rc = TSS_TPM_PCR_SELECTION_Unmarshalu(&target->pcrSelection, buffer, size);
    	if (rc != 0) {
    	    rc += (TPM_RC_P + TPM_RC_1);
    	}
    }
    return rc;
}

TPM_RC
Quote2_In_Unmarshal(Quote2_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;

    if (rc == 0) {
	target->keyHandle = handles[0];
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->externalData, SHA1_DIGEST_SIZE, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    if (rc == 0) {
	rc = TSS_TPM_PCR_SELECTION_Unmarshalu(&target->targetPCR, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_2);
	}
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&target->addVersion, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_3);
	}
    }
    return rc;
}

TPM_RC
ReadPubek_In_Unmarshal(ReadPubek_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;
    handles = handles;

    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->antiReplay, TPM_NONCE_SIZE, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    return rc;
}

TPM_RC
Sign12_In_Unmarshal(Sign12_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;

    if (rc == 0) {
	target->keyHandle = handles[0];
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->areaToSignSize, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    if (rc == 0) {
	if (target->areaToSignSize > sizeof(target->areaToSign)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->areaToSign, target->areaToSignSize, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_2);
	}
    }
    return rc;
}

TPM_RC
Startup12_In_Unmarshal(Startup12_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;
    handles = handles;

    if (rc == 0) {
	rc = TSS_TPM_STARTUP_TYPE_Unmarshalu(&target->startupType, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
    return rc;
}

TPM_RC
TakeOwnership_In_Unmarshal(TakeOwnership_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = 0;
    handles = handles;

   if (rc == 0) {
	rc = TSS_UINT16_Unmarshalu(&target->protocolID, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_1);
	}
    }
   if (rc == 0) {
       rc = TSS_UINT32_Unmarshalu(&target->encOwnerAuthSize, buffer, size);	
       if (rc != 0) {	
	   rc += (TPM_RC_P + TPM_RC_1);
       }
   }
     if (rc == 0) {
	 if (target->encOwnerAuthSize > sizeof(target->encOwnerAuth)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->encOwnerAuth, target->encOwnerAuthSize , buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_2);
	}
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->encSrkAuthSize, buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_3);
	}
    }
    if (rc == 0) {
	if (target->encSrkAuthSize > sizeof(target->encSrkAuth)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(target->encSrkAuth, target->encSrkAuthSize , buffer, size);	
	if (rc != 0) {	
	    rc += (TPM_RC_P + TPM_RC_4);
	}
    }
    if (rc == 0) {
    	rc = TSS_TPM_KEY12_Unmarshalu(&target->srkParams, buffer, size);
    	if (rc != 0) {
    	    rc += (TPM_RC_P + TPM_RC_5);
    	}
    }
    return rc;
}

