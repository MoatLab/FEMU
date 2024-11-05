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

#include <string.h>

#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsserror.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/Unmarshal_fp.h>

/* This file holds:

   ---------------------------------------

   Recommended functions - with an unsigned size

   * Primary marshal functions             TSS_primary_Marshalu
   * Primary unmarshal functions           TSS_primary_Unmarshalu  in Unmarshal.c
   * TPM 2.0 structure   marshal functions TSS_structure_Marshalu
   * TPM 2.0 structure unmarshal functions TSS_structure_Unmarshalu in Unmarshal.c
   * TPM 2.0 command     marshal functions TSS_command_In_Marshalu
     TPM 2.0 command   unmarshal functions command_In_Unmarshal 
   * TPM 2.0 response  unmarshal functions TSS_response_Out_Unmarshalu

   ---------------------------------------

   Deprecated functions - with a signed size

   * Primary   marshal functions           TSS_primary_Marshal
   * Primary unmarshal functions           primary_Unmarshal       in Unmarshal.c
   * TPM 2.0 structure   marshal functions TSS_structure_Marshal
   * TPM 2.0 structure unmarshal functions structure_Unmarshal     in Unmarshal.c
   * TPM 2.0 command     marshal functions TSS_command_In_Marshal
   * TPM 2.0 response  unmarshal functions TSS_response_Out_Unmarshal

   * are exposed in /tss2/
*/

/* The marshaling function prototype pattern is:

   Return:

   An extra return code, TSS_RC_INSUFFICIENT_BUFFER, indicates that the supplied buffer size is too
   small.  The TPM functions assert.

   'source' is the structure to be marshaled.
   'written' is the __additional__ number of bytes written.
   'buffer' is the buffer written.
   ' size' is the remaining size of the buffer.

   If 'buffer' is NULL, 'written' is updated but no marshaling is performed.  This is used in a two
   pass pattern, where the first pass returns the size of the buffer to be malloc'ed.

   If 'size' is NULL, the source is marshaled without a size check.  The caller must ensure that
   the buffer is sufficient, often due to a malloc after the first pass.  */

/* Marshal functions shared by TPM 1.2 and TPM 2.0 */

/* The functions with the _Marshalu suffix are preferred.  They use an unsigned size.  The functions
   with _Marshalu are deprecated.  */

TPM_RC
TSS_UINT8_Marshalu(const UINT8 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {	/* if buffer is NULL, don't marshal, just return written */
	/* if size is NULL, ignore it, else check sufficient */
	if ((size == NULL) || (*size >= sizeof(UINT8))) {
	    /* marshal, move the buffer */
	    (*buffer)[0] = *source;
	    *buffer += sizeof(UINT8);
	    /* is size was supplied, update it */
	    if (size != NULL) {
		*size -= sizeof(UINT8);
	    }
	}
	else {
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    *written += sizeof(UINT8);
    return rc;
}
    
TPM_RC
TSS_INT8_Marshalu(const INT8 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    rc = TSS_UINT8_Marshalu((const UINT8 *)source, written, buffer, size);
    return rc;
}

TPM_RC
TSS_UINT16_Marshalu(const UINT16 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {
	if ((size == NULL) || (*size >= sizeof(uint16_t))) {

	    (*buffer)[0] = (BYTE)((*source >> 8) & 0xff);
	    (*buffer)[1] = (BYTE)((*source >> 0) & 0xff);
	    *buffer += sizeof(uint16_t);

	    if (size != NULL) {
		*size -= sizeof(uint16_t);
	    }
	}
	else {
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    *written += sizeof(uint16_t);
    return rc;
}

TPM_RC
TSS_UINT32_Marshalu(const UINT32 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {
	if ((size == NULL) || (*size >= sizeof(uint32_t))) {

	    (*buffer)[0] = (BYTE)((*source >> 24) & 0xff);
	    (*buffer)[1] = (BYTE)((*source >> 16) & 0xff);
	    (*buffer)[2] = (BYTE)((*source >>  8) & 0xff);
	    (*buffer)[3] = (BYTE)((*source >>  0) & 0xff);
	    *buffer += sizeof(uint32_t);

	    if (size != NULL) {
		*size -= sizeof(uint32_t);
	    }
	}
	else {
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    *written += sizeof(uint32_t);
    return rc;
}

TPM_RC
TSS_INT32_Marshalu(const INT32 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    rc = TSS_UINT32_Marshalu((const UINT32 *)source, written, buffer, size);
    return rc;
}

TPM_RC
TSS_UINT64_Marshalu(const UINT64 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {
	if ((size == NULL) || (*size >= sizeof(UINT64))) {

	    (*buffer)[0] = (BYTE)((*source >> 56) & 0xff);
	    (*buffer)[1] = (BYTE)((*source >> 48) & 0xff);
	    (*buffer)[2] = (BYTE)((*source >> 40) & 0xff);
	    (*buffer)[3] = (BYTE)((*source >> 32) & 0xff);
	    (*buffer)[4] = (BYTE)((*source >> 24) & 0xff);
	    (*buffer)[5] = (BYTE)((*source >> 16) & 0xff);
	    (*buffer)[6] = (BYTE)((*source >>  8) & 0xff);
	    (*buffer)[7] = (BYTE)((*source >>  0) & 0xff);
	    *buffer += sizeof(UINT64);

	    if (size != NULL) {
		*size -= sizeof(UINT64);
	    }
	}
	else {
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    *written += sizeof(UINT64);
    return rc;
}

TPM_RC
TSS_Array_Marshalu(const BYTE *source, uint16_t sourceSize, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {
	if ((size == NULL) || (*size >= sourceSize)) {
	    memcpy(*buffer, source, sourceSize);

	    *buffer += sourceSize;

	    if (size != NULL) {
		*size -= sourceSize;
	    }
	}
	else {
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    *written += sourceSize;
    return rc;
}


#ifdef TPM_TPM20

/*
  TPM 2.0 Command parameter marshaling
*/

TPM_RC
TSS_Startup_In_Marshalu(const Startup_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_SU_Marshalu(&source->startupType, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Shutdown_In_Marshalu(const Shutdown_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_SU_Marshalu(&source->shutdownType, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_SelfTest_In_Marshalu(const SelfTest_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshalu(&source->fullTest, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_IncrementalSelfTest_In_Marshalu(const IncrementalSelfTest_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPML_ALG_Marshalu(&source->toTest, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_StartAuthSession_In_Marshalu(const StartAuthSession_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->tpmKey, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_ENTITY_Marshalu(&source->bind, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshalu(&source->nonceCaller, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Marshalu(&source->encryptedSalt, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_SE_Marshalu(&source->sessionType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SYM_DEF_Marshalu(&source->symmetric, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->authHash, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyRestart_In_Marshalu(const PolicyRestart_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->sessionHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Create_In_Marshalu(const Create_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->parentHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_SENSITIVE_CREATE_Marshalu(&source->inSensitive, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_Marshalu(&source->inPublic, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->outsideInfo, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshalu(&source->creationPCR, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Load_In_Marshalu(const Load_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->parentHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PRIVATE_Marshalu(&source->inPrivate, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_Marshalu(&source->inPublic, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_LoadExternal_In_Marshalu(const LoadExternal_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	/* optional parameter, use size as flag */
	if (source->inPrivate.b.size == 0) {		/* not present */
	    uint16_t zero = 0;
	    rc = TSS_UINT16_Marshalu(&zero, written, buffer, size);
	}
	else {
	    rc = TSS_TPM2B_SENSITIVE_Marshalu(&source->inPrivate, written, buffer, size);
	}
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_Marshalu(&source->inPublic, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshalu(&source->hierarchy, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ReadPublic_In_Marshalu(const ReadPublic_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->objectHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ActivateCredential_In_Marshalu(const ActivateCredential_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->activateHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ID_OBJECT_Marshalu(&source->credentialBlob, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Marshalu(&source->secret, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_MakeCredential_In_Marshalu(const MakeCredential_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->handle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->credential, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshalu(&source->objectName, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Unseal_In_Marshalu(const Unseal_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->itemHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ObjectChangeAuth_In_Marshalu(const ObjectChangeAuth_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->objectHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->parentHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshalu(&source->newAuth, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_CreateLoaded_In_Marshalu(const CreateLoaded_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->parentHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_SENSITIVE_CREATE_Marshalu(&source->inSensitive, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_TEMPLATE_Marshalu(&source->inPublic, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Duplicate_In_Marshalu(const Duplicate_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->objectHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->newParentHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->encryptionKeyIn, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Marshalu(&source->symmetricAlg, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Rewrap_In_Marshalu(const Rewrap_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->oldParent, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->newParent, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PRIVATE_Marshalu(&source->inDuplicate, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshalu(&source->name, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Marshalu(&source->inSymSeed, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Import_In_Marshalu(const Import_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->parentHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->encryptionKey, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_Marshalu(&source->objectPublic, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PRIVATE_Marshalu(&source->duplicate, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Marshalu(&source->inSymSeed, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Marshalu(&source->symmetricAlg, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_RSA_Encrypt_In_Marshalu(const RSA_Encrypt_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_KEY_RSA_Marshalu(&source->message, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_RSA_DECRYPT_Marshalu(&source->inScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->label, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_RSA_Decrypt_In_Marshalu(const RSA_Decrypt_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_KEY_RSA_Marshalu(&source->cipherText, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_RSA_DECRYPT_Marshalu(&source->inScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->label, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ECDH_KeyGen_In_Marshalu(const ECDH_KeyGen_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->keyHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ECDH_ZGen_In_Marshalu(const ECDH_ZGen_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_POINT_Marshalu(&source->inPoint, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ECC_Parameters_In_Marshalu(const ECC_Parameters_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ECC_CURVE_Marshalu(&source->curveID, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ZGen_2Phase_In_Marshalu(const ZGen_2Phase_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->keyA, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_POINT_Marshalu(&source->inQsB, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_POINT_Marshalu(&source->inQeB, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ECC_KEY_EXCHANGE_Marshalu(&source->inScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->counter, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EncryptDecrypt_In_Marshalu(const EncryptDecrypt_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshalu(&source->decrypt, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_CIPHER_MODE_Marshalu(&source->mode, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_IV_Marshalu(&source->ivIn, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_BUFFER_Marshalu(&source->inData, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EncryptDecrypt2_In_Marshalu(const EncryptDecrypt2_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_BUFFER_Marshalu(&source->inData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshalu(&source->decrypt, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_CIPHER_MODE_Marshalu(&source->mode, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_IV_Marshalu(&source->ivIn, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Hash_In_Marshalu(const Hash_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_BUFFER_Marshalu(&source->data, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->hashAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshalu(&source->hierarchy, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_HMAC_In_Marshalu(const HMAC_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->handle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_BUFFER_Marshalu(&source->buffer, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->hashAlg, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetRandom_In_Marshalu(const GetRandom_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->bytesRequested, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_StirRandom_In_Marshalu(const StirRandom_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_SENSITIVE_DATA_Marshalu(&source->inData, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_HMAC_Start_In_Marshalu(const HMAC_Start_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->handle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshalu(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->hashAlg, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_HashSequenceStart_In_Marshalu(const HashSequenceStart_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshalu(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->hashAlg, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_SequenceUpdate_In_Marshalu(const SequenceUpdate_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->sequenceHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_BUFFER_Marshalu(&source->buffer, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_SequenceComplete_In_Marshalu(const SequenceComplete_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->sequenceHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_BUFFER_Marshalu(&source->buffer, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshalu(&source->hierarchy, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EventSequenceComplete_In_Marshalu(const EventSequenceComplete_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_PCR_Marshalu(&source->pcrHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->sequenceHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_BUFFER_Marshalu(&source->buffer, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Certify_In_Marshalu(const Certify_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->objectHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->qualifyingData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshalu(&source->inScheme, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_CertifyCreation_In_Marshalu(const CertifyCreation_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->objectHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->qualifyingData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->creationHash, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshalu(&source->inScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_TK_CREATION_Marshalu(&source->creationTicket, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_CertifyX509_In_Marshalu(const CertifyX509_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->objectHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->reserved, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshalu(&source->inScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_BUFFER_Marshalu(&source->partialCertificate, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Quote_In_Marshalu(const Quote_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->qualifyingData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshalu(&source->inScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshalu(&source->PCRselect, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetSessionAuditDigest_In_Marshalu(const GetSessionAuditDigest_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_ENDORSEMENT_Marshalu(&source->privacyAdminHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_SH_HMAC_Marshalu(&source->sessionHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->qualifyingData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshalu(&source->inScheme, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetCommandAuditDigest_In_Marshalu(const GetCommandAuditDigest_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_ENDORSEMENT_Marshalu(&source->privacyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->qualifyingData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshalu(&source->inScheme, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetTime_In_Marshalu(const GetTime_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_ENDORSEMENT_Marshalu(&source->privacyAdminHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->qualifyingData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshalu(&source->inScheme, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Commit_In_Marshalu(const Commit_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_POINT_Marshalu(&source->P1, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_SENSITIVE_DATA_Marshalu(&source->s2, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshalu(&source->y2, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EC_Ephemeral_In_Marshalu(const EC_Ephemeral_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ECC_CURVE_Marshalu(&source->curveID, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_VerifySignature_In_Marshalu(const VerifySignature_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->digest, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIGNATURE_Marshalu(&source->signature, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Sign_In_Marshalu(const Sign_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->keyHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->digest, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshalu(&source->inScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_TK_HASHCHECK_Marshalu(&source->validation, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_SetCommandCodeAuditStatus_In_Marshalu(const SetCommandCodeAuditStatus_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PROVISION_Marshalu(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->auditAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_CC_Marshalu(&source->setList, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_CC_Marshalu(&source->clearList, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_Extend_In_Marshalu(const PCR_Extend_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_PCR_Marshalu(&source->pcrHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_VALUES_Marshalu(&source->digests, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_Event_In_Marshalu(const PCR_Event_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_PCR_Marshalu(&source->pcrHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_EVENT_Marshalu(&source->eventData, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_Read_In_Marshalu(const PCR_Read_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshalu(&source->pcrSelectionIn, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_Allocate_In_Marshalu(const PCR_Allocate_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PLATFORM_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshalu(&source->pcrAllocation, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_SetAuthPolicy_In_Marshalu(const PCR_SetAuthPolicy_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PLATFORM_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->authPolicy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->hashAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_PCR_Marshalu(&source->pcrNum, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_SetAuthValue_In_Marshalu(const PCR_SetAuthValue_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_PCR_Marshalu(&source->pcrHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->auth, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_Reset_In_Marshalu(const PCR_Reset_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_PCR_Marshalu(&source->pcrHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicySigned_In_Marshalu(const PolicySigned_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->authObject, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshalu(&source->nonceTPM, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->cpHashA, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshalu(&source->policyRef, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_INT32_Marshalu(&source->expiration, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIGNATURE_Marshalu(&source->auth, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicySecret_In_Marshalu(const PolicySecret_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_ENTITY_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshalu(&source->nonceTPM, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->cpHashA, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshalu(&source->policyRef, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_INT32_Marshalu(&source->expiration, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyTicket_In_Marshalu(const PolicyTicket_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_TIMEOUT_Marshalu(&source->timeout, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->cpHashA, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshalu(&source->policyRef, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshalu(&source->authName, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_TK_AUTH_Marshalu(&source->ticket, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyOR_In_Marshalu(const PolicyOR_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_Marshalu(&source->pHashList, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyPCR_In_Marshalu(const PolicyPCR_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->pcrDigest, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshalu(&source->pcrs, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyLocality_In_Marshalu(const PolicyLocality_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMA_LOCALITY_Marshalu(&source->locality, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyNV_In_Marshalu(const PolicyNV_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshalu(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_OPERAND_Marshalu(&source->operandB, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->offset, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_EO_Marshalu(&source->operation, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyCounterTimer_In_Marshalu(const PolicyCounterTimer_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_OPERAND_Marshalu(&source->operandB, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->offset, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_EO_Marshalu(&source->operation, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyCommandCode_In_Marshalu(const PolicyCommandCode_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_CC_Marshalu(&source->code, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyPhysicalPresence_In_Marshalu(const PolicyPhysicalPresence_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyCpHash_In_Marshalu(const PolicyCpHash_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->cpHashA, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyNameHash_In_Marshalu(const PolicyNameHash_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->nameHash, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyDuplicationSelect_In_Marshalu(const PolicyDuplicationSelect_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshalu(&source->objectName, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshalu(&source->newParentName, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshalu(&source->includeObject, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyAuthorize_In_Marshalu(const PolicyAuthorize_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->approvedPolicy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshalu(&source->policyRef, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshalu(&source->keySign, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_TK_VERIFIED_Marshalu(&source->checkTicket, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyAuthValue_In_Marshalu(const PolicyAuthValue_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyPassword_In_Marshalu(const PolicyPassword_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyGetDigest_In_Marshalu(const PolicyGetDigest_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyNvWritten_In_Marshalu(const PolicyNvWritten_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshalu(&source->writtenSet, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyTemplate_In_Marshalu(const PolicyTemplate_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->templateHash, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyAuthorizeNV_In_Marshalu(const PolicyAuthorizeNV_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshalu(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_SH_POLICY_Marshalu(&source->policySession, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_CreatePrimary_In_Marshalu(const CreatePrimary_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshalu(&source->primaryHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_SENSITIVE_CREATE_Marshalu(&source->inSensitive, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_Marshalu(&source->inPublic, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->outsideInfo, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshalu(&source->creationPCR, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_HierarchyControl_In_Marshalu(const HierarchyControl_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_ENABLES_Marshalu(&source->enable, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshalu(&source->state, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_SetPrimaryPolicy_In_Marshalu(const SetPrimaryPolicy_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_POLICY_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->authPolicy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->hashAlg, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ChangePPS_In_Marshalu(const ChangePPS_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PLATFORM_Marshalu(&source->authHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ChangeEPS_In_Marshalu(const ChangeEPS_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PLATFORM_Marshalu(&source->authHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Clear_In_Marshalu(const Clear_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_CLEAR_Marshalu(&source->authHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ClearControl_In_Marshalu(const ClearControl_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_CLEAR_Marshalu(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshalu(&source->disable, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_HierarchyChangeAuth_In_Marshalu(const HierarchyChangeAuth_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_AUTH_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshalu(&source->newAuth, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_DictionaryAttackLockReset_In_Marshalu(const DictionaryAttackLockReset_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_LOCKOUT_Marshalu(&source->lockHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_DictionaryAttackParameters_In_Marshalu(const DictionaryAttackParameters_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_LOCKOUT_Marshalu(&source->lockHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->newMaxTries, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->newRecoveryTime, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->lockoutRecovery, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PP_Commands_In_Marshalu(const PP_Commands_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PLATFORM_Marshalu(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_CC_Marshalu(&source->setList, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_CC_Marshalu(&source->clearList, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_SetAlgorithmSet_In_Marshalu(const SetAlgorithmSet_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PLATFORM_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->algorithmSet, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ContextSave_In_Marshalu(const ContextSave_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_CONTEXT_Marshalu(&source->saveHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ContextLoad_In_Marshalu(const ContextLoad_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_CONTEXT_Marshalu(&source->context, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_FlushContext_In_Marshalu(const FlushContext_In *source, uint16_t *written, BYTE **buffer, uint32_t *size) 
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_CONTEXT_Marshalu(&source->flushHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EvictControl_In_Marshalu(const EvictControl_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PROVISION_Marshalu(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->objectHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_PERSISTENT_Marshalu(&source->persistentHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ClockSet_In_Marshalu(const ClockSet_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PROVISION_Marshalu(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT64_Marshalu(&source->newTime, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ClockRateAdjust_In_Marshalu(const ClockRateAdjust_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PROVISION_Marshalu(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_CLOCK_ADJUST_Marshalu(&source->rateAdjust, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetCapability_In_Marshalu(const GetCapability_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_CAP_Marshalu(&source->capability, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->property, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->propertyCount, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TestParms_In_Marshalu(const TestParms_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMT_PUBLIC_PARMS_Marshalu(&source->parameters, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_DefineSpace_In_Marshalu(const NV_DefineSpace_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PROVISION_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshalu(&source->auth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NV_PUBLIC_Marshalu(&source->publicInfo, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_UndefineSpace_In_Marshalu(const NV_UndefineSpace_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PROVISION_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshalu(&source->nvIndex, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_UndefineSpaceSpecial_In_Marshalu(const NV_UndefineSpaceSpecial_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshalu(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_PLATFORM_Marshalu(&source->platform, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_ReadPublic_In_Marshalu(const NV_ReadPublic_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshalu(&source->nvIndex, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_Write_In_Marshalu(const NV_Write_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshalu(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_NV_BUFFER_Marshalu(&source->data, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->offset, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_Increment_In_Marshalu(const NV_Increment_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshalu(&source->nvIndex, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_Extend_In_Marshalu(const NV_Extend_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshalu(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_NV_BUFFER_Marshalu(&source->data, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_SetBits_In_Marshalu(const NV_SetBits_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshalu(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT64_Marshalu(&source->bits, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_WriteLock_In_Marshalu(const NV_WriteLock_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshalu(&source->nvIndex, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_GlobalWriteLock_In_Marshalu(const NV_GlobalWriteLock_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_PROVISION_Marshalu(&source->authHandle, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_Read_In_Marshalu(const NV_Read_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshalu(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->size, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->offset, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_ReadLock_In_Marshalu(const NV_ReadLock_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshalu(&source->nvIndex, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_ChangeAuth_In_Marshalu(const NV_ChangeAuth_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshalu(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshalu(&source->newAuth, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_Certify_In_Marshalu(const NV_Certify_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_DH_OBJECT_Marshalu(&source->signHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_AUTH_Marshalu(&source->authHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshalu(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->qualifyingData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SIG_SCHEME_Marshalu(&source->inScheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->size, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->offset, written, buffer, size);
    }
    return rc;
}

/*
  TPM 2.0 Response parameter unmarshaling
*/

TPM_RC
TSS_IncrementalSelfTest_Out_Unmarshalu(IncrementalSelfTest_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_ALG_Unmarshalu(&target->toDoList, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetTestResult_Out_Unmarshalu(GetTestResult_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    uint32_t parameterSize;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_MAX_BUFFER_Unmarshalu(&target->outData, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_RC_Unmarshalu(&target->testResult, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_StartAuthSession_Out_Unmarshalu(StartAuthSession_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_SH_AUTH_SESSION_Unmarshalu(&target->sessionHandle, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NONCE_Unmarshalu(&target->nonceTPM, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Create_Out_Unmarshalu(Create_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PRIVATE_Unmarshalu(&target->outPrivate, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PUBLIC_Unmarshalu(&target->outPublic, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_CREATION_DATA_Unmarshalu(&target->creationData, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->creationHash, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_TK_CREATION_Unmarshalu(&target->creationTicket, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Load_Out_Unmarshalu(Load_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(&target->objectHandle, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->name, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_LoadExternal_Out_Unmarshalu(LoadExternal_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(&target->objectHandle, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->name, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ReadPublic_Out_Unmarshalu(ReadPublic_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PUBLIC_Unmarshalu(&target->outPublic, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->name, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->qualifiedName, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ActivateCredential_Out_Unmarshalu(ActivateCredential_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->certInfo, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_MakeCredential_Out_Unmarshalu(MakeCredential_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ID_OBJECT_Unmarshalu(&target->credentialBlob, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Unmarshalu(&target->secret, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Unseal_Out_Unmarshalu(Unseal_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_SENSITIVE_DATA_Unmarshalu(&target->outData, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ObjectChangeAuth_Out_Unmarshalu(ObjectChangeAuth_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PRIVATE_Unmarshalu(&target->outPrivate, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_CreateLoaded_Out_Unmarshalu(CreateLoaded_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(&target->objectHandle, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PRIVATE_Unmarshalu(&target->outPrivate, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PUBLIC_Unmarshalu(&target->outPublic, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->name, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Duplicate_Out_Unmarshalu(Duplicate_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->encryptionKeyOut, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PRIVATE_Unmarshalu(&target->duplicate, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Unmarshalu(&target->outSymSeed, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Rewrap_Out_Unmarshalu(Rewrap_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PRIVATE_Unmarshalu(&target->outDuplicate, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Unmarshalu(&target->outSymSeed, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Import_Out_Unmarshalu(Import_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PRIVATE_Unmarshalu(&target->outPrivate, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_RSA_Encrypt_Out_Unmarshalu(RSA_Encrypt_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PUBLIC_KEY_RSA_Unmarshalu(&target->outData, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_RSA_Decrypt_Out_Unmarshalu(RSA_Decrypt_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PUBLIC_KEY_RSA_Unmarshalu(&target->message, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ECDH_KeyGen_Out_Unmarshalu(ECDH_KeyGen_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_POINT_Unmarshalu(&target->zPoint, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_POINT_Unmarshalu(&target->pubPoint, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ECDH_ZGen_Out_Unmarshalu(ECDH_ZGen_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_POINT_Unmarshalu(&target->outPoint, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ECC_Parameters_Out_Unmarshalu(ECC_Parameters_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_ALGORITHM_DETAIL_ECC_Unmarshalu(&target->parameters, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ZGen_2Phase_Out_Unmarshalu(ZGen_2Phase_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_POINT_Unmarshalu(&target->outZ1, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_POINT_Unmarshalu(&target->outZ2, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EncryptDecrypt_Out_Unmarshalu(EncryptDecrypt_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_MAX_BUFFER_Unmarshalu(&target->outData, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_IV_Unmarshalu(&target->ivOut, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EncryptDecrypt2_Out_Unmarshalu(EncryptDecrypt2_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    return TSS_EncryptDecrypt_Out_Unmarshalu((EncryptDecrypt_Out *)target, tag, buffer, size);
}
TPM_RC
TSS_Hash_Out_Unmarshalu(Hash_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->outHash, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_TK_HASHCHECK_Unmarshalu(&target->validation, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_HMAC_Out_Unmarshalu(HMAC_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->outHMAC, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetRandom_Out_Unmarshalu(GetRandom_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->randomBytes, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_HMAC_Start_Out_Unmarshalu(HMAC_Start_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_DH_OBJECT_Unmarshalu(&target->sequenceHandle, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    return rc;
}
TPM_RC
TSS_HashSequenceStart_Out_Unmarshalu(HashSequenceStart_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_DH_OBJECT_Unmarshalu(&target->sequenceHandle, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    return rc;
}
TPM_RC
TSS_SequenceComplete_Out_Unmarshalu(SequenceComplete_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->result, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_TK_HASHCHECK_Unmarshalu(&target->validation, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EventSequenceComplete_Out_Unmarshalu(EventSequenceComplete_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_DIGEST_VALUES_Unmarshalu(&target->results, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Certify_Out_Unmarshalu(Certify_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ATTEST_Unmarshalu(&target->certifyInfo, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIGNATURE_Unmarshalu(&target->signature, buffer, size, YES);
    }
    return rc;
}
TPM_RC
TSS_CertifyCreation_Out_Unmarshalu(CertifyCreation_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ATTEST_Unmarshalu(&target->certifyInfo, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIGNATURE_Unmarshalu(&target->signature, buffer, size, YES);
    }
    return rc;
}
TPM_RC
TSS_CertifyX509_Out_Unmarshalu(CertifyX509_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_MAX_BUFFER_Unmarshalu(&target->addedToCertificate, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->tbsDigest, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIGNATURE_Unmarshalu(&target->signature, buffer, size, YES);
    }
    return rc;
}
TPM_RC
TSS_Quote_Out_Unmarshalu(Quote_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ATTEST_Unmarshalu(&target->quoted, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIGNATURE_Unmarshalu(&target->signature, buffer, size, YES);
    }
    return rc;
}
TPM_RC
TSS_GetSessionAuditDigest_Out_Unmarshalu(GetSessionAuditDigest_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ATTEST_Unmarshalu(&target->auditInfo, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIGNATURE_Unmarshalu(&target->signature, buffer, size, YES);
    }
    return rc;
}
TPM_RC
TSS_GetCommandAuditDigest_Out_Unmarshalu(GetCommandAuditDigest_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ATTEST_Unmarshalu(&target->auditInfo, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIGNATURE_Unmarshalu(&target->signature, buffer, size, YES);
    }
    return rc;
}
TPM_RC
TSS_GetTime_Out_Unmarshalu(GetTime_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ATTEST_Unmarshalu(&target->timeInfo, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIGNATURE_Unmarshalu(&target->signature, buffer, size, YES);
    }
    return rc;
}
TPM_RC
TSS_Commit_Out_Unmarshalu(Commit_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_POINT_Unmarshalu(&target->K, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_POINT_Unmarshalu(&target->L, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_POINT_Unmarshalu(&target->E, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->counter, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_EC_Ephemeral_Out_Unmarshalu(EC_Ephemeral_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_POINT_Unmarshalu(&target->Q, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->counter, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_VerifySignature_Out_Unmarshalu(VerifySignature_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_TK_VERIFIED_Unmarshalu(&target->validation, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_Sign_Out_Unmarshalu(Sign_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIGNATURE_Unmarshalu(&target->signature, buffer, size, NO);
    }
    return rc;
}
TPM_RC
TSS_PCR_Event_Out_Unmarshalu(PCR_Event_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_DIGEST_VALUES_Unmarshalu(&target->digests, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PCR_Read_Out_Unmarshalu(PCR_Read_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->pcrUpdateCounter, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_PCR_SELECTION_Unmarshalu(&target->pcrSelectionOut, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_DIGEST_Unmarshalu(&target->pcrValues, buffer, size, 0);
    }
    return rc;
}
TPM_RC
TSS_PCR_Allocate_Out_Unmarshalu(PCR_Allocate_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_YES_NO_Unmarshalu(&target->allocationSuccess, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->maxPCR, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->sizeNeeded, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->sizeAvailable, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicySigned_Out_Unmarshalu(PolicySigned_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_TIMEOUT_Unmarshalu(&target->timeout, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_TK_AUTH_Unmarshalu(&target->policyTicket, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicySecret_Out_Unmarshalu(PolicySecret_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_TIMEOUT_Unmarshalu(&target->timeout, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_TK_AUTH_Unmarshalu(&target->policyTicket, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_PolicyGetDigest_Out_Unmarshalu(PolicyGetDigest_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->policyDigest, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_CreatePrimary_Out_Unmarshalu(CreatePrimary_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(&target->objectHandle, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PUBLIC_Unmarshalu(&target->outPublic, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_CREATION_DATA_Unmarshalu(&target->creationData, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->creationHash, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_TK_CREATION_Unmarshalu(&target->creationTicket, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->name, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ContextSave_Out_Unmarshalu(ContextSave_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_CONTEXT_Unmarshalu(&target->context, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_ContextLoad_Out_Unmarshalu(ContextLoad_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_DH_CONTEXT_Unmarshalu(&target->loadedHandle, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    return rc;
}
TPM_RC
TSS_ReadClock_Out_Unmarshalu(ReadClock_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_TIME_INFO_Unmarshalu(&target->currentTime, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_GetCapability_Out_Unmarshalu(GetCapability_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_YES_NO_Unmarshalu(&target->moreData, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_CAPABILITY_DATA_Unmarshalu(&target->capabilityData, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_ReadPublic_Out_Unmarshalu(NV_ReadPublic_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NV_PUBLIC_Unmarshalu(&target->nvPublic, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->nvName, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_Read_Out_Unmarshalu(NV_Read_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_MAX_NV_BUFFER_Unmarshalu(&target->data, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_NV_Certify_Out_Unmarshalu(NV_Certify_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t parameterSize = 0;
    if (rc == TPM_RC_SUCCESS) {
	if (tag == TPM_ST_SESSIONS) {
	    rc = TSS_UINT32_Unmarshalu(&parameterSize, buffer, size);
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ATTEST_Unmarshalu(&target->certifyInfo, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIGNATURE_Unmarshalu(&target->signature, buffer, size, YES);
    }
    return rc;
}

/*
  TPM 2.0 Structure marshaling
*/

TPM_RC
TSS_TPM2B_Marshalu(const TPM2B *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&(source->size), written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->buffer, source->size, written, buffer, size);
    }
    return rc;
}

/* Table 5 - Definition of Types for Documentation Clarity */

TPM_RC
TSS_TPM_KEY_BITS_Marshalu(const TPM_KEY_BITS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(source, written, buffer, size);
    }
    return rc;
}
   
/* Table 7 - Definition of (UINT32) TPM_GENERATED Constants <O> */

TPM_RC
TSS_TPM_GENERATED_Marshalu(const TPM_GENERATED *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(source, written, buffer, size);
    }
    return rc;
}
 
/* Table 9 - Definition of (UINT16) TPM_ALG_ID Constants <IN/OUT, S> */

TPM_RC
TSS_TPM_ALG_ID_Marshalu(const TPM_ALG_ID *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 10 - Definition of (uint16_t) {ECC} TPM_ECC_CURVE Constants <IN/OUT, S> */

#ifdef TPM_ALG_ECC
TPM_RC
TSS_TPM_ECC_CURVE_Marshalu(const TPM_ECC_CURVE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(source, written, buffer, size);
    }
    return rc;
}
#endif

/* Table 17 - Definition of (UINT32) TPM_RC Constants (Actions) <OUT> */

TPM_RC
TSS_TPM_RC_Marshalu(const TPM_RC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 18 - Definition of (INT8) TPM_CLOCK_ADJUST Constants <IN> */

TPM_RC
TSS_TPM_CLOCK_ADJUST_Marshalu(const TPM_CLOCK_ADJUST *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_INT8_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 19 - Definition of (UINT16) TPM_EO Constants <IN/OUT> */

TPM_RC
TSS_TPM_EO_Marshalu(const TPM_EO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 20 - Definition of (UINT16) TPM_ST Constants <IN/OUT, S> */

TPM_RC
TSS_TPM_ST_Marshalu(const TPM_ST *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(source, written, buffer, size);
    }
    return rc;
}
 
/* Table 21 - Definition of (UINT16) TPM_SU Constants <IN> */

TPM_RC
TSS_TPM_SU_Marshalu(const TPM_ST *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 22 - Definition of (UINT8) TPM_SE Constants <IN> */

TPM_RC
TSS_TPM_SE_Marshalu(const TPM_SE  *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 23 - Definition of (UINT32) TPM_CAP Constants  */

TPM_RC
TSS_TPM_CAP_Marshalu(const TPM_CAP *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 24 - Definition of (UINT32) TPM_PT Constants <IN/OUT, S> */

TPM_RC
TSS_TPM_PT_Marshalu(const TPM_PT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 25 - Definition of (UINT32) TPM_PT_PCR Constants <IN/OUT, S> */

TPM_RC
TSS_TPM_PT_PCR_Marshalu(const TPM_PT_PCR *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 27 - Definition of Types for Handles */

TPM_RC
TSS_TPM_HANDLE_Marshalu(const TPM_HANDLE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 31 - Definition of (UINT32) TPMA_ALGORITHM Bits */

TPM_RC
TSS_TPMA_ALGORITHM_Marshalu(const TPMA_ALGORITHM *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->val, written, buffer, size);
    }
    return rc;
}

/* Table 32 - Definition of (UINT32) TPMA_OBJECT Bits */

TPM_RC
TSS_TPMA_OBJECT_Marshalu(const TPMA_OBJECT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->val, written, buffer, size);
    }
    return rc;
}
 
/* Table 33 - Definition of (UINT8) TPMA_SESSION Bits <IN/OUT> */

TPM_RC
TSS_TPMA_SESSION_Marshalu(const TPMA_SESSION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->val, written, buffer, size);
    }
    return rc;
}

/* Table 34 - Definition of (UINT8) TPMA_LOCALITY Bits <IN/OUT> */

TPM_RC
TSS_TPMA_LOCALITY_Marshalu(const TPMA_LOCALITY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->val, written, buffer, size);
    }
    return rc;
}

/* Table 38 - Definition of (TPM_CC) TPMA_CC Bits <OUT> */

TPM_RC
TSS_TPM_CC_Marshalu(const TPM_CC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 38 - Definition of (TPM_CC) TPMA_CC Bits <OUT> */

TPM_RC
TSS_TPMA_CC_Marshalu(const TPMA_CC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->val, written, buffer, size);
    }
    return rc;
}

/* Table 39 - Definition of (BYTE) TPMI_YES_NO Type */

TPM_RC
TSS_TPMI_YES_NO_Marshalu(const TPMI_YES_NO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 40 - Definition of (TPM_HANDLE) TPMI_DH_OBJECT Type */

TPM_RC
TSS_TPMI_DH_OBJECT_Marshalu(const TPMI_DH_OBJECT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 41 - Definition of (TPM_HANDLE) TPMI_DH_PERSISTENT Type */

TPM_RC
TSS_TPMI_DH_PERSISTENT_Marshalu(const TPMI_DH_PERSISTENT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 42 - Definition of (TPM_HANDLE) TPMI_DH_ENTITY Type <IN> */

TPM_RC
TSS_TPMI_DH_ENTITY_Marshalu(const TPMI_DH_ENTITY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 43 - Definition of (TPM_HANDLE) TPMI_DH_PCR Type <IN> */

TPM_RC
TSS_TPMI_DH_PCR_Marshalu(const TPMI_DH_PCR  *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 44 - Definition of (TPM_HANDLE) TPMI_SH_AUTH_SESSION Type <IN/OUT> */

TPM_RC
TSS_TPMI_SH_AUTH_SESSION_Marshalu(const TPMI_SH_AUTH_SESSION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 45 - Definition of (TPM_HANDLE) TPMI_SH_HMAC Type <IN/OUT> */

TPM_RC
TSS_TPMI_SH_HMAC_Marshalu(const TPMI_SH_HMAC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 46 - Definition of (TPM_HANDLE) TPMI_SH_POLICY Type <IN/OUT> */

TPM_RC
TSS_TPMI_SH_POLICY_Marshalu(const TPMI_SH_POLICY*source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}
  
/* Table 47 - Definition of (TPM_HANDLE) TPMI_DH_CONTEXT Type  */

TPM_RC
TSS_TPMI_DH_CONTEXT_Marshalu(const TPMI_DH_CONTEXT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 49 - Definition of (TPM_HANDLE) TPMI_DH_SAVED Type  */

TPM_RC
TSS_TPMI_DH_SAVED_Marshalu(const TPMI_DH_SAVED *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 48 - Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY Type  */

TPM_RC
TSS_TPMI_RH_HIERARCHY_Marshalu(const TPMI_RH_HIERARCHY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}
   
/* Table 49 - Definition of (TPM_HANDLE) TPMI_RH_ENABLES Type */

TPM_RC
TSS_TPMI_RH_ENABLES_Marshalu(const TPMI_RH_ENABLES *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 50 - Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY_AUTH Type <IN> */

TPM_RC
TSS_TPMI_RH_HIERARCHY_AUTH_Marshalu(const TPMI_RH_HIERARCHY_AUTH *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 50 - Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY_POLICY Type <IN> */

TPM_RC
TSS_TPMI_RH_HIERARCHY_POLICY_Marshalu(const TPMI_RH_HIERARCHY_POLICY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 51 - Definition of (TPM_HANDLE) TPMI_RH_PLATFORM Type <IN> */

TPM_RC
TSS_TPMI_RH_PLATFORM_Marshalu(const TPMI_RH_PLATFORM *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 53 - Definition of (TPM_HANDLE) TPMI_RH_ENDORSEMENT Type <IN> */

TPM_RC
TSS_TPMI_RH_ENDORSEMENT_Marshalu(const TPMI_RH_ENDORSEMENT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 54 - Definition of (TPM_HANDLE) TPMI_RH_PROVISION Type <IN> */

TPM_RC
TSS_TPMI_RH_PROVISION_Marshalu(const TPMI_RH_PROVISION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 55 - Definition of (TPM_HANDLE) TPMI_RH_CLEAR Type <IN> */

TPM_RC
TSS_TPMI_RH_CLEAR_Marshalu(const TPMI_RH_CLEAR *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 56 - Definition of (TPM_HANDLE) TPMI_RH_NV_AUTH Type <IN> */

TPM_RC
TSS_TPMI_RH_NV_AUTH_Marshalu(const TPMI_RH_NV_AUTH *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 57 - Definition of (TPM_HANDLE) TPMI_RH_LOCKOUT Type <IN> */

TPM_RC
TSS_TPMI_RH_LOCKOUT_Marshalu(const TPMI_RH_LOCKOUT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 58 - Definition of (TPM_HANDLE) TPMI_RH_NV_INDEX Type <IN/OUT> */

TPM_RC
TSS_TPMI_RH_NV_INDEX_Marshalu(const TPMI_RH_NV_INDEX *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_HANDLE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 59 - Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type  */

TPM_RC
TSS_TPMI_ALG_HASH_Marshalu(const TPMI_ALG_HASH *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 61 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM Type */

TPM_RC
TSS_TPMI_ALG_SYM_Marshalu(const TPMI_ALG_SYM *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 62 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_OBJECT Type */

TPM_RC
TSS_TPMI_ALG_SYM_OBJECT_Marshalu(const TPMI_ALG_SYM_OBJECT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 63 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_MODE Type */

TPM_RC
TSS_TPMI_ALG_SYM_MODE_Marshalu(const TPMI_ALG_SYM_MODE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 64 - Definition of (TPM_ALG_ID) TPMI_ALG_KDF Type */

TPM_RC
TSS_TPMI_ALG_KDF_Marshalu(const TPMI_ALG_KDF *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 65 - Definition of (TPM_ALG_ID) TPMI_ALG_SIG_SCHEME Type */

TPM_RC
TSS_TPMI_ALG_SIG_SCHEME_Marshalu(const TPMI_ALG_SIG_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 66 - Definition of (TPM_ALG_ID) TPMI_ECC_KEY_EXCHANGE Type */

TPM_RC
TSS_TPMI_ECC_KEY_EXCHANGE_Marshalu(const TPMI_ECC_KEY_EXCHANGE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(source, written, buffer, size);
    }
    return rc;
} 

/* Table 67 - Definition of (TPM_ST) TPMI_ST_COMMAND_TAG Type */

TPM_RC
TSS_TPMI_ST_COMMAND_TAG_Marshalu(const TPMI_ST_COMMAND_TAG *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ST_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 71 - Definition of (TPM_ALG_ID) TPMI_ALG_MAC_SCHEME Type */

TPM_RC
TSS_TPMI_ALG_MAC_SCHEME_Marshalu(const TPMI_ALG_MAC_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size) 
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 72 - Definition of (TPM_ALG_ID) TPMI_ALG_CIPHER_MODE Type */

TPM_RC
TSS_TPMI_ALG_CIPHER_MODE_Marshalu(const TPMI_ALG_CIPHER_MODE *source, uint16_t *written, BYTE **buffer, uint32_t *size) 
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(source, written, buffer, size);
    }
    return rc;
} 

/* Table 70 - Definition of TPMU_HA Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_HA_Marshalu(const TPMU_HA *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    
    switch (selector) {
#ifdef TPM_ALG_SHA1
      case TPM_ALG_SHA1:
	if (rc == 0) {
	    rc = TSS_Array_Marshalu(&source->sha1[0], SHA1_DIGEST_SIZE, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SHA256
      case TPM_ALG_SHA256:
	if (rc == 0) {
	    rc = TSS_Array_Marshalu(&source->sha256[0], SHA256_DIGEST_SIZE, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SHA384
      case TPM_ALG_SHA384:
	if (rc == 0) {
	    rc = TSS_Array_Marshalu(&source->sha384[0], SHA384_DIGEST_SIZE, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SHA512
      case TPM_ALG_SHA512:
	if (rc == 0) {
	    rc = TSS_Array_Marshalu(&source->sha512[0], SHA512_DIGEST_SIZE, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SM3_256
      case TPM_ALG_SM3_256:
	if (rc == 0) {
	    rc = TSS_Array_Marshalu(&source->sm3_256[0], SM3_256_DIGEST_SIZE, written, buffer, size);
	}
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 71 - Definition of TPMT_HA Structure <IN/OUT> */

TPM_RC
TSS_TPMT_HA_Marshalu(const TPMT_HA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->hashAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_HA_Marshalu(&source->digest, written, buffer, size, source->hashAlg);
    }
    return rc;
}

/* Table 72 - Definition of TPM2B_DIGEST Structure */

TPM_RC
TSS_TPM2B_DIGEST_Marshalu(const TPM2B_DIGEST *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 73 - Definition of TPM2B_DATA Structure */

TPM_RC
TSS_TPM2B_DATA_Marshalu(const TPM2B_DATA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 74 - Definition of Types for TPM2B_NONCE */

TPM_RC
TSS_TPM2B_NONCE_Marshalu(const TPM2B_NONCE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 75 - Definition of Types for TPM2B_AUTH */

TPM_RC
TSS_TPM2B_AUTH_Marshalu(const TPM2B_AUTH *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 76 - Definition of Types for TPM2B_OPERAND */

TPM_RC
TSS_TPM2B_OPERAND_Marshalu(const TPM2B_OPERAND *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 77 - Definition of TPM2B_EVENT Structure */

TPM_RC
TSS_TPM2B_EVENT_Marshalu(const TPM2B_EVENT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 78 - Definition of TPM2B_MAX_BUFFER Structure */

TPM_RC
TSS_TPM2B_MAX_BUFFER_Marshalu(const TPM2B_MAX_BUFFER *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 79 - Definition of TPM2B_MAX_NV_BUFFER Structure */

TPM_RC
TSS_TPM2B_MAX_NV_BUFFER_Marshalu(const TPM2B_MAX_NV_BUFFER *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 80 - Definition of TPM2B_TIMEOUT Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_TIMEOUT_Marshalu(const TPM2B_TIMEOUT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 81 - Definition of TPM2B_IV Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_IV_Marshalu(const TPM2B_IV *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 83 - Definition of TPM2B_NAME Structure */

TPM_RC
TSS_TPM2B_NAME_Marshalu(const TPM2B_NAME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 85 - Definition of TPMS_PCR_SELECTION Structure */

TPM_RC
TSS_TPMS_PCR_SELECTION_Marshalu(const TPMS_PCR_SELECTION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->hash, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->sizeofSelect, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(&source->pcrSelect[0], source->sizeofSelect, written, buffer, size);
    }
    return rc;
}

/* Table 88 - Definition of TPMT_TK_CREATION Structure */

TPM_RC
TSS_TPMT_TK_CREATION_Marshalu(const TPMT_TK_CREATION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ST_Marshalu(&source->tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshalu(&source->hierarchy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->digest, written, buffer, size);
    }
    return rc;
}

/* Table 89 - Definition of TPMT_TK_VERIFIED Structure */

TPM_RC
TSS_TPMT_TK_VERIFIED_Marshalu(const TPMT_TK_VERIFIED *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ST_Marshalu(&source->tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshalu(&source->hierarchy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->digest, written, buffer, size);
    }
    return rc;
}

/* Table 90 - Definition of TPMT_TK_AUTH Structure */

TPM_RC
TSS_TPMT_TK_AUTH_Marshalu(const TPMT_TK_AUTH *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ST_Marshalu(&source->tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshalu(&source->hierarchy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->digest, written, buffer, size);
    }
    return rc;
}

/* Table 91 - Definition of TPMT_TK_HASHCHECK Structure */

TPM_RC
TSS_TPMT_TK_HASHCHECK_Marshalu(const TPMT_TK_HASHCHECK *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ST_Marshalu(&source->tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshalu(&source->hierarchy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->digest, written, buffer, size);
    }
    return rc;
}

/* Table 92 - Definition of TPMS_ALG_PROPERTY Structure <OUT> */

TPM_RC
TSS_TPMS_ALG_PROPERTY_Marshalu(const TPMS_ALG_PROPERTY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(&source->alg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMA_ALGORITHM_Marshalu(&source->algProperties, written, buffer, size);
    }
    return rc;
}

/* Table 93 - Definition of TPMS_TAGGED_PROPERTY Structure <OUT> */

TPM_RC
TSS_TPMS_TAGGED_PROPERTY_Marshalu(const TPMS_TAGGED_PROPERTY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_PT_Marshalu(&source->property, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->value, written, buffer, size);
    }
    return rc;
}

/* Table 94 - Definition of TPMS_TAGGED_PCR_SELECT Structure <OUT> */

TPM_RC
TSS_TPMS_TAGGED_PCR_SELECT_Marshalu(const TPMS_TAGGED_PCR_SELECT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_PT_PCR_Marshalu(&source->tag, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Marshalu(&source->sizeofSelect, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(&source->pcrSelect[0], source->sizeofSelect, written, buffer, size);
    }
    return rc;
}

/* Table 95 - Definition of TPML_CC Structure */

TPM_RC
TSS_TPML_CC_Marshalu(const TPML_CC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPM_CC_Marshalu(&source->commandCodes[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 96 - Definition of TPML_CCA Structure <OUT> */

TPM_RC
TSS_TPML_CCA_Marshalu(const TPML_CCA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPMA_CC_Marshalu(&source->commandAttributes[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 97 - Definition of TPML_ALG Structure */

TPM_RC
TSS_TPML_ALG_Marshalu(const TPML_ALG *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPM_ALG_ID_Marshalu(&source->algorithms[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 98 - Definition of TPML_HANDLE Structure <OUT> */

TPM_RC
TSS_TPML_HANDLE_Marshalu(const TPML_HANDLE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPM_HANDLE_Marshalu(&source->handle[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 99 - Definition of TPML_DIGEST Structure */

TPM_RC
TSS_TPML_DIGEST_Marshalu(const TPML_DIGEST *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPM2B_DIGEST_Marshalu(&source->digests[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 100 - Definition of TPML_DIGEST_VALUES Structure */

TPM_RC
TSS_TPML_DIGEST_VALUES_Marshalu(const TPML_DIGEST_VALUES *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPMT_HA_Marshalu(&source->digests[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 102 - Definition of TPML_PCR_SELECTION Structure */

TPM_RC
TSS_TPML_PCR_SELECTION_Marshalu(const TPML_PCR_SELECTION *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPMS_PCR_SELECTION_Marshalu(&source->pcrSelections[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 103 - Definition of TPML_ALG_PROPERTY Structure <OUT> */

TPM_RC
TSS_TPML_ALG_PROPERTY_Marshalu(const TPML_ALG_PROPERTY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPMS_ALG_PROPERTY_Marshalu(&source->algProperties[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 104 - Definition of TPML_TAGGED_TPM_PROPERTY Structure <OUT> */

TPM_RC
TSS_TPML_TAGGED_TPM_PROPERTY_Marshalu(const TPML_TAGGED_TPM_PROPERTY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPMS_TAGGED_PROPERTY_Marshalu(&source->tpmProperty[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 105 - Definition of TPML_TAGGED_PCR_PROPERTY Structure <OUT> */

TPM_RC
TSS_TPML_TAGGED_PCR_PROPERTY_Marshalu(const TPML_TAGGED_PCR_PROPERTY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPMS_TAGGED_PCR_SELECT_Marshalu(&source->pcrProperty[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 106 - Definition of {ECC} TPML_ECC_CURVE Structure <OUT> */

TPM_RC
TSS_TPML_ECC_CURVE_Marshalu(const TPML_ECC_CURVE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;
    
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPM_ECC_CURVE_Marshalu(&source->eccCurves[i], written, buffer, size);
	}
    }
    return rc;
}

/* Table 107 - Definition of TPMU_CAPABILITIES Union <OUT> */

TPM_RC
TSS_TPMU_CAPABILITIES_Marshalu(const TPMU_CAPABILITIES *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
      case TPM_CAP_ALGS:
	if (rc == 0) {
	    rc = TSS_TPML_ALG_PROPERTY_Marshalu(&source->algorithms, written, buffer, size);
	}
	break;
      case TPM_CAP_HANDLES:
	if (rc == 0) {
	    rc = TSS_TPML_HANDLE_Marshalu(&source->handles, written, buffer, size);
	}
	break;
      case TPM_CAP_COMMANDS:
	if (rc == 0) {
	    rc = TSS_TPML_CCA_Marshalu(&source->command, written, buffer, size);
	}
	break;
      case TPM_CAP_PP_COMMANDS:
	if (rc == 0) {
	    rc = TSS_TPML_CC_Marshalu(&source->ppCommands, written, buffer, size);
	}
	break;
      case TPM_CAP_AUDIT_COMMANDS:
	if (rc == 0) {
	    rc = TSS_TPML_CC_Marshalu(&source->auditCommands, written, buffer, size);
	}
	break;
      case TPM_CAP_PCRS:
	if (rc == 0) {
	    rc = TSS_TPML_PCR_SELECTION_Marshalu(&source->assignedPCR, written, buffer, size);
	}
	break;
      case TPM_CAP_TPM_PROPERTIES:
	if (rc == 0) {
	    rc = TSS_TPML_TAGGED_TPM_PROPERTY_Marshalu(&source->tpmProperties, written, buffer, size);
	}
	break;
      case TPM_CAP_PCR_PROPERTIES:
	if (rc == 0) {
	    rc = TSS_TPML_TAGGED_PCR_PROPERTY_Marshalu(&source->pcrProperties, written, buffer, size);
	}
	break;
      case TPM_CAP_ECC_CURVES:
	if (rc == 0) {
	    rc = TSS_TPML_ECC_CURVE_Marshalu(&source->eccCurves, written, buffer, size);
	}
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 108 - Definition of TPMS_CAPABILITY_DATA Structure <OUT> */

TPM_RC
TSS_TPMS_CAPABILITY_DATA_Marshalu(const TPMS_CAPABILITY_DATA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_CAP_Marshalu(&source->capability, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_CAPABILITIES_Marshalu(&source->data, written, buffer, size, source->capability);
    }
    return rc;
}

/* Table 109 - Definition of TPMS_CLOCK_INFO Structure */

TPM_RC
TSS_TPMS_CLOCK_INFO_Marshalu(const TPMS_CLOCK_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT64_Marshalu(&source->clock, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->resetCount, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->restartCount, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshalu(&source->safe, written, buffer, size);
    }
    return rc;
}

/* Table 110 - Definition of TPMS_TIME_INFO Structure */

TPM_RC
TSS_TPMS_TIME_INFO_Marshalu(const TPMS_TIME_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT64_Marshalu(&source->time, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMS_CLOCK_INFO_Marshalu(&source->clockInfo, written, buffer, size);
    }
    return rc;
}
    
/* Table 111 - Definition of TPMS_TIME_ATTEST_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_TIME_ATTEST_INFO_Marshalu(const TPMS_TIME_ATTEST_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_TIME_INFO_Marshalu(&source->time, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT64_Marshalu(&source->firmwareVersion, written, buffer, size);
    }
    return rc;
}

/* Table 112 - Definition of TPMS_CERTIFY_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_CERTIFY_INFO_Marshalu(const TPMS_CERTIFY_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshalu(&source->name, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshalu(&source->qualifiedName, written, buffer, size);
    }
    return rc;
}

/* Table 113 - Definition of TPMS_QUOTE_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_QUOTE_INFO_Marshalu(const TPMS_QUOTE_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshalu(&source->pcrSelect, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->pcrDigest, written, buffer, size);
    }
    return rc;
}

/* Table 114 - Definition of TPMS_COMMAND_AUDIT_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_COMMAND_AUDIT_INFO_Marshalu(const TPMS_COMMAND_AUDIT_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT64_Marshalu(&source->auditCounter, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(&source->digestAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->auditDigest, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->commandDigest, written, buffer, size);
    }
    return rc;
}

/* Table 115 - Definition of TPMS_SESSION_AUDIT_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_SESSION_AUDIT_INFO_Marshalu(const TPMS_SESSION_AUDIT_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_YES_NO_Marshalu(&source->exclusiveSession, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->sessionDigest, written, buffer, size);
    }
    return rc;
}

/* Table 116 - Definition of TPMS_CREATION_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_CREATION_INFO_Marshalu(const TPMS_CREATION_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshalu(&source->objectName, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->creationHash, written, buffer, size);
    }
    return rc;
}

/* Table 117 - Definition of TPMS_NV_CERTIFY_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_NV_CERTIFY_INFO_Marshalu(const TPMS_NV_CERTIFY_INFO *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshalu(&source->indexName, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->offset, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_MAX_NV_BUFFER_Marshalu(&source->nvContents, written, buffer, size);
    }
    return rc;
}

/* Table 118 - Definition of (TPM_ST) TPMI_ST_ATTEST Type <OUT> */

TPM_RC
TSS_TPMI_ST_ATTEST_Marshalu(const TPMI_ST_ATTEST *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ST_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 119 - Definition of TPMU_ATTEST Union <OUT> */

TPM_RC
TSS_TPMU_ATTEST_Marshalu(const TPMU_ATTEST  *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
      case TPM_ST_ATTEST_CERTIFY:
	if (rc == 0) {
	    rc = TSS_TPMS_CERTIFY_INFO_Marshalu(&source->certify, written, buffer, size);
	}
	break;
      case TPM_ST_ATTEST_CREATION:
	if (rc == 0) {
	    rc = TSS_TPMS_CREATION_INFO_Marshalu(&source->creation, written, buffer, size);
	}
	break;
      case TPM_ST_ATTEST_QUOTE:
	if (rc == 0) {
	    rc = TSS_TPMS_QUOTE_INFO_Marshalu(&source->quote, written, buffer, size);
	}
	break;
      case TPM_ST_ATTEST_COMMAND_AUDIT:
	if (rc == 0) {
	    rc = TSS_TPMS_COMMAND_AUDIT_INFO_Marshalu(&source->commandAudit, written, buffer, size);
	}
	break;
      case TPM_ST_ATTEST_SESSION_AUDIT:
	if (rc == 0) {
	    rc = TSS_TPMS_SESSION_AUDIT_INFO_Marshalu(&source->sessionAudit, written, buffer, size);
	}
	break;
      case TPM_ST_ATTEST_TIME:
	if (rc == 0) {
	    rc = TSS_TPMS_TIME_ATTEST_INFO_Marshalu(&source->time, written, buffer, size);
	}
	break;
      case TPM_ST_ATTEST_NV:
	if (rc == 0) {
	    rc = TSS_TPMS_NV_CERTIFY_INFO_Marshalu(&source->nv, written, buffer, size);
	}
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 120 - Definition of TPMS_ATTEST Structure <OUT> */

TPM_RC
TSS_TPMS_ATTEST_Marshalu(const TPMS_ATTEST  *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_GENERATED_Marshalu(&source->magic, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ST_ATTEST_Marshalu(&source->type, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshalu(&source->qualifiedSigner, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->extraData, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMS_CLOCK_INFO_Marshalu(&source->clockInfo, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT64_Marshalu(&source->firmwareVersion, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_ATTEST_Marshalu(&source->attested, written, buffer, size,source->type);
    }
    return rc;
}

/* Table 121 - Definition of TPM2B_ATTEST Structure <OUT> */

TPM_RC
TSS_TPM2B_ATTEST_Marshalu(const TPM2B_ATTEST *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 122 - Definition of TPMS_AUTH_COMMAND Structure <IN> */

TPM_RC
TSS_TPMS_AUTH_COMMAND_Marshalu(const TPMS_AUTH_COMMAND *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_SH_AUTH_SESSION_Marshalu(&source->sessionHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NONCE_Marshalu(&source->nonce, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMA_SESSION_Marshalu(&source->sessionAttributes, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshalu(&source->hmac, written, buffer, size);
    }
    return rc;
}

/* Table 124 - Definition of {AES} (TPM_KEY_BITS) TPMI_!ALG.S_KEY_BITS Type */

TPM_RC
TSS_TPMI_AES_KEY_BITS_Marshalu(const TPMI_AES_KEY_BITS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_KEY_BITS_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 125 - Definition of TPMU_SYM_KEY_BITS Union */

TPM_RC
TSS_TPMU_SYM_KEY_BITS_Marshalu(const TPMU_SYM_KEY_BITS *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch(selector) {
#ifdef TPM_ALG_AES
      case TPM_ALG_AES:
	if (rc == 0) {
	    rc = TSS_TPMI_AES_KEY_BITS_Marshalu(&source->aes, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SM4
      case TPM_ALG_SM4:
	if (rc == 0) {
	    rc = TSS_TPMI_SM4_KEY_BITS_Marshalu(&source->sm4, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_CAMELLIA
      case TPM_ALG_CAMELLIA:
	if (rc == 0) {
	    rc = TSS_TPMI_CAMELLIA_KEY_BITS_Marshalu(&source->camellia, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_XOR
      case TPM_ALG_XOR:
	if (rc == 0) {
	    rc = TSS_TPMI_ALG_HASH_Marshalu(&source->xorr, written, buffer, size);
	}
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	return rc;
    }
    return rc;
}

/* Table 126 - Definition of TPMU_SYM_MODE Union */

TPM_RC
TSS_TPMU_SYM_MODE_Marshalu(const TPMU_SYM_MODE *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_AES
      case TPM_ALG_AES:
	if (rc == 0) {
	    rc = TSS_TPMI_ALG_SYM_MODE_Marshalu(&source->aes, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SM4
      case TPM_ALG_SM4:
	if (rc == 0) {
	    rc = TSS_TPMI_ALG_SYM_MODE_Marshalu(&source->sm4, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_CAMELLIA
      case TPM_ALG_CAMELLIA:
	if (rc == 0) {
	    rc = TSS_TPMI_ALG_SYM_MODE_Marshalu(&source->camellia, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_XOR
      case TPM_ALG_XOR:
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 128 - Definition of TPMT_SYM_DEF Structure */

TPM_RC
TSS_TPMT_SYM_DEF_Marshalu(const TPMT_SYM_DEF *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_SYM_Marshalu(&source->algorithm, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SYM_KEY_BITS_Marshalu(&source->keyBits, written, buffer, size, source->algorithm);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SYM_MODE_Marshalu(&source->mode, written, buffer, size, source->algorithm);
    }
    return rc;
}

/* Table 129 - Definition of TPMT_SYM_DEF_OBJECT Structure */

TPM_RC
TSS_TPMT_SYM_DEF_OBJECT_Marshalu(const TPMT_SYM_DEF_OBJECT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_SYM_OBJECT_Marshalu(&source->algorithm, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SYM_KEY_BITS_Marshalu(&source->keyBits, written, buffer, size, source->algorithm);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SYM_MODE_Marshalu(&source->mode, written, buffer, size, source->algorithm);
    }
    return rc;
}

/* Table 130 - Definition of TPM2B_SYM_KEY Structure */

TPM_RC
TSS_TPM2B_SYM_KEY_Marshalu(const TPM2B_SYM_KEY *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 134 - Definition of TPM2B_LABEL Structure */

TPM_RC
TSS_TPM2B_LABEL_Marshalu(const TPM2B_LABEL *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 139 - Definition of TPMS_DERIVE Structure */

TPM_RC
TSS_TPMS_DERIVE_Marshalu(const TPMS_DERIVE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_LABEL_Marshalu(&source->label, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_LABEL_Marshalu(&source->context, written, buffer, size);
    }
    return rc;
}

/* Table 131 - Definition of TPMS_SYMCIPHER_PARMS Structure */

TPM_RC
TSS_TPMS_SYMCIPHER_PARMS_Marshalu(const TPMS_SYMCIPHER_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Marshalu(&source->sym, written, buffer, size);
    }
    return rc;
}

/* Table 132 - Definition of TPM2B_SENSITIVE_DATA Structure */

TPM_RC
TSS_TPM2B_SENSITIVE_DATA_Marshalu(const TPM2B_SENSITIVE_DATA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 133 - Definition of TPMS_SENSITIVE_CREATE Structure <IN> */

TPM_RC
TSS_TPMS_SENSITIVE_CREATE_Marshalu(const TPMS_SENSITIVE_CREATE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshalu(&source->userAuth, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_SENSITIVE_DATA_Marshalu(&source->data, written, buffer, size);
    }
    return rc;
}

/* Table 134 - Definition of TPM2B_SENSITIVE_CREATE Structure <IN, S> */

TPM_RC
TSS_TPM2B_SENSITIVE_CREATE_Marshalu(const TPM2B_SENSITIVE_CREATE  *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;

    if (buffer != NULL) {
	sizePtr = *buffer;
	*buffer += sizeof(uint16_t);
    }
    if (rc == 0) {
	rc = TSS_TPMS_SENSITIVE_CREATE_Marshalu(&source->sensitive, &sizeWritten, buffer, size);
    }
    if (rc == 0) {
	*written += sizeWritten;
	if (buffer != NULL) {
	    rc = TSS_UINT16_Marshalu(&sizeWritten, written, &sizePtr, size);	/* backfill 2B size */
	}
	else {
	    *written += sizeof(uint16_t);
	}
    }
    return rc;
}

/* Table 135 - Definition of TPMS_SCHEME_HASH Structure */

TPM_RC
TSS_TPMS_SCHEME_HASH_Marshalu(const TPMS_SCHEME_HASH *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->hashAlg, written, buffer, size);
    }
    return rc;
}
    
/* Table 136 - Definition of {ECC} TPMS_SCHEME_ECDAA Structure */

TPM_RC
TSS_TPMS_SCHEME_ECDAA_Marshalu(const TPMS_SCHEME_ECDAA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->hashAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->count, written, buffer, size);
    }
    return rc;
}

/* Table 137 - Definition of (TPM_ALG_ID) TPMI_ALG_KEYEDHASH_SCHEME Type */

TPM_RC
TSS_TPMI_ALG_KEYEDHASH_SCHEME_Marshalu(const TPMI_ALG_KEYEDHASH_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 138 - Definition of Types for HMAC_SIG_SCHEME */

TPM_RC
TSS_TPMS_SCHEME_HMAC_Marshalu(const TPMS_SCHEME_HMAC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 139 - Definition of TPMS_SCHEME_XOR Structure */

TPM_RC
TSS_TPMS_SCHEME_XOR_Marshalu(const TPMS_SCHEME_XOR *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->hashAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_KDF_Marshalu(&source->kdf, written, buffer, size);
    }
    return rc;
}

/* Table 140 - Definition of TPMU_SCHEME_KEYEDHASH Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_SCHEME_KEYEDHASH_Marshalu(const TPMU_SCHEME_KEYEDHASH *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_HMAC
      case TPM_ALG_HMAC:
	if (rc == 0) {
	    rc = TSS_TPMS_SCHEME_HMAC_Marshalu(&source->hmac, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_XOR
      case TPM_ALG_XOR:
	if (rc == 0) {
	    rc = TSS_TPMS_SCHEME_XOR_Marshalu(&source->xorr, written, buffer, size);
	}
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 141 - Definition of TPMT_KEYEDHASH_SCHEME Structure */

TPM_RC
TSS_TPMT_KEYEDHASH_SCHEME_Marshalu(const TPMT_KEYEDHASH_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_KEYEDHASH_SCHEME_Marshalu(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SCHEME_KEYEDHASH_Marshalu(&source->details, written, buffer, size, source->scheme);
    }
    return rc;
}

/* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */

TPM_RC
TSS_TPMS_SIG_SCHEME_RSASSA_Marshalu(const TPMS_SIG_SCHEME_RSASSA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshalu(source, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPMS_SIG_SCHEME_RSAPSS_Marshalu(const TPMS_SIG_SCHEME_RSAPSS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 143 - Definition of {ECC} Types for ECC Signature Schemes */

TPM_RC
TSS_TPMS_SIG_SCHEME_ECDSA_Marshalu(const TPMS_SIG_SCHEME_ECDSA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshalu(source, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TPMS_SIG_SCHEME_SM2_Marshalu(const TPMS_SIG_SCHEME_SM2 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshalu(source, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TPMS_SIG_SCHEME_ECSCHNORR_Marshalu(const TPMS_SIG_SCHEME_ECSCHNORR *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 143 - Definition of {ECC} Types for ECC Signature Schemes */

TPM_RC
TSS_TPMS_SIG_SCHEME_ECDAA_Marshalu(const TPMS_SIG_SCHEME_ECDAA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_ECDAA_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 144 - Definition of TPMU_SIG_SCHEME Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_SIG_SCHEME_Marshalu(const TPMU_SIG_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_RSASSA
      case TPM_ALG_RSASSA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_RSASSA_Marshalu(&source->rsassa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_RSAPSS
      case TPM_ALG_RSAPSS:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_RSAPSS_Marshalu(&source->rsapss, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECDSA
      case TPM_ALG_ECDSA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_ECDSA_Marshalu(&source->ecdsa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECDAA
      case TPM_ALG_ECDAA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_ECDAA_Marshalu(&source->ecdaa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SM2
      case TPM_ALG_SM2:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_SM2_Marshalu(&source->sm2, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_ECSCHNORR_Marshalu(&source->ecSchnorr, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_HMAC
      case TPM_ALG_HMAC:
	if (rc == 0) {
	    rc = TSS_TPMS_SCHEME_HMAC_Marshalu(&source->hmac, written, buffer, size);
	}
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}
 
/* Table 145 - Definition of TPMT_SIG_SCHEME Structure */

TPM_RC
TSS_TPMT_SIG_SCHEME_Marshalu(const TPMT_SIG_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_SIG_SCHEME_Marshalu(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SIG_SCHEME_Marshalu(&source->details, written, buffer, size,source->scheme);
    }
    return rc;
}

/* Table 146 - Definition of Types for {RSA} Encryption Schemes */

/* NOTE: Marked as const function in header */

TPM_RC
TSS_TPMS_ENC_SCHEME_OAEP_Marshalu(const TPMS_ENC_SCHEME_OAEP *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 146 - Definition of Types for {RSA} Encryption Schemes */

/* NOTE: Marked as const function in header */

TPM_RC
TSS_TPMS_ENC_SCHEME_RSAES_Marshalu(const TPMS_ENC_SCHEME_RSAES *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    source = source;
    written = written;
    buffer = buffer;
    size = size;
    return 0;
}

/* Table 147 - Definition of Types for {ECC} ECC Key Exchange */

TPM_RC
TSS_TPMS_KEY_SCHEME_ECDH_Marshalu(const TPMS_KEY_SCHEME_ECDH *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshalu(source, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TPMS_KEY_SCHEME_ECMQV_Marshalu(const TPMS_KEY_SCHEME_ECMQV *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 148 - Definition of Types for KDF Schemes, hash-based key- or mask-generation functions */

TPM_RC
TSS_TPMS_SCHEME_MGF1_Marshalu(const TPMS_SCHEME_MGF1 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshalu(source, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TPMS_SCHEME_KDF1_SP800_56A_Marshalu(const TPMS_SCHEME_KDF1_SP800_56A *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshalu(source, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TPMS_SCHEME_KDF2_Marshalu(const TPMS_SCHEME_KDF2 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshalu(source, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TPMS_SCHEME_KDF1_SP800_108_Marshalu(const TPMS_SCHEME_KDF1_SP800_108 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SCHEME_HASH_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 149 - Definition of TPMU_KDF_SCHEME Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_KDF_SCHEME_Marshalu(const TPMU_KDF_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_MGF1
      case TPM_ALG_MGF1:
	if (rc == 0) {
	    rc = TSS_TPMS_SCHEME_MGF1_Marshalu(&source->mgf1, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_KDF1_SP800_56A
      case TPM_ALG_KDF1_SP800_56A:
	if (rc == 0) {
	    rc = TSS_TPMS_SCHEME_KDF1_SP800_56A_Marshalu(&source->kdf1_SP800_56a, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_KDF2
      case TPM_ALG_KDF2:
	if (rc == 0) {
	    rc = TSS_TPMS_SCHEME_KDF2_Marshalu(&source->kdf2, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_KDF1_SP800_108
      case TPM_ALG_KDF1_SP800_108:
	if (rc == 0) {
	    rc = TSS_TPMS_SCHEME_KDF1_SP800_108_Marshalu(&source->kdf1_sp800_108, written, buffer, size);
	}
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}
/* Table 150 - Definition of TPMT_KDF_SCHEME Structure */

TPM_RC
TSS_TPMT_KDF_SCHEME_Marshalu(const TPMT_KDF_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_KDF_Marshalu(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_KDF_SCHEME_Marshalu(&source->details, written, buffer, size, source->scheme);
    }
    return rc;
}

/* Table 152 - Definition of TPMU_ASYM_SCHEME Union */

TPM_RC
TSS_TPMU_ASYM_SCHEME_Marshalu(const TPMU_ASYM_SCHEME  *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_ECDH
      case TPM_ALG_ECDH:
	if (rc == 0) {
	    rc = TSS_TPMS_KEY_SCHEME_ECDH_Marshalu(&source->ecdh, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECMQV
      case TPM_ALG_ECMQV:
	if (rc == 0) {
	    rc = TSS_TPMS_KEY_SCHEME_ECMQV_Marshalu(&source->ecmqvh, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_RSASSA
      case TPM_ALG_RSASSA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_RSASSA_Marshalu(&source->rsassa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_RSAPSS
      case TPM_ALG_RSAPSS:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_RSAPSS_Marshalu(&source->rsapss, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECDSA
      case TPM_ALG_ECDSA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_ECDSA_Marshalu(&source->ecdsa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECDAA
      case TPM_ALG_ECDAA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_ECDAA_Marshalu(&source->ecdaa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SM2
      case TPM_ALG_SM2:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_SM2_Marshalu(&source->sm2, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
	if (rc == 0) {
	    rc = TSS_TPMS_SIG_SCHEME_ECSCHNORR_Marshalu(&source->ecSchnorr, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_RSAES
      case TPM_ALG_RSAES:
	if (rc == 0) {
	    rc = TSS_TPMS_ENC_SCHEME_RSAES_Marshalu(&source->rsaes, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_OAEP
      case TPM_ALG_OAEP:
	if (rc == 0) {
	    rc = TSS_TPMS_ENC_SCHEME_OAEP_Marshalu(&source->oaep, written, buffer, size);
	}
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 154 - Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_SCHEME Type */

TPM_RC
TSS_TPMI_ALG_RSA_SCHEME_Marshalu(const TPMI_ALG_RSA_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 155 - Definition of {RSA} TPMT_RSA_SCHEME Structure */

TPM_RC
TSS_TPMT_RSA_SCHEME_Marshalu(const TPMT_RSA_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_RSA_SCHEME_Marshalu(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_ASYM_SCHEME_Marshalu(&source->details, written, buffer, size, source->scheme);
    }
    return rc;
}

/* Table 156 - Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_DECRYPT Type */

TPM_RC
TSS_TPMI_ALG_RSA_DECRYPT_Marshalu(const TPMI_ALG_RSA_DECRYPT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 157 - Definition of {RSA} TPMT_RSA_DECRYPT Structure */

TPM_RC
TSS_TPMT_RSA_DECRYPT_Marshalu(const TPMT_RSA_DECRYPT  *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_RSA_DECRYPT_Marshalu(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_ASYM_SCHEME_Marshalu(&source->details, written, buffer, size, source->scheme);
    }
    return rc;
}

/* Table 158 - Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure */

TPM_RC
TSS_TPM2B_PUBLIC_KEY_RSA_Marshalu(const TPM2B_PUBLIC_KEY_RSA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 159 - Definition of {RSA} (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type */

TPM_RC
TSS_TPMI_RSA_KEY_BITS_Marshalu(const TPMI_RSA_KEY_BITS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_KEY_BITS_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 160 - Definition of {RSA} TPM2B_PRIVATE_KEY_RSA Structure */

TPM_RC
TSS_TPM2B_PRIVATE_KEY_RSA_Marshalu(const TPM2B_PRIVATE_KEY_RSA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 161 - Definition of {ECC} TPM2B_ECC_PARAMETER Structure */

TPM_RC
TSS_TPM2B_ECC_PARAMETER_Marshalu(const TPM2B_ECC_PARAMETER *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 162 - Definition of {ECC} TPMS_ECC_POINT Structure */

TPM_RC
TSS_TPMS_ECC_POINT_Marshalu(const TPMS_ECC_POINT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshalu(&source->x, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshalu(&source->y, written, buffer, size);
    }
    return rc;
}

/* Table 163 - Definition of {ECC} TPM2B_ECC_POINT Structure */

TPM_RC
TSS_TPM2B_ECC_POINT_Marshalu(const TPM2B_ECC_POINT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;

    if (buffer != NULL) {
	sizePtr = *buffer;
	*buffer += sizeof(uint16_t);
    }
    if (rc == 0) {
	rc = TSS_TPMS_ECC_POINT_Marshalu(&source->point, &sizeWritten, buffer, size);
    }
    if (rc == 0) {
	*written += sizeWritten;
	if (buffer != NULL) {
	    rc = TSS_UINT16_Marshalu(&sizeWritten, written, &sizePtr, size);
	}
	else {
	    *written += sizeof(uint16_t);
	}
    }
    return rc;
}

/* Table 164 - Definition of (TPM_ALG_ID) {ECC} TPMI_ALG_ECC_SCHEME Type */

TPM_RC
TSS_TPMI_ALG_ECC_SCHEME_Marshalu(const TPMI_ALG_ECC_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 165 - Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type */

TPM_RC
TSS_TPMI_ECC_CURVE_Marshalu(const TPMI_ECC_CURVE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ECC_CURVE_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 166 - Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure */

TPM_RC
TSS_TPMT_ECC_SCHEME_Marshalu(const TPMT_ECC_SCHEME *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_ECC_SCHEME_Marshalu(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_ASYM_SCHEME_Marshalu(&source->details, written, buffer, size, source->scheme);
    }
    return rc;
}

/* Table 167 - Definition of {ECC} TPMS_ALGORITHM_DETAIL_ECC Structure <OUT> */

TPM_RC
TSS_TPMS_ALGORITHM_DETAIL_ECC_Marshalu(const TPMS_ALGORITHM_DETAIL_ECC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ECC_CURVE_Marshalu(&source->curveID, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->keySize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_KDF_SCHEME_Marshalu(&source->kdf, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_ECC_SCHEME_Marshalu(&source->sign, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshalu(&source->p, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshalu(&source->a, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshalu(&source->b, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshalu(&source->gX, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshalu(&source->gY, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshalu(&source->n, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshalu(&source->h, written, buffer, size);
    }
    return rc;
}
    
/* Table 168 - Definition of {RSA} TPMS_SIGNATURE_RSA Structure */

TPM_RC
TSS_TPMS_SIGNATURE_RSA_Marshalu(const TPMS_SIGNATURE_RSA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->hash, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_PUBLIC_KEY_RSA_Marshalu(&source->sig, written, buffer, size);
    }
    return rc;
}

/* Table 169 - Definition of Types for {RSA} Signature */

TPM_RC
TSS_TPMS_SIGNATURE_RSASSA_Marshalu(const TPMS_SIGNATURE_RSASSA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SIGNATURE_RSA_Marshalu(source, written, buffer, size);
    }
    return rc;
}
TPM_RC
TSS_TPMS_SIGNATURE_RSAPSS_Marshalu(const TPMS_SIGNATURE_RSAPSS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SIGNATURE_RSA_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 170 - Definition of {ECC} TPMS_SIGNATURE_ECC Structure */

TPM_RC
TSS_TPMS_SIGNATURE_ECC_Marshalu(const TPMS_SIGNATURE_ECC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->hash, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshalu(&source->signatureR, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_ECC_PARAMETER_Marshalu(&source->signatureS, written, buffer, size);
    }
    return rc;
}
    
/* Table 171 - Definition of Types for {ECC} TPMS_SIGNATURE_ECC */

TPM_RC
TSS_TPMS_SIGNATURE_ECDSA_Marshalu(const TPMS_SIGNATURE_ECDSA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SIGNATURE_ECC_Marshalu(source, written, buffer, size);
    }
    return rc;
}	

TPM_RC
TSS_TPMS_SIGNATURE_ECDAA_Marshalu(const TPMS_SIGNATURE_ECDAA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SIGNATURE_ECC_Marshalu(source, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPMS_SIGNATURE_SM2_Marshalu(const TPMS_SIGNATURE_SM2 *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SIGNATURE_ECC_Marshalu(source, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPMS_SIGNATURE_ECSCHNORR_Marshalu(const TPMS_SIGNATURE_ECSCHNORR *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMS_SIGNATURE_ECC_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 172 - Definition of TPMU_SIGNATURE Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_SIGNATURE_Marshalu(const TPMU_SIGNATURE *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_RSASSA
      case TPM_ALG_RSASSA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIGNATURE_RSASSA_Marshalu(&source->rsassa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_RSAPSS
      case TPM_ALG_RSAPSS:
	if (rc == 0) {
	    rc = TSS_TPMS_SIGNATURE_RSAPSS_Marshalu(&source->rsapss, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECDSA
      case TPM_ALG_ECDSA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIGNATURE_ECDSA_Marshalu(&source->ecdsa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECDAA
      case TPM_ALG_ECDAA:
	if (rc == 0) {
	    rc = TSS_TPMS_SIGNATURE_ECDSA_Marshalu(&source->ecdaa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SM2
      case TPM_ALG_SM2:
	if (rc == 0) {
	    rc = TSS_TPMS_SIGNATURE_ECDSA_Marshalu(&source->sm2, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
	if (rc == 0) {
	    rc = TSS_TPMS_SIGNATURE_ECDSA_Marshalu(&source->ecschnorr, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_HMAC
      case TPM_ALG_HMAC:
	if (rc == 0) {
	    rc = TSS_TPMT_HA_Marshalu(&source->hmac, written, buffer, size);
	}
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 173 - Definition of TPMT_SIGNATURE Structure */

TPM_RC
TSS_TPMT_SIGNATURE_Marshalu(const TPMT_SIGNATURE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_SIG_SCHEME_Marshalu(&source->sigAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SIGNATURE_Marshalu(&source->signature, written, buffer, size, source->sigAlg);
    }
    return rc;
}

/* Table 175 - Definition of TPM2B_ENCRYPTED_SECRET Structure */

TPM_RC
TSS_TPM2B_ENCRYPTED_SECRET_Marshalu(const TPM2B_ENCRYPTED_SECRET *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}
 
/* Table 176 - Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type */

TPM_RC
TSS_TPMI_ALG_PUBLIC_Marshalu(const TPMI_ALG_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(source, written, buffer, size);
    }
    return rc;
}

/* Table 177 - Definition of TPMU_PUBLIC_ID Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_PUBLIC_ID_Marshalu(const TPMU_PUBLIC_ID *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	if (rc == 0) {
	    rc = TSS_TPM2B_DIGEST_Marshalu(&source->keyedHash, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	if (rc == 0) {
	    rc = TSS_TPM2B_DIGEST_Marshalu(&source->sym, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	if (rc == 0) {
	    rc = TSS_TPM2B_PUBLIC_KEY_RSA_Marshalu(&source->rsa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	if (rc == 0) {
	    rc = TSS_TPMS_ECC_POINT_Marshalu(&source->ecc, written, buffer, size);
	}
	break;
#endif
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
} 

/* Table 178 - Definition of TPMS_KEYEDHASH_PARMS Structure */

TPM_RC
TSS_TPMS_KEYEDHASH_PARMS_Marshalu(const TPMS_KEYEDHASH_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMT_KEYEDHASH_SCHEME_Marshalu(&source->scheme, written, buffer, size);
    }
    return rc;
}

/* Table 180 - Definition of {RSA} TPMS_RSA_PARMS Structure */

TPM_RC
TSS_TPMS_RSA_PARMS_Marshalu(const TPMS_RSA_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Marshalu(&source->symmetric, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_RSA_SCHEME_Marshalu(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RSA_KEY_BITS_Marshalu(&source->keyBits, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->exponent, written, buffer, size);
    }
    return rc;
}
/* Table 181 - Definition of {ECC} TPMS_ECC_PARMS Structure */

TPM_RC
TSS_TPMS_ECC_PARMS_Marshalu(const TPMS_ECC_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Marshalu(&source->symmetric, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_ECC_SCHEME_Marshalu(&source->scheme, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ECC_CURVE_Marshalu(&source->curveID, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMT_KDF_SCHEME_Marshalu(&source->kdf, written, buffer, size);
    }
    return rc;
}

/* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_PUBLIC_PARMS_Marshalu(const TPMU_PUBLIC_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector) 
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	if (rc == 0) {
	    rc = TSS_TPMS_KEYEDHASH_PARMS_Marshalu(&source->keyedHashDetail, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	if (rc == 0) {
	    rc = TSS_TPMS_SYMCIPHER_PARMS_Marshalu(&source->symDetail, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	if (rc == 0) {
	    rc = TSS_TPMS_RSA_PARMS_Marshalu(&source->rsaDetail, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	if (rc == 0) {
	    rc = TSS_TPMS_ECC_PARMS_Marshalu(&source->eccDetail, written, buffer, size);
	}
	break;
#endif
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 183 - Definition of TPMT_PUBLIC_PARMS Structure */

TPM_RC
TSS_TPMT_PUBLIC_PARMS_Marshalu(const TPMT_PUBLIC_PARMS *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_PUBLIC_Marshalu(&source->type, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_PUBLIC_PARMS_Marshalu(&source->parameters, written, buffer, size, source->type);
    }
    return rc;
}

/* Table 184 - Definition of TPMT_PUBLIC Structure */

TPM_RC
TSS_TPMT_PUBLIC_Marshalu(const TPMT_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_PUBLIC_Marshalu(&source->type, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->nameAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMA_OBJECT_Marshalu(&source->objectAttributes, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->authPolicy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_PUBLIC_PARMS_Marshalu(&source->parameters, written, buffer, size, source->type);
    }
    if (rc == 0) {
	rc = TSS_TPMU_PUBLIC_ID_Marshalu(&source->unique, written, buffer, size, source->type);
    }
    return rc;
}

/* Table 184 - Definition of TPMT_PUBLIC Structure - special marshaling for derived object template */

TPM_RC
TSS_TPMT_PUBLIC_D_Marshalu(const TPMT_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_PUBLIC_Marshalu(&source->type, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->nameAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMA_OBJECT_Marshalu(&source->objectAttributes, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->authPolicy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_PUBLIC_PARMS_Marshalu(&source->parameters, written, buffer, size, source->type);
    }
    /* if derived from a derivation parent, marshal a TPMS_DERIVE structure */             
    if (rc == 0) {
	rc = TSS_TPMS_DERIVE_Marshalu(&source->unique.derive, written, buffer, size);
    }    
    return rc;
}

/* Table 185 - Definition of TPM2B_PUBLIC Structure */

TPM_RC
TSS_TPM2B_PUBLIC_Marshalu(const TPM2B_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;
    
    if (buffer != NULL) {
	sizePtr = *buffer;
	*buffer += sizeof(uint16_t);
    }
    if (rc == 0) {
	rc = TSS_TPMT_PUBLIC_Marshalu(&source->publicArea, &sizeWritten, buffer, size);
    }
    if (rc == 0) {
	*written += sizeWritten;
	if (buffer != NULL) {
	    rc = TSS_UINT16_Marshalu(&sizeWritten, written, &sizePtr, size);
	}
	else {
	    *written += sizeof(uint16_t);
	}
    }
    return rc;
}

TPM_RC
TSS_TPM2B_TEMPLATE_Marshalu(const TPM2B_TEMPLATE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 187 - Definition of TPMU_SENSITIVE_COMPOSITE Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_SENSITIVE_COMPOSITE_Marshalu(const TPMU_SENSITIVE_COMPOSITE *source, uint16_t *written, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = 0;
    switch (selector) {
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	if (rc == 0) {
	    rc = TSS_TPM2B_PRIVATE_KEY_RSA_Marshalu(&source->rsa, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	if (rc == 0) {
	    rc = TSS_TPM2B_ECC_PARAMETER_Marshalu(&source->ecc, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	if (rc == 0) {
	    rc = TSS_TPM2B_SENSITIVE_DATA_Marshalu(&source->bits, written, buffer, size);
	}
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	if (rc == 0) {
	    rc = TSS_TPM2B_SYM_KEY_Marshalu(&source->sym, written, buffer, size);
	}
	break;
#endif
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 188 - Definition of TPMT_SENSITIVE Structure */

TPM_RC
TSS_TPMT_SENSITIVE_Marshalu(const TPMT_SENSITIVE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_ALG_PUBLIC_Marshalu(&source->sensitiveType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_AUTH_Marshalu(&source->authValue, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->seedValue, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_SENSITIVE_COMPOSITE_Marshalu(&source->sensitive, written, buffer, size, source->sensitiveType);
    }
    return rc;
}

/* Table 189 - Definition of TPM2B_SENSITIVE Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_SENSITIVE_Marshalu(const TPM2B_SENSITIVE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;
    
    if (buffer != NULL) {
	sizePtr = *buffer;
	*buffer += sizeof(uint16_t);
    }
    if (rc == 0) {
	rc = TSS_TPMT_SENSITIVE_Marshalu(&source->t.sensitiveArea, &sizeWritten, buffer, size);
    }
    if (rc == 0) {
	*written += sizeWritten;
	if (buffer != NULL) {
	    rc = TSS_UINT16_Marshalu(&sizeWritten, written, &sizePtr, size);
	}
	else {
	    *written += sizeof(uint16_t);
	}
    }
    return rc;
}

/* Table 191 - Definition of TPM2B_PRIVATE Structure <IN/OUT, S> */

TPM_RC
TSS_TPM2B_PRIVATE_Marshalu(const TPM2B_PRIVATE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 193 - Definition of TPM2B_ID_OBJECT Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_ID_OBJECT_Marshalu(const TPM2B_ID_OBJECT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 196 - Definition of (UINT32) TPMA_NV Bits */

TPM_RC
TSS_TPMA_NV_Marshalu(const TPMA_NV *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->val, written, buffer, size);
    }
    return rc;
}

/* Table 197 - Definition of TPMS_NV_PUBLIC Structure */

TPM_RC
TSS_TPMS_NV_PUBLIC_Marshalu(const TPMS_NV_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPMI_RH_NV_INDEX_Marshalu(&source->nvIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_ALG_HASH_Marshalu(&source->nameAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMA_NV_Marshalu(&source->attributes, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->authPolicy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT16_Marshalu(&source->dataSize, written, buffer, size);
    }
    return rc;
}

/* Table 198 - Definition of TPM2B_NV_PUBLIC Structure */

TPM_RC
TSS_TPM2B_NV_PUBLIC_Marshalu(const TPM2B_NV_PUBLIC *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;

    if (buffer != NULL) {
 	sizePtr = *buffer;
	*buffer += sizeof(uint16_t);
    }
    if (rc == 0) {
	rc = TSS_TPMS_NV_PUBLIC_Marshalu(&source->nvPublic, &sizeWritten, buffer, size);
    }
    if (rc == 0) {
	*written += sizeWritten;
	if (buffer != NULL) {
	    rc = TSS_UINT16_Marshalu(&sizeWritten, written, &sizePtr, size);
	}
	else {
	    *written += sizeof(uint16_t);
	}
    }
    return rc;
}

/* Table 199 - Definition of TPM2B_CONTEXT_SENSITIVE Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_CONTEXT_SENSITIVE_Marshalu(const TPM2B_CONTEXT_SENSITIVE *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 201 - Definition of TPM2B_CONTEXT_DATA Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_CONTEXT_DATA_Marshalu(const TPM2B_CONTEXT_DATA  *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPM2B_Marshalu(&source->b, written, buffer, size);
    }
    return rc;
}

/* Table 202 - Definition of TPMS_CONTEXT Structure */

TPM_RC
TSS_TPMS_CONTEXT_Marshalu(const TPMS_CONTEXT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT64_Marshalu(&source->sequence, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_DH_SAVED_Marshalu(&source->savedHandle, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMI_RH_HIERARCHY_Marshalu(&source->hierarchy, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_CONTEXT_DATA_Marshalu(&source->contextBlob, written, buffer, size);
    }
    return rc;
}

/* Table 204 - Definition of TPMS_CREATION_DATA Structure <OUT> */

TPM_RC
TSS_TPMS_CREATION_DATA_Marshalu(const TPMS_CREATION_DATA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_TPML_PCR_SELECTION_Marshalu(&source->pcrSelect, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DIGEST_Marshalu(&source->pcrDigest, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMA_LOCALITY_Marshalu(&source->locality, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM_ALG_ID_Marshalu(&source->parentNameAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshalu(&source->parentName, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_NAME_Marshalu(&source->parentQualifiedName, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPM2B_DATA_Marshalu(&source->outsideInfo, written, buffer, size);
    }
    return rc;
}

/* Table 205 - Definition of TPM2B_CREATION_DATA Structure <OUT> */

TPM_RC
TSS_TPM2B_CREATION_DATA_Marshalu(const TPM2B_CREATION_DATA *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    uint16_t sizeWritten = 0;	/* of structure */
    BYTE *sizePtr;

    if (buffer != NULL) {
	sizePtr = *buffer;
	*buffer += sizeof(uint16_t);
    }
    if (rc == 0) {
	rc = TSS_TPMS_CREATION_DATA_Marshalu(&source->creationData, &sizeWritten, buffer, size);
    }
    if (rc == 0) {
	*written += sizeWritten;
	if (buffer != NULL) {
	    rc = TSS_UINT16_Marshalu(&sizeWritten, written, &sizePtr, size);
	}
	else {
	    *written += sizeof(uint16_t);
	}
    }
    return rc;
}

#ifndef TPM_TSS_NODEPRECATED

/* Deprecated functions that use a sized value for the size parameter.  The recommended functions
   use an unsigned value.

*/

TPM_RC
TSS_UINT8_Marshal(const UINT8 *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_UINT8_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_INT8_Marshal(const INT8 *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_INT8_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_UINT16_Marshal(const UINT16 *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_UINT16_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_UINT32_Marshal(const UINT32 *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_UINT32_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_INT32_Marshal(const INT32 *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_INT32_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_UINT64_Marshal(const UINT64 *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_UINT64_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Array_Marshal(const BYTE *source, uint16_t sourceSize, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_Array_Marshalu(source, sourceSize, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_Marshal(const TPM2B *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM_KEY_BITS_Marshal(const TPM_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_KEY_BITS_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM_GENERATED_Marshal(const TPM_GENERATED *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_GENERATED_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM_ALG_ID_Marshal(const TPM_ALG_ID *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_ALG_ID_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM_ECC_CURVE_Marshal(const TPM_ECC_CURVE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_ECC_CURVE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM_RC_Marshal(const TPM_RC *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_RC_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM_CLOCK_ADJUST_Marshal(const TPM_CLOCK_ADJUST *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_CLOCK_ADJUST_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM_EO_Marshal(const TPM_EO *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_EO_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM_ST_Marshal(const TPM_ST *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_ST_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM_SU_Marshal(const TPM_ST *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_SU_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM_SE_Marshal(const TPM_SE  *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_SE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM_CAP_Marshal(const TPM_CAP *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_CAP_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM_PT_Marshal(const TPM_PT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_PT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM_PT_PCR_Marshal(const TPM_PT_PCR *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_PT_PCR_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM_HANDLE_Marshal(const TPM_HANDLE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_HANDLE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMA_ALGORITHM_Marshal(const TPMA_ALGORITHM *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMA_ALGORITHM_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMA_OBJECT_Marshal(const TPMA_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMA_OBJECT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMA_SESSION_Marshal(const TPMA_SESSION *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMA_SESSION_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMA_LOCALITY_Marshal(const TPMA_LOCALITY *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMA_LOCALITY_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM_CC_Marshal(const TPM_CC *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_CC_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMA_CC_Marshal(const TPMA_CC *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMA_CC_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_YES_NO_Marshal(const TPMI_YES_NO *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_YES_NO_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_DH_OBJECT_Marshal(const TPMI_DH_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_DH_OBJECT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_DH_PERSISTENT_Marshal(const TPMI_DH_PERSISTENT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_DH_PERSISTENT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_DH_ENTITY_Marshal(const TPMI_DH_ENTITY *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_DH_ENTITY_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_DH_PCR_Marshal(const TPMI_DH_PCR  *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_DH_PCR_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_SH_AUTH_SESSION_Marshal(const TPMI_SH_AUTH_SESSION *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_SH_AUTH_SESSION_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_SH_HMAC_Marshal(const TPMI_SH_HMAC *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_SH_HMAC_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_SH_POLICY_Marshal(const TPMI_SH_POLICY*source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_SH_POLICY_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_DH_CONTEXT_Marshal(const TPMI_DH_CONTEXT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_DH_CONTEXT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_RH_HIERARCHY_Marshal(const TPMI_RH_HIERARCHY *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_RH_HIERARCHY_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_RH_ENABLES_Marshal(const TPMI_RH_ENABLES *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_RH_ENABLES_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_RH_HIERARCHY_AUTH_Marshal(const TPMI_RH_HIERARCHY_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_RH_HIERARCHY_AUTH_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_RH_PLATFORM_Marshal(const TPMI_RH_PLATFORM *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_RH_PLATFORM_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_RH_ENDORSEMENT_Marshal(const TPMI_RH_ENDORSEMENT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_RH_ENDORSEMENT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_RH_PROVISION_Marshal(const TPMI_RH_PROVISION *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_RH_PROVISION_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_RH_CLEAR_Marshal(const TPMI_RH_CLEAR *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_RH_CLEAR_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_RH_NV_AUTH_Marshal(const TPMI_RH_NV_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_RH_NV_AUTH_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_RH_LOCKOUT_Marshal(const TPMI_RH_LOCKOUT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_RH_LOCKOUT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_RH_NV_INDEX_Marshal(const TPMI_RH_NV_INDEX *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_RH_NV_INDEX_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ALG_HASH_Marshal(const TPMI_ALG_HASH *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ALG_HASH_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ALG_SYM_Marshal(const TPMI_ALG_SYM *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ALG_SYM_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ALG_SYM_OBJECT_Marshal(const TPMI_ALG_SYM_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ALG_SYM_OBJECT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ALG_SYM_MODE_Marshal(const TPMI_ALG_SYM_MODE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ALG_SYM_MODE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ALG_KDF_Marshal(const TPMI_ALG_KDF *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ALG_KDF_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ALG_SIG_SCHEME_Marshal(const TPMI_ALG_SIG_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ALG_SIG_SCHEME_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ECC_KEY_EXCHANGE_Marshal(const TPMI_ECC_KEY_EXCHANGE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ECC_KEY_EXCHANGE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ST_COMMAND_TAG_Marshal(const TPMI_ST_COMMAND_TAG *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ST_COMMAND_TAG_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ALG_MAC_SCHEME_Marshal(const TPMI_ALG_MAC_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ALG_MAC_SCHEME_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ALG_CIPHER_MODE_Marshal(const TPMI_ALG_CIPHER_MODE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ALG_CIPHER_MODE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMU_HA_Marshal(const TPMU_HA *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_HA_Marshalu(source, written, buffer, (uint32_t *)size, selector);
}
TPM_RC
TSS_TPMT_HA_Marshal(const TPMT_HA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_HA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_DIGEST_Marshal(const TPM2B_DIGEST *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_DIGEST_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_DATA_Marshal(const TPM2B_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_DATA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_NONCE_Marshal(const TPM2B_NONCE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_NONCE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_AUTH_Marshal(const TPM2B_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_AUTH_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_OPERAND_Marshal(const TPM2B_OPERAND *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_OPERAND_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_EVENT_Marshal(const TPM2B_EVENT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_EVENT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_MAX_BUFFER_Marshal(const TPM2B_MAX_BUFFER *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_MAX_BUFFER_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_MAX_NV_BUFFER_Marshal(const TPM2B_MAX_NV_BUFFER *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_MAX_NV_BUFFER_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_TIMEOUT_Marshal(const TPM2B_TIMEOUT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_TIMEOUT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_IV_Marshal(const TPM2B_IV *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_IV_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_NAME_Marshal(const TPM2B_NAME *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_NAME_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_PCR_SELECTION_Marshal(const TPMS_PCR_SELECTION *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_PCR_SELECTION_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMT_TK_CREATION_Marshal(const TPMT_TK_CREATION *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_TK_CREATION_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMT_TK_VERIFIED_Marshal(const TPMT_TK_VERIFIED *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_TK_VERIFIED_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMT_TK_AUTH_Marshal(const TPMT_TK_AUTH *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_TK_AUTH_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMT_TK_HASHCHECK_Marshal(const TPMT_TK_HASHCHECK *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_TK_HASHCHECK_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_ALG_PROPERTY_Marshal(const TPMS_ALG_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_ALG_PROPERTY_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_TAGGED_PROPERTY_Marshal(const TPMS_TAGGED_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_TAGGED_PROPERTY_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_TAGGED_PCR_SELECT_Marshal(const TPMS_TAGGED_PCR_SELECT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_TAGGED_PCR_SELECT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPML_CC_Marshal(const TPML_CC *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_CC_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPML_CCA_Marshal(const TPML_CCA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_CCA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPML_ALG_Marshal(const TPML_ALG *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_ALG_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPML_HANDLE_Marshal(const TPML_HANDLE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_HANDLE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPML_DIGEST_Marshal(const TPML_DIGEST *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_DIGEST_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPML_DIGEST_VALUES_Marshal(const TPML_DIGEST_VALUES *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_DIGEST_VALUES_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPML_PCR_SELECTION_Marshal(const TPML_PCR_SELECTION *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_PCR_SELECTION_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPML_ALG_PROPERTY_Marshal(const TPML_ALG_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_ALG_PROPERTY_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPML_TAGGED_TPM_PROPERTY_Marshal(const TPML_TAGGED_TPM_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_TAGGED_TPM_PROPERTY_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPML_TAGGED_PCR_PROPERTY_Marshal(const TPML_TAGGED_PCR_PROPERTY *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_TAGGED_PCR_PROPERTY_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPML_ECC_CURVE_Marshal(const TPML_ECC_CURVE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_ECC_CURVE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMU_CAPABILITIES_Marshal(const TPMU_CAPABILITIES *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_CAPABILITIES_Marshalu(source, written, buffer, (uint32_t *)size, selector);
}
TPM_RC
TSS_TPMS_CAPABILITY_DATA_Marshal(const TPMS_CAPABILITY_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_CAPABILITY_DATA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_CLOCK_INFO_Marshal(const TPMS_CLOCK_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_CLOCK_INFO_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_TIME_INFO_Marshal(const TPMS_TIME_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_TIME_INFO_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_TIME_ATTEST_INFO_Marshal(const TPMS_TIME_ATTEST_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_TIME_ATTEST_INFO_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_CERTIFY_INFO_Marshal(const TPMS_CERTIFY_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_CERTIFY_INFO_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_QUOTE_INFO_Marshal(const TPMS_QUOTE_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_QUOTE_INFO_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_COMMAND_AUDIT_INFO_Marshal(const TPMS_COMMAND_AUDIT_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_COMMAND_AUDIT_INFO_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SESSION_AUDIT_INFO_Marshal(const TPMS_SESSION_AUDIT_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SESSION_AUDIT_INFO_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_CREATION_INFO_Marshal(const TPMS_CREATION_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_CREATION_INFO_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_NV_CERTIFY_INFO_Marshal(const TPMS_NV_CERTIFY_INFO *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_NV_CERTIFY_INFO_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ST_ATTEST_Marshal(const TPMI_ST_ATTEST *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ST_ATTEST_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMU_ATTEST_Marshal(const TPMU_ATTEST  *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_ATTEST_Marshalu(source, written, buffer, (uint32_t *)size, selector);
}
TPM_RC
TSS_TPMS_ATTEST_Marshal(const TPMS_ATTEST  *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_ATTEST_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_ATTEST_Marshal(const TPM2B_ATTEST *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_ATTEST_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_AUTH_COMMAND_Marshal(const TPMS_AUTH_COMMAND *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_AUTH_COMMAND_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_AES_KEY_BITS_Marshal(const TPMI_AES_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_AES_KEY_BITS_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMU_SYM_KEY_BITS_Marshal(const TPMU_SYM_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_SYM_KEY_BITS_Marshalu(source, written, buffer, (uint32_t *)size, selector);
}
TPM_RC
TSS_TPMU_SYM_MODE_Marshal(const TPMU_SYM_MODE *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_SYM_MODE_Marshalu(source, written, buffer, (uint32_t *)size, selector);
}
TPM_RC
TSS_TPMT_SYM_DEF_Marshal(const TPMT_SYM_DEF *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_SYM_DEF_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMT_SYM_DEF_OBJECT_Marshal(const TPMT_SYM_DEF_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_SYM_DEF_OBJECT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_SYM_KEY_Marshal(const TPM2B_SYM_KEY *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_SYM_KEY_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_LABEL_Marshal(const TPM2B_LABEL *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_LABEL_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_DERIVE_Marshal(const TPMS_DERIVE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_DERIVE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SYMCIPHER_PARMS_Marshal(const TPMS_SYMCIPHER_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SYMCIPHER_PARMS_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_SENSITIVE_DATA_Marshal(const TPM2B_SENSITIVE_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_SENSITIVE_DATA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SENSITIVE_CREATE_Marshal(const TPMS_SENSITIVE_CREATE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SENSITIVE_CREATE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_SENSITIVE_CREATE_Marshal(const TPM2B_SENSITIVE_CREATE  *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_SENSITIVE_CREATE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SCHEME_HASH_Marshal(const TPMS_SCHEME_HASH *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SCHEME_HASH_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SCHEME_ECDAA_Marshal(const TPMS_SCHEME_ECDAA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SCHEME_ECDAA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ALG_KEYEDHASH_SCHEME_Marshal(const TPMI_ALG_KEYEDHASH_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ALG_KEYEDHASH_SCHEME_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SCHEME_HMAC_Marshal(const TPMS_SCHEME_HMAC *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SCHEME_HMAC_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SCHEME_XOR_Marshal(const TPMS_SCHEME_XOR *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SCHEME_XOR_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMU_SCHEME_KEYEDHASH_Marshal(const TPMU_SCHEME_KEYEDHASH *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_SCHEME_KEYEDHASH_Marshalu(source, written, buffer, (uint32_t *)size, selector);
}
TPM_RC
TSS_TPMT_KEYEDHASH_SCHEME_Marshal(const TPMT_KEYEDHASH_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_KEYEDHASH_SCHEME_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SIG_SCHEME_RSASSA_Marshal(const TPMS_SIG_SCHEME_RSASSA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIG_SCHEME_RSASSA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SIG_SCHEME_RSAPSS_Marshal(const TPMS_SIG_SCHEME_RSAPSS *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIG_SCHEME_RSAPSS_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SIG_SCHEME_ECDSA_Marshal(const TPMS_SIG_SCHEME_ECDSA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIG_SCHEME_ECDSA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SIG_SCHEME_SM2_Marshal(const TPMS_SIG_SCHEME_SM2 *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIG_SCHEME_SM2_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SIG_SCHEME_ECSCHNORR_Marshal(const TPMS_SIG_SCHEME_ECSCHNORR *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIG_SCHEME_ECSCHNORR_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SIG_SCHEME_ECDAA_Marshal(const TPMS_SIG_SCHEME_ECDAA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIG_SCHEME_ECDAA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMU_SIG_SCHEME_Marshal(const TPMU_SIG_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_SIG_SCHEME_Marshalu(source, written, buffer, (uint32_t *)size, selector);
}
TPM_RC
TSS_TPMT_SIG_SCHEME_Marshal(const TPMT_SIG_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_SIG_SCHEME_Marshalu(source, written, buffer, (uint32_t *)size);
}

/* NOTE: Marked as const function in header */

TPM_RC
TSS_TPMS_ENC_SCHEME_OAEP_Marshal(const TPMS_ENC_SCHEME_OAEP *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_ENC_SCHEME_OAEP_Marshalu(source, written, buffer, (uint32_t *)size);
}

/* NOTE: Marked as const function in header */

TPM_RC
TSS_TPMS_ENC_SCHEME_RSAES_Marshal(const TPMS_ENC_SCHEME_RSAES *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_ENC_SCHEME_RSAES_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_KEY_SCHEME_ECDH_Marshal(const TPMS_KEY_SCHEME_ECDH *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_KEY_SCHEME_ECDH_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_KEY_SCHEME_ECMQV_Marshal(const TPMS_KEY_SCHEME_ECMQV *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_KEY_SCHEME_ECMQV_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SCHEME_MGF1_Marshal(const TPMS_SCHEME_MGF1 *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SCHEME_MGF1_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SCHEME_KDF1_SP800_56A_Marshal(const TPMS_SCHEME_KDF1_SP800_56A *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SCHEME_KDF1_SP800_56A_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SCHEME_KDF2_Marshal(const TPMS_SCHEME_KDF2 *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SCHEME_KDF2_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SCHEME_KDF1_SP800_108_Marshal(const TPMS_SCHEME_KDF1_SP800_108 *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SCHEME_KDF1_SP800_108_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMU_KDF_SCHEME_Marshal(const TPMU_KDF_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_KDF_SCHEME_Marshalu(source, written, buffer, (uint32_t *)size, selector);
}
TPM_RC
TSS_TPMT_KDF_SCHEME_Marshal(const TPMT_KDF_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_KDF_SCHEME_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMU_ASYM_SCHEME_Marshal(const TPMU_ASYM_SCHEME  *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_ASYM_SCHEME_Marshalu(source, written, buffer, (uint32_t *)size, selector);
}
TPM_RC
TSS_TPMI_ALG_RSA_SCHEME_Marshal(const TPMI_ALG_RSA_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ALG_RSA_SCHEME_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMT_RSA_SCHEME_Marshal(const TPMT_RSA_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_RSA_SCHEME_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ALG_RSA_DECRYPT_Marshal(const TPMI_ALG_RSA_DECRYPT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ALG_RSA_DECRYPT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMT_RSA_DECRYPT_Marshal(const TPMT_RSA_DECRYPT  *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_RSA_DECRYPT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_PUBLIC_KEY_RSA_Marshal(const TPM2B_PUBLIC_KEY_RSA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_PUBLIC_KEY_RSA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_RSA_KEY_BITS_Marshal(const TPMI_RSA_KEY_BITS *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_RSA_KEY_BITS_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_PRIVATE_KEY_RSA_Marshal(const TPM2B_PRIVATE_KEY_RSA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_PRIVATE_KEY_RSA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_ECC_PARAMETER_Marshal(const TPM2B_ECC_PARAMETER *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_ECC_PARAMETER_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_ECC_POINT_Marshal(const TPMS_ECC_POINT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_ECC_POINT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_ECC_POINT_Marshal(const TPM2B_ECC_POINT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_ECC_POINT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ALG_ECC_SCHEME_Marshal(const TPMI_ALG_ECC_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ALG_ECC_SCHEME_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ECC_CURVE_Marshal(const TPMI_ECC_CURVE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ECC_CURVE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMT_ECC_SCHEME_Marshal(const TPMT_ECC_SCHEME *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_ECC_SCHEME_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_ALGORITHM_DETAIL_ECC_Marshal(const TPMS_ALGORITHM_DETAIL_ECC *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_ALGORITHM_DETAIL_ECC_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SIGNATURE_RSA_Marshal(const TPMS_SIGNATURE_RSA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_RSA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SIGNATURE_RSASSA_Marshal(const TPMS_SIGNATURE_RSASSA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_RSASSA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SIGNATURE_RSAPSS_Marshal(const TPMS_SIGNATURE_RSAPSS *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_RSAPSS_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SIGNATURE_ECC_Marshal(const TPMS_SIGNATURE_ECC *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_ECC_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SIGNATURE_ECDSA_Marshal(const TPMS_SIGNATURE_ECDSA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_ECDSA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SIGNATURE_ECDAA_Marshal(const TPMS_SIGNATURE_ECDAA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_ECDAA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SIGNATURE_SM2_Marshal(const TPMS_SIGNATURE_SM2 *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_SM2_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_SIGNATURE_ECSCHNORR_Marshal(const TPMS_SIGNATURE_ECSCHNORR *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_ECSCHNORR_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMU_SIGNATURE_Marshal(const TPMU_SIGNATURE *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_SIGNATURE_Marshalu(source, written, buffer, (uint32_t *)size, selector);
}
TPM_RC
TSS_TPMT_SIGNATURE_Marshal(const TPMT_SIGNATURE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_SIGNATURE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_ENCRYPTED_SECRET_Marshal(const TPM2B_ENCRYPTED_SECRET *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_ENCRYPTED_SECRET_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMI_ALG_PUBLIC_Marshal(const TPMI_ALG_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ALG_PUBLIC_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMU_PUBLIC_ID_Marshal(const TPMU_PUBLIC_ID *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_PUBLIC_ID_Marshalu(source, written, buffer, (uint32_t *)size, selector);
}
TPM_RC
TSS_TPMS_KEYEDHASH_PARMS_Marshal(const TPMS_KEYEDHASH_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_KEYEDHASH_PARMS_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_RSA_PARMS_Marshal(const TPMS_RSA_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_RSA_PARMS_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_ECC_PARMS_Marshal(const TPMS_ECC_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_ECC_PARMS_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMU_PUBLIC_PARMS_Marshal(const TPMU_PUBLIC_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_PUBLIC_PARMS_Marshalu(source, written, buffer, (uint32_t *)size, selector);
}
TPM_RC
TSS_TPMT_PUBLIC_PARMS_Marshal(const TPMT_PUBLIC_PARMS *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_PUBLIC_PARMS_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMT_PUBLIC_Marshal(const TPMT_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_PUBLIC_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMT_PUBLIC_D_Marshal(const TPMT_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_PUBLIC_D_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_PUBLIC_Marshal(const TPM2B_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_PUBLIC_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_TEMPLATE_Marshal(const TPM2B_TEMPLATE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_TEMPLATE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMU_SENSITIVE_COMPOSITE_Marshal(const TPMU_SENSITIVE_COMPOSITE *source, UINT16 *written, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_SENSITIVE_COMPOSITE_Marshalu(source, written, buffer, (uint32_t *)size, selector);
}
TPM_RC
TSS_TPMT_SENSITIVE_Marshal(const TPMT_SENSITIVE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_SENSITIVE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_SENSITIVE_Marshal(const TPM2B_SENSITIVE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_SENSITIVE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_PRIVATE_Marshal(const TPM2B_PRIVATE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_PRIVATE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_ID_OBJECT_Marshal(const TPM2B_ID_OBJECT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_ID_OBJECT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMA_NV_Marshal(const TPMA_NV *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMA_NV_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_NV_PUBLIC_Marshal(const TPMS_NV_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_NV_PUBLIC_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_NV_PUBLIC_Marshal(const TPM2B_NV_PUBLIC *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_NV_PUBLIC_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_CONTEXT_SENSITIVE_Marshal(const TPM2B_CONTEXT_SENSITIVE *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_CONTEXT_SENSITIVE_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_CONTEXT_DATA_Marshal(const TPM2B_CONTEXT_DATA  *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_CONTEXT_DATA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_CONTEXT_Marshal(const TPMS_CONTEXT *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_CONTEXT_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPMS_CREATION_DATA_Marshal(const TPMS_CREATION_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_CREATION_DATA_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TPM2B_CREATION_DATA_Marshal(const TPM2B_CREATION_DATA *source, UINT16 *written, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_CREATION_DATA_Marshalu(source, written, buffer, (uint32_t *)size);
}



TPM_RC
TSS_Startup_In_Marshal(const Startup_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_Startup_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Shutdown_In_Marshal(const Shutdown_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_Shutdown_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_SelfTest_In_Marshal(const SelfTest_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_SelfTest_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_IncrementalSelfTest_In_Marshal(const IncrementalSelfTest_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_IncrementalSelfTest_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_StartAuthSession_In_Marshal(const StartAuthSession_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_StartAuthSession_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyRestart_In_Marshal(const PolicyRestart_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyRestart_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Create_In_Marshal(const Create_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_Create_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Load_In_Marshal(const Load_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_Load_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_LoadExternal_In_Marshal(const LoadExternal_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_LoadExternal_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ReadPublic_In_Marshal(const ReadPublic_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_ReadPublic_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ActivateCredential_In_Marshal(const ActivateCredential_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_ActivateCredential_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_MakeCredential_In_Marshal(const MakeCredential_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_MakeCredential_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Unseal_In_Marshal(const Unseal_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_Unseal_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ObjectChangeAuth_In_Marshal(const ObjectChangeAuth_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_ObjectChangeAuth_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_CreateLoaded_In_Marshal(const CreateLoaded_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_CreateLoaded_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Duplicate_In_Marshal(const Duplicate_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_Duplicate_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Rewrap_In_Marshal(const Rewrap_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_Rewrap_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Import_In_Marshal(const Import_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_Import_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_RSA_Encrypt_In_Marshal(const RSA_Encrypt_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_RSA_Encrypt_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_RSA_Decrypt_In_Marshal(const RSA_Decrypt_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_RSA_Decrypt_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ECDH_KeyGen_In_Marshal(const ECDH_KeyGen_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_ECDH_KeyGen_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ECDH_ZGen_In_Marshal(const ECDH_ZGen_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_ECDH_ZGen_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ECC_Parameters_In_Marshal(const ECC_Parameters_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_ECC_Parameters_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ZGen_2Phase_In_Marshal(const ZGen_2Phase_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_ZGen_2Phase_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_EncryptDecrypt_In_Marshal(const EncryptDecrypt_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_EncryptDecrypt_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_EncryptDecrypt2_In_Marshal(const EncryptDecrypt2_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_EncryptDecrypt2_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Hash_In_Marshal(const Hash_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_Hash_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_HMAC_In_Marshal(const HMAC_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_HMAC_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_GetRandom_In_Marshal(const GetRandom_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_GetRandom_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_StirRandom_In_Marshal(const StirRandom_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_StirRandom_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_HMAC_Start_In_Marshal(const HMAC_Start_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_HMAC_Start_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_HashSequenceStart_In_Marshal(const HashSequenceStart_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_HashSequenceStart_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_SequenceUpdate_In_Marshal(const SequenceUpdate_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_SequenceUpdate_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_SequenceComplete_In_Marshal(const SequenceComplete_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_SequenceComplete_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_EventSequenceComplete_In_Marshal(const EventSequenceComplete_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_EventSequenceComplete_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Certify_In_Marshal(const Certify_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_Certify_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_CertifyCreation_In_Marshal(const CertifyCreation_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_CertifyCreation_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Quote_In_Marshal(const Quote_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_Quote_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_GetSessionAuditDigest_In_Marshal(const GetSessionAuditDigest_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_GetSessionAuditDigest_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_GetCommandAuditDigest_In_Marshal(const GetCommandAuditDigest_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_GetCommandAuditDigest_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_GetTime_In_Marshal(const GetTime_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_GetTime_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Commit_In_Marshal(const Commit_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_Commit_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_EC_Ephemeral_In_Marshal(const EC_Ephemeral_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_EC_Ephemeral_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_VerifySignature_In_Marshal(const VerifySignature_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_VerifySignature_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Sign_In_Marshal(const Sign_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_Sign_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_SetCommandCodeAuditStatus_In_Marshal(const SetCommandCodeAuditStatus_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_SetCommandCodeAuditStatus_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PCR_Extend_In_Marshal(const PCR_Extend_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PCR_Extend_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PCR_Event_In_Marshal(const PCR_Event_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PCR_Event_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PCR_Read_In_Marshal(const PCR_Read_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PCR_Read_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PCR_Allocate_In_Marshal(const PCR_Allocate_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PCR_Allocate_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PCR_SetAuthPolicy_In_Marshal(const PCR_SetAuthPolicy_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PCR_SetAuthPolicy_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PCR_SetAuthValue_In_Marshal(const PCR_SetAuthValue_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PCR_SetAuthValue_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PCR_Reset_In_Marshal(const PCR_Reset_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PCR_Reset_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicySigned_In_Marshal(const PolicySigned_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicySigned_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicySecret_In_Marshal(const PolicySecret_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicySecret_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyTicket_In_Marshal(const PolicyTicket_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyTicket_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyOR_In_Marshal(const PolicyOR_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyOR_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyPCR_In_Marshal(const PolicyPCR_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyPCR_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyLocality_In_Marshal(const PolicyLocality_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyLocality_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyNV_In_Marshal(const PolicyNV_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyNV_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyCounterTimer_In_Marshal(const PolicyCounterTimer_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyCounterTimer_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyCommandCode_In_Marshal(const PolicyCommandCode_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyCommandCode_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyPhysicalPresence_In_Marshal(const PolicyPhysicalPresence_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyPhysicalPresence_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyCpHash_In_Marshal(const PolicyCpHash_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyCpHash_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyNameHash_In_Marshal(const PolicyNameHash_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyNameHash_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyDuplicationSelect_In_Marshal(const PolicyDuplicationSelect_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyDuplicationSelect_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyAuthorize_In_Marshal(const PolicyAuthorize_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyAuthorize_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyAuthValue_In_Marshal(const PolicyAuthValue_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyAuthValue_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyPassword_In_Marshal(const PolicyPassword_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyPassword_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyGetDigest_In_Marshal(const PolicyGetDigest_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyGetDigest_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyNvWritten_In_Marshal(const PolicyNvWritten_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyNvWritten_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyTemplate_In_Marshal(const PolicyTemplate_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyTemplate_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyAuthorizeNV_In_Marshal(const PolicyAuthorizeNV_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyAuthorizeNV_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_CreatePrimary_In_Marshal(const CreatePrimary_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_CreatePrimary_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_HierarchyControl_In_Marshal(const HierarchyControl_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_HierarchyControl_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_SetPrimaryPolicy_In_Marshal(const SetPrimaryPolicy_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_SetPrimaryPolicy_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ChangePPS_In_Marshal(const ChangePPS_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_ChangePPS_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ChangeEPS_In_Marshal(const ChangeEPS_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_ChangeEPS_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Clear_In_Marshal(const Clear_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_Clear_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ClearControl_In_Marshal(const ClearControl_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_ClearControl_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_HierarchyChangeAuth_In_Marshal(const HierarchyChangeAuth_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_HierarchyChangeAuth_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_DictionaryAttackLockReset_In_Marshal(const DictionaryAttackLockReset_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_DictionaryAttackLockReset_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_DictionaryAttackParameters_In_Marshal(const DictionaryAttackParameters_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_DictionaryAttackParameters_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PP_Commands_In_Marshal(const PP_Commands_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_PP_Commands_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_SetAlgorithmSet_In_Marshal(const SetAlgorithmSet_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_SetAlgorithmSet_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ContextSave_In_Marshal(const ContextSave_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_ContextSave_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ContextLoad_In_Marshal(const ContextLoad_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_ContextLoad_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_FlushContext_In_Marshal(const FlushContext_In *source, uint16_t *written, BYTE **buffer, int32_t *size) 
{
    return TSS_FlushContext_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_EvictControl_In_Marshal(const EvictControl_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_EvictControl_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ClockSet_In_Marshal(const ClockSet_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_ClockSet_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ClockRateAdjust_In_Marshal(const ClockRateAdjust_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_ClockRateAdjust_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_GetCapability_In_Marshal(const GetCapability_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_GetCapability_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_TestParms_In_Marshal(const TestParms_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_TestParms_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_DefineSpace_In_Marshal(const NV_DefineSpace_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_NV_DefineSpace_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_UndefineSpace_In_Marshal(const NV_UndefineSpace_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_NV_UndefineSpace_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_UndefineSpaceSpecial_In_Marshal(const NV_UndefineSpaceSpecial_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_NV_UndefineSpaceSpecial_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_ReadPublic_In_Marshal(const NV_ReadPublic_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_NV_ReadPublic_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_Write_In_Marshal(const NV_Write_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_NV_Write_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_Increment_In_Marshal(const NV_Increment_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_NV_Increment_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_Extend_In_Marshal(const NV_Extend_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_NV_Extend_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_SetBits_In_Marshal(const NV_SetBits_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_NV_SetBits_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_WriteLock_In_Marshal(const NV_WriteLock_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_NV_WriteLock_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_GlobalWriteLock_In_Marshal(const NV_GlobalWriteLock_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_NV_GlobalWriteLock_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_Read_In_Marshal(const NV_Read_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_NV_Read_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_ReadLock_In_Marshal(const NV_ReadLock_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_NV_ReadLock_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_ChangeAuth_In_Marshal(const NV_ChangeAuth_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_NV_ChangeAuth_In_Marshalu(source, written, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_Certify_In_Marshal(const NV_Certify_In *source, uint16_t *written, BYTE **buffer, int32_t *size)
{
    return TSS_NV_Certify_In_Marshalu(source, written, buffer, (uint32_t *)size);
}



TPM_RC
TSS_IncrementalSelfTest_Out_Unmarshal(IncrementalSelfTest_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_IncrementalSelfTest_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_GetTestResult_Out_Unmarshal(GetTestResult_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_GetTestResult_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_StartAuthSession_Out_Unmarshal(StartAuthSession_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_StartAuthSession_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Create_Out_Unmarshal(Create_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_Create_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Load_Out_Unmarshal(Load_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_Load_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_LoadExternal_Out_Unmarshal(LoadExternal_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_LoadExternal_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ReadPublic_Out_Unmarshal(ReadPublic_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_ReadPublic_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ActivateCredential_Out_Unmarshal(ActivateCredential_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_ActivateCredential_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_MakeCredential_Out_Unmarshal(MakeCredential_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_MakeCredential_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Unseal_Out_Unmarshal(Unseal_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_Unseal_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ObjectChangeAuth_Out_Unmarshal(ObjectChangeAuth_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_ObjectChangeAuth_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_CreateLoaded_Out_Unmarshal(CreateLoaded_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_CreateLoaded_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Duplicate_Out_Unmarshal(Duplicate_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_Duplicate_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Rewrap_Out_Unmarshal(Rewrap_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_Rewrap_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Import_Out_Unmarshal(Import_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_Import_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_RSA_Encrypt_Out_Unmarshal(RSA_Encrypt_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_RSA_Encrypt_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_RSA_Decrypt_Out_Unmarshal(RSA_Decrypt_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_RSA_Decrypt_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ECDH_KeyGen_Out_Unmarshal(ECDH_KeyGen_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_ECDH_KeyGen_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ECDH_ZGen_Out_Unmarshal(ECDH_ZGen_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_ECDH_ZGen_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ECC_Parameters_Out_Unmarshal(ECC_Parameters_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_ECC_Parameters_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ZGen_2Phase_Out_Unmarshal(ZGen_2Phase_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_ZGen_2Phase_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_EncryptDecrypt_Out_Unmarshal(EncryptDecrypt_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_EncryptDecrypt_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_EncryptDecrypt2_Out_Unmarshal(EncryptDecrypt2_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_EncryptDecrypt2_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Hash_Out_Unmarshal(Hash_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_Hash_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_HMAC_Out_Unmarshal(HMAC_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_HMAC_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_GetRandom_Out_Unmarshal(GetRandom_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_GetRandom_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_HMAC_Start_Out_Unmarshal(HMAC_Start_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_HMAC_Start_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_HashSequenceStart_Out_Unmarshal(HashSequenceStart_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_HashSequenceStart_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_SequenceComplete_Out_Unmarshal(SequenceComplete_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_SequenceComplete_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_EventSequenceComplete_Out_Unmarshal(EventSequenceComplete_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_EventSequenceComplete_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Certify_Out_Unmarshal(Certify_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_Certify_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_CertifyCreation_Out_Unmarshal(CertifyCreation_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_CertifyCreation_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Quote_Out_Unmarshal(Quote_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_Quote_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_GetSessionAuditDigest_Out_Unmarshal(GetSessionAuditDigest_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_GetSessionAuditDigest_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_GetCommandAuditDigest_Out_Unmarshal(GetCommandAuditDigest_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_GetCommandAuditDigest_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_GetTime_Out_Unmarshal(GetTime_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_GetTime_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Commit_Out_Unmarshal(Commit_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_Commit_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_EC_Ephemeral_Out_Unmarshal(EC_Ephemeral_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_EC_Ephemeral_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_VerifySignature_Out_Unmarshal(VerifySignature_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_VerifySignature_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_Sign_Out_Unmarshal(Sign_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_Sign_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PCR_Event_Out_Unmarshal(PCR_Event_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_PCR_Event_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PCR_Read_Out_Unmarshal(PCR_Read_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_PCR_Read_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PCR_Allocate_Out_Unmarshal(PCR_Allocate_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_PCR_Allocate_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicySigned_Out_Unmarshal(PolicySigned_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_PolicySigned_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicySecret_Out_Unmarshal(PolicySecret_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_PolicySecret_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_PolicyGetDigest_Out_Unmarshal(PolicyGetDigest_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_PolicyGetDigest_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_CreatePrimary_Out_Unmarshal(CreatePrimary_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_CreatePrimary_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ContextSave_Out_Unmarshal(ContextSave_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_ContextSave_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ContextLoad_Out_Unmarshal(ContextLoad_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_ContextLoad_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_ReadClock_Out_Unmarshal(ReadClock_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_ReadClock_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_GetCapability_Out_Unmarshal(GetCapability_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_GetCapability_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_ReadPublic_Out_Unmarshal(NV_ReadPublic_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_NV_ReadPublic_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_Read_Out_Unmarshal(NV_Read_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_NV_Read_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
TPM_RC
TSS_NV_Certify_Out_Unmarshal(NV_Certify_Out *target, TPM_ST tag, BYTE **buffer, int32_t *size)
{
    return TSS_NV_Certify_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}

#endif	/* TPM_TSS_NODEPRECATED */
#endif /* TPM 2.0 */
