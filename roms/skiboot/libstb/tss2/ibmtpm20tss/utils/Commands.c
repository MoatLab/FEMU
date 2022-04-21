/********************************************************************************/
/*										*/
/*			  Command Parameter Unmarshaling			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2012 - 2019				*/
/*										*/
/********************************************************************************/

/* The TSS using the command parameter unmarshaling to validate caller input parameters before
   sending them to the TPM.

   It is essentially the same as the TPM side code.
*/

#include "Commands_fp.h"
#include <ibmtss/Parameters.h>

#include <ibmtss/Unmarshal_fp.h>

#ifndef TPM_TSS_NOCMDCHECK

/*
  In_Unmarshal - shared by TPM and TSS
*/

TPM_RC
Startup_In_Unmarshal(Startup_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_SU_Unmarshalu(&target->startupType, buffer, size);	
	if (rc != TPM_RC_SUCCESS) {	
	    rc += RC_Startup_startupType;
	}
    }
    return rc;
}
TPM_RC
Shutdown_In_Unmarshal(Shutdown_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_SU_Unmarshalu(&target->shutdownType, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Shutdown_shutdownType;
	}
    }
    return rc;
}
TPM_RC
SelfTest_In_Unmarshal(SelfTest_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_YES_NO_Unmarshalu(&target->fullTest, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_SelfTest_fullTest;
	}
    }
    return rc;
}
TPM_RC
IncrementalSelfTest_In_Unmarshal(IncrementalSelfTest_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_ALG_Unmarshalu(&target->toTest, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_IncrementalSelfTest_toTest;
	}
    }
    return rc;
}
TPM_RC
StartAuthSession_In_Unmarshal(StartAuthSession_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->tpmKey = handles[0];
	target->bind = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NONCE_Unmarshalu(&target->nonceCaller, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_StartAuthSession_nonceCaller;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Unmarshalu(&target->encryptedSalt, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_StartAuthSession_encryptedSalt;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_SE_Unmarshalu(&target->sessionType, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_StartAuthSession_sessionType;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SYM_DEF_Unmarshalu(&target->symmetric, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_StartAuthSession_symmetric;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->authHash, buffer, size, NO);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_StartAuthSession_authHash;
	}
    }
    return rc;
}
TPM_RC
PolicyRestart_In_Unmarshal(PolicyRestart_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;
    
    if (rc == TPM_RC_SUCCESS) {
	target->sessionHandle = handles[0];
    }
    return rc;
}
TPM_RC
Create_In_Unmarshal(Create_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->parentHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_SENSITIVE_CREATE_Unmarshalu(&target->inSensitive, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Create_inSensitive;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PUBLIC_Unmarshalu(&target->inPublic, buffer, size, NO);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Create_inPublic;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->outsideInfo, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Create_outsideInfo;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_PCR_SELECTION_Unmarshalu(&target->creationPCR, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Create_creationPCR;
	}
    }
    return rc;
}
TPM_RC
Load_In_Unmarshal(Load_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->parentHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PRIVATE_Unmarshalu(&target->inPrivate, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Load_inPrivate;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PUBLIC_Unmarshalu(&target->inPublic, buffer, size, NO);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Load_inPublic;
	}
    }
    return rc;
}
TPM_RC
LoadExternal_In_Unmarshal(LoadExternal_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_SENSITIVE_Unmarshalu(&target->inPrivate, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_LoadExternal_inPrivate;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PUBLIC_Unmarshalu(&target->inPublic, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_LoadExternal_inPublic;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_RH_HIERARCHY_Unmarshalu(&target->hierarchy, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_LoadExternal_hierarchy;
	}
    }
    return rc;
}

TPM_RC
ReadPublic_In_Unmarshal(ReadPublic_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->objectHandle = handles[0];
    }
    return rc;
}
TPM_RC
ActivateCredential_In_Unmarshal(ActivateCredential_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->activateHandle = handles[0];
	target->keyHandle = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ID_OBJECT_Unmarshalu(&target->credentialBlob, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_ActivateCredential_credentialBlob;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Unmarshalu(&target->secret, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_ActivateCredential_secret;
	}
    }
    return rc;
}
TPM_RC
MakeCredential_In_Unmarshal(MakeCredential_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->handle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->credential, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_MakeCredential_credential;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->objectName, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_MakeCredential_objectName;
	}
    }
    return rc;
}
TPM_RC
Unseal_In_Unmarshal(Unseal_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->itemHandle = handles[0];
    }
    return rc;
}
TPM_RC
ObjectChangeAuth_In_Unmarshal(ObjectChangeAuth_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->objectHandle = handles[0];
	target->parentHandle = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_AUTH_Unmarshalu(&target->newAuth, buffer, size);
    }
    return rc;
}
TPM_RC
CreateLoaded_In_Unmarshal(CreateLoaded_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->parentHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_SENSITIVE_CREATE_Unmarshalu(&target->inSensitive, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Create_inSensitive;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_TEMPLATE_Unmarshalu(&target->inPublic, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_CreateLoaded_inPublic;
	}
    }
    return rc;
}
TPM_RC
Duplicate_In_Unmarshal(Duplicate_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->objectHandle = handles[0];
	target->newParentHandle = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->encryptionKeyIn, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Duplicate_encryptionKeyIn;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Unmarshalu(&target->symmetricAlg, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Duplicate_symmetricAlg;
	}
    }
    return rc;
}
TPM_RC
Rewrap_In_Unmarshal(Rewrap_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->oldParent = handles[0];
	target->newParent = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PRIVATE_Unmarshalu(&target->inDuplicate, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Rewrap_inDuplicate;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->name, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Rewrap_name;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Unmarshalu(&target->inSymSeed, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Rewrap_inSymSeed;
	}
    }
    return rc;
}
TPM_RC
Import_In_Unmarshal(Import_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->parentHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->encryptionKey, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PUBLIC_Unmarshalu(&target->objectPublic, buffer, size, NO);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Import_objectPublic;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PRIVATE_Unmarshalu(&target->duplicate, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Import_duplicate;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ENCRYPTED_SECRET_Unmarshalu(&target->inSymSeed, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Import_inSymSeed;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Unmarshalu(&target->symmetricAlg, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Import_symmetricAlg;
	}
    }
    return rc;
}
TPM_RC
RSA_Encrypt_In_Unmarshal(RSA_Encrypt_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->keyHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PUBLIC_KEY_RSA_Unmarshalu(&target->message, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_RSA_Encrypt_message;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_RSA_DECRYPT_Unmarshalu(&target->inScheme, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_RSA_Encrypt_inScheme;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->label, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_RSA_Encrypt_label;
	}
    }
    return rc;
}
TPM_RC
RSA_Decrypt_In_Unmarshal(RSA_Decrypt_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->keyHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PUBLIC_KEY_RSA_Unmarshalu(&target->cipherText, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_RSA_Decrypt_cipherText;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_RSA_DECRYPT_Unmarshalu(&target->inScheme, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_RSA_Decrypt_inScheme;
	}
   }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->label, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_RSA_Decrypt_label;
	}
    }
    return rc;
}
TPM_RC
ECDH_KeyGen_In_Unmarshal(ECDH_KeyGen_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->keyHandle = handles[0];
    }
    return rc;
}
TPM_RC
ECDH_ZGen_In_Unmarshal(ECDH_ZGen_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->keyHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_POINT_Unmarshalu(&target->inPoint, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_ECDH_ZGen_inPoint;
	}
    }
    return rc;
}
TPM_RC
ECC_Parameters_In_Unmarshal(ECC_Parameters_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ECC_CURVE_Unmarshalu(&target->curveID, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_ECC_Parameters_curveID;
	}
    }
    return rc;
}
TPM_RC
ZGen_2Phase_In_Unmarshal(ZGen_2Phase_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->keyA = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_POINT_Unmarshalu(&target->inQsB, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_ZGen_2Phase_inQsB;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_POINT_Unmarshalu(&target->inQeB, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_ZGen_2Phase_inQeB;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ECC_KEY_EXCHANGE_Unmarshalu(&target->inScheme, buffer, size, NO);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_ZGen_2Phase_inScheme;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->counter, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_ZGen_2Phase_counter;
	}
    }
    return rc;
}
TPM_RC
EncryptDecrypt_In_Unmarshal(EncryptDecrypt_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->keyHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_YES_NO_Unmarshalu(&target->decrypt, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_EncryptDecrypt_decrypt;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_SYM_MODE_Unmarshalu(&target->mode, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_EncryptDecrypt_mode;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_IV_Unmarshalu(&target->ivIn, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_EncryptDecrypt_ivIn;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_MAX_BUFFER_Unmarshalu(&target->inData, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_EncryptDecrypt_inData;
	}
    }
    return rc;
}
TPM_RC
EncryptDecrypt2_In_Unmarshal(EncryptDecrypt2_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->keyHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_MAX_BUFFER_Unmarshalu(&target->inData, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_EncryptDecrypt2_inData;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_YES_NO_Unmarshalu(&target->decrypt, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_EncryptDecrypt2_decrypt;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_SYM_MODE_Unmarshalu(&target->mode, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_EncryptDecrypt2_mode;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_IV_Unmarshalu(&target->ivIn, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_EncryptDecrypt2_ivIn;
	}
    }
    return rc;
}
TPM_RC
Hash_In_Unmarshal(Hash_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_MAX_BUFFER_Unmarshalu(&target->data, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Hash_data;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->hashAlg, buffer, size, NO);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Hash_hashAlg;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_RH_HIERARCHY_Unmarshalu(&target->hierarchy, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Hash_hierarchy;
	}
    }
    return rc;
}
TPM_RC
HMAC_In_Unmarshal(HMAC_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->handle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_MAX_BUFFER_Unmarshalu(&target->buffer, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_HMAC_buffer;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->hashAlg, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_HMAC_hashAlg;
	}
    }
    return rc;
}
TPM_RC
GetRandom_In_Unmarshal(GetRandom_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->bytesRequested, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_GetRandom_bytesRequested;
	}
    }
    return rc;
}
TPM_RC
StirRandom_In_Unmarshal(StirRandom_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_SENSITIVE_DATA_Unmarshalu(&target->inData, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_StirRandom_inData;
	}
    }
    return rc;
}
TPM_RC
HMAC_Start_In_Unmarshal(HMAC_Start_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->handle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_AUTH_Unmarshalu(&target->auth, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_HMAC_Start_auth;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->hashAlg, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_HMAC_Start_hashAlg;
	}
    }
    return rc;
}
TPM_RC
HashSequenceStart_In_Unmarshal(HashSequenceStart_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_AUTH_Unmarshalu(&target->auth, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_HashSequenceStart_auth;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->hashAlg, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_HashSequenceStart_hashAlg;
	}
    }
    return rc;
}
TPM_RC
SequenceUpdate_In_Unmarshal(SequenceUpdate_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->sequenceHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_MAX_BUFFER_Unmarshalu(&target->buffer, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_SequenceUpdate_buffer;
	}
    }
    return rc;
}
TPM_RC
SequenceComplete_In_Unmarshal(SequenceComplete_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->sequenceHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_MAX_BUFFER_Unmarshalu(&target->buffer, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_SequenceComplete_buffer;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_RH_HIERARCHY_Unmarshalu(&target->hierarchy, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_SequenceComplete_hierarchy;
	}
    }
    return rc;
}
TPM_RC
EventSequenceComplete_In_Unmarshal(EventSequenceComplete_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->pcrHandle = handles[0];
	target->sequenceHandle = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_MAX_BUFFER_Unmarshalu(&target->buffer, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_EventSequenceComplete_buffer;
	}
    }
    return rc;
}
TPM_RC
Certify_In_Unmarshal(Certify_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->objectHandle = handles[0];
	target->signHandle = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->qualifyingData, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Certify_qualifyingData;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIG_SCHEME_Unmarshalu(&target->inScheme, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Certify_inScheme;
	}
    }
    return rc;
}
TPM_RC
CertifyX509_In_Unmarshal(CertifyX509_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->objectHandle = handles[0];
	target->signHandle = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->reserved, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_CertifyX509_reserved;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIG_SCHEME_Unmarshalu(&target->inScheme, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_CertifyX509_inScheme;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_MAX_BUFFER_Unmarshalu(&target->partialCertificate, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_CertifyX509_partialCertificate;
	}
    }
    return rc;
}
TPM_RC
CertifyCreation_In_Unmarshal(CertifyCreation_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->signHandle = handles[0];
	target->objectHandle = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->qualifyingData, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_CertifyCreation_creationHash;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->creationHash, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_CertifyCreation_creationHash;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIG_SCHEME_Unmarshalu(&target->inScheme, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_CertifyCreation_inScheme;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_TK_CREATION_Unmarshalu(&target->creationTicket, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_CertifyCreation_creationTicket;
	}
    }
    return rc;
}
TPM_RC
Quote_In_Unmarshal(Quote_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->signHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->qualifyingData, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Quote_qualifyingData;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIG_SCHEME_Unmarshalu(&target->inScheme, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Quote_inScheme;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_PCR_SELECTION_Unmarshalu(&target->PCRselect, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Quote_PCRselect;
	}
    }
    return rc;
}
TPM_RC
GetSessionAuditDigest_In_Unmarshal(GetSessionAuditDigest_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->privacyAdminHandle = handles[0];
	target->signHandle = handles[1];
	target->sessionHandle = handles[2];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->qualifyingData, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_GetSessionAuditDigest_qualifyingData;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIG_SCHEME_Unmarshalu(&target->inScheme, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_GetSessionAuditDigest_inScheme;
	}
    }
    return rc;
}
TPM_RC
GetCommandAuditDigest_In_Unmarshal(GetCommandAuditDigest_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->privacyHandle = handles[0];
	target->signHandle = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->qualifyingData, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_GetCommandAuditDigest_qualifyingData;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIG_SCHEME_Unmarshalu(&target->inScheme, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_GetCommandAuditDigest_inScheme;
	}
    }
    return rc;
}
TPM_RC
GetTime_In_Unmarshal(GetTime_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->privacyAdminHandle = handles[0];
	target->signHandle = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->qualifyingData, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_GetTime_qualifyingData;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIG_SCHEME_Unmarshalu(&target->inScheme, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_GetTime_inScheme;
	}
    }
    return rc;
}
TPM_RC
Commit_In_Unmarshal(Commit_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->signHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_POINT_Unmarshalu(&target->P1, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Commit_P1;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_SENSITIVE_DATA_Unmarshalu(&target->s2, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Commit_s2;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_PARAMETER_Unmarshalu(&target->y2, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Commit_y2;
	}
    }
    return rc;
}
TPM_RC
EC_Ephemeral_In_Unmarshal(EC_Ephemeral_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ECC_CURVE_Unmarshalu(&target->curveID, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_EC_Ephemeral_curveID;
	}
    }
    return rc;
}
TPM_RC
VerifySignature_In_Unmarshal(VerifySignature_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->keyHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->digest, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_VerifySignature_digest;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIGNATURE_Unmarshalu(&target->signature, buffer, size, NO);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_VerifySignature_signature;
	}
    }
    return rc;
}
TPM_RC
Sign_In_Unmarshal(Sign_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->keyHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->digest, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Sign_digest;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIG_SCHEME_Unmarshalu(&target->inScheme, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Sign_inScheme;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_TK_HASHCHECK_Unmarshalu(&target->validation, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_Sign_validation;
	}
    }
    return rc;
}
TPM_RC
SetCommandCodeAuditStatus_In_Unmarshal(SetCommandCodeAuditStatus_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->auth = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->auditAlg, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_SetCommandCodeAuditStatus_auditAlg;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_CC_Unmarshalu(&target->setList, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_SetCommandCodeAuditStatus_setList;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_CC_Unmarshalu(&target->clearList, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_SetCommandCodeAuditStatus_clearList;
	}
    }
    return rc;
}
TPM_RC
PCR_Extend_In_Unmarshal(PCR_Extend_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->pcrHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_DIGEST_VALUES_Unmarshalu(&target->digests, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PCR_Extend_digests;
	}
    }
    return rc;
}
TPM_RC
PCR_Event_In_Unmarshal(PCR_Event_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->pcrHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_EVENT_Unmarshalu(&target->eventData, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PCR_Event_eventData;
	}
    }
    return rc;
}
TPM_RC
PCR_Read_In_Unmarshal(PCR_Read_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_PCR_SELECTION_Unmarshalu(&target->pcrSelectionIn, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PCR_Read_pcrSelectionIn;
	}
    }
    return rc;
}
TPM_RC
PCR_Allocate_In_Unmarshal(PCR_Allocate_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_PCR_SELECTION_Unmarshalu(&target->pcrAllocation, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PCR_Allocate_pcrAllocation;
	}
    }
    return rc;
}
TPM_RC
PCR_SetAuthPolicy_In_Unmarshal(PCR_SetAuthPolicy_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->authPolicy, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PCR_SetAuthPolicy_authPolicy;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->hashAlg, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PCR_SetAuthPolicy_hashAlg;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_DH_PCR_Unmarshalu(&target->pcrNum, buffer, size, NO);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PCR_SetAuthPolicy_pcrNum;
	}
    }
    return rc;
}
TPM_RC
PCR_SetAuthValue_In_Unmarshal(PCR_SetAuthValue_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->pcrHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->auth, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PCR_SetAuthValue_auth;
	}
    }
    return rc;
}
TPM_RC
PCR_Reset_In_Unmarshal(PCR_Reset_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->pcrHandle = handles[0];
    }
    return rc;
}
TPM_RC
PolicySigned_In_Unmarshal(PolicySigned_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->authObject = handles[0];
	target->policySession = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NONCE_Unmarshalu(&target->nonceTPM, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicySigned_nonceTPM;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->cpHashA, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicySigned_cpHashA;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NONCE_Unmarshalu(&target->policyRef, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicySigned_policyRef;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_INT32_Unmarshalu(&target->expiration, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicySigned_expiration;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIGNATURE_Unmarshalu(&target->auth, buffer, size, NO);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicySigned_auth;
	}
    }
    return rc;
}
TPM_RC
PolicySecret_In_Unmarshal(PolicySecret_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
	target->policySession = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NONCE_Unmarshalu(&target->nonceTPM, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicySecret_nonceTPM;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->cpHashA, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicySecret_cpHashA;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NONCE_Unmarshalu(&target->policyRef, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicySecret_policyRef;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_INT32_Unmarshalu(&target->expiration, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicySecret_expiration;
	}
    }
    return rc;
}
TPM_RC
PolicyTicket_In_Unmarshal(PolicyTicket_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_TIMEOUT_Unmarshalu(&target->timeout, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyTicket_timeout;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->cpHashA, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyTicket_cpHashA;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NONCE_Unmarshalu(&target->policyRef, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyTicket_policyRef;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->authName, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyTicket_authName;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_TK_AUTH_Unmarshalu(&target->ticket, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyTicket_ticket;
	}
    }
    return rc;
}
TPM_RC
PolicyOR_In_Unmarshal(PolicyOR_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	/* Policy OR requires at least two OR terms */
	rc = TSS_TPML_DIGEST_Unmarshalu(&target->pHashList, buffer, size, 2);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyOR_pHashList;
	}
    }
    return rc;
}
TPM_RC
PolicyPCR_In_Unmarshal(PolicyPCR_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->pcrDigest, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyPCR_pcrDigest;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_PCR_SELECTION_Unmarshalu(&target->pcrs, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyPCR_pcrs;
	}
    }
    return rc;
}
TPM_RC
PolicyLocality_In_Unmarshal(PolicyLocality_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMA_LOCALITY_Unmarshalu(&target->locality, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyLocality_locality;
	}
    }
    return rc;
}
TPM_RC
PolicyNV_In_Unmarshal(PolicyNV_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
	target->nvIndex = handles[1];
	target->policySession = handles[2];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_OPERAND_Unmarshalu(&target->operandB, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyNV_operandB;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->offset, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyNV_offset;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_EO_Unmarshalu(&target->operation, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyNV_operation;
	}
    }
    return rc;
}
TPM_RC
PolicyAuthorizeNV_In_Unmarshal(PolicyAuthorizeNV_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
	target->nvIndex = handles[1];
	target->policySession = handles[2];
    }
    return rc;
}
TPM_RC
PolicyCounterTimer_In_Unmarshal(PolicyCounterTimer_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_OPERAND_Unmarshalu(&target->operandB, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyCounterTimer_operandB;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->offset, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyCounterTimer_offset;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_EO_Unmarshalu(&target->operation, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyCounterTimer_operation;
	}
    }
    return rc;
}
TPM_RC
PolicyCommandCode_In_Unmarshal(PolicyCommandCode_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_CC_Unmarshalu(&target->code, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyCommandCode_code;
	}
    }
    return rc;
}
TPM_RC
PolicyPhysicalPresence_In_Unmarshal(PolicyPhysicalPresence_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    return rc;
}
TPM_RC
PolicyCpHash_In_Unmarshal(PolicyCpHash_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->cpHashA, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyCpHash_cpHashA;
	}
    }
    return rc;
}
TPM_RC
PolicyNameHash_In_Unmarshal(PolicyNameHash_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->nameHash, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyNameHash_nameHash;
	}
    }
    return rc;
}
TPM_RC
PolicyDuplicationSelect_In_Unmarshal(PolicyDuplicationSelect_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->objectName, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyDuplicationSelect_objectName;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->newParentName, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyDuplicationSelect_newParentName;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_YES_NO_Unmarshalu(&target->includeObject, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyDuplicationSelect_includeObject;
	}
    }
    return rc;
}
TPM_RC
PolicyAuthorize_In_Unmarshal(PolicyAuthorize_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->approvedPolicy, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyAuthorize_approvedPolicy;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NONCE_Unmarshalu(&target->policyRef, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyAuthorize_policyRef;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->keySign, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyAuthorize_keySign;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_TK_VERIFIED_Unmarshalu(&target->checkTicket, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyAuthorize_checkTicket;
	}
    }
    return rc;
}
TPM_RC
PolicyAuthValue_In_Unmarshal(PolicyAuthValue_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    return rc;
}
TPM_RC
PolicyPassword_In_Unmarshal(PolicyPassword_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    return rc;
}
TPM_RC
PolicyGetDigest_In_Unmarshal(PolicyGetDigest_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    return rc;
}
TPM_RC
PolicyNvWritten_In_Unmarshal(PolicyNvWritten_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_YES_NO_Unmarshalu(&target->writtenSet, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyNvWritten_writtenSet;
	}
    }
    return rc;
}
TPM_RC
PolicyTemplate_In_Unmarshal(PolicyTemplate_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->policySession = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->templateHash, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PolicyTemplate_templateHash;
	}
    }
    return rc;
}
TPM_RC
CreatePrimary_In_Unmarshal(CreatePrimary_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->primaryHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_SENSITIVE_CREATE_Unmarshalu(&target->inSensitive, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_CreatePrimary_inSensitive;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PUBLIC_Unmarshalu(&target->inPublic, buffer, size, NO);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_CreatePrimary_inPublic;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->outsideInfo, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_CreatePrimary_outsideInfo;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_PCR_SELECTION_Unmarshalu(&target->creationPCR, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_CreatePrimary_creationPCR;
	}
    }
    return rc;
}
TPM_RC
HierarchyControl_In_Unmarshal(HierarchyControl_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_RH_ENABLES_Unmarshalu(&target->enable, buffer, size, NO);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_HierarchyControl_enable;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_YES_NO_Unmarshalu(&target->state, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_HierarchyControl_state;
	}
    }
    return rc;
}
TPM_RC
SetPrimaryPolicy_In_Unmarshal(SetPrimaryPolicy_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->authPolicy, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_SetPrimaryPolicy_authPolicy;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->hashAlg, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_SetPrimaryPolicy_hashAlg;
	}
    }
    return rc;
}
TPM_RC
ChangePPS_In_Unmarshal(ChangePPS_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
    }
    return rc;
}
TPM_RC
ChangeEPS_In_Unmarshal(ChangeEPS_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
    }
    return rc;
}
TPM_RC
Clear_In_Unmarshal(Clear_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
    }
    return rc;
}
TPM_RC
ClearControl_In_Unmarshal(ClearControl_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->auth = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_YES_NO_Unmarshalu(&target->disable, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_ClearControl_disable;
	}
    }
    return rc;
}
TPM_RC
HierarchyChangeAuth_In_Unmarshal(HierarchyChangeAuth_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_AUTH_Unmarshalu(&target->newAuth, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_HierarchyChangeAuth_newAuth;
	}
    }
    return rc;
}
TPM_RC
DictionaryAttackLockReset_In_Unmarshal(DictionaryAttackLockReset_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->lockHandle = handles[0];
    }
    return rc;
}
TPM_RC
DictionaryAttackParameters_In_Unmarshal(DictionaryAttackParameters_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->lockHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->newMaxTries, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_DictionaryAttackParameters_newMaxTries;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->newRecoveryTime, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_DictionaryAttackParameters_newRecoveryTime;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->lockoutRecovery, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_DictionaryAttackParameters_lockoutRecovery;
	}
    }
    return rc;
}
TPM_RC
PP_Commands_In_Unmarshal(PP_Commands_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->auth = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_CC_Unmarshalu(&target->setList, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PP_Commands_setList;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_CC_Unmarshalu(&target->clearList, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_PP_Commands_clearList;
	}
    }
    return rc;
}
TPM_RC
SetAlgorithmSet_In_Unmarshal(SetAlgorithmSet_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->algorithmSet, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_SetAlgorithmSet_algorithmSet;
	}
    }
    return rc;
}
TPM_RC
ContextSave_In_Unmarshal(ContextSave_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->saveHandle = handles[0];
    }
    return rc;
}
TPM_RC
ContextLoad_In_Unmarshal(ContextLoad_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_CONTEXT_Unmarshalu(&target->context, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_ContextLoad_context;
	}
    }
    return rc;
}
TPM_RC
FlushContext_In_Unmarshal(FlushContext_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_DH_CONTEXT_Unmarshalu(&target->flushHandle, buffer, size, NO);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_FlushContext_flushHandle;
	}
    }
    return rc;
}
TPM_RC
EvictControl_In_Unmarshal(EvictControl_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->auth = handles[0];
	target->objectHandle = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_DH_PERSISTENT_Unmarshalu(&target->persistentHandle, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_EvictControl_persistentHandle;
	}
    }
    return rc;
}
TPM_RC
ClockSet_In_Unmarshal(ClockSet_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->auth = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT64_Unmarshalu(&target->newTime, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_ClockSet_newTime;
	}
    }
    return rc;
}
TPM_RC
ClockRateAdjust_In_Unmarshal(ClockRateAdjust_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->auth = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_CLOCK_ADJUST_Unmarshalu(&target->rateAdjust, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_ClockRateAdjust_rateAdjust;
	}
    }
    return rc;
}
TPM_RC
GetCapability_In_Unmarshal(GetCapability_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_CAP_Unmarshalu(&target->capability, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_GetCapability_capability;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->property, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_GetCapability_property;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->propertyCount, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_GetCapability_propertyCount;
	}
    }
    return rc;
}
TPM_RC
TestParms_In_Unmarshal(TestParms_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_PUBLIC_PARMS_Unmarshalu(&target->parameters, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_TestParms_parameters;
	}
    }
    return rc;
}
TPM_RC
NV_DefineSpace_In_Unmarshal(NV_DefineSpace_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_AUTH_Unmarshalu(&target->auth, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_NV_DefineSpace_auth;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NV_PUBLIC_Unmarshalu(&target->publicInfo, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_NV_DefineSpace_publicInfo;
	}
    }
    return rc;
}
TPM_RC
NV_UndefineSpace_In_Unmarshal(NV_UndefineSpace_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
	target->nvIndex = handles[1];
    }
    return rc;
}
TPM_RC
NV_UndefineSpaceSpecial_In_Unmarshal(NV_UndefineSpaceSpecial_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->nvIndex = handles[0];
	target->platform = handles[1];
    }
    return rc;
}
TPM_RC
NV_ReadPublic_In_Unmarshal(NV_ReadPublic_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->nvIndex = handles[0];
    }
    return rc;
}
TPM_RC
NV_Write_In_Unmarshal(NV_Write_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
	target->nvIndex = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_MAX_NV_BUFFER_Unmarshalu(&target->data, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_NV_Write_data;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->offset, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_NV_Write_offset;
	}
    }
    return rc;
}
TPM_RC
NV_Increment_In_Unmarshal(NV_Increment_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
	target->nvIndex = handles[1];
    }
    return rc;
}
TPM_RC
NV_Extend_In_Unmarshal(NV_Extend_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
 	target->nvIndex = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_MAX_NV_BUFFER_Unmarshalu(&target->data, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_NV_Extend_data;
	}
    }
    return rc;
}
TPM_RC
NV_SetBits_In_Unmarshal(NV_SetBits_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
	target->nvIndex = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT64_Unmarshalu(&target->bits, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_NV_SetBits_bits;
	}
    }
    return rc;
}
TPM_RC
NV_WriteLock_In_Unmarshal(NV_WriteLock_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
	target->nvIndex = handles[1];
    }
    return rc;
}
TPM_RC
NV_GlobalWriteLock_In_Unmarshal(NV_GlobalWriteLock_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
    }
    return rc;
}
TPM_RC
NV_Read_In_Unmarshal(NV_Read_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
 	target->nvIndex = handles[1];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->size, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_NV_Read_size;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->offset, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_NV_Read_offset;
	}
    }
    return rc;
}
TPM_RC
NV_ReadLock_In_Unmarshal(NV_ReadLock_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    buffer = buffer;
    size = size;

    if (rc == TPM_RC_SUCCESS) {
	target->authHandle = handles[0];
 	target->nvIndex = handles[1];
    }
    return rc;
}
TPM_RC
NV_ChangeAuth_In_Unmarshal(NV_ChangeAuth_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->nvIndex = handles[0];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_AUTH_Unmarshalu(&target->newAuth, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_NV_ChangeAuth_newAuth;
	}
    }
    return rc;
}
TPM_RC
NV_Certify_In_Unmarshal(NV_Certify_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	target->signHandle = handles[0];
	target->authHandle = handles[1];
	target->nvIndex = handles[2];
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->qualifyingData, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_NV_Certify_qualifyingData;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SIG_SCHEME_Unmarshalu(&target->inScheme, buffer, size, YES);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_NV_Certify_inScheme;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->size, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_NV_Certify_size;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->offset, buffer, size);
	if (rc != TPM_RC_SUCCESS) {
	    rc += RC_NV_Certify_offset;
	}
    }
    return rc;
}

#endif /* TPM_TSS_NOCMDCHECK */
