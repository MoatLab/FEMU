/********************************************************************************/
/*										*/
/*			     Structure Print and Scan Utilities			*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <ibmtss/tsserror.h>
#include <ibmtss/tssutils.h>

#include <ibmtss/tssprint.h>

extern int tssVerbose;

#ifdef TPM_TSS_NO_PRINT

/* false to compile out printf */
int tssSwallowRc = 0;
/* function prototype to match the printf prototype */
int TSS_SwallowPrintf(const char *format, ...)
{
    format = format;
    return 0;
}

#endif

#ifndef TPM_TSS_NOFILE
/* TSS_Array_Scan() converts a string to a binary array */

uint32_t TSS_Array_Scan(unsigned char **data,	/* output binary, freed by caller */
			size_t *len,
			const char *string)	/* input string */
{
    uint32_t rc = 0;
    size_t strLength;
    
    if (rc == 0) {
	strLength = strlen(string);
	if ((strLength %2) != 0) {
	    if (tssVerbose) printf("TSS_Array_Scan: Error, string length %lu is not even\n",
				   (unsigned long)strLength);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    if (rc == 0) {
	*len = strLength / 2;		/* safe because already tested for even number of bytes */
        rc = TSS_Malloc(data, (*len) + 8);
    }
    if (rc == 0) {
	unsigned int i;
	for (i = 0 ; i < *len ; i++) {
	    unsigned int tmpint;
	    int irc = sscanf(string + (2*i), "%2x", &tmpint);
	    *((*data)+i) = tmpint;
	    if (irc != 1) {
		if (tssVerbose) printf("TSS_Array_Scan: invalid hexascii\n");
		rc = TSS_RC_BAD_PROPERTY_VALUE;
	    }
	}
    }
    return rc;
}
#endif /* TPM_TSS_NOFILE */

/* TSS_PrintAll() prints 'string', the length, and then the entire byte array
 */

void TSS_PrintAll(const char *string, const unsigned char* buff, uint32_t length)
{
    TSS_PrintAlli(string, 1, buff, length);
}

/* TSS_PrintAlli() prints 'string', the length, and then the entire byte array
   
   Each line indented 'indent' spaces.
*/

void TSS_PrintAlli(const char *string, unsigned int indent, const unsigned char* buff, uint32_t length)
{
    TSS_PrintAllLogLevel(LOGLEVEL_DEBUG, string, indent, buff, length);
}

/* TSS_PrintAllLogLevel() prints based on loglevel the 'string', the length, and then the entire
   byte array

   loglevel LOGLEVEL_DEBUG prints the length and prints the array with a newline every 16 bytes.
   otherwise prints no length and prints the array with no newlines.

*/

void TSS_PrintAllLogLevel(uint32_t loglevel, const char *string, unsigned int indent,
			  const unsigned char* buff, uint32_t length)
{
    uint32_t i;
    if (buff != NULL) {
        if (loglevel == LOGLEVEL_DEBUG) {
	    printf("%*s" "%s length %u\n" "%*s", indent, "", string, length, indent, "");
	}
        else {
	    printf("%*s" "%s" "%*s", indent, "", string, indent, "");
	}
        for (i = 0 ; i < length ; i++) {
            if ((loglevel == LOGLEVEL_DEBUG) && i && !( i % 16 )) {
                printf("\n" "%*s", indent, "");
	    }
            printf("%.2x ",buff[i]);
        }
	printf("\n");
    }
    else {
        printf("%*s" "%s null\n", indent, "", string);
    }
    return;
}

#ifndef TPM_TSS_NO_PRINT
#ifdef TPM_TPM20

void TSS_TPM2B_Print(const char *string, unsigned int indent, TPM2B *source)
{
    TSS_PrintAlli(string, indent, source->buffer, source->size);
    return;
}

/* Table 9 - Definition of (UINT16) TPM_ALG_ID Constants <IN/OUT, S> */

void TSS_TPM_ALG_ID_Print(const char *string, TPM_ALG_ID source, unsigned int indent)
{
    printf("%*s", indent, "");
    switch (source) {
      case  ALG_RSA_VALUE:
	printf("%s TPM_ALG_RSA\n", string);
	break;
      case  ALG_TDES_VALUE:
	printf("%s TPM_ALG_TDES\n", string);
	break;
      case  ALG_SHA1_VALUE:
	printf("%s TPM_ALG_SHA1\n", string);
	break;
      case  ALG_HMAC_VALUE:
	printf("%s TPM_ALG_HMAC\n", string);
	break;
      case  ALG_AES_VALUE:
	printf("%s TPM_ALG_AES\n", string);
	break;
      case  ALG_MGF1_VALUE:
	printf("%s TPM_ALG_MGF1\n", string);
	break;
      case  ALG_KEYEDHASH_VALUE:
	printf("%s TPM_ALG_KEYEDHASH\n", string);
	break;
      case  ALG_XOR_VALUE:
	printf("%s TPM_ALG_XOR\n", string);
	break;
      case  ALG_SHA256_VALUE:
	printf("%s TPM_ALG_SHA256\n", string);
	break;
      case  ALG_SHA384_VALUE:
	printf("%s TPM_ALG_SHA384\n", string);
	break;
      case  ALG_SHA512_VALUE:
	printf("%s TPM_ALG_SHA512\n", string);
	break;
      case  ALG_NULL_VALUE:
	printf("%s TPM_ALG_NULL\n", string);
	break;
      case  ALG_SM3_256_VALUE:
	printf("%s TPM_ALG_SM3_256\n", string);
	break;
      case  ALG_SM4_VALUE:
	printf("%s TPM_ALG_SM4\n", string);
	break;
      case  ALG_RSASSA_VALUE:
	printf("%s TPM_ALG_RSASSA\n", string);
	break;
      case  ALG_RSAES_VALUE:
	printf("%s TPM_ALG_RSAES\n", string);
	break;
      case  ALG_RSAPSS_VALUE:
	printf("%s TPM_ALG_RSAPSS\n", string);
	break;
      case  ALG_OAEP_VALUE:
	printf("%s TPM_ALG_OAEP\n", string);
	break;
      case  ALG_ECDSA_VALUE:
	printf("%s TPM_ALG_ECDSA\n", string);
	break;
      case  ALG_ECDH_VALUE:
	printf("%s TPM_ALG_ECDH\n", string);
	break;
      case  ALG_ECDAA_VALUE:
	printf("%s TPM_ALG_ECDAA\n", string);
	break;
      case  ALG_SM2_VALUE:
	printf("%s TPM_ALG_SM2\n", string);
	break;
      case  ALG_ECSCHNORR_VALUE:
	printf("%s TPM_ALG_ECSCHNORR\n", string);
	break;
      case  ALG_ECMQV_VALUE:
	printf("%s TPM_ALG_ECMQV\n", string);
	break;
      case  ALG_KDF1_SP800_56A_VALUE:
	printf("%s TPM_ALG_KDF1_SP800_56A\n", string);
	break;
      case  ALG_KDF2_VALUE:
	printf("%s TPM_ALG_KDF2\n", string);
	break;
      case  ALG_KDF1_SP800_108_VALUE:
	printf("%s TPM_ALG_KDF1_SP800_108\n", string);
	break;
      case  ALG_ECC_VALUE:
	printf("%s TPM_ALG_ECC\n", string);
	break;
      case  ALG_SYMCIPHER_VALUE:
	printf("%s TPM_ALG_SYMCIPHER\n", string);
	break;
      case  ALG_CAMELLIA_VALUE:
	printf("%s TPM_ALG_CAMELLIA\n", string);
	break;
      case ALG_SHA3_256_VALUE:
	printf("%s TPM_ALG_SHA3_256\n", string);
	break;
      case ALG_SHA3_384_VALUE:
	printf("%s TPM_ALG_SHA3_384\n", string);
	break;
      case ALG_SHA3_512_VALUE:
	printf("%s TPM_ALG_SHA3_512\n", string);
	break;
      case ALG_CMAC_VALUE:
	printf("%s TPM_ALG_CMAC\n", string);
	break;
      case  ALG_CTR_VALUE:
	printf("%s TPM_ALG_CTR\n", string);
	break;
      case  ALG_OFB_VALUE:
	printf("%s TPM_ALG_OFB\n", string);
	break;
      case  ALG_CBC_VALUE:
	printf("%s TPM_ALG_CBC\n", string);
	break;
      case  ALG_CFB_VALUE:
	printf("%s TPM_ALG_CFB\n", string);
	break;
      case  ALG_ECB_VALUE:
	printf("%s TPM_ALG_ECB\n", string);
	break;
      default:
	printf("%s TPM_ALG_ID value %04hx unknown\n", string, source);
    }
    return;
}

/* Table 10 - Definition of (UINT16) {ECC} TPM_ECC_CURVE Constants <IN/OUT, S> */

void TSS_TPM_ECC_CURVE_Print(const char *string, TPM_ECC_CURVE source, unsigned int indent)
{
    printf("%*s", indent, "");
    switch (source) {
      case TPM_ECC_NONE:
	printf("%s TPM_ECC_NONE\n", string);
	break;
      case TPM_ECC_NIST_P192:
	printf("%s TPM_ECC_NIST_P192\n", string);
	break;
      case TPM_ECC_NIST_P224:
	printf("%s TPM_ECC_NIST_P224\n", string);
	break;
      case TPM_ECC_NIST_P256:
	printf("%s TPM_ECC_NIST_P256\n", string);
	break;
      case TPM_ECC_NIST_P384:
	printf("%s TPM_ECC_NIST_P384\n", string);
	break;
      case TPM_ECC_NIST_P521:
	printf("%s TPM_ECC_NIST_P521\n", string);
	break;
      case TPM_ECC_BN_P256:
	printf("%s TPM_ECC_BN_P256\n", string);
	break;
      case TPM_ECC_BN_P638:
	printf("%s TPM_ECC_BN_P638\n", string);
	break;
      case TPM_ECC_SM2_P256:
	printf("%s TPM_ECC_SM2_P256\n", string);
	break;
      default:
	printf("%s TPM_ECC_CURVE value %04hx unknown\n", string, source);
    }
    return;
}

/* Table 100 - Definition of TPMS_TAGGED_POLICY Structure <OUT> */

void TSS_TPMS_TAGGED_POLICY_Print(TPMS_TAGGED_POLICY *source, unsigned int indent)
{
    TSS_TPM_HANDLE_Print("handle", source->handle, indent);
    TSS_TPMT_HA_Print(&source->policyHash, indent);
    return;
}

/* Table 12 - Definition of (UINT32) TPM_CC Constants (Numeric Order) <IN/OUT, S> */

void TSS_TPM_CC_Print(const char *string, TPM_CC source, unsigned int indent)
{
    printf("%*s", indent, "");
    switch (source) {
      case TPM_CC_NV_UndefineSpaceSpecial:
	printf("%s TPM_CC_NV_UndefineSpaceSpecial\n", string);
	break;
      case TPM_CC_EvictControl:
	printf("%s TPM_CC_EvictControl\n", string);
	break;
      case TPM_CC_HierarchyControl:
	printf("%s TPM_CC_HierarchyControl\n", string);
	break;
      case TPM_CC_NV_UndefineSpace:
	printf("%s TPM_CC_NV_UndefineSpace\n", string);
	break;
      case TPM_CC_ChangeEPS:
	printf("%s TPM_CC_ChangeEPS\n", string);
	break;
      case TPM_CC_ChangePPS:
	printf("%s TPM_CC_ChangePPS\n", string);
	break;
      case TPM_CC_Clear:
	printf("%s TPM_CC_Clear\n", string);
	break;
      case TPM_CC_ClearControl:
	printf("%s TPM_CC_ClearControl\n", string);
	break;
      case TPM_CC_ClockSet:
	printf("%s TPM_CC_ClockSet\n", string);
	break;
      case TPM_CC_HierarchyChangeAuth:
	printf("%s TPM_CC_HierarchyChangeAuth\n", string);
	break;
      case TPM_CC_NV_DefineSpace:
	printf("%s TPM_CC_NV_DefineSpace\n", string);
	break;
      case TPM_CC_PCR_Allocate:
	printf("%s TPM_CC_PCR_Allocate\n", string);
	break;
      case TPM_CC_PCR_SetAuthPolicy:
	printf("%s TPM_CC_PCR_SetAuthPolicy\n", string);
	break;
      case TPM_CC_PP_Commands:
	printf("%s TPM_CC_PP_Commands\n", string);
	break;
      case TPM_CC_SetPrimaryPolicy:
	printf("%s TPM_CC_SetPrimaryPolicy\n", string);
	break;
#if 0
      case TPM_CC_FieldUpgradeStart:
	printf("%s TPM_CC_FieldUpgradeStart\n", string);
	break;
#endif
      case TPM_CC_ClockRateAdjust:
	printf("%s TPM_CC_ClockRateAdjust\n", string);
	break;
      case TPM_CC_CreatePrimary:
	printf("%s TPM_CC_CreatePrimary\n", string);
	break;
      case TPM_CC_NV_GlobalWriteLock:
	printf("%s TPM_CC_NV_GlobalWriteLock\n", string);
	break;
      case TPM_CC_GetCommandAuditDigest:
	printf("%s TPM_CC_GetCommandAuditDigest\n", string);
	break;
      case TPM_CC_NV_Increment:
	printf("%s TPM_CC_NV_Increment\n", string);
	break;
      case TPM_CC_NV_SetBits:
	printf("%s TPM_CC_NV_SetBits\n", string);
	break;
      case TPM_CC_NV_Extend:
	printf("%s TPM_CC_NV_Extend\n", string);
	break;
      case TPM_CC_NV_Write:
	printf("%s TPM_CC_NV_Write\n", string);
	break;
      case TPM_CC_NV_WriteLock:
	printf("%s TPM_CC_NV_WriteLock\n", string);
	break;
      case TPM_CC_DictionaryAttackLockReset:
	printf("%s TPM_CC_DictionaryAttackLockReset\n", string);
	break;
      case TPM_CC_DictionaryAttackParameters:
	printf("%s TPM_CC_DictionaryAttackParameters\n", string);
	break;
      case TPM_CC_NV_ChangeAuth:
	printf("%s TPM_CC_NV_ChangeAuth\n", string);
	break;
      case TPM_CC_PCR_Event:
	printf("%s TPM_CC_PCR_Event\n", string);
	break;
      case TPM_CC_PCR_Reset:
	printf("%s TPM_CC_PCR_Reset\n", string);
	break;
      case TPM_CC_SequenceComplete:
	printf("%s TPM_CC_SequenceComplete\n", string);
	break;
      case TPM_CC_SetAlgorithmSet:
	printf("%s TPM_CC_SetAlgorithmSet\n", string);
	break;
      case TPM_CC_SetCommandCodeAuditStatus:
	printf("%s TPM_CC_SetCommandCodeAuditStatus\n", string);
	break;
#if 0
      case TPM_CC_FieldUpgradeData:
	printf("%s TPM_CC_FieldUpgradeData\n", string);
	break;
#endif
      case TPM_CC_IncrementalSelfTest:
	printf("%s TPM_CC_IncrementalSelfTest\n", string);
	break;
      case TPM_CC_SelfTest:
	printf("%s TPM_CC_SelfTest\n", string);
	break;
      case TPM_CC_Startup:
	printf("%s TPM_CC_Startup\n", string);
	break;
      case TPM_CC_Shutdown:
	printf("%s TPM_CC_Shutdown\n", string);
	break;
      case TPM_CC_StirRandom:
	printf("%s TPM_CC_StirRandom\n", string);
	break;
      case TPM_CC_ActivateCredential:
	printf("%s TPM_CC_ActivateCredential\n", string);
	break;
      case TPM_CC_Certify:
	printf("%s TPM_CC_Certify\n", string);
	break;
      case TPM_CC_PolicyNV:
	printf("%s TPM_CC_PolicyNV\n", string);
	break;
      case TPM_CC_CertifyCreation:
	printf("%s TPM_CC_CertifyCreation\n", string);
	break;
      case TPM_CC_Duplicate:
	printf("%s TPM_CC_Duplicate\n", string);
	break;
      case TPM_CC_GetTime:
	printf("%s TPM_CC_GetTime\n", string);
	break;
      case TPM_CC_GetSessionAuditDigest:
	printf("%s TPM_CC_GetSessionAuditDigest\n", string);
	break;
      case TPM_CC_NV_Read:
	printf("%s TPM_CC_NV_Read\n", string);
	break;
      case TPM_CC_NV_ReadLock:
	printf("%s TPM_CC_NV_ReadLock\n", string);
	break;
      case TPM_CC_ObjectChangeAuth:
	printf("%s TPM_CC_ObjectChangeAuth\n", string);
	break;
      case TPM_CC_PolicySecret:
	printf("%s TPM_CC_PolicySecret\n", string);
	break;
      case TPM_CC_Rewrap:
	printf("%s TPM_CC_Rewrap\n", string);
	break;
      case TPM_CC_Create:
	printf("%s TPM_CC_Create\n", string);
	break;
      case TPM_CC_ECDH_ZGen:
	printf("%s TPM_CC_ECDH_ZGen\n", string);
	break;
      case TPM_CC_HMAC:
	printf("%s TPM_CC_HMAC\n", string);
	break;
#if 0
      case TPM_CC_MAC:
	printf("%s TPM_CC_MAC\n", string);
	break;
#endif
      case TPM_CC_Import:
	printf("%s TPM_CC_Import\n", string);
	break;
      case TPM_CC_Load:
	printf("%s TPM_CC_Load\n", string);
	break;
      case TPM_CC_Quote:
	printf("%s TPM_CC_Quote\n", string);
	break;
      case TPM_CC_RSA_Decrypt:
	printf("%s TPM_CC_RSA_Decrypt\n", string);
	break;
      case TPM_CC_HMAC_Start:
	printf("%s TPM_CC_HMAC_Start\n", string);
	break;
#if 0
      case TPM_CC_MAC_Start:
	printf("%s TPM_CC_MAC_Start\n", string);
	break;
#endif
      case TPM_CC_SequenceUpdate:
	printf("%s TPM_CC_SequenceUpdate\n", string);
	break;
      case TPM_CC_Sign:
	printf("%s TPM_CC_Sign\n", string);
	break;
      case TPM_CC_Unseal:
	printf("%s TPM_CC_Unseal\n", string);
	break;
      case TPM_CC_PolicySigned:
	printf("%s TPM_CC_PolicySigned\n", string);
	break;
      case TPM_CC_ContextLoad:
	printf("%s TPM_CC_ContextLoad\n", string);
	break;
      case TPM_CC_ContextSave:
	printf("%s TPM_CC_ContextSave\n", string);
	break;
      case TPM_CC_ECDH_KeyGen:
	printf("%s TPM_CC_ECDH_KeyGen\n", string);
	break;
      case TPM_CC_EncryptDecrypt:
	printf("%s TPM_CC_EncryptDecrypt\n", string);
	break;
      case TPM_CC_FlushContext:
	printf("%s TPM_CC_FlushContext\n", string);
	break;
      case TPM_CC_LoadExternal:
	printf("%s TPM_CC_LoadExternal\n", string);
	break;
      case TPM_CC_MakeCredential:
	printf("%s TPM_CC_MakeCredential\n", string);
	break;
      case TPM_CC_NV_ReadPublic:
	printf("%s TPM_CC_NV_ReadPublic\n", string);
	break;
      case TPM_CC_PolicyAuthorize:
	printf("%s TPM_CC_PolicyAuthorize\n", string);
	break;
      case TPM_CC_PolicyAuthValue:
	printf("%s TPM_CC_PolicyAuthValue\n", string);
	break;
      case TPM_CC_PolicyCommandCode:
	printf("%s TPM_CC_PolicyCommandCode\n", string);
	break;
      case TPM_CC_PolicyCounterTimer:
	printf("%s TPM_CC_PolicyCounterTimer\n", string);
	break;
      case TPM_CC_PolicyCpHash:
	printf("%s TPM_CC_PolicyCpHash\n", string);
	break;
      case TPM_CC_PolicyLocality:
	printf("%s TPM_CC_PolicyLocality\n", string);
	break;
      case TPM_CC_PolicyNameHash:
	printf("%s TPM_CC_PolicyNameHash\n", string);
	break;
      case TPM_CC_PolicyOR:
	printf("%s TPM_CC_PolicyOR\n", string);
	break;
      case TPM_CC_PolicyTicket:
	printf("%s TPM_CC_PolicyTicket\n", string);
	break;
      case TPM_CC_ReadPublic:
	printf("%s TPM_CC_ReadPublic\n", string);
	break;
      case TPM_CC_RSA_Encrypt:
	printf("%s TPM_CC_RSA_Encrypt\n", string);
	break;
      case TPM_CC_StartAuthSession:
	printf("%s TPM_CC_StartAuthSession\n", string);
	break;
      case TPM_CC_VerifySignature:
	printf("%s TPM_CC_VerifySignature\n", string);
	break;
      case TPM_CC_ECC_Parameters:
	printf("%s TPM_CC_ECC_Parameters\n", string);
	break;
#if 0
      case TPM_CC_FirmwareRead:
	printf("%s TPM_CC_FirmwareRead\n", string);
	break;
#endif
      case TPM_CC_GetCapability:
	printf("%s TPM_CC_GetCapability\n", string);
	break;
      case TPM_CC_GetRandom:
	printf("%s TPM_CC_GetRandom\n", string);
	break;
      case TPM_CC_GetTestResult:
	printf("%s TPM_CC_GetTestResult\n", string);
	break;
      case TPM_CC_Hash:
	printf("%s TPM_CC_Hash\n", string);
	break;
      case TPM_CC_PCR_Read:
	printf("%s TPM_CC_PCR_Read\n", string);
	break;
      case TPM_CC_PolicyPCR:
	printf("%s TPM_CC_PolicyPCR\n", string);
	break;
      case TPM_CC_PolicyRestart:
	printf("%s TPM_CC_PolicyRestart\n", string);
	break;
      case TPM_CC_ReadClock:
	printf("%s TPM_CC_ReadClock\n", string);
	break;
      case TPM_CC_PCR_Extend:
	printf("%s TPM_CC_PCR_Extend\n", string);
	break;
      case TPM_CC_PCR_SetAuthValue:
	printf("%s TPM_CC_PCR_SetAuthValue\n", string);
	break;
      case TPM_CC_NV_Certify:
	printf("%s TPM_CC_NV_Certify\n", string);
	break;
      case TPM_CC_EventSequenceComplete:
	printf("%s TPM_CC_EventSequenceComplete\n", string);
	break;
      case TPM_CC_HashSequenceStart:
	printf("%s TPM_CC_HashSequenceStart\n", string);
	break;
      case TPM_CC_PolicyPhysicalPresence:
	printf("%s TPM_CC_PolicyPhysicalPresence\n", string);
	break;
      case TPM_CC_PolicyDuplicationSelect:
	printf("%s TPM_CC_PolicyDuplicationSelect\n", string);
	break;
      case TPM_CC_PolicyGetDigest:
	printf("%s TPM_CC_PolicyGetDigest\n", string);
	break;
      case TPM_CC_TestParms:
	printf("%s TPM_CC_TestParms\n", string);
	break;
      case TPM_CC_Commit:
	printf("%s TPM_CC_Commit\n", string);
	break;
      case TPM_CC_PolicyPassword:
	printf("%s TPM_CC_PolicyPassword\n", string);
	break;
      case TPM_CC_ZGen_2Phase:
	printf("%s TPM_CC_ZGen_2Phase\n", string);
	break;
      case TPM_CC_EC_Ephemeral:
	printf("%s TPM_CC_EC_Ephemeral\n", string);
	break;
      case TPM_CC_PolicyNvWritten:
	printf("%s TPM_CC_PolicyNvWritten\n", string);
	break;
      case TPM_CC_PolicyTemplate:
	printf("%s TPM_CC_PolicyTemplate\n", string);
	break;
      case TPM_CC_CreateLoaded:
	printf("%s TPM_CC_CreateLoaded\n", string);
	break;
      case TPM_CC_PolicyAuthorizeNV:
	printf("%s TPM_CC_PolicyAuthorizeNV\n", string);
	break;
      case TPM_CC_EncryptDecrypt2:
	printf("%s TPM_CC_EncryptDecrypt2\n", string);
	break;
#if 0
      case TPM_CC_AC_GetCapability:
	printf("%s TPM_CC_AC_GetCapability\n", string);
	break;
      case TPM_CC_AC_Send:
	printf("%s TPM_CC_AC_Send\n", string);
	break;
      case TPM_CC_Policy_AC_SendSelect:
	printf("%s TPM_CC_Policy_AC_SendSelect\n", string);
	break;
#endif
      default:
	printf("%s TPM_CC value %08x unknown\n", string, source);
    }
    return;
}

/* Table 17 - Definition of (INT8) TPM_CLOCK_ADJUST Constants <IN> */

void TSS_TPM_CLOCK_ADJUST_Print(const char *string, TPM_CLOCK_ADJUST source, unsigned int indent)
{
    printf("%*s", indent, "");
    switch (source) {
      case TPM_CLOCK_COARSE_SLOWER:
	printf("%s TPM_CLOCK_COARSE_SLOWER\n", string);
	break;
      case TPM_CLOCK_MEDIUM_SLOWER:
	printf("%s TPM_CLOCK_MEDIUM_SLOWER\n", string);
	break;
      case TPM_CLOCK_FINE_SLOWER:
	printf("%s TPM_CLOCK_FINE_SLOWER\n", string);
	break;
      case TPM_CLOCK_NO_CHANGE:
	printf("%s TPM_CLOCK_NO_CHANGE\n", string);
	break;
      case TPM_CLOCK_FINE_FASTER:
	printf("%s TPM_CLOCK_FINE_FASTER\n", string);
	break;
      case TPM_CLOCK_MEDIUM_FASTER:
	printf("%s TPM_CLOCK_MEDIUM_FASTER\n", string);
	break;
      case TPM_CLOCK_COARSE_FASTER:
	printf("%s TPM_CLOCK_COARSE_FASTER\n", string);
	break;
      default:
	printf("%s TPM_CLOCK_ADJUST value %d unknown\n", string, source);
    }
    return;
}

/* Table 18 - Definition of (UINT16) TPM_EO Constants <IN/OUT> */

void TSS_TPM_EO_Print(const char *string, TPM_EO source, unsigned int indent) 
{
    printf("%*s", indent, "");
    switch (source) {
      case TPM_EO_EQ:
	printf("%s TPM_EO_EQ\n", string);
	break;
      case TPM_EO_NEQ:
	printf("%s TPM_EO_NEQ\n", string);
	break;
      case TPM_EO_SIGNED_GT:
	printf("%s TPM_EO_SIGNED_GT\n", string);
	break;
      case TPM_EO_UNSIGNED_GT:
	printf("%s TPM_EO_UNSIGNED_GT\n", string);
	break;
      case TPM_EO_SIGNED_LT:
	printf("%s TPM_EO_SIGNED_LT\n", string);
	break;
      case TPM_EO_UNSIGNED_LT:
	printf("%s TPM_EO_UNSIGNED_LT\n", string);
	break;
      case TPM_EO_SIGNED_GE:
	printf("%s TPM_EO_SIGNED_GE\n", string);
	break;
      case TPM_EO_UNSIGNED_GE:
	printf("%s TPM_EO_UNSIGNED_GE\n", string);
	break;
      case TPM_EO_SIGNED_LE:
	printf("%s TPM_EO_SIGNED_LE\n", string);
	break;
      case TPM_EO_UNSIGNED_LE:
	printf("%s TPM_EO_UNSIGNED_LE\n", string);
	break;
      case TPM_EO_BITSET:
	printf("%s TPM_EO_BITSET\n", string);
	break;
      case TPM_EO_BITCLEAR:
	printf("%s TPM_EO_BITCLEAR\n", string);
	break;
      default:
	printf("%s TPM_EO value %04hx unknown\n", string, source);
    }
    return;
}

/* Table 19 - Definition of (UINT16) TPM_ST Constants <IN/OUT, S> */

void TSS_TPM_ST_Print(const char *string, TPM_ST source, unsigned int indent) 
{
    printf("%*s", indent, "");
    switch (source) {
      case TPM_ST_RSP_COMMAND:
	printf("%s TPM_ST_RSP_COMMAND\n", string);
	break;
      case TPM_ST_NULL:
	printf("%s TPM_ST_NULL\n", string);
	break;
      case TPM_ST_NO_SESSIONS:
	printf("%s TPM_ST_NO_SESSIONS\n", string);
	break;
      case TPM_ST_SESSIONS:
	printf("%s TPM_ST_SESSIONS\n", string);
	break;
      case TPM_ST_ATTEST_NV:
	printf("%s TPM_ST_ATTEST_NV\n", string);
	break;
      case TPM_ST_ATTEST_COMMAND_AUDIT:
	printf("%s TPM_ST_ATTEST_COMMAND_AUDIT\n", string);
	break;
      case TPM_ST_ATTEST_SESSION_AUDIT:
	printf("%s TPM_ST_ATTEST_SESSION_AUDIT\n", string);
	break;
      case TPM_ST_ATTEST_CERTIFY:
	printf("%s TPM_ST_ATTEST_CERTIFY\n", string);
	break;
      case TPM_ST_ATTEST_QUOTE:
	printf("%s TPM_ST_ATTEST_QUOTE\n", string);
	break;
      case TPM_ST_ATTEST_TIME:
	printf("%s TPM_ST_ATTEST_TIME\n", string);
	break;
      case TPM_ST_ATTEST_CREATION:
	printf("%s TPM_ST_ATTEST_CREATION\n", string);
	break;
      case TPM_ST_ATTEST_NV_DIGEST:
	printf("%s TPM_ST_ATTEST_NV_DIGEST\n", string);
	break;
      case TPM_ST_CREATION:
	printf("%s TPM_ST_CREATION\n", string);
	break;
      case TPM_ST_VERIFIED:
	printf("%s TPM_ST_VERIFIED\n", string);
	break;
      case TPM_ST_AUTH_SECRET:
	printf("%s TPM_ST_AUTH_SECRET\n", string);
	break;
      case TPM_ST_HASHCHECK:
	printf("%s TPM_ST_HASHCHECK\n", string);
	break;
      case TPM_ST_AUTH_SIGNED:
	printf("%s TPM_ST_AUTH_SIGNED\n", string);
	break;
      default:
	printf("%s TPM_ST value %04hx unknown\n", string, source);
    }
    return;
}

/* Table 20 - Definition of (UINT16) TPM_SU Constants <IN> */

void TSS_TPM_SU_Print(const char *string, TPM_SU source, unsigned int indent) 
{
    printf("%*s", indent, "");
    switch (source) {
      case TPM_SU_CLEAR:
	printf("%s TPM_SU_CLEAR\n", string);
	break;
      case TPM_SU_STATE:
	printf("%s TPM_SU_STATE\n", string);
	break;
      default:
	printf("%s TPM_SU value %04hx unknown\n", string, source);
    }
    return;
}

/* Table 21 - Definition of (UINT8) TPM_SE Constants <IN> */

void TSS_TPM_SE_Print(const char *string, TPM_SE source, unsigned int indent)
{
    printf("%*s", indent, "");
    switch (source) {
      case TPM_SE_HMAC:
	printf("%s TPM_SE_HMAC\n", string);
	break;
      case TPM_SE_POLICY:
	printf("%s TPM_SE_POLICY\n", string); 
	break;
      case TPM_SE_TRIAL:
	printf("%s TPM_SE_TRIAL\n", string); 
	break;
      default:
	printf("%s TPM_SE value %02x unknown\n", string, source);
    }
    return;
}

/* Table 22 - Definition of (UINT32) TPM_CAP Constants */

void TSS_TPM_CAP_Print(const char *string, TPM_CAP source, unsigned int indent)
{
    printf("%*s", indent, "");
    switch (source) {
     case TPM_CAP_ALGS:
       printf("%s TPM_CAP_ALGS\n", string);
	break;
      case TPM_CAP_HANDLES:
	printf("%s TPM_CAP_HANDLES\n", string);
	break;
      case TPM_CAP_COMMANDS:
	printf("%s TPM_CAP_COMMANDS\n", string);
	break;
      case TPM_CAP_PP_COMMANDS:
	printf("%s TPM_CAP_PP_COMMANDS\n", string);
	break;
      case TPM_CAP_AUDIT_COMMANDS:
	printf("%s TPM_CAP_AUDIT_COMMANDS\n", string);
	break;
      case TPM_CAP_PCRS:
	printf("%s TPM_CAP_PCRS\n", string);
	break;
      case TPM_CAP_TPM_PROPERTIES:
	printf("%s TPM_CAP_TPM_PROPERTIES\n", string);
	break;
      case TPM_CAP_PCR_PROPERTIES:
	printf("%s TPM_CAP_PCR_PROPERTIES\n", string);
	break;
      case TPM_CAP_ECC_CURVES:
	printf("%s TPM_CAP_ECC_CURVES\n", string);
	break;
      case TPM_CAP_AUTH_POLICIES:
	printf("%s TPM_CAP_AUTH_POLICIES\n", string);
	break;
      case TPM_CAP_VENDOR_PROPERTY:
	printf("%s TPM_CAP_VENDOR_PROPERTY\n", string);
	break;
      default:
	printf("%s TPM_CAP value %08x unknown\n", string, source);
    }
    return;
}

/* Table 26 - Definition of Types for Handles */

void TSS_TPM_HANDLE_Print(const char *string, TPM_HANDLE source, unsigned int indent)
{
    printf("%*s", indent, "");
    switch (source) {
      case TPM_RH_SRK:
	printf("%s TPM_RH_SRK\n", string);
	break;
      case TPM_RH_OWNER:
	printf("%s TPM_RH_OWNER\n", string);
	break;
      case TPM_RH_REVOKE:
	printf("%s TPM_RH_REVOKE\n", string);
	break;
      case TPM_RH_TRANSPORT:
	printf("%s TPM_RH_TRANSPORT\n", string);
	break;
      case TPM_RH_OPERATOR:
	printf("%s TPM_RH_OPERATOR\n", string);
	break;
      case TPM_RH_ADMIN:
	printf("%s TPM_RH_ADMIN\n", string);
	break;
      case TPM_RH_EK:
	printf("%s TPM_RH_EK\n", string);
	break;
      case TPM_RH_NULL:
	printf("%s TPM_RH_NULL\n", string);
	break;
      case TPM_RH_UNASSIGNED:
	printf("%s TPM_RH_UNASSIGNED\n", string);
	break;
      case TPM_RS_PW:
	printf("%s TPM_RS_PW\n", string);
	break;
      case TPM_RH_LOCKOUT:
	printf("%s TPM_RH_LOCKOUT\n", string);
	break;
      case TPM_RH_ENDORSEMENT:
	printf("%s TPM_RH_ENDORSEMENT\n", string);
	break;
      case TPM_RH_PLATFORM:
	printf("%s TPM_RH_PLATFORM\n", string);
	break;
      case TPM_RH_PLATFORM_NV:
	printf("%s TPM_RH_PLATFORM_NV\n", string);
	break;
      default:
	printf("%s TPM_HANDLE %08x\n", string, source);
    }
    return;
}

/* Table 30 - Definition of (UINT32) TPMA_ALGORITHM Bits */

void TSS_TPM_TPMA_ALGORITHM_Print(TPMA_ALGORITHM source, unsigned int indent)
{
    if (source.val & TPMA_ALGORITHM_ASYMMETRIC) printf("%*s" "TPMA_ALGORITHM: asymmetric\n", indent, "");
    if (source.val & TPMA_ALGORITHM_SYMMETRIC) printf("%*s" "TPMA_ALGORITHM: symmetric\n", indent, "");
    if (source.val & TPMA_ALGORITHM_HASH) printf("%*s" "TPMA_ALGORITHM: hash\n", indent, "");
    if (source.val & TPMA_ALGORITHM_OBJECT) printf("%*s" "TPMA_ALGORITHM: object\n", indent, "");
    if (source.val & TPMA_ALGORITHM_SIGNING) printf("%*s" "TPMA_ALGORITHM: signing\n", indent, "");
    if (source.val & TPMA_ALGORITHM_ENCRYPTING) printf("%*s" "TPMA_ALGORITHM: encrypting\n", indent, "");
    if (source.val & TPMA_ALGORITHM_METHOD) printf("%*s" "TPMA_ALGORITHM: method\n", indent, "");
    return;
}

/* Table 31 - Definition of (UINT32) TPMA_OBJECT Bits */

void TSS_TPMA_OBJECT_Print(const char *string, TPMA_OBJECT source, unsigned int indent)
{
    printf("%*s%s: %08x\n", indent, "", string, source.val);
    if (source.val & TPMA_OBJECT_FIXEDTPM) printf("%*s%s: fixedTpm\n", indent, "", string);
    if (source.val & TPMA_OBJECT_STCLEAR) printf("%*s%s: stClear\n", indent, "", string);
    if (source.val & TPMA_OBJECT_FIXEDPARENT) printf("%*s%s: fixedParent\n", indent, "", string);
    if (source.val & TPMA_OBJECT_SENSITIVEDATAORIGIN) printf("%*s%s: sensitiveDataOrigin\n", indent, "", string);
    if (source.val & TPMA_OBJECT_USERWITHAUTH) printf("%*s%s: userWithAuth\n", indent, "", string);
    if (source.val & TPMA_OBJECT_ADMINWITHPOLICY) printf("%*s%s: adminWithPolicy\n", indent, "", string);
    if (source.val & TPMA_OBJECT_NODA) printf("%*s%s: noDA\n", indent, "", string);
    if (source.val & TPMA_OBJECT_ENCRYPTEDDUPLICATION) printf("%*s%s: encryptedDuplication\n", indent, "", string);
    if (source.val & TPMA_OBJECT_RESTRICTED) printf("%*s%s: restricted\n", indent, "", string);
    if (source.val & TPMA_OBJECT_DECRYPT) printf("%*s%s: decrypt\n", indent, "", string);
    if (source.val & TPMA_OBJECT_SIGN) printf("%*s%s: sign\n", indent, "", string);
    return;
}

/* Table 32 - Definition of (UINT8) TPMA_SESSION Bits <IN/OUT> */

void TSS_TPMA_SESSION_Print(TPMA_SESSION source, unsigned int indent)
{
    
    if (source.val & TPMA_SESSION_CONTINUESESSION) printf("%*s" "TPMA_SESSION: continue\n", indent, "");
    if (source.val & TPMA_SESSION_AUDITEXCLUSIVE) printf("%*s" "TPMA_SESSION: auditexclusive\n", indent, ""); 
    if (source.val & TPMA_SESSION_AUDITRESET) printf("%*s" "TPMA_SESSION: auditreset\n", indent, ""); 
    if (source.val & TPMA_SESSION_DECRYPT) printf("%*s" "TPMA_SESSION: decrypt\n", indent, ""); 
    if (source.val & TPMA_SESSION_ENCRYPT) printf("%*s" "TPMA_SESSION: encrypt\n", indent, ""); 
    if (source.val & TPMA_SESSION_AUDIT) printf("%*s" "TPMA_SESSION: audit\n", indent, ""); 
    return;
}

/* Table 33 - Definition of (UINT8) TPMA_LOCALITY Bits <IN/OUT> */

void TSS_TPMA_LOCALITY_Print(TPMA_LOCALITY source, unsigned int indent)
{
    if (source.val & TPMA_LOCALITY_ZERO) printf("%*s" "TPMA_LOCALITY: zero\n", indent, "");
    if (source.val & TPMA_LOCALITY_ONE) printf("%*s" "TPMA_LOCALITY: one\n", indent, "");
    if (source.val & TPMA_LOCALITY_TWO) printf("%*s" "TPMA_LOCALITY: two\n", indent, "");
    if (source.val & TPMA_LOCALITY_THREE) printf("%*s" "TPMA_LOCALITY: three\n", indent, "");
    if (source.val & TPMA_LOCALITY_FOUR) printf("%*s" "TPMA_LOCALITY: four\n", indent, "");
    if (source.val & TPMA_LOCALITY_EXTENDED) printf("%*s" "TPMA_LOCALITY: extended\n", indent, "");
    return;
}

/* Table 34 - Definition of (UINT32) TPMA_PERMANENT Bits <OUT> */

void TSS_TPMA_PERMANENT_Print(TPMA_PERMANENT source, unsigned int indent)
{
    printf("%*s" "TPMA_PERMANENT: ownerAuthSet %s\n", indent, "",
	   (source.val & TPMA_PERMANENT_OWNERAUTHSET) ? "yes" : "no"); 
    printf("%*s" "TPMA_PERMANENT: endorsementAuthSet %s\n", indent, "",
	   (source.val & TPMA_PERMANENT_ENDORSEMENTAUTHSET)  ? "yes" : "no"); 
    printf("%*s" "TPMA_PERMANENT: lockoutAuthSet %s\n", indent, "",
	   (source.val & TPMA_PERMANENT_LOCKOUTAUTHSET)  ? "yes" : "no"); 
    printf("%*s" "TPMA_PERMANENT: disableClear %s\n", indent, "",
	   (source.val & TPMA_PERMANENT_DISABLECLEAR) ? "yes" : "no"); 
    printf("%*s" "TPMA_PERMANENT: inLockout %s\n", indent, "",
	   (source.val & TPMA_PERMANENT_INLOCKOUT) ? "yes" : "no"); 
    printf("%*s" "TPMA_PERMANENT: tpmGeneratedEPS %s\n", indent, "",
	   (source.val & TPMA_PERMANENT_TPMGENERATEDEPS)  ? "yes" : "no"); 
    return;
}

/* Table 35 - Definition of (UINT32) TPMA_STARTUP_CLEAR Bits <OUT> */

void TSS_TPMA_STARTUP_CLEAR_Print(TPMA_STARTUP_CLEAR source, unsigned int indent)
{
    printf("%*s" "TPMA_STARTUP_CLEAR: phEnable %s\n", indent, "",
	   (source.val & TPMA_STARTUP_CLEAR_PHENABLE)  ? "yes" : "no"); 
    printf("%*s" "TPMA_STARTUP_CLEAR: shEnable %s\n", indent, "",
	   (source.val & TPMA_STARTUP_CLEAR_SHENABLE)  ? "yes" : "no"); 
    printf("%*s" "TPMA_STARTUP_CLEAR: ehEnable %s\n", indent, "",
	   (source.val & TPMA_STARTUP_CLEAR_EHENABLE)  ? "yes" : "no"); 
    printf("%*s" "TPMA_STARTUP_CLEAR: phEnableNV %s\n", indent, "",
	   (source.val & TPMA_STARTUP_CLEAR_PHENABLENV)  ? "yes" : "no"); 
    printf("%*s" "TPMA_STARTUP_CLEAR: orderly %s\n", indent, "",
	   (source.val & TPMA_STARTUP_CLEAR_ORDERLY)  ? "yes" : "no"); 
    return;
}

/* Table 36 - Definition of (UINT32) TPMA_MEMORY Bits <Out> */

void TSS_TPMA_MEMORY_Print(TPMA_MEMORY source, unsigned int indent)
{
    printf("%*s" "TPMA_MEMORY: sharedRAM %s\n", indent, "",
	   (source.val & TPMA_MEMORY_SHAREDRAM) ? "yes" : "no");
    printf("%*s" "TPMA_MEMORY: sharedNV %s\n", indent, "",
	   (source.val & TPMA_MEMORY_SHAREDNV) ? "yes" : "no");
    printf("%*s" "TPMA_MEMORY: objectCopiedToRam %s\n", indent, "",
	   (source.val & TPMA_MEMORY_OBJECTCOPIEDTORAM) ? "yes" : "no");
    return;
}

/* Table 38 - Definition of (UINT32) TPMA_MODES Bits <Out> */

void TSS_TPMA_MODES_Print(TPMA_MODES source, unsigned int indent)
{
    printf("%*s" "TPMA_MODES: TPMA_MODES_FIPS_140_2 %s\n", indent, "",
	   (source.val & TPMA_MODES_FIPS_140_2) ? "yes" : "no");
    return;
}

/* Table 39 - Definition of (BYTE) TPMI_YES_NO Type */

void TSS_TPMI_YES_NO_Print(const char *string, TPMI_YES_NO source, unsigned int indent)
{
    printf("%*s", indent, "");
    switch (source) {
      case NO:
	printf("%s no\n", string);
	break;
      case YES:
	printf("%s yes\n", string);
	break;
      default:
	printf("%s TPMI_YES_NO %02x unknown\n", string, source);
    }
    return;
}

/* Table 75 - Definition of TPMU_HA Union <IN/OUT, S> */


void TSS_TPMU_HA_Print(TPMU_HA *source, uint32_t selector, unsigned int indent)
{
    switch (selector) {
#ifdef TPM_ALG_SHA1
      case TPM_ALG_SHA1:
	TSS_PrintAlli("sha1", indent, source->sha1, SHA1_DIGEST_SIZE);
	break;
#endif
#ifdef TPM_ALG_SHA256
      case TPM_ALG_SHA256:
	TSS_PrintAlli("sha256", indent, source->sha256, SHA256_DIGEST_SIZE);
	break;
#endif
#ifdef TPM_ALG_SHA384
      case TPM_ALG_SHA384:
	TSS_PrintAlli("sha384", indent, source->sha384, SHA384_DIGEST_SIZE);
	break;
#endif
#ifdef TPM_ALG_SHA512
      case TPM_ALG_SHA512:
	TSS_PrintAlli("sha512", indent, source->sha512, SHA512_DIGEST_SIZE);
	break;
#endif
#ifdef TPM_ALG_SM3_256
      case TPM_ALG_SM3_256:
	TSS_PrintAlli("sm3_256", indent, source->sm3_256, SM3_256_DIGEST_SIZE);
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	printf("%*s" "TPMU_HA: selection %08x not implemented\n", indent, "", selector);
    }
    return;
}

/* Table 76 - Definition of TPMT_HA Structure <IN/OUT> */

void TSS_TPMT_HA_Print(TPMT_HA *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("hashAlg", source->hashAlg, indent+2);	
    TSS_TPMU_HA_Print(&source->digest, source->hashAlg, indent+2);
    return;
}

/* Table 89 - Definition of TPMS_PCR_SELECT Structure */

void TSS_TPMS_PCR_SELECT_Print(TPMS_PCR_SELECT *source, unsigned int indent)
{
    printf("%*s" "TSS_TPMS_PCR_SELECT sizeofSelect %u\n", indent, "", source->sizeofSelect);
    TSS_PrintAlli("pcrSelect", indent, source->pcrSelect, source->sizeofSelect);
    return;
}

/* Table 90 - Definition of TPMS_PCR_SELECTION Structure */

void TSS_TPMS_PCR_SELECTION_Print(TPMS_PCR_SELECTION *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("hash", source->hash, indent+2);
    TSS_PrintAlli("TPMS_PCR_SELECTION", indent+2,
		  source->pcrSelect,
		  source->sizeofSelect);
    return;
}

/* Table 93 - Definition of TPMT_TK_CREATION Structure */

void TSS_TPMT_TK_CREATION_Print(TPMT_TK_CREATION *source, unsigned int indent)
{
    TSS_TPM_ST_Print("tag", source->tag, indent);
    TSS_TPM_HANDLE_Print("hierarchy", source->hierarchy, indent);	
    TSS_TPM2B_Print("TPMT_TK_CREATION digest", indent, &source->digest.b);
    return;
}

/* Table 94 - Definition of TPMT_TK_VERIFIED Structure */

void TSS_TPMT_TK_VERIFIED_Print(TPMT_TK_VERIFIED *source, unsigned int indent)
{
    TSS_TPM_ST_Print("tag", source->tag, indent);
    TSS_TPM_HANDLE_Print("hierarchy", source->hierarchy, indent);	
    TSS_TPM2B_Print("TPMT_TK_VERIFIED digest", indent, &source->digest.b);
    return;
}
	
/* Table 95 - Definition of TPMT_TK_AUTH Structure */

void TSS_TPMT_TK_AUTH_Print(TPMT_TK_AUTH *source, unsigned int indent)
{
    TSS_TPM_ST_Print("tag", source->tag, indent);
    TSS_TPM_HANDLE_Print("hierarchy", source->hierarchy, indent);	
    TSS_TPM2B_Print("TPMT_TK_AUTH digest", indent, &source->digest.b);
    return;
}

/* Table 96 - Definition of TPMT_TK_HASHCHECK Structure */

void TSS_TPMT_TK_HASHCHECK_Print(TPMT_TK_HASHCHECK *source, unsigned int indent)
{
    TSS_TPM_ST_Print("tag", source->tag, indent);
    TSS_TPM_HANDLE_Print("hierarchy", source->hierarchy, indent);	
    TSS_TPM2B_Print("TPMT_TK_AUTH digest", indent, &source->digest.b);
    return;
}

/* Table 101 - Definition of TPML_CC Structure */

void TSS_TPML_CC_Print(TPML_CC *source, unsigned int indent)
{
    uint32_t i;
    printf("%*s" "TPML_CC count %u\n", indent, "", source->count);
    for (i = 0 ; (i < source->count) ; i++) {
	TSS_TPM_CC_Print("commandCode", source->commandCodes[i], indent);
    }
    return;
}

/* Table 102 - Definition of TPML_PCR_SELECTION Structure */

void TSS_TPML_PCR_SELECTION_Print(TPML_PCR_SELECTION *source, unsigned int indent)
{
    uint32_t i;
    printf("%*s" "TPML_PCR_SELECTION count %u\n", indent, "", source->count);
    for (i = 0 ; (i < source->count) ; i++) {
	TSS_TPMS_PCR_SELECTION_Print(&source->pcrSelections[i], indent);
    }
    return;
}

/* Table 103 - Definition of TPML_ALG Structure */

void TSS_TPML_ALG_Print(TPML_ALG *source, unsigned int indent)
{
    uint32_t i;
    printf("%*s" "TPML_ALG count %u\n", indent, "", source->count);
    for (i = 0 ; (i < source->count) ; i++) {
	TSS_TPM_ALG_ID_Print("algorithms", source->algorithms[i], indent);
    }
    return;
}

/* Table 105 - Definition of TPML_DIGEST Structure */

void TSS_TPML_DIGEST_Print(TPML_DIGEST *source, unsigned int indent)
{
    uint32_t i;
    printf("%*s" "TPML_DIGEST count %u\n", indent, "", source->count);
    for (i = 0 ; (i < source->count) ; i++) {
	TSS_TPM2B_Print("TPML_DIGEST digest", indent, &source->digests[i].b);
    }
    return;
}

/* Table 106 - Definition of TPML_DIGEST_VALUES Structure */

void TSS_TPML_DIGEST_VALUES_Print(TPML_DIGEST_VALUES *source, unsigned int indent)
{
    uint32_t i;
    printf("%*s" "TPML_DIGEST_VALUES count %u\n", indent, "", source->count);
    for (i = 0 ; (i < source->count) ; i++) {
	TSS_TPMT_HA_Print(&source->digests[i], indent);
    }
    return;
}

/* Table 115 - Definition of TPMS_CLOCK_INFO Structure */

void TSS_TPMS_CLOCK_INFO_Print(TPMS_CLOCK_INFO *source, unsigned int indent)
{
    printf("%*s" "TPMS_CLOCK_INFO clock %"PRIu64"\n", indent, "", source->clock);
    printf("%*s" "TPMS_CLOCK_INFO resetCount %u\n", indent, "", source->resetCount);
    printf("%*s" "TPMS_CLOCK_INFO restartCount %u\n", indent, "", source->restartCount);
    printf("%*s" "TPMS_CLOCK_INFO safe %x\n", indent, "", source->safe);
    return;
}

/* Table 116 - Definition of TPMS_TIME_INFO Structure */

void TSS_TPMS_TIME_INFO_Print(TPMS_TIME_INFO *source, unsigned int indent)
{
    uint64_t days;
    uint64_t hours;
    uint64_t minutes;
    uint64_t seconds;
    printf("%*s" "TPMS_TIME_INFO time %"PRIu64" msec", indent, "", source->time);
    days = source->time/(1000 * 60 * 60 * 24);
    hours = (source->time % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60);
    minutes = (source->time % (1000 * 60 * 60)) / (1000 * 60);
    seconds = (source->time % (1000 * 60)) / (1000);
    printf(" - %"PRIu64" days %"PRIu64" hours %"PRIu64" minutes %"PRIu64" seconds\n",
	   days, hours, minutes, seconds);
    TSS_TPMS_CLOCK_INFO_Print(&source->clockInfo, indent+2);
    return;
}
    
/* Table 117 - Definition of TPMS_TIME_ATTEST_INFO Structure <OUT> */

void TSS_TPMS_TIME_ATTEST_INFO_Print(TPMS_TIME_ATTEST_INFO *source, unsigned int indent)
{
    TSS_TPMS_TIME_INFO_Print(&source->time, indent+2);
    printf("%*s" "TPMS_TIME_ATTEST_INFO firmwareVersion %"PRIu64"\n", indent, "", source->firmwareVersion);
    return;
}

/* Table 118 - Definition of TPMS_CERTIFY_INFO Structure <OUT> */

void TSS_TPMS_CERTIFY_INFO_Print(TPMS_CERTIFY_INFO *source, unsigned int indent)
{
    TSS_TPM2B_Print("TPMS_CERTIFY_INFO name", indent, &source->name.b);
    TSS_TPM2B_Print("TPMS_CERTIFY_INFO qualifiedName", indent, &source->qualifiedName.b);
    return;
}

/* Table 119 - Definition of TPMS_QUOTE_INFO Structure <OUT> */

void TSS_TPMS_QUOTE_INFO_Print(TPMS_QUOTE_INFO *source, unsigned int indent)
{
    TSS_TPML_PCR_SELECTION_Print(&source->pcrSelect, indent+2);
    TSS_TPM2B_Print("TPMS_QUOTE_INFO pcrDigest", indent+2, &source->pcrDigest.b);
    return;
}

/* Table 120 - Definition of TPMS_COMMAND_AUDIT_INFO Structure <OUT> */

void TSS_TPMS_COMMAND_AUDIT_INFO_Print(TPMS_COMMAND_AUDIT_INFO *source, unsigned int indent)
{
    printf("%*s" "TPMS_COMMAND_AUDIT_INFO auditCounter %"PRIu64"\n", indent, "", source->auditCounter);
    TSS_TPM_ALG_ID_Print("digestAlg", source->digestAlg, indent);
    TSS_TPM2B_Print("TPMS_COMMAND_AUDIT_INFO auditDigest", indent, &source->auditDigest.b);
    TSS_TPM2B_Print("TPMS_COMMAND_AUDIT_INFO commandDigest", indent, &source->commandDigest.b);
    return;
}
  
/* Table 121 - Definition of TPMS_SESSION_AUDIT_INFO Structure */

void TSS_TPMS_SESSION_AUDIT_INFO_Print(TPMS_SESSION_AUDIT_INFO *source, unsigned int indent)
{
    printf("%*s" "TPMS_SESSION_AUDIT_INFO exclusiveSession %d\n", indent, "",
	   source->exclusiveSession);
    TSS_TPM2B_Print("TPMS_SESSION_AUDIT_INFO sessionDigest", indent, &source->sessionDigest.b);
   return;
}

/* Table 122 - Definition of TPMS_CREATION_INFO Structure <OUT> */

void TSS_TPMS_CREATION_INFO_Print(TPMS_CREATION_INFO *source, unsigned int indent)
{
    TSS_TPM2B_Print("TPMS_CREATION_INFO objectName", indent, &source->objectName.b);
    TSS_TPM2B_Print("TPMS_CREATION_INFO creationHash", indent, &source->creationHash.b);
    return;
}

/* Table 123 - Definition of TPMS_NV_CERTIFY_INFO Structure */

void TSS_TPMS_NV_CERTIFY_INFO_Print(TPMS_NV_CERTIFY_INFO *source, unsigned int indent)
{
    TSS_TPM2B_Print("TPMS_NV_CERTIFY_INFO indexName", indent, &source->indexName.b);
    printf("%*s" "TPMS_NV_CERTIFY_INFO offset %d\n", indent, "",  source->offset);
    TSS_TPM2B_Print("TPMS_NV_CERTIFY_INFO nvContents", indent, &source->nvContents.b);
    return;
}

/* Table 125 - Definition of TPMS_NV_DIGEST_CERTIFY_INFO Structure <OUT> */
void TSS_TPMS_NV_DIGEST_CERTIFY_INFO_Print(TPMS_NV_DIGEST_CERTIFY_INFO  *source, unsigned int indent)
{
    TSS_TPM2B_Print("TPMS_NV_DIGEST_CERTIFY_INFO indexName", indent, &source->indexName.b);
    TSS_TPM2B_Print("TPMS_NV_DIGEST_CERTIFY_INFO nvDigest", indent, &source->nvDigest.b);
    return;
}

/* Table 124 - Definition of (TPM_ST) TPMI_ST_ATTEST Type <OUT> */

void TSS_TPMI_ST_ATTEST_Print(const char *string, TPMI_ST_ATTEST selector, unsigned int indent)
{
    printf("%*s", indent, "");
    switch (selector) {
      case TPM_ST_ATTEST_CERTIFY:
	printf("%s TPM_ST_ATTEST_CERTIFY\n", string);
	break;
      case TPM_ST_ATTEST_CREATION:
	printf("%s TPM_ST_ATTEST_CREATION\n", string);
	break;
      case TPM_ST_ATTEST_QUOTE:
	printf("%s TPM_ST_ATTEST_QUOTE\n", string);
	break;
      case TPM_ST_ATTEST_COMMAND_AUDIT:
	printf("%s TPM_ST_ATTEST_COMMAND_AUDIT\n", string);
	break;
      case TPM_ST_ATTEST_SESSION_AUDIT:
	printf("%s TPM_ST_ATTEST_SESSION_AUDIT\n", string);
	break;
      case TPM_ST_ATTEST_TIME:
	printf("%s TPM_ST_ATTEST_TIME\n", string);
	break;
      case TPM_ST_ATTEST_NV:
	printf("%s TPM_ST_ATTEST_NV\n", string);
	break;
      case TPM_ST_ATTEST_NV_DIGEST:
	printf("%s TPM_ST_ATTEST_NV_DIGEST\n", string);
	break;
      default:
	printf("%s TPMI_ST_ATTEST_Print: selection %04hx not implemented\n", string, selector);
    }
    return;
}

/* Table 125 - Definition of TPMU_ATTEST Union <OUT> */

void TSS_TPMU_ATTEST_Print(TPMU_ATTEST *source, TPMI_ST_ATTEST selector, unsigned int indent)
{
    switch (selector) {
      case TPM_ST_ATTEST_CERTIFY:
	TSS_TPMS_CERTIFY_INFO_Print(&source->certify, indent+2);
	break;
      case TPM_ST_ATTEST_CREATION:
	TSS_TPMS_CREATION_INFO_Print(&source->creation, indent+2);
	break;
      case TPM_ST_ATTEST_QUOTE:
	TSS_TPMS_QUOTE_INFO_Print(&source->quote, indent+2);
	break;
      case TPM_ST_ATTEST_COMMAND_AUDIT:
	TSS_TPMS_COMMAND_AUDIT_INFO_Print(&source->commandAudit, indent+2);
	break;
      case TPM_ST_ATTEST_SESSION_AUDIT:
	TSS_TPMS_SESSION_AUDIT_INFO_Print(&source->sessionAudit, indent+2);
	break;
      case TPM_ST_ATTEST_TIME:
	TSS_TPMS_TIME_ATTEST_INFO_Print(&source->time, indent+2);
	break;
      case TPM_ST_ATTEST_NV:
	TSS_TPMS_NV_CERTIFY_INFO_Print(&source->nv, indent+2);
	break;
      case TPM_ST_ATTEST_NV_DIGEST:
	TSS_TPMS_NV_DIGEST_CERTIFY_INFO_Print(&source->nvDigest, indent+2);
	break;
      default:
	printf("%*s" "TPMU_ATTEST selection %04hx not implemented\n", indent, "", selector);
    }
    return;
}

/* Table 126 - Definition of TPMS_ATTEST Structure <OUT> */

void TSS_TPMS_ATTEST_Print(TPMS_ATTEST *source, unsigned int indent)
{
    printf("%*s" "TPMS_ATTEST magic %08x\n", indent+2, "", source->magic);
    TSS_TPMI_ST_ATTEST_Print("type", source->type, indent+2);
    TSS_TPM2B_Print("TPMS_ATTEST qualifiedSigner", indent+2, &source->qualifiedSigner.b);
    TSS_TPM2B_Print("TPMS_ATTEST extraData", indent+2, &source->extraData.b);
    TSS_TPMS_CLOCK_INFO_Print(&source->clockInfo, indent+2);
    printf("%*s" "TPMS_ATTEST firmwareVersion %"PRIu64"\n",  indent+2, "", source->firmwareVersion);
    TSS_TPMU_ATTEST_Print(&source->attested, source->type, indent+2);
    return;
}

#if 0	/* Removed because it required a large stack allocation.  The utilities didn't use it, but
	   rather did the unmarshal and print themselves. */

/* Table 127 - Definition of TPM2B_ATTEST Structure <OUT> */

void TSS_TPM2B_ATTEST_Print(TPM2B_ATTEST *source, unsigned int indent)
{
    TPM_RC			rc = 0;
    TPMS_ATTEST 		attests;
    uint32_t			size;
    uint8_t			*buffer = NULL;

    /* unmarshal the TPMS_ATTEST from the TPM2B_ATTEST */
    if (rc == 0) {
	buffer = source->t.attestationData;
	size = source->t.size;
	rc = TSS_TPMS_ATTEST_Unmarshalu(&attests, &buffer, &size);
    }
    if (rc == 0) {
	TSS_TPMS_ATTEST_Print(&attests, indent+2);
    }
    else {
	printf("%*s" "TPMS_ATTEST_Unmarshal failed\n", indent, "");
    }
    return;
}
#endif

/* Table 128 - Definition of TPMS_AUTH_COMMAND Structure <IN> */

void TSS_TPMS_AUTH_COMMAND_Print(TPMS_AUTH_COMMAND *source, unsigned int indent)
{
    TSS_TPM_HANDLE_Print("sessionHandle", source->sessionHandle, indent);	
    TSS_TPM2B_Print("TPMS_AUTH_COMMAND nonce", indent, &source->nonce.b);
    TSS_TPMA_SESSION_Print(source->sessionAttributes, indent);
    TSS_TPM2B_Print("TPMS_AUTH_COMMAND hmac", indent, &source->hmac.b);
    return;
}

/* Table 129 - Definition of TPMS_AUTH_RESPONSE Structure <OUT> */

void TSS_TPMS_AUTH_RESPONSE_Print(TPMS_AUTH_RESPONSE *source, unsigned int indent)
{
    TSS_PrintAlli("TPMS_AUTH_RESPONSE nonce", indent,
		  source->nonce.t.buffer,
		  source->nonce.t.size);
    TSS_TPMA_SESSION_Print(source->sessionAttributes, indent);
    TSS_TPM2B_Print("TPMS_AUTH_RESPONSE hmac", indent, &source->hmac.b);
    return;
}

/* Table 130 - Definition of  {!ALG.S} (TPM_KEY_BITS) TPMI_!ALG.S_KEY_BITS   Type */

void TSS_TPM_KEY_BITS_Print(TPM_KEY_BITS source, unsigned int indent)
{
    printf("%*s" "TPM_KEY_BITS %u\n", indent, "", source);
    return;
}

/* Table 131 - Definition of TPMU_SYM_KEY_BITS Union */

void TSS_TPMU_SYM_KEY_BITS_Print(TPMU_SYM_KEY_BITS *source, TPMI_ALG_SYM selector, unsigned int indent)
{
    switch (selector) {
#ifdef TPM_ALG_AES
      case TPM_ALG_AES:
	TSS_TPM_KEY_BITS_Print(source->aes, indent);
	break;
#endif
#ifdef TPM_ALG_SM4
      case TPM_ALG_SM4:
	TSS_TPM_KEY_BITS_Print(source->sm4, indent);
	break;
#endif
#ifdef TPM_ALG_CAMELLIA
      case TPM_ALG_CAMELLIA:
	TSS_TPM_KEY_BITS_Print(source->camellia, indent);
	break;
#endif
#ifdef TPM_ALG_XOR
      case TPM_ALG_XOR:
	TSS_TPM_ALG_ID_Print("xorr", source->xorr, indent);
	break;
#endif
      default:
	printf("%*s" "TPMI_ALG_SYM value %04hx unknown\n", indent, "", selector);
    }

    return;
}

/* Table 134 - Definition of TPMT_SYM_DEF Structure */

void TSS_TPMT_SYM_DEF_Print(TPMT_SYM_DEF *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("algorithm", source->algorithm, indent);
    TSS_TPMU_SYM_KEY_BITS_Print(&source->keyBits, source->algorithm, indent);
    TSS_TPM_ALG_ID_Print("mode", source->mode.sym, indent);		
    return;
}

/* Table 135 - Definition of TPMT_SYM_DEF_OBJECT Structure */

void TSS_TPMT_SYM_DEF_OBJECT_Print(TPMT_SYM_DEF_OBJECT *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("algorithm", source->algorithm, indent+2);
    if (source->algorithm != TPM_ALG_NULL) {
	printf("%*s" "keyBits: %u\n", indent+2, "", source->keyBits.sym);
	TSS_TPM_ALG_ID_Print("mode", source->mode.sym, indent+2);
    }
    return;
}

/* Table 139 - Definition of TPMS_DERIVE Structure */

void TSS_TPMS_DERIVE_Print(TPMS_DERIVE *source, unsigned int indent)
{
    TSS_TPM2B_Print("TPMS_DERIVE label", indent, &source->label.b);
    TSS_TPM2B_Print("TPMS_DERIVE context", indent, &source->context.b);
    return;
}

/* Table 143 - Definition of TPMS_SENSITIVE_CREATE Structure <IN> */

void TSS_TPMS_SENSITIVE_CREATE_Print(TPMS_SENSITIVE_CREATE *source, unsigned int indent)
{
    TSS_TPM2B_Print("userAuth", indent, &source->userAuth.b);
    TSS_TPM2B_Print("data", indent, &source->data.b);
    return;
}

/* Table 144 - Definition of TPM2B_SENSITIVE_CREATE Structure <IN, S> */

void TSS_TPM2B_SENSITIVE_CREATE_Print(const char *string, TPM2B_SENSITIVE_CREATE *source, unsigned int indent)
{
    printf("%*s" "%s\n", indent, "", string);
    TSS_TPMS_SENSITIVE_CREATE_Print(&source->sensitive, indent+2);
    return;
}

/* Table 146 - Definition of {ECC} TPMS_SCHEME_ECDAA Structure */

void TSS_TPMS_SCHEME_ECDAA_Print(TPMS_SCHEME_ECDAA *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("hashAlg", source->hashAlg, indent+2);
    printf("%*s" "TPMS_SCHEME_ECDAA count %u\n", indent+2, "", source->count);
    return;
}

/* Table 149 - Definition of TPMS_SCHEME_XOR Structure */

void TSS_TPMS_SCHEME_XOR_Print(TPMS_SCHEME_XOR *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("hashAlg", source->hashAlg, indent+2);
    TSS_TPM_ALG_ID_Print("kdf", source->kdf, indent+2);
    return;
}

/* Table 150 - Definition of TPMU_SCHEME_KEYEDHASH Union <IN/OUT, S> */

void TSS_TPMU_SCHEME_KEYEDHASH_Print(TPMU_SCHEME_KEYEDHASH *source, TPMI_ALG_KEYEDHASH_SCHEME selector,
				     unsigned int indent)
{
    switch (selector) {
#ifdef TPM_ALG_HMAC
      case TPM_ALG_HMAC:
	TSS_TPM_ALG_ID_Print("hmac", source->hmac.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_XOR
      case TPM_ALG_XOR:
	TSS_TPMS_SCHEME_XOR_Print(&source->xorr, indent+2);
	break;
#endif
      default:
	printf("%*s" "TPMU_SCHEME_KEYEDHASH selection %04hx not implemented\n", indent, "", selector);
    }
    return;
}

/* Table 151 - Definition of TPMT_KEYEDHASH_SCHEME Structure */

void TSS_TPMT_KEYEDHASH_SCHEME_Print(TPMT_KEYEDHASH_SCHEME *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("scheme", source->scheme, indent+2);
    if (source->scheme != TPM_ALG_NULL) {
	TSS_TPMU_SCHEME_KEYEDHASH_Print(&source->details, source->scheme, indent+2);
    }
    return;
}

/* Table 154 - Definition of TPMU_SIG_SCHEME Union <IN/OUT, S> */

void TSS_TPMU_SIG_SCHEME_Print(TPMU_SIG_SCHEME *source, TPMI_ALG_SIG_SCHEME selector, unsigned int indent)
{
    switch (selector) {
#ifdef TPM_ALG_RSASSA
      case TPM_ALG_RSASSA:
	TSS_TPM_ALG_ID_Print("rsassa", source->rsassa.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_RSAPSS
      case TPM_ALG_RSAPSS:
	TSS_TPM_ALG_ID_Print("rsapss", source->rsapss.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECDSA
      case TPM_ALG_ECDSA:
	TSS_TPM_ALG_ID_Print("ecdsa", source->ecdsa.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECDAA
      case TPM_ALG_ECDAA:
	TSS_TPMS_SCHEME_ECDAA_Print(&source->ecdaa, indent+2);
	break;
#endif
#ifdef TPM_ALG_SM2
      case TPM_ALG_SM2:
	TSS_TPM_ALG_ID_Print("sm2", source->sm2.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
	TSS_TPM_ALG_ID_Print("ecSchnorr", source->ecSchnorr.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_HMAC
      case TPM_ALG_HMAC:
	TSS_TPM_ALG_ID_Print("hmac", source->hmac.hashAlg, indent+2);
	break;
#endif
      default:
	printf("%*s" "TPMU_SIG_SCHEME selection %04hx not implemented\n", indent, "", selector);
    }
    return;
}

/* Table " Definition", 155 - Definition of TPMT_SIG_SCHEME Structure */

void TSS_TPMT_SIG_SCHEME_Print(TPMT_SIG_SCHEME *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("scheme", source->scheme, indent+2);
    if (source->scheme != TPM_ALG_NULL) {
	TSS_TPMU_SIG_SCHEME_Print(&source->details, source->scheme, indent+2);
    }
    return;
}

/* Table 160 - Definition of TPMT_KDF_SCHEME Structure */

void TSS_TPMT_KDF_SCHEME_Print(TPMT_KDF_SCHEME *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("scheme", source->scheme, indent+2);
    if (source->scheme != TPM_ALG_NULL) {
	TSS_TPM_ALG_ID_Print("details", source->details.mgf1.hashAlg, indent+2);
    }
    return;
}

/* Table 162 - Definition of TPMU_ASYM_SCHEME Union */

void TSS_TPMU_ASYM_SCHEME_Print(TPMU_ASYM_SCHEME *source, TPMI_ALG_ASYM_SCHEME selector, unsigned int indent)
{
    switch (selector) {
#ifdef TPM_ALG_ECDH
      case TPM_ALG_ECDH:
	TSS_TPM_ALG_ID_Print("ecdh", source->ecdh.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECMQV
      case TPM_ALG_ECMQV:
	TSS_TPM_ALG_ID_Print("ecmqvh", source->ecmqvh.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_RSASSA
      case TPM_ALG_RSASSA:
	TSS_TPM_ALG_ID_Print("rsassa", source->rsassa.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_RSAPSS
      case TPM_ALG_RSAPSS:
	TSS_TPM_ALG_ID_Print("rsapss", source->rsapss.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECDSA
      case TPM_ALG_ECDSA:
	TSS_TPM_ALG_ID_Print("ecdsa", source->ecdsa.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECDAA
      case TPM_ALG_ECDAA:
	TSS_TPMS_SCHEME_ECDAA_Print(&source->ecdaa, indent+2);
	break;
#endif
#ifdef TPM_ALG_SM2
      case TPM_ALG_SM2:
	TSS_TPM_ALG_ID_Print("sm2", source->sm2.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
	TSS_TPM_ALG_ID_Print("ecSchnorr", source->ecSchnorr.hashAlg, indent+2);
	break;
#endif
#ifdef TPM_ALG_RSAES
      case TPM_ALG_RSAES:
	break;
#endif
#ifdef TPM_ALG_OAEP
      case TPM_ALG_OAEP:
	TSS_TPM_ALG_ID_Print("oaep", source->oaep.hashAlg, indent+2);
	break;
#endif
      default:
	printf("%*s" "TPMU_ASYM_SCHEME selection %04hx not implemented\n", indent, "", selector);
    }
    return;
}

/* Table 163 - Definition of TPMT_ASYM_SCHEME Structure <> */

void TSS_TPMT_ASYM_SCHEME_Print(TPMT_ASYM_SCHEME *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("scheme", source->scheme, indent+2);
    if (source->scheme != TPM_ALG_NULL) {
	TSS_TPMU_ASYM_SCHEME_Print(&source->details, source->scheme, indent+2);
    }
    return;
}
	
/* Table 165 - Definition of {RSA} TPMT_RSA_SCHEME Structure */

void TSS_TPMT_RSA_SCHEME_Print(TPMT_RSA_SCHEME *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("scheme", source->scheme, indent);
    if (source->scheme != TPM_ALG_NULL) {
	TSS_TPM_ALG_ID_Print("details", source->details.anySig.hashAlg, indent+2);
    }
    return;
}

/* Table 167 - Definition of {RSA} TPMT_RSA_DECRYPT Structure */

void TSS_TPMT_RSA_DECRYPT_Print(TPMT_RSA_DECRYPT *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("scheme", source->scheme, indent+2);
    if (source->scheme != TPM_ALG_NULL) {
	TSS_TPMU_ASYM_SCHEME_Print(&source->details, source->scheme, indent+2);
    }
    return;
}

/* Table 169 - Definition of {RSA} (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type */

void TSS_TPMI_RSA_KEY_BITS_Print(TPMI_RSA_KEY_BITS source, unsigned int indent)
{
    printf("%*s" "TPM_KEY_BITS keyBits: %u\n", indent, "", source);
    return;
}

/* Table 172 - Definition of {ECC} TPMS_ECC_POINT Structure */

void TSS_TPMS_ECC_POINT_Print(TPMS_ECC_POINT *source, unsigned int indent)
{
    TSS_TPM2B_Print("TPMS_ECC_POINT x", indent+2, &source->x.b);
    TSS_TPM2B_Print("TPMS_ECC_POINT y", indent+2, &source->y.b);
    return;
}

/* Table 173 - Definition of {ECC} TPM2B_ECC_POINT Structure */

void TSS_TPM2B_ECC_POINT_Print(const char *string, TPM2B_ECC_POINT *source, unsigned int indent)
{
    printf("%*s" "%s\n", indent, "", string);
    TSS_TPMS_ECC_POINT_Print(&source->point, indent);
    return;
}

/* Table 175 - Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type */

void TSS_TPMI_ECC_CURVE_Print(const char *string, TPMI_ECC_CURVE source, unsigned int indent)
{
    printf("%*s", indent, "");
    switch (source) {
      case TPM_ECC_BN_P256:
	printf("%s TPM_ECC_BN_P256\n", string);
	break;
      case TPM_ECC_NIST_P256:
	printf("%s TPM_ECC_NIST_P256\n", string);
	break;
      case TPM_ECC_NIST_P384:
	printf("%s TPM_ECC_NIST_P384\n", string);
	break;
      default:
	printf("%s TPMI_ECC_CURVE %04hx unknown\n", string, source);
    }
    return;
}

/* Table 176 - Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure */

void TSS_TPMT_ECC_SCHEME_Print(TPMT_ECC_SCHEME *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("scheme", source->scheme, indent+2);
    if (source->scheme != TPM_ALG_NULL) {
	TSS_TPM_ALG_ID_Print("details", source->details.anySig.hashAlg, indent+2);
    }
    return;
}

/* Table 177 - Definition of {ECC} TPMS_ALGORITHM_DETAIL_ECC Structure <OUT> */

void TSS_TPMS_ALGORITHM_DETAIL_ECC_Print(TPMS_ALGORITHM_DETAIL_ECC *source, unsigned int indent)
{
    TSS_TPM_ECC_CURVE_Print("curveID", source->curveID, indent+2);
    printf("%*s" "TPMS_ALGORITHM_DETAIL_ECC keySize %u\n", indent+2, "", source->keySize);
    TSS_TPMT_KDF_SCHEME_Print(&source->kdf, indent+2);
    TSS_TPMT_ECC_SCHEME_Print(&source->sign, indent+2);
    TSS_TPM2B_Print("TPMS_ALGORITHM_DETAIL_ECC p", indent, &source->p.b);
    TSS_TPM2B_Print("TPMS_ALGORITHM_DETAIL_ECC a", indent, &source->a.b);
    TSS_TPM2B_Print("TPMS_ALGORITHM_DETAIL_ECC b", indent, &source->b.b);
    TSS_TPM2B_Print("TPMS_ALGORITHM_DETAIL_ECC gX", indent, &source->gX.b);
    TSS_TPM2B_Print("TPMS_ALGORITHM_DETAIL_ECC gY", indent, &source->gY.b);
    TSS_TPM2B_Print("TPMS_ALGORITHM_DETAIL_ECC n", indent, &source->n.b);
    TSS_TPM2B_Print("TPMS_ALGORITHM_DETAIL_ECC h", indent, &source->h.b);
    return;
}

/* Table 178 - Definition of {RSA} TPMS_SIGNATURE_RSA Structure */

void TSS_TPMS_SIGNATURE_RSA_Print(TPMS_SIGNATURE_RSA *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("hash", source->hash, indent+2);
    TSS_TPM2B_Print("TPMS_SIGNATURE_RSA sig", indent+2, &source->sig.b);
    return;
}

/* Table 179 - Definition of Types for {RSA} Signature */

void TSS_TPMS_SIGNATURE_RSASSA_Print(TPMS_SIGNATURE_RSASSA *source, unsigned int indent)
{
    TSS_TPMS_SIGNATURE_RSA_Print(source, indent+2);
    return;
}

/* Table 180 - Definition of {ECC} TPMS_SIGNATURE_ECC Structure */

void TSS_TPMS_SIGNATURE_ECC_Print(TPMS_SIGNATURE_ECC *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("hash", source->hash, indent);
    TSS_TPM2B_Print("TPMS_SIGNATURE_ECC signatureR", indent, &source->signatureR.b);
    TSS_TPM2B_Print("TPMS_SIGNATURE_ECC signatureS", indent, &source->signatureS.b);
    return;
}

/* Table 182 - Definition of TPMU_SIGNATURE Union <IN/OUT, S> */

void TSS_TPMU_SIGNATURE_Print(TPMU_SIGNATURE *source, TPMI_ALG_SIG_SCHEME selector, unsigned int indent)
{
    switch (selector) {
#ifdef TPM_ALG_RSASSA
      case TPM_ALG_RSASSA:
	TSS_TPMS_SIGNATURE_RSA_Print(&source->rsassa, indent+2);
	break;
#endif
#ifdef TPM_ALG_RSAPSS
      case TPM_ALG_RSAPSS:
	TSS_TPMS_SIGNATURE_RSA_Print(&source->rsapss, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECDSA
      case TPM_ALG_ECDSA:
	TSS_TPMS_SIGNATURE_ECC_Print(&source->ecdsa, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECDAA
      case TPM_ALG_ECDAA:
	TSS_TPMS_SIGNATURE_ECC_Print(&source->ecdaa, indent+2);
	break;
#endif
#ifdef TPM_ALG_SM2
      case TPM_ALG_SM2:
	TSS_TPMS_SIGNATURE_ECC_Print(&source->sm2, indent+2);
	break;
#endif
#ifdef TPM_ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
	TSS_TPMS_SIGNATURE_ECC_Print(&source->ecschnorr, indent+2);
	break;
#endif
#ifdef TPM_ALG_HMAC
      case TPM_ALG_HMAC:
	TSS_TPMT_HA_Print(&source->hmac, indent+2);
	break;
#endif
     default:
	printf("%*s" "TPMU_SIGNATURE selection %04hx not implemented\n", indent, "", selector);
	
    }
}

/* Table 183 - Definition of TPMT_SIGNATURE Structure */

void TSS_TPMT_SIGNATURE_Print(TPMT_SIGNATURE *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("sigAlg", source->sigAlg, indent+2);
    if (source->sigAlg != TPM_ALG_NULL) {
	TSS_TPMU_SIGNATURE_Print(&source->signature, source->sigAlg, indent);
    }
    return;
}

/* Table 186 - Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type */

void TSS_TPMI_ALG_PUBLIC_Print(const char *string, TPMI_ALG_PUBLIC source, unsigned int indent)
{
    printf("%*s", indent, "");
    switch (source) {
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	printf("%s TPM_ALG_KEYEDHASH\n", string);
	break;
#endif
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	printf("%s TPM_ALG_RSA\n", string);
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	printf("%s TPM_ALG_ECC\n", string);
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	printf("%s TPM_ALG_SYMCIPHER\n", string);
	break;
#endif
      default:
	printf("%s selection %04hx not implemented\n", string, source);
    }
    return;
}
    
/* Table 187 - Definition of TPMU_PUBLIC_ID Union <IN/OUT, S> */

void TSS_TPMU_PUBLIC_ID_Print(TPMU_PUBLIC_ID *source, TPMI_ALG_PUBLIC selector, unsigned int indent)
{
    switch (selector) {
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	TSS_TPM2B_Print("TPM_ALG_KEYEDHASH keyedHash", indent, &source->keyedHash.b);
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	TSS_TPM2B_Print("TPM_ALG_SYMCIPHER sym", indent, &source->sym.b);
	break;
#endif
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA: 
	TSS_TPM2B_Print("TPM_ALG_RSA rsa", indent, &source->rsa.b);
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	TSS_TPM2B_Print("TPM_ALG_ECC x", indent, &source->ecc.x.b);
	TSS_TPM2B_Print("TPM_ALG_ECC y", indent, &source->ecc.y.b);
	break;
#endif
      default:
	printf("%*s" "TPMU_PUBLIC_ID_Print: selection %04hx not implemented\n", indent, "", selector);
    }
    return;
}

/* Table 188 - Definition of TPMS_KEYEDHASH_PARMS Structure */

void TSS_TPMS_KEYEDHASH_PARMS_Print(TPMS_KEYEDHASH_PARMS *source, unsigned int indent)
{
    TSS_TPMT_KEYEDHASH_SCHEME_Print(&source->scheme, indent);
    return;
}

/* Table 189 - Definition of TPMS_ASYM_PARMS Structure <> */

void TSS_TPMS_ASYM_PARMS_Print(TPMS_ASYM_PARMS *source, unsigned int indent)
{
    TSS_TPMT_SYM_DEF_OBJECT_Print(&source->symmetric, indent+2);
    TSS_TPMT_ASYM_SCHEME_Print(&source->scheme, indent+2);
    return;
}

/* Table 190 - Definition of {RSA} TPMS_RSA_PARMS Structure */

void TSS_TPMS_RSA_PARMS_Print(TPMS_RSA_PARMS *source, unsigned int indent)
{
    TSS_TPMT_SYM_DEF_OBJECT_Print(&source->symmetric, indent);
    TSS_TPMT_RSA_SCHEME_Print(&source->scheme, indent);
    TSS_TPMI_RSA_KEY_BITS_Print(source->keyBits, indent);
    printf("%*s" "TPMS_RSA_PARMS exponent %08x\n", indent, "", source->exponent);
    return;
}

/* Table 191 - Definition of {ECC} TPMS_ECC_PARMS Structure */

void TSS_TPMS_ECC_PARMS_Print(TPMS_ECC_PARMS *source, unsigned int indent)
{
    TSS_TPMT_SYM_DEF_OBJECT_Print(&source->symmetric, indent);
    TSS_TPMT_ECC_SCHEME_Print(&source->scheme, indent);
    TSS_TPMI_ECC_CURVE_Print("curveID", source->curveID, indent);
    TSS_TPMT_KDF_SCHEME_Print(&source->kdf, indent);
    return;
}

/* Table 192 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */

void TSS_TPMU_PUBLIC_PARMS_Print(TPMU_PUBLIC_PARMS *source, uint32_t selector, unsigned int indent)
{
    switch (selector) {
      case TPM_ALG_KEYEDHASH:
	printf("%*s" "TPMU_PUBLIC_PARMS keyedHashDetail\n", indent, "");
	TSS_TPMS_KEYEDHASH_PARMS_Print(&source->keyedHashDetail, indent);
	break;
#if 0
      case TPM_ALG_SYMCIPHER:
	printf("%*s" "TPMU_PUBLIC_PARMS symDetail\n", indent, "");
	TSS_TPMS_SYMCIPHER_PARMS_Print(&source->symDetail, indent);
	break;
#endif
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	printf("%*s" "TPMU_PUBLIC_PARMS rsaDetail\n", indent, "");
	TSS_TPMS_RSA_PARMS_Print(&source->rsaDetail, indent);
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	printf("%*s" "TPMU_PUBLIC_PARMS eccDetail\n", indent, "");
	TSS_TPMS_ECC_PARMS_Print(&source->eccDetail, indent);
	break;
#endif
      default:
	printf("%*s" "TPMU_PUBLIC_PARMS: selector %04x not implemented\n", indent, "", selector);
    }
    return;
}

/* Table 193 - Definition of TPMT_PUBLIC_PARMS Structure */

void TSS_TPMT_PUBLIC_PARMS_Print(TPMT_PUBLIC_PARMS *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("type", source->type, indent);
    TSS_TPMU_PUBLIC_PARMS_Print(&source->parameters, source->type, indent);
    return;
}
/* Table 194 - Definition of TPMT_PUBLIC Structure */

void TSS_TPMT_PUBLIC_Print(TPMT_PUBLIC *source, unsigned int indent)
{
    TSS_TPMI_ALG_PUBLIC_Print("type", source->type, indent);
    TSS_TPM_ALG_ID_Print("nameAlg", source->nameAlg, indent);
    TSS_TPMA_OBJECT_Print("objectAttributes", source->objectAttributes, indent);	
    TSS_TPM2B_Print("authPolicy", indent, &source->authPolicy.b);
    TSS_TPMU_PUBLIC_PARMS_Print(&source->parameters, source->type, indent);		
    TSS_TPMU_PUBLIC_ID_Print(&source->unique, source->type, indent);			
    return;
}

/* Table 195 - Definition of TPM2B_PUBLIC Structure */

void TSS_TPM2B_PUBLIC_Print(const char *string, TPM2B_PUBLIC *source, unsigned int indent)
{
    printf("%*s" "%s\n", indent, "", string);
    TSS_TPMT_PUBLIC_Print(&source->publicArea, indent+2);		
    return;
}

/* Table 198 - Definition of TPMU_SENSITIVE_COMPOSITE Union <IN/OUT, S> */

void TSS_TPMU_SENSITIVE_COMPOSITE_Print(TPMU_SENSITIVE_COMPOSITE *source, uint32_t selector, unsigned int indent)
{
    switch (selector) {
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	TSS_TPM2B_Print("TPMU_SENSITIVE_COMPOSITE rsa", indent+2, &source->rsa.b);
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	TSS_TPM2B_Print("TPMU_SENSITIVE_COMPOSITE ecc", indent+2, &source->ecc.b);
	break;
#endif
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	TSS_TPM2B_Print("TPMU_SENSITIVE_COMPOSITE bits", indent+2, &source->bits.b);
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	TSS_TPM2B_Print("TPMU_SENSITIVE_COMPOSITE sym", indent+2, &source->sym.b);
	break;
#endif
      default:
	printf("%*s" "TPMU_SENSITIVE_COMPOSITE: selection %08x not implemented \n", indent+2, "", selector);
    }
    return;
}

/* Table 199 - Definition of TPMT_SENSITIVE Structure */

void TSS_TPMT_SENSITIVE_Print(TPMT_SENSITIVE *source, unsigned int indent)
{
    TSS_TPM_ALG_ID_Print("sensitiveType", source->sensitiveType, indent+2);
    TSS_TPM2B_Print("TPMT_SENSITIVE authValue", indent+2, &source->authValue.b);
    TSS_TPM2B_Print("TPMT_SENSITIVE seedValue", indent+2, &source->seedValue.b);
    TSS_TPMU_SENSITIVE_COMPOSITE_Print(&source->sensitive, source->sensitiveType, indent+2);
    return;
}

/* Table 200 - Definition of TPM2B_SENSITIVE Structure <IN/OUT> */

void TSS_TPM2B_SENSITIVE_Print(TPM2B_SENSITIVE *source, unsigned int indent)
{
    printf("%*s" "TPM2B_SENSITIVE size %u\n", indent+2, "", source->t.size);
    if (source->t.size != 0) {
	TSS_TPMT_SENSITIVE_Print(&source->t.sensitiveArea, indent+2);
    }
    return;
}

/* Table 207 - Definition of TPMS_NV_PIN_COUNTER_PARAMETERS Structure */

void TSS_TPMS_NV_PIN_COUNTER_PARAMETERS_Print(TPMS_NV_PIN_COUNTER_PARAMETERS *source, unsigned int indent)
{
    printf("%*s" "pinCount %u\n", indent+2, "", source->pinCount);
    printf("%*s" "pinLimit %u\n", indent+2, "", source->pinLimit);
    return;
}

/* Table 208 - Definition of (UINT32) TPMA_NV Bits */

void TSS_TPMA_NV_Print(TPMA_NV source, unsigned int indent)
{
    uint32_t nvType;

    if (source.val & TPMA_NVA_PPWRITE) printf("%*s" "TPMA_NV_PPWRITE\n", indent, "");
    if (source.val & TPMA_NVA_OWNERWRITE) printf("%*s" "TPMA_NV_OWNERWRITE\n", indent, "");
    if (source.val & TPMA_NVA_AUTHWRITE) printf("%*s" "TPMA_NV_AUTHWRITE\n", indent, "");
    if (source.val & TPMA_NVA_POLICYWRITE) printf("%*s" "TPMA_NV_POLICYWRITE\n", indent, "");

    nvType = (source.val & TPMA_NVA_TPM_NT_MASK) >> 4;
    switch (nvType) {
      case TPM_NT_ORDINARY:
	printf("%*s" "TPM_NT_ORDINARY\n", indent, "");
	break;
      case TPM_NT_COUNTER:
	printf("%*s" "TPM_NT_COUNTER\n", indent, "");
	break;
      case TPM_NT_BITS:
	printf("%*s" "TPM_NT_COUNTER\n", indent, "");
	break;
      case TPM_NT_EXTEND:
	printf("%*s" "TPM_NT_EXTEND\n", indent, "");
	break;
      case TPM_NT_PIN_FAIL:
	printf("%*s" "TPM_NT_PIN_FAIL\n", indent, "");
	break;
      case TPM_NT_PIN_PASS:
	printf("%*s" "TPM_NT_PIN_PASS\n", indent, "");
	break;
      default:
	printf("%*s" "TPMA_NV type %02x unknown\n", indent, "", nvType);
    }

    if (source.val & TPMA_NVA_POLICY_DELETE) printf("%*s" "TPMA_NV_POLICY_DELETE\n", indent, "");
    if (source.val & TPMA_NVA_WRITELOCKED) printf("%*s" "TPMA_NV_WRITELOCKED\n", indent, "");
    if (source.val & TPMA_NVA_WRITEALL) printf("%*s" "TPMA_NV_WRITEALL\n", indent, "");
    if (source.val & TPMA_NVA_WRITEDEFINE) printf("%*s" "TPMA_NV_WRITEDEFINE\n", indent, "");
    if (source.val & TPMA_NVA_WRITE_STCLEAR) printf("%*s" "TPMA_NV_WRITE_STCLEAR\n", indent, "");
    if (source.val & TPMA_NVA_GLOBALLOCK) printf("%*s" "TPMA_NV_GLOBALLOCK\n", indent, "");
    if (source.val & TPMA_NVA_PPREAD) printf("%*s" "TPMA_NV_PPREAD\n", indent, "");
    if (source.val & TPMA_NVA_OWNERREAD) printf("%*s" "TPMA_NV_OWNERREAD\n", indent, "");
    if (source.val & TPMA_NVA_AUTHREAD) printf("%*s" "TPMA_NV_AUTHREAD\n", indent, "");
    if (source.val & TPMA_NVA_POLICYREAD) printf("%*s" "TPMA_NV_POLICYREAD\n", indent, "");
    if (source.val & TPMA_NVA_NO_DA) printf("%*s" "TPMA_NV_NO_DA\n", indent, "");
    if (source.val & TPMA_NVA_ORDERLY) printf("%*s" "TPMA_NV_ORDERLY\n", indent, "");
    if (source.val & TPMA_NVA_CLEAR_STCLEAR) printf("%*s" "TPMA_NV_CLEAR_STCLEAR\n", indent, "");
    if (source.val & TPMA_NVA_READLOCKED) printf("%*s" "TPMA_NV_READLOCKED\n", indent, "");
    if (source.val & TPMA_NVA_WRITTEN) printf("%*s" "TPMA_NV_WRITTEN\n", indent, "");
    if (source.val & TPMA_NVA_PLATFORMCREATE) printf("%*s" "TPMA_NV_PLATFORMCREATE\n", indent, "");
    if (source.val & TPMA_NVA_READ_STCLEAR) printf("%*s" "TPMA_NV_READ_STCLEAR\n", indent, "");
    return;
}

/* Table 209 - Definition of TPMS_NV_PUBLIC Structure */

void TSS_TPMS_NV_PUBLIC_Print(TPMS_NV_PUBLIC *source, unsigned int indent)
{
    printf("%*s" "TPMS_NV_PUBLIC nvIndex %08x\n", indent+2, "", source->nvIndex);
    TSS_TPM_ALG_ID_Print("nameAlg", source->nameAlg, indent+2);
    TSS_TPMA_NV_Print(source->attributes, indent+2);
    TSS_TPM2B_Print("TPMS_NV_PUBLIC authPolicy", indent+2, &source->authPolicy.b);
    printf("%*s" "TPMS_NV_PUBLIC dataSize %u\n", indent+2, "", source->dataSize);
    return;
}

/* Table 210 - Definition of TPM2B_NV_PUBLIC Structure */

void TSS_TPM2B_NV_PUBLIC_Print(TPM2B_NV_PUBLIC *source, unsigned int indent)
{
    TSS_TPMS_NV_PUBLIC_Print(&source->nvPublic, indent+2);
    return;
}

/* Table 212 - Definition of TPMS_CONTEXT_DATA Structure <IN/OUT, S> */

void TSS_TPMS_CONTEXT_DATA_Print(TPMS_CONTEXT_DATA *source, unsigned int indent)
{
    TSS_TPM2B_Print("TPMS_CONTEXT_DATA integrity", indent+2, &source->integrity.b);
    TSS_TPM2B_Print("TPMS_CONTEXT_DATA encrypted", indent+2, &source->encrypted.b);
    return;
}

/* Table 214 - Definition of TPMS_CONTEXT Structure */

void TSS_TPMS_CONTEXT_Print(TPMS_CONTEXT *source, unsigned int indent)
{
    printf("%*s" "TPMS_CONTEXT sequence %"PRIu64"\n", indent+2, "", source->sequence);
    TSS_TPM_HANDLE_Print("savedHandle", source->savedHandle, indent+2);
    TSS_TPM_HANDLE_Print("hierarchy", source->hierarchy, indent+2);
    TSS_TPM2B_Print("TPMS_CONTEXT contextBlob", indent+2, &source->contextBlob.b);
    return;
}

/* Table 216 - Definition of TPMS_CREATION_DATA Structure <OUT> */

void TSS_TPMS_CREATION_DATA_Print(TPMS_CREATION_DATA *source, unsigned int indent)
{
    TSS_TPML_PCR_SELECTION_Print(&source->pcrSelect, indent+2);
    TSS_TPM2B_Print("TPMS_CREATION_DATA pcrDigest", indent+2, &source->pcrDigest.b);
    TSS_TPMA_LOCALITY_Print(source->locality, indent+2);
    TSS_TPM_ALG_ID_Print("parentNameAlg", source->parentNameAlg, indent+2);
    TSS_TPM2B_Print("TPMS_CREATION_DATA parentName", indent+2, &source->parentName.b);
    TSS_TPM2B_Print("TPMS_CREATION_DATA parentQualifiedName", indent+2, &source->parentQualifiedName.b);
    TSS_TPM2B_Print("TPMS_CREATION_DATA outsideInfo", indent+2, &source->outsideInfo.b);
return;
}

/* Table 217 - Definition of TPM2B_CREATION_DATA Structure <OUT> */

void TSS_TPM2B_CREATION_DATA_Print(TPM2B_CREATION_DATA *source, unsigned int indent)
{
    printf("%*s" "TPM2B_CREATION_DATA size %u\n", indent+2, "", source->size);
    TSS_TPMS_CREATION_DATA_Print(&source->creationData, indent+2);
    return;
}

#endif	/* TPM_TPM20 */

#endif /* TPM_TSS_NO_PRINT */
