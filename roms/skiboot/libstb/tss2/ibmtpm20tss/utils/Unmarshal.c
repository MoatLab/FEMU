/********************************************************************************/
/*										*/
/*			     Parameter Unmarshaling				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2019					*/
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

#include <ibmtss/Unmarshal_fp.h>

/* The functions with the TSS_ prefix are preferred.  They use an unsigned size.  The functions
   without the prefix are deprecated.  */

/* TPM_TSS_NOCMDCHECK defined strips the unmarshal functions used for command parameter checking
   TPM_TSS_NODEPRECATED	defines strips the deprecated functions that used a signed size
*/

/* The int and array functions are common to TPM 1.2 and TPM 2.0 */

TPM_RC
TSS_UINT8_Unmarshalu(UINT8 *target, BYTE **buffer, uint32_t *size)
{
    if (*size < sizeof(UINT8)) {
	return TPM_RC_INSUFFICIENT;
    }
    *target = (*buffer)[0];
    *buffer += sizeof(UINT8);
    *size -= sizeof(UINT8);
    return TPM_RC_SUCCESS;
}

#ifndef TPM_TSS_NOCMDCHECK
TPM_RC
TSS_INT8_Unmarshalu(INT8 *target, BYTE **buffer, uint32_t *size)
{
    return TSS_UINT8_Unmarshalu((UINT8 *)target, buffer, size);
}
#endif	/* TPM_TSS_NOCMDCHECK */

TPM_RC
TSS_UINT16_Unmarshalu(uint16_t *target, BYTE **buffer, uint32_t *size)
{
    if (*size < sizeof(uint16_t)) {
	return TPM_RC_INSUFFICIENT;
    }
    *target = ((uint16_t)((*buffer)[0]) << 8) |
	      ((uint16_t)((*buffer)[1]) << 0);
    *buffer += sizeof(uint16_t);
    *size -= sizeof(uint16_t);
    return TPM_RC_SUCCESS;
}

TPM_RC
TSS_UINT32_Unmarshalu(UINT32 *target, BYTE **buffer, uint32_t *size)
{
    if (*size < sizeof(uint32_t)) {
	return TPM_RC_INSUFFICIENT;
    }
    *target = ((uint32_t)((*buffer)[0]) << 24) |
	      ((uint32_t)((*buffer)[1]) << 16) |
	      ((uint32_t)((*buffer)[2]) <<  8) |
	      ((uint32_t)((*buffer)[3]) <<  0);
    *buffer += sizeof(uint32_t);
    *size -= sizeof(uint32_t);
    return TPM_RC_SUCCESS;
}

#ifndef TPM_TSS_NOCMDCHECK    
TPM_RC
TSS_INT32_Unmarshalu(INT32 *target, BYTE **buffer, uint32_t *size)
{
    return TSS_UINT32_Unmarshalu((UINT32 *)target, buffer, size);
}
#endif	/* TPM_TSS_NOCMDCHECK */

TPM_RC
TSS_UINT64_Unmarshalu(UINT64 *target, BYTE **buffer, uint32_t *size)
{
    if (*size < sizeof(UINT64)) {
	return TPM_RC_INSUFFICIENT;
    }
    *target = ((UINT64)((*buffer)[0]) << 56) |
	      ((UINT64)((*buffer)[1]) << 48) |
	      ((UINT64)((*buffer)[2]) << 40) |
	      ((UINT64)((*buffer)[3]) << 32) |
	      ((UINT64)((*buffer)[4]) << 24) |
	      ((UINT64)((*buffer)[5]) << 16) |
	      ((UINT64)((*buffer)[6]) <<  8) |
	      ((UINT64)((*buffer)[7]) <<  0);
    *buffer += sizeof(UINT64);
    *size -= sizeof(UINT64);
    return TPM_RC_SUCCESS;
}

TPM_RC
TSS_Array_Unmarshalu(BYTE *targetBuffer, uint16_t targetSize, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (*size < targetSize) {
	rc = TPM_RC_INSUFFICIENT;
    }
    else {
	memcpy(targetBuffer, *buffer, targetSize);
	*buffer += targetSize;
	*size -= targetSize;
    }
    return rc;
}

#ifndef TPM_TSS_NODEPRECATED
#ifndef TPM_TSS_NOCMDCHECK
TPM_RC UINT8_Unmarshal(UINT8 *target, BYTE **buffer, INT32 *size)
{
    return TSS_UINT8_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC INT8_Unmarshal(INT8 *target, BYTE **buffer, INT32 *size)
{
    return TSS_INT8_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC UINT16_Unmarshal(UINT16 *target, BYTE **buffer, INT32 *size)
{
    return TSS_UINT16_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC UINT32_Unmarshal(UINT32 *target, BYTE **buffer, INT32 *size)
{
    return TSS_UINT32_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC INT32_Unmarshal(INT32 *target, BYTE **buffer, INT32 *size)
{
    return TSS_INT32_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC UINT64_Unmarshal(UINT64 *target, BYTE **buffer, INT32 *size)
{
    return TSS_UINT64_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC Array_Unmarshal(BYTE *targetBuffer, UINT16 targetSize, BYTE **buffer, INT32 *size)
{
    return TSS_Array_Unmarshalu(targetBuffer, targetSize, buffer, (uint32_t *)size);
}

#endif /* TPM_TSS_NOCMDCHECK */
#endif /* TPM_TSS_NODEPRECATED */
#ifdef TPM_TPM20

TPM_RC
TSS_TPM2B_Unmarshalu(TPM2B *target, uint16_t targetSize, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->size, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->size > targetSize) {
	    rc = TPM_RC_SIZE;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_Array_Unmarshalu(target->buffer, target->size, buffer, size);
    }
    return rc;
}

/* Table 5 - Definition of Types for Documentation Clarity */

TPM_RC
TSS_TPM_KEY_BITS_Unmarshalu(TPM_KEY_BITS *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 7 - Definition of (UINT32) TPM_GENERATED Constants <O> */

#ifndef TPM_TSS_NOCMDCHECK
TPM_RC
TSS_TPM_GENERATED_Unmarshalu(TPM_GENERATED *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	if (*target != TPM_GENERATED_VALUE) {
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}
#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 9 - Definition of (UINT16) TPM_ALG_ID Constants <IN/OUT, S> */

TPM_RC
TSS_TPM_ALG_ID_Unmarshalu(TPM_ALG_ID *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 10 - Definition of (UINT16) {ECC} TPM_ECC_CURVE Constants <IN/OUT, S> */

#ifdef TPM_ALG_ECC
TPM_RC
TSS_TPM_ECC_CURVE_Unmarshalu(TPM_ECC_CURVE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(target, buffer, size);
    }
    return rc;
}
#endif	/*  TPM_ALG_ECC */

/* Table 13 - Definition of (UINT32) TPM_CC Constants (Numeric Order) <IN/OUT, S> */

TPM_RC
TSS_TPM_CC_Unmarshalu(TPM_RC *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 17 - Definition of (UINT32) TPM_RC Constants (Actions) <OUT> */

TPM_RC
TSS_TPM_RC_Unmarshalu(TPM_RC *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

#ifndef TPM_TSS_NOCMDCHECK

/* Table 18 - Definition of (INT8) TPM_CLOCK_ADJUST Constants <IN> */

TPM_RC
TSS_TPM_CLOCK_ADJUST_Unmarshalu(TPM_CLOCK_ADJUST *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_INT8_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_CLOCK_COARSE_SLOWER:
	  case TPM_CLOCK_MEDIUM_SLOWER:
	  case TPM_CLOCK_FINE_SLOWER:
	  case TPM_CLOCK_NO_CHANGE:
	  case TPM_CLOCK_FINE_FASTER:
	  case TPM_CLOCK_MEDIUM_FASTER:
	  case TPM_CLOCK_COARSE_FASTER:
	    break;
	  default:
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* Table 19 - Definition of (UINT16) TPM_EO Constants <IN/OUT> */

TPM_RC
TSS_TPM_EO_Unmarshalu(TPM_EO *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_EO_EQ:
	  case TPM_EO_NEQ:
	  case TPM_EO_SIGNED_GT:
	  case TPM_EO_UNSIGNED_GT:
	  case TPM_EO_SIGNED_LT:
	  case TPM_EO_UNSIGNED_LT:
	  case TPM_EO_SIGNED_GE:
	  case TPM_EO_UNSIGNED_GE:
	  case TPM_EO_SIGNED_LE:
	  case TPM_EO_UNSIGNED_LE:
	  case TPM_EO_BITSET:
	  case TPM_EO_BITCLEAR:
	    break;
	  default:
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 20 - Definition of (UINT16) TPM_ST Constants <IN/OUT, S> */

TPM_RC
TSS_TPM_ST_Unmarshalu(TPM_ST *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

#ifndef TPM_TSS_NOCMDCHECK
/* Table 21 - Definition of (UINT16) TPM_SU Constants <IN> */

TPM_RC
TSS_TPM_SU_Unmarshalu(TPM_SU *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_SU_CLEAR:
	  case TPM_SU_STATE:
	    break;
	  default:
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 22 - Definition of (UINT8) TPM_SE Constants <IN> */

TPM_RC
TSS_TPM_SE_Unmarshalu(TPM_SE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT8_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_SE_HMAC:
	  case TPM_SE_POLICY:
	  case TPM_SE_TRIAL:
	    break;
	  default:
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* Table 23 - Definition of (UINT32) TPM_CAP Constants  */

TPM_RC
TSS_TPM_CAP_Unmarshalu(TPM_CAP *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 24 - Definition of (UINT32) TPM_PT Constants <IN/OUT, S> */

TPM_RC
TSS_TPM_PT_Unmarshalu(TPM_HANDLE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 25 - Definition of (UINT32) TPM_PT_PCR Constants <IN/OUT, S> */

TPM_RC
TSS_TPM_PT_PCR_Unmarshalu(TPM_PT_PCR *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 27 - Definition of Types for Handles */

TPM_RC
TSS_TPM_HANDLE_Unmarshalu(TPM_HANDLE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 31 - Definition of (UINT32) TPMA_ALGORITHM Bits */

TPM_RC
TSS_TPMA_ALGORITHM_Unmarshalu(TPMA_ALGORITHM *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->val, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->val & TPMA_ALGORITHM_RESERVED) {
	    rc = TPM_RC_RESERVED_BITS;
	}
    }
    return rc;
}

/* Table 32 - Definition of (UINT32) TPMA_OBJECT Bits */

TPM_RC
TSS_TPMA_OBJECT_Unmarshalu(TPMA_OBJECT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->val, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->val & TPMA_OBJECT_RESERVED) {
	    rc = TPM_RC_RESERVED_BITS;
	}
    }
    return rc;
}

/* Table 33 - Definition of (UINT8) TPMA_SESSION Bits <IN/OUT> */

TPM_RC
TSS_TPMA_SESSION_Unmarshalu(TPMA_SESSION *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT8_Unmarshalu(&target->val, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->val & TPMA_SESSION_RESERVED) {
	    rc = TPM_RC_RESERVED_BITS;
	}
    }
    return rc;
}

/* Table 34 - Definition of (UINT8) TPMA_LOCALITY Bits <IN/OUT> */

TPM_RC
TSS_TPMA_LOCALITY_Unmarshalu(TPMA_LOCALITY *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT8_Unmarshalu(&target->val, buffer, size);  
    }
    return rc;
}

/* Table 38 - Definition of (TPM_CC) TPMA_CC Bits <OUT> */

TPM_RC
TSS_TPMA_CC_Unmarshalu(TPMA_CC *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->val, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->val & TPMA_CC_RESERVED) {
	    rc = TPM_RC_RESERVED_BITS;
	}
    }
    return rc;
}

/* Table 39 - Definition of (BYTE) TPMI_YES_NO Type */

TPM_RC
TSS_TPMI_YES_NO_Unmarshalu(TPMI_YES_NO *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT8_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 40 - Definition of (TPM_HANDLE) TPMI_DH_OBJECT Type */

TPM_RC
TSS_TPMI_DH_OBJECT_Unmarshalu(TPMI_DH_OBJECT *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	BOOL isNotTransient = (*target < TRANSIENT_FIRST) || (*target > TRANSIENT_LAST);
	BOOL isNotPersistent = (*target < PERSISTENT_FIRST) || (*target > PERSISTENT_LAST);
	BOOL isNotLegalNull = (*target != TPM_RH_NULL) || !allowNull;
	if (isNotTransient &&
	    isNotPersistent &&
	    isNotLegalNull) {
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}
/* Table 41 - Definition of (TPM_HANDLE) TPMI_DH_PERSISTENT Type */

#ifndef TPM_TSS_NOCMDCHECK
TPM_RC
TSS_TPMI_DH_PERSISTENT_Unmarshalu(TPMI_DH_PERSISTENT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	BOOL isNotPersistent = (*target < PERSISTENT_FIRST) || (*target > PERSISTENT_LAST);
	if (isNotPersistent) {
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}
#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 42 - Definition of (TPM_HANDLE) TPMI_DH_ENTITY Type <IN> */

TPM_RC
TSS_TPMI_DH_ENTITY_Unmarshalu(TPMI_DH_ENTITY *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	BOOL isNotOwner = *target != TPM_RH_OWNER;
	BOOL isNotEndorsement = *target != TPM_RH_ENDORSEMENT;
	BOOL isNotPlatform = *target != TPM_RH_PLATFORM;
	BOOL isNotLockout = *target != TPM_RH_LOCKOUT;
	BOOL isNotTransient = (*target < TRANSIENT_FIRST) || (*target > TRANSIENT_LAST);
	BOOL isNotPersistent = (*target < PERSISTENT_FIRST) || (*target > PERSISTENT_LAST);
	BOOL isNotNv = (*target < NV_INDEX_FIRST) || (*target > NV_INDEX_LAST);
	BOOL isNotPcr = (*target > PCR_LAST);
	BOOL isNotAuth = (*target < TPM_RH_AUTH_00) || (*target > TPM_RH_AUTH_FF);
	BOOL isNotLegalNull = (*target != TPM_RH_NULL) || !allowNull;
	if (isNotOwner &&
	    isNotEndorsement &&
	    isNotPlatform &&
	    isNotLockout &&
	    isNotTransient &&
	    isNotPersistent &&
	    isNotNv &&
	    isNotPcr &&
	    isNotAuth &&
	    isNotLegalNull) {
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* Table 43 - Definition of (TPM_HANDLE) TPMI_DH_PCR Type <IN> */

#ifndef TPM_TSS_NOCMDCHECK
TPM_RC
TSS_TPMI_DH_PCR_Unmarshalu(TPMI_DH_PCR *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	BOOL isNotPcr = (*target > PCR_LAST);
	BOOL isNotLegalNull = (*target != TPM_RH_NULL) || !allowNull;
	if (isNotPcr &&
	    isNotLegalNull) {
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}
#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 44 - Definition of (TPM_HANDLE) TPMI_SH_AUTH_SESSION Type <IN/OUT> */

TPM_RC
TSS_TPMI_SH_AUTH_SESSION_Unmarshalu(TPMI_SH_AUTH_SESSION *target, BYTE **buffer, uint32_t *size, BOOL allowPwd)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	BOOL isNotHmacSession = (*target < HMAC_SESSION_FIRST ) || (*target > HMAC_SESSION_LAST);
	BOOL isNotPolicySession = (*target < POLICY_SESSION_FIRST) || (*target > POLICY_SESSION_LAST);
	BOOL isNotLegalPwd = (*target != TPM_RS_PW) || !allowPwd;
	if (isNotHmacSession &&
	    isNotPolicySession &&
	    isNotLegalPwd) {
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* Table 45 - Definition of (TPM_HANDLE) TPMI_SH_HMAC Type <IN/OUT> */

#ifndef TPM_TSS_NOCMDCHECK
TPM_RC
TSS_TPMI_SH_HMAC_Unmarshalu(TPMI_SH_HMAC *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	BOOL isNotHmacSession = (*target < HMAC_SESSION_FIRST ) || (*target > HMAC_SESSION_LAST);
	if (isNotHmacSession) {
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* Table 46 - Definition of (TPM_HANDLE) TPMI_SH_POLICY Type <IN/OUT> */

TPM_RC
TSS_TPMI_SH_POLICY_Unmarshalu(TPMI_SH_POLICY *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	BOOL isNotPolicySession = (*target < POLICY_SESSION_FIRST) || (*target > POLICY_SESSION_LAST);
	if (isNotPolicySession) {
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}
#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 47 - Definition of (TPM_HANDLE) TPMI_DH_CONTEXT Type  */

TPM_RC
TSS_TPMI_DH_CONTEXT_Unmarshalu(TPMI_DH_CONTEXT *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	BOOL isNotHmacSession = (*target < HMAC_SESSION_FIRST ) || (*target > HMAC_SESSION_LAST);
	BOOL isNotPolicySession = (*target < POLICY_SESSION_FIRST) || (*target > POLICY_SESSION_LAST);
	BOOL isNotTransient = (*target < TRANSIENT_FIRST) || (*target > TRANSIENT_LAST);
	if (isNotHmacSession &&
	    isNotPolicySession &&
	    isNotTransient) {
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* Table 49 - Definition of (TPM_HANDLE) TPMI_DH_SAVED Type  */

TPM_RC
TSS_TPMI_DH_SAVED_Unmarshalu(TPMI_DH_SAVED *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	BOOL isNotHmacSession = (*target < HMAC_SESSION_FIRST ) || (*target > HMAC_SESSION_LAST);
	BOOL isNotPolicySession = (*target < POLICY_SESSION_FIRST) || (*target > POLICY_SESSION_LAST);
	BOOL isNotTransient = (*target != 0x80000000);
	BOOL isNotSequence = (*target != 0x80000001);
	BOOL isNotTransientStClear = (*target != 0x80000002);

	if (isNotHmacSession &&
	    isNotPolicySession &&
	    isNotTransient && 
	    isNotSequence &&
	    isNotTransientStClear) {
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* Table 48 - Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY Type  */

TPM_RC
TSS_TPMI_RH_HIERARCHY_Unmarshalu(TPMI_RH_HIERARCHY *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_RH_OWNER:
	  case TPM_RH_PLATFORM:
	  case TPM_RH_ENDORSEMENT:
	    break;
	  case TPM_RH_NULL:
	    if (!allowNull) {
		rc = TPM_RC_VALUE;
	    }
	    break;
	  default:
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}
/* Table 49 - Definition of (TPM_HANDLE) TPMI_RH_ENABLES Type */

#ifndef TPM_TSS_NOCMDCHECK
TPM_RC
TSS_TPMI_RH_ENABLES_Unmarshalu(TPMI_RH_ENABLES *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_RH_OWNER:
	  case TPM_RH_PLATFORM:
	  case TPM_RH_ENDORSEMENT:
	  case TPM_RH_PLATFORM_NV:
	    break;
	  case TPM_RH_NULL:
	    if (!allowNull) {
		rc = TPM_RC_VALUE;
	    }
	    break;
	  default:
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* Table 50 - Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY_AUTH Type <IN> */

TPM_RC
TSS_TPMI_RH_HIERARCHY_AUTH_Unmarshalu(TPMI_RH_HIERARCHY_AUTH *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_RH_OWNER:
	  case TPM_RH_PLATFORM:
	  case TPM_RH_ENDORSEMENT:
	  case TPM_RH_LOCKOUT:
	    break;
	  default:
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* Table 51 - Definition of (TPM_HANDLE) TPMI_RH_PLATFORM Type <IN> */

TPM_RC
TSS_TPMI_RH_PLATFORM_Unmarshalu(TPMI_RH_PLATFORM *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_RH_PLATFORM:
	    break;
	  default:
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* Table 53 - Definition of (TPM_HANDLE) TPMI_RH_ENDORSEMENT Type <IN> */

TPM_RC
TSS_TPMI_RH_ENDORSEMENT_Unmarshalu(TPMI_RH_ENDORSEMENT *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_RH_ENDORSEMENT:
	    break;
	  case TPM_RH_NULL:
	    if (!allowNull) {
		rc = TPM_RC_VALUE;
	    }
	    break;
	  default:
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* Table 54 - Definition of (TPM_HANDLE) TPMI_RH_PROVISION Type <IN> */

TPM_RC
TSS_TPMI_RH_PROVISION_Unmarshalu(TPMI_RH_PROVISION *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_RH_OWNER:
	  case TPM_RH_PLATFORM:
	    break;
	  default:
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* Table 55 - Definition of (TPM_HANDLE) TPMI_RH_CLEAR Type <IN> */

TPM_RC
TSS_TPMI_RH_CLEAR_Unmarshalu(TPMI_RH_CLEAR *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_RH_LOCKOUT:
	  case TPM_RH_PLATFORM:
	    break;
	  default:
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* Table 56 - Definition of (TPM_HANDLE) TPMI_RH_NV_AUTH Type <IN> */

TPM_RC
TSS_TPMI_RH_NV_AUTH_Unmarshalu(TPMI_RH_NV_AUTH *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_RH_OWNER:
	  case TPM_RH_PLATFORM:
	    break;
	  default:
	      {
		  BOOL isNotNv = (*target < NV_INDEX_FIRST) || (*target > NV_INDEX_LAST);
		  if (isNotNv) {
		      rc = TPM_RC_VALUE;
		  }
	      }
	}
    }
    return rc;
}

/* Table 57 - Definition of (TPM_HANDLE) TPMI_RH_LOCKOUT Type <IN> */

TPM_RC
TSS_TPMI_RH_LOCKOUT_Unmarshalu(TPMI_RH_LOCKOUT *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_RH_LOCKOUT:
	    break;
	  default:
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}
#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 58 - Definition of (TPM_HANDLE) TPMI_RH_NV_INDEX Type <IN/OUT> */

TPM_RC
TSS_TPMI_RH_NV_INDEX_Unmarshalu(TPMI_RH_NV_INDEX *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	BOOL isNotNv = (*target < NV_INDEX_FIRST) || (*target > NV_INDEX_LAST);
	if (isNotNv) {
	    rc = TPM_RC_VALUE;
	}
    }
    return rc;
}

/* Table 59 - Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type  */

TPM_RC
TSS_TPMI_ALG_HASH_Unmarshalu(TPMI_ALG_HASH *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 61 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM Type */

TPM_RC
TSS_TPMI_ALG_SYM_Unmarshalu(TPMI_ALG_SYM *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 62 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_OBJECT Type */

TPM_RC
TSS_TPMI_ALG_SYM_OBJECT_Unmarshalu(TPMI_ALG_SYM_OBJECT *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 63 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_MODE Type */

TPM_RC
TSS_TPMI_ALG_SYM_MODE_Unmarshalu(TPMI_ALG_SYM_MODE *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 64 - Definition of (TPM_ALG_ID) TPMI_ALG_KDF Type */

TPM_RC
TSS_TPMI_ALG_KDF_Unmarshalu(TPMI_ALG_KDF *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;
   
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 65 - Definition of (TPM_ALG_ID) TPMI_ALG_SIG_SCHEME Type */

TPM_RC
TSS_TPMI_ALG_SIG_SCHEME_Unmarshalu(TPMI_ALG_SIG_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

#ifndef TPM_TSS_NOCMDCHECK

/* Table 66 - Definition of (TPM_ALG_ID) TPMI_ECC_KEY_EXCHANGE Type */

TPM_RC
TSS_TPMI_ECC_KEY_EXCHANGE_Unmarshalu(TPMI_ECC_KEY_EXCHANGE *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 67 - Definition of (TPM_ST) TPMI_ST_COMMAND_TAG Type */

TPM_RC
TSS_TPMI_ST_COMMAND_TAG_Unmarshalu(TPMI_ST_COMMAND_TAG *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ST_Unmarshalu(target, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	switch (*target) {
	  case TPM_ST_NO_SESSIONS:
	  case TPM_ST_SESSIONS:
	    break;
	  default:
	    rc = TPM_RC_BAD_TAG;
	}
    }
    return rc;
}

/* Table 70 TPMI_ALG_MAC_SCHEME */

TPM_RC
TSS_TPMI_ALG_MAC_SCHEME_Unmarshalu(TPMI_ALG_MAC_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(target, buffer, size);  
    }
    return rc;
}
    
/* Table 70 TPMI_ALG_CIPHER_MODE */

TPM_RC
TSS_TPMI_ALG_CIPHER_MODE_Unmarshalu(TPMI_ALG_CIPHER_MODE*target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 68 - Definition of TPMS_EMPTY Structure <IN/OUT> */

/* NOTE: Marked as const function in header */

TPM_RC
TSS_TPMS_EMPTY_Unmarshalu(TPMS_EMPTY *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    target = target;
    buffer = buffer;
    size = size;
    return rc;
}

/* Table 70 - Definition of TPMU_HA Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_HA_Unmarshalu(TPMU_HA *target, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    switch (selector) {
#ifdef TPM_ALG_SHA1
      case TPM_ALG_SHA1:
	rc = TSS_Array_Unmarshalu(target->sha1, SHA1_DIGEST_SIZE, buffer, size);
	break;
#endif
#ifdef TPM_ALG_SHA256
      case TPM_ALG_SHA256:
	rc = TSS_Array_Unmarshalu(target->sha256, SHA256_DIGEST_SIZE, buffer, size);
	break;
#endif
#ifdef TPM_ALG_SHA384
      case TPM_ALG_SHA384:
	rc =TSS_Array_Unmarshalu(target->sha384, SHA384_DIGEST_SIZE, buffer, size);
	break;
#endif
#ifdef TPM_ALG_SHA512
      case TPM_ALG_SHA512:
	rc = TSS_Array_Unmarshalu(target->sha512, SHA512_DIGEST_SIZE, buffer, size);
	break;
#endif
#ifdef TPM_ALG_SM3_256
      case TPM_ALG_SM3_256:
	rc = TSS_Array_Unmarshalu(target->sm3_256, SM3_256_DIGEST_SIZE, buffer, size);
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
TSS_TPMT_HA_Unmarshalu(TPMT_HA *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->hashAlg, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_HA_Unmarshalu(&target->digest, buffer, size, target->hashAlg);
    }
    return rc;
}

/* Table 72 - Definition of TPM2B_DIGEST Structure */

TPM_RC
TSS_TPM2B_DIGEST_Unmarshalu(TPM2B_DIGEST *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}

/* Table 73 - Definition of TPM2B_DATA Structure */

TPM_RC
TSS_TPM2B_DATA_Unmarshalu(TPM2B_DATA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}

/* Table 74 - Definition of Types for TPM2B_NONCE */

TPM_RC
TSS_TPM2B_NONCE_Unmarshalu(TPM2B_NONCE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/* Table 75 - Definition of Types for TPM2B_AUTH */

TPM_RC
TSS_TPM2B_AUTH_Unmarshalu(TPM2B_AUTH *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(target, buffer, size);
    }
    return rc;
}

#ifndef TPM_TSS_NOCMDCHECK

/* Table 76 - Definition of Types for TPM2B_OPERAND */

TPM_RC
TSS_TPM2B_OPERAND_Unmarshalu(TPM2B_OPERAND *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/* Table 77 - Definition of TPM2B_EVENT Structure */

TPM_RC
TSS_TPM2B_EVENT_Unmarshalu(TPM2B_EVENT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}
 
#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 78 - Definition of TPM2B_MAX_BUFFER Structure */

TPM_RC
TSS_TPM2B_MAX_BUFFER_Unmarshalu(TPM2B_MAX_BUFFER *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}

/* Table 79 - Definition of TPM2B_MAX_NV_BUFFER Structure */

TPM_RC
TSS_TPM2B_MAX_NV_BUFFER_Unmarshalu(TPM2B_MAX_NV_BUFFER *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}

/* Table 80 - Definition of TPM2B_TIMEOUT Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_TIMEOUT_Unmarshalu(TPM2B_TIMEOUT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/* Table 81 - Definition of TPM2B_IV Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_IV_Unmarshalu(TPM2B_IV *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}

/* Table 83 - Definition of TPM2B_NAME Structure */

TPM_RC
TSS_TPM2B_NAME_Unmarshalu(TPM2B_NAME *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.name), buffer, size);
    }
    return rc;
}

/* Table 85 - Definition of TPMS_PCR_SELECTION Structure */

TPM_RC
TSS_TPMS_PCR_SELECTION_Unmarshalu(TPMS_PCR_SELECTION *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->hash, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT8_Unmarshalu(&target->sizeofSelect, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->sizeofSelect > PCR_SELECT_MAX) {
	    rc = TPM_RC_VALUE;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_Array_Unmarshalu(target->pcrSelect, target->sizeofSelect, buffer, size);
    }
    return rc;
}

/* Table 88 - Definition of TPMT_TK_CREATION Structure */

TPM_RC
TSS_TPMT_TK_CREATION_Unmarshalu(TPMT_TK_CREATION *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ST_Unmarshalu(&target->tag, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->tag != TPM_ST_CREATION) {
	    rc = TPM_RC_TAG;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_RH_HIERARCHY_Unmarshalu(&target->hierarchy, buffer, size, YES);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->digest, buffer, size);
    }
    return rc;
}

/* Table 89 - Definition of TPMT_TK_VERIFIED Structure */

TPM_RC
TSS_TPMT_TK_VERIFIED_Unmarshalu(TPMT_TK_VERIFIED *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ST_Unmarshalu(&target->tag, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->tag != TPM_ST_VERIFIED) {
	    rc = TPM_RC_TAG;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_RH_HIERARCHY_Unmarshalu(&target->hierarchy, buffer, size, YES);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->digest, buffer, size);
    }
    return rc;
}

/* Table 90 - Definition of TPMT_TK_AUTH Structure */

TPM_RC
TSS_TPMT_TK_AUTH_Unmarshalu(TPMT_TK_AUTH *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ST_Unmarshalu(&target->tag, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if ((target->tag != TPM_ST_AUTH_SIGNED) &&
	    (target->tag != TPM_ST_AUTH_SECRET)) {
	    rc = TPM_RC_TAG;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_RH_HIERARCHY_Unmarshalu(&target->hierarchy, buffer, size, YES);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->digest, buffer, size);
    }
    return rc;
}

/* Table 91 - Definition of TPMT_TK_HASHCHECK Structure */

TPM_RC
TSS_TPMT_TK_HASHCHECK_Unmarshalu(TPMT_TK_HASHCHECK *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ST_Unmarshalu(&target->tag, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->tag != TPM_ST_HASHCHECK) {
	    rc = TPM_RC_TAG;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_RH_HIERARCHY_Unmarshalu(&target->hierarchy, buffer, size, YES);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->digest, buffer, size);
    }
    return rc;
}

/* Table 92 - Definition of TPMS_ALG_PROPERTY Structure <OUT> */

TPM_RC
TSS_TPMS_ALG_PROPERTY_Unmarshalu(TPMS_ALG_PROPERTY *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(&target->alg, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMA_ALGORITHM_Unmarshalu(&target->algProperties, buffer, size);
    }
    return rc;
}

/* Table 93 - Definition of TPMS_TAGGED_PROPERTY Structure <OUT> */

TPM_RC
TSS_TPMS_TAGGED_PROPERTY_Unmarshalu(TPMS_TAGGED_PROPERTY *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_PT_Unmarshalu(&target->property, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->value, buffer, size);
    }
    return rc;
}

/* Table 94 - Definition of TPMS_TAGGED_PCR_SELECT Structure <OUT> */

TPM_RC
TSS_TPMS_TAGGED_PCR_SELECT_Unmarshalu(TPMS_TAGGED_PCR_SELECT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_PT_PCR_Unmarshalu(&target->tag, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT8_Unmarshalu(&target->sizeofSelect, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_Array_Unmarshalu(target->pcrSelect, target->sizeofSelect, buffer, size);
    }
    return rc;
}

/* Table 100 - Definition of TPMS_TAGGED_POLICY Structure <OUT> */

TPM_RC
TSS_TPMS_TAGGED_POLICY_Unmarshalu(TPMS_TAGGED_POLICY *target, BYTE **buffer, uint32_t *size) 
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_HANDLE_Unmarshalu(&target->handle, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_HA_Unmarshalu(&target->policyHash, buffer, size, YES);
    }
    return rc;
}

/* Table 95 - Definition of TPML_CC Structure */

TPM_RC
TSS_TPML_CC_Unmarshalu(TPML_CC *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    uint32_t i;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->count, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count > MAX_CAP_CC) {
	    rc = TPM_RC_SIZE;
	}
    }
    for (i = 0 ; (rc == TPM_RC_SUCCESS) && (i < target->count) ; i++) {
	rc = TSS_TPM_CC_Unmarshalu(&target->commandCodes[i], buffer, size);
    }
    return rc;
}

/* Table 96 - Definition of TPML_CCA Structure <OUT> */

TPM_RC
TSS_TPML_CCA_Unmarshalu(TPML_CCA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    uint32_t i;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->count, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count > MAX_CAP_CC) {
	    rc = TPM_RC_SIZE;
	}
    }
    for (i = 0 ; (rc == TPM_RC_SUCCESS) && (i < target->count) ; i++) {
	rc = TSS_TPMA_CC_Unmarshalu(&target->commandAttributes[i], buffer, size);
    }
    return rc;
}

/* Table 97 - Definition of TPML_ALG Structure */

TPM_RC
TSS_TPML_ALG_Unmarshalu(TPML_ALG *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    uint32_t i;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->count, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count > MAX_ALG_LIST_SIZE) {
	    rc = TPM_RC_SIZE;
	}
    }
    for (i = 0 ; (rc == TPM_RC_SUCCESS) && (i < target->count) ; i++) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(&target->algorithms[i], buffer, size);
    }
    return rc;
}

/* Table 98 - Definition of TPML_HANDLE Structure <OUT> */

TPM_RC
TSS_TPML_HANDLE_Unmarshalu(TPML_HANDLE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    uint32_t i;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->count, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count > MAX_CAP_HANDLES) {
	    rc = TPM_RC_SIZE;
	}
    }
    for (i = 0 ; (rc == TPM_RC_SUCCESS) && (i < target->count) ; i++) {
	rc = TSS_TPM_HANDLE_Unmarshalu(&target->handle[i], buffer, size);
    }
    return rc;
}

/* Table 99 - Definition of TPML_DIGEST Structure */

/* PolicyOr has a restriction of at least a count of two.  This function is also used to unmarshal
   PCR_Read, where a count of one is permitted.
*/

TPM_RC
TSS_TPML_DIGEST_Unmarshalu(TPML_DIGEST *target, BYTE **buffer, uint32_t *size, uint32_t minCount)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    uint32_t i;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->count, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count < minCount) {
	    rc = TPM_RC_SIZE;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count > 8) {
	    rc = TPM_RC_SIZE;
	}
    }
    for (i = 0 ; (rc == TPM_RC_SUCCESS) && (i < target->count) ; i++) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->digests[i], buffer, size);
    }
    return rc;
}

/* Table 100 - Definition of TPML_DIGEST_VALUES Structure */

TPM_RC
TSS_TPML_DIGEST_VALUES_Unmarshalu(TPML_DIGEST_VALUES *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    uint32_t i;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->count, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count > HASH_COUNT) {
	    rc = TPM_RC_SIZE;
	}
    }
    for (i = 0 ; (rc == TPM_RC_SUCCESS) && (i < target->count) ; i++) {
	rc = TSS_TPMT_HA_Unmarshalu(&target->digests[i], buffer, size, NO);
    }
    return rc;
}

/* Table 102 - Definition of TPML_PCR_SELECTION Structure */

TPM_RC
TSS_TPML_PCR_SELECTION_Unmarshalu(TPML_PCR_SELECTION *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    uint32_t i;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->count, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count > HASH_COUNT) {
	    rc = TPM_RC_SIZE;
	}
    }
    for (i = 0 ; (rc == TPM_RC_SUCCESS) && (i < target->count) ; i++) {
	rc = TSS_TPMS_PCR_SELECTION_Unmarshalu(&target->pcrSelections[i], buffer, size);
    }
    return rc;
}

/* Table 103 - Definition of TPML_ALG_PROPERTY Structure <OUT> */

TPM_RC
TSS_TPML_ALG_PROPERTY_Unmarshalu(TPML_ALG_PROPERTY *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    uint32_t i;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->count, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count > MAX_CAP_ALGS) {
	    rc = TPM_RC_SIZE;
	}
    }
    for (i = 0 ; (rc == TPM_RC_SUCCESS) && (i < target->count) ; i++) {
	rc = TSS_TPMS_ALG_PROPERTY_Unmarshalu(&target->algProperties[i], buffer, size);
    }
    return rc;
}

/* Table 104 - Definition of TPML_TAGGED_TPM_PROPERTY Structure <OUT> */

TPM_RC
TSS_TPML_TAGGED_TPM_PROPERTY_Unmarshalu(TPML_TAGGED_TPM_PROPERTY  *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    uint32_t i;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->count, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count > MAX_TPM_PROPERTIES) {
	    rc = TPM_RC_SIZE;
	}
    }
    for (i = 0 ; (rc == TPM_RC_SUCCESS) && (i < target->count) ; i++) {
	rc = TSS_TPMS_TAGGED_PROPERTY_Unmarshalu(&target->tpmProperty[i], buffer, size);
    }
    return rc;
}

/* Table 105 - Definition of TPML_TAGGED_PCR_PROPERTY Structure <OUT> */

TPM_RC
TSS_TPML_TAGGED_PCR_PROPERTY_Unmarshalu(TPML_TAGGED_PCR_PROPERTY *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    uint32_t i;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->count, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count > MAX_PCR_PROPERTIES) {
	    rc = TPM_RC_SIZE;
	}
    }
    for (i = 0 ; (rc == TPM_RC_SUCCESS) && (i < target->count) ; i++) {
	rc = TSS_TPMS_TAGGED_PCR_SELECT_Unmarshalu(&target->pcrProperty[i], buffer, size);
    }
    return rc;
}

/* Table 106 - Definition of {ECC} TPML_ECC_CURVE Structure <OUT> */

TPM_RC
TSS_TPML_ECC_CURVE_Unmarshalu(TPML_ECC_CURVE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    uint32_t i;
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->count, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count > MAX_ECC_CURVES) {
	    rc = TPM_RC_SIZE;
	}
    }
    for (i = 0 ; (rc == TPM_RC_SUCCESS) && (i < target->count) ; i++) {
	rc = TSS_TPM_ECC_CURVE_Unmarshalu(&target->eccCurves[i], buffer, size);
    }
    return rc;	
}

/* Table 112 - Definition of TPML_TAGGED_POLICY Structure <OUT> */

TPM_RC
TSS_TPML_TAGGED_POLICY_Unmarshalu(TPML_TAGGED_POLICY *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    uint32_t i;  
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->count, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count > MAX_TAGGED_POLICIES) {
	    rc = TPM_RC_SIZE;
	}
    }
    for (i = 0 ; (rc == TPM_RC_SUCCESS) && (i < target->count) ; i++) {
	rc = TSS_TPMS_TAGGED_POLICY_Unmarshalu(&target->policies[i], buffer, size);
    }
    return rc;	
}

/* Table 107 - Definition of TPMU_CAPABILITIES Union <OUT> */

TPM_RC
TSS_TPMU_CAPABILITIES_Unmarshalu(TPMU_CAPABILITIES *target, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    switch (selector) {
      case TPM_CAP_ALGS:
	rc = TSS_TPML_ALG_PROPERTY_Unmarshalu(&target->algorithms, buffer, size);
	break;
      case TPM_CAP_HANDLES:
	rc = TSS_TPML_HANDLE_Unmarshalu(&target->handles, buffer, size);
	break;
      case TPM_CAP_COMMANDS:
	rc = TSS_TPML_CCA_Unmarshalu(&target->command, buffer, size);
	break;
      case TPM_CAP_PP_COMMANDS:
	rc = TSS_TPML_CC_Unmarshalu(&target->ppCommands, buffer, size);
	break;
      case TPM_CAP_AUDIT_COMMANDS:
	rc = TSS_TPML_CC_Unmarshalu(&target->auditCommands, buffer, size);
	break;
      case TPM_CAP_PCRS:
	rc = TSS_TPML_PCR_SELECTION_Unmarshalu(&target->assignedPCR, buffer, size);
	break;
      case TPM_CAP_TPM_PROPERTIES:
	rc = TSS_TPML_TAGGED_TPM_PROPERTY_Unmarshalu(&target->tpmProperties, buffer, size);
	break;
      case TPM_CAP_PCR_PROPERTIES:
	rc = TSS_TPML_TAGGED_PCR_PROPERTY_Unmarshalu(&target->pcrProperties, buffer, size);
	break;
      case TPM_CAP_ECC_CURVES:
	rc = TSS_TPML_ECC_CURVE_Unmarshalu(&target->eccCurves, buffer, size);
	break;
      case TPM_CAP_AUTH_POLICIES:
	rc = TSS_TPML_TAGGED_POLICY_Unmarshalu(&target->authPolicies, buffer, size);
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 108 - Definition of TPMS_CAPABILITY_DATA Structure <OUT> */

TPM_RC
TSS_TPMS_CAPABILITY_DATA_Unmarshalu(TPMS_CAPABILITY_DATA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
  
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_CAP_Unmarshalu(&target->capability, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_CAPABILITIES_Unmarshalu(&target->data, buffer, size, target->capability);
    }
    return rc;
}

/* Table 109 - Definition of TPMS_CLOCK_INFO Structure */

TPM_RC
TSS_TPMS_CLOCK_INFO_Unmarshalu(TPMS_CLOCK_INFO *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT64_Unmarshalu(&target->clock, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->resetCount, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->restartCount, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_YES_NO_Unmarshalu(&target->safe, buffer, size);
    }
    return rc;
}

/* Table 110 - Definition of TPMS_TIME_INFO Structure */

TPM_RC
TSS_TPMS_TIME_INFO_Unmarshalu(TPMS_TIME_INFO *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT64_Unmarshalu(&target->time, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_CLOCK_INFO_Unmarshalu(&target->clockInfo, buffer, size);
    }
    return rc;
}

#ifndef TPM_TSS_NOCMDCHECK

/* Table 111 - Definition of TPMS_TIME_ATTEST_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_TIME_ATTEST_INFO_Unmarshalu(TPMS_TIME_ATTEST_INFO *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_TIME_INFO_Unmarshalu(&target->time, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT64_Unmarshalu(&target->firmwareVersion, buffer, size);
    }
    return rc;
}

/* Table 112 - Definition of TPMS_CERTIFY_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_CERTIFY_INFO_Unmarshalu(TPMS_CERTIFY_INFO *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->name, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->qualifiedName, buffer, size);
    }
    return rc;
}

/* Table 113 - Definition of TPMS_QUOTE_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_QUOTE_INFO_Unmarshalu(TPMS_QUOTE_INFO *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_PCR_SELECTION_Unmarshalu(&target->pcrSelect, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->pcrDigest, buffer, size);
    }
    return rc;
}

/* Table 114 - Definition of TPMS_COMMAND_AUDIT_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_COMMAND_AUDIT_INFO_Unmarshalu(TPMS_COMMAND_AUDIT_INFO *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT64_Unmarshalu(&target->auditCounter, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(&target->digestAlg, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->auditDigest, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->commandDigest, buffer, size);
    }
    return rc;
}

/* Table 115 - Definition of TPMS_SESSION_AUDIT_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_SESSION_AUDIT_INFO_Unmarshalu(TPMS_SESSION_AUDIT_INFO *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_YES_NO_Unmarshalu(&target->exclusiveSession, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->sessionDigest, buffer, size);
    }
    return rc;
}

/* Table 116 - Definition of TPMS_CREATION_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_CREATION_INFO_Unmarshalu(TPMS_CREATION_INFO *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->objectName, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->creationHash, buffer, size);
    }
    return rc;
}

/* Table 117 - Definition of TPMS_NV_CERTIFY_INFO Structure <OUT> */

TPM_RC
TSS_TPMS_NV_CERTIFY_INFO_Unmarshalu(TPMS_NV_CERTIFY_INFO *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->indexName, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->offset, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_MAX_NV_BUFFER_Unmarshalu(&target->nvContents, buffer, size);
    }
    return rc;
}

/* Table 125 - Definition of TPMS_NV_DIGEST_CERTIFY_INFO Structure <OUT> */
TPM_RC
TSS_TPMS_NV_DIGEST_CERTIFY_INFO_Unmarshalu(TPMS_NV_DIGEST_CERTIFY_INFO *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->indexName, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->nvDigest, buffer, size);
    }
    return rc;
}

/* Table 118 - Definition of (TPM_ST) TPMI_ST_ATTEST Type <OUT> */

TPM_RC
TSS_TPMI_ST_ATTEST_Unmarshalu(TPMI_ST_ATTEST *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ST_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/*  Table 119 - Definition of TPMU_ATTEST Union <OUT> */

TPM_RC
TSS_TPMU_ATTEST_Unmarshalu(TPMU_ATTEST *target, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    switch (selector) {
      case TPM_ST_ATTEST_CERTIFY:
	rc = TSS_TPMS_CERTIFY_INFO_Unmarshalu(&target->certify, buffer, size);
	break;
      case TPM_ST_ATTEST_CREATION:
	rc = TSS_TPMS_CREATION_INFO_Unmarshalu(&target->creation, buffer, size);
	break;
      case TPM_ST_ATTEST_QUOTE:
	rc = TSS_TPMS_QUOTE_INFO_Unmarshalu(&target->quote, buffer, size);
	break;
      case TPM_ST_ATTEST_COMMAND_AUDIT:
	rc = TSS_TPMS_COMMAND_AUDIT_INFO_Unmarshalu(&target->commandAudit, buffer, size);
	break;
      case TPM_ST_ATTEST_SESSION_AUDIT:
	rc = TSS_TPMS_SESSION_AUDIT_INFO_Unmarshalu(&target->sessionAudit, buffer, size);
	break;
      case TPM_ST_ATTEST_TIME:
	rc = TSS_TPMS_TIME_ATTEST_INFO_Unmarshalu(&target->time, buffer, size);
	break;
      case TPM_ST_ATTEST_NV:
	rc = TSS_TPMS_NV_CERTIFY_INFO_Unmarshalu(&target->nv, buffer, size);
	break;
      case TPM_ST_ATTEST_NV_DIGEST:
	rc = TSS_TPMS_NV_DIGEST_CERTIFY_INFO_Unmarshalu(&target->nvDigest, buffer, size);
	break;
      default:
	rc = TPM_RC_SELECTOR;
	
    }
    return rc;
}

/* Table 120 - Definition of TPMS_ATTEST Structure <OUT> */

TPM_RC
TSS_TPMS_ATTEST_Unmarshalu(TPMS_ATTEST *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_GENERATED_Unmarshalu(&target->magic, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ST_ATTEST_Unmarshalu(&target->type, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->qualifiedSigner, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->extraData, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_CLOCK_INFO_Unmarshalu(&target->clockInfo, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT64_Unmarshalu(&target->firmwareVersion, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_ATTEST_Unmarshalu(&target->attested, buffer, size, target->type);
    }
    return rc;
}

#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 121 - Definition of TPM2B_ATTEST Structure <OUT> */

TPM_RC
TSS_TPM2B_ATTEST_Unmarshalu(TPM2B_ATTEST *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.attestationData), buffer, size);
    }
    return rc;
}

/* Table 123 - Definition of TPMS_AUTH_RESPONSE Structure <OUT> */

TPM_RC
TSS_TPMS_AUTH_RESPONSE_Unmarshalu(TPMS_AUTH_RESPONSE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NONCE_Unmarshalu(&target->nonce, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMA_SESSION_Unmarshalu(&target->sessionAttributes, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_AUTH_Unmarshalu(&target->hmac, buffer, size);
    }
    return rc;
}

/* Table 124 - Definition of {!ALG.S} (TPM_KEY_BITS) TPMI_!ALG.S_KEY_BITS Type */

#ifdef TPM_ALG_AES

TPM_RC
TSS_TPMI_AES_KEY_BITS_Unmarshalu(TPMI_AES_KEY_BITS *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_KEY_BITS_Unmarshalu(target, buffer, size);  
    }
    return rc;
}
#endif	/* TPM_ALG_AES */

#ifndef TPM_TSS_NOCMDCHECK

#ifdef TPM_ALG_CAMELLIA
TPM_RC
TSS_TPMI_CAMELLIA_KEY_BITS_Unmarshalu(TPMI_CAMELLIA_KEY_BITS *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_KEY_BITS_Unmarshalu(target, buffer, size);  
    }
    return rc;
}
#endif	/*  TPM_ALG_CAMELLIA */

#ifdef TPM_ALG_SM4
TPM_RC
TSS_TPMI_SM4_KEY_BITS_Unmarshalu(TPMI_SM4_KEY_BITS *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_KEY_BITS_Unmarshalu(target, buffer, size);  
    }
    return rc;
}
#endif	/* TPM_ALG_SM4 */
#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 125 - Definition of TPMU_SYM_KEY_BITS Union */

TPM_RC
TSS_TPMU_SYM_KEY_BITS_Unmarshalu(TPMU_SYM_KEY_BITS *target, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    switch (selector) {
#ifdef TPM_ALG_AES
      case TPM_ALG_AES:
	rc = TSS_TPMI_AES_KEY_BITS_Unmarshalu(&target->aes, buffer, size);
	break;
#endif
#ifdef TPM_ALG_SM4
      case TPM_ALG_SM4:
	rc = TSS_TPMI_SM4_KEY_BITS_Unmarshalu(&target->sm4, buffer, size);
	break;
#endif
#ifdef TPM_ALG_CAMELLIA
      case TPM_ALG_CAMELLIA:
	rc = TSS_TPMI_CAMELLIA_KEY_BITS_Unmarshalu(&target->camellia, buffer, size);
	break;
#endif
#ifdef TPM_ALG_XOR
      case TPM_ALG_XOR:
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->xorr, buffer, size, NO);
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 126 - Definition of TPMU_SYM_MODE Union */

TPM_RC
TSS_TPMU_SYM_MODE_Unmarshalu(TPMU_SYM_MODE *target, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    switch (selector) {
#ifdef TPM_ALG_AES
      case TPM_ALG_AES:
	rc = TSS_TPMI_ALG_SYM_MODE_Unmarshalu(&target->aes, buffer, size, YES);
	break;
#endif
#ifdef TPM_ALG_SM4
      case TPM_ALG_SM4:
	rc = TSS_TPMI_ALG_SYM_MODE_Unmarshalu(&target->sm4, buffer, size, YES);
	break;
#endif
#ifdef TPM_ALG_CAMELLIA
      case TPM_ALG_CAMELLIA:
	rc = TSS_TPMI_ALG_SYM_MODE_Unmarshalu(&target->camellia, buffer, size, YES);
	break;
#endif
      case TPM_ALG_XOR:
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 128 - Definition of TPMT_SYM_DEF Structure */

TPM_RC
TSS_TPMT_SYM_DEF_Unmarshalu(TPMT_SYM_DEF *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_SYM_Unmarshalu(&target->algorithm, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_SYM_KEY_BITS_Unmarshalu(&target->keyBits, buffer, size, target->algorithm);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_SYM_MODE_Unmarshalu(&target->mode, buffer, size, target->algorithm);
    }
    return rc;
}

/* Table 129 - Definition of TPMT_SYM_DEF_OBJECT Structure */

TPM_RC
TSS_TPMT_SYM_DEF_OBJECT_Unmarshalu(TPMT_SYM_DEF_OBJECT *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_SYM_OBJECT_Unmarshalu(&target->algorithm, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_SYM_KEY_BITS_Unmarshalu(&target->keyBits, buffer, size, target->algorithm);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_SYM_MODE_Unmarshalu(&target->mode, buffer, size, target->algorithm);
    }
    return rc;
}

#ifndef TPM_TSS_NOCMDCHECK

/* Table 130 - Definition of TPM2B_SYM_KEY Structure */

TPM_RC
TSS_TPM2B_SYM_KEY_Unmarshalu(TPM2B_SYM_KEY *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}

#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 131 - Definition of TPMS_SYMCIPHER_PARMS Structure */

TPM_RC
TSS_TPMS_SYMCIPHER_PARMS_Unmarshalu(TPMS_SYMCIPHER_PARMS *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Unmarshalu(&target->sym, buffer, size, NO);
    }
    return rc;
}

/* Table 132 - Definition of TPM2B_SENSITIVE_DATA Structure */

TPM_RC
TSS_TPM2B_SENSITIVE_DATA_Unmarshalu(TPM2B_SENSITIVE_DATA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}

#ifndef TPM_TSS_NOCMDCHECK

/* Table 133 - Definition of TPMS_SENSITIVE_CREATE Structure <IN> */

TPM_RC
TSS_TPMS_SENSITIVE_CREATE_Unmarshalu(TPMS_SENSITIVE_CREATE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_AUTH_Unmarshalu(&target->userAuth, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_SENSITIVE_DATA_Unmarshalu(&target->data, buffer, size);
    }
    return rc;
}

/* Table 134 - Definition of TPM2B_SENSITIVE_CREATE Structure <IN, S> */

TPM_RC
TSS_TPM2B_SENSITIVE_CREATE_Unmarshalu(TPM2B_SENSITIVE_CREATE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t startSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->size, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->size == 0) {
	    rc = TPM_RC_SIZE;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	startSize = *size;
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SENSITIVE_CREATE_Unmarshalu(&target->sensitive, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->size != startSize - *size) {
	    rc = TPM_RC_SIZE;
	}
    }
    return rc;
}

#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 135 - Definition of TPMS_SCHEME_HASH Structure */

TPM_RC
TSS_TPMS_SCHEME_HASH_Unmarshalu(TPMS_SCHEME_HASH *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->hashAlg, buffer, size, NO);
    }
    return rc;
}

/* Table 136 - Definition of {ECC} TPMS_SCHEME_ECDAA Structure */

TPM_RC
TSS_TPMS_SCHEME_ECDAA_Unmarshalu(TPMS_SCHEME_ECDAA *target, BYTE **buffer, uint32_t *size) 
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->hashAlg, buffer, size, NO);	
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->count, buffer, size);	
    }
    return rc;
}

/* Table 137 - Definition of (TPM_ALG_ID) TPMI_ALG_KEYEDHASH_SCHEME Type */

TPM_RC
TSS_TPMI_ALG_KEYEDHASH_SCHEME_Unmarshalu(TPMI_ALG_KEYEDHASH_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 138 - Definition of Types for HMAC_SIG_SCHEME */

TPM_RC
TSS_TPMS_SCHEME_HMAC_Unmarshalu(TPMS_SCHEME_HMAC *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SCHEME_HASH_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/* Table 139 - Definition of TPMS_SCHEME_XOR Structure */

TPM_RC
TSS_TPMS_SCHEME_XOR_Unmarshalu(TPMS_SCHEME_XOR *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->hashAlg, buffer, size, NO);	/* as of rev 147 */
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_KDF_Unmarshalu(&target->kdf, buffer, size, YES);
    }
    return rc;
}

/* Table 140 - Definition of TPMU_SCHEME_KEYEDHASH Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_SCHEME_KEYEDHASH_Unmarshalu(TPMU_SCHEME_KEYEDHASH *target, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    switch (selector) {
#ifdef TPM_ALG_HMAC
      case TPM_ALG_HMAC:
	rc = TSS_TPMS_SCHEME_HMAC_Unmarshalu(&target->hmac, buffer, size);
	break;
#endif
#ifdef TPM_ALG_XOR
      case TPM_ALG_XOR:
	rc = TSS_TPMS_SCHEME_XOR_Unmarshalu(&target->xorr, buffer, size);
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
TSS_TPMT_KEYEDHASH_SCHEME_Unmarshalu(TPMT_KEYEDHASH_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_KEYEDHASH_SCHEME_Unmarshalu(&target->scheme, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_SCHEME_KEYEDHASH_Unmarshalu(&target->details, buffer, size, target->scheme);
    }
    return rc;
}

/* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */

TPM_RC
TSS_TPMS_SIG_SCHEME_RSAPSS_Unmarshalu(TPMS_SIG_SCHEME_RSAPSS *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SCHEME_HASH_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */

TPM_RC
TSS_TPMS_SIG_SCHEME_RSASSA_Unmarshalu(TPMS_SIG_SCHEME_RSASSA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SCHEME_HASH_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/* Table 143 - Definition of {ECC} Types for ECC Signature Schemes */

TPM_RC
TSS_TPMS_SIG_SCHEME_ECDAA_Unmarshalu(TPMS_SIG_SCHEME_ECDAA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SCHEME_ECDAA_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/* Table 143 - Definition of {ECC} Types for ECC Signature Schemes */

TPM_RC
TSS_TPMS_SIG_SCHEME_ECDSA_Unmarshalu(TPMS_SIG_SCHEME_ECDSA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SCHEME_HASH_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/* Table 143 - Definition of {ECC} Types for ECC Signature Schemes */

TPM_RC
TSS_TPMS_SIG_SCHEME_ECSCHNORR_Unmarshalu(TPMS_SIG_SCHEME_ECSCHNORR *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SCHEME_HASH_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/* Table 143 - Definition of {ECC} Types for ECC Signature Schemes */

TPM_RC
TSS_TPMS_SIG_SCHEME_SM2_Unmarshalu(TPMS_SIG_SCHEME_SM2 *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SCHEME_HASH_Unmarshalu(target, buffer, size);
    }
    return rc;
}

#ifndef TPM_TSS_NOCMDCHECK

/* Table 144 - Definition of TPMU_SIG_SCHEME Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_SIG_SCHEME_Unmarshalu(TPMU_SIG_SCHEME *target, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    switch (selector) {
#ifdef TPM_ALG_RSASSA
      case TPM_ALG_RSASSA:
	rc = TSS_TPMS_SIG_SCHEME_RSASSA_Unmarshalu(&target->rsassa, buffer, size);
	break;
#endif
#ifdef TPM_ALG_RSAPSS
      case TPM_ALG_RSAPSS:
	rc = TSS_TPMS_SIG_SCHEME_RSAPSS_Unmarshalu(&target->rsapss, buffer, size);
	break;
#endif
#ifdef TPM_ALG_ECDSA
      case TPM_ALG_ECDSA:
	rc = TSS_TPMS_SIG_SCHEME_ECDSA_Unmarshalu(&target->ecdsa, buffer, size);
	break;
#endif
#ifdef TPM_ALG_ECDAA
      case TPM_ALG_ECDAA:
	rc = TSS_TPMS_SIG_SCHEME_ECDAA_Unmarshalu(&target->ecdaa, buffer, size);
	break;
#endif
#ifdef TPM_ALG_SM2
      case TPM_ALG_SM2:
	rc = TSS_TPMS_SIG_SCHEME_SM2_Unmarshalu(&target->sm2, buffer, size);
	break;
#endif
#ifdef TPM_ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
	rc = TSS_TPMS_SIG_SCHEME_ECSCHNORR_Unmarshalu(&target->ecSchnorr, buffer, size);
	break;
#endif
#ifdef TPM_ALG_HMAC
      case TPM_ALG_HMAC:
	rc = TSS_TPMS_SCHEME_HMAC_Unmarshalu(&target->hmac, buffer, size);
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
TSS_TPMT_SIG_SCHEME_Unmarshalu(TPMT_SIG_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_SIG_SCHEME_Unmarshalu(&target->scheme, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_SIG_SCHEME_Unmarshalu(&target->details, buffer, size, target->scheme);
    }
    return rc;
}

#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 146 - Definition of Types for {RSA} Encryption Schemes */

TPM_RC
TSS_TPMS_ENC_SCHEME_OAEP_Unmarshalu(TPMS_ENC_SCHEME_OAEP *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SCHEME_HASH_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/* Table 146 - Definition of Types for {RSA} Encryption Schemes */

/* NOTE: Marked as const function in header */

TPM_RC
TSS_TPMS_ENC_SCHEME_RSAES_Unmarshalu(TPMS_ENC_SCHEME_RSAES *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_EMPTY_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/* Table 147 - Definition of Types for {ECC} ECC Key Exchange */

TPM_RC
TSS_TPMS_KEY_SCHEME_ECDH_Unmarshalu(TPMS_KEY_SCHEME_ECDH *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SCHEME_HASH_Unmarshalu(target, buffer, size); 
    }
    return rc;
}

#ifndef TPM_TSS_NOCMDCHECK

/* Table 147 - Definition of Types for {ECC} ECC Key Exchange */

TPM_RC
TSS_TPMS_KEY_SCHEME_ECMQV_Unmarshalu(TPMS_KEY_SCHEME_ECMQV *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SCHEME_HASH_Unmarshalu(target, buffer, size); 
    }
    return rc;
}

#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 148 - Definition of Types for KDF Schemes, hash-based key- or mask-generation functions */

TPM_RC
TSS_TPMS_SCHEME_KDF1_SP800_108_Unmarshalu(TPMS_SCHEME_KDF1_SP800_108 *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SCHEME_HASH_Unmarshalu(target, buffer, size); 
    }
    return rc;
}

/* Table 148 - Definition of Types for KDF Schemes, hash-based key- or mask-generation functions */

TPM_RC
TSS_TPMS_SCHEME_KDF1_SP800_56A_Unmarshalu(TPMS_SCHEME_KDF1_SP800_56A *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SCHEME_HASH_Unmarshalu(target, buffer, size); 
    }
    return rc;
}

#ifndef TPM_TSS_NOCMDCHECK

/* Table 148 - Definition of Types for KDF Schemes, hash-based key- or mask-generation functions */

TPM_RC
TSS_TPMS_SCHEME_KDF2_Unmarshalu(TPMS_SCHEME_KDF2 *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SCHEME_HASH_Unmarshalu(target, buffer, size);
    }
    return rc;
}

#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 148 - Definition of Types for KDF Schemes, hash-based key- or mask-generation functions */

TPM_RC
TSS_TPMS_SCHEME_MGF1_Unmarshalu(TPMS_SCHEME_MGF1 *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SCHEME_HASH_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/* Table 149 - Definition of TPMU_KDF_SCHEME Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_KDF_SCHEME_Unmarshalu(TPMU_KDF_SCHEME *target, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    switch (selector) {
#ifdef TPM_ALG_MGF1
      case TPM_ALG_MGF1:
	rc = TSS_TPMS_SCHEME_MGF1_Unmarshalu(&target->mgf1, buffer, size);
	break;
#endif
#ifdef TPM_ALG_KDF1_SP800_56A
      case TPM_ALG_KDF1_SP800_56A:
	rc = TSS_TPMS_SCHEME_KDF1_SP800_56A_Unmarshalu(&target->kdf1_SP800_56a, buffer, size);
	break;
#endif
#ifdef TPM_ALG_KDF2
      case TPM_ALG_KDF2:
	rc = TSS_TPMS_SCHEME_KDF2_Unmarshalu(&target->kdf2, buffer, size);
	break;
#endif
#ifdef TPM_ALG_KDF1_SP800_108
      case TPM_ALG_KDF1_SP800_108:
	rc = TSS_TPMS_SCHEME_KDF1_SP800_108_Unmarshalu(&target->kdf1_sp800_108, buffer, size);
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
TSS_TPMT_KDF_SCHEME_Unmarshalu(TPMT_KDF_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_KDF_Unmarshalu(&target->scheme, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_KDF_SCHEME_Unmarshalu(&target->details, buffer, size, target->scheme);
    }
    return rc;
}

/* Table 151 - Definition of (TPM_ALG_ID) TPMI_ALG_ASYM_SCHEME Type <> */

#if 0
TPM_RC
TSS_TPMI_ALG_ASYM_SCHEME_Unmarshalu(TPMI_ALG_ASYM_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(target, buffer, size);  
    }
    return rc;
}
#endif	/* 0 */

/* Table 152 - Definition of TPMU_ASYM_SCHEME Union */

TPM_RC
TSS_TPMU_ASYM_SCHEME_Unmarshalu(TPMU_ASYM_SCHEME *target, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    switch (selector) {
#ifdef TPM_ALG_ECDH
      case TPM_ALG_ECDH:
	rc = TSS_TPMS_KEY_SCHEME_ECDH_Unmarshalu(&target->ecdh, buffer, size);
	break;
#endif
#ifdef TPM_ALG_ECMQV
      case TPM_ALG_ECMQV:
	rc = TSS_TPMS_KEY_SCHEME_ECMQV_Unmarshalu(&target->ecmqvh, buffer, size);
	break;
#endif
#ifdef TPM_ALG_RSASSA
      case TPM_ALG_RSASSA:
	rc = TSS_TPMS_SIG_SCHEME_RSASSA_Unmarshalu(&target->rsassa, buffer, size);
	break;
#endif
#ifdef TPM_ALG_RSAPSS
      case TPM_ALG_RSAPSS:
	rc = TSS_TPMS_SIG_SCHEME_RSAPSS_Unmarshalu(&target->rsapss, buffer, size);
	break;
#endif
#ifdef TPM_ALG_ECDSA
      case TPM_ALG_ECDSA:
	rc = TSS_TPMS_SIG_SCHEME_ECDSA_Unmarshalu(&target->ecdsa, buffer, size);
	break;
#endif
#ifdef TPM_ALG_ECDAA
      case TPM_ALG_ECDAA:
	rc = TSS_TPMS_SIG_SCHEME_ECDAA_Unmarshalu(&target->ecdaa, buffer, size);
	break;
#endif
#ifdef TPM_ALG_SM2
      case TPM_ALG_SM2:
	rc = TSS_TPMS_SIG_SCHEME_SM2_Unmarshalu(&target->sm2, buffer, size);
	break;
#endif
#ifdef TPM_ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
	rc = TSS_TPMS_SIG_SCHEME_ECSCHNORR_Unmarshalu(&target->ecSchnorr, buffer, size);
	break;
#endif
#ifdef TPM_ALG_RSAES
      case TPM_ALG_RSAES:
	rc = TSS_TPMS_ENC_SCHEME_RSAES_Unmarshalu(&target->rsaes, buffer, size);
	break;
#endif
#ifdef TPM_ALG_OAEP
      case TPM_ALG_OAEP:
	rc = TSS_TPMS_ENC_SCHEME_OAEP_Unmarshalu(&target->oaep, buffer, size);
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 153 - Definition of TPMT_ASYM_SCHEME Structure <> */

#if 0
TPM_RC
TSS_TPMT_ASYM_SCHEME_Unmarshalu(TPMT_ASYM_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_ASYM_SCHEME_Unmarshalu(&target->scheme, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_ASYM_SCHEME_Unmarshalu(&target->details, buffer, size, target->scheme);
    }
    return rc;
}
#endif	/* 0 */

/* Table 154 - Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_SCHEME Type */

TPM_RC
TSS_TPMI_ALG_RSA_SCHEME_Unmarshalu(TPMI_ALG_RSA_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 155 - Definition of {RSA} TPMT_RSA_SCHEME Structure */

TPM_RC
TSS_TPMT_RSA_SCHEME_Unmarshalu(TPMT_RSA_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_RSA_SCHEME_Unmarshalu(&target->scheme, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_ASYM_SCHEME_Unmarshalu(&target->details, buffer, size, target->scheme);
    }
    return rc;
}

#ifndef TPM_TSS_NOCMDCHECK

/* Table 156 - Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_DECRYPT Type */

TPM_RC
TSS_TPMI_ALG_RSA_DECRYPT_Unmarshalu(TPMI_ALG_RSA_DECRYPT *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 157 - Definition of {RSA} TPMT_RSA_DECRYPT Structure */

TPM_RC
TSS_TPMT_RSA_DECRYPT_Unmarshalu(TPMT_RSA_DECRYPT *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_RSA_DECRYPT_Unmarshalu(&target->scheme, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_ASYM_SCHEME_Unmarshalu(&target->details, buffer, size, target->scheme);
    }
    return rc;
}

#endif /* TPM_TSS_NOCMDCHECK */

/* Table 158 - Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure */
TPM_RC
TSS_TPM2B_PUBLIC_KEY_RSA_Unmarshalu(TPM2B_PUBLIC_KEY_RSA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}

/* Table 159 - Definition of {RSA} (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type */

TPM_RC
TSS_TPMI_RSA_KEY_BITS_Unmarshalu(TPMI_RSA_KEY_BITS *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_KEY_BITS_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

#ifndef TPM_TSS_NOCMDCHECK

/* Table 160 - Definition of {RSA} TPM2B_PRIVATE_KEY_RSA Structure */

TPM_RC
TSS_TPM2B_PRIVATE_KEY_RSA_Unmarshalu(TPM2B_PRIVATE_KEY_RSA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}
 
#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 161 - Definition of {ECC} TPM2B_ECC_PARAMETER Structure */

TPM_RC
TSS_TPM2B_ECC_PARAMETER_Unmarshalu(TPM2B_ECC_PARAMETER *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
     	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}

/* Table 162 - Definition of {ECC} TPMS_ECC_POINT Structure */

TPM_RC
TSS_TPMS_ECC_POINT_Unmarshalu(TPMS_ECC_POINT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_PARAMETER_Unmarshalu(&target->x, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_PARAMETER_Unmarshalu(&target->y, buffer, size);
    }
    return rc;
}

/* Table 163 - Definition of {ECC} TPM2B_ECC_POINT Structure */

TPM_RC
TSS_TPM2B_ECC_POINT_Unmarshalu(TPM2B_ECC_POINT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t startSize = 0;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->size, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->size == 0) {
	    rc = TPM_RC_SIZE;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	startSize = *size;
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_ECC_POINT_Unmarshalu(&target->point, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->size != startSize - *size) {
	    rc = TPM_RC_SIZE;
	}
    }
    return rc;
}

/* Table 164 - Definition of (TPM_ALG_ID) {ECC} TPMI_ALG_ECC_SCHEME Type */

TPM_RC
TSS_TPMI_ALG_ECC_SCHEME_Unmarshalu(TPMI_ALG_ECC_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 165 - Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type */

TPM_RC
TSS_TPMI_ECC_CURVE_Unmarshalu(TPMI_ECC_CURVE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ECC_CURVE_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 166 - Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure */

TPM_RC
TSS_TPMT_ECC_SCHEME_Unmarshalu(TPMT_ECC_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_ECC_SCHEME_Unmarshalu(&target->scheme, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_ASYM_SCHEME_Unmarshalu(&target->details, buffer, size, target->scheme);
    }
    return rc;
}

/* Table 167 - Definition of {ECC} TPMS_ALGORITHM_DETAIL_ECC Structure <OUT> */

TPM_RC
TSS_TPMS_ALGORITHM_DETAIL_ECC_Unmarshalu(TPMS_ALGORITHM_DETAIL_ECC *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ECC_CURVE_Unmarshalu(&target->curveID, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->keySize, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_KDF_SCHEME_Unmarshalu(&target->kdf, buffer, size, YES);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_ECC_SCHEME_Unmarshalu(&target->sign, buffer, size, YES);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_PARAMETER_Unmarshalu(&target->p, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_PARAMETER_Unmarshalu(&target->a, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_PARAMETER_Unmarshalu(&target->b, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_PARAMETER_Unmarshalu(&target->gX, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_PARAMETER_Unmarshalu(&target->gY, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_PARAMETER_Unmarshalu(&target->n, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_PARAMETER_Unmarshalu(&target->h, buffer, size);
    }
    return rc;
}

/* Table 168 - Definition of {RSA} TPMS_SIGNATURE_RSA Structure */

TPM_RC
TSS_TPMS_SIGNATURE_RSA_Unmarshalu(TPMS_SIGNATURE_RSA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->hash, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_PUBLIC_KEY_RSA_Unmarshalu(&target->sig, buffer, size);
    }
    return rc;
}

/* Table 169 - Definition of Types for {RSA} Signature */

TPM_RC
TSS_TPMS_SIGNATURE_RSASSA_Unmarshalu(TPMS_SIGNATURE_RSASSA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SIGNATURE_RSA_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/* Table 169 - Definition of Types for {RSA} Signature */
    
TPM_RC
TSS_TPMS_SIGNATURE_RSAPSS_Unmarshalu(TPMS_SIGNATURE_RSAPSS *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SIGNATURE_RSA_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/* Table 170 - Definition of {ECC} TPMS_SIGNATURE_ECC Structure */

TPM_RC
TSS_TPMS_SIGNATURE_ECC_Unmarshalu(TPMS_SIGNATURE_ECC *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->hash, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_PARAMETER_Unmarshalu(&target->signatureR, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_ECC_PARAMETER_Unmarshalu(&target->signatureS, buffer, size);
    }
    return rc;
}

/* Table 171 - Definition of Types for {ECC} TPMS_SIGNATURE_ECC */

TPM_RC
TSS_TPMS_SIGNATURE_ECDSA_Unmarshalu(TPMS_SIGNATURE_ECDSA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
     
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SIGNATURE_ECC_Unmarshalu(target, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPMS_SIGNATURE_ECDAA_Unmarshalu(TPMS_SIGNATURE_ECDAA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
     
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SIGNATURE_ECC_Unmarshalu(target, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPMS_SIGNATURE_SM2_Unmarshalu(TPMS_SIGNATURE_SM2 *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
     
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SIGNATURE_ECC_Unmarshalu(target, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_TPMS_SIGNATURE_ECSCHNORR_Unmarshalu(TPMS_SIGNATURE_ECSCHNORR *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
     
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_SIGNATURE_ECC_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/* Table 172 - Definition of TPMU_SIGNATURE Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_SIGNATURE_Unmarshalu(TPMU_SIGNATURE *target, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    switch (selector) {
#ifdef TPM_ALG_RSASSA
      case TPM_ALG_RSASSA:
	rc = TSS_TPMS_SIGNATURE_RSASSA_Unmarshalu(&target->rsassa, buffer, size);
	break;
#endif
#ifdef TPM_ALG_RSAPSS
      case TPM_ALG_RSAPSS:
	rc = TSS_TPMS_SIGNATURE_RSAPSS_Unmarshalu(&target->rsapss, buffer, size);
	break;
#endif
#ifdef TPM_ALG_ECDSA
      case TPM_ALG_ECDSA:
	rc = TSS_TPMS_SIGNATURE_ECDSA_Unmarshalu(&target->ecdsa, buffer, size);
	break;
#endif
#ifdef TPM_ALG_ECDAA
      case TPM_ALG_ECDAA:
	rc = TSS_TPMS_SIGNATURE_ECDAA_Unmarshalu(&target->ecdaa, buffer, size);
	break;
#endif
#ifdef TPM_ALG_SM2
      case TPM_ALG_SM2:
	rc = TSS_TPMS_SIGNATURE_SM2_Unmarshalu(&target->sm2, buffer, size);
	break;
#endif
#ifdef TPM_ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
	rc = TSS_TPMS_SIGNATURE_ECSCHNORR_Unmarshalu(&target->ecschnorr, buffer, size);
	break;
#endif
#ifdef TPM_ALG_HMAC
      case TPM_ALG_HMAC:
	rc = TSS_TPMT_HA_Unmarshalu(&target->hmac, buffer, size, NO);
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
TSS_TPMT_SIGNATURE_Unmarshalu(TPMT_SIGNATURE *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_SIG_SCHEME_Unmarshalu(&target->sigAlg, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_SIGNATURE_Unmarshalu(&target->signature, buffer, size, target->sigAlg);
    }
    return rc;
}

/* Table 175 - Definition of TPM2B_ENCRYPTED_SECRET Structure */

TPM_RC
TSS_TPM2B_ENCRYPTED_SECRET_Unmarshalu(TPM2B_ENCRYPTED_SECRET *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.secret), buffer, size);
    }
    return rc;
}

/* Table 176 - Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type */

TPM_RC
TSS_TPMI_ALG_PUBLIC_Unmarshalu(TPMI_ALG_PUBLIC *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(target, buffer, size);  
    }
    return rc;
}

/* Table 177 - Definition of TPMU_PUBLIC_ID Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_PUBLIC_ID_Unmarshalu(TPMU_PUBLIC_ID *target, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    switch (selector) {
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->keyedHash, buffer, size);
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->sym, buffer, size);
	break;
#endif
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA: 
	rc = TSS_TPM2B_PUBLIC_KEY_RSA_Unmarshalu(&target->rsa, buffer, size);
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	rc = TSS_TPMS_ECC_POINT_Unmarshalu(&target->ecc, buffer, size);
	break;
#endif
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 178 - Definition of TPMS_KEYEDHASH_PARMS Structure */

TPM_RC
TSS_TPMS_KEYEDHASH_PARMS_Unmarshalu(TPMS_KEYEDHASH_PARMS *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_KEYEDHASH_SCHEME_Unmarshalu(&target->scheme, buffer, size, YES);
    }
    return rc;
}

/* Table 179 - Definition of TPMS_ASYM_PARMS Structure <> */

#if 0
TPM_RC
TSS_TPMS_ASYM_PARMS_Unmarshalu(TPMS_ASYM_PARMS *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Unmarshalu(&target->symmetric, buffer, size, YES);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_ASYM_SCHEME_Unmarshalu(&target->scheme, buffer, size, YES);
    }
    return rc;
}
#endif

/* Table 180 - Definition of {RSA} TPMS_RSA_PARMS Structure */

TPM_RC
TSS_TPMS_RSA_PARMS_Unmarshalu(TPMS_RSA_PARMS *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Unmarshalu(&target->symmetric, buffer, size, YES);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_RSA_SCHEME_Unmarshalu(&target->scheme, buffer, size, YES);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_RSA_KEY_BITS_Unmarshalu(&target->keyBits, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->exponent, buffer, size);
    }
    return rc;
}

/* Table 181 - Definition of {ECC} TPMS_ECC_PARMS Structure */

TPM_RC
TSS_TPMS_ECC_PARMS_Unmarshalu(TPMS_ECC_PARMS *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_SYM_DEF_OBJECT_Unmarshalu(&target->symmetric, buffer, size, YES);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_ECC_SCHEME_Unmarshalu(&target->scheme, buffer, size, YES);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ECC_CURVE_Unmarshalu(&target->curveID, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_KDF_SCHEME_Unmarshalu(&target->kdf, buffer, size, YES);
    }
    return rc;
}

/* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_PUBLIC_PARMS_Unmarshalu(TPMU_PUBLIC_PARMS *target, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    switch (selector) {
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	rc = TSS_TPMS_KEYEDHASH_PARMS_Unmarshalu(&target->keyedHashDetail, buffer, size);
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	rc = TSS_TPMS_SYMCIPHER_PARMS_Unmarshalu(&target->symDetail, buffer, size);
	break;
#endif
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	rc = TSS_TPMS_RSA_PARMS_Unmarshalu(&target->rsaDetail, buffer, size);
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	rc = TSS_TPMS_ECC_PARMS_Unmarshalu(&target->eccDetail, buffer, size);
	break;
#endif
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

#ifndef TPM_TSS_NOCMDCHECK

/* Table 183 - Definition of TPMT_PUBLIC_PARMS Structure */

TPM_RC
TSS_TPMT_PUBLIC_PARMS_Unmarshalu(TPMT_PUBLIC_PARMS *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_PUBLIC_Unmarshalu(&target->type, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_PUBLIC_PARMS_Unmarshalu(&target->parameters, buffer, size, target->type);
    }
    return rc;
}

#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 184 - Definition of TPMT_PUBLIC Structure */

TPM_RC
TSS_TPMT_PUBLIC_Unmarshalu(TPMT_PUBLIC *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_PUBLIC_Unmarshalu(&target->type, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->nameAlg, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMA_OBJECT_Unmarshalu(&target->objectAttributes, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->authPolicy, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_PUBLIC_PARMS_Unmarshalu(&target->parameters, buffer, size, target->type);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_PUBLIC_ID_Unmarshalu(&target->unique, buffer, size, target->type);
    }
    return rc;
}

/* Table 185 - Definition of TPM2B_PUBLIC Structure */

TPM_RC
TSS_TPM2B_PUBLIC_Unmarshalu(TPM2B_PUBLIC *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t startSize = 0;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->size, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->size == 0) {
	    rc = TPM_RC_SIZE;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	startSize = *size;
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMT_PUBLIC_Unmarshalu(&target->publicArea, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->size != startSize - *size) {
	    rc = TPM_RC_SIZE;
	}
    }
    return rc;
}
#ifndef TPM_TSS_NOCMDCHECK

/* Table 192 - Definition of TPM2B_TEMPLATE Structure */

TPM_RC
TSS_TPM2B_TEMPLATE_Unmarshalu(TPM2B_TEMPLATE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}
    
/* Table 187 - Definition of TPMU_SENSITIVE_COMPOSITE Union <IN/OUT, S> */

TPM_RC
TSS_TPMU_SENSITIVE_COMPOSITE_Unmarshalu(TPMU_SENSITIVE_COMPOSITE *target, BYTE **buffer, uint32_t *size, uint32_t selector)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    switch (selector) {
#ifdef TPM_ALG_RSA
      case TPM_ALG_RSA:
	rc = TSS_TPM2B_PRIVATE_KEY_RSA_Unmarshalu(&target->rsa, buffer, size);
	break;
#endif
#ifdef TPM_ALG_ECC
      case TPM_ALG_ECC:
	rc = TSS_TPM2B_ECC_PARAMETER_Unmarshalu(&target->ecc, buffer, size);
	break;
#endif
#ifdef TPM_ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
	rc = TSS_TPM2B_SENSITIVE_DATA_Unmarshalu(&target->bits, buffer, size);
	break;
#endif
#ifdef TPM_ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
	rc = TSS_TPM2B_SYM_KEY_Unmarshalu(&target->sym, buffer, size);
	break;
#endif
      default:
	rc = TPM_RC_SELECTOR;
    }
    return rc;
}

/* Table 188 - Definition of TPMT_SENSITIVE Structure */

TPM_RC
TSS_TPMT_SENSITIVE_Unmarshalu(TPMT_SENSITIVE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_PUBLIC_Unmarshalu(&target->sensitiveType, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_AUTH_Unmarshalu(&target->authValue, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->seedValue, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_SENSITIVE_COMPOSITE_Unmarshalu(&target->sensitive, buffer, size, target->sensitiveType);
    }
    return rc;
}

/* Table 189 - Definition of TPM2B_SENSITIVE Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_SENSITIVE_Unmarshalu(TPM2B_SENSITIVE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t startSize = 0;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->t.size, buffer, size);
    }
    if (target->t.size != 0) {
	if (rc == TPM_RC_SUCCESS) {
	    startSize = *size;
	}
	if (rc == TPM_RC_SUCCESS) {
	    rc = TSS_TPMT_SENSITIVE_Unmarshalu(&target->t.sensitiveArea, buffer, size);
	}
	if (rc == TPM_RC_SUCCESS) {
	    if (target->t.size != startSize - *size) {
		rc = TPM_RC_SIZE;
	    }
	}
    }
    return rc;
}

#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 191 - Definition of TPM2B_PRIVATE Structure <IN/OUT, S> */

TPM_RC
TSS_TPM2B_PRIVATE_Unmarshalu(TPM2B_PRIVATE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}

/* Table 193 - Definition of TPM2B_ID_OBJECT Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_ID_OBJECT_Unmarshalu(TPM2B_ID_OBJECT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.credential), buffer, size);
    }
    return rc;
}

/* Table 196 - Definition of (UINT32) TPMA_NV Bits */

TPM_RC
TSS_TPMA_NV_Unmarshalu(TPMA_NV *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT32_Unmarshalu(&target->val, buffer, size);  
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->val & TPMA_NV_RESERVED) {
	    rc = TPM_RC_RESERVED_BITS;
	}
    }
    return rc;
}

/* Table 197 - Definition of TPMS_NV_PUBLIC Structure */

TPM_RC
TSS_TPMS_NV_PUBLIC_Unmarshalu(TPMS_NV_PUBLIC *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_RH_NV_INDEX_Unmarshalu(&target->nvIndex, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_Unmarshalu(&target->nameAlg, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMA_NV_Unmarshalu(&target->attributes, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->authPolicy, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->dataSize, buffer, size);
    }
    return rc;
}

/* Table 198 - Definition of TPM2B_NV_PUBLIC Structure */

TPM_RC
TSS_TPM2B_NV_PUBLIC_Unmarshalu(TPM2B_NV_PUBLIC *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t startSize = 0;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->size, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->size == 0) {
	    rc = TPM_RC_SIZE;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	startSize = *size;
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_NV_PUBLIC_Unmarshalu(&target->nvPublic, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->size != startSize - *size) {
	    rc = TPM_RC_SIZE;
	}
    }
    return rc;
}

#ifndef TPM_TSS_NOCMDCHECK

/* Table 199 - Definition of TPM2B_CONTEXT_SENSITIVE Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_CONTEXT_SENSITIVE_Unmarshalu(TPM2B_CONTEXT_SENSITIVE *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}

/* Table 200 - Definition of TPMS_CONTEXT_DATA Structure <IN/OUT, S> */

TPM_RC
TSS_TPMS_CONTEXT_DATA_Unmarshalu(TPMS_CONTEXT_DATA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->integrity, buffer, size);	
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_CONTEXT_SENSITIVE_Unmarshalu(&target->encrypted, buffer, size);
    }
    return rc;
}

#endif	/* TPM_TSS_NOCMDCHECK */

/* Table 201 - Definition of TPM2B_CONTEXT_DATA Structure <IN/OUT> */

TPM_RC
TSS_TPM2B_CONTEXT_DATA_Unmarshalu(TPM2B_CONTEXT_DATA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_Unmarshalu(&target->b, sizeof(target->t.buffer), buffer, size);
    }
    return rc;
}

/* Table 202 - Definition of TPMS_CONTEXT Structure */

TPM_RC
TSS_TPMS_CONTEXT_Unmarshalu(TPMS_CONTEXT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT64_Unmarshalu(&target->sequence, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_DH_SAVED_Unmarshalu(&target->savedHandle, buffer, size, NO);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_RH_HIERARCHY_Unmarshalu(&target->hierarchy, buffer, size, YES);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_CONTEXT_DATA_Unmarshalu(&target->contextBlob, buffer, size);
    }
    return rc;
}

/* Table 204 - Definition of TPMS_CREATION_DATA Structure <OUT> */

TPM_RC
TSS_TPMS_CREATION_DATA_Unmarshalu(TPMS_CREATION_DATA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPML_PCR_SELECTION_Unmarshalu(&target->pcrSelect, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DIGEST_Unmarshalu(&target->pcrDigest, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMA_LOCALITY_Unmarshalu(&target->locality, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_Unmarshalu(&target->parentNameAlg, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->parentName, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_NAME_Unmarshalu(&target->parentQualifiedName, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM2B_DATA_Unmarshalu(&target->outsideInfo, buffer, size);
    }
    return rc;
}

/* Table 205 - Definition of TPM2B_CREATION_DATA Structure <OUT> */

TPM_RC
TSS_TPM2B_CREATION_DATA_Unmarshalu(TPM2B_CREATION_DATA *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    uint32_t startSize = 0;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_UINT16_Unmarshalu(&target->size, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->size == 0) {
	    rc = TPM_RC_SIZE;
	}
    }
    if (rc == TPM_RC_SUCCESS) {
	startSize = *size;
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMS_CREATION_DATA_Unmarshalu(&target->creationData, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->size != startSize - *size) {
	    rc = TPM_RC_SIZE;
	}
    }
    return rc;
}
#ifndef TPM_TSS_NOCMDCHECK

/* Deprecated functions that use a sized value for the size parameter.  The recommended functions
   use an unsigned value.

*/

TPM_RC TPM2B_Unmarshal(TPM2B *target, UINT16 targetSize, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_Unmarshalu(target, targetSize, buffer, (uint32_t *)size);
}

TPM_RC TPM_KEY_BITS_Unmarshal(TPM_KEY_BITS *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_KEY_BITS_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM_GENERATED_Unmarshal(TPM_GENERATED *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_GENERATED_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM_ALG_ID_Unmarshal(TPM_ALG_ID *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_ALG_ID_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM_ECC_CURVE_Unmarshal(TPM_ECC_CURVE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_ECC_CURVE_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM_CC_Unmarshal(TPM_RC *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_CC_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM_RC_Unmarshal(TPM_RC *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_RC_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM_CLOCK_ADJUST_Unmarshal(TPM_CLOCK_ADJUST *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_CLOCK_ADJUST_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM_EO_Unmarshal(TPM_EO *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_EO_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM_ST_Unmarshal(TPM_ST *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_ST_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM_SU_Unmarshal(TPM_SU *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_SU_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM_SE_Unmarshal(TPM_SE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_SE_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM_CAP_Unmarshal(TPM_CAP *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_CAP_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM_PT_Unmarshal(TPM_HANDLE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_PT_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM_PT_PCR_Unmarshal(TPM_PT_PCR *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_PT_PCR_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM_HANDLE_Unmarshal(TPM_HANDLE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM_HANDLE_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMA_ALGORITHM_Unmarshal(TPMA_ALGORITHM *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMA_ALGORITHM_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMA_OBJECT_Unmarshal(TPMA_OBJECT *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMA_OBJECT_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMA_SESSION_Unmarshal(TPMA_SESSION *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMA_SESSION_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMA_LOCALITY_Unmarshal(TPMA_LOCALITY *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMA_LOCALITY_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMA_CC_Unmarshal(TPMA_CC *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMA_CC_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMI_YES_NO_Unmarshal(TPMI_YES_NO *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_YES_NO_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMI_DH_OBJECT_Unmarshal(TPMI_DH_OBJECT *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_DH_OBJECT_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

#if 0
TPM_RC TPMI_DH_PARENT_Unmarshal(TPMI_DH_PARENT *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_DH_PARENT_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}
#endif

TPM_RC TPMI_DH_PERSISTENT_Unmarshal(TPMI_DH_PERSISTENT *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_DH_PERSISTENT_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMI_DH_ENTITY_Unmarshal(TPMI_DH_ENTITY *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_DH_ENTITY_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_DH_PCR_Unmarshal(TPMI_DH_PCR *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_DH_PCR_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_SH_AUTH_SESSION_Unmarshal(TPMI_SH_AUTH_SESSION *target, BYTE **buffer, INT32 *size, BOOL allowPwd)
{
    return TSS_TPMI_SH_AUTH_SESSION_Unmarshalu(target, buffer, (uint32_t *)size, allowPwd);
}

TPM_RC TPMI_SH_HMAC_Unmarshal(TPMI_SH_HMAC *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_SH_HMAC_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_SH_POLICY_Unmarshal(TPMI_SH_POLICY *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_SH_POLICY_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_DH_CONTEXT_Unmarshal(TPMI_DH_CONTEXT *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_DH_CONTEXT_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_RH_HIERARCHY_Unmarshal(TPMI_RH_HIERARCHY *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_RH_HIERARCHY_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_RH_ENABLES_Unmarshal(TPMI_RH_ENABLES *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_RH_ENABLES_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_RH_HIERARCHY_AUTH_Unmarshal(TPMI_RH_HIERARCHY_AUTH *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_RH_HIERARCHY_AUTH_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_RH_PLATFORM_Unmarshal(TPMI_RH_PLATFORM *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_RH_PLATFORM_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_RH_ENDORSEMENT_Unmarshal(TPMI_RH_ENDORSEMENT *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_RH_ENDORSEMENT_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_RH_PROVISION_Unmarshal(TPMI_RH_PROVISION *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_RH_PROVISION_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_RH_CLEAR_Unmarshal(TPMI_RH_CLEAR *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_RH_CLEAR_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_RH_NV_AUTH_Unmarshal(TPMI_RH_NV_AUTH *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_RH_NV_AUTH_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_RH_LOCKOUT_Unmarshal(TPMI_RH_LOCKOUT *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_RH_LOCKOUT_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_RH_NV_INDEX_Unmarshal(TPMI_RH_NV_INDEX *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_RH_NV_INDEX_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_ALG_HASH_Unmarshal(TPMI_ALG_HASH *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_ALG_HASH_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_ALG_SYM_Unmarshal(TPMI_ALG_SYM *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_ALG_SYM_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_ALG_SYM_OBJECT_Unmarshal(TPMI_ALG_SYM_OBJECT *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_ALG_SYM_OBJECT_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_ALG_SYM_MODE_Unmarshal(TPMI_ALG_SYM_MODE *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_ALG_SYM_MODE_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_ALG_KDF_Unmarshal(TPMI_ALG_KDF *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_ALG_KDF_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_ALG_SIG_SCHEME_Unmarshal(TPMI_ALG_SIG_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_ALG_SIG_SCHEME_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_ECC_KEY_EXCHANGE_Unmarshal(TPMI_ECC_KEY_EXCHANGE *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_ECC_KEY_EXCHANGE_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_ST_COMMAND_TAG_Unmarshal(TPMI_ST_COMMAND_TAG *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ST_COMMAND_TAG_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMI_ALG_MAC_SCHEME_Unmarshal(TPMI_ALG_MAC_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_ALG_MAC_SCHEME_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_ALG_CIPHER_MODE_Unmarshal(TPMI_ALG_CIPHER_MODE *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_ALG_CIPHER_MODE_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

/* NOTE: Marked as const function in header */

TPM_RC TPMS_EMPTY_Unmarshal(TPMS_EMPTY *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_EMPTY_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMU_HA_Unmarshal(TPMU_HA *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_HA_Unmarshalu(target, buffer, (uint32_t *)size, selector);
}

TPM_RC TPMT_HA_Unmarshal(TPMT_HA *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMT_HA_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPM2B_DIGEST_Unmarshal(TPM2B_DIGEST *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_DIGEST_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_DATA_Unmarshal(TPM2B_DATA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_DATA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_NONCE_Unmarshal(TPM2B_NONCE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_NONCE_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_AUTH_Unmarshal(TPM2B_AUTH *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_AUTH_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_OPERAND_Unmarshal(TPM2B_OPERAND *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_OPERAND_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_EVENT_Unmarshal(TPM2B_EVENT *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_EVENT_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_MAX_BUFFER_Unmarshal(TPM2B_MAX_BUFFER *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_MAX_BUFFER_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_MAX_NV_BUFFER_Unmarshal(TPM2B_MAX_NV_BUFFER *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_MAX_NV_BUFFER_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_TIMEOUT_Unmarshal(TPM2B_TIMEOUT *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_TIMEOUT_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_IV_Unmarshal(TPM2B_IV *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_IV_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_NAME_Unmarshal(TPM2B_NAME *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_NAME_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_PCR_SELECTION_Unmarshal(TPMS_PCR_SELECTION *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_PCR_SELECTION_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMT_TK_CREATION_Unmarshal(TPMT_TK_CREATION *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_TK_CREATION_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMT_TK_VERIFIED_Unmarshal(TPMT_TK_VERIFIED *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_TK_VERIFIED_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMT_TK_AUTH_Unmarshal(TPMT_TK_AUTH *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_TK_AUTH_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMT_TK_HASHCHECK_Unmarshal(TPMT_TK_HASHCHECK *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_TK_HASHCHECK_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_ALG_PROPERTY_Unmarshal(TPMS_ALG_PROPERTY *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_ALG_PROPERTY_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_TAGGED_PROPERTY_Unmarshal(TPMS_TAGGED_PROPERTY *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_TAGGED_PROPERTY_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_TAGGED_PCR_SELECT_Unmarshal(TPMS_TAGGED_PCR_SELECT *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_TAGGED_PCR_SELECT_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPML_CC_Unmarshal(TPML_CC *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_CC_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPML_CCA_Unmarshal(TPML_CCA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_CCA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPML_ALG_Unmarshal(TPML_ALG *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_ALG_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPML_HANDLE_Unmarshal(TPML_HANDLE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_HANDLE_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPML_DIGEST_Unmarshal(TPML_DIGEST *target, BYTE **buffer, INT32 *size,uint32_t minCount)
{
    return TSS_TPML_DIGEST_Unmarshalu(target, buffer, (uint32_t *)size, minCount);
}

TPM_RC TPML_DIGEST_VALUES_Unmarshal(TPML_DIGEST_VALUES *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_DIGEST_VALUES_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPML_PCR_SELECTION_Unmarshal(TPML_PCR_SELECTION *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_PCR_SELECTION_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPML_ALG_PROPERTY_Unmarshal(TPML_ALG_PROPERTY *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_ALG_PROPERTY_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPML_TAGGED_TPM_PROPERTY_Unmarshal(TPML_TAGGED_TPM_PROPERTY  *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_TAGGED_TPM_PROPERTY_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPML_TAGGED_PCR_PROPERTY_Unmarshal(TPML_TAGGED_PCR_PROPERTY  *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_TAGGED_PCR_PROPERTY_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPML_ECC_CURVE_Unmarshal(TPML_ECC_CURVE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_ECC_CURVE_Unmarshalu(target, buffer, (uint32_t *)size);
}

#if 0
TPM_RC TPML_TAGGED_POLICY_Unmarshal(TPML_TAGGED_POLICY *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPML_TAGGED_POLICY_Unmarshalu(target, buffer, (uint32_t *)size);
}
#endif

TPM_RC TPMU_CAPABILITIES_Unmarshal(TPMU_CAPABILITIES *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_CAPABILITIES_Unmarshalu(target, buffer, (uint32_t *)size, selector);
}

TPM_RC TPMS_CLOCK_INFO_Unmarshal(TPMS_CLOCK_INFO *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_CLOCK_INFO_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_TIME_INFO_Unmarshal(TPMS_TIME_INFO *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_TIME_INFO_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_TIME_ATTEST_INFO_Unmarshal(TPMS_TIME_ATTEST_INFO *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_TIME_ATTEST_INFO_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_CERTIFY_INFO_Unmarshal(TPMS_CERTIFY_INFO *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_CERTIFY_INFO_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_QUOTE_INFO_Unmarshal(TPMS_QUOTE_INFO *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_QUOTE_INFO_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_COMMAND_AUDIT_INFO_Unmarshal(TPMS_COMMAND_AUDIT_INFO *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_COMMAND_AUDIT_INFO_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SESSION_AUDIT_INFO_Unmarshal(TPMS_SESSION_AUDIT_INFO *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SESSION_AUDIT_INFO_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_CREATION_INFO_Unmarshal(TPMS_CREATION_INFO *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_CREATION_INFO_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_NV_CERTIFY_INFO_Unmarshal(TPMS_NV_CERTIFY_INFO *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_NV_CERTIFY_INFO_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMI_ST_ATTEST_Unmarshal(TPMI_ST_ATTEST *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ST_ATTEST_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMU_ATTEST_Unmarshal(TPMU_ATTEST *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_ATTEST_Unmarshalu(target, buffer, (uint32_t *)size, selector);
}

TPM_RC TPMS_ATTEST_Unmarshal(TPMS_ATTEST *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_ATTEST_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_ATTEST_Unmarshal(TPM2B_ATTEST *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_ATTEST_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_CAPABILITY_DATA_Unmarshal(TPMS_CAPABILITY_DATA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_CAPABILITY_DATA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_AUTH_RESPONSE_Unmarshal(TPMS_AUTH_RESPONSE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_AUTH_RESPONSE_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMI_AES_KEY_BITS_Unmarshal(TPMI_AES_KEY_BITS *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_AES_KEY_BITS_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMU_SYM_KEY_BITS_Unmarshal(TPMU_SYM_KEY_BITS *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_SYM_KEY_BITS_Unmarshalu(target, buffer, (uint32_t *)size, selector);
}

TPM_RC TPMU_SYM_MODE_Unmarshal(TPMU_SYM_MODE *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_SYM_MODE_Unmarshalu(target, buffer, (uint32_t *)size, selector);
}

TPM_RC TPMT_SYM_DEF_Unmarshal(TPMT_SYM_DEF *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMT_SYM_DEF_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMT_SYM_DEF_OBJECT_Unmarshal(TPMT_SYM_DEF_OBJECT *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMT_SYM_DEF_OBJECT_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPM2B_SYM_KEY_Unmarshal(TPM2B_SYM_KEY *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_SYM_KEY_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SYMCIPHER_PARMS_Unmarshal(TPMS_SYMCIPHER_PARMS *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SYMCIPHER_PARMS_Unmarshalu(target, buffer, (uint32_t *)size);
}

#if 0
TPM_RC TPM2B_LABEL_Unmarshal(TPM2B_LABEL *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_LABEL_Unmarshalu(target, buffer, (uint32_t *)size);
}
#endif

TPM_RC TPM2B_SENSITIVE_DATA_Unmarshal(TPM2B_SENSITIVE_DATA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_SENSITIVE_DATA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SENSITIVE_CREATE_Unmarshal(TPMS_SENSITIVE_CREATE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SENSITIVE_CREATE_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_SENSITIVE_CREATE_Unmarshal(TPM2B_SENSITIVE_CREATE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_SENSITIVE_CREATE_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SCHEME_HASH_Unmarshal(TPMS_SCHEME_HASH *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SCHEME_HASH_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SCHEME_ECDAA_Unmarshal(TPMS_SCHEME_ECDAA *target, BYTE **buffer, INT32 *size) 
{
    return TSS_TPMS_SCHEME_ECDAA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMI_ALG_KEYEDHASH_SCHEME_Unmarshal(TPMI_ALG_KEYEDHASH_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_ALG_KEYEDHASH_SCHEME_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMS_SCHEME_HMAC_Unmarshal(TPMS_SCHEME_HMAC *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SCHEME_HMAC_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SCHEME_XOR_Unmarshal(TPMS_SCHEME_XOR *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SCHEME_XOR_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMU_SCHEME_KEYEDHASH_Unmarshal(TPMU_SCHEME_KEYEDHASH *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_SCHEME_KEYEDHASH_Unmarshalu(target, buffer, (uint32_t *)size, selector);
}

TPM_RC TPMT_KEYEDHASH_SCHEME_Unmarshal(TPMT_KEYEDHASH_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMT_KEYEDHASH_SCHEME_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMS_SIG_SCHEME_ECDAA_Unmarshal(TPMS_SIG_SCHEME_ECDAA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIG_SCHEME_ECDAA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SIG_SCHEME_ECDSA_Unmarshal(TPMS_SIG_SCHEME_ECDSA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIG_SCHEME_ECDSA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SIG_SCHEME_ECSCHNORR_Unmarshal(TPMS_SIG_SCHEME_ECSCHNORR *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIG_SCHEME_ECSCHNORR_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SIG_SCHEME_RSAPSS_Unmarshal(TPMS_SIG_SCHEME_RSAPSS *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIG_SCHEME_RSAPSS_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SIG_SCHEME_RSASSA_Unmarshal(TPMS_SIG_SCHEME_RSASSA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIG_SCHEME_RSASSA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SIG_SCHEME_SM2_Unmarshal(TPMS_SIG_SCHEME_SM2 *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIG_SCHEME_SM2_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMU_SIG_SCHEME_Unmarshal(TPMU_SIG_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_SIG_SCHEME_Unmarshalu(target, buffer, (uint32_t *)size, selector);
}

TPM_RC TPMT_SIG_SCHEME_Unmarshal(TPMT_SIG_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMT_SIG_SCHEME_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMS_ENC_SCHEME_OAEP_Unmarshal(TPMS_ENC_SCHEME_OAEP *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_ENC_SCHEME_OAEP_Unmarshalu(target, buffer, (uint32_t *)size);
}

/* NOTE: Marked as const function in header */

TPM_RC TPMS_ENC_SCHEME_RSAES_Unmarshal(TPMS_ENC_SCHEME_RSAES *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_ENC_SCHEME_RSAES_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_KEY_SCHEME_ECDH_Unmarshal(TPMS_KEY_SCHEME_ECDH *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_KEY_SCHEME_ECDH_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_KEY_SCHEME_ECMQV_Unmarshal(TPMS_KEY_SCHEME_ECMQV *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_KEY_SCHEME_ECMQV_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SCHEME_KDF1_SP800_108_Unmarshal(TPMS_SCHEME_KDF1_SP800_108 *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SCHEME_KDF1_SP800_108_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SCHEME_KDF1_SP800_56A_Unmarshal(TPMS_SCHEME_KDF1_SP800_56A *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SCHEME_KDF1_SP800_56A_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SCHEME_KDF2_Unmarshal(TPMS_SCHEME_KDF2 *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SCHEME_KDF2_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SCHEME_MGF1_Unmarshal(TPMS_SCHEME_MGF1 *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SCHEME_MGF1_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMU_KDF_SCHEME_Unmarshal(TPMU_KDF_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_KDF_SCHEME_Unmarshalu(target, buffer, (uint32_t *)size, selector);
}

TPM_RC TPMT_KDF_SCHEME_Unmarshal(TPMT_KDF_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMT_KDF_SCHEME_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

#if 0
TPM_RC TPMI_ALG_ASYM_SCHEME_Unmarshal(TPMI_ALG_ASYM_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_ALG_ASYM_SCHEME_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}
#endif

TPM_RC TPMU_ASYM_SCHEME_Unmarshal(TPMU_ASYM_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_ASYM_SCHEME_Unmarshalu(target, buffer, (uint32_t *)size, selector);
}

#if 0
TPM_RC TPMT_ASYM_SCHEME_Unmarshal(TPMT_ASYM_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMT_ASYM_SCHEME_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}
#endif

TPM_RC TPMI_ALG_RSA_SCHEME_Unmarshal(TPMI_ALG_RSA_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_ALG_RSA_SCHEME_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMT_RSA_SCHEME_Unmarshal(TPMT_RSA_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMT_RSA_SCHEME_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_ALG_RSA_DECRYPT_Unmarshal(TPMI_ALG_RSA_DECRYPT *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_ALG_RSA_DECRYPT_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMT_RSA_DECRYPT_Unmarshal(TPMT_RSA_DECRYPT *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMT_RSA_DECRYPT_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPM2B_PUBLIC_KEY_RSA_Unmarshal(TPM2B_PUBLIC_KEY_RSA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_PUBLIC_KEY_RSA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMI_RSA_KEY_BITS_Unmarshal(TPMI_RSA_KEY_BITS *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_RSA_KEY_BITS_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_PRIVATE_KEY_RSA_Unmarshal(TPM2B_PRIVATE_KEY_RSA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_PRIVATE_KEY_RSA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_ECC_PARAMETER_Unmarshal(TPM2B_ECC_PARAMETER *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_ECC_PARAMETER_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_ECC_POINT_Unmarshal(TPMS_ECC_POINT *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_ECC_POINT_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_ECC_POINT_Unmarshal(TPM2B_ECC_POINT *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_ECC_POINT_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMI_ALG_ECC_SCHEME_Unmarshal(TPMI_ALG_ECC_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMI_ALG_ECC_SCHEME_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMI_ECC_CURVE_Unmarshal(TPMI_ECC_CURVE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ECC_CURVE_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMT_ECC_SCHEME_Unmarshal(TPMT_ECC_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMT_ECC_SCHEME_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPMS_ALGORITHM_DETAIL_ECC_Unmarshal(TPMS_ALGORITHM_DETAIL_ECC *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_ALGORITHM_DETAIL_ECC_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SIGNATURE_RSA_Unmarshal(TPMS_SIGNATURE_RSA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_RSA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SIGNATURE_RSASSA_Unmarshal(TPMS_SIGNATURE_RSASSA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_RSASSA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SIGNATURE_RSAPSS_Unmarshal(TPMS_SIGNATURE_RSAPSS *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_RSAPSS_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SIGNATURE_ECC_Unmarshal(TPMS_SIGNATURE_ECC *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_ECC_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SIGNATURE_ECDSA_Unmarshal(TPMS_SIGNATURE_ECDSA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_ECDSA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SIGNATURE_ECDAA_Unmarshal(TPMS_SIGNATURE_ECDAA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_ECDAA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SIGNATURE_SM2_Unmarshal(TPMS_SIGNATURE_SM2 *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_SM2_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_SIGNATURE_ECSCHNORR_Unmarshal(TPMS_SIGNATURE_ECSCHNORR *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_SIGNATURE_ECSCHNORR_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMU_SIGNATURE_Unmarshal(TPMU_SIGNATURE *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_SIGNATURE_Unmarshalu(target, buffer, (uint32_t *)size, selector);
}

TPM_RC TPMT_SIGNATURE_Unmarshal(TPMT_SIGNATURE *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMT_SIGNATURE_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPM2B_ENCRYPTED_SECRET_Unmarshal(TPM2B_ENCRYPTED_SECRET *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_ENCRYPTED_SECRET_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMI_ALG_PUBLIC_Unmarshal(TPMI_ALG_PUBLIC *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMI_ALG_PUBLIC_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMU_PUBLIC_ID_Unmarshal(TPMU_PUBLIC_ID *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_PUBLIC_ID_Unmarshalu(target, buffer, (uint32_t *)size, selector);
}

TPM_RC TPMS_KEYEDHASH_PARMS_Unmarshal(TPMS_KEYEDHASH_PARMS *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_KEYEDHASH_PARMS_Unmarshalu(target, buffer, (uint32_t *)size);
}

#if 0
TPM_RC TPMS_ASYM_PARMS_Unmarshal(TPMS_ASYM_PARMS *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_ASYM_PARMS_Unmarshalu(target, buffer, (uint32_t *)size);
}
#endif

TPM_RC TPMS_RSA_PARMS_Unmarshal(TPMS_RSA_PARMS *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_RSA_PARMS_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_ECC_PARMS_Unmarshal(TPMS_ECC_PARMS *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_ECC_PARMS_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMU_PUBLIC_PARMS_Unmarshal(TPMU_PUBLIC_PARMS *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_PUBLIC_PARMS_Unmarshalu(target, buffer, (uint32_t *)size, selector);
}

TPM_RC TPMT_PUBLIC_PARMS_Unmarshal(TPMT_PUBLIC_PARMS *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_PUBLIC_PARMS_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMT_PUBLIC_Unmarshal(TPMT_PUBLIC *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPMT_PUBLIC_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPM2B_PUBLIC_Unmarshal(TPM2B_PUBLIC *target, BYTE **buffer, INT32 *size, BOOL allowNull)
{
    return TSS_TPM2B_PUBLIC_Unmarshalu(target, buffer, (uint32_t *)size, allowNull);
}

TPM_RC TPM2B_TEMPLATE_Unmarshal(TPM2B_TEMPLATE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_TEMPLATE_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMU_SENSITIVE_COMPOSITE_Unmarshal(TPMU_SENSITIVE_COMPOSITE *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    return TSS_TPMU_SENSITIVE_COMPOSITE_Unmarshalu(target, buffer, (uint32_t *)size, selector);
}

TPM_RC TPMT_SENSITIVE_Unmarshal(TPMT_SENSITIVE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMT_SENSITIVE_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_SENSITIVE_Unmarshal(TPM2B_SENSITIVE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_SENSITIVE_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_PRIVATE_Unmarshal(TPM2B_PRIVATE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_PRIVATE_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_ID_OBJECT_Unmarshal(TPM2B_ID_OBJECT *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_ID_OBJECT_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMA_NV_Unmarshal(TPMA_NV *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMA_NV_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_NV_PUBLIC_Unmarshal(TPMS_NV_PUBLIC *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_NV_PUBLIC_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_NV_PUBLIC_Unmarshal(TPM2B_NV_PUBLIC *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_NV_PUBLIC_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_CONTEXT_SENSITIVE_Unmarshal(TPM2B_CONTEXT_SENSITIVE *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_CONTEXT_SENSITIVE_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_CONTEXT_DATA_Unmarshal(TPMS_CONTEXT_DATA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_CONTEXT_DATA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_CONTEXT_DATA_Unmarshal(TPM2B_CONTEXT_DATA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_CONTEXT_DATA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_CONTEXT_Unmarshal(TPMS_CONTEXT *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_CONTEXT_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPMS_CREATION_DATA_Unmarshal(TPMS_CREATION_DATA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPMS_CREATION_DATA_Unmarshalu(target, buffer, (uint32_t *)size);
}

TPM_RC TPM2B_CREATION_DATA_Unmarshal(TPM2B_CREATION_DATA *target, BYTE **buffer, INT32 *size)
{
    return TSS_TPM2B_CREATION_DATA_Unmarshalu(target, buffer, (uint32_t *)size);
}

#endif 	/* TPM_TSS_NOCMDCHECK */

#endif /* TPM_TPM20 */
