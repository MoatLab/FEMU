/********************************************************************************/
/*										*/
/*			   Unmarshal Functions  				*/
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
/*  (c) Copyright IBM Corp. and others, 2012-2019				*/
/*										*/
/********************************************************************************/

/* The functions with the TSS_ prefix are preferred.  They use an unsigned size.  The functions
   without the prefix are deprecated.  */

#ifndef UNMARSHAL_FP_H
#define UNMARSHAL_FP_H

#include "TPM_Types.h"

#ifdef __cplusplus
extern "C" {
#endif

    LIB_EXPORT TPM_RC
    TSS_UINT8_Unmarshalu(UINT8 *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_INT8_Unmarshalu(INT8 *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_UINT16_Unmarshalu(UINT16 *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_UINT32_Unmarshalu(UINT32 *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_INT32_Unmarshalu(INT32 *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_UINT64_Unmarshalu(UINT64 *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_Array_Unmarshalu(BYTE *targetBuffer, UINT16 targetSize, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_Unmarshalu(TPM2B *target, UINT16 targetSize, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_KEY_BITS_Unmarshalu(TPM_KEY_BITS *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_GENERATED_Unmarshalu(TPM_GENERATED *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_ALG_ID_Unmarshalu(TPM_ALG_ID *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_ECC_CURVE_Unmarshalu(TPM_ECC_CURVE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_CC_Unmarshalu(TPM_RC *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_RC_Unmarshalu(TPM_RC *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_CLOCK_ADJUST_Unmarshalu(TPM_CLOCK_ADJUST *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_EO_Unmarshalu(TPM_EO *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_ST_Unmarshalu(TPM_ST *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_SU_Unmarshalu(TPM_SU *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_SE_Unmarshalu(TPM_SE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_CAP_Unmarshalu(TPM_CAP *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_PT_Unmarshalu(TPM_HANDLE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_PT_PCR_Unmarshalu(TPM_PT_PCR *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM_HANDLE_Unmarshalu(TPM_HANDLE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_ALGORITHM_Unmarshalu(TPMA_ALGORITHM *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_OBJECT_Unmarshalu(TPMA_OBJECT *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_SESSION_Unmarshalu(TPMA_SESSION *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_LOCALITY_Unmarshalu(TPMA_LOCALITY *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_CC_Unmarshalu(TPMA_CC *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_YES_NO_Unmarshalu(TPMI_YES_NO *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_OBJECT_Unmarshalu(TPMI_DH_OBJECT *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_PARENT_Unmarshalu(TPMI_DH_PARENT *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_PERSISTENT_Unmarshalu(TPMI_DH_PERSISTENT *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_ENTITY_Unmarshalu(TPMI_DH_ENTITY *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_PCR_Unmarshalu(TPMI_DH_PCR *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_SH_AUTH_SESSION_Unmarshalu(TPMI_SH_AUTH_SESSION *target, BYTE **buffer, uint32_t *size, BOOL allowPwd);
    LIB_EXPORT TPM_RC
    TSS_TPMI_SH_HMAC_Unmarshalu(TPMI_SH_HMAC *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_SH_POLICY_Unmarshalu(TPMI_SH_POLICY *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_CONTEXT_Unmarshalu(TPMI_DH_CONTEXT *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_DH_SAVED_Unmarshalu(TPMI_DH_SAVED *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_HIERARCHY_Unmarshalu(TPMI_RH_HIERARCHY *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_ENABLES_Unmarshalu(TPMI_RH_ENABLES *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_HIERARCHY_AUTH_Unmarshalu(TPMI_RH_HIERARCHY_AUTH *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_PLATFORM_Unmarshalu(TPMI_RH_PLATFORM *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_ENDORSEMENT_Unmarshalu(TPMI_RH_ENDORSEMENT *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_PROVISION_Unmarshalu(TPMI_RH_PROVISION *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_CLEAR_Unmarshalu(TPMI_RH_CLEAR *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_NV_AUTH_Unmarshalu(TPMI_RH_NV_AUTH *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_LOCKOUT_Unmarshalu(TPMI_RH_LOCKOUT *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RH_NV_INDEX_Unmarshalu(TPMI_RH_NV_INDEX *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_HASH_Unmarshalu(TPMI_ALG_HASH *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_SYM_Unmarshalu(TPMI_ALG_SYM *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_SYM_OBJECT_Unmarshalu(TPMI_ALG_SYM_OBJECT *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_SYM_MODE_Unmarshalu(TPMI_ALG_SYM_MODE *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_KDF_Unmarshalu(TPMI_ALG_KDF *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_SIG_SCHEME_Unmarshalu(TPMI_ALG_SIG_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ECC_KEY_EXCHANGE_Unmarshalu(TPMI_ECC_KEY_EXCHANGE *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ST_COMMAND_TAG_Unmarshalu(TPMI_ST_COMMAND_TAG *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_MAC_SCHEME_Unmarshalu(TPMI_ALG_MAC_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_CIPHER_MODE_Unmarshalu(TPMI_ALG_CIPHER_MODE *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMS_EMPTY_Unmarshalu(TPMS_EMPTY *target, BYTE **buffer, uint32_t *size)
#ifdef __ULTRAVISOR__
	__attribute__ ((const))
#endif
	;
    LIB_EXPORT TPM_RC
    TSS_TPMU_HA_Unmarshalu(TPMU_HA *target, BYTE **buffer, uint32_t *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_HA_Unmarshalu(TPMT_HA *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_DIGEST_Unmarshalu(TPM2B_DIGEST *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_DATA_Unmarshalu(TPM2B_DATA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_NONCE_Unmarshalu(TPM2B_NONCE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_AUTH_Unmarshalu(TPM2B_AUTH *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_OPERAND_Unmarshalu(TPM2B_OPERAND *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_EVENT_Unmarshalu(TPM2B_EVENT *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_MAX_BUFFER_Unmarshalu(TPM2B_MAX_BUFFER *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_MAX_NV_BUFFER_Unmarshalu(TPM2B_MAX_NV_BUFFER *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_TIMEOUT_Unmarshalu(TPM2B_TIMEOUT *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_IV_Unmarshalu(TPM2B_IV *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_NAME_Unmarshalu(TPM2B_NAME *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_PCR_SELECTION_Unmarshalu(TPMS_PCR_SELECTION *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_TK_CREATION_Unmarshalu(TPMT_TK_CREATION *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_TK_VERIFIED_Unmarshalu(TPMT_TK_VERIFIED *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_TK_AUTH_Unmarshalu(TPMT_TK_AUTH *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_TK_HASHCHECK_Unmarshalu(TPMT_TK_HASHCHECK *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ALG_PROPERTY_Unmarshalu(TPMS_ALG_PROPERTY *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_TAGGED_PROPERTY_Unmarshalu(TPMS_TAGGED_PROPERTY *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_TAGGED_PCR_SELECT_Unmarshalu(TPMS_TAGGED_PCR_SELECT *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_CC_Unmarshalu(TPML_CC *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_TAGGED_POLICY_Unmarshalu(TPMS_TAGGED_POLICY *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_CCA_Unmarshalu(TPML_CCA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_ALG_Unmarshalu(TPML_ALG *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_HANDLE_Unmarshalu(TPML_HANDLE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_DIGEST_Unmarshalu(TPML_DIGEST *target, BYTE **buffer, uint32_t *size ,uint32_t minCount);
    LIB_EXPORT TPM_RC
    TSS_TPML_DIGEST_VALUES_Unmarshalu(TPML_DIGEST_VALUES *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_PCR_SELECTION_Unmarshalu(TPML_PCR_SELECTION *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_ALG_PROPERTY_Unmarshalu(TPML_ALG_PROPERTY *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_TAGGED_TPM_PROPERTY_Unmarshalu(TPML_TAGGED_TPM_PROPERTY  *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_TAGGED_PCR_PROPERTY_Unmarshalu(TPML_TAGGED_PCR_PROPERTY  *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_ECC_CURVE_Unmarshalu(TPML_ECC_CURVE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPML_TAGGED_POLICY_Unmarshalu(TPML_TAGGED_POLICY *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_CAPABILITIES_Unmarshalu(TPMU_CAPABILITIES *target, BYTE **buffer, uint32_t *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CLOCK_INFO_Unmarshalu(TPMS_CLOCK_INFO *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_TIME_INFO_Unmarshalu(TPMS_TIME_INFO *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_TIME_ATTEST_INFO_Unmarshalu(TPMS_TIME_ATTEST_INFO *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CERTIFY_INFO_Unmarshalu(TPMS_CERTIFY_INFO *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_QUOTE_INFO_Unmarshalu(TPMS_QUOTE_INFO *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_COMMAND_AUDIT_INFO_Unmarshalu(TPMS_COMMAND_AUDIT_INFO *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SESSION_AUDIT_INFO_Unmarshalu(TPMS_SESSION_AUDIT_INFO *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CREATION_INFO_Unmarshalu(TPMS_CREATION_INFO *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_NV_CERTIFY_INFO_Unmarshalu(TPMS_NV_CERTIFY_INFO *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_NV_DIGEST_CERTIFY_INFO_Unmarshalu(TPMS_NV_DIGEST_CERTIFY_INFO *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ST_ATTEST_Unmarshalu(TPMI_ST_ATTEST *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_ATTEST_Unmarshalu(TPMU_ATTEST *target, BYTE **buffer, uint32_t *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ATTEST_Unmarshalu(TPMS_ATTEST *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_ATTEST_Unmarshalu(TPM2B_ATTEST *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CAPABILITY_DATA_Unmarshalu(TPMS_CAPABILITY_DATA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_AUTH_RESPONSE_Unmarshalu(TPMS_AUTH_RESPONSE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_AES_KEY_BITS_Unmarshalu(TPMI_AES_KEY_BITS *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SYM_KEY_BITS_Unmarshalu(TPMU_SYM_KEY_BITS *target, BYTE **buffer, uint32_t *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SYM_MODE_Unmarshalu(TPMU_SYM_MODE *target, BYTE **buffer, uint32_t *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_SYM_DEF_Unmarshalu(TPMT_SYM_DEF *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMT_SYM_DEF_OBJECT_Unmarshalu(TPMT_SYM_DEF_OBJECT *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_SYM_KEY_Unmarshalu(TPM2B_SYM_KEY *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SYMCIPHER_PARMS_Unmarshalu(TPMS_SYMCIPHER_PARMS *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_LABEL_Unmarshalu(TPM2B_LABEL *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_SENSITIVE_DATA_Unmarshalu(TPM2B_SENSITIVE_DATA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SENSITIVE_CREATE_Unmarshalu(TPMS_SENSITIVE_CREATE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_SENSITIVE_CREATE_Unmarshalu(TPM2B_SENSITIVE_CREATE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_HASH_Unmarshalu(TPMS_SCHEME_HASH *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_ECDAA_Unmarshalu(TPMS_SCHEME_ECDAA *target, BYTE **buffer, uint32_t *size) ;
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_KEYEDHASH_SCHEME_Unmarshalu(TPMI_ALG_KEYEDHASH_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_HMAC_Unmarshalu(TPMS_SCHEME_HMAC *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_XOR_Unmarshalu(TPMS_SCHEME_XOR *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SCHEME_KEYEDHASH_Unmarshalu(TPMU_SCHEME_KEYEDHASH *target, BYTE **buffer, uint32_t *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_KEYEDHASH_SCHEME_Unmarshalu(TPMT_KEYEDHASH_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_ECDAA_Unmarshalu(TPMS_SIG_SCHEME_ECDAA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_ECDSA_Unmarshalu(TPMS_SIG_SCHEME_ECDSA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_ECSCHNORR_Unmarshalu(TPMS_SIG_SCHEME_ECSCHNORR *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_RSAPSS_Unmarshalu(TPMS_SIG_SCHEME_RSAPSS *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_RSASSA_Unmarshalu(TPMS_SIG_SCHEME_RSASSA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIG_SCHEME_SM2_Unmarshalu(TPMS_SIG_SCHEME_SM2 *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SIG_SCHEME_Unmarshalu(TPMU_SIG_SCHEME *target, BYTE **buffer, uint32_t *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_SIG_SCHEME_Unmarshalu(TPMT_SIG_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ENC_SCHEME_OAEP_Unmarshalu(TPMS_ENC_SCHEME_OAEP *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ENC_SCHEME_RSAES_Unmarshalu(TPMS_ENC_SCHEME_RSAES *target, BYTE **buffer, uint32_t *size)
#ifdef __ULTRAVISOR__
	__attribute__ ((const))
#endif
	;
    LIB_EXPORT TPM_RC
    TSS_TPMS_KEY_SCHEME_ECDH_Unmarshalu(TPMS_KEY_SCHEME_ECDH *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_KEY_SCHEME_ECMQV_Unmarshalu(TPMS_KEY_SCHEME_ECMQV *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_KDF1_SP800_108_Unmarshalu(TPMS_SCHEME_KDF1_SP800_108 *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_KDF1_SP800_56A_Unmarshalu(TPMS_SCHEME_KDF1_SP800_56A *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_KDF2_Unmarshalu(TPMS_SCHEME_KDF2 *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SCHEME_MGF1_Unmarshalu(TPMS_SCHEME_MGF1 *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_KDF_SCHEME_Unmarshalu(TPMU_KDF_SCHEME *target, BYTE **buffer, uint32_t *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_KDF_SCHEME_Unmarshalu(TPMT_KDF_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_ASYM_SCHEME_Unmarshalu(TPMI_ALG_ASYM_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMU_ASYM_SCHEME_Unmarshalu(TPMU_ASYM_SCHEME *target, BYTE **buffer, uint32_t *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_ASYM_SCHEME_Unmarshalu(TPMT_ASYM_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_RSA_SCHEME_Unmarshalu(TPMI_ALG_RSA_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMT_RSA_SCHEME_Unmarshalu(TPMT_RSA_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_RSA_DECRYPT_Unmarshalu(TPMI_ALG_RSA_DECRYPT *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMT_RSA_DECRYPT_Unmarshalu(TPMT_RSA_DECRYPT *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_PUBLIC_KEY_RSA_Unmarshalu(TPM2B_PUBLIC_KEY_RSA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_RSA_KEY_BITS_Unmarshalu(TPMI_RSA_KEY_BITS *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_PRIVATE_KEY_RSA_Unmarshalu(TPM2B_PRIVATE_KEY_RSA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_ECC_PARAMETER_Unmarshalu(TPM2B_ECC_PARAMETER *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ECC_POINT_Unmarshalu(TPMS_ECC_POINT *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_ECC_POINT_Unmarshalu(TPM2B_ECC_POINT *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_ECC_SCHEME_Unmarshalu(TPMI_ALG_ECC_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ECC_CURVE_Unmarshalu(TPMI_ECC_CURVE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_ECC_SCHEME_Unmarshalu(TPMT_ECC_SCHEME *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ALGORITHM_DETAIL_ECC_Unmarshalu(TPMS_ALGORITHM_DETAIL_ECC *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_RSA_Unmarshalu(TPMS_SIGNATURE_RSA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_RSASSA_Unmarshalu(TPMS_SIGNATURE_RSASSA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_RSAPSS_Unmarshalu(TPMS_SIGNATURE_RSAPSS *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_ECC_Unmarshalu(TPMS_SIGNATURE_ECC *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_ECDSA_Unmarshalu(TPMS_SIGNATURE_ECDSA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_ECDAA_Unmarshalu(TPMS_SIGNATURE_ECDAA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_SM2_Unmarshalu(TPMS_SIGNATURE_SM2 *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_SIGNATURE_ECSCHNORR_Unmarshalu(TPMS_SIGNATURE_ECSCHNORR *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SIGNATURE_Unmarshalu(TPMU_SIGNATURE *target, BYTE **buffer, uint32_t *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_SIGNATURE_Unmarshalu(TPMT_SIGNATURE *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_ENCRYPTED_SECRET_Unmarshalu(TPM2B_ENCRYPTED_SECRET *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMI_ALG_PUBLIC_Unmarshalu(TPMI_ALG_PUBLIC *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_PUBLIC_ID_Unmarshalu(TPMU_PUBLIC_ID *target, BYTE **buffer, uint32_t *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMS_KEYEDHASH_PARMS_Unmarshalu(TPMS_KEYEDHASH_PARMS *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ASYM_PARMS_Unmarshalu(TPMS_ASYM_PARMS *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_RSA_PARMS_Unmarshalu(TPMS_RSA_PARMS *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_ECC_PARMS_Unmarshalu(TPMS_ECC_PARMS *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_PUBLIC_PARMS_Unmarshalu(TPMU_PUBLIC_PARMS *target, BYTE **buffer, uint32_t *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_PUBLIC_PARMS_Unmarshalu(TPMT_PUBLIC_PARMS *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMT_PUBLIC_Unmarshalu(TPMT_PUBLIC *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_PUBLIC_Unmarshalu(TPM2B_PUBLIC *target, BYTE **buffer, uint32_t *size, BOOL allowNull);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_TEMPLATE_Unmarshalu(TPM2B_TEMPLATE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMU_SENSITIVE_COMPOSITE_Unmarshalu(TPMU_SENSITIVE_COMPOSITE *target, BYTE **buffer, uint32_t *size, UINT32 selector);
    LIB_EXPORT TPM_RC
    TSS_TPMT_SENSITIVE_Unmarshalu(TPMT_SENSITIVE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_SENSITIVE_Unmarshalu(TPM2B_SENSITIVE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_PRIVATE_Unmarshalu(TPM2B_PRIVATE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_ID_OBJECT_Unmarshalu(TPM2B_ID_OBJECT *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMA_NV_Unmarshalu(TPMA_NV *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_NV_PUBLIC_Unmarshalu(TPMS_NV_PUBLIC *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_NV_PUBLIC_Unmarshalu(TPM2B_NV_PUBLIC *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_CONTEXT_SENSITIVE_Unmarshalu(TPM2B_CONTEXT_SENSITIVE *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CONTEXT_DATA_Unmarshalu(TPMS_CONTEXT_DATA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_CONTEXT_DATA_Unmarshalu(TPM2B_CONTEXT_DATA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CONTEXT_Unmarshalu(TPMS_CONTEXT *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPMS_CREATION_DATA_Unmarshalu(TPMS_CREATION_DATA *target, BYTE **buffer, uint32_t *size);
    LIB_EXPORT TPM_RC
    TSS_TPM2B_CREATION_DATA_Unmarshalu(TPM2B_CREATION_DATA *target, BYTE **buffer, uint32_t *size);

    /* These functions are deprecated.  They were adapted from the TPM side, but the signed size
       caused static analysis tool warnings. */
    
    TPM_RC UINT8_Unmarshal(UINT8 *target, BYTE **buffer, INT32 *size);
    TPM_RC INT8_Unmarshal(INT8 *target, BYTE **buffer, INT32 *size);
    TPM_RC UINT16_Unmarshal(UINT16 *target, BYTE **buffer, INT32 *size);
    TPM_RC UINT32_Unmarshal(UINT32 *target, BYTE **buffer, INT32 *size);
    TPM_RC INT32_Unmarshal(INT32 *target, BYTE **buffer, INT32 *size);
    TPM_RC UINT64_Unmarshal(UINT64 *target, BYTE **buffer, INT32 *size);
    TPM_RC Array_Unmarshal(BYTE *targetBuffer, UINT16 targetSize, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_Unmarshal(TPM2B *target, UINT16 targetSize, BYTE **buffer, INT32 *size);
    TPM_RC TPM_KEY_BITS_Unmarshal(TPM_KEY_BITS *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM_GENERATED_Unmarshal(TPM_GENERATED *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM_ALG_ID_Unmarshal(TPM_ALG_ID *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM_ECC_CURVE_Unmarshal(TPM_ECC_CURVE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM_CC_Unmarshal(TPM_RC *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM_RC_Unmarshal(TPM_RC *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM_CLOCK_ADJUST_Unmarshal(TPM_CLOCK_ADJUST *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM_EO_Unmarshal(TPM_EO *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM_ST_Unmarshal(TPM_ST *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM_SU_Unmarshal(TPM_SU *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM_SE_Unmarshal(TPM_SE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM_CAP_Unmarshal(TPM_CAP *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM_PT_Unmarshal(TPM_HANDLE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM_PT_PCR_Unmarshal(TPM_PT_PCR *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM_HANDLE_Unmarshal(TPM_HANDLE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMA_ALGORITHM_Unmarshal(TPMA_ALGORITHM *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMA_OBJECT_Unmarshal(TPMA_OBJECT *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMA_SESSION_Unmarshal(TPMA_SESSION *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMA_LOCALITY_Unmarshal(TPMA_LOCALITY *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMA_CC_Unmarshal(TPMA_CC *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMI_YES_NO_Unmarshal(TPMI_YES_NO *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMI_DH_OBJECT_Unmarshal(TPMI_DH_OBJECT *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_DH_PARENT_Unmarshal(TPMI_DH_PARENT *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_DH_PERSISTENT_Unmarshal(TPMI_DH_PERSISTENT *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMI_DH_ENTITY_Unmarshal(TPMI_DH_ENTITY *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_DH_PCR_Unmarshal(TPMI_DH_PCR *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_SH_AUTH_SESSION_Unmarshal(TPMI_SH_AUTH_SESSION *target, BYTE **buffer, INT32 *size, BOOL allowPwd);
    TPM_RC TPMI_SH_HMAC_Unmarshal(TPMI_SH_HMAC *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_SH_POLICY_Unmarshal(TPMI_SH_POLICY *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_DH_CONTEXT_Unmarshal(TPMI_DH_CONTEXT *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_RH_HIERARCHY_Unmarshal(TPMI_RH_HIERARCHY *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_RH_ENABLES_Unmarshal(TPMI_RH_ENABLES *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_RH_HIERARCHY_AUTH_Unmarshal(TPMI_RH_HIERARCHY_AUTH *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_RH_PLATFORM_Unmarshal(TPMI_RH_PLATFORM *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_RH_ENDORSEMENT_Unmarshal(TPMI_RH_ENDORSEMENT *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_RH_PROVISION_Unmarshal(TPMI_RH_PROVISION *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_RH_CLEAR_Unmarshal(TPMI_RH_CLEAR *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_RH_NV_AUTH_Unmarshal(TPMI_RH_NV_AUTH *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_RH_LOCKOUT_Unmarshal(TPMI_RH_LOCKOUT *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_RH_NV_INDEX_Unmarshal(TPMI_RH_NV_INDEX *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_ALG_HASH_Unmarshal(TPMI_ALG_HASH *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_ALG_SYM_Unmarshal(TPMI_ALG_SYM *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_ALG_SYM_OBJECT_Unmarshal(TPMI_ALG_SYM_OBJECT *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_ALG_SYM_MODE_Unmarshal(TPMI_ALG_SYM_MODE *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_ALG_KDF_Unmarshal(TPMI_ALG_KDF *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_ALG_SIG_SCHEME_Unmarshal(TPMI_ALG_SIG_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_ECC_KEY_EXCHANGE_Unmarshal(TPMI_ECC_KEY_EXCHANGE *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_ST_COMMAND_TAG_Unmarshal(TPMI_ST_COMMAND_TAG *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMI_ALG_MAC_SCHEME_Unmarshal(TPMI_ALG_MAC_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_ALG_CIPHER_MODE_Unmarshal(TPMI_ALG_CIPHER_MODE *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMS_EMPTY_Unmarshal(TPMS_EMPTY *target, BYTE **buffer, INT32 *size)
#ifdef __ULTRAVISOR__
	__attribute__ ((const))
#endif
	;
    TPM_RC TPMU_HA_Unmarshal(TPMU_HA *target, BYTE **buffer, INT32 *size, UINT32 selector);
    TPM_RC TPMT_HA_Unmarshal(TPMT_HA *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPM2B_DIGEST_Unmarshal(TPM2B_DIGEST *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_DATA_Unmarshal(TPM2B_DATA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_NONCE_Unmarshal(TPM2B_NONCE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_AUTH_Unmarshal(TPM2B_AUTH *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_OPERAND_Unmarshal(TPM2B_OPERAND *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_EVENT_Unmarshal(TPM2B_EVENT *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_MAX_BUFFER_Unmarshal(TPM2B_MAX_BUFFER *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_MAX_NV_BUFFER_Unmarshal(TPM2B_MAX_NV_BUFFER *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_TIMEOUT_Unmarshal(TPM2B_TIMEOUT *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_IV_Unmarshal(TPM2B_IV *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_NAME_Unmarshal(TPM2B_NAME *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_PCR_SELECTION_Unmarshal(TPMS_PCR_SELECTION *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMT_TK_CREATION_Unmarshal(TPMT_TK_CREATION *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMT_TK_VERIFIED_Unmarshal(TPMT_TK_VERIFIED *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMT_TK_AUTH_Unmarshal(TPMT_TK_AUTH *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMT_TK_HASHCHECK_Unmarshal(TPMT_TK_HASHCHECK *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_ALG_PROPERTY_Unmarshal(TPMS_ALG_PROPERTY *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_TAGGED_PROPERTY_Unmarshal(TPMS_TAGGED_PROPERTY *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_TAGGED_PCR_SELECT_Unmarshal(TPMS_TAGGED_PCR_SELECT *target, BYTE **buffer, INT32 *size);
    TPM_RC TPML_CC_Unmarshal(TPML_CC *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_TAGGED_POLICY_Unmarshal(TPMS_TAGGED_POLICY *target, BYTE **buffer, INT32 *size);
    TPM_RC TPML_CCA_Unmarshal(TPML_CCA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPML_ALG_Unmarshal(TPML_ALG *target, BYTE **buffer, INT32 *size);
    TPM_RC TPML_HANDLE_Unmarshal(TPML_HANDLE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPML_DIGEST_Unmarshal(TPML_DIGEST *target, BYTE **buffer, INT32 *size,uint32_t minCount);
    TPM_RC TPML_DIGEST_VALUES_Unmarshal(TPML_DIGEST_VALUES *target, BYTE **buffer, INT32 *size);
    TPM_RC TPML_PCR_SELECTION_Unmarshal(TPML_PCR_SELECTION *target, BYTE **buffer, INT32 *size);
    TPM_RC TPML_ALG_PROPERTY_Unmarshal(TPML_ALG_PROPERTY *target, BYTE **buffer, INT32 *size);
    TPM_RC TPML_TAGGED_TPM_PROPERTY_Unmarshal(TPML_TAGGED_TPM_PROPERTY  *target, BYTE **buffer, INT32 *size);
    TPM_RC TPML_TAGGED_PCR_PROPERTY_Unmarshal(TPML_TAGGED_PCR_PROPERTY  *target, BYTE **buffer, INT32 *size);
    TPM_RC TPML_ECC_CURVE_Unmarshal(TPML_ECC_CURVE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPML_TAGGED_POLICY_Unmarshal(TPML_TAGGED_POLICY *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMU_CAPABILITIES_Unmarshal(TPMU_CAPABILITIES *target, BYTE **buffer, INT32 *size, UINT32 selector);
    TPM_RC TPMS_CLOCK_INFO_Unmarshal(TPMS_CLOCK_INFO *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_TIME_INFO_Unmarshal(TPMS_TIME_INFO *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_TIME_ATTEST_INFO_Unmarshal(TPMS_TIME_ATTEST_INFO *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_CERTIFY_INFO_Unmarshal(TPMS_CERTIFY_INFO *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_QUOTE_INFO_Unmarshal(TPMS_QUOTE_INFO *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_COMMAND_AUDIT_INFO_Unmarshal(TPMS_COMMAND_AUDIT_INFO *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SESSION_AUDIT_INFO_Unmarshal(TPMS_SESSION_AUDIT_INFO *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_CREATION_INFO_Unmarshal(TPMS_CREATION_INFO *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_NV_CERTIFY_INFO_Unmarshal(TPMS_NV_CERTIFY_INFO *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMI_ST_ATTEST_Unmarshal(TPMI_ST_ATTEST *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMU_ATTEST_Unmarshal(TPMU_ATTEST *target, BYTE **buffer, INT32 *size, UINT32 selector);
    TPM_RC TPMS_ATTEST_Unmarshal(TPMS_ATTEST *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_ATTEST_Unmarshal(TPM2B_ATTEST *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_CAPABILITY_DATA_Unmarshal(TPMS_CAPABILITY_DATA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_AUTH_RESPONSE_Unmarshal(TPMS_AUTH_RESPONSE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMI_AES_KEY_BITS_Unmarshal(TPMI_AES_KEY_BITS *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMU_SYM_KEY_BITS_Unmarshal(TPMU_SYM_KEY_BITS *target, BYTE **buffer, INT32 *size, UINT32 selector);
    TPM_RC TPMU_SYM_MODE_Unmarshal(TPMU_SYM_MODE *target, BYTE **buffer, INT32 *size, UINT32 selector);
    TPM_RC TPMT_SYM_DEF_Unmarshal(TPMT_SYM_DEF *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMT_SYM_DEF_OBJECT_Unmarshal(TPMT_SYM_DEF_OBJECT *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPM2B_SYM_KEY_Unmarshal(TPM2B_SYM_KEY *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SYMCIPHER_PARMS_Unmarshal(TPMS_SYMCIPHER_PARMS *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_LABEL_Unmarshal(TPM2B_LABEL *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_SENSITIVE_DATA_Unmarshal(TPM2B_SENSITIVE_DATA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SENSITIVE_CREATE_Unmarshal(TPMS_SENSITIVE_CREATE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_SENSITIVE_CREATE_Unmarshal(TPM2B_SENSITIVE_CREATE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SCHEME_HASH_Unmarshal(TPMS_SCHEME_HASH *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SCHEME_ECDAA_Unmarshal(TPMS_SCHEME_ECDAA *target, BYTE **buffer, INT32 *size) ;
    TPM_RC TPMI_ALG_KEYEDHASH_SCHEME_Unmarshal(TPMI_ALG_KEYEDHASH_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMS_SCHEME_HMAC_Unmarshal(TPMS_SCHEME_HMAC *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SCHEME_XOR_Unmarshal(TPMS_SCHEME_XOR *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMU_SCHEME_KEYEDHASH_Unmarshal(TPMU_SCHEME_KEYEDHASH *target, BYTE **buffer, INT32 *size, UINT32 selector);
    TPM_RC TPMT_KEYEDHASH_SCHEME_Unmarshal(TPMT_KEYEDHASH_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMS_SIG_SCHEME_ECDAA_Unmarshal(TPMS_SIG_SCHEME_ECDAA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SIG_SCHEME_ECDSA_Unmarshal(TPMS_SIG_SCHEME_ECDSA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SIG_SCHEME_ECSCHNORR_Unmarshal(TPMS_SIG_SCHEME_ECSCHNORR *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SIG_SCHEME_RSAPSS_Unmarshal(TPMS_SIG_SCHEME_RSAPSS *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SIG_SCHEME_RSASSA_Unmarshal(TPMS_SIG_SCHEME_RSASSA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SIG_SCHEME_SM2_Unmarshal(TPMS_SIG_SCHEME_SM2 *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMU_SIG_SCHEME_Unmarshal(TPMU_SIG_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector);
    TPM_RC TPMT_SIG_SCHEME_Unmarshal(TPMT_SIG_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMS_ENC_SCHEME_OAEP_Unmarshal(TPMS_ENC_SCHEME_OAEP *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_ENC_SCHEME_RSAES_Unmarshal(TPMS_ENC_SCHEME_RSAES *target, BYTE **buffer, INT32 *size)
#ifdef __ULTRAVISOR__
	__attribute__ ((const))
#endif
	;
    TPM_RC TPMS_KEY_SCHEME_ECDH_Unmarshal(TPMS_KEY_SCHEME_ECDH *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_KEY_SCHEME_ECMQV_Unmarshal(TPMS_KEY_SCHEME_ECMQV *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SCHEME_KDF1_SP800_108_Unmarshal(TPMS_SCHEME_KDF1_SP800_108 *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SCHEME_KDF1_SP800_56A_Unmarshal(TPMS_SCHEME_KDF1_SP800_56A *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SCHEME_KDF2_Unmarshal(TPMS_SCHEME_KDF2 *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SCHEME_MGF1_Unmarshal(TPMS_SCHEME_MGF1 *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMU_KDF_SCHEME_Unmarshal(TPMU_KDF_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector);
    TPM_RC TPMT_KDF_SCHEME_Unmarshal(TPMT_KDF_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_ALG_ASYM_SCHEME_Unmarshal(TPMI_ALG_ASYM_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMU_ASYM_SCHEME_Unmarshal(TPMU_ASYM_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector);
    TPM_RC TPMT_ASYM_SCHEME_Unmarshal(TPMT_ASYM_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_ALG_RSA_SCHEME_Unmarshal(TPMI_ALG_RSA_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMT_RSA_SCHEME_Unmarshal(TPMT_RSA_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_ALG_RSA_DECRYPT_Unmarshal(TPMI_ALG_RSA_DECRYPT *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMT_RSA_DECRYPT_Unmarshal(TPMT_RSA_DECRYPT *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPM2B_PUBLIC_KEY_RSA_Unmarshal(TPM2B_PUBLIC_KEY_RSA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMI_RSA_KEY_BITS_Unmarshal(TPMI_RSA_KEY_BITS *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_PRIVATE_KEY_RSA_Unmarshal(TPM2B_PRIVATE_KEY_RSA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_ECC_PARAMETER_Unmarshal(TPM2B_ECC_PARAMETER *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_ECC_POINT_Unmarshal(TPMS_ECC_POINT *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_ECC_POINT_Unmarshal(TPM2B_ECC_POINT *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMI_ALG_ECC_SCHEME_Unmarshal(TPMI_ALG_ECC_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMI_ECC_CURVE_Unmarshal(TPMI_ECC_CURVE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMT_ECC_SCHEME_Unmarshal(TPMT_ECC_SCHEME *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPMS_ALGORITHM_DETAIL_ECC_Unmarshal(TPMS_ALGORITHM_DETAIL_ECC *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SIGNATURE_RSA_Unmarshal(TPMS_SIGNATURE_RSA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SIGNATURE_RSASSA_Unmarshal(TPMS_SIGNATURE_RSASSA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SIGNATURE_RSAPSS_Unmarshal(TPMS_SIGNATURE_RSAPSS *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SIGNATURE_ECC_Unmarshal(TPMS_SIGNATURE_ECC *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SIGNATURE_ECDSA_Unmarshal(TPMS_SIGNATURE_ECDSA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SIGNATURE_ECDAA_Unmarshal(TPMS_SIGNATURE_ECDAA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SIGNATURE_SM2_Unmarshal(TPMS_SIGNATURE_SM2 *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_SIGNATURE_ECSCHNORR_Unmarshal(TPMS_SIGNATURE_ECSCHNORR *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMU_SIGNATURE_Unmarshal(TPMU_SIGNATURE *target, BYTE **buffer, INT32 *size, UINT32 selector);
    TPM_RC TPMT_SIGNATURE_Unmarshal(TPMT_SIGNATURE *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPM2B_ENCRYPTED_SECRET_Unmarshal(TPM2B_ENCRYPTED_SECRET *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMI_ALG_PUBLIC_Unmarshal(TPMI_ALG_PUBLIC *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMU_PUBLIC_ID_Unmarshal(TPMU_PUBLIC_ID *target, BYTE **buffer, INT32 *size, UINT32 selector);
    TPM_RC TPMS_KEYEDHASH_PARMS_Unmarshal(TPMS_KEYEDHASH_PARMS *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_ASYM_PARMS_Unmarshal(TPMS_ASYM_PARMS *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_RSA_PARMS_Unmarshal(TPMS_RSA_PARMS *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_ECC_PARMS_Unmarshal(TPMS_ECC_PARMS *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMU_PUBLIC_PARMS_Unmarshal(TPMU_PUBLIC_PARMS *target, BYTE **buffer, INT32 *size, UINT32 selector);
    TPM_RC TPMT_PUBLIC_PARMS_Unmarshal(TPMT_PUBLIC_PARMS *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMT_PUBLIC_Unmarshal(TPMT_PUBLIC *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPM2B_PUBLIC_Unmarshal(TPM2B_PUBLIC *target, BYTE **buffer, INT32 *size, BOOL allowNull);
    TPM_RC TPM2B_TEMPLATE_Unmarshal(TPM2B_TEMPLATE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMU_SENSITIVE_COMPOSITE_Unmarshal(TPMU_SENSITIVE_COMPOSITE *target, BYTE **buffer, INT32 *size, UINT32 selector);
    TPM_RC TPMT_SENSITIVE_Unmarshal(TPMT_SENSITIVE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_SENSITIVE_Unmarshal(TPM2B_SENSITIVE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_PRIVATE_Unmarshal(TPM2B_PRIVATE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_ID_OBJECT_Unmarshal(TPM2B_ID_OBJECT *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMA_NV_Unmarshal(TPMA_NV *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_NV_PUBLIC_Unmarshal(TPMS_NV_PUBLIC *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_NV_PUBLIC_Unmarshal(TPM2B_NV_PUBLIC *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_CONTEXT_SENSITIVE_Unmarshal(TPM2B_CONTEXT_SENSITIVE *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_CONTEXT_DATA_Unmarshal(TPMS_CONTEXT_DATA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_CONTEXT_DATA_Unmarshal(TPM2B_CONTEXT_DATA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_CONTEXT_Unmarshal(TPMS_CONTEXT *target, BYTE **buffer, INT32 *size);
    TPM_RC TPMS_CREATION_DATA_Unmarshal(TPMS_CREATION_DATA *target, BYTE **buffer, INT32 *size);
    TPM_RC TPM2B_CREATION_DATA_Unmarshal(TPM2B_CREATION_DATA *target, BYTE **buffer, INT32 *size);

#ifdef __cplusplus
}
#endif

#endif
