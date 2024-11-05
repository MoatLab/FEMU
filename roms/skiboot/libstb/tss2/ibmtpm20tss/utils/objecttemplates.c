/********************************************************************************/
/*										*/
/*			 Object Templates					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2016 - 2019.					*/
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

/* These are templates suitable for creating typical objects.  The functions are shared by create
   and createprimary

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>

#include "objecttemplates.h"

/* asymPublicTemplate() is a template for an ECC or RSA key.

   It can create these types:

   TYPE_ST:   storage key (decrypt, restricted, RSA NULL scheme, EC NULL scheme)
   TYPE_DEN:  decryption key (not storage key, RSA NULL scheme, EC NULL scheme)
   TYPE_DEO:  decryption key (not storage key, RSA OAEP scheme, EC NULL scheme)
   TYPE_DEE:  decryption key (not storage key, RSA ES scheme, EC NULL scheme)
   TYPE_SI:   signing key (unrestricted, RSA NULL schemem EC NULL scheme)
   TYPE_SIR:  signing key (restricted, RSA RSASSA scheme, EC ECDSA scheme)
   TYPE_GP:   general purpose key
   TYPE_DAA:  signing key (unrestricted, ECDAA)
   TYPE_DAAR: signing key (restricted, ECDAA)
*/

TPM_RC asymPublicTemplate(TPMT_PUBLIC *publicArea,	/* output */
			  TPMA_OBJECT addObjectAttributes,	/* add default, can be overridden
								   here */
			  TPMA_OBJECT deleteObjectAttributes,
			  int keyType,			/* see above */
			  TPMI_ALG_PUBLIC algPublic,	/* RSA or ECC */
			  TPMI_RSA_KEY_BITS keyBits,	/* RSA modulus */
			  TPMI_ECC_CURVE curveID,	/* for ECC */
			  TPMI_ALG_HASH nalg,		/* Name algorithm */
			  TPMI_ALG_HASH halg,		/* hash algorithm */
			  const char *policyFilename)	/* binary policy, NULL means empty */
{
    TPM_RC			rc = 0;

    if (rc == 0) {
	publicArea->objectAttributes = addObjectAttributes;
	/* Table 185 - TPM2B_PUBLIC inPublic */
	/* Table 184 - TPMT_PUBLIC publicArea */
	publicArea->type = algPublic;		/* RSA or ECC */
	publicArea->nameAlg = nalg;

	/* Table 32 - TPMA_OBJECT objectAttributes */
	publicArea->objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	publicArea->objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;

	switch (keyType) {
	  case TYPE_DEN:
	  case TYPE_DEO:
	  case TYPE_DEE:
	    publicArea->objectAttributes.val &= ~TPMA_OBJECT_SIGN;
	    publicArea->objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	    publicArea->objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	    break;
	  case TYPE_ST:
	    publicArea->objectAttributes.val &= ~TPMA_OBJECT_SIGN;
	    publicArea->objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	    publicArea->objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	    break;
	  case TYPE_SI:
	  case TYPE_DAA:
	    publicArea->objectAttributes.val |= TPMA_OBJECT_SIGN;
	    publicArea->objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
	    publicArea->objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	    break;
	  case TYPE_SIR:
	  case TYPE_DAAR:
	    publicArea->objectAttributes.val |= TPMA_OBJECT_SIGN;
	    publicArea->objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
	    publicArea->objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	    break;
	  case TYPE_GP:
	    publicArea->objectAttributes.val |= TPMA_OBJECT_SIGN;
	    publicArea->objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	    publicArea->objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	    break;
	}
	publicArea->objectAttributes.val &= ~deleteObjectAttributes.val;
    }
    if (rc == 0) {
	/* Table 72 -  TPM2B_DIGEST authPolicy */
	/* policy set separately */

	/* Table 182 - Definition of TPMU_PUBLIC_PARMS parameters */
	if (algPublic == TPM_ALG_RSA) {
	    /* Table 180 - Definition of {RSA} TPMS_RSA_PARMS rsaDetail */
	    /* Table 129 - Definition of TPMT_SYM_DEF_OBJECT Structure symmetric */
	    switch (keyType) {
	      case TYPE_DEN:
	      case TYPE_DEO:
	      case TYPE_DEE:
	      case TYPE_SI:
	      case TYPE_SIR:
	      case TYPE_GP:
		/* Non-storage keys must have TPM_ALG_NULL for the symmetric algorithm */
		publicArea->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
		break;
	      case TYPE_ST:
		publicArea->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
		/* Table 125 - TPMU_SYM_KEY_BITS keyBits */
		publicArea->parameters.rsaDetail.symmetric.keyBits.aes = 128;
		/* Table 126 - TPMU_SYM_MODE mode */
		publicArea->parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
		break;
	    }

	    /* Table 155 - Definition of {RSA} TPMT_RSA_SCHEME scheme */
	    switch (keyType) {
	      case TYPE_DEN:
	      case TYPE_GP:
	      case TYPE_ST:
	      case TYPE_SI:
		publicArea->parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
		break;
	      case TYPE_DEO:
		publicArea->parameters.rsaDetail.scheme.scheme = TPM_ALG_OAEP;
		/* Table 152 - Definition of TPMU_ASYM_SCHEME details */
		/* Table 152 - Definition of TPMU_ASYM_SCHEME rsassa */
		/* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */
		/* Table 135 - Definition of TPMS_SCHEME_HASH hashAlg */
		publicArea->parameters.rsaDetail.scheme.details.oaep.hashAlg = halg;
		break;
	      case TYPE_DEE:
		publicArea->parameters.rsaDetail.scheme.scheme = TPM_ALG_RSAES;
		/* Table 152 - Definition of TPMU_ASYM_SCHEME details */
		/* Table 152 - Definition of TPMU_ASYM_SCHEME rsassa */
		/* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */
		/* Table 135 - Definition of TPMS_SCHEME_HASH hashAlg */
		publicArea->parameters.rsaDetail.scheme.details.oaep.hashAlg = halg;
		break;
	      case TYPE_SIR:
		publicArea->parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
		/* Table 152 - Definition of TPMU_ASYM_SCHEME details */
		/* Table 152 - Definition of TPMU_ASYM_SCHEME rsassa */
		/* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */
		/* Table 135 - Definition of TPMS_SCHEME_HASH hashAlg */
		publicArea->parameters.rsaDetail.scheme.details.rsassa.hashAlg = halg;
		break;
	    }
	
	    /* Table 159 - Definition of {RSA} (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type keyBits */
	    publicArea->parameters.rsaDetail.keyBits = keyBits;
	    publicArea->parameters.rsaDetail.exponent = 0;
	    /* Table 177 - TPMU_PUBLIC_ID unique */
	    /* Table 177 - Definition of TPMU_PUBLIC_ID */
	    publicArea->unique.rsa.t.size = 0;
	}
	else {	/* algPublic == TPM_ALG_ECC */
	    /* Table 181 - Definition of {ECC} TPMS_ECC_PARMS Structure eccDetail */
	    /* Table 129 - Definition of TPMT_SYM_DEF_OBJECT Structure symmetric */
	    switch (keyType) {
	      case TYPE_DEN:
	      case TYPE_DEO:
	      case TYPE_DEE:
	      case TYPE_SI:
	      case TYPE_SIR:
	      case TYPE_DAA:
	      case TYPE_DAAR:
	      case TYPE_GP:
		/* Non-storage keys must have TPM_ALG_NULL for the symmetric algorithm */
		publicArea->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
		break;
	      case TYPE_ST:
		publicArea->parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
		/* Table 125 - TPMU_SYM_KEY_BITS keyBits */
		publicArea->parameters.eccDetail.symmetric.keyBits.aes = 128;
		/* Table 126 - TPMU_SYM_MODE mode */
		publicArea->parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
		break;
	    }
	    /* Table 166 - Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure scheme */
	    /* Table 164 - Definition of (TPM_ALG_ID) {ECC} TPMI_ALG_ECC_SCHEME Type scheme */
	    switch (keyType) {
	      case TYPE_GP:
	      case TYPE_SI:
	      case TYPE_DEN:
	      case TYPE_DEO:
	      case TYPE_DEE:
		publicArea->parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
		/* Table 165 - Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type */
		/* Table 10 - Definition of (UINT16) {ECC} TPM_ECC_CURVE Constants curveID */
		publicArea->parameters.eccDetail.curveID = curveID;
		/* Table 150 - Definition of TPMT_KDF_SCHEME Structure kdf */
		/* Table 64 - Definition of (TPM_ALG_ID) TPMI_ALG_KDF Type */
		publicArea->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		break;
	      case TYPE_SIR:
		publicArea->parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
		/* Table 152 - Definition of TPMU_ASYM_SCHEME details */
		/* Table 143 - Definition of {ECC} Types for ECC Signature Schemes */
		publicArea->parameters.eccDetail.scheme.details.ecdsa.hashAlg = halg;
		/* Table 165 - Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type */
		/* Table 10 - Definition of (UINT16) {ECC} TPM_ECC_CURVE Constants curveID */
		publicArea->parameters.eccDetail.curveID = curveID;
		/* Table 150 - Definition of TPMT_KDF_SCHEME Structure kdf */
		/* Table 64 - Definition of (TPM_ALG_ID) TPMI_ALG_KDF Type */
		publicArea->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		/* Table 149 - Definition of TPMU_KDF_SCHEME Union <IN/OUT, S> */
		/* Table 148 - Definition of Types for KDF Schemes, hash-based key-
		   or mask-generation functions */
		/* Table 135 - Definition of TPMS_SCHEME_HASH Structure hashAlg */
		publicArea->parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;
		break;
	      case TYPE_DAA:
	      case TYPE_DAAR:
		publicArea->parameters.eccDetail.scheme.scheme = TPM_ALG_ECDAA;
		publicArea->parameters.eccDetail.scheme.details.ecdaa.hashAlg = halg;
		publicArea->parameters.eccDetail.scheme.details.ecdaa.count = 1;
		publicArea->parameters.eccDetail.curveID = curveID;
		publicArea->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		publicArea->unique.ecc.y.t.size = 0;
		publicArea->unique.ecc.x.t.size = 0;
		break;
	      case TYPE_ST:
		publicArea->parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
		publicArea->parameters.eccDetail.scheme.details.anySig.hashAlg = 0;
		publicArea->parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
		publicArea->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		publicArea->parameters.eccDetail.kdf.details.mgf1.hashAlg = 0;
		break;
	    }
	    /* Table 177 - TPMU_PUBLIC_ID unique */
	    /* Table 177 - Definition of TPMU_PUBLIC_ID */
	    publicArea->unique.ecc.x.t.size = 0;
	    publicArea->unique.ecc.y.t.size = 0;
	}
    }
    if (rc == 0) {
	rc = getPolicy(publicArea, policyFilename);
    }
    return rc;
}

/* symmetricCipherTemplate() is a template for an AES 128 CFB key

 */

TPM_RC symmetricCipherTemplate(TPMT_PUBLIC *publicArea,		/* output */
			       TPMA_OBJECT addObjectAttributes,	/* add default, can be overridden
								   here */
			       TPMA_OBJECT deleteObjectAttributes,
			       TPMI_ALG_HASH nalg,		/* Name algorithm */
			       int rev116,		/* TPM rev 116 compatibility, sets SIGN */
			       const char *policyFilename)	/* binary policy, NULL means empty */
{
    TPM_RC rc = 0;
    
    if (rc == 0) {
	publicArea->objectAttributes = addObjectAttributes;

	/* Table 185 - TPM2B_PUBLIC inPublic */
	/* Table 184 - TPMT_PUBLIC publicArea */
	publicArea->type = TPM_ALG_SYMCIPHER;
	publicArea->nameAlg = nalg;
	/* Table 32 - TPMA_OBJECT objectAttributes */
	/* rev 116 used DECRYPT for both decrypt and encrypt.  After 116, encrypt required SIGN */
	if (!rev116) {
	    /* actually encrypt */
	    publicArea->objectAttributes.val |= TPMA_OBJECT_SIGN;
	}
	publicArea->objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	publicArea->objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	publicArea->objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	publicArea->objectAttributes.val &= ~deleteObjectAttributes.val;
	/* Table 72 -  TPM2B_DIGEST authPolicy */
	/* policy set separately */
	/* Table 182 - Definition of TPMU_PUBLIC_PARMS parameters */
	{
	    /* Table 131 - Definition of TPMS_SYMCIPHER_PARMS symDetail */
	    {
		/* Table 129 - Definition of TPMT_SYM_DEF_OBJECT sym */
		/* Table 62 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_OBJECT Type */
		publicArea->parameters.symDetail.sym.algorithm = TPM_ALG_AES;
		/* Table 125 - Definition of TPMU_SYM_KEY_BITS Union */
		publicArea->parameters.symDetail.sym.keyBits.aes = 128;
		/* Table 126 - Definition of TPMU_SYM_MODE Union */
		publicArea->parameters.symDetail.sym.mode.aes = TPM_ALG_CFB;
	    }
	}
	/* Table 177 - TPMU_PUBLIC_ID unique */
	/* Table 72 - Definition of TPM2B_DIGEST Structure */
	publicArea->unique.sym.t.size = 0; 
    }
    if (rc == 0) {
	rc = getPolicy(publicArea, policyFilename);
    }
    return rc;
}

/* keyedHashPublicTemplate() is a template for an HMAC key

   It can create these types:

   TYPE_KH:	HMAC key, unrestricted
   TYPE_KHR:	HMAC key, restricted
*/

TPM_RC keyedHashPublicTemplate(TPMT_PUBLIC *publicArea,		/* output */
			       TPMA_OBJECT addObjectAttributes,	/* add default, can be overridden
								   here */
			       TPMA_OBJECT deleteObjectAttributes,
			       int keyType,			/* see above */
			       TPMI_ALG_HASH nalg,		/* Name algorithm */
			       TPMI_ALG_HASH halg,		/* hash algorithm */
			       const char *policyFilename)	/* binary policy, NULL means empty */
{
    TPM_RC			rc = 0;

    if (rc == 0) {
	publicArea->objectAttributes = addObjectAttributes;

	/* Table 185 - TPM2B_PUBLIC inPublic */
	/* Table 184 - TPMT_PUBLIC publicArea */
	/* Table 176 - Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type */
	publicArea->type = TPM_ALG_KEYEDHASH;
	/* Table 59 - Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type  */
	publicArea->nameAlg = nalg;
	/* Table 32 - TPMA_OBJECT objectAttributes */
	publicArea->objectAttributes.val |= TPMA_OBJECT_SIGN;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	publicArea->objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	publicArea->objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	switch (keyType) {
	  case TYPE_KH:
	    publicArea->objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	    break;
	  case TYPE_KHR:
	    publicArea->objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	    break;
	}
	publicArea->objectAttributes.val &= ~deleteObjectAttributes.val;
	/* Table 72 -  TPM2B_DIGEST authPolicy */
	/* policy set separately */
	{
	    /* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */
	    /* Table 178 - Definition of TPMS_KEYEDHASH_PARMS Structure */
	    /* Table 141 - Definition of TPMT_KEYEDHASH_SCHEME Structure */
	    /* Table 137 - Definition of (TPM_ALG_ID) TPMI_ALG_KEYEDHASH_SCHEME Type */
	    publicArea->parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
	    /* Table 140 - Definition of TPMU_SCHEME_KEYEDHASH Union <IN/OUT, S> */
	    /* Table 138 - Definition of Types for HMAC_SIG_SCHEME */
	    /* Table 135 - Definition of TPMS_SCHEME_HASH Structure */
	    publicArea->parameters.keyedHashDetail.scheme.details.hmac.hashAlg = halg;
	}
	/* Table 177 - TPMU_PUBLIC_ID unique */
	/* Table 72 - Definition of TPM2B_DIGEST Structure */
	publicArea->unique.sym.t.size = 0; 
    }
    if (rc == 0) {
	rc = getPolicy(publicArea, policyFilename);
    }
    return rc;
}

/* derivationParentPublicTemplate() is a template for a derivation parent

   The key is not restricted
*/

TPM_RC derivationParentPublicTemplate(TPMT_PUBLIC *publicArea,		/* output */
				      TPMA_OBJECT addObjectAttributes,	/* add default, can be
									   overridden here */
				      TPMA_OBJECT deleteObjectAttributes,
				      TPMI_ALG_HASH nalg,		/* Name algorithm */
				      TPMI_ALG_HASH halg,		/* hash algorithm */
				      const char *policyFilename)	/* binary policy, NULL means
									   empty */
{
    TPM_RC			rc = 0;

    if (rc == 0) {
	publicArea->objectAttributes = addObjectAttributes;

	/* Table 185 - TPM2B_PUBLIC inPublic */
	/* Table 184 - TPMT_PUBLIC publicArea */
	/* Table 176 - Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type */
	publicArea->type = TPM_ALG_KEYEDHASH;
	/* Table 59 - Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type  */
	publicArea->nameAlg = nalg;
	/* Table 32 - TPMA_OBJECT objectAttributes */
	publicArea->objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
	publicArea->objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_SIGN;
	publicArea->objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	publicArea->objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	publicArea->objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	publicArea->objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	publicArea->objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	publicArea->objectAttributes.val &= ~deleteObjectAttributes.val;
	/* Table 72 -  TPM2B_DIGEST authPolicy */
	/* policy set separately */
	{
	    /* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */
	    /* Table 178 - Definition of TPMS_KEYEDHASH_PARMS Structure */
	    /* Table 141 - Definition of TPMT_KEYEDHASH_SCHEME Structure */
	    /* Table 137 - Definition of (TPM_ALG_ID) TPMI_ALG_KEYEDHASH_SCHEME Type */
	    publicArea->parameters.keyedHashDetail.scheme.scheme = TPM_ALG_XOR;
	    /* Table 140 - Definition of TPMU_SCHEME_KEYEDHASH Union <IN/OUT, S> */
	    /* Table 138 - Definition of Types for HMAC_SIG_SCHEME */
	    /* Table 135 - Definition of TPMS_SCHEME_HASH Structure */
	    publicArea->parameters.keyedHashDetail.scheme.details.xorr.kdf = TPM_ALG_KDF1_SP800_108;
	    publicArea->parameters.keyedHashDetail.scheme.details.xorr.hashAlg = halg;
	}
	/* Table 177 - TPMU_PUBLIC_ID unique */
	/* Table 72 - Definition of TPM2B_DIGEST Structure */
	publicArea->unique.sym.t.size = 0; 
    }
    if (rc == 0) {
	rc = getPolicy(publicArea, policyFilename);
    }
    return rc;
}

/* blPublicTemplate() is a template for a sealed data blob.

*/

TPM_RC blPublicTemplate(TPMT_PUBLIC *publicArea,	/* output */
			TPMA_OBJECT addObjectAttributes,	/* add default, can be overridden
								   here */
			TPMA_OBJECT deleteObjectAttributes,
			TPMI_ALG_HASH nalg,		/* Name algorithm */
			const char *policyFilename)	/* binary policy, NULL means empty */
{
    TPM_RC			rc = 0;

    if (rc == 0) {
	publicArea->objectAttributes = addObjectAttributes;

	/* Table 185 - TPM2B_PUBLIC inPublic */
	/* Table 184 - TPMT_PUBLIC publicArea */
	/* Table 176 - Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type */
	publicArea->type = TPM_ALG_KEYEDHASH;
	/* Table 59 - Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type  */
	publicArea->nameAlg = nalg;
	/* Table 32 - TPMA_OBJECT objectAttributes */
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_SIGN;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;
	publicArea->objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	publicArea->objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	publicArea->objectAttributes.val &= ~deleteObjectAttributes.val;
	/* Table 72 -  TPM2B_DIGEST authPolicy */
	/* policy set separately */
	{
	    /* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */
	    /* Table 178 - Definition of TPMS_KEYEDHASH_PARMS Structure */
	    /* Table 141 - Definition of TPMT_KEYEDHASH_SCHEME Structure */
	    /* Table 137 - Definition of (TPM_ALG_ID) TPMI_ALG_KEYEDHASH_SCHEME Type */
	    publicArea->parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
	    /* Table 140 - Definition of TPMU_SCHEME_KEYEDHASH Union <IN/OUT, S> */
	}
	/* Table 177 - TPMU_PUBLIC_ID unique */
	/* Table 72 - Definition of TPM2B_DIGEST Structure */
	publicArea->unique.sym.t.size = 0; 
    }
    if (rc == 0) {
	rc = getPolicy(publicArea, policyFilename);
    }
    return rc;
}

TPM_RC getPolicy(TPMT_PUBLIC *publicArea,
		 const char *policyFilename)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	if (policyFilename != NULL) {
	    rc = TSS_File_Read2B(&publicArea->authPolicy.b,
				 sizeof(publicArea->authPolicy.t.buffer),
				 policyFilename);
	}
	else {
	    publicArea->authPolicy.t.size = 0;	/* default empty policy */
	}
    }
    return rc;
}

void printUsageTemplate(void)
{
    printf("\t[Asymmetric Key Algorithm]\n");
    printf("\n");
    printf("\t-rsa keybits (default)\n");
    printf("\t\t(2048 default)\n");
    printf("\t-ecc curve\n");
    printf("\t\tbnp256\n");
    printf("\t\tnistp256\n");
    printf("\t\tnistp384\n");
    printf("\n");
    printf("\tKey attributes\n");
    printf("\n");
    printf("\t\t-bl\tdata blob for unseal (create only)\n");
    printf("\t\t\trequires -if\n");
    printf("\t\t-den\tdecryption, (unrestricted, RSA and EC NULL scheme)\n");
    printf("\t\t-deo\tdecryption, (unrestricted, RSA OAEP, EC NULL scheme)\n");
    printf("\t\t-dee\tdecryption, (unrestricted, RSA ES, EC NULL scheme)\n");
    printf("\t\t-des\tencryption/decryption, AES symmetric\n");
    printf("\t\t\t[-116 for TPM rev 116 compatibility]\n");
    printf("\t\t-st\tstorage (restricted)\n");
    printf("\t\t\t[default for primary keys]\n");
    printf("\t\t-si\tunrestricted signing (RSA and EC NULL scheme)\n");
    printf("\t\t-sir\trestricted signing (RSA RSASSA, EC ECDSA scheme)\n");
    printf("\t\t-dau\tunrestricted ECDAA signing key pair\n");
    printf("\t\t-dar\trestricted ECDAA signing key pair\n");
    printf("\t\t-kh\tkeyed hash (unrestricted, hmac)\n");
    printf("\t\t-khr\tkeyed hash (restricted, hmac)\n");
    printf("\t\t-dp\tderivation parent\n");
    printf("\t\t-gp\tgeneral purpose, not storage\n");
    printf("\n");
    printf("\t\t[-kt\t(can be specified more than once)]\n"
	   "\t\t\tf\tfixedTPM (default for primary keys and derivation parents)\n"
	   "\t\t\tp\tfixedParent (default for primary keys and derivation parents)\n"
	   "\t\t\tnf\tno fixedTPM (default for non-primary keys)\n"
	   "\t\t\tnp\tno fixedParent (default for non-primary keys)\n"
	   "\t\t\ted\tencrypted duplication (default not set)\n");
    printf("\t[-da\tobject subject to DA protection (default no)]\n");
    printf("\t[-pol\tpolicy file (default empty)]\n");
    printf("\t[-uwa\tuserWithAuth attribute clear (default set)]\n");
    printf("\t[-if\tdata (inSensitive) file name]\n");
    printf("\n");
    printf("\t[-nalg\tname hash algorithm (sha1, sha256, sha384, sha512) (default sha256)]\n");
    printf("\t[-halg\tscheme hash algorithm (sha1, sha256, sha384, sha512) (default sha256)]\n");
    return;	
}
