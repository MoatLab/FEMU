/********************************************************************************/
/*										*/
/*			 Object Templates					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2016 - 2019					*/
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

#ifndef OBJECTTEMPLATES_H
#define OBJECTTEMPLATES_H

/* object type */

#define TYPE_BL		1
#define TYPE_ST		2
#define TYPE_DEN	3	
#define TYPE_DEO	4
#define TYPE_SI		5
#define TYPE_SIR	6
#define TYPE_GP		7
#define TYPE_DES	8
#define TYPE_KH		9
#define TYPE_DP		10
#define TYPE_DAA        11
#define TYPE_DAAR       12
#define TYPE_KHR	13
#define TYPE_DEE	14

#ifdef __cplusplus
extern "C" {
#endif

    TPM_RC asymPublicTemplate(TPMT_PUBLIC *publicArea,
			      TPMA_OBJECT addObjectAttributes,
			      TPMA_OBJECT deleteObjectAttributes,
			      int type,
			      TPMI_ALG_PUBLIC algPublic,
			      TPMI_RSA_KEY_BITS keyBits,
			      TPMI_ECC_CURVE curveID,			       
			      TPMI_ALG_HASH nalg,
			      TPMI_ALG_HASH halg,
			      const char *policyFilename);
    TPM_RC symmetricCipherTemplate(TPMT_PUBLIC *publicArea,
				   TPMA_OBJECT addObjectAttributes,
				   TPMA_OBJECT deleteObjectAttributes,
				   TPMI_ALG_HASH nalg,
				   int rev116,
				   const char *policyFilename);
    TPM_RC keyedHashPublicTemplate(TPMT_PUBLIC *publicArea,
				   TPMA_OBJECT addObjectAttributes,
				   TPMA_OBJECT deleteObjectAttributes,
				   int type,
				   TPMI_ALG_HASH nalg,
				   TPMI_ALG_HASH halg,
				   const char *policyFilename);
    TPM_RC derivationParentPublicTemplate(TPMT_PUBLIC *publicArea,
					  TPMA_OBJECT addObjectAttributes,
					  TPMA_OBJECT deleteObjectAttributes,
					  TPMI_ALG_HASH nalg,
					  TPMI_ALG_HASH halg,
					  const char *policyFilename);
    TPM_RC blPublicTemplate(TPMT_PUBLIC *publicArea,
			    TPMA_OBJECT addObjectAttributes,
			    TPMA_OBJECT deleteObjectAttributes,
			    TPMI_ALG_HASH nalg,
			    const char *policyFilename);

    void printUsageTemplate(void);

    TPM_RC getPolicy(TPMT_PUBLIC *publicArea,
		     const char *policyFilename);


#ifdef __cplusplus
}
#endif

#endif
