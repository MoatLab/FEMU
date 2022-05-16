/********************************************************************************/
/*										*/
/*			    Create Primary	 				*/
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

/* 

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsscryptoh.h>

#include "objecttemplates.h"
#include "cryptoutils.h"

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    CreatePrimary_In 		in;
    CreatePrimary_Out 		out;
    char 			hierarchyChar = 'n';
    TPMI_RH_HIERARCHY		primaryHandle = TPM_RH_NULL;
    TPMA_OBJECT			addObjectAttributes;
    TPMA_OBJECT			deleteObjectAttributes;
    int				keyType = TYPE_ST;
    uint32_t 			keyTypeSpecified = 0;
    int				rev116 = FALSE;
    const char 			*uniqueFilename = NULL;
    TPMI_ALG_PUBLIC 		algPublic = TPM_ALG_RSA;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    TPMI_ALG_HASH		nalg = TPM_ALG_SHA256;
    TPMI_RSA_KEY_BITS 		keyBits = 2048;
    TPMI_ECC_CURVE		curveID = TPM_ECC_NONE;
    const char			*policyFilename = NULL;
    const char			*publicKeyFilename = NULL;
    const char			*pemFilename = NULL;
    const char			*ticketFilename = NULL;
    const char			*creationHashFilename = NULL;
    const char 			*dataFilename = NULL;
    const char			*keyPassword = NULL; 
    const char			*parentPassword = NULL; 
    const char			*parentPasswordFilename = NULL; 
    const char			*parentPasswordPtr = NULL; 
    uint8_t			*parentPasswordBuffer = NULL;		/* for the free */
    size_t 			parentPasswordLength = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;
    
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */
    addObjectAttributes.val = 0;
    addObjectAttributes.val |= TPMA_OBJECT_NODA;
    addObjectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
    addObjectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
    deleteObjectAttributes.val = 0;

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-hi") == 0) {
	    i++;
	    if (i < argc) {
		hierarchyChar = argv[i][0];
	    }
	    else {
		printf("Missing parameter for -hi\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-bl") == 0) {
	    keyType = TYPE_BL;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-den") == 0) {
	    keyType = TYPE_DEN;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-deo") == 0) {
	    keyType = TYPE_DEO;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-dee") == 0) {
	    keyType = TYPE_DEE;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-des") == 0) {
	    keyType = TYPE_DES;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-st") == 0) {
	    keyType = TYPE_ST;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-si") == 0) {
	    keyType = TYPE_SI;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-sir") == 0) {
	    keyType = TYPE_SIR;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-dau") == 0) {
	    keyType = TYPE_DAA;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-dar") == 0) {
	    keyType = TYPE_DAAR;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-kh") == 0) {
	    keyType = TYPE_KH;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-khr") == 0) {
	    keyType = TYPE_KHR;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-dp") == 0) {
	    keyType = TYPE_DP;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-gp") == 0) {
	    keyType = TYPE_GP;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-116") == 0) {
	    rev116 = TRUE;
	}
	else if (strcmp(argv[i], "-rsa") == 0) {
	    algPublic = TPM_ALG_RSA;
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%hu", &keyBits);
	    }
	    else {
		printf("Missing parameter for -rsa\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-ecc") == 0) {
	    algPublic = TPM_ALG_ECC;
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"bnp256") == 0) {
		    curveID = TPM_ECC_BN_P256;
		}
		else if (strcmp(argv[i],"nistp256") == 0) {
		    curveID = TPM_ECC_NIST_P256;
		}
		else if (strcmp(argv[i],"nistp384") == 0) {
		    curveID = TPM_ECC_NIST_P384;
		}
		else {
		    printf("Bad parameter %s for -ecc\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-ecc option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-kt") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i], "f") == 0) {
		    addObjectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
   		}
		else if (strcmp(argv[i], "p") == 0) {
		    addObjectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
		}
		else if (strcmp(argv[i], "nf") == 0) {
		    deleteObjectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
		}
		else if (strcmp(argv[i], "np")  == 0) {
		    deleteObjectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
		}
		else if (strcmp(argv[i], "ed")  == 0) {
		    addObjectAttributes.val |= TPMA_OBJECT_ENCRYPTEDDUPLICATION;
		}
		else {
		    printf("Bad parameter %s for -kt\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -kt\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-uwa") == 0) {
	    deleteObjectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	}
	else if (strcmp(argv[i], "-da") == 0) {
	    addObjectAttributes.val &= ~TPMA_OBJECT_NODA;
	}
	else if (strcmp(argv[i],"-halg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    halg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    halg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    halg = TPM_ALG_SHA384;
		}
		else if (strcmp(argv[i],"sha512") == 0) {
		    halg = TPM_ALG_SHA512;
		}
		else {
		    printf("Bad parameter %s for -halg\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-halg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-nalg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    nalg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    nalg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    nalg = TPM_ALG_SHA384;
		}
		else if (strcmp(argv[i],"sha512") == 0) {
		    nalg = TPM_ALG_SHA512;
		}
		else {
		    printf("Bad parameter %s for -nalg\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-nalg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdp") == 0) {
	    i++;
	    if (i < argc) {
		parentPassword = argv[i];
	    }
	    else {
		printf("-pwdp option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdpi") == 0) {
	    i++;
	    if (i < argc) {
		parentPasswordFilename = argv[i];
	    }
	    else {
		printf("-pwdpi option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdk") == 0) {
	    i++;
	    if (i < argc) {
		keyPassword = argv[i];
	    }
	    else {
		printf("-pwdk option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-iu") == 0) {
	    i++;
	    if (i < argc) {
		uniqueFilename = argv[i];
	    }
	    else {
		printf("-iu option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-opu") == 0) {
	    i++;
	    if (i < argc) {
		publicKeyFilename = argv[i];
	    }
	    else {
		printf("-opu option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-opem") == 0) {
	    i++;
	    if (i < argc) {
		pemFilename = argv[i];
	    }
	    else {
		printf("-opem option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-tk") == 0) {
	    i++;
	    if (i < argc) {
		ticketFilename = argv[i];
	    }
	    else {
		printf("-tk option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ch") == 0) {
	    i++;
	    if (i < argc) {
		creationHashFilename = argv[i];
	    }
	    else {
		printf("-ch option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pol") == 0) {
	    i++;
	    if (i < argc) {
		policyFilename = argv[i];
	    }
	    else {
		printf("-pol option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		dataFilename = argv[i];
	    }
	    else {
		printf("-if option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se0") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle0);
	    }
	    else {
		printf("Missing parameter for -se0\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes0);
		if (sessionAttributes0 > 0xff) {
		    printf("Out of range session attributes for -se0\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se0\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se1") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle1);
	    }
	    else {
		printf("Missing parameter for -se1\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes1);
		if (sessionAttributes1 > 0xff) {
		    printf("Out of range session attributes for -se1\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se1\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se2") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle2);
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes2);
		if (sessionAttributes2 > 0xff) {
		    printf("Out of range session attributes for -se2\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    tssUtilsVerbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (keyTypeSpecified > 1) {
	printf("Too many key attributes\n");
	printUsage();
    }
    switch (keyType) {
      case TYPE_BL:
	if (dataFilename == NULL) {
	    printf("-bl needs -if (sealed data object needs data to seal)\n");
	    printUsage();
	}
	break;
      case TYPE_DAA:
      case TYPE_DAAR:
	if (algPublic != TPM_ALG_ECC) {
	    printf("-dau and -dar need -ecc\n");
 	    printUsage();
	}
	if (dataFilename != NULL) {
	    printf("asymmetric key cannot have -if (sensitive data)\n");
	    printUsage();
	}
	break;
      case TYPE_ST:
      case TYPE_DEN:
      case TYPE_DEO:
      case TYPE_DEE:
      case TYPE_SI:
      case TYPE_SIR:
      case TYPE_GP:
	if (dataFilename != NULL) {
	    printf("asymmetric key cannot have -if (sensitive data)\n");
	    printUsage();
	}
	break;
      case TYPE_DES:
      case TYPE_KH:
      case TYPE_KHR:
      case TYPE_DP:
	/* inSensitive optional for symmetric keys */
	break;
    }
    if (rc == 0) {
	if ((parentPassword != NULL) && (parentPasswordFilename != NULL)) {
	    printf("Cannot specify both -pwdp and -pwdpi\n");
	    printUsage();
	}
    }
    if (rc == 0) {
	/* command auth from string */
	if (parentPassword != NULL) {
	    parentPasswordPtr = parentPassword; 
	}
	/* command parent from file */
	else if (parentPasswordFilename != NULL) {
	    if (rc == 0) {
		/* must be freed by caller */
		rc = TSS_File_ReadBinaryFile(&parentPasswordBuffer,	/* freed @1 */
					     &parentPasswordLength,
					     parentPasswordFilename);
	    }
	    if (rc == 0) {
		if (parentPasswordLength > sizeof(TPMU_HA)) {
		    printf("Password too long %u\n", (unsigned int)parentPasswordLength);
		    rc = TSS_RC_INSUFFICIENT_BUFFER;
		}
	    }
	    if (rc == 0) {
		parentPasswordPtr = (const char *)parentPasswordBuffer;
	    }
	}
	/* no command parent specified */
	else {
	    parentPasswordPtr = NULL;
	}
    }
    /* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
    if (rc == 0) {
	if (hierarchyChar == 'e') {
	    primaryHandle = TPM_RH_ENDORSEMENT;
	}
	else if (hierarchyChar == 'o') {
	    primaryHandle = TPM_RH_OWNER;
	}
	else if (hierarchyChar == 'p') {
	    primaryHandle = TPM_RH_PLATFORM;
	}
	else if (hierarchyChar == 'n') {
	    primaryHandle = TPM_RH_NULL;
	}
	else {
	    printf("Bad parameter %c for -hi\n", hierarchyChar);
	    printUsage();
	}
	in.primaryHandle = primaryHandle;
    }
    /* Table 134 - TPM2B_SENSITIVE_CREATE inSensitive */
    if (rc == 0) {
	/* Table 133 - TPMS_SENSITIVE_CREATE */
	{
	    if (keyPassword == NULL) {
		in.inSensitive.sensitive.userAuth.t.size = 0;
	    }
	    else {
		rc = TSS_TPM2B_StringCopy(&in.inSensitive.sensitive.userAuth.b,
					  keyPassword,
					  sizeof(in.inSensitive.sensitive.userAuth.t.buffer));
	    }
	}
    }
    if (rc == 0) {
	/* Table 132 - Definition of TPM2B_SENSITIVE_DATA Structure data */
	if (dataFilename != NULL) {
	    rc = TSS_File_Read2B(&in.inSensitive.sensitive.data.b,
				 sizeof(in.inSensitive.sensitive.data.t.buffer),
				 dataFilename);
	}
	else {
	    in.inSensitive.sensitive.data.t.size = 0;
	}
    }
    /* Table 185 - TPM2B_PUBLIC	inPublic */
    if (rc == 0) {
	switch (keyType) {
	  case TYPE_BL:
	    rc = blPublicTemplate(&in.inPublic.publicArea,
				  addObjectAttributes, deleteObjectAttributes,
				  nalg,
				  policyFilename);
	    break;
	  case TYPE_ST:
	  case TYPE_DAA:
	  case TYPE_DAAR:
	  case TYPE_DEN:
	  case TYPE_DEO:
	  case TYPE_DEE:
	  case TYPE_SI:
	  case TYPE_SIR:
	  case TYPE_GP:
	    rc = asymPublicTemplate(&in.inPublic.publicArea,
				    addObjectAttributes, deleteObjectAttributes,
				    keyType, algPublic, keyBits, curveID, nalg, halg,
				    policyFilename);
	    break;
	  case TYPE_DES:
	    rc = symmetricCipherTemplate(&in.inPublic.publicArea,
					 addObjectAttributes, deleteObjectAttributes,
					 nalg, rev116,
					 policyFilename);
	    break;
	  case TYPE_KH:
	  case TYPE_KHR:
	    rc = keyedHashPublicTemplate(&in.inPublic.publicArea,
					 addObjectAttributes, deleteObjectAttributes,
					 keyType, nalg, halg,
					 policyFilename);
	    break;
	  case TYPE_DP:
	    rc = derivationParentPublicTemplate(&in.inPublic.publicArea,
						addObjectAttributes, deleteObjectAttributes,
						nalg, halg,
						policyFilename);
	    break;
	}
    }
    /* Table 177 - TPMU_PUBLIC_ID unique */
    /* Table 158 - TPM2B_PUBLIC_KEY_RSA rsa */
    if (rc == 0) {
	if (uniqueFilename != NULL) {
	    rc = TSS_File_Read2B(&in.inPublic.publicArea.unique.rsa.b,
				 sizeof(in.inPublic.publicArea.unique.rsa.t.buffer),
				 uniqueFilename);
	}
	else {
	    in.inPublic.publicArea.unique.rsa.t.size = 0;
	}
    }
    /* TPM2B_DATA outsideInfo */
    if (rc == 0) {
	in.outsideInfo.t.size = 0;
    }
    /* Table 102 - TPML_PCR_SELECTION */
    /* TPML_PCR_SELECTION	creationPCR */
    if (rc == 0) {
	in.creationPCR.count = 0;
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_CreatePrimary,
			 sessionHandle0, parentPasswordPtr, sessionAttributes0,
			 sessionHandle1, NULL, sessionAttributes1,
			 sessionHandle2, NULL, sessionAttributes2,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    /*
      validate the creation data
    */
    {
	uint16_t	written = 0;
	uint8_t		*buffer = NULL;		/* for the free */
	uint32_t 	sizeInBytes;
	TPMT_HA		digest;

	/* get the digest size from the Name algorithm */
	if (rc == 0) {
	    sizeInBytes = TSS_GetDigestSize(nalg);
	    if (out.creationHash.b.size != sizeInBytes) {
		printf("createprimary: failed, "
		       "creationData size %u incompatible with name algorithm %04x\n",
		       out.creationHash.b.size, nalg);
		rc = EXIT_FAILURE;
	    }
	}
	/* re-marshal the output structure */
	if (rc == 0) {
	    rc = TSS_Structure_Marshal(&buffer,	/* freed @1 */
				       &written,
				       &out.creationData.creationData,
				       (MarshalFunction_t)TSS_TPMS_CREATION_DATA_Marshalu);
	}
	/* recalculate the creationHash from creationData */
	if (rc == 0) {
	    digest.hashAlg = nalg;			/* Name digest algorithm */
	    rc = TSS_Hash_Generate(&digest,	
				   written, buffer,
				   0, NULL);
	}
	/* compare the digest to creation hash */
	if (rc == 0) {
	    int irc;
	    irc = memcmp((uint8_t *)&digest.digest, &out.creationHash.b.buffer, sizeInBytes);
	    if (irc != 0) {
		printf("createprimary: failed, creationData hash does not match creationHash\n");
		rc = EXIT_FAILURE;
	    }
	}
	free(buffer);	/* @1 */
    }
    /* save the public key */
    if ((rc == 0) && (publicKeyFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.outPublic,
				     (MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshalu,
				     publicKeyFilename);
    }
    /* save the optional PEM public key */
    if ((rc == 0) && (pemFilename != NULL)) {
	rc = convertPublicToPEM(&out.outPublic,
				pemFilename);
    }
    /* save the optional creation ticket */
    if ((rc == 0) && (ticketFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.creationTicket,
				     (MarshalFunction_t)TSS_TPMT_TK_CREATION_Marshalu,
				     ticketFilename);
    }
    /* save the optional creation hash */
    if ((rc == 0) && (creationHashFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(out.creationHash.b.buffer,
				      out.creationHash.b.size,
				      creationHashFilename);
    }
    if (rc == 0) {
	printf("Handle %08x\n", out.objectHandle);
	if (algPublic == TPM_ALG_RSA) {
	    if (tssUtilsVerbose) TSS_PrintAll("createprimary: public modulus",
				      out.outPublic.publicArea.unique.rsa.t.buffer,
				      out.outPublic.publicArea.unique.rsa.t.size);
	}
	else if (algPublic == TPM_ALG_ECC) {
	    if (tssUtilsVerbose) TSS_PrintAll("createprimary: public point X",
				      out.outPublic.publicArea.unique.ecc.x.t.buffer,
				      out.outPublic.publicArea.unique.ecc.x.t.size);
	    if (tssUtilsVerbose) TSS_PrintAll("createprimary: public point Y",
				      out.outPublic.publicArea.unique.ecc.y.t.buffer,
				      out.outPublic.publicArea.unique.ecc.y.t.size);
	}
	if (tssUtilsVerbose) printf("createprimary: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("createprimary: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    free(parentPasswordBuffer);		/* @1 */
    parentPasswordBuffer = NULL;
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("createprimary creates a primary storage key\n");
    printf("\n");
    printf("Runs TPM2_CreatePrimary\n");
    printf("\n");
    printf("\t[-hi\t\thierarchy (e, o, p, n) (default null)]\n");
    printf("\t[-pwdp\t\tpassword for hierarchy (default empty)]\n");
    printf("\t[-pwdpi\t\tpassword file name for hierarchy (default empty)]\n");
    printf("\t[-pwdk\t\tpassword for key (default empty)]\n");
    printf("\t[-iu\t\tinPublic unique field file (default none)]\n");
    printf("\t[-opu\t\tpublic key file name (default do not save)]\n");
    printf("\t[-opem\t\tpublic key PEM format file name (default do not save)]\n");
    printf("\t[-tk\t\toutput ticket file name]\n");
    printf("\t[-ch\t\toutput creation hash file name]\n");
    printf("\n");
    printUsageTemplate();
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t40\tresponse encrypt\n");
    exit(1);	
}
