/********************************************************************************/
/*										*/
/*			    Create Loaded					*/
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

#include "objecttemplates.h"
#include "cryptoutils.h"

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    CreateLoaded_In 		in;
    CreateLoaded_Out		out;
    TPMT_PUBLIC			publicArea;
    TPMI_DH_OBJECT		parentHandle = 0;
    TPMA_OBJECT			addObjectAttributes;
    TPMA_OBJECT			deleteObjectAttributes;
    int 			derived = FALSE;	/* parent is derivation parent */
    int				keyType = 0;
    uint32_t 			keyTypeSpecified = 0;
    int				rev116 = FALSE;
    TPMI_ALG_PUBLIC 		algPublic = TPM_ALG_RSA;
    TPMI_RSA_KEY_BITS 		keyBits = 2048;
    TPMI_ECC_CURVE		curveID = TPM_ECC_NONE;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    TPMI_ALG_HASH		nalg = TPM_ALG_SHA256;
    const char			*policyFilename = NULL;
    const char			*publicKeyFilename = NULL;
    const char			*privateKeyFilename = NULL;
    const char			*pemFilename = NULL;
    const char 			*dataFilename = NULL;
    const char			*keyPassword = NULL; 
    const char			*parentPassword = NULL; 
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
    deleteObjectAttributes.val = 0;
 	
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-hp") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &parentHandle);
	    }
	    else {
		printf("Missing parameter for -hp\n");
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
	else if (strcmp(argv[i], "-der") == 0) {
	    derived = TRUE;
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
			printf("Bad parameter %c for -kt\n", argv[i][0]);
			printUsage();
		    }
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
	else if (strcmp(argv[i],"-opr") == 0) {
	    i++;
	    if (i < argc) {
		privateKeyFilename = argv[i];
	    }
	    else {
		printf("-opr option needs a value\n");
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
    if (parentHandle == 0) {
	printf("Missing handle parameter -hp\n");
	printUsage();
    }
    if (keyTypeSpecified != 1) {
	printf("Missing key attributes\n");
	printUsage();
    }
    switch (keyType) {
      case TYPE_BL:
	if (dataFilename == NULL) {
	    printf("-bl needs -if (sealed data object needs data to seal)\n");
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
      case TYPE_DES:
      case TYPE_KH:
      case TYPE_KHR:
      case TYPE_DP:
	/* inSensitive optional for symmetric keys */
	break;
    }
    if (rc == 0) {
	in.parentHandle = parentHandle;
    }
    /* Table 134 - Definition of TPM2B_SENSITIVE_CREATE inSensitive */
    if (rc == 0) {
	/* Table 133 - Definition of TPMS_SENSITIVE_CREATE Structure <IN>sensitive  */
	/* Table 75 - Definition of Types for TPM2B_AUTH userAuth */
	if (keyPassword == NULL) {
	    in.inSensitive.sensitive.userAuth.t.size = 0;
	}
	else {
	    rc = TSS_TPM2B_StringCopy(&in.inSensitive.sensitive.userAuth.b,
				      keyPassword,
				      sizeof(in.inSensitive.sensitive.userAuth.t.buffer));
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
    /* TPM2B_PUBLIC */
    if (rc == 0) {
	switch (keyType) {
	  case TYPE_BL:
	    rc = blPublicTemplate(&publicArea,
				  addObjectAttributes, deleteObjectAttributes,
				  nalg,
				  policyFilename);
	    break;
	  case TYPE_ST:
	  case TYPE_DEN:
	  case TYPE_DEO:
	  case TYPE_DEE:
	  case TYPE_SI:
	  case TYPE_SIR:
	  case TYPE_GP:
	    rc = asymPublicTemplate(&publicArea,
				    addObjectAttributes, deleteObjectAttributes,
				    keyType, algPublic, keyBits, curveID, nalg, halg,
				    policyFilename);
	    break;
	  case TYPE_DES:
	    rc = symmetricCipherTemplate(&publicArea,
					 addObjectAttributes, deleteObjectAttributes,
					 nalg, rev116,
					 policyFilename);
	    break;
	  case TYPE_KH:
	  case TYPE_KHR:
	    rc = keyedHashPublicTemplate(&publicArea,
					 addObjectAttributes, deleteObjectAttributes,
					 keyType, nalg, halg,
					 policyFilename);
	    break;
	  case TYPE_DP:
	    rc = derivationParentPublicTemplate(&publicArea,
						addObjectAttributes, deleteObjectAttributes,
						nalg, halg,
						policyFilename);
	} 
    }
    /* marshal the TPMT_PUBLIC into the TPM2B_TEMPLATE */
    if (rc == 0) {
	uint16_t written = 0;
	uint32_t size = sizeof(in.inPublic.t.buffer);
	uint8_t *buffer = in.inPublic.t.buffer;
	if (!derived) {		/* not derivation parent */
	    rc = TSS_TPMT_PUBLIC_Marshalu(&publicArea, &written, &buffer, &size);
	}
	else {			/* derivation parent */
	    /* The API changed from rev 142 to 146.  This is the 146 API.  It is unlikely that any
	       138 HW TPM will implement the 142 errata, but care must be taken to use a current SW
	       TPM. */
	    /* derived key has TPMS_CONTEXT parameter */
	    publicArea.unique.derive.label.t.size = 0;
	    publicArea.unique.derive.context.t.size = 0;
	    /* sensitiveDataOrigin has to be CLEAR in a derived object */	
	    publicArea.objectAttributes.val &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;
	    rc = TSS_TPMT_PUBLIC_D_Marshalu(&publicArea, &written, &buffer, &size);
	}
	in.inPublic.t.size = written;
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
			 TPM_CC_CreateLoaded,
			 sessionHandle0, parentPassword, sessionAttributes0,
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
    /* save the private key */
    if ((rc == 0) && (privateKeyFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.outPrivate,
				     (MarshalFunction_t)TSS_TPM2B_PRIVATE_Marshalu,
				     privateKeyFilename);
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
    if (rc == 0) {
	printf("Handle %08x\n", out.objectHandle);
	if (tssUtilsVerbose) printf("createloaded: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("createloaded: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("createloaded\n");
    printf("\n");
    printf("Runs TPM2_CreateLoaded\n");
    printf("\n");
    printf("\t-hp parent handle (can be hierarchy)\n");
    printf("\t\t40000001 Owner\n");
    printf("\t\t4000000c Platform\n");
    printf("\t\t4000000b Endorsement\n");
    printf("\n");
    printUsageTemplate();
    printf("\n");
    printf("\t[-der\tobject's parent is a derivation parent]\n");
    printf("\n");
    printf("\t[-pwdk\tpassword for key (default empty)]\n");
    printf("\t[-pwdp\tpassword for parent key (default empty)]\n");
    printf("\n");
    printf("\t[-opu\tpublic key file name (default do not save)]\n");
    printf("\t[-opr\tprivate key file name (default do not save)]\n");
    printf("\t[-opem\tpublic key PEM format file name (default do not save)]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t40\tresponse encrypt\n");
    exit(1);	
}
