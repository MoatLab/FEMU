/********************************************************************************/
/*										*/
/*			         Public Name  					*/
/*		      Written by Mark Marshall & Ken Goldman			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2018 - 2019.					*/
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
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tsscryptoh.h>
#include "objecttemplates.h"
#include "cryptoutils.h"

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    int				noSpace = FALSE;
    TPM2B_PUBLIC		inPublic;
    TPM2B_NV_PUBLIC		nvPublic;
    int				keyType = TYPE_SI;
    TPMI_ALG_SIG_SCHEME 	scheme = TPM_ALG_RSASSA;
    uint32_t 			keyTypeSpecified = 0;
    TPMI_ALG_PUBLIC 		algPublic = TPM_ALG_RSA;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    TPMI_ALG_HASH		nalg = TPM_ALG_SHA256;
    const char			*nvPublicFilename = NULL;
    const char			*publicKeyFilename = NULL;
    const char			*derKeyFilename = NULL;
    const char			*pemKeyFilename = NULL;
    const char			*nameFilename = NULL;
    int				userWithAuth = TRUE;
    int				object = TRUE;		/* TPM object, false if NV index */
    unsigned int		inputCount = 0;
    TPM2B_TEMPLATE		marshaled;
    uint16_t			written;
    uint32_t			size;
    uint8_t			*buffer;
    TPMT_HA			name;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-halg") == 0) {
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
	else if (strcmp(argv[i], "-rsa") == 0) {
	    algPublic = TPM_ALG_RSA;
	}
	else if (strcmp(argv[i], "-ecc") == 0) {
	    algPublic = TPM_ALG_ECC;
	}
	else if (strcmp(argv[i],"-scheme") == 0) {
	    if (keyType == TYPE_SI) {
		i++;
		if (i < argc) {
		    if (strcmp(argv[i],"rsassa") == 0) {
			scheme = TPM_ALG_RSASSA;
		    }
		    else if (strcmp(argv[i],"rsapss") == 0) {
			scheme = TPM_ALG_RSAPSS;
		    }
		    else if (strcmp(argv[i],"null") == 0) {
			scheme = TPM_ALG_NULL;
		    }
		    else {
			printf("Bad parameter %s for -scheme\n", argv[i]);
			printUsage();
		    }
		}
	    }
	    else {
		printf("-scheme can only be specified for signing key\n");
		printUsage();
	    }
        }
	else if (strcmp(argv[i], "-st") == 0) {
	    keyType = TYPE_ST;
	    scheme = TPM_ALG_NULL;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-den") == 0) {
	    keyType = TYPE_DEN;
	    scheme = TPM_ALG_NULL;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i], "-si") == 0) {
	    keyType = TYPE_SI;
	    keyTypeSpecified++;
	}
	else if (strcmp(argv[i],"-ipu") == 0) {
	    i++;
	    if (i < argc) {
		publicKeyFilename = argv[i];
		inputCount++;
	    }
	    else {
		printf("-ipu option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-invpu") == 0) {
	    i++;
	    if (i < argc) {
		nvPublicFilename = argv[i];
		object = FALSE;
		inputCount++;
	    }
	    else {
		printf("-ipu option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ipem") == 0) {
	    i++;
	    if (i < argc) {
		pemKeyFilename = argv[i];
		inputCount++;
	    }
	    else {
		printf("-ipem option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ider") == 0) {
	    i++;
	    if (i < argc) {
		derKeyFilename = argv[i];
		inputCount++;
	    }
	    else {
		printf("-ider option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-uwa") == 0) {
	    userWithAuth = FALSE;
	}
	else if (strcmp(argv[i],"-on") == 0) {
	    i++;
	    if (i < argc) {
		nameFilename = argv[i];
	    }
	    else {
		printf("-on option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ns") == 0) {
	    noSpace = TRUE;
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
    if (inputCount != 1) {
	printf("Missing or too many parameters -ipu, -ipem, -ider, -invpu\n");
	printUsage();
    }
    if (keyTypeSpecified > 1) {
	printf("Too many key attributes\n");
	printUsage();
    }
    if ((publicKeyFilename != NULL) && (!userWithAuth)) {
	printf("userWithAuth unused for TPM2B_PUBLIC input\n");
	printUsage();
	
    }
    /* loadexternal key pair cannot be restricted (storage key) and must have NULL symmetric
       scheme*/
    if (derKeyFilename != NULL) {
	if (keyType == TYPE_ST) {
	    keyType = TYPE_DEN;
	}
    }
    if (rc == 0) {
	/* TPM format key, output from create */
	if (publicKeyFilename != NULL) {
	    rc = TSS_File_ReadStructureFlag(&inPublic,
					    (UnmarshalFunctionFlag_t)TSS_TPM2B_PUBLIC_Unmarshalu,
					    TRUE,			/* NULL permitted */
					    publicKeyFilename);
	}
	/* NV Index public area */
	else if (nvPublicFilename != 0) {
	    rc = TSS_File_ReadStructure(&nvPublic,
					(UnmarshalFunction_t)TSS_TPM2B_NV_PUBLIC_Unmarshalu,
					nvPublicFilename);
	    
	}
	/* PEM format, output from e.g. openssl, readpublic, createprimary, create */
	else if (pemKeyFilename != NULL) {
	    switch (algPublic) {
	      case TPM_ALG_RSA:
		rc = convertRsaPemToPublic(&inPublic,
					   keyType,
					   scheme,
					   nalg,
					   halg,
					   pemKeyFilename);
		break;
#ifndef TPM_TSS_NOECC
	      case TPM_ALG_ECC:
		rc = convertEcPemToPublic(&inPublic,
					  keyType,
					  scheme,
					  nalg,
					  halg,
					  pemKeyFilename);
		break;
#endif	/* TPM_TSS_NOECC */
	      default:
		printf("-rsa algorithm %04x not supported\n", algPublic);
		rc = TPM_RC_ASYMMETRIC;
	    }
	}
	/* DER format key pair */
	else if (derKeyFilename != NULL) {
	    switch (algPublic) {
	      case TPM_ALG_RSA:
		rc = convertRsaDerToPublic(&inPublic,
					   keyType,
					   scheme,
					   nalg,
					   halg,
					   derKeyFilename);
		break;
#ifndef TPM_TSS_NOECC
	      case TPM_ALG_ECC:
		rc = convertEcDerToPublic(&inPublic,
					  keyType,
					  scheme,
					  nalg,
					  halg,
					  derKeyFilename);
		break;
#endif	/* TPM_TSS_NOECC */
	      default:
		printf("-rsa algorithm %04x not supported\n", algPublic);
		rc = TPM_RC_ASYMMETRIC;
	    }
	}
	else {
	    printf("Failure parsing -ipu, -ipem, -ider\n");
	    printUsage();
	}
    }
    /* TPM object */
    if (object) {
	if (rc == 0) {
	    name.hashAlg = inPublic.publicArea.nameAlg;
	    if (!userWithAuth) {
		inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_USERWITHAUTH;
	    }
	}
	if (rc == 0) {
	    if (tssUtilsVerbose) TSS_TPMT_PUBLIC_Print(&inPublic.publicArea, 2);
	}
	if (rc == 0) {
	    written = 0;
	    size = sizeof(marshaled.t.buffer);
	    buffer = marshaled.t.buffer;

	    rc = TSS_TPMT_PUBLIC_Marshalu(&inPublic.publicArea, &written, &buffer, &size);
	    marshaled.t.size = written;
	}
    }
    /* TPM NV Index */
    else {
	if (rc == 0) {
	    name.hashAlg = nvPublic.nvPublic.nameAlg;
	}
	if (rc == 0) {
	    if (tssUtilsVerbose) TSS_TPMS_NV_PUBLIC_Print(&nvPublic.nvPublic, 2);
	}
	if (rc == 0) {
	    written = 0;
	    size = sizeof(marshaled.t.buffer);
	    buffer = marshaled.t.buffer;

	    rc = TSS_TPMS_NV_PUBLIC_Marshalu(&nvPublic.nvPublic, &written, &buffer, &size);
	    marshaled.t.size = written;
	}
    }
    if (rc == 0) {
	rc = TSS_Hash_Generate(&name,
			       marshaled.t.size, marshaled.t.buffer,
			       0, NULL);
    }
    /* trace the Name */
    if ((rc == 0) && noSpace) {
	printf("%02X%02x", name.hashAlg >> 8, name.hashAlg & 0xff);
	for (i = 0; i < TSS_GetDigestSize(name.hashAlg); i++) {
	    printf("%02x", name.digest.tssmax[i]);
	}
	printf("\n");
    }
    /* save the Name */
    if ((rc == 0) && (nameFilename != NULL)) {
	rc = TSS_File_WriteStructure(&name,
				     (MarshalFunction_t)TSS_TPMT_HA_Marshalu,
				     nameFilename);
    }
    if (rc != 0) {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("publicname: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
 
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("publicname\n");
    printf("\n");
    printf("Calculates the public name of an entity. There are times that a policy creator\n"
	   "has TPM, PEM, or DER format information, but does not have access to a TPM.\n"
	   "This utility accepts these inputs and outputs the name in the 'no spaces'\n"
	   "format suitable for pasting into a policy.  The binary format is used in the\n"
	   "regression test\n");
    printf("\n");
    printf("\t-invpu\tTPM2B_NV_PUBLIC public key file name\n");
    printf("\t-ipu\tTPM2B_PUBLIC public key file name\n");
    printf("\t-ipem\tPEM format public key file name\n");
    printf("\t-ider\tDER format plaintext key pair file name]\n");
    printf("\t[-on\tbinary format Name file name]\n");
    printf("\t[-ns\tprint Name in hexacsii]\n");
    printf("\n");
    printf("\t\t-pem and -ider optional arguments\n");
    printf("\n");
    printf("\t[-rsa\t(default)]\n");
    printf("\t[-ecc\t]\n");
    printf("\t[-scheme  for signing key (default RSASSA scheme)]\n");
    printf("\t\trsassa\n");
    printf("\t\trsapss\n");
    printf("\t\tnull\n");
    printf("\t[-nalg\tname hash algorithm (sha1, sha256, sha384, sha512) (default sha256)]\n");
    printf("\t[-halg\tscheme hash algorithm (sha1, sha256, sha384, sha512) (default sha256)]\n");
    printf("\t[-uwa\tuserWithAuth attribute clear (default set)]\n");
    printf("\t[-si\tsigning (default) RSA]\n");
    printf("\t[-st\tstorage (default NULL scheme)]\n");
    printf("\t[-den\tdecryption, (unrestricted, RSA and EC NULL scheme)\n");
    printf("\n");
    exit(1);
}
