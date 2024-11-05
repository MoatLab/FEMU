/********************************************************************************/
/*										*/
/*			   Load External					*/
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

/*
  DER example:

  Create a key pair in PEM format
  
  > openssl genrsa -out keypair.pem -aes256 -passout pass:rrrr 2048
  > openssl ecparam -name prime256v1 -genkey -noout -out tmpkeypairecc.pem

  Convert to plaintext DER format

  > openssl rsa -inform pem -outform der -in keypair.pem -out keypair.der -passin pass:rrrr
  > openssl ec -inform pem -outform der -in tmpkeypairecc.pem -out tmpkeypairecc.der -passin pass:rrrr > run.out
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Windows 10 crypto API clashes with openssl */
#ifdef TPM_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/Unmarshal_fp.h>
#include "objecttemplates.h"
#include "cryptoutils.h"
#include "ekutils.h"

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    LoadExternal_In 		in;
    LoadExternal_Out 		out;
    char 			hierarchyChar = 0;
    TPMI_RH_HIERARCHY		hierarchy = TPM_RH_NULL;
    int				keyType = TYPE_SI;
    TPMI_ALG_SIG_SCHEME 	scheme = TPM_ALG_RSASSA;
    uint32_t 			keyTypeSpecified = 0;
    TPMI_ALG_PUBLIC 		algPublic = TPM_ALG_RSA;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    TPMI_ALG_HASH		nalg = TPM_ALG_SHA256;
    const char			*publicKeyFilename = NULL;
    const char			*derKeyFilename = NULL;
    const char			*pemKeyFilename = NULL;
    const char			*keyPassword = NULL;
    int				userWithAuth = TRUE;
    unsigned int		inputCount = 0;
    int				noSpace = FALSE;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RH_NULL;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-hi") == 0) {
	    i++;
	    if (i < argc) {
		if (argv[i][0] != 'e' && argv[i][0] != 'o' &&
		    argv[i][0] != 'p' && argv[i][0] != 'n') {
		    printUsage();
		}
		hierarchyChar = argv[i][0];
	    }
	    else {
		printf("Missing parameter for -hi\n");
		printUsage();
	    }
	    
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
	else if (strcmp(argv[i], "-uwa") == 0) {
	    userWithAuth = FALSE;
	}
	else if (strcmp(argv[i],"-ns") == 0) {
	    noSpace = TRUE;
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
    if (inputCount != 1) {
	printf("Missing or too many parameters -ipu, -ipem, -ider\n");
	printUsage();
    }
    if (keyTypeSpecified > 1) {
	printf("Too many key attributes\n");
	printUsage();
    }
    if (derKeyFilename == NULL) {
	if (keyPassword != NULL) {
	    printf("Password only valid for -ider keypair\n");
	    printUsage();
	}
    }
    /* loadexternal key pair cannot be restricted (storage key) and must have NULL symmetric
       scheme*/
    if (derKeyFilename != NULL) {
	if (keyType == TYPE_ST) {
	    keyType = TYPE_DEN;
	}
    }
    /* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
    if (rc == 0) {
	if (hierarchyChar == 'e') {
	    hierarchy = TPM_RH_ENDORSEMENT;
	}
	else if (hierarchyChar == 'o') {
	    hierarchy = TPM_RH_OWNER;
	}
	else if (hierarchyChar == 'p') {
	    hierarchy = TPM_RH_PLATFORM;
	}
	else if (hierarchyChar == 'n') {
	    hierarchy = TPM_RH_NULL;
	}
    }
    if (rc == 0) {
	in.inPrivate.t.size = 0;	/* default - mark optional inPrivate not used */
	/* TPM format key, output from create */
	if (publicKeyFilename != NULL) {
	    rc = TSS_File_ReadStructureFlag(&in.inPublic,
					    (UnmarshalFunctionFlag_t)TSS_TPM2B_PUBLIC_Unmarshalu,
					    TRUE,			/* NULL permitted */
					    publicKeyFilename);
	}
	/* PEM format, output from e.g. openssl, readpublic, createprimary, create */
	else if (pemKeyFilename != NULL) {
	    switch (algPublic) {
	      case TPM_ALG_RSA:
		rc = convertRsaPemToPublic(&in.inPublic,
					   keyType,
					   scheme,
					   nalg,
					   halg,
					   pemKeyFilename);
		break;
#ifndef TPM_TSS_NOECC
	      case TPM_ALG_ECC:
		rc = convertEcPemToPublic(&in.inPublic,
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
	    in.inPrivate.t.size = 1;		/* mark that private area should be loaded */
	    switch (algPublic) {
	      case TPM_ALG_RSA:
		rc = convertRsaDerToKeyPair(&in.inPublic,
					    &in.inPrivate,
					    keyType,
					    scheme,
					    nalg,
					    halg,
					    derKeyFilename,
					    keyPassword);
		break;
#ifndef TPM_TSS_NOECC
	      case TPM_ALG_ECC:
		rc = convertEcDerToKeyPair(&in.inPublic,
					   &in.inPrivate,
					   keyType,
					   scheme,
					   nalg,
					   halg,
					   derKeyFilename,
					   keyPassword);
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
    if (rc == 0) {
	if (!userWithAuth) {
	    in.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_USERWITHAUTH;
	}
	in.hierarchy = hierarchy;
    }
    if (rc == 0) {
	if (tssUtilsVerbose) TSS_TPMT_PUBLIC_Print(&in.inPublic.publicArea, 0);
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
			 TPM_CC_LoadExternal,
			 sessionHandle0, NULL, sessionAttributes0,
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
    if (rc == 0) {
	printf("Handle %08x\n", out.objectHandle);
	if (noSpace) {
	    unsigned int b;
	    for (b = 0 ; b < out.name.t.size ; b++) {
		printf("%02x", out.name.t.name[b]);
	    }
	    printf("\n");
	}
	if (tssUtilsVerbose) printf("loadexternal: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("loadexternal: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("loadexternal\n");
    printf("\n");
    printf("Runs TPM2_LoadExternal\n");
    printf("\n");
    printf("\t[-hi\thierarchy (e, o, p, n) (default NULL)]\n");
    printf("\t[-nalg\tname hash algorithm (sha1, sha256, sha384, sha512) (default sha256)]\n");
    printf("\t[-halg\tscheme hash algorithm (sha1, sha256, sha384, sha512) (default sha256)]\n");
    printf("\n");
    printf("\t[Asymmetric Key Algorithm]\n");
    printf("\n");
    printf("\t[-rsa\t(default)]\n");
    printf("\t[-ecc\t]\n");
    printf("\n");
    printf("\t-ipu\tTPM2B_PUBLIC public key file name\n");
    printf("\t-ipem\tPEM format public key file name\n");
    printf("\t-ider\tDER format plaintext key pair file name\n");
    printf("\t[-pwdk\tpassword for DER key (default empty)]\n");
    printf("\t[-uwa\tuserWithAuth attribute clear (default set)]\n");
    printf("\t[-si\tsigning (default) RSA]\n");
    printf("\t[-scheme  for signing key (default RSASSA scheme)]\n");
    printf("\t\trsassa\n");
    printf("\t\trsapss\n");
    printf("\t[-st\tstorage (default NULL scheme)]\n");
    printf("\t[-den\tdecryption, (unrestricted, RSA and EC NULL scheme)\n");
    printf("\t[-ns\tadditionally print Name in hex ascii on one line]\n");
    printf("\t\tUseful to paste into policy\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default NULL)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t40\tresponse encrypt\n");
    printf("\t80\taudit\n");
    exit(1);	
}
