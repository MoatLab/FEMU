/********************************************************************************/
/*										*/
/*			   Import a PEM keypair 				*/
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

/* Use OpenSSL to create an RSA or ECC keypair like this

   > openssl genrsa -out tmpprivkey.pem -aes256 -passout pass:rrrr 2048
   > openssl ecparam -name prime256v1 -genkey -noout |
	openssl pkey -aes256 -passout pass:rrrr -text > tmpecprivkey.pem

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>

#include "cryptoutils.h"
#include "objecttemplates.h"

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    Import_In 			in;
    Import_Out 			out;
    TPMI_DH_OBJECT		parentHandle = 0;
    const char			*parentPassword = NULL;
    const char			*pemKeyFilename = NULL;
    const char			*pemKeyPassword = "";	/* default empty password */
    const char			*outPublicFilename = NULL;
    const char			*outPrivateFilename = NULL;
    const char			*policyFilename = NULL;
    int				keyType = TYPE_SI;
    uint32_t 			keyTypeSpecified = 0;
    TPMI_ALG_SIG_SCHEME 	scheme = TPM_ALG_RSASSA;
    TPMI_ALG_PUBLIC 		algPublic = TPM_ALG_RSA;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    TPMI_ALG_HASH		nalg = TPM_ALG_SHA256;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;
    FILE 			*pemKeyFile = NULL;
    
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */
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
	else if (strcmp(argv[i],"-ipem") == 0) {
	    i++;
	    if (i < argc) {
		pemKeyFilename = argv[i];
	    }
	    else {
		printf("-ipem option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-rsa") == 0) {
	    algPublic = TPM_ALG_RSA;
	}
	else if (strcmp(argv[i], "-ecc") == 0) {
	    algPublic = TPM_ALG_ECC;
	    scheme = TPM_ALG_ECDSA;
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
	else if (strcmp(argv[i],"-pwdk") == 0) {
	    i++;
	    if (i < argc) {
		pemKeyPassword = argv[i];
	    }
	    else {
		printf("-pwdk option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-opu") == 0) {
	    i++;
	    if (i < argc) {
		outPublicFilename = argv[i];
	    }
	    else {
		printf("-opu option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-opr") == 0) {
	    i++;
	    if (i < argc) {
		outPrivateFilename = argv[i];
	    }
	    else {
		printf("-opr option needs a value\n");
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
	printf("Missing or bad object handle parameter -hp\n");
	printUsage();
    }
    if (pemKeyFilename == NULL) {
	printf("Missing parameter -ipem\n");
	printUsage();
    }
    if (keyTypeSpecified > 1) {
	printf("Too many key attributes\n");
	printUsage();
    }
    if (outPublicFilename == NULL) {
	printf("Missing parameter -opu\n");
	printUsage();
    }
    if (outPrivateFilename == NULL) {
	printf("Missing parameter -opr\n");
	printUsage();
    }
    if (rc == 0) {
	in.parentHandle = parentHandle;
	in.encryptionKey.t.size = 0;
	in.inSymSeed.t.size = 0;
	in.symmetricAlg.algorithm = TPM_ALG_NULL;
    }
    if (rc == 0) {
	switch (algPublic) {
	  case TPM_ALG_RSA:
	    rc = convertRsaPemToKeyPair(&in.objectPublic,
					&in.duplicate,
					keyType,
					scheme,
					nalg,
					halg,
					pemKeyFilename,
					pemKeyPassword);
	    break;
#ifndef TPM_TSS_NOECC
	  case TPM_ALG_ECC:
	    rc = convertEcPemToKeyPair(&in.objectPublic,
				       &in.duplicate,
				       keyType,
				       scheme,
				       nalg,
				       halg,
				       pemKeyFilename,
				       pemKeyPassword);
	    break;
#endif	/* TPM_TSS_NOECC */
	  default:
	    printf("-rsa algorithm %04x not supported\n", algPublic);
	    rc = TPM_RC_ASYMMETRIC;
	}
    }
    /* instantiate optional policy */
    if (rc == 0) {
	rc = getPolicy(&in.objectPublic.publicArea, policyFilename);
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
			 TPM_CC_Import,
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
    /* output the TPM2B_PUBLIC */
    if (rc == 0) {
	rc = TSS_File_WriteStructure(&in.objectPublic,
				     (MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshalu,
				     outPublicFilename);
    }
    /* output the TPM2B_PRIVATE, which is now wrapped by the parent */
    if (rc == 0) {
	rc = TSS_File_WriteStructure(&out.outPrivate,
				     (MarshalFunction_t)TSS_TPM2B_PRIVATE_Marshalu,
				     outPrivateFilename);
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("importpem: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("importpem: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    if (pemKeyFile != NULL) {
	fclose(pemKeyFile);			/* @2 */
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("importpem\n");
    printf("\n");
    printf("Runs TPM2_Import for a PEM key\n");
    printf("\n");
    printf("\t-hp\tparent handle\n");
    printf("\t[-pwdp\tpassword for parent (default empty)]\n");
    printf("\t-ipem\tPEM format key pair\n");
    printf("\n");
    printf("\t[Asymmetric Key Algorithm]\n");
    printf("\n");
    printf("\t[-rsa\t(default)]\n");
    printf("\t[-ecc\t]\n");
    printf("\n");
    printf("\t[-si\tsigning (default)]\n");
    printf("\t[-scheme  signing scheme (rsassa rsapss) (RSA default RSASSA) (ECC ECDSA)]\n");
    printf("\t[-st\tstorage (NULL scheme)]\n");
    printf("\t[-den\tdecryption, (unrestricted, RSA and ECC NULL scheme)\n");
    printf("\t[-pwdk\tpassword for key (default empty)]\n");
    printf("\t-opu\tpublic area file name\n");
    printf("\t-opr\tprivate area file name\n");
    printf("\t[-nalg\tname hash algorithm (sha1, sha256, sha384, sha512) (default sha256)]\n");
    printf("\t[-halg\tscheme hash algorithm (sha1, sha256, sha384, sha512) (default sha256)]\n");
    printf("\t[-pol\tpolicy file (default empty)]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t40\tresponse encrypt\n");
    exit(1);	
}
