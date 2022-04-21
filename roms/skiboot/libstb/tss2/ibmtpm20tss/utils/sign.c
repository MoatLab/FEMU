/********************************************************************************/
/*										*/
/*			    Sign						*/
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

/* Windows 10 crypto API clashes with openssl */
#ifdef TPM_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/Unmarshal_fp.h>

#include "cryptoutils.h"

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    Sign_In 			in;
    Sign_Out 			out;
    TPMI_DH_OBJECT		keyHandle = 0;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    TPMI_ALG_SIG_SCHEME		scheme = TPM_ALG_RSASSA;
    const char			*messageFilename = NULL;
    const char                  *counterFilename = NULL;
    const char			*ticketFilename = NULL;
    const char			*publicKeyFilename = NULL;
    const char			*signatureFilename = NULL;
    const char			*keyPassword = NULL; 
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;
 
    unsigned char 		*data = NULL;	/* message */
    size_t 			length;
    uint32_t           		sizeInBytes;	/* hash algorithm mapped to size */
    TPMT_HA 			digest;		/* digest of the message */

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-hk") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x",&keyHandle);
	    }
	    else {
		printf("Missing parameter for -hk\n");
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
	else if (strcmp(argv[i],"-salg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"rsa") == 0) {
		    scheme = TPM_ALG_RSASSA;
		}
		else if (strcmp(argv[i],"ecc") == 0) {
		    scheme = TPM_ALG_ECDSA;
		}
		else if (strcmp(argv[i],"hmac") == 0) {
		    scheme = TPM_ALG_HMAC;
		}
		else {
		    printf("Bad parameter %s for -salg\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-salg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-scheme") == 0) {
            i++;
	    if (i < argc) {
		if (strcmp(argv[i],"rsassa") == 0) {
		    scheme = TPM_ALG_RSASSA;
		}
		else if (strcmp(argv[i],"rsapss") == 0) {
		    scheme = TPM_ALG_RSAPSS;
		}
		else if (strcmp(argv[i],"ecdsa") == 0) {
		    scheme = TPM_ALG_ECDSA;
		}
		else if (strcmp(argv[i],"ecdaa") == 0) {
		    scheme = TPM_ALG_ECDAA;
		}
		else if (strcmp(argv[i],"hmac") == 0) {
		    scheme = TPM_ALG_HMAC;
		}
		else {
		    printf("Bad parameter %s for -scheme\n", argv[i]);
		    printUsage();
		}
	    }
        }
	else if (strcmp(argv[i],"-cf") == 0) {
	    i++;
	    if (i < argc) {
	        counterFilename = argv[i];
	    }
	    else {
		printf("-cf option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		messageFilename = argv[i];
	    }
	    else {
		printf("-if option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ipu") == 0) {
	    i++;
	    if (i < argc) {
		publicKeyFilename = argv[i];
	    }
	    else {
		printf("-ipu option needs a value\n");
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
 	else if (strcmp(argv[i],"-os") == 0) {
	    i++;
	    if (i < argc) {
		signatureFilename = argv[i];
	    }
	    else {
		printf("-os option needs a value\n");
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
    if (messageFilename == NULL) {
	printf("Missing message file name -if\n");
	printUsage();
    }
    if (keyHandle == 0) {
	printf("Missing handle parameter -hk\n");
	printUsage();
    }
    if ((scheme == TPM_ALG_ECDAA) && (counterFilename == NULL)) {
	printf("Missing counter file name -cf for ECDAA algorithm\n");
	printUsage();
    }
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&data,     /* freed @1 */
				     &length,
				     messageFilename);
    }
    /* hash the file */
    if (rc == 0) {
	digest.hashAlg = halg;
	sizeInBytes = TSS_GetDigestSize(digest.hashAlg);
	rc = TSS_Hash_Generate(&digest,
			       length, data,
			       0, NULL);
    }
    if (rc == 0) {
	/* Handle of key that will perform signing */
	in.keyHandle = keyHandle;

	/* digest to be signed */
	in.digest.t.size = sizeInBytes;
	memcpy(&in.digest.t.buffer, (uint8_t *)&digest.digest, sizeInBytes);
	/* Table 145 - Definition of TPMT_SIG_SCHEME inScheme */
	in.inScheme.scheme = scheme;
	/* Table 144 - Definition of TPMU_SIG_SCHEME details > */
	/* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */
	/* Table 135 - Definition of TPMS_SCHEME_HASH Structure */
	/* Table 59 - Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type  */
	if ((scheme == TPM_ALG_RSASSA) ||
	    (scheme == TPM_ALG_RSAPSS)) {
	    in.inScheme.details.rsassa.hashAlg = halg;
	}
	else if (scheme == TPM_ALG_ECDAA) {
	    in.inScheme.details.ecdaa.hashAlg = halg;
	    rc = TSS_File_ReadStructure(&in.inScheme.details.ecdaa.count, 
					(UnmarshalFunction_t)TSS_UINT16_Unmarshalu,
					counterFilename);
	}
	else {	/* scheme TPM_ALG_ECDSA */
	    in.inScheme.details.ecdsa.hashAlg = halg;
	}
    }
    if (rc == 0) {
	if (ticketFilename == NULL) {
	    /* proof that digest was created by the TPM (NULL ticket) */
	    /* Table 91 - Definition of TPMT_TK_HASHCHECK Structure */
	    in.validation.tag = TPM_ST_HASHCHECK;
	    in.validation.hierarchy = TPM_RH_NULL;
	    in.validation.digest.t.size = 0;
	}
	else {
	    rc = TSS_File_ReadStructure(&in.validation,
					(UnmarshalFunction_t)TSS_TPMT_TK_HASHCHECK_Unmarshalu,
					ticketFilename);
	}
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
			 TPM_CC_Sign,
			 sessionHandle0, keyPassword, sessionAttributes0,
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
    if ((rc == 0) && (signatureFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.signature,
				     (MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshalu,
				     signatureFilename);
    }
    /* if a public key was specified, use openssl to verify the signature using an openssl RSA
       format key token */
    if (publicKeyFilename != NULL) {
	TPM2B_PUBLIC 	public;
	void         	*rsaPubKey = NULL;
	if (rc == 0) {
	    rc = TSS_File_ReadStructureFlag(&public,
					    (UnmarshalFunctionFlag_t)TSS_TPM2B_PUBLIC_Unmarshalu,
					    TRUE,			/* NULL permitted */
					    publicKeyFilename);
	}
	/* construct the OpenSSL RSA public key token */
	if (rc == 0) {
	    unsigned char earr[3] = {0x01, 0x00, 0x01};
	    rc = TSS_RSAGeneratePublicTokenI
		 (&rsaPubKey,					/* freed @2 */
		  public.publicArea.unique.rsa.t.buffer, 	/* public modulus */
		  public.publicArea.unique.rsa.t.size,
		  earr,      					/* public exponent */
		  sizeof(earr));
	}
	/*
	  verify the TPM signature
	*/
	if (rc == 0) {
	    rc = verifyRSASignatureFromRSA((uint8_t *)&in.digest.t.buffer,
					   in.digest.t.size,
					   &out.signature,
					   halg,
					   rsaPubKey);

	}
	TSS_RsaFree(rsaPubKey); 		/* @2 */
    }
    free(data);					/* @1 */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("sign: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("sign: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}
    
static void printUsage(void)
{
    printf("\n");
    printf("sign\n");
    printf("\n");
    printf("Runs TPM2_Sign\n");
    printf("\n");
    printf("\t-hk\tkey handle\n");
    printf("\t-if\tinput message to hash and sign\n");
    printf("\t[-pwdk\tpassword for key (default empty)]\n");
    printf("\t[-halg\t(sha1, sha256, sha384, sha512) (default sha256)]\n");
    printf("\t[-salg\tsignature algorithm (rsa, ecc, hmac) (default rsa)]\n");
    printf("\t[-scheme signing scheme (rsassa, rsapss, ecdsa, ecdaa, hmac)]\n");
    printf("\t\t(default rsassa, ecdsa, hmac)]\n");
    printf("\t[-cf\tinput counter file (commit count required for ECDAA scheme]\n");
    printf("\t[-ipu\tpublic key file name to verify signature (default no verify)]\n");
    printf("\t\tVerify only supported for RSA now\n");
    printf("\t[-os\tsignature file name (default do not save)]\n");
    printf("\t[-tk\tticket file name]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    exit(1);	
}
