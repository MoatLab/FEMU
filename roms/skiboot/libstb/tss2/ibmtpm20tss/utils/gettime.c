/********************************************************************************/
/*										*/
/*			    GetTime						*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2020.					*/
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
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tssmarshal.h>

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    GetTime_In 			in;
    GetTime_Out 		out;
    TPMI_DH_OBJECT		signHandle = 0;
    const char			*keyPassword = NULL; 
    const char			*endorsementPassword = NULL; 
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    const char			*signatureFilename = NULL;
    const char			*attestInfoFilename = NULL;
    const char			*qualifyingDataFilename = NULL;
    TPM_ALG_ID			sigAlg = TPM_ALG_RSA;
    TPMS_ATTEST 		tpmsAttest;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RS_PW;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;
 
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */
    
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-hk") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &signHandle);
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
	else if (strcmp(argv[i],"-pwde") == 0) {
	    i++;
	    if (i < argc) {
		endorsementPassword = argv[i];
	    }
	    else {
		printf("-pwde option needs a value\n");
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
		    sigAlg = TPM_ALG_RSA;
		}
		else if (strcmp(argv[i],"ecc") == 0) {
		    sigAlg = TPM_ALG_ECDSA;
		}
		else if (strcmp(argv[i],"hmac") == 0) {
		    sigAlg = TPM_ALG_HMAC;
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
	else if (strcmp(argv[i],"-oa") == 0) {
	    i++;
	    if (i < argc) {
		attestInfoFilename = argv[i];
	    }
	    else {
		printf("-oa option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-qd") == 0) {
	    i++;
	    if (i < argc) {
		qualifyingDataFilename = argv[i];
	    }
	    else {
		printf("-qd option needs a value\n");
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
    if (signHandle == 0) {
	printf("Missing sign handle parameter -hs\n");
	printUsage();
    }
    if (rc == 0) {
	/* handle of the privacy administrator */
	in.privacyAdminHandle = TPM_RH_ENDORSEMENT;
	/* Handle of key that will perform signing */
	in.signHandle = signHandle;
	if (sigAlg == TPM_ALG_RSA) {
	    /* Table 145 - Definition of TPMT_SIG_SCHEME Structure */
	    in.inScheme.scheme = TPM_ALG_RSASSA;	
	    /* Table 144 - Definition of TPMU_SIG_SCHEME Union <IN/OUT, S> */
	    /* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */
	    /* Table 135 - Definition of TPMS_SCHEME_HASH Structure */
	    in.inScheme.details.rsassa.hashAlg = halg;
	}
	else if (sigAlg == TPM_ALG_ECDSA) {
	    in.inScheme.scheme = TPM_ALG_ECDSA;	
	    in.inScheme.details.ecdsa.hashAlg = halg;
	}
	else {	/* HMAC */
	    in.inScheme.scheme = TPM_ALG_HMAC;	
	    in.inScheme.details.hmac.hashAlg = halg;
	}
    }
    /* data supplied by the caller */
    if (rc == 0) {
	if (qualifyingDataFilename != NULL) {
	    rc = TSS_File_Read2B(&in.qualifyingData.b,
				 sizeof(in.qualifyingData.t.buffer),
				 qualifyingDataFilename);
	}
	else {
	    in.qualifyingData.t.size = 0;
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
			 TPM_CC_GetTime,
			 sessionHandle0, endorsementPassword, sessionAttributes0,
			 sessionHandle1, keyPassword, sessionAttributes1,
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
	uint8_t *tmpBuffer = out.timeInfo.t.attestationData;
	uint32_t tmpSize = out.timeInfo.t.size;
	rc = TSS_TPMS_ATTEST_Unmarshalu(&tpmsAttest, &tmpBuffer, &tmpSize);
    }
    if (rc == 0) {
	if (tssUtilsVerbose) TSS_TPMS_ATTEST_Print(&tpmsAttest, 0);
    }
    if (rc == 0) {
	int match;
	match = TSS_TPM2B_Compare(&in.qualifyingData.b, &tpmsAttest.extraData.b);
	if (!match) {
	    printf("quote: failed, extraData != qualifyingData\n");
	    rc = EXIT_FAILURE;
	}
    }
    if ((rc == 0) && (signatureFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.signature,
				     (MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshalu,
				     signatureFilename);
    }    
    if ((rc == 0) && (attestInfoFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(out.timeInfo.t.attestationData,
				      out.timeInfo.t.size,
				      attestInfoFilename);
    }
    if (rc == 0) {
	if (tssUtilsVerbose) TSS_TPMT_SIGNATURE_Print(&out.signature, 0);
	if (tssUtilsVerbose) printf("gettime: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("gettime: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("gettime\n");
    printf("\n");
    printf("Runs TPM2_GetTime\n");
    printf("\n");
    printf("\t-hk\tsigning key handle\n");
    printf("\t[-pwdk\tpassword for signing key (default empty)]\n");
    printf("\t[-pwde\tpassword for endorsement hierarchy (default empty)]\n");
    printf("\t[-halg\t(sha1, sha256, sha384, sha512) (default sha256)]\n");
    printf("\t[-salg\tsignature algorithm (rsa, ecc, hmac) (default rsa)]\n");
    printf("\t[-qd\tqualifying data file name]\n");
    printf("\t[-os\tsignature file name  (default do not save)]\n");
    printf("\t[-oa\tattestation output file name (default do not save)]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t40\tresponse encrypt\n");
    exit(1);	
}
