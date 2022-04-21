/********************************************************************************/
/*										*/
/*			    PCR_Allocate	 				*/
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

static void setPcrSelect(TPMS_PCR_SELECTION *pcrSelections,
			 TPM_ALG_ID hashAlg,
			 uint8_t select);
static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    PCR_Allocate_In 		in;
    PCR_Allocate_Out 		out;
    const char			*platformPassword = NULL; 
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;
    unsigned int		bankNumber = 0;
   
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-pwdp") == 0) {
	    i++;
	    if (i < argc) {
		platformPassword = argv[i];
	    }
	    else {
		printf("-pwdp option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-sha1") == 0) {
	    if (bankNumber < HASH_COUNT) {
		setPcrSelect(&in.pcrAllocation.pcrSelections[bankNumber],
			     TPM_ALG_SHA1, 0x00);
		bankNumber++;
	    }
	    else {
		printf("%u banks specified, TSS supports %u banks\n",
		       bankNumber+1, HASH_COUNT);
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"+sha1") == 0) {
	    if (bankNumber < HASH_COUNT) {
		setPcrSelect(&in.pcrAllocation.pcrSelections[bankNumber],
			     TPM_ALG_SHA1, 0xff);
		bankNumber++;
	    }
	    else {
		printf("%u banks specified, TSS supports %u banks\n",
		       bankNumber+1, HASH_COUNT);
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-sha256") == 0) {
	    if (bankNumber < HASH_COUNT) {
		setPcrSelect(&in.pcrAllocation.pcrSelections[bankNumber],
			     TPM_ALG_SHA256, 0x00);
		bankNumber++;
	    }
	    else {
		printf("%u banks specified, TSS supports %u banks\n",
		       bankNumber+1, HASH_COUNT);
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"+sha256") == 0) {
	    if (bankNumber < HASH_COUNT) {
		setPcrSelect(&in.pcrAllocation.pcrSelections[bankNumber],
			     TPM_ALG_SHA256, 0xff);
		bankNumber++;
	    }
	    else {
		printf("%u banks specified, TSS supports %u banks\n",
		       bankNumber+1, HASH_COUNT);
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-sha384") == 0) {
	    if (bankNumber < HASH_COUNT) {
		setPcrSelect(&in.pcrAllocation.pcrSelections[bankNumber],
			     TPM_ALG_SHA384, 0x00);
		bankNumber++;
	    }
	    else {
		printf("%u banks specified, TSS supports %u banks\n",
		       bankNumber+1, HASH_COUNT);
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"+sha384") == 0) {
	    if (bankNumber < HASH_COUNT) {
		setPcrSelect(&in.pcrAllocation.pcrSelections[bankNumber],
			     TPM_ALG_SHA384, 0xff);
		bankNumber++;
	    }
	    else {
		printf("%u banks specified, TSS supports %u banks\n",
		       bankNumber+1, HASH_COUNT);
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-sha512") == 0) {
	    if (bankNumber < HASH_COUNT) {
		setPcrSelect(&in.pcrAllocation.pcrSelections[bankNumber],
			     TPM_ALG_SHA512, 0x00);
		bankNumber++;
	    }
	    else {
		printf("%u banks specified, TSS supports %u banks\n",
		       bankNumber+1, HASH_COUNT);
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"+sha512") == 0) {
	    if (bankNumber < HASH_COUNT) {
		setPcrSelect(&in.pcrAllocation.pcrSelections[bankNumber],
			     TPM_ALG_SHA512, 0xff);
		bankNumber++;
	    }
	    else {
		printf("%u banks specified, TSS supports %u banks\n",
		       bankNumber+1, HASH_COUNT);
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
    /* at least one bank must be selected */
    if (rc == 0) {
	if (bankNumber == 0) {
	    printf("No PCR algorithm specified\n");
	    printUsage();
	}
    }
    if (rc == 0) {
	in.authHandle = TPM_RH_PLATFORM;
	in.pcrAllocation.count = bankNumber;
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
			 TPM_CC_PCR_Allocate,
			 sessionHandle0, platformPassword, sessionAttributes0,
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
	if (tssUtilsVerbose) printf("pcrallocate: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("pcrallocate: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void setPcrSelect(TPMS_PCR_SELECTION *pcrSelections,
			 TPM_ALG_ID hashAlg,
			 uint8_t select)
{
    pcrSelections->hash = hashAlg;
    pcrSelections->sizeofSelect = 3;
    pcrSelections->pcrSelect[0] = select;
    pcrSelections->pcrSelect[1] = select;
    pcrSelections->pcrSelect[2] = select;
    return;
}

static void printUsage(void)
{
    printf("\n");
    printf("pcrallocate\n");
    printf("\n");
    printf("Runs TPM2_PCR_Allocate\n");
    printf("\n");
    printf("\nAllocates banks for a full set of PCR 0-23.  Not all\n"
	   "hardware TPMs support multiple banks or all algorithms\n");
    printf("\n");
    printf("\t[-pwdp\tplatform hierarchy password (default empty)]\n");
    printf("\t+sha1   -sha1   allocate / deallocate a SHA-1 bank\n");
    printf("\t+sha256 -sha256 allocate / deallocate a SHA-256 bank\n");
    printf("\t+sha384 -sha384 allocate / deallocate a SHA-384 bank\n");
    printf("\t+sha512 -sha512 allocate / deallocate a SHA-512 bank\n");
    printf("\t\tMore than one algorithm can be specified\n");
    exit(1);	
}
