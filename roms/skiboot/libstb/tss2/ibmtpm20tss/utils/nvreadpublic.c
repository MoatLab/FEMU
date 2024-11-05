/********************************************************************************/
/*										*/
/*			    NV ReadPublic					*/
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

/* for endian conversion */
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsscrypto.h>

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    NV_ReadPublic_In 		in;
    NV_ReadPublic_Out		out;
    TPMI_RH_NV_INDEX		nvIndex = 0;
    TPMI_ALG_HASH		nalg = TPM_ALG_NULL;
    TPMI_ALG_HASH 		nameHashAlg;
    const char			*nvPublicFilename = NULL;
    const char			*nameFilename = NULL;
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
    
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ha") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &nvIndex);
	    }
	    else {
		printf("Missing parameter for -ha\n");
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
	else if (strcmp(argv[i],"-opu") == 0) {
	    i++;
	    if (i < argc) {
		nvPublicFilename = argv[i];
	    }
	    else {
		printf("-opu option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ns") == 0) {
	    noSpace = TRUE;
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
    if ((nvIndex >> 24) != TPM_HT_NV_INDEX) {
	printf("NV index handle not specified or out of range, MSB not 01\n");
	printUsage();
    }
    if (rc == 0) {
	in.nvIndex = nvIndex;
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
			 TPM_CC_NV_ReadPublic,
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
    /* NOTE: The caller validates the result to the extent that it does not trust the NV index to be
       defined properly */
    
    /* Table 197 - Definition of TPM2B_NV_PUBLIC Structure - nvPublic*/
    /* Table 196 - Definition of TPMS_NV_PUBLIC Structure */
    /* Table 83 - Definition of TPM2B_NAME Structure t */

    /* TPMS_NV_PUBLIC hash alg vs expected */
    if (rc == 0) {
	if ((nalg != TPM_ALG_NULL) && (out.nvPublic.nvPublic.nameAlg != nalg)) {
	    printf("nvreadpublic: TPM2B_NV_PUBLIC hash algorithm does not match expected\n");
	    rc = TSS_RC_MALFORMED_NV_PUBLIC;
	}
    }
    /* TPM2B_NAME hash algorithm vs expected */
    if (rc == 0) {
	uint16_t tmp16;
	memcpy(&tmp16, out.nvName.t.name, sizeof(uint16_t));
	/* nameHashAlg = ntohs(*(TPMI_ALG_HASH *)(out.nvName.t.name)); */
	nameHashAlg = ntohs(tmp16);
	if ((nalg != TPM_ALG_NULL) && (nameHashAlg != nalg)) {
	    printf("nvreadpublic: TPM2B_NAME hash algorithm does not match expected\n");
	    rc = TSS_RC_MALFORMED_NV_PUBLIC;
	}
    }
    /* TPMS_NV_PUBLIC index vs expected */
    if (rc == 0) {
	if (out.nvPublic.nvPublic.nvIndex != in.nvIndex) {
	    printf("nvreadpublic: TPM2B_NV_PUBLIC index does not match expected\n");
	    rc = TSS_RC_MALFORMED_NV_PUBLIC;
	}
    }
    /* save the public key */
    if ((rc == 0) && (nvPublicFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.nvPublic,
				     (MarshalFunction_t)TSS_TPM2B_NV_PUBLIC_Marshalu,
				     nvPublicFilename);
    }
    /* save the Name */
    if ((rc == 0) && (nameFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(out.nvName.b.buffer,
				      out.nvName.b.size,
				      nameFilename);
    }
    if (rc == 0) {
	printf("nvreadpublic: name algorithm %04x\n", out.nvPublic.nvPublic.nameAlg);
	printf("nvreadpublic: data size %u\n", out.nvPublic.nvPublic.dataSize);
	printf("nvreadpublic: attributes %08x\n", out.nvPublic.nvPublic.attributes.val);
	TSS_TPMA_NV_Print(out.nvPublic.nvPublic.attributes, 0);
	TSS_PrintAll("nvreadpublic: policy",
		     out.nvPublic.nvPublic.authPolicy.t.buffer,
		     out.nvPublic.nvPublic.authPolicy.t.size);
	TSS_PrintAll("nvreadpublic: name",
		     out.nvName.t.name, out.nvName.t.size);
	if (noSpace) {
	    unsigned int b;
	    for (b = 0 ; b < out.nvName.t.size ; b++) {
		printf("%02x", out.nvName.t.name[b]);
	    }
	    printf("\n");
	}
	if (tssUtilsVerbose) printf("nvreadpublic: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("nvreadpublic: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("nvreadpublic\n");
    printf("\n");
    printf("Runs TPM2_NV_ReadPublic\n");
    printf("\n");
    printf("\t-ha\tNV index handle\n");
    printf("\t[-nalg\texpected name hash algorithm (sha1, sha256, sha384 sha512)\n"
	   "\t\t(default no check)]\n");
    printf("\t[-opu\tNV public file name (default do not save)]\n");
    printf("\t[-ns\tadditionally print Name in hex ascii on one line]\n");
    printf("\t[-on\tbinary format Name file name]\n");
    printf("\t\tUseful to paste into policy\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default NULL)\n");
    printf("\t01\tcontinue\n");
    printf("\t40\tresponse encrypt\n");
    printf("\t80\taudit\n");
    exit(1);	
}
