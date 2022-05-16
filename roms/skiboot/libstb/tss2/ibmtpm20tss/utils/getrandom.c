/********************************************************************************/
/*										*/
/*			   GetRandom						*/
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
#include <ibmtss/Unmarshal_fp.h>

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    GetRandom_In 		in;
    GetRandom_Out 		out;
    uint32_t			bytesRequested = 0;
    uint32_t 			bytesCopied;
    const char 			*outFilename = NULL;
    unsigned char 		*randomBuffer = NULL;
    int				noZeros = FALSE;
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
	if (strcmp(argv[i],"-by") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%u", &bytesRequested);
	    }
	    else {
		printf("Missing parameter for -by\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-of") == 0) {
	    i++;
	    if (i < argc) {
		outFilename = argv[i];
	    }
	    else {
		printf("-of option needs a value\n");
		printUsage();
	    }
	}
 	else if (strcmp(argv[i],"-nz") == 0) {
	    noZeros = TRUE;
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
    if ((bytesRequested == 0) ||
	(bytesRequested > 0xffff)) {
	printf("Missing or bad parameter -by\n");
	printUsage();
    }
    /* allocate a buffer for the bytes requested, add 1 for optional nul terminator */
    if (rc == 0) {
	rc = TSS_Malloc(&randomBuffer, bytesRequested + 1);	/* freed @1 */
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* This is somewhat optimized, but if a zero byte is obtained in the last pass, an extra pass is
       needed.  The trade-off is that, in general, asking for more random numbers than needed may slow
       down the TPM.  In any case, needing non-zero values for random auth should not happen very
       often.
     */
    for (bytesCopied = 0 ; (rc == 0) && (bytesCopied < bytesRequested) ; ) {
	/* Request whatever is left */
	if (rc == 0) {
	    in.bytesRequested = bytesRequested - bytesCopied;
	}
	/* call TSS to execute the command */
	if (rc == 0) {
	    rc = TSS_Execute(tssContext,
			     (RESPONSE_PARAMETERS *)&out, 
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_CC_GetRandom,
			     sessionHandle0, NULL, sessionAttributes0,
			     sessionHandle1, NULL, sessionAttributes1,
			     sessionHandle2, NULL, sessionAttributes2,
			     TPM_RH_NULL, NULL, 0);
	}
	if (rc == 0) {
	    size_t br;
	    if (tssUtilsVerbose) TSS_PrintAll("randomBytes in pass",
				      out.randomBytes.t.buffer, out.randomBytes.t.size);
	    /* copy as many bytes as were received or until bytes requested */
	    for (br = 0 ; (br < out.randomBytes.t.size) && (bytesCopied < bytesRequested) ; br++) {

		if (!noZeros || (out.randomBytes.t.buffer[br] != 0)) {
		    randomBuffer[bytesCopied] = out.randomBytes.t.buffer[br];
		    bytesCopied++;
		}
	    }
	}
	if (rc == 0) {
	    if (noZeros) {
		randomBuffer[bytesCopied] = 0x00;
	    }
	}
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if ((rc == 0) && (outFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(randomBuffer, bytesRequested + (noZeros ? 1 : 0),
				      outFilename);
    }
    if (rc == 0) {
	/* machine readable format */
	if (noSpace) {
	    uint32_t bp;
	    for (bp = 0 ; bp < bytesRequested ; bp++) {
		printf("%02x", randomBuffer[bp]);
	    }
	    printf("\n");
	}
	/* human readable format */
	else {
	    TSS_PrintAll("randomBytes", randomBuffer, bytesRequested);
	}
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("getrandom: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    free(randomBuffer);		/* @1 */
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("getrandom\n");
    printf("\n");
    printf("Runs TPM2_GetRandom\n");
    printf("\n");
    printf("\t-by\tbytes requested\n");
    printf("\t[-of\toutput file, with -nz, appends nul terminator (default do not save)]\n");
    printf("\t[-nz\tget random number with no zero bytes (for authorization value)]\n");
    printf("\t[-ns\tno space, no text, no newlines]\n");
    printf("\t\tjust a string of hexascii suitable for a symmetric key\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default NULL)\n");
    printf("\t01\tcontinue\n");
    printf("\t40\tresponse encrypt\n");
    exit(1);	
}
