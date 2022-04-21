/********************************************************************************/
/*										*/
/*			   EncryptDecrypt					*/
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


static void printDecrypt(EncryptDecrypt_Out *out);
static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    EncryptDecrypt_In 		in;
    EncryptDecrypt_Out 		out;
    EncryptDecrypt2_In 		in2;
    TPMI_DH_OBJECT		keyHandle = 0;
    const char			*inFilename = NULL;
    const char			*outFilename = NULL;
    TPMI_YES_NO			decrypt = NO;
    int				two = FALSE;
    const char			*keyPassword = NULL; 
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;

    uint16_t			written;
    size_t			length;
    uint8_t			*buffer = NULL;		/* for the free */
    uint8_t			*buffer1 = NULL;	/* for marshaling */

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
	else if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		inFilename = argv[i];
	    }
	    else {
		printf("-if option needs a value\n");
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
 	else if (strcmp(argv[i],"-d") == 0) {
	    decrypt = YES;
	}
 	else if (strcmp(argv[i],"-2") == 0) {
	    two = TRUE;
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
    if (keyHandle == 0) {
	printf("Missing handle parameter -hk\n");
	printUsage();
    }
    if (inFilename == NULL) {
	printf("Missing encrypted message -if\n");
	printUsage();
    }
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&buffer,     /* freed @1 */
				     &length,
				     inFilename);
    }
    if (rc == 0) {
	if (length > sizeof(in.inData.t.buffer)) {
	    printf("Input data too long %u\n", (uint32_t)length);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	if (!two) {	/* use TPM_CC_EncryptDecrypt */
	    /* the symmetric key used for the operation */
	    in.keyHandle = keyHandle;
	    /* if YES, then the operation is decryption; if NO, the operation is encryption */
	    in.decrypt = decrypt;
	    /* symmetric mode */
	    in.mode = TPM_ALG_NULL;
	    /* an initial value as required by the algorithm */
	    in.ivIn.t.size = MAX_SYM_BLOCK_SIZE;
	    memset(in.ivIn.t.buffer, 0, MAX_SYM_BLOCK_SIZE);
	    /* the data to be encrypted/decrypted */
	    in.inData.t.size = (uint16_t)length;
	    if (length > 0) {	/* if length is 0, buffer is NULL */
		memcpy(in.inData.t.buffer, buffer, length);
	    }
	}
	else {
	    /* the symmetric key used for the operation */
	    in2.keyHandle = keyHandle;
	    /* if YES, then the operation is decryption; if NO, the operation is encryption */
	    in2.decrypt = decrypt;
	    /* symmetric mode */
	    in2.mode = TPM_ALG_NULL;
	    /* an initial value as required by the algorithm */
	    in2.ivIn.t.size = MAX_SYM_BLOCK_SIZE;
	    memset(in2.ivIn.t.buffer, 0, MAX_SYM_BLOCK_SIZE);
	    /* the data to be encrypted/decrypted */
	    in2.inData.t.size = (uint16_t)length;
	    if (length > 0) {	/* if length is 0, buffer is NULL */
		memcpy(in2.inData.t.buffer, buffer, length);
	    }
	}
    }
    free (buffer);	/* @1 */
    buffer = NULL;

    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	if (!two) {	/* use TPM_CC_EncryptDecrypt */
	    rc = TSS_Execute(tssContext,
			     (RESPONSE_PARAMETERS *)&out,
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_CC_EncryptDecrypt,
			     sessionHandle0, keyPassword, sessionAttributes0,
			     sessionHandle1, NULL, sessionAttributes1,
			     sessionHandle2, NULL, sessionAttributes2,
			     TPM_RH_NULL, NULL, 0);
	}
	else {	/* use TPM_CC_EncryptDecrypt2 */
	    rc = TSS_Execute(tssContext,
			     (RESPONSE_PARAMETERS *)&out,
			     (COMMAND_PARAMETERS *)&in2,
			     NULL,
			     TPM_CC_EncryptDecrypt2,
			     sessionHandle0, keyPassword, sessionAttributes0,
			     sessionHandle1, NULL, sessionAttributes1,
			     sessionHandle2, NULL, sessionAttributes2,
			     TPM_RH_NULL, NULL, 0);
	}
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if ((rc == 0) && (outFilename != NULL)) {
	written = 0;
	rc = TSS_TPM2B_MAX_BUFFER_Marshalu(&out.outData, &written, NULL, NULL);
    }
    if ((rc == 0) && (outFilename != NULL)) {
	buffer = realloc(buffer, written);	/* freed @2 */
	buffer1 = buffer;
	written = 0;
	rc = TSS_TPM2B_MAX_BUFFER_Marshalu(&out.outData, &written, &buffer1, NULL);
    }    
    if ((rc == 0) && (outFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(buffer + sizeof(uint16_t),
				      written - sizeof(uint16_t),
				      outFilename);
    }    
    free(buffer);	/* @2 */
    if (rc == 0) {
	if (tssUtilsVerbose) printDecrypt(&out);
	if (tssUtilsVerbose) printf("encryptdecrypt: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("encryptdecrypt: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printDecrypt(EncryptDecrypt_Out *out)
{
    TSS_PrintAll("outData", out->outData.t.buffer, out->outData.t.size);
}

static void printUsage(void)
{
    printf("\n");
    printf("encryptdecrypt\n");
    printf("\n");
    printf("Runs TPM2_EncryptDecrypt\n");
    printf("\n");
    printf("\t-hk\tkey handle\n");
    printf("\t-pwdk\tpassword for key (default empty)\n");
    printf("\t-d\tdecrypt (default encrypt)\n");
    printf("\t-if\tinput file name\n");
    printf("\t[-of\toutput file name (default do not save)]\n");
    printf("\t[-2\tuse TPM2_EncryptDecrypt2]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t40\tresponse encrypt\n");
    exit(1);	
}
