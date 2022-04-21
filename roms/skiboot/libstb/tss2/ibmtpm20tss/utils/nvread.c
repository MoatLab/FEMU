/********************************************************************************/
/*										*/
/*			    NV Read		 				*/
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
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/Unmarshal_fp.h>
#include "ekutils.h"

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    NV_Read_In 			in;
    NV_Read_Out			out;
    uint16_t 			offset = 0;			/* default 0 */
    uint16_t 			readLength = 0;			/* bytes to read */
    int 			ireadLength = 0;		/* bytes to read as integer */
    int 			cert = FALSE;			/* boolean, read certificate */
    const char			*certificateFilename = NULL;
    int				readLengthSet = FALSE;
    char 			hierarchyAuthChar = 0;
    const char 			*datafilename = NULL;
    TPMI_RH_NV_INDEX		nvIndex = 0;
    const char			*nvPassword = NULL; 		/* default no password */
    uint32_t 			pinCount = 0;	/* these two initialized to suppress falose gcc -O3
						   warnings */
    uint32_t 			pinLimit = 0;
    int				inData = FALSE;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;
    unsigned char 		*readBuffer = NULL; 
    uint32_t 			nvBufferMax;
    uint16_t 			bytesRead;			/* bytes read so far */
    int				done = FALSE;
   
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-pwdn") == 0) {
	    i++;
	    if (i < argc) {
		nvPassword = argv[i];
	    }
	    else {
		printf("-pwdn option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-hia") == 0) {
	    i++;
	    if (i < argc) {
		hierarchyAuthChar = argv[i][0];
	    }
	    else {
		printf("Missing parameter for -hia\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ha") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &nvIndex);
	    }
	    else {
		printf("Missing parameter for -ha\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-of")  == 0) {
	    i++;
	    if (i < argc) {
		datafilename = argv[i];
	    } else {
		printf("-of option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-off") == 0) {
	    i++;
	    if (i < argc) {
		offset = atoi(argv[i]);
	    }
	    else {
		printf("-off option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-sz") == 0) {
	    i++;
	    if (i < argc) {
		ireadLength = atoi(argv[i]);
		readLengthSet  = TRUE;
	    }
	    else {
		printf("-sz option needs a value\n");
		printUsage();
	    }
	    if ((ireadLength >= 0) && (ireadLength <= 0xffff)) {
		readLength = (uint16_t)ireadLength;
	    }
	    else {
		printf("-sz %d out of range\n", ireadLength);
		printUsage();
	    }
	}
	else if (!strcmp("-cert",argv[i])) {
	    cert = TRUE;
	}
	else if (strcmp(argv[i],"-ocert") == 0) {
	    i++;
	    if (i < argc) {
		certificateFilename = argv[i];
	    }
	    else {
		printf("-ocert option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-id")  == 0) {
	    i++;
	    if (i < argc) {
		pinCount = atoi(argv[i]);
		i++;
		if (i < argc) {
		    pinLimit = atoi(argv[i]);
		    inData = TRUE;
		}
		else {
		    printf("-id option needs two values\n");
		    printUsage();
		}
	    }
	    else {
		printf("-id option needs two values\n");
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
    /* Authorization handle */
    if (rc == 0) {
	if (hierarchyAuthChar == 'o') {
	    in.authHandle = TPM_RH_OWNER;  
	}
	else if (hierarchyAuthChar == 'p') {
	    in.authHandle = TPM_RH_PLATFORM;  
	}
	else if (hierarchyAuthChar == 0) {
	    in.authHandle = nvIndex;
	}
	else {
	    printf("\n");
	    printUsage();
	}
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* Determine the readLength from the NV index type.  This is just for the utility.  An
       application would already know the index type. */
    if (!readLengthSet) {	/* if caller specifies a read length, use it */
	NV_ReadPublic_In 		in;
	NV_ReadPublic_Out		out;
	if (rc == 0) {
	    in.nvIndex = nvIndex;
	    rc = TSS_Execute(tssContext,
			     (RESPONSE_PARAMETERS *)&out,
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_CC_NV_ReadPublic,
			     TPM_RH_NULL, NULL, 0);
	}
	if (rc == 0) {
	    TPMI_ALG_HASH nameAlg;
	    uint32_t nvType = (out.nvPublic.nvPublic.attributes.val & TPMA_NVA_TPM_NT_MASK) >> 4;
	    switch (nvType) {
	      case TPM_NT_ORDINARY:
		readLength = out.nvPublic.nvPublic.dataSize;
		break;
	      case TPM_NT_COUNTER:
	      case TPM_NT_BITS:
	      case TPM_NT_PIN_FAIL:
	      case TPM_NT_PIN_PASS:
		readLength = 8;
		break;
	      case TPM_NT_EXTEND:
		nameAlg = out.nvPublic.nvPublic.nameAlg;
		readLength = TSS_GetDigestSize(nameAlg);
		break;
	    }
	}
    }
    if (rc == 0) {
	if (readLength > 0) {	
	    readBuffer = malloc(readLength);		/* freed @1 */
	    if (readBuffer == NULL) {
		printf("Cannot malloc %u bytes for read buffer\n", readLength);
		exit(1);	
	    }
	}
	else {
	    readBuffer = NULL;
	}
    }
    if ((rc == 0) && inData) {
	if (readLength != 8) {
	    printf("-id needs read length 8, is %u\n", readLength);
	    exit(1);	
	}
    }
    /* data may have to be read in chunks.  Read the TPM_PT_NV_BUFFER_MAX, the chunk size */
    if (rc == 0) {
	rc = readNvBufferMax(tssContext,
			     &nvBufferMax);
    }    
    if (rc == 0) {
	in.nvIndex = nvIndex;
	in.offset = offset;	/* start at supplied offset */
	bytesRead = 0;		/* bytes read so far */
    }
    /* call TSS to execute the command */
    while ((rc == 0) && !done) {
	if (rc == 0) {
	    /* read a chunk */
	    in.offset = offset + bytesRead;
	    if ((uint32_t)(readLength - bytesRead) < nvBufferMax) {
		in.size = readLength - bytesRead;	/* last chunk */
	    }
	    else {
		in.size = nvBufferMax;		/* next chunk */
	    }
	}
	if (rc == 0) {
	    if (tssUtilsVerbose) printf("nvread: reading %u bytes\n", in.size);
	    rc = TSS_Execute(tssContext,
			     (RESPONSE_PARAMETERS *)&out,
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_CC_NV_Read,
			     sessionHandle0, nvPassword, sessionAttributes0,
			     sessionHandle1, NULL, sessionAttributes1,
			     sessionHandle2, NULL, sessionAttributes2,
			     TPM_RH_NULL, NULL, 0);
	}
	/* copy the results to the read buffer */
	if ((rc == 0) && (readBuffer != NULL)) {	/* check to handle 0 size read */
	    memcpy(readBuffer + bytesRead, out.data.b.buffer, out.data.b.size);
	}
	if (rc == 0) {
	    bytesRead += out.data.b.size;
	    if (bytesRead == readLength) {
		done = TRUE;
	    }
	}
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if ((rc == 0) && (datafilename != NULL) && (readBuffer != NULL)) {
	rc = TSS_File_WriteBinaryFile(readBuffer, readLength, datafilename);
    }
    if (rc == 0) {
	/* if not tracing the certificate, trace the result */
	if (!cert) {
	    if (tssUtilsVerbose) printf("nvread: success\n");
	    TSS_PrintAll("nvread: data", readBuffer, readLength);
	}
	if (cert || (certificateFilename != NULL)) {
	    void *x509Certificate = NULL;	/* opaque structure */
	    /* convert the DER stream to crypto library structure */
	    rc = convertDerToX509(&x509Certificate,	/* freed @2 */
				  readLength,
				  readBuffer);
	    /* if cert, trace the certificate using openssl print function */
	    if ((rc == 0) && cert) {
		x509PrintStructure(x509Certificate);
	    }
	    /* if a file name was specified, write the certificate in PEM format */
	    if ((rc == 0) && (certificateFilename != NULL)) {
		rc = convertX509ToPem(certificateFilename,
				      x509Certificate);
	    }
	    x509FreeStructure(x509Certificate);   	/* @2 */
	}
    }
    /* PIN index regression test aid, compare expected to actual */
    if (rc == 0) {
	if (inData) {
	    uint32_t tmpSize = 8;		/* readLength was checked previously */
	    uint8_t *tmpBuffer = readBuffer;
	    uint32_t actual;		/* data comes off TPM big endian (nbo) */

	    TSS_UINT32_Unmarshalu(&actual, &tmpBuffer, &tmpSize);
	    if (pinCount != actual) {
		printf("Error: Expected pinCount %u Actual %u\n", pinCount, actual);
		rc = TSS_RC_BAD_READ_VALUE;
	    }
	    TSS_UINT32_Unmarshalu(&actual, &tmpBuffer, &tmpSize);
	    if (pinLimit != actual) {
		printf("Error: Expected pinLimit %u Actual %u\n", pinLimit, actual);
		rc = TSS_RC_BAD_READ_VALUE;
	    }
	}
    }
    if (rc != 0) {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("nvread: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    free(readBuffer);	/* @1 */
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("nvread\n");
    printf("\n");
    printf("Runs TPM2_NV_Read\n");
    printf("\n");
    printf("\t[-hia\thierarchy authorization (o, p)(default index authorization)]\n");
    printf("\t-ha\tNV index handle\n");
    printf("\t[-pwdn\tpassword for NV index (default empty)]\n");
    printf("\t[-sz\tdata size (default to size of index)]\n");
    printf("\t\tcounter, bits, pin read 8 bytes, extend reads based on hash algorithm\n");
    printf("\t[-cert\tdumps the certificate\n");
    printf("\t01c00002\tRSA EK certificate\n");
    printf("\t01c0000a\tECC EK certificate\n");
    printf("\t[-ocert\t certificate file name, writes in PEM format\n");
    printf("\t[-off\t offset (default 0)]\n");
    printf("\t[-of\t data file (default do not save)]\n");
    printf("\t[-id\tdata values for pinCount and pinLimit verification, (4 bytes each)]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t40\tresponse encrypt\n");
    exit(1);	
}
