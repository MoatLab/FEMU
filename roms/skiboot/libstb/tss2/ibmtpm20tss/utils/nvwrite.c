/********************************************************************************/
/*										*/
/*			    NV Write		 				*/
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

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include "ekutils.h"

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    NV_Write_In 		in;
    uint16_t 			offset = 0;			/* default 0 */
    uint32_t 			pinPass = 0;	/* these two initialized to suppress falose gcc -O3
						   warnings */
    uint32_t 			pinLimit = 0;
    int				inData = FALSE;
    unsigned int		dataSource = 0;
    const char 			*commandData = NULL;
    const char 			*datafilename = NULL;
    char 			hierarchyAuthChar = 0;
    TPMI_RH_NV_INDEX		nvIndex = 0;
    const char			*nvPassword = NULL; 		/* default no password */
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;
    uint32_t 			nvBufferMax;
    size_t 			writeLength;		/* file bytes to write */
    unsigned char 		*writeBuffer = NULL; 	/* file buffer to write */
    uint16_t 			bytesWritten;		/* bytes written so far */
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
	else if (strcmp(argv[i],"-ic") == 0) {
	    i++;
	    if (i < argc) {
		commandData = argv[i];
		dataSource++;
	    }
	    else {
		printf("-ic option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-if")  == 0) {
	    i++;
	    if (i < argc) {
		datafilename = argv[i];
		dataSource++;
	    }
	    else {
		printf("-if option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-id")  == 0) {
	    i++;
	    if (i < argc) {
		pinPass = atoi(argv[i]);
		i++;
		if (i < argc) {
		    pinLimit = atoi(argv[i]);
		    dataSource++;
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
    if (dataSource > 1) {
	printf("More than one input data source (-if, -ic, -id\n");
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
    /* data may have to be written in chunks.  Read the chunk size */
    if (rc == 0) {
	rc = readNvBufferMax(tssContext,
			     &nvBufferMax);
    }
    /* if there is no input data source, default to 0 byte write */
    if ((rc == 0) && (dataSource == 0)) {
	in.data.b.size = 0;
    }
    /* -if, file data can be written in chunks */
    if ((rc == 0) && (datafilename != NULL)) {
	rc = TSS_File_ReadBinaryFile(&writeBuffer,     /* freed @1 */
				     &writeLength,
				     datafilename);
    }
    if ((rc == 0) && (datafilename != NULL)) {
	if (writeLength > 0xffff) {	/* overflow TPM2B uint16_t */
	    printf("nvwrite: size %u greater than 0xffff\n", (unsigned int)writeLength);	
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* -id, for pin pass or pin fail */
    if ((rc == 0) && (inData)) {
	uint32_t tmpData;
	in.data.b.size = sizeof(uint32_t) + sizeof(uint32_t);
	tmpData = htonl(pinPass);
	memcpy(in.data.b.buffer, &tmpData, sizeof(tmpData));
	tmpData = htonl(pinLimit);
	memcpy(in.data.b.buffer + sizeof(tmpData), &tmpData, sizeof(tmpData));
    }
    /* -ic, command line data must fit in one write */
    if ((rc == 0) && (commandData != NULL)) {
	rc = TSS_TPM2B_StringCopy(&in.data.b, commandData, nvBufferMax);
    }
    if (rc == 0) {
	in.nvIndex = nvIndex;
	in.offset = offset;		/* beginning offset */
	bytesWritten = 0;
    }
    while ((rc == 0) && !done) {
	uint16_t writeBytes = 0;		/* bytes to write in this pass, initialized to
						   suppress false gcc -O3 warning */
	if (rc == 0) {
	    /* for data from file, write a chunk */
	    if (datafilename != NULL) {
		in.offset = offset + bytesWritten;
		if ((uint32_t)(writeLength - bytesWritten) < nvBufferMax) {
		    writeBytes = (uint16_t)writeLength - bytesWritten;	/* last chunk */
		}
		else {
		    writeBytes = nvBufferMax;	/* next chunk */
		}
		rc = TSS_TPM2B_Create(&in.data.b, writeBuffer + bytesWritten, writeBytes,
				      sizeof(in.data.t.buffer));
	    }
	}
	/* call TSS to execute the command */
	if (rc == 0) {
	    if (tssUtilsVerbose) printf("nvwrite: writing %u bytes\n", in.data.b.size);
	    rc = TSS_Execute(tssContext,
			     NULL,
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_CC_NV_Write,
			     sessionHandle0, nvPassword, sessionAttributes0,
			     sessionHandle1, NULL, sessionAttributes1,
			     sessionHandle2, NULL, sessionAttributes2,
			     TPM_RH_NULL, NULL, 0);
	}
	/* data file can be written in chunks, other options are single write */
	if (rc == 0) {
	    if (datafilename == NULL) {
		done = TRUE;
	    }
	    else {
		bytesWritten += writeBytes;
		if (bytesWritten == writeLength) {
		    done = TRUE;
		}
	    }
	}
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("nvwrite: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("nvwrite: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	if (rc == TSS_RC_FILE_OPEN) {
	    printf("Possible cause: missing nvreadpublic before nvwrite\n");
	}
	rc = EXIT_FAILURE;
    }
    free(writeBuffer);	/* @1 */
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("nvwrite\n");
    printf("\n");
    printf("Runs TPM2_NV_Write\n");
    printf("\n");
    printf("\t[-hia\thierarchy authorization (o, p)(default index authorization)]\n");
    printf("\t-ha\tNV index handle\n");
    printf("\t[-pwdn\tauthorization password (default empty)]\n");
    printf("\t\thierarchy or NV index password\n");
    printf("\t[-ic\tdata string]\n");
    printf("\t[-if\tdata file]\n");
    printf("\t[-id\tdata values, pinPass and pinLimit (4 bytes each)]\n");
    printf("\t\tif none is specified, a 0 byte write occurs\n");
    printf("\t\t-id is normally used for pin pass or pin fail indexes\n");
    printf("\t[-off\toffset (default 0)]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t01\tcontinue\n");
    exit(1);	
}
