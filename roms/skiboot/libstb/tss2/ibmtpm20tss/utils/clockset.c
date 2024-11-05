/********************************************************************************/
/*										*/
/*			   ClockSet						*/
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
#include <inttypes.h>

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
    ClockSet_In 		in;
    char 			hierarchyChar = 'p';
    TPMI_RH_HIERARCHY		authHandle = TPM_RH_PLATFORM;
    const char			*parentPassword = NULL; 
    uint64_t			newClock = 0;
    unsigned int		addSec = 0;
    const char			*clockFilename = NULL;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
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
		hierarchyChar = argv[i][0];
	    }
	    else {
		printf("Missing parameter for -hi\n");
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
	else if (strcmp(argv[i],"-clock") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%"SCNu64, &newClock);
	    }
	    else {
		printf("Missing parameter for -clock\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-addsec") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%u", &addSec);
	    }
	    else {
		printf("Missing parameter for -addsec\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-iclock") == 0) {
	    i++;
	    if (i < argc) {
		clockFilename = argv[i];
	    }
	    else {
		printf("-iclock option needs a value\n");
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
    if ((newClock == 0) && (clockFilename == NULL)) {
	printf("Missing -clock or -iclock\n");
	printUsage();
    }
    if ((newClock != 0) && (clockFilename != NULL)) {
	printf("Cannot have both -clock and -iclock\n");
	printUsage();
    }
    if ((rc == 0) && (newClock != 0)) {
	in.newTime = newClock;
    }
    if ((rc == 0) && (clockFilename != NULL)) {
	unsigned char *data = NULL;
	size_t length;
	if (rc == 0) {
	    rc = TSS_File_ReadBinaryFile(&data, &length, clockFilename);	/* freed @1 */
	}
	if (rc == 0) {
	    if (length != sizeof(in.newTime)) {
		printf("Clock file %s length %lu should be %lu\n",
		       clockFilename, (unsigned long)length, (unsigned long)sizeof(in.newTime));
	    }
	}
	if (rc == 0) {
	    memcpy((uint8_t *)&in.newTime, data, length);
	}
	free(data);	/* @1 */
    }	
    /* Table 50 - TPMI_RH_HIERARCHY authHandle */
    if (rc == 0) {
	in.newTime += (addSec * 1000);	/* new clock is in msec */
	if (tssUtilsVerbose) printf("clockset: New clock %"PRIu64"\n", in.newTime);
	if (hierarchyChar == 'o') {
	    authHandle = TPM_RH_OWNER;
	}
	else if (hierarchyChar == 'p') {
	    authHandle = TPM_RH_PLATFORM;
	}
	else {
	    printf("Bad parameter %c for -hi\n", hierarchyChar);
	    printUsage();
	}
	in.auth = authHandle;
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_ClockSet,
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
    if (rc == 0) {
	if (tssUtilsVerbose) printf("clockset: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("clockset: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("clockset\n");
    printf("\n");
    printf("Runs TPM2_ClockSet\n");
    printf("\n");
    printf("\t-clock\t\tnew clock\n");
    printf("\t-iclock\t\tnew clock file name\n");
    printf("\t[-addsec\tseconds to add to new clock]\n");
    printf("\t-hi\t\thierarchy (o, p) (default platform)\n");
    printf("\t\to owner, p platform\n");
    printf("\t-pwdp\t\tpassword for hierarchy (default empty)\n");
    printf("\n");
    printf("\t-se[0-2]\t session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    exit(1);	
}
