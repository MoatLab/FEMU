/********************************************************************************/
/*										*/
/*		      Extend an IMA measurement list into PCRs			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2014 - 2020.					*/
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

/* imaextend is test/demo code.  It parses a TPM 1.2 IMA event log file and extends the measurements
   into TPM PCRs.  This simulates the actions that would be performed by the Linux kernel IMA in a
   hardware platform.

   To test incremental attestations, the caller can optionally specify a beginning event number and
   ending event number.

   To test a platform without a TPM or TPM device driver, but where IMA is creating an event log,
   the caller can optionally specify a sleep time.  The program will then incrementally extend after
   each sleep.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tssutils.h>

#include "imalib.h"

/* local prototypes */

static TPM_RC copyDigest(PCR_Extend_In 	*in,
			 ImaEvent 	*imaEvent);
static TPM_RC pcrread(TSS_CONTEXT *tssContext,
		      TPMI_DH_PCR pcrHandle);
static void printUsage(void);

extern int tssUtilsVerbose;
int vverbose = FALSE;

int main(int argc, char * argv[])
{
    TPM_RC 		rc = 0;
    int 		i = 0;
    TSS_CONTEXT		*tssContext = NULL;
    PCR_Extend_In 	in;
    const char 		*infilename = NULL;
    FILE 		*infile = NULL;
    int 		littleEndian = FALSE;
    int			sim = FALSE;			/* extend into simulated PCRs */
    uint32_t 		bankNum = 0;			/* PCR hash bank, 0 is SHA-1, 1 is
							   SHA-256 */
    unsigned int 	pcrNum = 0;			/* PCR number iterator */
    TPMT_HA 		simPcrs[IMA_PCR_BANKS][IMPLEMENTATION_PCR];
    unsigned long	beginEvent = 0;			/* default beginning of log */
    unsigned long	endEvent = 0xffffffff;		/* default end of log */
    unsigned int	loopTime = 0;			/* default no loop */
    ImaEvent 		imaEvent;
    unsigned int 	lineNum;
    
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    for (i=1 ; i<argc ; i++) {
	if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		infilename = argv[i];
	    }
	    else {
		printf("-if option needs a value\n");
		printUsage();
		exit(2);
	    }
	}
	else if (strcmp(argv[i],"-sim") == 0) {
	    sim = TRUE;
	}
	else if (strcmp(argv[i],"-le") == 0) {
	    littleEndian = TRUE; 
	}
	else if (strcmp(argv[i],"-b") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%lu", &beginEvent);
	    }
	    else {
		printf("Missing parameter for -b\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-e") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%lu", &endEvent);
	    }
	    else {
		printf("Missing parameter for -e\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-l") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%u", &loopTime);
	    }
	    else {
		printf("Missing parameter for -e\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-h")) {
	    printUsage();
	}
	else if (!strcmp(argv[i], "-v")) {
	    tssUtilsVerbose = TRUE;
	    vverbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (infilename == NULL) {
	printf("Missing -if argument\n");
	printUsage();
    }
    if (!sim) {
	/* Start a TSS context */
	if (rc == 0) {
	    rc = TSS_Create(&tssContext);
	}
	if (rc == 0) {
	    uint32_t algs;				/* hash algorithm iterator */
	    in.digests.count = 2;			/* extend SHA-1 and SHA-256 banks */
	    in.digests.digests[0].hashAlg = TPM_ALG_SHA1;
	    in.digests.digests[1].hashAlg = TPM_ALG_SHA256;
	    /* IMA zero extends into the SHA-256 bank */
	    for (algs = 0 ; algs < in.digests.count ; algs++) {
		memset((uint8_t *)&in.digests.digests[algs].digest, 0, sizeof(TPMU_HA));
	    }
	}
	if ((rc == 0) && tssUtilsVerbose) {
	    printf("Initial PCR 10 value\n");
	    rc = pcrread(tssContext, 10);
	}
    }
    else {	/* sim TRUE */
	/* simulated PCRs start at zero at boot */
	if (rc == 0) {
	    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
		/* initialize each algorithm ID */
		simPcrs[0][pcrNum].hashAlg = TPM_ALG_SHA1;
		simPcrs[1][pcrNum].hashAlg = TPM_ALG_SHA256;
		memset(&simPcrs[0][pcrNum].digest.tssmax, 0, SHA1_DIGEST_SIZE);
		memset(&simPcrs[1][pcrNum].digest.tssmax, 0, SHA256_DIGEST_SIZE);
	    }
	}
    }
    /*
      scan each measurement 'line' in the binary
    */
    do {
	/* read the IMA event log file */
	int endOfFile = FALSE;
	if (rc == 0) {
	    infile = fopen(infilename,"rb");
	    if (infile == NULL) {
		printf("Unable to open input file '%s'\n", infilename);
		rc = TSS_RC_FILE_OPEN;
	    }
	}
	for (lineNum = 0 ; (rc == 0) && !endOfFile ; lineNum++) {
	    /* read an IMA event line */
	    IMA_Event_Init(&imaEvent);
	    if (rc == 0) {
		rc = IMA_Event_ReadFile(&imaEvent, &endOfFile, infile,
					littleEndian);
	    }
	    /*
	      if the event line is in range
	    */
	    if ((rc == 0) && (lineNum >= beginEvent) && (lineNum <= endEvent) && !endOfFile) {
		/* debug tracing */
		if (rc == 0) {
		    ImaTemplateData imaTemplateData;
		    if (tssUtilsVerbose) printf("\n");
		    printf("imaextend: line %u\n", lineNum);
		    if (tssUtilsVerbose) {
			IMA_Event_Trace(&imaEvent, FALSE);
			/* unmarshal the template data */
			if (rc == 0) {
			    rc = IMA_TemplateData_ReadBuffer(&imaTemplateData,
							     &imaEvent,
							     littleEndian);
			}
			if (rc == 0) {
			    IMA_TemplateData_Trace(&imaTemplateData,
						   imaEvent.nameInt);
			}
			else {
			    printf("imaextend: Error parsing template data, event %u\n", lineNum);
			    rc = 0;		/* not a fatal error */
			}
		    }
		}
		if (!sim) {
		    if (rc == 0) {
			in.pcrHandle = imaEvent.pcrIndex;		/* normally PCR 10 */
		    }
		    /* copy the SHA-1 digest to be extended into the SHA-1 and SHA-256 banks */
		    if (rc == 0) {
			rc = copyDigest(&in, &imaEvent);
		    }	
		    if (rc == 0) {
			rc = TSS_Execute(tssContext,
					 NULL, 
					 (COMMAND_PARAMETERS *)&in,
					 NULL,
					 TPM_CC_PCR_Extend,
					 TPM_RS_PW, NULL, 0,
					 TPM_RH_NULL, NULL, 0);
		    }
		    if (rc == 0 && tssUtilsVerbose) {
			rc = pcrread(tssContext, imaEvent.pcrIndex);
		    }
		}
		else {		/* sim */
		    /* even though IMA_Event_ReadFile() range checks the PCR index, range check it
		       again here to silence the static analysis tool */
		    if (rc == 0) {
			if (imaEvent.pcrIndex >= IMPLEMENTATION_PCR) {
			    printf("imaextend: PCR index %u %08x out of range\n",
				   imaEvent.pcrIndex, imaEvent.pcrIndex);
			    rc = TSS_RC_BAD_PROPERTY_VALUE;
			}
		    }
		    if (rc == 0) {
			rc = IMA_Event_PcrExtend(simPcrs, &imaEvent);
		    }
		    if (rc == 0 && tssUtilsVerbose) {
			TSS_PrintAll("PCR digest SHA-1",
				     simPcrs[0][imaEvent.pcrIndex].digest.tssmax,
				     SHA1_DIGEST_SIZE);
			TSS_PrintAll("PCR digest SHA-256",
				     simPcrs[1][imaEvent.pcrIndex].digest.tssmax,
				     SHA256_DIGEST_SIZE);
			
			
		    }
		}
	    }	/* for each IMA event in range */
	    IMA_Event_Free(&imaEvent);
	}	/* for each IMA event line */
	if (tssUtilsVerbose && (loopTime != 0)) printf("set beginEvent to %u\n", lineNum-1);
	beginEvent = lineNum-1;		/* remove the last increment at EOF */
	if (infile != NULL) {
	    fclose(infile);
	}
#ifdef TPM_POSIX
	sleep(loopTime);
#endif
#ifdef TPM_WINDOWS
	Sleep(loopTime * 1000);
#endif
	
    } while ((rc == 0) && (loopTime != 0)); 		/* sleep loop */
    if (!sim) {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    else {	/* sim */
	for (bankNum = 0 ; (rc == 0) && (bankNum < IMA_PCR_BANKS) ; bankNum++) {
	    TSS_TPM_ALG_ID_Print("algorithmId", simPcrs[bankNum][0].hashAlg, 0);
	    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
	        char 		pcrString[9];	/* PCR number */
		uint16_t 	digestSize;
		sprintf(pcrString, "PCR %02u:", pcrNum);
		/* TSS_PrintAllLogLevel() with a log level of LOGLEVEL_INFO to print the byte
		   array on one line with no length */
		digestSize = TSS_GetDigestSize(simPcrs[bankNum][pcrNum].hashAlg);
		TSS_PrintAllLogLevel(LOGLEVEL_INFO, pcrString, 1,
				     simPcrs[bankNum][pcrNum].digest.tssmax,
				     digestSize);
	    }
	}
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("imaextend: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("imaextend: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static TPM_RC copyDigest(PCR_Extend_In 	*in,
			 ImaEvent 	*imaEvent)
{
    TPM_RC 		rc = 0;
    unsigned char 	zeroDigest[SHA1_DIGEST_SIZE];
    int 		notAllZero;
    if (rc == 0) {
	memset(zeroDigest, 0, SHA1_DIGEST_SIZE);
	notAllZero = memcmp(imaEvent->digest, zeroDigest, SHA1_DIGEST_SIZE);
	/* the SHA-256 bank has already been 0 extended, so only the first 20 bytes need be
	   copied */
	if (notAllZero) {
	    memcpy((uint8_t *)&in->digests.digests[0].digest, imaEvent->digest, SHA1_DIGEST_SIZE);
	    memcpy((uint8_t *)&in->digests.digests[1].digest, imaEvent->digest, SHA1_DIGEST_SIZE);
	}
	/* IMA has a quirk where some measurements store a zero digest in the event log, but
	   extend ones into PCR 10 */
	else {
	    memset((uint8_t *)&in->digests.digests[0].digest, 0xff, SHA1_DIGEST_SIZE);
	    memset((uint8_t *)&in->digests.digests[1].digest, 0xff, SHA1_DIGEST_SIZE);
	}
    }
    return rc;
}	

static TPM_RC pcrread(TSS_CONTEXT *tssContext,
		      TPMI_DH_PCR pcrHandle)
{
    TPM_RC 		rc = 0;
    /* for debug, read back and trace the PCR value after the extend */
    PCR_Read_In 		pcrReadIn;
    PCR_Read_Out 		pcrReadOut;

    if (rc == 0) {
	pcrReadIn.pcrSelectionIn.count = 2;
	pcrReadIn.pcrSelectionIn.pcrSelections[0].hash = TPM_ALG_SHA1;
	pcrReadIn.pcrSelectionIn.pcrSelections[1].hash = TPM_ALG_SHA256;
	pcrReadIn.pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
	pcrReadIn.pcrSelectionIn.pcrSelections[1].sizeofSelect = 3;
	pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0;
	pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0;
	pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0;
	pcrReadIn.pcrSelectionIn.pcrSelections[1].pcrSelect[0] = 0;
	pcrReadIn.pcrSelectionIn.pcrSelections[1].pcrSelect[1] = 0;
	pcrReadIn.pcrSelectionIn.pcrSelections[1].pcrSelect[2] = 0;
	pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[pcrHandle / 8] =
	    1 << (pcrHandle % 8);
	pcrReadIn.pcrSelectionIn.pcrSelections[1].pcrSelect[pcrHandle / 8] =
	    1 << (pcrHandle % 8);
    }
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&pcrReadOut,
			 (COMMAND_PARAMETERS *)&pcrReadIn,
			 NULL,
			 TPM_CC_PCR_Read,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	TSS_PrintAll("PCR digest SHA-1",
		     pcrReadOut.pcrValues.digests[0].t.buffer,
		     pcrReadOut.pcrValues.digests[0].t.size);
	TSS_PrintAll("PCR digest SHA-256",
		     pcrReadOut.pcrValues.digests[1].t.buffer,
		     pcrReadOut.pcrValues.digests[1].t.size);
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("imaextend\n");
    printf("\n");
    printf("Runs TPM2_PCR_Extend to Extend a SHA-1 IMA measurement file (binary) into TPM PCRs\n");
    printf("The IMA measurement is directly extended into the SHA-1 bank, and a zero padded\n");
    printf("measurement is extended into the SHA-256 bank\n");
    printf("\n");
    printf("This handles the case where a zero measurement extends ones into the IMA PCR\n");
    printf("\n");
    printf("If -sim is specified, TPM PCRs are not extended.  Rather, imaextend extends into\n");
    printf("simluated PCRs and traces the result.\n");
    printf("\n");
    printf("\t-if\tIMA event log file name\n");
    printf("\t[-le\tinput file is little endian (default big endian)]\n");
    printf("\t[-sim\tcalculate simulated PCRs]\n");
    printf("\t[-b\tbeginning entry (default 0, beginning of log)]\n");
    printf("\t\tA beginning entry after the end of the log becomes a noop\n");
    printf("\t[-e\tending entry (default end of log)]\n");
    printf("\t\tE.g., -b 0 -e 0 sends one entry\n");
    printf("\t[-l\ttime - run in a continuous loop, with a sleep of 'time' seconds betwteen loops]\n");
    printf("\t\tThe intent is that this be run without specifying -b and -e\n");
    printf("\t\tAfer each pass, the next beginning entry is set to the last entry +1\n");
    printf("\n");
    exit(1);
}

