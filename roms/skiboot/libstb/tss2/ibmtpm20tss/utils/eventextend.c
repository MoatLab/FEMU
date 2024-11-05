/********************************************************************************/
/*										*/
/*		      Extend an EVENT measurement file into PCRs		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2016 - 2019.					*/
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

/* eventextend is test/demo code.  It parses a TPM2 event log file and extends the measurements into
   TPM PCRs or simulated PCRs.  This simulates the actions that would be performed by BIOS /
   firmware in a hardware platform.  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsscryptoh.h>

#include "eventlib.h"

/* local prototypes */

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char * argv[])
{
    TPM_RC 			rc = 0;
    int 			i = 0;
    TSS_CONTEXT			*tssContext = NULL;
    const char 			*infilename = NULL;
    FILE 			*infile = NULL;
    int				tpm = FALSE;	/* extend into TPM */
    int				sim = FALSE;	/* extend into simulated PCRs */
    int				nospec = FALSE;	/* event log does not start with spec file */
    int				noSpace = FALSE;
    uint32_t 			bankNum = 0;	/* PCR hash bank */
    unsigned int 		pcrNum = 0;	/* PCR number iterator */
    TPMI_DH_PCR 		pcrMax = 7;
    TPMT_HA 			simPcrs[HASH_COUNT][IMPLEMENTATION_PCR];
    TPMT_HA 			bootAggregates[HASH_COUNT];
    TCG_PCR_EVENT2 		event2;			/* TPM 2.0 event log entry */
    TCG_PCR_EVENT 		event;			/* TPM 1.2 event log entry */
    TCG_EfiSpecIDEvent 		specIdEvent;
    unsigned int 		lineNum;
    int 			endOfFile = FALSE;
	
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
	else if (strcmp(argv[i],"-tpm") == 0) {
	    tpm = TRUE;
	}
	else if (strcmp(argv[i],"-nospec") == 0) {
	    nospec = TRUE;
	}
	else if (strcmp(argv[i],"-sim") == 0) {
	    sim = TRUE;
	}
	else if (strcmp(argv[i],"-ns") == 0) {
	    noSpace = TRUE;
	}
	else if (strcmp(argv[i],"-pcrmax") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%u", &pcrMax);
	    }
	    else {
		printf("Missing parameter for -pcrmax");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-h")) {
	    printUsage();
	}
	else if (!strcmp(argv[i], "-v")) {
	    tssUtilsVerbose = TRUE;
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
    if (!tpm && !sim) {
	printf("-tpm or -sim must be specified\n");
	printUsage();
    }
    if (sim && nospec) {
	printf("-sim incompatible with -nospec\n");
	printUsage();
    }
    /*
    ** read the event log file
    */
    infile = fopen(infilename,"rb");
    if (infile == NULL) {
	printf("Unable to open input file '%s'\n", infilename);
	exit(-4);
    }
    /* the first event is a TPM 1.2 format event */
    /* read an event line */
    if ((rc == 0) && !nospec) {
	rc = TSS_EVENT_Line_Read(&event, &endOfFile, infile);
    }
    /* debug tracing */
    if ((rc == 0) && !nospec && !endOfFile && tssUtilsVerbose) {
	printf("\neventextend: line 0\n");
	TSS_EVENT_Line_Trace(&event);
    }
    /* parse the event, populates the TCG_EfiSpecIDEvent structure */
    if ((rc == 0) && !nospec && !endOfFile) {
	rc = TSS_SpecIdEvent_Unmarshal(&specIdEvent,
				       event.eventDataSize, event.event);
    }
    /* range check numberOfAlgorithms before the trace */
    if ((rc == 0) && !nospec && !endOfFile) {
	if (specIdEvent.numberOfAlgorithms > HASH_COUNT) {
	    printf("specIdEvent.numberOfAlgorithms %u greater than %u\n",
		   specIdEvent.numberOfAlgorithms, HASH_COUNT);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    /* trace the specIdEvent event */
    if ((rc == 0) && !nospec && !endOfFile && tssUtilsVerbose) {
	TSS_SpecIdEvent_Trace(&specIdEvent);
    }
    /* Start a TSS context */
    if ((rc == 0) && tpm) {
	rc = TSS_Create(&tssContext);
    }
    /* initialize simulated PCRs */
    if ((rc == 0) && sim) {
	if (specIdEvent.numberOfAlgorithms > HASH_COUNT) {
	    printf("specIdEvent.numberOfAlgorithms %u greater than %u\n",
		   specIdEvent.numberOfAlgorithms, HASH_COUNT);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    /* simulated BIOS PCRs start at zero at boot */
    if ((rc == 0) && sim) {
	for (bankNum = 0 ; bankNum < specIdEvent.numberOfAlgorithms ; bankNum++) {
	    bootAggregates[bankNum].hashAlg = specIdEvent.digestSizes[bankNum].algorithmId;
	    for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
		/* initialize each algorithm ID based on the specIdEvent */
		simPcrs[bankNum][pcrNum].hashAlg = specIdEvent.digestSizes[bankNum].algorithmId;
		memset(&simPcrs[bankNum][pcrNum].digest.tssmax, 0, sizeof(TPMU_HA));
	    }
	}
    }
    /* scan each measurement 'line' in the binary */
    for (lineNum = 1 ; (rc == 0) && !endOfFile ; lineNum++) {

	/* read a TPM 2.0 hash agile event line */
	if (rc == 0) {
	    rc = TSS_EVENT2_Line_Read(&event2, &endOfFile, infile);
	}
	/* debug tracing */
	if ((rc == 0) && !endOfFile && tssUtilsVerbose) {
	    printf("\neventextend: line %u\n", lineNum);
	    TSS_EVENT2_Line_Trace(&event2);
	}
	/* don't extend no action events */
	if ((rc == 0) && !endOfFile) {
	    if (event2.eventType == EV_NO_ACTION) {
		continue;
	    }
	}
	if ((rc == 0) && !endOfFile && tpm) {	/* extend TPM */
	    PCR_Extend_In 		in;
	    PCR_Read_In 		pcrReadIn;
	    PCR_Read_Out 		pcrReadOut;

	    if (rc == 0) {
		in.pcrHandle = event2.pcrIndex;
		in.digests = event2.digests;
		rc = TSS_Execute(tssContext,
				 NULL, 
				 (COMMAND_PARAMETERS *)&in,
				 NULL,
				 TPM_CC_PCR_Extend,
				 TPM_RS_PW, NULL, 0,
				 TPM_RH_NULL, NULL, 0);
	    }
	    /* for debug, read back and trace the PCR value after the extend */
	    if ((rc == 0) && tssUtilsVerbose) {
		pcrReadIn.pcrSelectionIn.count = 1;
		pcrReadIn.pcrSelectionIn.pcrSelections[0].hash =
		    event2.digests.digests[0].hashAlg;
		pcrReadIn.pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
		pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0;
		pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0;
		pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0;
		pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[event2.pcrIndex / 8] =
		    1 << (event2.pcrIndex % 8);

		rc = TSS_Execute(tssContext,
				 (RESPONSE_PARAMETERS *)&pcrReadOut,
				 (COMMAND_PARAMETERS *)&pcrReadIn,
				 NULL,
				 TPM_CC_PCR_Read,
				 TPM_RH_NULL, NULL, 0);
	    }
	    if ((rc == 0) && tssUtilsVerbose) {
		TSS_PrintAll("PCR digest",
			     pcrReadOut.pcrValues.digests[0].t.buffer,
			     pcrReadOut.pcrValues.digests[0].t.size);
	    }
	}
	if ((rc == 0) && !endOfFile && sim) {	/* extend simulated PCRs */
	    rc = TSS_EVENT2_PCR_Extend(simPcrs, &event2);
	}
    }
    {
	if (tpm) {
	    TPM_RC rc1 = TSS_Delete(tssContext);
	    if (rc == 0) {
		rc = rc1;
	    }
	}
    }
    if ((rc == 0) && sim) {
	for (bankNum = 0 ; (rc == 0) && (bankNum < specIdEvent.numberOfAlgorithms) ; bankNum++) {
	    /* trace the virtual PCRs */
	    if (rc == 0) {
	        char pcrString[9];	/* PCR number */

		printf("\n");
		TSS_TPM_ALG_ID_Print("algorithmId", specIdEvent.digestSizes[bankNum].algorithmId, 0);
		for (pcrNum = 0 ; pcrNum < IMPLEMENTATION_PCR ; pcrNum++) {
		    sprintf(pcrString, "PCR %02u:", pcrNum);
		    if (!noSpace) {
			/* TSS_PrintAllLogLevel() with a log level of LOGLEVEL_INFO to print the byte
			   array on one line with no length */
			TSS_PrintAllLogLevel(LOGLEVEL_INFO, pcrString, 1,
					     simPcrs[bankNum][pcrNum].digest.tssmax,
					     specIdEvent.digestSizes[bankNum].digestSize);
		    }
		    else {	/* print with no spaces */
			uint32_t bp;
			printf("PCR %02u: ", pcrNum);
			for (bp = 0 ; bp < specIdEvent.digestSizes[bankNum].digestSize ; bp++) {
			    printf("%02x", simPcrs[bankNum][pcrNum].digest.tssmax[bp]);
			}
			printf("\n");
		    }
		}
	    }
	    /* calculate the boot aggregate, hash of PCR 0-7 */
	    if (rc == 0) {
		int length[IMPLEMENTATION_PCR];
		size_t j;
		for (j = 0 ; j < IMPLEMENTATION_PCR ; j++) {
		    if (j <= pcrMax) {	/* include PCRs up to here */
			length[j] = specIdEvent.digestSizes[bankNum].digestSize;
		    }
		    else {
			length[j] = 0;	/* exclude PCRs after to here */
		    }
		}
		rc = TSS_Hash_Generate(&bootAggregates[bankNum],
				       length[0], &simPcrs[bankNum][0].digest.tssmax,
				       length[1], &simPcrs[bankNum][1].digest.tssmax,
				       length[2], &simPcrs[bankNum][2].digest.tssmax,
				       length[3], &simPcrs[bankNum][3].digest.tssmax,
				       length[4], &simPcrs[bankNum][4].digest.tssmax,
				       length[5], &simPcrs[bankNum][5].digest.tssmax,
				       length[6], &simPcrs[bankNum][6].digest.tssmax,
				       length[7], &simPcrs[bankNum][7].digest.tssmax,
				       length[8], &simPcrs[bankNum][8].digest.tssmax,
				       length[9], &simPcrs[bankNum][9].digest.tssmax,
				       length[10], &simPcrs[bankNum][10].digest.tssmax,
				       length[11], &simPcrs[bankNum][11].digest.tssmax,
				       length[12], &simPcrs[bankNum][12].digest.tssmax,
				       length[13], &simPcrs[bankNum][13].digest.tssmax,
				       length[14], &simPcrs[bankNum][14].digest.tssmax,
				       length[15], &simPcrs[bankNum][15].digest.tssmax,
				       length[16], &simPcrs[bankNum][16].digest.tssmax,
				       length[17], &simPcrs[bankNum][17].digest.tssmax,
				       length[18], &simPcrs[bankNum][18].digest.tssmax,
				       length[19], &simPcrs[bankNum][19].digest.tssmax,
				       length[20], &simPcrs[bankNum][20].digest.tssmax,
				       length[21], &simPcrs[bankNum][21].digest.tssmax,
				       length[22], &simPcrs[bankNum][22].digest.tssmax,
				       length[23], &simPcrs[bankNum][23].digest.tssmax,
				       0, NULL);
	    }
	    /* trace the boot aggregate */
	    if (rc == 0) {
		if (!noSpace) {
		    TSS_PrintAllLogLevel(LOGLEVEL_INFO, "\nboot aggregate:", 1,
					 bootAggregates[bankNum].digest.tssmax,
					 specIdEvent.digestSizes[bankNum].digestSize);
		}
		else {	/* print with no spaces */
		    uint32_t bp;
		    printf("\nboot aggregate: ");
		    for (bp = 0 ; bp < specIdEvent.digestSizes[bankNum].digestSize ; bp++) {
			printf("%02x", bootAggregates[bankNum].digest.tssmax[bp]);
		    }
		    printf("\n");
		}
	    }
	}
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("eventextend: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("eventextend: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    if (infile != NULL) {
	fclose(infile);
    }
    return rc;
}

static void printUsage(void)
{
    printf("Usage: eventextend -if <measurement file> [-v]\n");
    printf("\n");
    printf("Extends a measurement file (binary) into a TPM or simulated PCRs\n");
    printf("\n");
    printf("\t-if\tfile containing the data to be extended\n");
    printf("\t[-nospec\tfile does not contain spec ID header (useful for incremental test)]\n");
    printf("\t[-tpm\textend TPM PCRs]\n");
    printf("\t[-sim\tcalculate simulated PCRs and boot aggregate]\n");
    printf("\t[-pcrmax\twith -sim, sets the highest PCR number to be used to calculate the\n"
	   "\t\tboot aggregate (default 7)]\n");
    printf("\t[-ns\tno space, no text, no newlines]\n");
    printf("\n");
   exit(-1);
}

