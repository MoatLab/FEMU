/********************************************************************************/
/*										*/
/*			         Print Attributes				*/
/*		      Written by Ken Goldman					*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2019						*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Re-distributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Re-distributions in binary form must reproduce the above copyright		*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssprint.h>

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    unsigned int		tmpSession;
    TPMA_OBJECT 		object;
    TPMA_SESSION 		session;
    TPMA_STARTUP_CLEAR 		startup;
    TPMA_NV 			nv;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ob") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%8x", &object.val);
		TSS_TPMA_OBJECT_Print("TPMA_OBJECT", object, 0);
	    }
	    else {
		printf("Missing parameter for -ob\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%2x", &tmpSession);
		session.val = tmpSession;
		TSS_TPMA_SESSION_Print(session, 0);
	    }
	    else {
		printf("Missing parameter for -se\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-st") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%8x", &startup.val);
		TSS_TPMA_STARTUP_CLEAR_Print(startup, 0);
	    }
	    else {
		printf("Missing parameter for -st\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-nv") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%8x", &nv.val);
		TSS_TPMA_NV_Print(nv, 0);
	    }
	    else {
		printf("Missing parameter for -nv\n");
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
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("printattr\n");
    printf("\n");
    printf("Prints TPMA attributes as text\n");
    printf("\n");
    printf("\t-ob TPMA_OBJECT\n");
    printf("\t-se TPMA_SESSION \n");
    printf("\t-st TPMA_STARTUP_CLEAR \n");
    printf("\t-nv TPMA_NV\n"); 
    exit(1);
}
