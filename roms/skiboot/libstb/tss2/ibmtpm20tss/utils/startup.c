/********************************************************************************/
/*										*/
/*			    Startup		 				*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssresponsecode.h>

static void printUsage(void);
TPM_RC selftestCommand(void);
TPM_RC startupCommand(TPM_SU startupType);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC 		rc = 0;
    int			i;				/* argc iterator */
    int                 doStartup = TRUE;		/* default startup */
    int                 doSelftest = FALSE;		/* default no self test */
    TPM_SU		startupType = TPM_SU_CLEAR;
   
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-c") == 0) {
	    startupType = TPM_SU_CLEAR;
	    doStartup = TRUE;
	}
	else if (strcmp(argv[i],"-s") == 0) {
	    doStartup = TRUE;
	    startupType = TPM_SU_STATE;
	}
	else if (strcmp(argv[i],"-st") == 0) {
	    doSelftest = TRUE;
	}
	else if (strcmp(argv[i],"-sto") == 0) {
	    doStartup = FALSE;
	    doSelftest = TRUE;
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
    if ((rc == 0) && doStartup) {
	rc = startupCommand(startupType);
    }
    if ((rc == 0) && doSelftest ) {
	rc = selftestCommand();
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("startup: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("startup: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

TPM_RC startupCommand(TPM_SU startupType)
{
    TPM_RC 		rc = 0;
    TSS_CONTEXT		*tssContext = NULL;
    Startup_In 		in;

    /*
      Start a TSS context
    */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	in.startupType = startupType;
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Startup,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    return rc;
}

TPM_RC selftestCommand(void)
{
    TPM_RC 		rc = 0;
    TSS_CONTEXT		*tssContext = NULL;
    SelfTest_In 	in;

    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	in.fullTest = YES;
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_SelfTest,
			 TPM_RH_NULL, NULL, 0);
    }
    /* Delete the TSS context */
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	printf("selftest: success\n");
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("startup\n");
    printf("\n");
    printf("Runs TPM2_Startup\n");
    printf("\n");
    printf("\t[-c\tstartup clear (default)]\n");
    printf("\t[-s\tstartup state]\n");
    printf("\t[-st\trun TPM2_SelfTest]\n");
    printf("\t[-sto\trun only TPM2_SelfTest (no startup)]\n");
    exit(1);	
}

