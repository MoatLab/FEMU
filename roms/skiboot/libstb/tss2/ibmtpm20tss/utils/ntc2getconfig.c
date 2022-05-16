/********************************************************************************/
/*										*/
/*			   Nuvoton GetConfig 	 				*/
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
   Gets the Nuvoton preConfig registers.  Optionally checks 'lock' and several
   hard coded configurations.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>

#include "ntc2lib.h"

static void printUsage(void);
static void printHexResponse(NTC2_CFG_STRUCT *preConfig);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    		/* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    NTC2_GetConfig_Out 		out;
    NTC2_CFG_STRUCT 		preConfig;	
    int 			verify = FALSE;
    int 			verifyLocked = FALSE;
    int				p8 = FALSE;
    int				p9 = FALSE;
  
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-verify") == 0) {
	    verify = TRUE;
	}
	else if (strcmp(argv[i],"-verifylocked") == 0) {
	    verify = TRUE;
	    verifyLocked = TRUE;
	}
	else if (strcmp(argv[i],"-p8") == 0) {
	    p8 = TRUE;
	}
	else if (strcmp(argv[i],"-p9") == 0) {
	    p9 = TRUE;
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
    if (verify) {
	if (!p8 && !p9) {
	    printf("Either -p8 or -p9 must be specified\n");
	    printUsage();
	}
	if (p8 && p9) {
	    printf("-p8 and -p9 cannot both be specified\n");
	    printUsage();
	}
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out, 
			 NULL,
			 NULL,
			 NTC2_CC_GetConfig,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	printHexResponse(&out.preConfig);
    }
    /* required / expected values */
    if (verify) {
	if (rc == 0) {
	    requiredConfig(&preConfig, p9);
	}
	if (rc == 0) {
	    rc = verifyConfig(&preConfig,	/* expected */
			      &out.preConfig,	/* actual */
			      verifyLocked);	/* expect locked */
	}
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("ntc2getconfig: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ntc2getconfig: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* printHexResponse() prints the read preConfig in a concise hex format */

static void printHexResponse(NTC2_CFG_STRUCT *preConfig)
{
    printf("i2cLoc1_2:\t%02x\n", preConfig->i2cLoc1_2);
    printf("i2cLoc3_4:\t%02x\n", preConfig->i2cLoc3_4);
    printf("AltCfg:\t\t%02x\n", preConfig->AltCfg);
    printf("Direction:\t%02x\n", preConfig->Direction);
    printf("PullUp:\t\t%02x\n", preConfig->PullUp);
    printf("PushPull:\t%02x\n", preConfig->PushPull);
    printf("CFG_A:\t\t%02x\n", preConfig->CFG_A);
    printf("CFG_B:\t\t%02x\n", preConfig->CFG_B);
    printf("CFG_C:\t\t%02x\n", preConfig->CFG_C);
    printf("CFG_D:\t\t%02x\n", preConfig->CFG_D);
    printf("CFG_E:\t\t%02x\n", preConfig->CFG_E);
    printf("CFG_F:\t\t%02x\n", preConfig->CFG_F);
    printf("CFG_G:\t\t%02x\n", preConfig->CFG_G);
    printf("CFG_H:\t\t%02x\n", preConfig->CFG_H);
    printf("CFG_I:\t\t%02x\n", preConfig->CFG_I);
    printf("CFG_J:\t\t%02x\n", preConfig->CFG_J);
    printf("IsValid:\t%02x\n", preConfig->IsValid);
    printf("IsLocked:\t%02x\n", preConfig->IsLocked);
    return;
}

static void printUsage(void)
{
    printf("\n");
    printf("ntc2getconfig\n");
    printf("\n");
    printf("Runs NTC2_GetConfig\n");
    printf("\n");
    printf("\t[-verify\tVerify results against System P default (default no verify)]\n");
    printf("\t[-verifylocked\tAlso verify that the preconfig is locked\n"
	   "\t\t(default verify not locked)]\n");
    printf("\t[-p8 or -p9\tVerify Nuvoton TPM for P8 or P9]");
    printf("\n");
    exit(1);
}
