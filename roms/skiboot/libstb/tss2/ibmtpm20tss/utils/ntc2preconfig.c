/********************************************************************************/
/*										*/
/*			   Nuvoton Preconfig 	 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2019					*/
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

/* The function permits configuring either standard manufacturing values or individual registers.

   The hard coded values are in ../src/ntc2lib.h.  They are configured as a set.

   That file also has certain required values that cannot be changed.

   To override the standard manufacturing values, cautiously use -override.  This can brick the TPM,
   since it's setting up the bus interface.  Override does a red-modify-write, reading the registers
   and substiuting the new values.

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
static TPM_RC fixedConfig(NTC2_CFG_STRUCT *preConfig);
static void mergeConfig(NTC2_CFG_STRUCT *preConfigOut,
			const NTC2_CFG_STRUCT *preConfigIn,
			const NTC2_CFG_STRUCT *preConfigSet);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    		/* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    NTC2_GetConfig_Out 		out;
    NTC2_PreConfig_In 		in;
    NTC2_CFG_STRUCT 		preConfigSet;		/* flags mark values to change */
    NTC2_CFG_STRUCT 		preConfigIn;		/* values to change */
    int				p8 = FALSE;
    int				p9 = FALSE;
    int 			override = FALSE;	/* TRUE to override P required values */

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;

    memset(&preConfigSet, 0, sizeof(NTC2_CFG_STRUCT));	/* default nothing to change */
    memset(&preConfigIn, 0, sizeof(NTC2_CFG_STRUCT));   /* initialized to suppress false gcc -O3
							   warning */
    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	int inttmp;	/* for sccanf */
	if (strcmp(argv[i],"-p8") == 0) {
	    p8 = TRUE;
	}
	else if (strcmp(argv[i],"-p9") == 0) {
	    p9 = TRUE;
	}
	else if (strcmp(argv[i],"-override") == 0) {
	    override = TRUE;
	}
	else if (strcmp(argv[i],"-i2cLoc1_2") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.i2cLoc1_2 = inttmp;
		preConfigSet.i2cLoc1_2 = 1;
	    }
	    else {
		printf("Missing parameter for -i2cLoc1_2\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-i2cLoc3_4") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.i2cLoc3_4 = inttmp;
		preConfigSet.i2cLoc3_4 = 1;
	    }
	    else {
		printf("Missing parameter for -i2cLoc3_4\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-AltCfg") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.AltCfg = inttmp;
		preConfigSet.AltCfg = 1;
	    }
	    else {
		printf("Missing parameter for -AltCfg\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-Direction") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.Direction = inttmp;
		preConfigSet.Direction = 1;
	    }
	    else {
		printf("Missing parameter for -Direction\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-PullUp") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.PullUp = inttmp;
		preConfigSet.PullUp = 1;
	    }
	    else {
		printf("Missing parameter for -PullUp\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-PushPull") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.PushPull = inttmp;
		preConfigSet.PushPull = 1;
	    }
	    else {
		printf("Missing parameter for -PushPull\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-CFG_A") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.CFG_A = inttmp;
		preConfigSet.CFG_A = 1;
	    }
	    else {
		printf("Missing parameter for -CFG_A\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-CFG_B") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.CFG_B = inttmp;
		preConfigSet.CFG_B = 1;
	    }
	    else {
		printf("Missing parameter for -CFG_B\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-CFG_C") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.CFG_C = inttmp;
		preConfigSet.CFG_C = 1;
	    }
	    else {
		printf("Missing parameter for -CFG_C\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-CFG_D") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.CFG_D = inttmp;
		preConfigSet.CFG_D = 1;
	    }
	    else {
		printf("Missing parameter for -CFG_D\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-CFG_E") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.CFG_E = inttmp;
		preConfigSet.CFG_E = 1;
	    }
	    else {
		printf("Missing parameter for -CFG_E\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-CFG_F") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.CFG_F = inttmp;
		preConfigSet.CFG_F = 1;
	    }
	    else {
		printf("Missing parameter for -CFG_F\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-CFG_G") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.CFG_G = inttmp;
		preConfigSet.CFG_G = 1;
	    }
	    else {
		printf("Missing parameter for -CFG_G\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-CFG_H") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.CFG_H = inttmp;
		preConfigSet.CFG_H = 1;
	    }
	    else {
		printf("Missing parameter for -CFG_H\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-CFG_I") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.CFG_I = inttmp;
		preConfigSet.CFG_I = 1;
	    }
	    else {
		printf("Missing parameter for -CFG_I\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-CFG_J") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.CFG_J = inttmp;
		preConfigSet.CFG_J = 1;
	    }
	    else {
		printf("Missing parameter for -CFG_J\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-IsValid") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &inttmp);
		preConfigIn.IsValid = inttmp;
		preConfigSet.IsValid = 1;
	    }
	    else {
		printf("Missing parameter for -IsValid\n");
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
    if (p8 && p9) {
	printf("-p8 and -p9 cannot both be specified\n");
	printUsage();
    }
     /* can't specify both hard coded and override */
    if ((p8 || p9) && override) {
	printf("\nCannot have both -override and -p8 or -p9\n");
	printUsage();
    }
    /* must specify one of these options */
    if (!(p8 || p9) && !override) {
	printf("\nNeed either -p8, -p9, or -override\n");
	printUsage();
    }
    /* if override, at least one of the registers must be specified */
    if (override && 
	!(preConfigSet.i2cLoc1_2 	||
	  preConfigSet.i2cLoc3_4 	||
	  preConfigSet.AltCfg  		||
	  preConfigSet.Direction  	||
	  preConfigSet.PullUp  		||
	  preConfigSet.PushPull  	||
	  preConfigSet.CFG_A  		||
	  preConfigSet.CFG_B  		||
	  preConfigSet.CFG_C  		||
	  preConfigSet.CFG_D  		||
	  preConfigSet.CFG_E  		||
	  preConfigSet.CFG_F  		||
	  preConfigSet.CFG_G  		||
	  preConfigSet.CFG_H  		||
	  preConfigSet.CFG_I  		||
	  preConfigSet.CFG_J  		||
	  preConfigSet.IsValid)) {
	printf("\n-override requires at least one value to set\n");
	printUsage();
    }
    /* if hard coded values, none of the registers can be specified */
    if ((p8 || p9) && 
	(preConfigSet.i2cLoc1_2 	||
	 preConfigSet.i2cLoc3_4 	||
	 preConfigSet.AltCfg  		||
	 preConfigSet.Direction  	||
	 preConfigSet.PullUp  		||
	 preConfigSet.PushPull  	||
	 preConfigSet.CFG_A  		||
	 preConfigSet.CFG_B  		||
	 preConfigSet.CFG_C  		||
	 preConfigSet.CFG_D  		||
	 preConfigSet.CFG_E  		||
	 preConfigSet.CFG_F  		||
	 preConfigSet.CFG_G  		||
	 preConfigSet.CFG_H  		||
	 preConfigSet.CFG_I  		||
	 preConfigSet.CFG_J  		||
	 preConfigSet.IsValid )) {
	printf("\n-p8 and -p9  cannot specify a value to set\n");
	printUsage();
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* if overriding hard coded values, do read-modify-write */
    if (override) {
	/* call TSS NTC2_CC_GetConfig to read the current configuration parameters */
	if (rc == 0) {
	    rc = TSS_Execute(tssContext,
			     (RESPONSE_PARAMETERS *)&out, 
			     NULL,
			     NULL,
			     NTC2_CC_GetConfig,
			     TPM_RH_NULL, NULL, 0);
	}
	if (rc == 0) {
	    /* copy the existing read config to the new write config as the baseline values */
	    in.preConfig = out.preConfig;
	    /* merge values to change, from command line parameters */
	    mergeConfig(&in.preConfig,	/* baseline on input, merged on output */
			&preConfigIn,	/* values to merge */
			&preConfigSet);	/* boolean, true to merge the value */
	}
    }
    /* if setting System P required values */
    if (p8 || p9) {
	if (rc == 0) {
	    requiredConfig(&in.preConfig, p9);
	}
    }
    /* check that Nuvoton fixed values are in the correct state.  This is a sanity check for
       -p8 or -p9, but a required test for override */
    if (rc == 0) {
	rc = fixedConfig(&in.preConfig);
    }
    /* call TSS to execute the NTC2_CC_PreConfig command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 NTC2_CC_PreConfig,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("ntc2preconfig: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ntc2preconfig: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* fixedConfig() is a sanity check that the TPM is not being configured incorrectly.  Certain values
   are fixed.

   For -prequired, this is a simple consistency check on the required and fixed #define values
   For -override, this is a validation of the user input
*/

static TPM_RC fixedConfig(NTC2_CFG_STRUCT *preConfig)
{
    if (preConfig->Direction != FIXED_Direction) {
	printf("Direction is not the required value %02x\n", FIXED_Direction);
	return TPM_RC_RANGE;
    }
    if (preConfig->PullUp != FIXED_PullUp) {
	printf("PullUp is not the required value %02x\n", FIXED_PullUp);
	return TPM_RC_RANGE;
    }
    if (preConfig->PushPull != FIXED_PushPull) {
	printf("PushPull is not the required value %02x\n", FIXED_PushPull);
	return TPM_RC_RANGE;
    }
    if (preConfig->CFG_F != FIXED_CFG_F) {
	printf("CFG_F is not the required value %02x\n", FIXED_CFG_F);
	return TPM_RC_RANGE;
    }
    if (preConfig->CFG_I != FIXED_CFG_I) {
	printf("CFG_I is not the required value %02x\n", FIXED_CFG_I);
	return TPM_RC_RANGE;
    }
    if (preConfig->CFG_J != FIXED_CFG_J) {
	printf("CFG_J is not the required value %02x\n", FIXED_CFG_J);
	return TPM_RC_RANGE;
    }
    if (preConfig->IsValid != FIXED_IsValid) {
	printf("IsValid is not the required value %02x\n", FIXED_IsValid);
	return TPM_RC_RANGE;
    }
    return 0;
}

/* mergeConfig() handles the read modify write setup.

   preConfigIn are the new values
   preConfigSet are booleans, true for the new values
   preConfigOut at input are the current values, at output are the merged values
*/

static void mergeConfig(NTC2_CFG_STRUCT *preConfigOut,
			const NTC2_CFG_STRUCT *preConfigIn,
			const NTC2_CFG_STRUCT *preConfigSet)
{
    if (preConfigSet->i2cLoc1_2) {
	preConfigOut->i2cLoc1_2 = preConfigIn->i2cLoc1_2;
    }
    if (preConfigSet->i2cLoc3_4) {
	preConfigOut->i2cLoc3_4 = preConfigIn->i2cLoc3_4;
    }
    if (preConfigSet->AltCfg) {
	preConfigOut->AltCfg = preConfigIn->AltCfg;
    }
    if (preConfigSet->Direction) {
	preConfigOut->Direction = preConfigIn->Direction;
    }
    if (preConfigSet->PullUp) {
	preConfigOut->PullUp = preConfigIn->PullUp;
    }
    if (preConfigSet->PushPull) {
	preConfigOut->PushPull = preConfigIn->PushPull;
    }
    if (preConfigSet->CFG_A) {
	preConfigOut->CFG_A = preConfigIn->CFG_A;
    }
    if (preConfigSet->CFG_B) {
	preConfigOut->CFG_B = preConfigIn->CFG_B;
    }
    if (preConfigSet->CFG_C) {
	preConfigOut->CFG_C = preConfigIn->CFG_C;
    }
    if (preConfigSet->CFG_D) {
	preConfigOut->CFG_D = preConfigIn->CFG_D;
    }
    if (preConfigSet->CFG_E) {
	preConfigOut->CFG_E = preConfigIn->CFG_E;
    }
    if (preConfigSet->CFG_F) {
	preConfigOut->CFG_F = preConfigIn->CFG_F;
    }
    if (preConfigSet->CFG_G) {
	preConfigOut->CFG_G = preConfigIn->CFG_G;
    }
    if (preConfigSet->CFG_H) {
	preConfigOut->CFG_H = preConfigIn->CFG_H;
    }
    if (preConfigSet->CFG_I) {
	preConfigOut->CFG_I = preConfigIn->CFG_I;
    }
    if (preConfigSet->CFG_J) {
	preConfigOut->CFG_J = preConfigIn->CFG_J;
    }
    if (preConfigSet->IsValid) {
	preConfigOut->IsValid = preConfigIn->IsValid;
    }
    return;
}

static void printUsage(void)
{
    printf("\n");
    printf("ntc2preconfig\n");
    printf("\n");
    printf("Runs NTC2_PreConfig\n");
    printf("\n");
    printf("\t-p8 or -p9\tConfigure Nuvoton TPM for P8 or P9\n");
    printf("\t-override\tpermits individual register values, read-modify-write\n");
    printf("\n");
    printf("Values to set, each is a hex byte, (default do not change)\n");
    printf("\n");
    printf("\t[-i2cLoc1_2\tbyte]\n");
    printf("\t[-i2cLoc3_4\tbyte]\n");
    printf("\t[-AltCfg\tbyte]\n");
    printf("\t[-Direction\tbyte]\n");
    printf("\t[-PullUp\tbyte]\n");
    printf("\t[-PushPull\tbyte]\n");
    printf("\t[-CFG_A\t\tbyte]\n");
    printf("\t[-CFG_B\t\tbyte]\n");
    printf("\t[-CFG_C\t\tbyte]\n");
    printf("\t[-CFG_D\t\tbyte]\n");
    printf("\t[-CFG_E\t\tbyte]\n");
    printf("\t[-CFG_F\t\tbyte]\n");
    printf("\t[-CFG_G\t\tbyte]\n");
    printf("\t[-CFG_H\t\tbyte]\n");
    printf("\t[-CFG_I\t\tbyte]\n");
    printf("\t[-CFG_J\t\tbyte]\n");
    printf("\t[-IsValid\tbyte]\n");
    exit(1);
}



