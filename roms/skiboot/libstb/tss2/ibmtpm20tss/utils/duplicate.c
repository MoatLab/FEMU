/********************************************************************************/
/*										*/
/*			   Duplicate		 				*/
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

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    Duplicate_In 		in;
    Duplicate_Out 		out;
    TPMI_DH_OBJECT		objectHandle = 0;
    TPMI_DH_OBJECT		newParentHandle = TPM_RH_NULL;
    const char 			*encryptionKeyInFilename = NULL;
    const char 			*encryptionKeyOutFilename = NULL;
    const char			*duplicateFilename = NULL;
    const char			*outSymSeedFilename = NULL;
    const char			*objectPassword = NULL; 
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
    /* Table 129 - Definition of TPMT_SYM_DEF_OBJECT Structure */
    in.symmetricAlg.algorithm = TPM_ALG_NULL;

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ho") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &objectHandle);
	    }
	    else {
		printf("Missing parameter for -ho\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdo") == 0) {
	    i++;
	    if (i < argc) {
		objectPassword = argv[i];
	    }
	    else {
		printf("-pwdo option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-hp") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &newParentHandle);
	    }
	    else {
		printf("Missing parameter for -hp\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ik") == 0) {
	    i++;
	    if (i < argc) {
		encryptionKeyInFilename = argv[i];
	    }
	    else {
		printf("-ik option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-salg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"aes") == 0) {
		    in.symmetricAlg.algorithm = TPM_ALG_AES;
		    in.symmetricAlg.keyBits.aes = 128;
		    in.symmetricAlg.mode.aes = TPM_ALG_CFB;
		}
		else {
		    printf("Bad parameter %s for -salg\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-salg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-oek") == 0) {
	    i++;
	    if (i < argc) {
		encryptionKeyOutFilename = argv[i];
	    }
	    else {
		printf("-oek option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-od") == 0) {
	    i++;
	    if (i < argc) {
		duplicateFilename = argv[i];
	    }
	    else {
		printf("-od option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-oss") == 0) {
	    i++;
	    if (i < argc) {
		outSymSeedFilename = argv[i];
	    }
	    else {
		printf("-oss option needs a value\n");
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
    if (objectHandle == 0) {
	printf("Missing or bad object handle parameter -ho\n");
	printUsage();
    }
    if ((in.symmetricAlg.algorithm == TPM_ALG_NULL) &&
	(encryptionKeyInFilename != NULL)) {
	printf("-ik needs -salg\n");
	printUsage();
    }
    if ((in.symmetricAlg.algorithm != TPM_ALG_NULL) &&
	(encryptionKeyInFilename == NULL)) {
	printf("-salg needs -ik\n");
	printUsage();
    }
    if (rc == 0) {
	in.objectHandle = objectHandle;
	in.newParentHandle = newParentHandle;
    }
    /* optional symmetric encryption key */
    if (encryptionKeyInFilename != NULL) {
	rc = TSS_File_Read2B(&in.encryptionKeyIn.b,
			     sizeof(in.encryptionKeyIn.t.buffer),
			     encryptionKeyInFilename);
    }
    else {
	in.encryptionKeyIn.t.size = 0;
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Duplicate,
			 sessionHandle0, objectPassword, sessionAttributes0,
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
    if ((rc == 0) && (encryptionKeyOutFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(out.encryptionKeyOut.t.buffer,
				      out.encryptionKeyOut.t.size,
				      encryptionKeyOutFilename);
    }
    if ((rc == 0) && (duplicateFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(out.duplicate.t.buffer,
				      out.duplicate.t.size,
				      duplicateFilename);
    }
    if ((rc == 0) && (outSymSeedFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(out.outSymSeed.t.secret,
				      out.outSymSeed.t.size,
				      outSymSeedFilename);
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("duplicate: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("duplicate: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("duplicate\n");
    printf("\n");
    printf("Runs TPM2_Duplicate\n");
    printf("\n");
    printf("\t-ho\tobject handle\n");
    printf("\t[-pwdo\tpassword for object (default empty)]\n");
    printf("\t[-hp\tnew parent handle (default TPM_RH_NULL)]\n");
    printf("\t[-ik\tencryption key in file name]\n");
    printf("\t[-salg\tsymmetric algorithm (aes)(default none)]\n");
    printf("\n");
    printf("\t[-oek\tencryption key out file name (default do not save)]\n");
    printf("\t[-od\tduplicate private area file name (default do not save)]\n");
    printf("\t[-oss\tsymmetric seed file name (default do not save)]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t40\tresponse encrypt\n");
    exit(1);	
}
