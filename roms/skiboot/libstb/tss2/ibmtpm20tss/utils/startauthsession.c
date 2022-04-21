/********************************************************************************/
/*										*/
/*			    StartAuthSession	 				*/
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
    StartAuthSession_In 	in;
    StartAuthSession_Out 	out;
    StartAuthSession_Extra	extra;
    TPMI_DH_OBJECT		tpmKey = TPM_RH_NULL;		/* salt key */
    TPMI_DH_ENTITY		bindHandle = TPM_RH_NULL;	/* default */
    const char 			*bindPassword = NULL;
    char 			seChar = 0;			/* session type */
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;		/* default */
    TPMI_ALG_SYM		algorithm = TPM_ALG_XOR;	/* default symmetric algorithm */
    const char			*nonceTPMFilename = NULL;
    
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-se") == 0) {
	    i++;
	    if (i < argc) {
		seChar = argv[i][0];
	    }
	    else {
		printf("Missing parameter for -se\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-halg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    halg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    halg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    halg = TPM_ALG_SHA384;
		}
		else if (strcmp(argv[i],"sha512") == 0) {
		    halg = TPM_ALG_SHA512;
		}
		else {
		    printf("Bad parameter %s for -halg\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-halg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-hs") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i], "%x", &tpmKey);
	    }
	    else {
		printf("Bad parameter %s for -hs\n", argv[i]);
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-bi") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i], "%x", &bindHandle);
	    }
	    else {
		printf("Bad parameter %s for -bi\n", argv[i]);
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-sym") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"xor") == 0) {
		    algorithm = TPM_ALG_XOR;
		}
		else if (strcmp(argv[i],"aes") == 0) {
		    algorithm = TPM_ALG_AES;
		}
		else {
		    printf("Bad parameter %s for -sym\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -sym\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-on") == 0) {
	    i++;
	    if (i < argc) {
		nonceTPMFilename = argv[i];
	    }
	    else {
		printf("-on option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdb") == 0) {
	    i++;
	    if (i < argc) {
		bindPassword = argv[i];
	    }
	    else {
		printf("-pwdb option needs a value\n");
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
    if ((bindHandle == TPM_RH_NULL) && (bindPassword != NULL)) {
	printf("-pwdb (bind password) unused without -bi (bind handle)\n");
	printUsage();
    }
    /* sessionType */
    switch (seChar) {
      case 'h':
	in.sessionType = TPM_SE_HMAC;
	break;
      case 'p':
	in.sessionType = TPM_SE_POLICY;
	break;
      case 't':
	in.sessionType = TPM_SE_TRIAL;
	break;
      default:
	printf("Missing or illegal parameter for -se\n");
	printUsage();
    }
    if (rc == 0) {
	/* salt key */
	in.tpmKey = tpmKey;
	/* encryptedSalt (not required) */
	in.encryptedSalt.b.size = 0;
	/* bind handle */
	in.bind = bindHandle;
	/* nonceCaller (not required) */
	in.nonceCaller.t.size = 0;
	/* for parameter encryption */
	in.symmetric.algorithm = algorithm;
	/* authHash */
	in.authHash = halg;
    }
    /* symmetric */
    /* Table 128 - Definition of TPMT_SYM_DEF Structure */
    if (rc == 0) {	/* XOR */
	if (in.symmetric.algorithm == TPM_ALG_XOR) {
	    /* Table 61 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM Type */
	    /* Table 125 - Definition of TPMU_SYM_KEY_BITS Union */
	    in.symmetric.keyBits.xorr = halg;
	    /* Table 126 - Definition of TPMU_SYM_MODE Union */
	    in.symmetric.mode.sym = TPM_ALG_NULL;		/* none for xor */
	}
	else {		/* AES */
	    /* Table 61 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM Type */
	    /* Table 125 - Definition of TPMU_SYM_KEY_BITS Union */
	    in.symmetric.keyBits.aes = 128;
	    /* Table 126 - Definition of TPMU_SYM_MODE Union */
	    /* Table 63 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_MODE Type */
	    in.symmetric.mode.aes = TPM_ALG_CFB;
	}
    }
    /* pass the bind password to the TSS post processor for the session key calculation */
    if (rc == 0) {
	extra.bindPassword = bindPassword;
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
			 (EXTRA_PARAMETERS *)&extra,
			 TPM_CC_StartAuthSession,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    /* optionally store the nonceTPM for use in policy commands */
    if ((rc == 0) && (nonceTPMFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile((uint8_t *)&out.nonceTPM.t.buffer,
				      out.nonceTPM.t.size,
				      nonceTPMFilename); 
    }
    if (rc == 0) {
	printf("Handle %08x\n", out.sessionHandle);
	if (tssUtilsVerbose) printf("startauthsession: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("startauthsession: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("startauthsession\n");
    printf("\n");
    printf("Runs TPM2_StartAuthSession\n");
    printf("\n");
    printf("\t-se\n");
    printf("\n");
    printf("\t\th  HMAC session\n");
    printf("\t\tp  Policy session\n");
    printf("\t\tt  Trial policy session\n");
    printf("\n");
    printf("\t[-halg\t(sha1, sha256, sha384, sha512) (default sha256)]\n");
    printf("\t[-hs\tsalt handle (default TPM_RH_NULL)]\n");
    printf("\t[-bi\tbind handle (default TPM_RH_NULL)]\n");
    printf("\t[-pwdb\tbind password for bind handle (default empty)]\n");
    printf("\t[-sym\t(xor, aes) symmetric parameter encryption algorithm (default xor)]\n");
    printf("\t[-on\tnonceTPM file for policy session (default do not save)]\n");
    exit(1);	
}
