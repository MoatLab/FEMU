/********************************************************************************/
/*										*/
/*			    NV Define Space	 				*/
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

#define TPMA_NVA_CLEAR_STCLEAR	0x08000000


int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    NV_DefineSpace_In 		in;
    char 			hierarchyChar = 0;
    char 			hierarchyAuthChar = '\0';
    TPMI_ALG_HASH		nalg = TPM_ALG_SHA256;
    unsigned int		hashSize = SHA256_DIGEST_SIZE;
    char 			typeChar = 'o';
    unsigned int		typeCount = 0;
    TPMI_RH_NV_INDEX		nvIndex = 0;
    uint16_t 			dataSize = 0;
    TPMA_NV			nvAttributes;	  	/* final attributes to command */
    TPMA_NV			setAttributes;		/* attributes to add to defaults*/
    TPMA_NV			clearAttributes;	/* attributes to subtract from defaults */
    const char			*policyFilename = NULL;
    const char			*nvPassword = NULL; 
    const char			*parentPassword = NULL; 
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;
    
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* nvAttributes first accumumates attributes that are default side effects of other arguments.
       E.g., specifying a policy sets POLICYWRITE and POLICYREAD.  After all arguments are
       processed, setAttributes and clearAttributes may optional fine tune the attributes. E.g.,
       POLICYWRITE can be cleared. */

    /* default values */
    nvAttributes.val = 0;
    setAttributes.val = TPMA_NVA_NO_DA;
    clearAttributes.val = 0;

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
	else if (strcmp(argv[i],"-nalg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    nalg = TPM_ALG_SHA1;
		    hashSize = SHA1_DIGEST_SIZE;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    nalg = TPM_ALG_SHA256;
		    hashSize = SHA256_DIGEST_SIZE;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    nalg = TPM_ALG_SHA384;
		    hashSize = SHA384_DIGEST_SIZE;
		}
		else if (strcmp(argv[i],"sha512") == 0) {
		    nalg = TPM_ALG_SHA512;
		    hashSize = SHA512_DIGEST_SIZE;
		}
		else {
		    printf("Bad parameter %s for -nalg\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-nalg option needs a value\n");
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
	else if (strcmp(argv[i],"-pwdn") == 0) {
	    i++;
	    if (i < argc) {
		nvPassword = argv[i];
	    }
	    else {
		printf("-pwdn option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pol") == 0) {
	    i++;
	    if (i < argc) {
		policyFilename = argv[i];
	    }
	    else {
		printf("-pol option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-sz") == 0) {
	    i++;
	    if (i < argc) {
		dataSize = atoi(argv[i]);
	    }
	    else {
		printf("-sz option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ty") == 0) {
	    i++;
	    if (i < argc) {
		typeChar = argv[i][0];
		typeCount++;
	    }
	    else {
		printf("-ty option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "+at") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i], "wd")  == 0) {
		    setAttributes.val |= TPMA_NVA_WRITEDEFINE;
		}
		else if (strcmp(argv[i], "wst") == 0) {
		    setAttributes.val |= TPMA_NVA_WRITE_STCLEAR;
		}
		else if (strcmp(argv[i], "gl") == 0) {
		    setAttributes.val |= TPMA_NVA_GLOBALLOCK;
		}
		else if (strcmp(argv[i], "rst") == 0) {
		    setAttributes.val |= TPMA_NVA_READ_STCLEAR;
		}
		else if (strcmp(argv[i], "pold") == 0) {
		    setAttributes.val |= TPMA_NVA_POLICY_DELETE;
		}
		else if (strcmp(argv[i], "stc") == 0) {
		    setAttributes.val |= TPMA_NVA_CLEAR_STCLEAR;
		}
		else if (strcmp(argv[i], "ody") == 0) {
		    setAttributes.val |= TPMA_NVA_ORDERLY;
		}
		else if (strcmp(argv[i], "ppw") == 0) {
		    setAttributes.val |= TPMA_NVA_PPWRITE;
		}
		else if (strcmp(argv[i], "ppr") == 0) {
		    setAttributes.val |= TPMA_NVA_PPREAD;
		}
		else if (strcmp(argv[i], "ow") == 0) {
		    setAttributes.val |= TPMA_NVA_OWNERWRITE;
		}
		else if (strcmp(argv[i], "or") == 0) {
		    setAttributes.val |= TPMA_NVA_OWNERREAD;
		}
		else if (strcmp(argv[i], "aw") == 0) {
		    setAttributes.val |= TPMA_NVA_AUTHWRITE;
		}
		else if (strcmp(argv[i], "ar") == 0) {
		    setAttributes.val |= TPMA_NVA_AUTHREAD;
		}
		else if (strcmp(argv[i], "wa") == 0) {
		    setAttributes.val |= TPMA_NVA_WRITEALL;
		}
		else {
		    printf("Bad parameter %s for +at\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for +at\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-at") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i], "da") == 0) {
		    clearAttributes.val |= TPMA_NVA_NO_DA;
		}
		else if (strcmp(argv[i], "ppw") == 0) {
		    clearAttributes.val |= TPMA_NVA_PPWRITE;
		}
		else if (strcmp(argv[i], "ppr") == 0) {
		    clearAttributes.val |= TPMA_NVA_PPREAD;
		}
		else if (strcmp(argv[i], "ow") == 0) {
		    clearAttributes.val |= TPMA_NVA_OWNERWRITE;
		}
		else if (strcmp(argv[i], "or") == 0) {
		    clearAttributes.val |= TPMA_NVA_OWNERREAD;
		}
		else if (strcmp(argv[i], "aw") == 0) {
		    clearAttributes.val |= TPMA_NVA_AUTHWRITE;
		}
		else if (strcmp(argv[i], "ar") == 0) {
		    clearAttributes.val |= TPMA_NVA_AUTHREAD;
		}
		else if (strcmp(argv[i], "pw") == 0) {
		    clearAttributes.val |= TPMA_NVA_POLICYWRITE;
		}
		else if (strcmp(argv[i], "pr") == 0) {
		    clearAttributes.val |= TPMA_NVA_POLICYREAD;
		}
		else {
		    printf("Bad parameter %s for -at\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -at\n");
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
    if (typeCount > 1) {
	printf("-ty can only be specified once\n");
	printUsage();
    }
    /* Authorization attributes */
    if (rc == 0) {
	if (hierarchyAuthChar == 'o') {
	    nvAttributes.val |= TPMA_NVA_OWNERWRITE | TPMA_NVA_OWNERREAD;
	}
	else if (hierarchyAuthChar == 'p') {
	    nvAttributes.val |= TPMA_NVA_PPWRITE | TPMA_NVA_PPREAD;
	}
	else if (hierarchyAuthChar == '\0') {
	    nvAttributes.val |= TPMA_NVA_AUTHWRITE | TPMA_NVA_AUTHREAD;
	}
	else {
	    printf("-hia has bad parameter\n");
	    printUsage();
	}
    }
    if (rc == 0) {
	if (hierarchyChar == 'o') {
	    in.authHandle = TPM_RH_OWNER;
	}
	else if (hierarchyChar == 'p') {
	    in.authHandle = TPM_RH_PLATFORM;
	    nvAttributes.val |= TPMA_NVA_PLATFORMCREATE;
	}
	else {
	    printf("Missing or illegal -hi\n");
	    printUsage();
	}
    }
    if (rc == 0) {
	switch (typeChar) {
	  case 'o':
	    nvAttributes.val |= TPMA_NVA_ORDINARY;
	    break;
	  case 'c':
	    nvAttributes.val |= TPMA_NVA_COUNTER;
	    dataSize = 8;
	    break;
	  case 'b':
	    nvAttributes.val |= TPMA_NVA_BITS;
	    dataSize = 8;
	    break;
	  case 'e':
	    nvAttributes.val |= TPMA_NVA_EXTEND;
	    dataSize = hashSize;
	    break;
	  case 'p':
	    nvAttributes.val |= TPMA_NVA_PIN_PASS;
	    dataSize = 8;
	    break;
	  case 'f':
	    nvAttributes.val |= TPMA_NVA_PIN_FAIL;
	    dataSize = 8;
	    break;
	  default:
	    printf("Illegal -ty\n");
	    printUsage();
	}
    }	
    /* Table 75 - Definition of Types for TPM2B_AUTH */
    if (rc == 0) {
	if (nvPassword == NULL) {
	    in.auth.b.size = 0;
	}
	/* if there was a password specified, permit index authorization */
	else {
	    /* PIN index cannot use index AUTHWRITE authorization */
	    if (((nvAttributes.val & TPMA_NVA_TPM_NT_MASK) != TPMA_NVA_PIN_FAIL) &&
		((nvAttributes.val & TPMA_NVA_TPM_NT_MASK) != TPMA_NVA_PIN_PASS)) {
		nvAttributes.val |= TPMA_NVA_AUTHWRITE;
	    }
	    nvAttributes.val |= TPMA_NVA_AUTHREAD;
	    rc = TSS_TPM2B_StringCopy(&in.auth.b,
				      nvPassword, sizeof(in.auth.t.buffer));
	}
    }
    /* optional authorization policy */
    if (rc == 0) {
	if (policyFilename != NULL) {
	    if (rc == 0) {
		nvAttributes.val |= TPMA_NVA_POLICYWRITE | TPMA_NVA_POLICYREAD;
		rc = TSS_File_Read2B(&in.publicInfo.nvPublic.authPolicy.b,
				     sizeof(in.publicInfo.nvPublic.authPolicy.t.buffer),
				     policyFilename);
	    }
	    /* sanity check that the size of the policy hash matches the name algorithm */
	    if (rc == 0) {
		if (in.publicInfo.nvPublic.authPolicy.b.size != hashSize) {
		    printf("Policy size %u does not match name algorithm %u\n",
			   in.publicInfo.nvPublic.authPolicy.b.size, hashSize);
		    rc = TPM_RC_POLICY;
		}
	    }
	}
	else {
	    in.publicInfo.nvPublic.authPolicy.t.size = 0;	/* default empty policy */
	}
    }
    /* Table 197 - Definition of TPM2B_NV_PUBLIC Structure publicInfo */
    /* Table 196 - Definition of TPMS_NV_PUBLIC Structure nvPublic */
    if (rc == 0) {
	in.publicInfo.nvPublic.nvIndex = nvIndex;	/* the handle of the data area */
	in.publicInfo.nvPublic.nameAlg = nalg;		/* hash algorithm used to compute the name
							   of the Index and used for the
							   authPolicy */
	in.publicInfo.nvPublic.attributes = nvAttributes;	/* the default Index attributes */
	/* additional set attributes */
	in.publicInfo.nvPublic.attributes.val |= setAttributes.val;
	/* clear attributes */
	in.publicInfo.nvPublic.attributes.val &= ~(clearAttributes.val);
	in.publicInfo.nvPublic.dataSize = dataSize;	/* the size of the data area */
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
			 TPM_CC_NV_DefineSpace,
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
	printf("nvdefinespace: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("nvdefinespace: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("nvdefinespace\n");
    printf("\n");
    printf("Runs TPM2_NV_DefineSpace\n");
    printf("\n");
    printf("\t-ha\tNV index handle\n");
    printf("\t\t01xxxxxx\n");
    printf("\t-hi\tauthorizing hierarchy (o, p)\n");
    printf("\t\to owner, p platform\n");
    printf("\t\tp sets PLATFORMCREATE\n");
    printf("\t[-pwdp\tpassword for hierarchy (default empty)]\n");
    printf("\t[-hia\thierarchy authorization (o, p)(default index authorization)]\n");
    printf("\n");
    printf("\t\tdefault  AUTHWRITE, AUTHREAD\n");
    printf("\t\to sets  OWNERWRITE, OWNERREAD\n");
    printf("\t\tp sets  PPWRITE, PPREAD (platform)\n");
    printf("\n");
    printf("\t[-pwdn\tpassword for NV index (default empty)]\n");
    printf("\t\tsets AUTHWRITE (if not PIN index), AUTHREAD\n");
    printf("\t[-nalg\tname algorithm (sha1, sha256, sha384 sha512) (default sha256)]\n");
    printf("\t[-sz\tdata size in decimal (default 0)]\n");
    printf("\t\tIgnored for other than ordinary index\n");
    printf("\t[-ty\tindex type (o, c, b, e, p, f) (default ordinary)]\n");
    printf("\t\tordinary, counter, bits, extend, pin pass, pin fail\n");
    printf("\t[-pol\tpolicy file (default empty)]\n");
    printf("\t\tsets POLICYWRITE, POLICYREAD\n");
    printf("\t[+at\tattributes to add (may be specified more than once)]\n");
    printf("\n");
    printf("\t\tppw   (PPWRITE)\t\tppr (PPREAD) \n");
    printf("\t\tow    (OWNERWRITE)\tor  (OWNERREAD) \n");
    printf("\t\taw    (AUTHWRITE)\tar  (AUTHREAD) \n");
    printf("\t\twd    (WRITEDEFINE)\tgl  (GLOBALLOCK) \n");
    printf("\t\trst   (READ_STCLEAR)\twst (WRITE_STCLEAR) \n");
    printf("\t\twa    (WRITEALL)\tody (ORDERLY) \n");
    printf("\t\tpold  (POLICY_DELETE) \tstc (CLEAR_STCLEAR) \n");
    printf("\n");
    printf("\t[-at\tattributes to delete (may be specified more than once)]\n");
    printf("\n");
    printf("\t\tppw   (PPWRITE)\t\tppr (PPREAD)\n");
    printf("\t\tow    (OWNERWRITE)\tor  (OWNERREAD)\n");
    printf("\t\taw    (AUTHWRITE)\tar  (AUTHREAD)\n");
    printf("\t\tpw    (POLICYWRITE)\tpr  (POLICYREAD)\n");
    printf("\t\tda    (NO_DA) (default set)\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    exit(1);	
}
