/********************************************************************************/
/*										*/
/*			   PCR_Extend 						*/
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
#include <ibmtss/Unmarshal_fp.h>

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    	/* argc iterator */
    uint32_t			algs;	/* hash algorithm iterator */
    TSS_CONTEXT			*tssContext = NULL;
    PCR_Extend_In 		in;
    TPMI_DH_PCR 		pcrHandle = IMPLEMENTATION_PCR;
    const char 			*dataString = NULL;
    const char 			*datafilename = NULL;
   
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* Table 100 - Definition of TPML_DIGEST_VALUES Structure */
    in.digests.count = 0xffffffff;	/* flag for default hash algorithm */

    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ha") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%u", &pcrHandle);
	    }
	    else {
		printf("Missing parameter for -ha\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-halg") == 0) {
	    /* Table 100 - Definition of TPML_DIGEST_VALUES Structure */
	    if (in.digests.count == 0xffffffff) {	/* first time */
		in.digests.count = 1;			/* extend a bank */
	    }
	    else {
		in.digests.count++;			/* extend a bank */
	    }
	    if (in.digests.count > HASH_COUNT) {
		printf("Too many -halg specifiers, %u permitted\n", HASH_COUNT);
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		/* Table 100 - Definition of TPML_DIGEST_VALUES Structure digests */
		/* Table 71 - Definition of TPMT_HA Structure <IN/OUT> */
		/* Table 59 - Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type hashAlg */
		if (strcmp(argv[i],"sha1") == 0) {
		    in.digests.digests[in.digests.count-1].hashAlg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    in.digests.digests[in.digests.count-1].hashAlg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    in.digests.digests[in.digests.count-1].hashAlg = TPM_ALG_SHA384;
		}
		else if (strcmp(argv[i],"sha512") == 0) {
		    in.digests.digests[in.digests.count-1].hashAlg = TPM_ALG_SHA512;
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
	else if (strcmp(argv[i],"-ic") == 0) {
	    i++;
	    if (i < argc) {
		dataString = argv[i];
	    }
	    else {
		printf("-ic option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-if")  == 0) {
	    i++;
	    if (i < argc) {
		datafilename = argv[i];
	    } else {
		printf("-if option needs a value\n");
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
    if (pcrHandle >= IMPLEMENTATION_PCR) {
	printf("Missing or bad PCR handle parameter -ha\n");
	printUsage();
    }
    if ((dataString == NULL) && (datafilename == NULL)) {
	printf("Data string or data file must be specified\n");
	printUsage();
    }
    if ((dataString != NULL) && (datafilename != NULL)) {
	printf("Data string and data file cannot both be specified\n");
	printUsage();
    }
    if ((dataString != NULL) && (strlen(dataString) > sizeof(TPMU_HA))) {
	printf("Data length greater than maximum hash size %lu bytes\n",
	       (unsigned long)sizeof(TPMU_HA));
	printUsage();
    }
    /* handle default hash algorithm */
    if (in.digests.count == 0xffffffff) {	/* if none specified */
	in.digests.count = 1;
	in.digests.digests[0].hashAlg = TPM_ALG_SHA256;
    }
    if (rc == 0) {
	in.pcrHandle = pcrHandle;
	/* Table 70 - Definition of TPMU_HA Union <IN/OUT, S> */
	/* append zero padding to maximum hash algorithm length */
	for (algs = 0 ; algs < in.digests.count ; algs++) {
	    memset((uint8_t *)&in.digests.digests[algs].digest, 0, sizeof(TPMU_HA));
	}
    }
    if (rc == 0) {
	if (dataString != NULL) {
	    if (tssUtilsVerbose) printf("Extending %u bytes from stream into %u banks\n",
				(unsigned int)strlen(dataString), in.digests.count);
	    for (algs = 0 ; algs < in.digests.count ; algs++) {
		memcpy((uint8_t *)&in.digests.digests[algs].digest,
		       dataString, strlen(dataString));
	    }
	}
    }
    if (datafilename != NULL) {
	unsigned char 	*fileData = NULL;
	size_t 		length;
	if (rc == 0) {
	    rc = TSS_File_ReadBinaryFile(&fileData,			/* freed @1 */
					 &length, datafilename);
	}
	if (rc == 0) {
	    if (length > sizeof(TPMU_HA)) {
		printf("Data length greater than maximum hash size %lu bytes\n",
		       (unsigned long)sizeof(TPMU_HA));
		rc = EXIT_FAILURE;
	    } 
	}
	if (rc == 0) {
	    if (tssUtilsVerbose) printf("Extending %u bytes from file into %u banks\n",
				(unsigned int)length, in.digests.count);
	    for (algs = 0 ; algs < in.digests.count ; algs++) {
		memcpy((uint8_t *)&in.digests.digests[algs].digest, fileData, length);
	    }
	}
	free(fileData);		/* @1 */
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
			 TPM_CC_PCR_Extend,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("pcrextend: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("pcrextend: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("pcrextend\n");
    printf("\n");
    printf("Runs TPM2_PCR_Extend\n");
    printf("\n");
    printf("\t-ha\tpcr handle\n");
    printf("\t[-halg\t(sha1, sha256, sha384, sha512) (default sha256)]\n");
    printf("\t\t-halg may be specified more than once\n");
    printf("\n");
    printf("\t-ic\tdata string, 0 pad appended to halg length\n");
    printf("\t-if\tdata file, 0 pad appended to halg length\n");
    exit(1);	
}
