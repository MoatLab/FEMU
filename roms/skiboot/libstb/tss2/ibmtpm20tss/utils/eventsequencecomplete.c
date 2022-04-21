/********************************************************************************/
/*										*/
/*			    EventSequenceComplete				*/
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
    EventSequenceComplete_In 	in;
    EventSequenceComplete_Out	out;
    TPMI_DH_PCR 		pcrHandle = TPM_RH_NULL;
    TPMI_DH_OBJECT		sequenceHandle = 0;
    const char			*inFilename = NULL;
    const char			*outFilename1 = NULL;	/* for sha1 */
    const char			*outFilename2 = NULL;	/* for sha256 */
    const char			*outFilename3 = NULL;	/* for sha384 */
    const char			*outFilename5 = NULL;	/* for sha512 */
    int				process1 = FALSE;	/* these catch the case */
    int				process2 = FALSE;	/* where an output file was */
    int				process3 = FALSE;	/* specified but the TPM did */
    int				process5 = FALSE;	/* not return the algorithm */
    const char			*sequencePassword = NULL; 
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RS_PW;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
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
	else if (strcmp(argv[i],"-hs") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sequenceHandle);
	    }
	    else {
		printf("Missing parameter for -ha\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwds") == 0) {
	    i++;
	    if (i < argc) {
		sequencePassword = argv[i];
	    }
	    else {
		printf("-pwds option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		inFilename = argv[i];
	    }
	    else {
		printf("-if option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-of1")  == 0) {
	    i++;
	    if (i < argc) {
		outFilename1 = argv[i];
		process1 = TRUE;
	    } else {
		printf("-of1 option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-of2")  == 0) {
	    i++;
	    if (i < argc) {
		outFilename2 = argv[i];
		process2 = TRUE;
	    } else {
		printf("-of2 option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-of3")  == 0) {
	    i++;
	    if (i < argc) {
		outFilename3 = argv[i];
		process3 = TRUE;
	    } else {
		printf("-of3 option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-of5")  == 0) {
	    i++;
	    if (i < argc) {
		outFilename5 = argv[i];
		process5 = TRUE;
	    } else {
		printf("-of5 option needs a value\n");
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
    if (sequenceHandle == 0) {
	printf("Missing sequence handle parameter -hs\n");
	printUsage();
    }
    if (rc == 0) {
	if (inFilename != NULL) {
	    rc = TSS_File_Read2B(&in.buffer.b,
				 sizeof(in.buffer.t.buffer),
				 inFilename);
	}
	else {
	    in.buffer.b.size = 0;
	}
    }
    if (rc == 0) {
	in.pcrHandle = pcrHandle;
	in.sequenceHandle = sequenceHandle;
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
			 TPM_CC_EventSequenceComplete,
			 sessionHandle0, NULL, sessionAttributes0,
			 sessionHandle1, sequencePassword, sessionAttributes1,
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
	uint32_t c;
	printf("eventsequencecomplete: success\n");
	/* Table 100 - Definition of TPML_DIGEST_VALUES Structure */
	/* Table 71 - Definition of TPMT_HA Structure <IN/OUT> digests[] */
	/* Table 70 - Definition of TPMU_HA Union <IN/OUT, S> digests */
	printf("eventsequencecomplete: count %u\n", out.results.count);

	for (c = 0 ;  c < out.results.count ;c++) {
	    switch (out.results.digests[c].hashAlg) {
	      case TPM_ALG_SHA1:
		if (tssUtilsVerbose) printf("Hash algorithm SHA-1\n");
		if (tssUtilsVerbose) TSS_PrintAll("Digest",
					  (uint8_t *)&out.results.digests[c].digest.sha1,
					  SHA1_DIGEST_SIZE);
		if (outFilename1 != NULL) {
		    rc = TSS_File_WriteBinaryFile((uint8_t *)&out.results.digests[c].digest.sha1,
						  SHA1_DIGEST_SIZE,
						  outFilename1); 
		    process1 = FALSE;
		}
		break;
	      case TPM_ALG_SHA256:
		if (tssUtilsVerbose) printf("Hash algorithm SHA-256\n");
		if (tssUtilsVerbose) TSS_PrintAll("Digest",
					  (uint8_t *)&out.results.digests[c].digest.sha256,
					  SHA256_DIGEST_SIZE);
		if (outFilename2 != NULL) {
		    rc = TSS_File_WriteBinaryFile((uint8_t *)&out.results.digests[c].digest.sha256,
						  SHA256_DIGEST_SIZE,
						  outFilename2); 
		    process2 = FALSE;
		}
		break;
	      case TPM_ALG_SHA384:
		if (tssUtilsVerbose) printf("Hash algorithm SHA-384\n");
		if (tssUtilsVerbose) TSS_PrintAll("Digest",
					  (uint8_t *)&out.results.digests[c].digest.sha384,
					  SHA384_DIGEST_SIZE);
		if (outFilename3 != NULL) {
		    rc = TSS_File_WriteBinaryFile((uint8_t *)&out.results.digests[c].digest.sha384,
						  SHA384_DIGEST_SIZE,
						  outFilename3); 
		    process3 = FALSE;
		}
		break;
	      case TPM_ALG_SHA512:
		if (tssUtilsVerbose) printf("Hash algorithm SHA-512\n");
		if (tssUtilsVerbose) TSS_PrintAll("Digest",
					  (uint8_t *)&out.results.digests[c].digest.sha512,
					  SHA512_DIGEST_SIZE);
		if (outFilename5 != NULL) {
		    rc = TSS_File_WriteBinaryFile((uint8_t *)&out.results.digests[c].digest.sha512,
						  SHA512_DIGEST_SIZE,
						  outFilename5); 
		    process5 = FALSE;
		}
		break;
	      default:
		printf("Hash algorithm %04x unknown\n", out.results.digests[c].hashAlg);
		break;
	    }
	}
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("eventsequencecomplete: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    if (rc == 0) {
	if (process1) {
	    printf("-of1 specified but TPM did not return SHA-1\n");
	    rc = EXIT_FAILURE;
	}
	if (process2) {
	    printf("-of2 specified but TPM did not return SHA-256\n");
	    rc = EXIT_FAILURE;
	}
	if (process3) {
	    printf("-of3 specified but TPM did not return SHA-384\n");
	    rc = EXIT_FAILURE;
	}
	if (process5) {
	    printf("-of5 specified but TPM did not return SHA-512\n");
	    rc = EXIT_FAILURE;
	}
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("eventsequencecomplete\n");
    printf("\n");
    printf("Runs TPM2_EventSequenceComplete\n");
    printf("\n");
    printf("\t[-ha\tpcr handle (default NULL)]\n");
    printf("\t-hs\tsequence handle\n");
    printf("\t[-pwds\tpassword for sequence (default empty)]\n");
    printf("\t[-if\tinput file to be added (default no data)]\n");
    printf("\t[-of1\tsha1 output digest file (default do not save)]\n");
    printf("\t[-of2\tsha256 output digest file (default do not save)]\n");
    printf("\t[-of3\tsha384 output digest file (default do not save)]\n");
    printf("\t[-of5\tsha512 output digest file (default do not save)]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    exit(1);	
}
