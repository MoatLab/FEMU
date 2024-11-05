/********************************************************************************/
/*										*/
/*			    EC_Ephemeral					*/
/*	     		Written by Bill Martin 					*/
/*                 Green Hills Integrity Software Services 			*/
/*										*/
/* (c) Copyright IBM Corporation 2017 - 2019					*/
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
#include <ibmtss/tssmarshal.h>

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC 			rc = 0;
    int 			i;    /* argc iterator */
    TSS_CONTEXT 		*tssContext = NULL;
    EC_Ephemeral_In 		in;
    EC_Ephemeral_Out            out;
    TPMI_ECC_CURVE              curveID = TPM_ECC_NONE;
    const char                  *QFilename = NULL;
    const char                  *counterFilename = NULL;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i], "-ecc") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"bnp256") == 0) {
		    curveID = TPM_ECC_BN_P256;
		}
		else if (strcmp(argv[i],"nistp256") == 0) {
		    curveID = TPM_ECC_NIST_P256;
		}
		else if (strcmp(argv[i],"nistp384") == 0) {
		    curveID = TPM_ECC_NIST_P384;
		}
		else {
		    printf("Bad parameter %s for -ecc\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-ecc option needs a value\n");
		printUsage();
	    }
	}
        else if (strcmp(argv[i], "-oq") == 0) {
            i++;
            if (i < argc) {
                QFilename = argv[i];
            } else {
                printf("-oq option needs a value\n");
                printUsage();
            }
        }
        else if (strcmp(argv[i], "-cf")  == 0) {
	    i++;
	    if (i < argc) {
		counterFilename = argv[i];
	    } else {
		printf("-cf option needs a value\n");
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
    if (curveID == TPM_ECC_NONE) {
	printf("Missing curve ID -ecc\n");
	printUsage();
    }
    if (rc == 0) {
        in.curveID = curveID;
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
			 TPM_CC_EC_Ephemeral,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	} 
    }
    if ((rc == 0) && (QFilename != NULL)) {
        rc = TSS_File_WriteStructure(&out.Q,
                                     (MarshalFunction_t)TSS_TPM2B_ECC_POINT_Marshalu,
				     QFilename);
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("counter is %d\n", out.counter);
	if (counterFilename != NULL)  {
	    rc = TSS_File_WriteStructure(&out.counter,
					 (MarshalFunction_t)TSS_UINT16_Marshalu,
					 counterFilename);
	}
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("ecephemeral: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("ecephemeral: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}


static void printUsage(void)
{
    printf("\n");
    printf("ecephmeral\n");
    printf("\n");
    printf("Runs TPM2_EC_Ephemeral\n");
    printf("\n");
    printf("\t-ecc\tcurve\n");
    printf("\t\tbnp256\n");
    printf("\t\tnistp256\n");
    printf("\t\tnistp384\n");
    printf("\t[-oq\toutput Q ephemeral public key file name (default do not save)]\n");
    printf("\t[-cf\toutput counter file name (default do not save)]\n");
    exit(1); 
}
