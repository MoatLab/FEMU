/********************************************************************************/
/*										*/
/*			    Commit						*/
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
#include <ibmtss/Unmarshal_fp.h>

#include "objecttemplates.h"

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC 			rc = 0;
    int 			i;    /* argc iterator */
    TSS_CONTEXT 		*tssContext = NULL;
    Commit_In   		in;
    Commit_Out   		out;
    TPMI_DH_OBJECT      	signHandle = 0;
    TPMA_OBJECT         	objectAttributes;
    const char          	*s2Filename = NULL;
    const char          	*y2Filename = NULL;
    const char 			*dataFilename = NULL;
    const char       		*Kfilename = NULL;
    const char          	*Lfilename = NULL;
    const char          	*Efilename = NULL;
    const char                  *counterFilename = NULL;
    const char          	*keyPassword = NULL;
    TPMI_SH_AUTH_SESSION        sessionHandle0 = TPM_RS_PW;
    unsigned int                sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION        sessionHandle1 = TPM_RH_NULL;
    unsigned int                sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION        sessionHandle2 = TPM_RH_NULL;
    unsigned int                sessionAttributes2 = 0;
 
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */
    objectAttributes.val = 0;
    objectAttributes.val |= TPMA_OBJECT_NODA;

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
        if (strcmp(argv[i], "-hk") == 0) {
            i++;
            if (i < argc) {
                sscanf(argv[i],"%x", &signHandle);
            }
            else {
                printf("Missing parameter for -hk\n");
                printUsage();
            }
        }
	else if (strcmp(argv[i], "-pt")  == 0) {
	    i++;
	    if (i < argc) {
		dataFilename = argv[i];
	    } else {
		printf("-pt option needs a value\n");
		printUsage();
	    }
	}
        // for inSensitive data s2 see stirrandom.c
        // I think this is gX put in array form
        else if (strcmp(argv[i],"-s2") == 0) {
            i++;
            if (i < argc) {
                s2Filename = argv[i];
            }
            else {
                printf("-s2 option needs a value\n");
                printUsage();
            }
        }
        // for inSensitive data y2 see stirrandom.c
        // I think this is gX put in array form
        else if (strcmp(argv[i],"-y2") == 0) {
            i++;
            if (i < argc) {
                y2Filename = argv[i];
            }
            else {
                printf("-y2 option needs a value\n");
                printUsage();
            }
        }
	else if (strcmp(argv[i], "-Kf")  == 0) {
	    i++;
	    if (i < argc) {
		Kfilename = argv[i];
	    } else {
		printf("-Kf option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-Lf")  == 0) {
	    i++;
	    if (i < argc) {
                Lfilename = argv[i];
	    } else {
		printf("-Lf option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-Ef")  == 0) {
	    i++;
	    if (i < argc) {
		Efilename = argv[i];
	    } else {
		printf("-Ef option needs a value\n");
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
        else if (strcmp(argv[i],"-pwdk") == 0) {
            i++;
            if (i < argc) {
                keyPassword = argv[i];
            }
            else {
                printf("-pwdk option needs a value\n");
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
    if (signHandle == 0) {
	printf("Missing handle parameter -hk\n");
	printUsage();
    }
    if (rc == 0) {
	/* Handle of key that will perform signing */
	in.signHandle = signHandle;
    }
    /* set P1 */
    if (rc == 0) {
	if (dataFilename != NULL) {
	    rc = TSS_File_ReadStructure(&in.P1,
					(UnmarshalFunction_t)TSS_TPM2B_ECC_POINT_Unmarshalu,
					dataFilename);
	}
	else {
	    in.P1.point.x.t.size = 0;
	    in.P1.point.y.t.size = 0;
	}
    }
    /* set S2 */
    if (rc == 0) {
	if (s2Filename != NULL) {
	    rc = TSS_File_Read2B(&in.s2.b,
				 sizeof(in.s2.t.buffer),
				 s2Filename);
	}
	else {
	    in.s2.t.size = 0;
	}
    }
    /* set y2 */
    if (rc == 0) {
	if (y2Filename != NULL) {
	    rc = TSS_File_Read2B(&in.y2.b,
				 sizeof(in.y2.t.buffer),
				 y2Filename);
	}
	else {
	    in.y2.t.size = 0;
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
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Commit,
                         sessionHandle0, keyPassword, sessionAttributes0,
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
    if ((rc == 0) && (Kfilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.K,
				     (MarshalFunction_t)TSS_TPM2B_ECC_POINT_Marshalu,
				     Kfilename);


    }
    if ((rc == 0) && (Lfilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.L,
				     (MarshalFunction_t)TSS_TPM2B_ECC_POINT_Marshalu,
				     Lfilename);


    }
    if ((rc == 0) && (Efilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.E,
				     (MarshalFunction_t)TSS_TPM2B_ECC_POINT_Marshalu,
				     Efilename);


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
	if (tssUtilsVerbose) printf("commit: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("commit: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}


static void printUsage(void)
{
    printf("\n");
    printf("commit\n");
    printf("\n");
    printf("Runs TPM2_Commit\n");
    printf("\n");
    printf("\t-hk\tkey handle\n");
    printf("\t[-pt\tpoint input file name (default empty)]\n");
    printf("\t[-s2\ts2 input file name (default empty)]\n");
    printf("\t[-y2\ty2 input file name (default empty)]\n");
    printf("\t[-Kf\tK output data file name (default do not save)]\n");
    printf("\t[-Lf\toutput data file name (default do not save)]\n");
    printf("\t[-Ef\toutput data file name (default do not save)]\n");
    printf("\t[-cf\toutput counter file name (default do not save)]\n");
    printf("\t[-pwdk\tpassword for key (default empty)]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t40\tresponse encrypt\n");
    exit(1); 
}



